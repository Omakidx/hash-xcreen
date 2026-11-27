//! The repository lease `hx-lease.json` (ipc.md §29, "The lease" and "The lease, completed").
//!
//! This module is the rules; the Drive reads and writes are in [`super::gdrive`]. Two servers must
//! not write one repository: the lease names the server that does, and the helper checks it
//! before it mutates.

use std::future::Future;
use std::time::{Duration, Instant};

use hx_ipc::repo::pb;
use serde::{Deserialize, Serialize};

use super::retry::DriveError;

/// The lease object's name, in the repository folder, outside rustic's file types.
pub const LEASE_FILE: &str = "hx-lease.json";
/// Larger than this, a lease object is unreadable.
pub const MAX_LEASE_BYTES: usize = 4096;
/// Longest `hostname_hint`.
pub const MAX_HINT_BYTES: usize = 64;

/// The content of the lease object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    /// Always 1.
    pub format: u32,
    /// 16 random bytes, lower-case hex.
    pub server_id: String,
    /// Starts at 1, plus 1 at every takeover.
    pub generation: u64,
    /// Unix seconds.
    pub taken_at: u64,
    /// The host's name, sanitized, at most 64 bytes. For a human; never trusted.
    pub hostname_hint: String,
}

/// The lease object cannot be used (too large, not the format, not hex, generation 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unreadable;

/// What was found in the folder.
pub type Found = Option<Result<Lease, Unreadable>>;

/// `server_id` as the lease spells it.
#[must_use]
pub fn hex_id(id: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(id.len() * 2);
    for b in id {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The host's name for `hostname_hint`: every byte outside `[A-Za-z0-9._-]` becomes `-`, cut to
/// 64 bytes, `unknown` when empty.
#[must_use]
pub fn sanitize_hint(raw: &[u8]) -> String {
    let s: String = raw
        .iter()
        .take(MAX_HINT_BYTES)
        .map(|&b| {
            if b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-' {
                char::from(b)
            } else {
                '-'
            }
        })
        .collect();
    if s.is_empty() {
        "unknown".to_owned()
    } else {
        s
    }
}

impl Lease {
    /// A new lease for `server_id` (hex) at `generation`.
    #[must_use]
    pub fn new(server_id: &str, generation: u64, taken_at: u64, hint: &str) -> Self {
        Self {
            format: 1,
            server_id: server_id.to_owned(),
            generation,
            taken_at,
            hostname_hint: hint.to_owned(),
        }
    }

    /// Parses the object.
    ///
    /// # Errors
    /// [`Unreadable`] unless it is a format 1 lease with a 32-digit lower-case hex `server_id`, a
    /// generation of at least 1 and a hint of at most 64 bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, Unreadable> {
        if bytes.len() > MAX_LEASE_BYTES {
            return Err(Unreadable);
        }
        let l: Lease = serde_json::from_slice(bytes).map_err(|_| Unreadable)?;
        let ok = l.format == 1
            && l.generation >= 1
            && l.server_id.len() == 32
            && l.server_id
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            && l.hostname_hint.len() <= MAX_HINT_BYTES;
        if ok { Ok(l) } else { Err(Unreadable) }
    }

    /// The JSON the object is written as.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

/// What `OpenRepo` does about the lease it found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenDecision {
    /// The lease names this server: hold it at this generation, write nothing.
    Accept(u64),
    /// Write this lease, then hold it.
    Write(u64),
    /// Another server holds it: `LEASE_HELD`.
    Held,
    /// Unusable and no takeover: `INTERNAL`.
    Unreadable,
}

/// §29: no lease, generation 1; this server's, accepted; another's, `LEASE_HELD` unless
/// `takeover`, which writes generation + 1; an unreadable one is replaced (generation 1) only by
/// a takeover.
#[must_use]
pub fn decide_open(found: &Found, ours: &str, takeover: bool) -> OpenDecision {
    match found {
        None => OpenDecision::Write(1),
        Some(Ok(l)) if l.server_id == ours => OpenDecision::Accept(l.generation),
        Some(Ok(l)) if takeover => OpenDecision::Write(l.generation.saturating_add(1)),
        Some(Ok(_)) => OpenDecision::Held,
        Some(Err(Unreadable)) if takeover => OpenDecision::Write(1),
        Some(Err(Unreadable)) => OpenDecision::Unreadable,
    }
}

/// A request that changes the repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutation {
    /// `Create`.
    Create,
    /// `Write`.
    Write,
    /// `Remove`.
    Remove,
}

#[derive(Debug)]
struct St {
    ours: String,
    generation: u64,
    read_at: Instant,
    first_done: bool,
    lost: bool,
}

/// The session's view of the lease: what it holds, when it was last confirmed, whether it was lost.
#[derive(Debug)]
pub struct LeaseGuard {
    cache: Duration,
    st: tokio::sync::Mutex<St>,
}

impl LeaseGuard {
    /// Holds `generation` of `ours` (hex), just confirmed.
    #[must_use]
    pub fn new(ours: String, generation: u64, cache: Duration) -> Self {
        Self {
            cache,
            st: tokio::sync::Mutex::new(St {
                ours,
                generation,
                read_at: Instant::now(),
                first_done: false,
                lost: false,
            }),
        }
    }

    /// Has the lease been seen to be lost?
    pub async fn is_lost(&self) -> bool {
        self.st.lock().await.lost
    }

    /// Checks the lease before `m`. The first mutation of the session, and every `Remove`, reads
    /// the lease from Drive through `read`; the others accept a read at most `cache` old.
    ///
    /// # Errors
    /// `LEASE_HELD` when the lease does not name this server at the held generation (and for every
    /// later mutation), or the error of `read`.
    pub async fn check<F, Fut>(&self, m: Mutation, read: F) -> Result<(), DriveError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Found, DriveError>>,
    {
        let mut st = self.st.lock().await;
        if st.lost {
            return Err(DriveError::new(pb::ErrorClass::LeaseHeld));
        }
        let fresh = !st.first_done || m == Mutation::Remove || st.read_at.elapsed() > self.cache;
        if !fresh {
            return Ok(());
        }
        let found = read().await?;
        match found {
            Some(Ok(l)) if l.server_id == st.ours && l.generation == st.generation => {
                st.read_at = Instant::now();
                st.first_done = true;
                Ok(())
            }
            _ => {
                st.lost = true;
                Err(DriveError::new(pb::ErrorClass::LeaseHeld))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const US: &str = "00112233445566778899aabbccddeeff";
    const THEM: &str = "ffeeddccbbaa99887766554433221100";

    fn lease(id: &str, g: u64) -> Found {
        Some(Ok(Lease::new(id, g, 1, "h")))
    }

    #[test]
    fn open_decisions_follow_the_contract() {
        assert_eq!(decide_open(&None, US, false), OpenDecision::Write(1));
        assert_eq!(decide_open(&None, US, true), OpenDecision::Write(1));
        assert_eq!(
            decide_open(&lease(US, 4), US, false),
            OpenDecision::Accept(4)
        );
        assert_eq!(
            decide_open(&lease(US, 4), US, true),
            OpenDecision::Accept(4)
        );
        assert_eq!(decide_open(&lease(THEM, 4), US, false), OpenDecision::Held);
        assert_eq!(
            decide_open(&lease(THEM, 4), US, true),
            OpenDecision::Write(5)
        );
        assert_eq!(
            decide_open(&lease(THEM, u64::MAX), US, true),
            OpenDecision::Write(u64::MAX)
        );
        let bad: Found = Some(Err(Unreadable));
        assert_eq!(decide_open(&bad, US, false), OpenDecision::Unreadable);
        assert_eq!(decide_open(&bad, US, true), OpenDecision::Write(1));
    }

    #[test]
    fn parsing_is_strict() {
        let good = Lease::new(US, 3, 1_700_000_000, "box-1").to_bytes();
        assert_eq!(Lease::parse(&good).unwrap().generation, 3);
        let mk = |f: &str| f.as_bytes().to_vec();
        for bad in [
            mk(
                r#"{"format":2,"server_id":"00112233445566778899aabbccddeeff","generation":1,"taken_at":1,"hostname_hint":"h"}"#,
            ),
            mk(
                r#"{"format":1,"server_id":"00112233445566778899AABBCCDDEEFF","generation":1,"taken_at":1,"hostname_hint":"h"}"#,
            ),
            mk(
                r#"{"format":1,"server_id":"0011","generation":1,"taken_at":1,"hostname_hint":"h"}"#,
            ),
            mk(
                r#"{"format":1,"server_id":"00112233445566778899aabbccddeeff","generation":0,"taken_at":1,"hostname_hint":"h"}"#,
            ),
            mk(
                r#"{"format":1,"server_id":"00112233445566778899aabbccddeeff","generation":1,"taken_at":1,"hostname_hint":"h","x":1}"#,
            ),
            vec![b' '; MAX_LEASE_BYTES + 1],
            b"not json".to_vec(),
        ] {
            assert!(
                Lease::parse(&bad).is_err(),
                "{}",
                String::from_utf8_lossy(&bad)
            );
        }
        let long = Lease::new(US, 1, 1, &"h".repeat(65)).to_bytes();
        assert!(Lease::parse(&long).is_err());
    }

    #[test]
    fn the_hostname_hint_is_sanitized_and_cut() {
        assert_eq!(sanitize_hint(b"my-host.example_1"), "my-host.example_1");
        assert_eq!(sanitize_hint(b"a b/c\n\"d\xff"), "a-b-c--d-");
        assert_eq!(sanitize_hint(&[b'x'; 100]).len(), 64);
        assert_eq!(sanitize_hint(b""), "unknown");
        assert_eq!(hex_id(&[0, 1, 0xab]), "0001ab");
    }

    #[tokio::test]
    async fn the_first_mutation_and_every_remove_read_the_lease_and_writes_use_the_cache() {
        let g = LeaseGuard::new(US.into(), 2, Duration::from_millis(80));
        let reads = std::sync::atomic::AtomicU32::new(0);
        let read = || {
            reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::future::ready(Ok(lease(US, 2)))
        };
        let n = || reads.load(std::sync::atomic::Ordering::SeqCst);
        g.check(Mutation::Write, read).await.unwrap();
        assert_eq!(n(), 1, "the first mutation always reads");
        g.check(Mutation::Write, read).await.unwrap();
        g.check(Mutation::Create, read).await.unwrap();
        assert_eq!(n(), 1, "within the cache window a write does not");
        g.check(Mutation::Remove, read).await.unwrap();
        g.check(Mutation::Remove, read).await.unwrap();
        assert_eq!(n(), 3, "every remove reads");
        tokio::time::sleep(Duration::from_millis(120)).await;
        g.check(Mutation::Write, read).await.unwrap();
        assert_eq!(n(), 4, "the cache expired");
    }

    #[tokio::test]
    async fn a_lost_lease_is_sticky_and_a_read_error_is_not_a_loss() {
        let g = LeaseGuard::new(US.into(), 2, Duration::from_secs(60));
        let e = g
            .check(Mutation::Write, || {
                std::future::ready(Err(DriveError::new(pb::ErrorClass::Transient)))
            })
            .await
            .unwrap_err();
        assert_eq!(e.class, pb::ErrorClass::Transient);
        assert!(!g.is_lost().await);
        for found in [lease(THEM, 2), lease(US, 3), None, Some(Err(Unreadable))] {
            let g = LeaseGuard::new(US.into(), 2, Duration::from_secs(60));
            g.check(Mutation::Write, || std::future::ready(Ok(lease(US, 2))))
                .await
                .unwrap();
            let e = g
                .check(Mutation::Remove, || std::future::ready(Ok(found)))
                .await
                .unwrap_err();
            assert_eq!(e.class, pb::ErrorClass::LeaseHeld);
            // never read again, never allowed again
            let e = g
                .check(Mutation::Write, || std::future::ready(Ok(lease(US, 2))))
                .await
                .unwrap_err();
            assert_eq!(e.class, pb::ErrorClass::LeaseHeld);
            assert!(g.is_lost().await);
        }
    }
}
