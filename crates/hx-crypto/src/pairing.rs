//! SPAKE2 pairing (protocol §11.3): the server's pairing window of valid secrets, the
//! transcript binding, and both sides of the exchange.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use hmac::{Hmac, Mac};
use hx_proto::{
    channel::CloseCode,
    pb::{ControlMessage, Intent, RefuseReason, control_message::Message as Ctl},
    version::{Features, capabilities},
};
use hx_transport::{Client, ClientHello, ClientOptions, Connection, Target, TransportPreference};
use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use zeroize::Zeroizing;

use crate::{
    clock::Clock,
    error::{Error, Result},
    keys::{IdentityKey, PublicKey, random_bytes},
    registry::{DeviceRecord, DeviceRegistry},
    secrets::{PairingCode, PairingCredential, PairingToken, TOKEN_ID_LEN},
    text::sanitize_label,
    tls,
    wire::{
        PairConfirm, PairFailure, PairFailureReason, PairMode, PairServerHello, PairStart,
        PairingMessage, pairing_message::Body,
    },
};

/// Longest `device_name` / `server_name` accepted in the pairing exchange.
pub const MAX_NAME: usize = 64;
const SPAKE_LEN: usize = 33;
const MAC_LEN: usize = 32;
const ID_CLIENT: &[u8] = b"hx-pair-client";
const ID_SERVER: &[u8] = b"hx-pair-server";

// ------------------------------------------------------------------ transcript

/// Everything both sides must agree on, including the TLS keys each of them saw.
struct Transcript<'a> {
    client_spki: [u8; crate::keys::SPKI_LEN],
    server_spki: [u8; crate::keys::SPKI_LEN],
    mode: PairMode,
    token_id: &'a [u8],
    client_spake: &'a [u8],
    server_spake: &'a [u8],
    device_name: &'a str,
    server_name: &'a str,
}

fn lp(h: &mut Sha256, data: &[u8]) {
    h.update((data.len() as u32).to_be_bytes());
    h.update(data);
}

impl Transcript<'_> {
    fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"hx-pair-v1");
        lp(&mut h, &self.client_spki);
        lp(&mut h, &self.server_spki);
        lp(&mut h, &[self.mode as u8]);
        lp(&mut h, self.token_id);
        lp(&mut h, self.client_spake);
        lp(&mut h, self.server_spake);
        lp(&mut h, self.device_name.as_bytes());
        lp(&mut h, self.server_name.as_bytes());
        h.finalize().into()
    }
}

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy)]
enum Role {
    Client,
    Server,
}

fn mac_for(role: Role, key: &[u8], transcript: &[u8; 32]) -> Result<HmacSha256> {
    let mut m = <HmacSha256 as Mac>::new_from_slice(key).map_err(|_| Error::PairingFailed)?;
    m.update(match role {
        Role::Client => b"hx-pair-v1 client".as_slice(),
        Role::Server => b"hx-pair-v1 server".as_slice(),
    });
    m.update(transcript);
    Ok(m)
}

fn compute_mac(role: Role, key: &[u8], transcript: &[u8; 32]) -> Result<Vec<u8>> {
    Ok(mac_for(role, key, transcript)?
        .finalize()
        .into_bytes()
        .to_vec())
}

/// Constant-time check.
fn verify_mac(role: Role, key: &[u8], transcript: &[u8; 32], tag: &[u8]) -> bool {
    tag.len() == MAC_LEN
        && mac_for(role, key, transcript)
            .map(|m| m.verify_slice(tag).is_ok())
            .unwrap_or(false)
}

// ------------------------------------------------------------------ the window

/// Limits of the pairing window.
#[derive(Clone, Debug)]
pub struct PairingLimits {
    /// How long a token stays valid (default 15 minutes).
    pub token_ttl: Duration,
    /// How long a short code stays valid (default 15 minutes).
    pub code_ttl: Duration,
    /// Attempts that may be started against one token (default 5).
    pub token_attempts: u32,
    /// Attempts that may be started against the code (default 3).
    pub code_attempts: u32,
    /// Tokens valid at once (default 16); the oldest is dropped beyond this.
    pub max_tokens: usize,
}

impl Default for PairingLimits {
    fn default() -> Self {
        Self {
            token_ttl: Duration::from_secs(15 * 60),
            code_ttl: Duration::from_secs(15 * 60),
            token_attempts: 5,
            code_attempts: 3,
            max_tokens: 16,
        }
    }
}

struct Entry {
    generation: u64,
    password: Zeroizing<Vec<u8>>,
    expires: Instant,
    attempts_left: u32,
}

#[derive(Default)]
struct WindowState {
    next_generation: u64,
    tokens: HashMap<[u8; TOKEN_ID_LEN], Entry>,
    code: Option<Entry>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    Token([u8; TOKEN_ID_LEN]),
    Code,
}

/// A started attempt against a real secret.
pub(crate) struct Attempt {
    slot: Slot,
    generation: u64,
    pub(crate) password: Zeroizing<Vec<u8>>,
}

/// The tokens and the code that currently allow pairing. In memory only: SPAKE2 needs the
/// plaintext, so hashing at rest would not help, and nothing here is ever persisted.
pub struct PairingWindow {
    clock: Arc<dyn Clock>,
    limits: PairingLimits,
    state: Mutex<WindowState>,
}

impl PairingWindow {
    /// An empty (closed) window.
    pub fn new(clock: Arc<dyn Clock>, limits: PairingLimits) -> Self {
        Self {
            clock,
            limits,
            state: Mutex::new(WindowState::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, WindowState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn prune(&self, s: &mut WindowState) {
        let now = self.clock.now();
        s.tokens.retain(|_, e| e.expires > now);
        if s.code.as_ref().is_some_and(|e| e.expires <= now) {
            s.code = None;
        }
    }

    fn entry(
        &self,
        s: &mut WindowState,
        password: Zeroizing<Vec<u8>>,
        ttl: Duration,
        tries: u32,
    ) -> Entry {
        s.next_generation += 1;
        Entry {
            generation: s.next_generation,
            password,
            expires: self.clock.now() + ttl,
            attempts_left: tries,
        }
    }

    /// Create a token (for the one-liner or the app). Valid for `token_ttl`, single use.
    pub fn issue_token(&self) -> Result<PairingToken> {
        let token = PairingToken::generate()?;
        let mut s = self.lock();
        self.prune(&mut s);
        if s.tokens.len() >= self.limits.max_tokens
            && let Some(oldest) = s
                .tokens
                .iter()
                .min_by_key(|(_, e)| e.generation)
                .map(|(k, _)| *k)
        {
            s.tokens.remove(&oldest);
        }
        let e = self.entry(
            &mut s,
            token.password(),
            self.limits.token_ttl,
            self.limits.token_attempts,
        );
        s.tokens.insert(token.id(), e);
        Ok(token)
    }

    /// Create the short code (interactive install), replacing any earlier one.
    pub fn issue_code(&self) -> Result<PairingCode> {
        let code = PairingCode::generate()?;
        let mut s = self.lock();
        self.prune(&mut s);
        let e = self.entry(
            &mut s,
            code.password(),
            self.limits.code_ttl,
            self.limits.code_attempts,
        );
        s.code = Some(e);
        Ok(code)
    }

    /// True while at least one secret could still be used (unexpired, attempts left).
    pub fn is_open(&self) -> bool {
        let mut s = self.lock();
        self.prune(&mut s);
        s.tokens.values().any(|e| e.attempts_left > 0)
            || s.code.as_ref().is_some_and(|e| e.attempts_left > 0)
    }

    /// Invalidate every token and the code.
    pub fn close(&self) {
        let mut s = self.lock();
        s.tokens.clear();
        s.code = None;
    }

    /// Start an attempt, consuming one of the secret's attempts at once. `None` if no such
    /// secret exists, it expired or its attempts are used up (the caller then runs the
    /// exchange against a random password so the peer cannot tell).
    pub(crate) fn begin(&self, mode: PairMode, token_id: &[u8]) -> Option<Attempt> {
        let mut s = self.lock();
        self.prune(&mut s);
        let (slot, entry) = match mode {
            PairMode::Token => {
                let id: [u8; TOKEN_ID_LEN] = token_id.try_into().ok()?;
                (Slot::Token(id), s.tokens.get_mut(&id)?)
            }
            PairMode::Code => (Slot::Code, s.code.as_mut()?),
            PairMode::Unspecified => return None,
        };
        if entry.attempts_left == 0 {
            return None;
        }
        entry.attempts_left -= 1;
        Some(Attempt {
            slot,
            generation: entry.generation,
            password: entry.password.clone(),
        })
    }

    /// Spend the secret: succeeds for exactly one caller, and only while it is still the
    /// same unexpired secret.
    pub(crate) fn consume(&self, a: &Attempt) -> bool {
        let mut s = self.lock();
        self.prune(&mut s);
        match a.slot {
            Slot::Token(id) => {
                if s.tokens
                    .get(&id)
                    .is_some_and(|e| e.generation == a.generation)
                {
                    s.tokens.remove(&id);
                    true
                } else {
                    false
                }
            }
            Slot::Code => {
                if s.code
                    .as_ref()
                    .is_some_and(|e| e.generation == a.generation)
                {
                    s.code = None;
                    true
                } else {
                    false
                }
            }
        }
    }
}

// ------------------------------------------------------------------ shared helpers

async fn recv_pairing(conn: &Connection, wait: Duration) -> Result<Body> {
    let m: ControlMessage = tokio::time::timeout(wait, conn.recv_control())
        .await
        .map_err(|_| Error::Timeout("pairing message"))?
        .map_err(|e| match e {
            // The server closed with UNAUTHORIZED instead of (or before we could read) its
            // verdict: that is a failed pairing, whatever the reason.
            hx_transport::Error::Closed(info)
                if info.by_peer && info.code == CloseCode::Unauthorized =>
            {
                Error::PairingFailed
            }
            other => Error::Transport(other),
        })?;
    if let Some(Ctl::Goodbye(_)) = m.message {
        return Err(Error::Protocol("peer ended the exchange"));
    }
    PairingMessage::from_control(&m)?
        .body
        .ok_or(Error::Protocol("empty pairing message"))
}

async fn send_pairing(conn: &Connection, body: Body) -> Result<()> {
    conn.send_control(&PairingMessage::new(body).into_control()?)
        .await?;
    Ok(())
}

// ------------------------------------------------------------------ server side

/// What the server learned from a successful pairing.
#[derive(Debug)]
pub struct PairedDevice {
    /// The new (or refreshed) registry entry.
    pub record: DeviceRecord,
}

/// Run the server side of the pairing exchange on an accepted `INTENT_PAIR` connection.
/// Registers the device before telling the client it succeeded. On failure the client is told
/// (coarsely) and the error is returned; the caller closes the connection.
pub(crate) async fn serve_pairing(
    conn: &Connection,
    window: &PairingWindow,
    registry: &Arc<dyn DeviceRegistry>,
    clock: &Arc<dyn Clock>,
    server_key: &PublicKey,
    server_name: &str,
    client_key: &PublicKey,
    wait: Duration,
) -> Result<PairedDevice> {
    match serve_inner(
        conn,
        window,
        registry,
        clock,
        server_key,
        server_name,
        client_key,
        wait,
    )
    .await
    {
        Ok(p) => Ok(p),
        Err(e) => {
            let reason = match e {
                Error::Protocol(_) => PairFailureReason::Protocol,
                _ => PairFailureReason::Failed,
            };
            let _ = send_pairing(
                conn,
                Body::Failure(PairFailure {
                    reason: reason as i32,
                }),
            )
            .await;
            Err(e)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_inner(
    conn: &Connection,
    window: &PairingWindow,
    registry: &Arc<dyn DeviceRegistry>,
    clock: &Arc<dyn Clock>,
    server_key: &PublicKey,
    server_name: &str,
    client_key: &PublicKey,
    wait: Duration,
) -> Result<PairedDevice> {
    let Body::Start(start) = recv_pairing(conn, wait).await? else {
        return Err(Error::Protocol("expected PairStart"));
    };
    let mode = PairMode::try_from(start.mode).unwrap_or(PairMode::Unspecified);
    let id_ok = match mode {
        PairMode::Token => start.token_id.len() == TOKEN_ID_LEN,
        PairMode::Code => start.token_id.is_empty(),
        PairMode::Unspecified => false,
    };
    if !id_ok || start.spake.len() != SPAKE_LEN || start.device_name.len() > MAX_NAME {
        return Err(Error::Protocol("malformed PairStart"));
    }
    let device_name = sanitize_label(&start.device_name, MAX_NAME, "unnamed device");
    let server_name = sanitize_label(server_name, MAX_NAME, "server");

    // A real attempt consumes one of the secret's tries now; otherwise run the exchange
    // against a random password so the failure looks the same.
    let attempt = window.begin(mode, &start.token_id);
    let password = match &attempt {
        Some(a) => a.password.clone(),
        None => Zeroizing::new(random_bytes::<32>()?.to_vec()),
    };
    let (spake, server_spake) = Spake2::<Ed25519Group>::start_b(
        &Password::new(&*password),
        &Identity::new(ID_CLIENT),
        &Identity::new(ID_SERVER),
    );
    send_pairing(
        conn,
        Body::ServerHello(PairServerHello {
            spake: server_spake.clone(),
            server_name: server_name.clone(),
        }),
    )
    .await?;

    let Body::ClientConfirm(confirm) = recv_pairing(conn, wait).await? else {
        return Err(Error::Protocol("expected PairConfirm"));
    };
    let key = Zeroizing::new(
        spake
            .finish(&start.spake)
            .map_err(|_| Error::PairingFailed)?,
    );
    let t = Transcript {
        client_spki: client_key.spki(),
        server_spki: server_key.spki(),
        mode,
        token_id: &start.token_id,
        client_spake: &start.spake,
        server_spake: &server_spake,
        device_name: &device_name,
        server_name: &server_name,
    }
    .hash();
    let proved = verify_mac(Role::Client, &key, &t, &confirm.mac);
    // Only a verified proof may spend the secret, and only one caller can.
    let spent = proved && attempt.as_ref().is_some_and(|a| window.consume(a));
    if !spent {
        return Err(Error::PairingFailed);
    }

    let (reg, key_copy, name, now) = (
        registry.clone(),
        *client_key,
        device_name.clone(),
        clock.unix_secs(),
    );
    let record = tokio::task::spawn_blocking(move || reg.upsert_paired(&key_copy, &name, now))
        .await
        .map_err(|_| Error::PairingFailed)??;
    send_pairing(
        conn,
        Body::ServerConfirm(PairConfirm {
            mac: compute_mac(Role::Server, &key, &t)?,
        }),
    )
    .await?;
    Ok(PairedDevice { record })
}

// ------------------------------------------------------------------ client side

/// Options of [`pair_device`].
#[derive(Clone, Debug)]
pub struct PairClientOptions {
    /// Transport to use.
    pub preference: TransportPreference,
    /// Label the server will show for this device (at most 64 bytes).
    pub device_name: String,
    /// Software string for `Hello` (at most 128 bytes).
    pub software: String,
    /// Bound on the whole exchange after the connection is up.
    pub exchange_timeout: Duration,
    /// Transport tunables.
    pub transport: ClientOptions,
}

impl Default for PairClientOptions {
    fn default() -> Self {
        Self {
            preference: TransportPreference::Auto,
            device_name: "device".into(),
            software: concat!("hx-crypto ", env!("CARGO_PKG_VERSION")).into(),
            exchange_timeout: Duration::from_secs(20),
            transport: ClientOptions::default(),
        }
    }
}

/// A completed pairing, as the client sees it. The server key is authenticated (SPAKE2
/// confirmation bound to it): pin it and store it. The connection is still open so that the
/// caller can send what must follow pairing (password and PIN setup); call [`finish`](Self::finish)
/// when done.
#[derive(Debug)]
pub struct PairedServer {
    /// The server's identity key. Pin this from now on.
    pub server_key: PublicKey,
    /// The server's label (sanitised).
    pub server_name: String,
    /// The pairing connection (encrypted, mutually authenticated; only control messages).
    pub connection: Connection,
}

impl PairedServer {
    /// Close the pairing connection normally.
    pub async fn finish(self) {
        self.connection.close(CloseCode::NoError, "paired").await;
    }
}

/// Pair this device with a server using the token or code the user supplied (protocol §11.3).
///
/// Fails with [`Error::PairingClosed`] if the server has no valid secret, and with
/// [`Error::PairingFailed`] for a wrong or expired secret **or an interception**: the
/// server key presented in TLS is bound into the confirmation, so a man in the middle makes
/// this fail. Nothing is returned for the caller to store unless the confirmation succeeded.
pub async fn pair_device(
    target: &Target,
    device: &Arc<IdentityKey>,
    credential: &PairingCredential,
    opts: &PairClientOptions,
) -> Result<PairedServer> {
    let mut transport = opts.transport.clone();
    transport.preference = opts.preference;
    let client = Client::new(tls::client_config_pairing(device)?, transport);
    let hello = ClientHello {
        capabilities: capabilities(&[], Features::NONE),
        intent: Intent::Pair,
        software: opts.software.clone(),
        device_name: opts.device_name.clone(),
    };
    let conn = client.connect(target, &hello).await.map_err(|e| match e {
        hx_transport::Error::Refused {
            reason: RefuseReason::PairingClosed,
            ..
        } => Error::PairingClosed,
        hx_transport::Error::Refused {
            reason, message, ..
        } => Error::Refused { reason, message },
        other => Error::Transport(other),
    })?;
    match tokio::time::timeout(
        opts.exchange_timeout,
        client_exchange(&conn, device, credential, opts),
    )
    .await
    {
        Ok(Ok((server_key, server_name))) => Ok(PairedServer {
            server_key,
            server_name,
            connection: conn,
        }),
        Ok(Err(e)) => {
            conn.close(CloseCode::Unauthorized, "pairing failed").await;
            Err(e)
        }
        Err(_) => {
            conn.close(CloseCode::Unauthorized, "pairing timed out")
                .await;
            Err(Error::Timeout("pairing"))
        }
    }
}

async fn client_exchange(
    conn: &Connection,
    device: &Arc<IdentityKey>,
    credential: &PairingCredential,
    opts: &PairClientOptions,
) -> Result<(PublicKey, String)> {
    let wait = opts.exchange_timeout;
    let server_key = tls::peer_key(conn.peer_certificates())?;
    let (mode, token_id, password) = match credential {
        PairingCredential::Token(t) => (PairMode::Token, t.id().to_vec(), t.password()),
        PairingCredential::Code(c) => (PairMode::Code, Vec::new(), c.password()),
    };
    let device_name = sanitize_label(&opts.device_name, MAX_NAME, "device");
    let (spake, client_spake) = Spake2::<Ed25519Group>::start_a(
        &Password::new(&*password),
        &Identity::new(ID_CLIENT),
        &Identity::new(ID_SERVER),
    );
    send_pairing(
        conn,
        Body::Start(PairStart {
            mode: mode as i32,
            token_id: token_id.clone(),
            spake: client_spake.clone(),
            device_name: device_name.clone(),
        }),
    )
    .await?;

    let hello = match recv_pairing(conn, wait).await? {
        Body::ServerHello(h) => h,
        Body::Failure(_) => return Err(Error::PairingFailed),
        _ => return Err(Error::Protocol("expected PairServerHello")),
    };
    if hello.spake.len() != SPAKE_LEN || hello.server_name.len() > MAX_NAME {
        return Err(Error::Protocol("malformed PairServerHello"));
    }
    let key = Zeroizing::new(
        spake
            .finish(&hello.spake)
            .map_err(|_| Error::PairingFailed)?,
    );
    let t = Transcript {
        client_spki: device.public().spki(),
        server_spki: server_key.spki(),
        mode,
        token_id: &token_id,
        client_spake: &client_spake,
        server_spake: &hello.spake,
        device_name: &device_name,
        server_name: &hello.server_name,
    }
    .hash();
    send_pairing(
        conn,
        Body::ClientConfirm(PairConfirm {
            mac: compute_mac(Role::Client, &key, &t)?,
        }),
    )
    .await?;
    match recv_pairing(conn, wait).await? {
        Body::ServerConfirm(c) => {
            if verify_mac(Role::Server, &key, &t, &c.mac) {
                Ok((
                    server_key,
                    sanitize_label(&hello.server_name, MAX_NAME, "server"),
                ))
            } else {
                Err(Error::PairingFailed)
            }
        }
        Body::Failure(_) => Err(Error::PairingFailed),
        _ => Err(Error::Protocol("expected PairConfirm")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;

    fn window(limits: PairingLimits) -> (PairingWindow, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::new());
        (PairingWindow::new(clock.clone(), limits), clock)
    }

    #[test]
    fn a_code_allows_exactly_its_attempt_budget_even_in_parallel() {
        let (w, _) = window(PairingLimits::default());
        let _code = w.issue_code().unwrap();
        let w = Arc::new(w);
        let granted: usize = (0..16)
            .map(|_| {
                let w = w.clone();
                std::thread::spawn(move || w.begin(PairMode::Code, &[]).is_some())
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| usize::from(h.join().unwrap()))
            .sum();
        assert_eq!(granted, 3);
        assert!(!w.is_open());
    }

    #[test]
    fn a_secret_can_be_spent_once() {
        let (w, _) = window(PairingLimits::default());
        let t = w.issue_token().unwrap();
        let a = w.begin(PairMode::Token, &t.id()).unwrap();
        let b = w.begin(PairMode::Token, &t.id()).unwrap();
        assert!(w.consume(&a));
        assert!(!w.consume(&b));
        assert!(w.begin(PairMode::Token, &t.id()).is_none());
        assert!(!w.is_open());
    }

    #[test]
    fn tokens_expire_and_unknown_ids_are_unknown() {
        let (w, clock) = window(PairingLimits::default());
        let t = w.issue_token().unwrap();
        assert!(w.begin(PairMode::Token, &[0u8; TOKEN_ID_LEN]).is_none());
        assert!(w.begin(PairMode::Token, &[1, 2, 3]).is_none());
        clock.advance(Duration::from_secs(15 * 60 - 1));
        assert!(w.is_open());
        clock.advance(Duration::from_secs(2));
        assert!(!w.is_open());
        assert!(w.begin(PairMode::Token, &t.id()).is_none());
    }

    #[test]
    fn a_new_code_replaces_the_old_one_and_stale_attempts_cannot_spend_it() {
        let (w, _) = window(PairingLimits::default());
        let _first = w.issue_code().unwrap();
        let stale = w.begin(PairMode::Code, &[]).unwrap();
        let _second = w.issue_code().unwrap();
        assert!(!w.consume(&stale));
        assert!(w.is_open());
    }

    #[test]
    fn closing_the_window_invalidates_everything() {
        let (w, _) = window(PairingLimits::default());
        let t = w.issue_token().unwrap();
        w.issue_code().unwrap();
        w.close();
        assert!(!w.is_open());
        assert!(w.begin(PairMode::Token, &t.id()).is_none());
    }

    #[test]
    fn the_oldest_token_is_dropped_beyond_the_cap() {
        let (w, _) = window(PairingLimits {
            max_tokens: 2,
            ..Default::default()
        });
        let a = w.issue_token().unwrap();
        let _b = w.issue_token().unwrap();
        let _c = w.issue_token().unwrap();
        assert!(w.begin(PairMode::Token, &a.id()).is_none());
    }

    fn transcript<'a>(cs: &PublicKey, ss: &PublicKey, name: &'a str) -> Transcript<'a> {
        Transcript {
            client_spki: cs.spki(),
            server_spki: ss.spki(),
            mode: PairMode::Token,
            token_id: &[7u8; 8],
            client_spake: &[1u8; 33],
            server_spake: &[2u8; 33],
            device_name: name,
            server_name: "srv",
        }
    }

    #[test]
    fn the_mac_depends_on_every_transcript_field_and_on_the_role() {
        let k = |n: u8| IdentityKey::from_seed(&[n; 32]).unwrap().public();
        let (a, b, c) = (k(1), k(2), k(3));
        let key = [9u8; 32];
        let base = transcript(&a, &b, "dev").hash();
        let mac = compute_mac(Role::Client, &key, &base).unwrap();
        assert!(verify_mac(Role::Client, &key, &base, &mac));
        // Different role, key, transcript, length: all fail.
        assert!(!verify_mac(Role::Server, &key, &base, &mac));
        assert!(!verify_mac(Role::Client, &[8u8; 32], &base, &mac));
        assert!(!verify_mac(Role::Client, &key, &base, &mac[..31]));
        for other in [
            transcript(&c, &b, "dev").hash(),
            transcript(&a, &c, "dev").hash(),
            transcript(&a, &b, "dev2").hash(),
        ] {
            assert_ne!(other, base);
            assert!(!verify_mac(Role::Client, &key, &other, &mac));
        }
        // Swapping the two keys (a reflection) changes the transcript too.
        assert_ne!(transcript(&b, &a, "dev").hash(), base);
    }

    #[test]
    fn spake2_agrees_only_for_the_same_password() {
        let run = |pa: &[u8], pb: &[u8]| {
            let (sa, ma) = Spake2::<Ed25519Group>::start_a(
                &Password::new(pa),
                &Identity::new(ID_CLIENT),
                &Identity::new(ID_SERVER),
            );
            let (sb, mb) = Spake2::<Ed25519Group>::start_b(
                &Password::new(pb),
                &Identity::new(ID_CLIENT),
                &Identity::new(ID_SERVER),
            );
            assert_eq!((ma.len(), mb.len()), (SPAKE_LEN, SPAKE_LEN));
            (sa.finish(&mb).unwrap(), sb.finish(&ma).unwrap())
        };
        let (ka, kb) = run(b"hx-pair-codeABCD1234", b"hx-pair-codeABCD1234");
        assert_eq!(ka, kb);
        let (ka, kb) = run(b"hx-pair-codeABCD1234", b"hx-pair-codeABCD1235");
        assert_ne!(ka, kb);
    }
}
