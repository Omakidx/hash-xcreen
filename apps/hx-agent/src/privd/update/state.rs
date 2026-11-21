//! `updates-state` (ipc.md 6.12 rule 3): what privd remembers between updates, in its root-only
//! state directory.
//!
//! | Field | Meaning |
//! |---|---|
//! | `highest_by_channel` | Per channel, the highest manifest timestamp accepted so far; an older manifest of that channel is refused (replay). Never lowered. Per channel so that switching `beta` to `stable` does not make valid stable manifests look like replays. |
//! | `apply_log` | When `ApplyUpdate` was last admitted (a day's worth): the 2-a-day limit survives a restart of privd. |
//! | `manual_rollback` | The last release an Admin rolled back; re-applying it is Admin-only for 24 h, like a release that failed its health check. |
//! | `verified_version` | The version whose manifest and signature privd holds in `staging/` after a successful `CheckUpdate`. |
//! | `pending` | An update that was switched in and has not yet passed its health check. Present across the re-exec; the **new** privd reads it at start and finishes the check (or rolls back). |
//! | `rolled_back` | The last automatic rollback (version and reason); cleared when an update succeeds. |
//!
//! Written atomically like the rest of privd's state, and refused (not reset) when corrupt.

use std::collections::BTreeMap;
use std::io;

use serde::{Deserialize, Serialize};

use crate::privd::state::StateStore;

/// File name in the state directory.
pub const FILE: &str = "updates-state";

/// An update switched in but not yet confirmed healthy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    /// The version that was switched in.
    pub version: String,
    /// The version `current` pointed at before (the rollback target).
    pub previous: Option<String>,
    /// When it was switched in, Unix seconds (the 90 s window counts from here).
    pub started_unix: u64,
    /// How many times a privd has started with this pending record (a crash loop of the new
    /// binary ends in a rollback instead of an endless restart).
    #[serde(default)]
    pub attempts: u32,
    /// gatewayd's `MainPID` before the switch: the health check requires a different one, which
    /// proves gatewayd restarted into the new binary.
    #[serde(default)]
    pub gateway_pid: Option<u32>,
}

/// The last automatic rollback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolledBack {
    /// The version that failed.
    pub version: String,
    /// Why (privd's own sanitized text).
    pub reason: String,
    /// When, Unix seconds.
    pub at: u64,
}

/// The persisted state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct UpdateState {
    /// Highest accepted manifest timestamp, per channel.
    #[serde(default)]
    pub highest_by_channel: BTreeMap<String, u64>,
    /// When `ApplyUpdate` was admitted, Unix seconds (entries older than a day are dropped).
    #[serde(default)]
    pub apply_log: Vec<u64>,
    /// The last release an Admin rolled back.
    #[serde(default)]
    pub manual_rollback: Option<RolledBack>,
    /// Version of the verified manifest held in staging.
    #[serde(default)]
    pub verified_version: Option<String>,
    /// An update awaiting its health check.
    #[serde(default)]
    pub pending: Option<Pending>,
    /// The last automatic rollback.
    #[serde(default)]
    pub rolled_back: Option<RolledBack>,
}

impl UpdateState {
    /// Loads it; a missing file is the default, a corrupt one an error.
    pub fn load(store: &StateStore) -> io::Result<Self> {
        store.load_json(FILE)
    }

    /// Saves it atomically.
    pub fn save(&self, store: &StateStore) -> io::Result<()> {
        store.save_json(FILE, self)
    }

    /// Whether a manifest dated `ts` is fresh: not older than the highest accepted so far.
    pub fn is_fresh(&self, channel: &str, ts: u64) -> bool {
        ts >= self.highest(channel)
    }

    /// The highest timestamp accepted on `channel` (0 if none).
    pub fn highest(&self, channel: &str) -> u64 {
        self.highest_by_channel.get(channel).copied().unwrap_or(0)
    }

    /// Records an accepted timestamp (never lowers it).
    pub fn accept(&mut self, channel: &str, ts: u64) {
        let e = self
            .highest_by_channel
            .entry(channel.to_string())
            .or_insert(0);
        *e = (*e).max(ts);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freshness_is_monotonic_and_persists() {
        let d = tempfile::tempdir().unwrap();
        let store = StateStore::open(d.path()).unwrap();
        let mut s = UpdateState::load(&store).unwrap();
        assert!(s.is_fresh("stable", 1));
        s.accept("stable", 100);
        s.accept("stable", 50);
        assert_eq!(s.highest("stable"), 100);
        // Another channel has its own counter.
        assert!(s.is_fresh("beta", 1));
        s.accept("beta", 5_000);
        assert!(s.is_fresh("stable", 100) && !s.is_fresh("beta", 4_999));
        s.save(&store).unwrap();
        let again = UpdateState::load(&store).unwrap();
        assert!(again.is_fresh("stable", 100));
        assert!(!again.is_fresh("stable", 99));
        std::fs::write(store.path(FILE), b"{oops").unwrap();
        assert!(UpdateState::load(&store).is_err());
    }
}
