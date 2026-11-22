//! `images-state` (docs/ipc.md 2 and 6.5): what privd remembers about prebuilt images, in its
//! root-only state directory.
//!
//! | Field | Meaning |
//! |---|---|
//! | `highest_manifest_ts` | The highest images-manifest timestamp accepted **online**; an older manifest is refused (a replayed old, signed manifest that still lists vulnerable images). Never lowered. The offline path neither checks nor updates it. |
//! | `cached` | The `hx-img-*` images privd imported into Incus and has not deleted yet (fingerprint, recipe, build id, import time). A retried `CreateDesktop` reuses one that is still the selected entry and at most 7 days old; `Uninstall` deletes every one. |
//!
//! Written atomically like the rest of privd's state, and refused (not reset) when corrupt. A
//! record is written **before** the import starts, so a crash between the import and the next
//! bookkeeping step leaves a record to clean up, never an unrecorded image.

use std::io;

use serde::{Deserialize, Serialize};

use crate::privd::state::StateStore;

/// File name in the state directory.
pub const FILE: &str = "images-state";

/// How long a cached image may be reused: 7 days.
pub const CACHE_MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;

/// An image privd imported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedImage {
    /// SHA-256 of the image file, which is its Incus fingerprint.
    pub fingerprint: String,
    /// The recipe name.
    pub recipe: String,
    /// The build id of the manifest entry.
    pub build_id: String,
    /// When privd started importing it, Unix seconds.
    pub imported_unix: u64,
}

/// The persisted state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ImagesState {
    /// Highest accepted online manifest timestamp.
    #[serde(default)]
    pub highest_manifest_ts: u64,
    /// Images privd imported and has not deleted.
    #[serde(default)]
    pub cached: Vec<CachedImage>,
}

/// Most records kept (a runaway list is a bug, not data).
pub const MAX_CACHED: usize = 8;

impl ImagesState {
    /// Loads it; a missing file is the default, a corrupt one an error.
    pub fn load(store: &StateStore) -> io::Result<Self> {
        store.load_json(FILE)
    }

    /// Saves it atomically.
    pub fn save(&self, store: &StateStore) -> io::Result<()> {
        store.save_json(FILE, self)
    }

    /// Whether an online manifest dated `ts` is fresh: not older than the highest accepted.
    pub fn is_fresh(&self, ts: u64) -> bool {
        ts >= self.highest_manifest_ts
    }

    /// Records an accepted timestamp (never lowers it).
    pub fn accept(&mut self, ts: u64) {
        self.highest_manifest_ts = self.highest_manifest_ts.max(ts);
    }

    /// The record of `fingerprint`.
    pub fn find(&self, fingerprint: &str) -> Option<&CachedImage> {
        self.cached.iter().find(|c| c.fingerprint == fingerprint)
    }

    /// Adds or replaces a record.
    pub fn insert(&mut self, c: CachedImage) {
        self.cached.retain(|x| x.fingerprint != c.fingerprint);
        self.cached.push(c);
        // Keep the newest few; older ones were never going to be cleaned up by a healthy run.
        if self.cached.len() > MAX_CACHED {
            let extra = self.cached.len() - MAX_CACHED;
            self.cached.drain(..extra);
        }
    }

    /// Drops the record of `fingerprint`; whether there was one.
    pub fn remove(&mut self, fingerprint: &str) -> bool {
        let n = self.cached.len();
        self.cached.retain(|c| c.fingerprint != fingerprint);
        self.cached.len() != n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(fp: &str, at: u64) -> CachedImage {
        CachedImage {
            fingerprint: fp.into(),
            recipe: "ubuntu-24.04-xfce-basic".into(),
            build_id: "20261123.1".into(),
            imported_unix: at,
        }
    }

    #[test]
    fn freshness_is_monotonic_and_persists() {
        let d = tempfile::tempdir().unwrap();
        let store = StateStore::open(d.path()).unwrap();
        let mut s = ImagesState::load(&store).unwrap();
        assert!(s.is_fresh(1));
        s.accept(100);
        s.accept(50);
        assert_eq!(s.highest_manifest_ts, 100);
        assert!(s.is_fresh(100) && !s.is_fresh(99));
        s.insert(rec("aa", 5));
        s.save(&store).unwrap();
        let again = ImagesState::load(&store).unwrap();
        assert_eq!(again, s);
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(store.path(FILE)).unwrap().permissions(),
        );
        assert_eq!(mode & 0o777, 0o600);
        std::fs::write(store.path(FILE), b"{oops").unwrap();
        assert!(ImagesState::load(&store).is_err());
    }

    #[test]
    fn records_are_replaced_removed_and_bounded() {
        let mut s = ImagesState::default();
        s.insert(rec("a", 1));
        s.insert(rec("a", 2));
        assert_eq!(s.cached.len(), 1);
        assert_eq!(s.find("a").unwrap().imported_unix, 2);
        assert!(s.remove("a") && !s.remove("a"));
        for i in 0..20 {
            s.insert(rec(&format!("{i:02}"), i));
        }
        assert_eq!(s.cached.len(), MAX_CACHED);
        assert!(s.find("19").is_some() && s.find("00").is_none());
    }
}
