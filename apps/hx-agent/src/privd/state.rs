//! privd's persistent state: the phase and the setup window, the desktop registry and the
//! `needs_attention` flags, in a root-only directory.
//!
//! # On-disk layout (`PrivdConfig::state_dir`, default `/var/lib/hx`, mode 0700)
//!
//! | File | Content | Mode |
//! |---|---|---|
//! | `privd-state` | JSON: phase and setup window, desktop registry, attention flags, host setup record | 0600 |
//! | `ratelimit` | JSON: failure logs and locks of `PepperVerify`, enrol and current-password check logs | 0600 |
//! | `pepper.key` | 32 random bytes, the verifier pepper (never sent; `systemd-creds` sealing is a follow-up) | 0600 |
//! | `owner-key` | the enrolled owner public key (Phase 2 shape) | 0644 |
//!
//! Every write is atomic (temporary file, `fsync`, `rename`, `fsync` of the directory). A file that
//! exists but cannot be parsed is an error, not a reset: privd refuses to start rather than
//! silently clear a lockout or a window (fail closed).

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use hx_ipc::privd::pb;
use rustix::fs::OFlags;
use serde::{Deserialize, Serialize};

/// The phase of ipc.md 5.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PhaseKind {
    /// Nothing has been set up.
    #[default]
    Uninitialized,
    /// The setup window is open.
    SetupOpen,
    /// Set up; the window is closed.
    Ready,
}

impl PhaseKind {
    /// The wire value.
    pub fn to_pb(self) -> pb::Phase {
        match self {
            Self::Uninitialized => pb::Phase::Uninitialized,
            Self::SetupOpen => pb::Phase::SetupOpen,
            Self::Ready => pb::Phase::Ready,
        }
    }
}

/// A `needs_attention` flag (ipc.md 5.1, 6.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Flag {
    /// The host account policy self-check failed.
    HostAccountPolicy,
    /// An Incus operation could not be ended (per desktop).
    StuckOperation,
    /// Docker's rollback failed; the desktop may run with nesting on (per desktop).
    IsolationNotRestored,
    /// The PIN purpose is locked.
    PinLocked,
    /// The password purpose is locked.
    PasswordLocked,
    /// An update was rolled back.
    UpdateRolledBack,
    /// The `DOCKER-USER` rules could not be applied.
    HostDockerForwarding,
}

impl Flag {
    /// The wire value.
    pub fn to_pb(self) -> pb::NeedsAttention {
        match self {
            Self::HostAccountPolicy => pb::NeedsAttention::HostAccountPolicy,
            Self::StuckOperation => pb::NeedsAttention::StuckOperation,
            Self::IsolationNotRestored => pb::NeedsAttention::IsolationNotRestored,
            Self::PinLocked => pb::NeedsAttention::PinLocked,
            Self::PasswordLocked => pb::NeedsAttention::PasswordLocked,
            Self::UpdateRolledBack => pb::NeedsAttention::UpdateRolledBack,
            Self::HostDockerForwarding => pb::NeedsAttention::HostDockerForwarding,
        }
    }
}

/// The phase and the setup window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PhaseRecord {
    /// Current phase (before applying the window's expiry; see [`PrivdState::expire_window`]).
    pub phase: PhaseKind,
    /// The phase to return to when the window expires.
    pub return_to: PhaseKind,
    /// Unix seconds at which the open window began (0 when closed).
    pub window_started: u64,
    /// Unix seconds at which it closes (0 when closed).
    pub window_expires: u64,
}

/// A desktop privd knows about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DesktopRecord {
    /// Per-desktop attention flags.
    #[serde(default)]
    pub flags: BTreeSet<Flag>,
}

/// What the last `SetupHost` asked for, so that the automatic re-run (ipc.md 6.4, last paragraph)
/// regenerates the same ruleset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct HostSetupRecord {
    /// `allow_private_networks` as given by Admin.
    pub allow_private_networks: bool,
    /// `extra_host_addresses` as given by Admin.
    pub extra_host_addresses: Vec<String>,
}

/// The whole persisted state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PrivdState {
    /// Phase and window.
    #[serde(default)]
    pub phase: PhaseRecord,
    /// Registered desktops by id (privd only manages desktops it created).
    #[serde(default)]
    pub desktops: BTreeMap<String, DesktopRecord>,
    /// Host-wide attention flags.
    #[serde(default)]
    pub flags: BTreeSet<Flag>,
    /// The last successful `SetupHost`.
    #[serde(default)]
    pub host: Option<HostSetupRecord>,
}

impl PrivdState {
    /// Closes the window if it has expired at `now`, returning to the phase it was opened from.
    /// Returns whether the state changed.
    pub fn expire_window(&mut self, now: u64) -> bool {
        let p = &mut self.phase;
        if p.phase == PhaseKind::SetupOpen && now >= p.window_expires {
            p.phase = p.return_to;
            p.window_started = 0;
            p.window_expires = 0;
            return true;
        }
        false
    }

    /// Flags of one desktop plus the host-wide ones, in a stable order.
    pub fn attention_for(&self, desktop_id: &str) -> Vec<Flag> {
        let mut all: BTreeSet<Flag> = self.flags.clone();
        if let Some(d) = self.desktops.get(desktop_id) {
            all.extend(d.flags.iter().copied());
        }
        all.into_iter().collect()
    }
}

/// Reads and writes the files of the state directory.
#[derive(Debug, Clone)]
pub struct StateStore {
    dir: PathBuf,
}

impl StateStore {
    /// Opens (creating, mode 0700, if needed) the state directory.
    pub fn open(dir: &Path) -> io::Result<Self> {
        match std::fs::symlink_metadata(dir) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "the state path exists and is not a directory",
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(dir)?;
            }
            Err(e) => return Err(e),
        }
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Path of a file in the directory.
    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// The persisted state; a missing file is the default state, an unparseable one an error.
    pub fn load_state(&self) -> io::Result<PrivdState> {
        self.load_json("privd-state")
    }

    /// Persists the state.
    pub fn save_state(&self, s: &PrivdState) -> io::Result<()> {
        self.save_json("privd-state", s)
    }

    /// Loads a JSON file; missing means `T::default()`.
    pub fn load_json<T: for<'de> Deserialize<'de> + Default>(&self, name: &str) -> io::Result<T> {
        match std::fs::read(self.path(name)) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{name} is corrupt ({e}); refusing to reset it"),
                )
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(T::default()),
            Err(e) => Err(e),
        }
    }

    /// Atomically writes a JSON file (mode 0600).
    pub fn save_json<T: Serialize>(&self, name: &str, v: &T) -> io::Result<()> {
        let bytes = serde_json::to_vec(v).map_err(io::Error::other)?;
        write_atomic(&self.path(name), &bytes, 0o600)
    }
}

/// Writes `bytes` to `path` atomically with `mode`: a sibling temporary file (never followed if it
/// is a symlink), `fsync`, `rename`, then `fsync` of the directory.
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no parent directory"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
    let mut tmp_name = name.to_os_string();
    tmp_name.push(".tmp");
    let tmp = dir.join(tmp_name);
    // A stale temporary file from a crash is replaced; O_NOFOLLOW refuses a planted symlink.
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)?;
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_expiry_returns_to_the_phase_it_was_opened_from() {
        let mut s = PrivdState {
            phase: PhaseRecord {
                phase: PhaseKind::SetupOpen,
                return_to: PhaseKind::Ready,
                window_started: 100,
                window_expires: 200,
            },
            ..PrivdState::default()
        };
        assert!(!s.expire_window(199));
        assert_eq!(s.phase.phase, PhaseKind::SetupOpen);
        assert!(s.expire_window(200));
        assert_eq!(s.phase.phase, PhaseKind::Ready);
        assert!(!s.expire_window(300));
    }

    #[test]
    fn state_round_trips_and_corruption_is_an_error() {
        let d = tempfile::tempdir().unwrap();
        let store = StateStore::open(&d.path().join("s")).unwrap();
        assert_eq!(store.load_state().unwrap(), PrivdState::default());
        let mut s = PrivdState::default();
        s.desktops.insert("main".into(), DesktopRecord::default());
        s.flags.insert(Flag::PinLocked);
        store.save_state(&s).unwrap();
        assert_eq!(store.load_state().unwrap(), s);
        let mode = std::fs::metadata(store.path("privd-state"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::write(store.path("privd-state"), b"{not json").unwrap();
        assert!(store.load_state().is_err());
    }

    #[test]
    fn attention_merges_host_and_desktop_flags() {
        let mut s = PrivdState::default();
        s.flags.insert(Flag::PinLocked);
        s.desktops
            .entry("main".into())
            .or_default()
            .flags
            .insert(Flag::StuckOperation);
        assert_eq!(
            s.attention_for("main"),
            vec![Flag::StuckOperation, Flag::PinLocked]
        );
        assert_eq!(s.attention_for("other"), vec![Flag::PinLocked]);
    }
}
