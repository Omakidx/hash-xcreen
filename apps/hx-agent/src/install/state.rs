//! `install-state.json` (design C7): what the installer did, so that a failed run resumes, a
//! complete one is re-verified, and uninstall knows what it created.
//!
//! **No secret is ever in it.** It holds the normalized options (no password, PIN or token), the
//! public identity key, stage results and the list of objects the installer created. It is
//! written atomically with [`crate::privd::state::write_atomic`], root-only (0600).

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::options::Options;
use crate::privd::state::write_atomic;

/// The schema version.
pub const SCHEMA: u32 = 1;

/// The stage ids, in order (design D3).
pub const STAGES: [&str; 19] = [
    "preflight",
    "packages",
    "incus",
    "release",
    "system-files",
    "credentials",
    "config",
    "units",
    "setup-window",
    "host",
    "firewall-port",
    "pairing-token",
    "desktop",
    "verifiers",
    "owner-key",
    "backup",
    "pairing",
    "finish",
    "done",
];

/// One stage's result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StageRecord {
    /// `done`, `failed`, `deferred`, `manual` or `skipped`.
    pub state: String,
    /// When (Unix seconds).
    pub at: u64,
    /// The failure, when `state` is `failed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<StageError>,
}

/// A recorded failure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StageError {
    /// The class (`TOOL`, `VERIFY`, ...).
    pub code: String,
    /// Sanitized text.
    pub message: String,
    /// A re-run may help.
    pub retryable: bool,
}

/// The port rule the installer added.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PortRule {
    /// `ufw`, `nft`, `manual` or `none`.
    pub backend: String,
    /// The port the rule opens.
    pub port: u16,
    /// ufw protocols (`tcp`, `udp`) whose rule already existed before the installer ran: they
    /// are the administrator's and uninstall leaves them.
    #[serde(default)]
    pub adopted: Vec<String>,
}

/// Incus as the installer found or installed it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct IncusRecord {
    /// The installer installed the package (false: adopted).
    pub by_installer: bool,
    /// `distro`, `zabbly` or `existing`.
    pub source: String,
    /// The version text, as far as known.
    pub version: String,
}

/// Objects the installer created (the uninstall list).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Created {
    /// Files written (absolute system paths).
    pub files: Vec<String>,
    /// Drop-in files written.
    pub dropins: Vec<String>,
    /// Packages the installer installed.
    pub packages: Vec<String>,
    /// Incus.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incus: Option<IncusRecord>,
    /// apt files written (they stay on uninstall).
    pub apt: Vec<String>,
    /// The port rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_rule: Option<PortRule>,
    /// The installer created the `hx-gatewayd` user.
    pub user: bool,
    /// The port the public socket drop-in currently names.
    #[serde(default)]
    pub socket_port: u16,
}

/// What `CreateDesktop` reported.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DesktopReport {
    /// The desktop id.
    pub id: String,
    /// `PREBUILT` or `BUILD`.
    pub path_taken: String,
    /// Why.
    pub reason: String,
    /// Warnings of privd.
    pub warnings: Vec<String>,
}

/// The whole file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstallState {
    /// [`SCHEMA`].
    pub schema: u32,
    /// 32 hex characters, chosen at the first run.
    pub install_id: String,
    /// The version of the agent that wrote it.
    pub agent_version: String,
    /// `ssh`, `pair`, `token` or `interactive`.
    pub mode: String,
    /// The normalized options.
    pub options: Options,
    /// The agent's Ed25519 public key (64 hex), derived when the seed was generated.
    #[serde(default)]
    pub server_public_key: String,
    /// Results by stage id.
    pub stages: BTreeMap<String, StageRecord>,
    /// What was created.
    pub created: Created,
    /// The desktop report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desktop: Option<DesktopReport>,
    /// Notes for the operator that outlive the run (a nameserver that was not allowed, ...).
    #[serde(default)]
    pub notes: Vec<String>,
    /// Every stage of the mode is done.
    pub complete: bool,
    /// Last write (Unix seconds).
    pub updated_unix: u64,
}

impl InstallState {
    /// A fresh state.
    pub fn new(install_id: String, mode: &str, options: Options, now: u64) -> Self {
        Self {
            schema: SCHEMA,
            install_id,
            agent_version: env!("CARGO_PKG_VERSION").to_owned(),
            mode: mode.to_owned(),
            options,
            server_public_key: String::new(),
            stages: BTreeMap::new(),
            created: Created::default(),
            desktop: None,
            notes: Vec::new(),
            complete: false,
            updated_unix: now,
        }
    }

    /// `id` is recorded as done (or skipped, deferred or manual: it has run to its end).
    pub fn finished(&self, id: &str) -> bool {
        self.stages
            .get(id)
            .is_some_and(|r| matches!(r.state.as_str(), "done" | "deferred" | "manual" | "skipped"))
    }

    /// `id` is recorded as `done`.
    pub fn is_done(&self, id: &str) -> bool {
        self.stages.get(id).is_some_and(|r| r.state == "done")
    }

    /// Records a result.
    pub fn record(&mut self, id: &str, state: &str, now: u64, error: Option<StageError>) {
        self.stages.insert(
            id.to_owned(),
            StageRecord {
                state: state.to_owned(),
                at: now,
                error,
            },
        );
        self.updated_unix = now;
    }

    /// Adds `path` to the created files once.
    pub fn created_file(&mut self, path: &str) {
        if !self.created.files.iter().any(|f| f == path) {
            self.created.files.push(path.to_owned());
        }
    }

    /// Adds `path` to the created drop-ins once.
    pub fn created_dropin(&mut self, path: &str) {
        if !self.created.dropins.iter().any(|f| f == path) {
            self.created.dropins.push(path.to_owned());
        }
    }
}

/// Loads the state file. `Ok(None)` when it does not exist.
pub fn load(path: &Path) -> io::Result<Option<InstallState>> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let st: InstallState = serde_json::from_slice(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "install-state.json is corrupt"))?;
    if st.schema != SCHEMA {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "install-state.json has an unknown schema",
        ));
    }
    Ok(Some(st))
}

/// Saves the state atomically, root-only.
pub fn save(path: &Path, st: &InstallState) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut bytes = serde_json::to_vec_pretty(st).map_err(io::Error::other)?;
    bytes.push(b'\n');
    write_atomic(path, &bytes, 0o600)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stage_ids_are_unique_and_end_with_done() {
        let mut v = STAGES.to_vec();
        v.sort_unstable();
        v.dedup();
        assert_eq!(v.len(), STAGES.len());
        assert_eq!(STAGES[STAGES.len() - 1], "done");
    }

    #[test]
    fn state_round_trips_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("v/install-state.json");
        assert!(load(&p).unwrap().is_none());
        let mut st = InstallState::new("ab".repeat(16), "ssh", Options::default(), 5);
        st.record("packages", "done", 6, None);
        st.created_file("/etc/hx/gatewayd.toml");
        st.created_file("/etc/hx/gatewayd.toml");
        save(&p, &st).unwrap();
        assert_eq!(load(&p).unwrap().unwrap(), st);
        assert_eq!(st.created.files.len(), 1);
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::write(&p, b"{").unwrap();
        assert!(load(&p).is_err());
    }
}
