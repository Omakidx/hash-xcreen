//! Self-update of the agent (docs/ipc.md 6.12, architecture 5.5). The commands are in
//! `privd::cmd::update`; this module holds what they are made of.
//!
//! # The flow
//!
//! ```text
//!  CheckUpdate                                   ApplyUpdate(version)
//!  ───────────                                   ────────────────────
//!  sweep the fetch dir (unlinkat, by fd)         the staged manifest must name `version`;
//!  systemctl start hx-update-fetcher@manifest-<ch>   it must be newer than the running version,
//!  read manifest + .minisig once (openat2)           for this arch, min_previous satisfied
//!  minisign verify against the embedded keys     fetcher: artifact-<version>
//!  parse and check every field                   read once into an O_TMPFILE, SHA-256 + size
//!  freshness: timestamp >= updates-state             against the signed manifest
//!  stage manifest + signature (root-only)        preupdate snapshot of each desktop (best effort)
//!  report `available`                            extract (openat2 BENEATH) into .incoming-*, check, rename
//!                                                record `pending`, switch previous/current
//!                                                answer `restarting`; then restart gatewayd, re-exec privd
//!
//!  new privd, at start: `Daemon::resume_update`
//!  pending? -> health check (privd answers, gatewayd stable 30 s, admin Status) within 90 s
//!              ok  -> clear pending and the rolled-back record, prune to two versions
//!              bad -> flip back, restart both, needs_attention=UPDATE_ROLLED_BACK
//! ```
//!
//! # Modules
//!
//! | Module | Role |
//! |---|---|
//! | [`version`] | the strict version syntax (rule 1) and its order |
//! | [`manifest`] | the signed manifest and its field checks |
//! | [`keys`], [`verify`] | the embedded current and next minisign keys, SHA-256 |
//! | [`fetchdir`] | reading the hostile fetch directory once (rule 2) |
//! | [`state`] | `updates-state`: freshness, pending, last rollback (rule 3) |
//! | [`extract`] | safe extraction (rule 4) |
//! | [`switch`] | `/usr/lib/hx/<version>/`, `current` and `previous` |
//! | [`health`] | the 90 s health check |
//! | [`system`] | the systemd and socket seams (fakes in tests) |

pub mod beneath;
pub mod extract;
pub mod fetchdir;
pub mod health;
pub mod keys;
pub mod manifest;
pub mod state;
pub mod switch;
pub mod system;
pub mod verify;
pub mod version;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::fetcher::Channel;
use crate::privd::runner::CommandRunner;

pub use health::HealthPolicy;
pub use keys::UpdateKeys;
pub use system::{HealthProbe, SocketProbe, Systemd, SystemdCtl, Unit};

/// Where the agent's releases live.
pub const VERSIONS_DIR: &str = "/usr/lib/hx";
/// privd's policy file (ipc.md 2); only `[update] channel` is read.
pub const POLICY_FILE: &str = "/etc/hx/privd.toml";
/// gatewayd's admin socket.
pub const ADMIN_SOCKET: &str = "/run/hx/gatewayd-admin.sock";

/// Paths and policy of the update path, fixed at construction like the rest of
/// [`PrivdConfig`](crate::privd::PrivdConfig).
#[derive(Debug, Clone)]
pub struct UpdateConfig {
    /// `/usr/lib/hx`: the version directories and the `current` and `previous` links.
    pub versions_dir: PathBuf,
    /// Where the fetcher writes (`/var/lib/hx/updates`, bind-mounted into its unit).
    pub fetch_dir: PathBuf,
    /// privd's verified copies (`/var/lib/hx/staging`), root-only.
    pub staging_dir: PathBuf,
    /// The version of the running binary.
    pub running_version: String,
    /// This host's architecture, as in manifests and artifact names.
    pub arch: String,
    /// The release channel (from `privd.toml`, never from a request).
    pub channel: Channel,
    /// Health check timing.
    pub health: HealthPolicy,
    /// How long after answering `ApplyUpdate` privd waits before it restarts the units, so that
    /// the response reaches the caller first.
    pub restart_grace: Duration,
    /// gatewayd's admin socket.
    pub admin_socket: PathBuf,
}

impl UpdateConfig {
    /// The production values, with the channel read from `privd.toml`.
    pub fn production(state_dir: &Path) -> Self {
        Self {
            versions_dir: VERSIONS_DIR.into(),
            fetch_dir: state_dir.join("updates"),
            staging_dir: state_dir.join("staging"),
            running_version: env!("CARGO_PKG_VERSION").to_string(),
            arch: std::env::consts::ARCH.to_string(),
            channel: read_channel(Path::new(POLICY_FILE)),
            health: HealthPolicy::default(),
            restart_grace: Duration::from_millis(1500),
            admin_socket: ADMIN_SOCKET.into(),
        }
    }

    /// Values for tests, rooted in `dir`: version 1.0.0, the host's architecture, fast timings.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_tests(dir: &Path) -> Self {
        Self {
            versions_dir: dir.join("lib-hx"),
            fetch_dir: dir.join("state").join("updates"),
            staging_dir: dir.join("state").join("staging"),
            running_version: "1.0.0".into(),
            arch: std::env::consts::ARCH.to_string(),
            channel: Channel::Stable,
            health: HealthPolicy {
                window: Duration::from_millis(600),
                stable: Duration::from_millis(60),
                poll: Duration::from_millis(10),
            },
            restart_grace: Duration::from_millis(10),
            admin_socket: dir.join("gatewayd-admin.sock"),
        }
    }
}

/// Reads `[update] channel` from the policy file. The file must be a regular file owned by the
/// effective uid and writable by nobody else, or it is ignored; a missing file, an unknown value
/// and any parse problem mean `stable`.
pub fn read_channel(path: &Path) -> Channel {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let Ok(f) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
    else {
        return Channel::Stable;
    };
    let Ok(m) = f.metadata() else {
        return Channel::Stable;
    };
    if !m.is_file() || m.uid() != rustix::process::geteuid().as_raw() || m.mode() & 0o022 != 0 {
        crate::privd::log::warn(
            "privd.toml is not a root-owned, private file; using the stable channel",
        );
        return Channel::Stable;
    }
    let mut text = String::new();
    if f.take(64 * 1024).read_to_string(&mut text).is_err() {
        return Channel::Stable;
    }
    text.parse::<toml::Table>()
        .ok()
        .and_then(|t| {
            t.get("update")?
                .get("channel")?
                .as_str()
                .and_then(Channel::parse)
        })
        .unwrap_or(Channel::Stable)
}

/// The replaceable collaborators of the update path.
pub struct UpdateDeps {
    /// The embedded release keys.
    pub keys: UpdateKeys,
    /// systemd (fetcher, restarts, unit state).
    pub systemd: Arc<dyn Systemd>,
    /// The health probes.
    pub probe: Arc<dyn HealthProbe>,
}

impl UpdateDeps {
    /// The real collaborators: the embedded keys, `systemctl` through `runner`, the real sockets.
    pub fn system(
        runner: Arc<dyn CommandRunner>,
        privd_socket: &Path,
        admin_socket: &Path,
    ) -> Self {
        Self {
            keys: UpdateKeys::embedded(),
            systemd: Arc::new(SystemdCtl::new(runner)),
            probe: Arc::new(SocketProbe {
                privd_socket: privd_socket.to_path_buf(),
                admin_socket: admin_socket.to_path_buf(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn channel_comes_from_a_private_policy_file() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("privd.toml");
        assert_eq!(read_channel(&p), Channel::Stable, "missing file");
        std::fs::write(&p, "[update]\nchannel = \"beta\"\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(read_channel(&p), Channel::Beta);
        std::fs::write(&p, "[update]\nchannel = \"nightly\"\n").unwrap();
        assert_eq!(read_channel(&p), Channel::Stable, "unknown value");
        std::fs::write(&p, "not toml {{").unwrap();
        assert_eq!(read_channel(&p), Channel::Stable, "garbage");
        std::fs::write(&p, "[update]\nchannel = \"beta\"\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(read_channel(&p), Channel::Stable, "writable by others");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let link = d.path().join("link.toml");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert_eq!(read_channel(&link), Channel::Stable, "symlink");
    }
}
