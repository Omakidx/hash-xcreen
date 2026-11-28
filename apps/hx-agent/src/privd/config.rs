//! Where privd's files live, and the identity it serves.
//!
//! [`PrivdConfig::production`] is the only constructor reachable from the binary: every path is a
//! compiled-in constant, and the gateway uid comes from the passwd entry of the compiled-in user
//! name. There is no configuration file, environment variable or argument that changes any of
//! this. (The tests build their own with `for_tests`, behind the `test-support` feature.)

use std::path::PathBuf;

use hx_provision::host::Naming;

use super::identity::{FileMeta, GatewayIdentity, IdentityError, resolve_gateway_from};
use super::image::ImageConfig;
use super::update::UpdateConfig;

/// The privd socket (ipc.md 3).
pub const SOCKET_PATH: &str = "/run/hx/privd.sock";
/// privd's root-only state directory (the unit's `StateDirectory=hx`).
pub const STATE_DIR: &str = "/var/lib/hx";
/// The persisted host ruleset that `hx-host-firewall.service` loads at boot.
pub const FIREWALL_FILE: &str = "/etc/hx/host-firewall.nft";
/// The sysctl drop-in (ipc.md 6.4).
pub const SYSCTL_FILE: &str = "/etc/sysctl.d/90-hx-incus.conf";
/// The audit log (the unit's `LogsDirectory=hx`).
pub const AUDIT_LOG: &str = "/var/log/hx/audit.log";

/// The one value taken from the environment: systemd's `$CREDENTIALS_DIRECTORY`. It is used only
/// if it names a directory under `/run/credentials/` (where systemd puts a service's credentials),
/// so no other path can be substituted; an unset variable (a development run) means no credential.
fn credentials_dir_from_env() -> Option<PathBuf> {
    let v = std::env::var_os("CREDENTIALS_DIRECTORY")?;
    let p = PathBuf::from(v);
    (p.starts_with("/run/credentials/") && !p.components().any(|c| c.as_os_str() == ".."))
        .then_some(p)
}

/// uid and gid of the desktop user inside the container, from the recipe (ipc.md 6.11).
pub const DESKTOP_IDS: (u32, u32) = (1000, 1000);

/// Everything privd needs to know about the host, fixed at construction.
#[derive(Debug, Clone)]
pub struct PrivdConfig {
    /// The privd socket (`/run/hx/privd.sock`).
    pub socket_path: PathBuf,
    /// Mode and owner the socket must have (self-check).
    pub expected_socket: FileMeta,
    /// systemd's credential directory of this unit (`$CREDENTIALS_DIRECTORY`), where the unit's
    /// `LoadCredentialEncrypted=pepper:...` puts the decrypted pepper.
    pub credentials_dir: Option<PathBuf>,
    /// Root-only state directory (`/var/lib/hx`).
    pub state_dir: PathBuf,
    /// Persisted host firewall ruleset (`/etc/hx/host-firewall.nft`).
    pub firewall_file: PathBuf,
    /// Sysctl drop-in (`/etc/sysctl.d/90-hx-incus.conf`).
    pub sysctl_file: PathBuf,
    /// Append-only audit log (`/var/log/hx/audit.log`).
    pub audit_log: PathBuf,
    /// The Incus socket.
    pub incus_socket: PathBuf,
    /// Incus's data directory (pool free space is read from it).
    pub incus_dir: PathBuf,
    /// privd's verified `hx-session` packages: the `session/<distro>/` directories of the current
    /// release (`/usr/lib/hx/current/session`, ipc.md 6.12 layout).
    pub session_store: PathBuf,
    /// Time zone database for `Settings::with_timezone_in`.
    pub zoneinfo_dir: PathBuf,
    /// Passwd file.
    pub passwd_file: PathBuf,
    /// Group file.
    pub group_file: PathBuf,
    /// The directory of the link sockets (`/run/hx/link`, made by tmpfiles).
    pub link_dir: PathBuf,
    /// What `link_dir` must look like (owner, group, mode; not a symlink) before privd adds a
    /// proxy device whose host side listens in it; `None` skips the check (tests only).
    pub expected_link_dir: Option<FileMeta>,
    /// Names of Incus objects.
    pub naming: Naming,
    /// Prefix of instance names: instance = prefix + desktop id (`hx-` in production; tests of
    /// a real Incus use their own so that every object they create is recognisable).
    pub instance_prefix: String,
    /// The gateway's uid and gid.
    pub gateway: GatewayIdentity,
    /// Most desktops that may exist (v1: 1).
    pub max_desktops: usize,
    /// Paths and policy of self-update (ipc.md 6.12).
    pub update: UpdateConfig,
    /// Paths and timings of the prebuilt-image path (ipc.md 6.5, 6.12).
    pub image: ImageConfig,
    /// Where the sealed credentials live (`/etc/hx/creds`); privd only checks that the Drive
    /// token credential exists there (ipc.md 26, "Admission").
    pub creds_dir: PathBuf,
    /// The directory of the repository-link sockets of backup jobs (`/run/hx/backup`, ipc.md 24).
    pub backup_run_dir: PathBuf,
    /// The Drive helper's socket (`/run/hx/drive.sock`, ipc.md 24).
    pub drive_socket: PathBuf,
    /// The owner that the backup run directory and the backup key credential must have (root in
    /// production); `None` skips the owner checks (tests that run as an ordinary user).
    pub backup_owner: Option<u32>,
}

impl PrivdConfig {
    /// The production configuration. Fails if the gateway user does not exist or has uid 0.
    pub fn production() -> Result<Self, IdentityError> {
        let passwd_file = PathBuf::from("/etc/passwd");
        let gateway = resolve_gateway_from(&passwd_file)?;
        Ok(Self {
            socket_path: SOCKET_PATH.into(),
            expected_socket: FileMeta {
                mode: 0o660,
                uid: 0,
                gid: gateway.gid,
            },
            credentials_dir: credentials_dir_from_env(),
            state_dir: STATE_DIR.into(),
            firewall_file: FIREWALL_FILE.into(),
            sysctl_file: SYSCTL_FILE.into(),
            audit_log: AUDIT_LOG.into(),
            incus_socket: "/var/lib/incus/unix.socket".into(),
            incus_dir: "/var/lib/incus".into(),
            session_store: "/usr/lib/hx/current/session".into(),
            zoneinfo_dir: "/usr/share/zoneinfo".into(),
            passwd_file,
            group_file: "/etc/group".into(),
            link_dir: "/run/hx/link".into(),
            expected_link_dir: Some(FileMeta {
                mode: 0o750,
                uid: 0,
                gid: gateway.gid,
            }),
            naming: Naming::production(),
            instance_prefix: "hx-".into(),
            gateway,
            max_desktops: 1,
            update: UpdateConfig::production(std::path::Path::new(STATE_DIR)),
            image: ImageConfig::production(
                std::path::Path::new(STATE_DIR),
                std::path::Path::new("/var/lib/incus"),
            ),
            creds_dir: "/etc/hx/creds".into(),
            backup_run_dir: "/run/hx/backup".into(),
            drive_socket: "/run/hx/drive.sock".into(),
            backup_owner: Some(0),
        })
    }

    /// A configuration rooted in `dir` with an injected gateway identity, for tests and the
    /// ignored real-Incus test. Not available without the `test-support` feature, and nothing in
    /// the binary calls it.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_tests(dir: &std::path::Path, gateway: GatewayIdentity) -> Self {
        Self {
            socket_path: dir.join("privd.sock"),
            expected_socket: FileMeta {
                mode: 0o755,
                uid: rustix::process::getuid().as_raw(),
                gid: rustix::process::getgid().as_raw(),
            },
            credentials_dir: None,
            state_dir: dir.join("state"),
            firewall_file: dir.join("host-firewall.nft"),
            sysctl_file: dir.join("90-hx-incus.conf"),
            audit_log: dir.join("audit.log"),
            incus_socket: dir.join("incus.sock"),
            incus_dir: dir.join("incus"),
            session_store: dir.join("session"),
            zoneinfo_dir: "/usr/share/zoneinfo".into(),
            passwd_file: dir.join("passwd"),
            group_file: dir.join("group"),
            link_dir: dir.join("link"),
            expected_link_dir: None,
            naming: Naming::production(),
            instance_prefix: "hx-".into(),
            gateway,
            max_desktops: 1,
            update: UpdateConfig::for_tests(dir),
            image: ImageConfig::for_tests(dir),
            creds_dir: dir.join("creds"),
            backup_run_dir: dir.join("run-backup"),
            drive_socket: dir.join("drive.sock"),
            backup_owner: None,
        }
    }

    /// The Incus instance name of a desktop id (`hx-<id>`); the caller never supplies one.
    pub fn instance_name(&self, desktop_id: &str) -> String {
        format!("{}{desktop_id}", self.instance_prefix)
    }
}
