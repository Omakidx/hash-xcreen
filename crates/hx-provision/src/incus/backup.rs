//! The Incus side of the backup helper container (ipc.md Part 3, 24; architecture 9.4 to 9.8).
//!
//! For every backup or restore job `hx-privd` creates one ephemeral, empty, network-less helper
//! container, `hx-bkw-<8 hex digits of the job id>`, whose only content is the static
//! `hx-backup-worker` as `/sbin/init`. Everything that reaches Incus for it is built here, from
//! validated names and constants, the way [`SessionLink`](super::SessionLink) is (ipc.md 7, rule
//! 4): there is no way to add a config key, a device, a profile, a NIC or another path.
//!
//! - [`BackupHelperSpec`] is the instance: the exact config of ipc.md 24, `ephemeral: true`, no
//!   profiles, no image, a 256 MiB root disk on the pool, no NIC;
//! - [`SnapshotMount`] (device `src`) and [`TargetMount`] (device `dst`) are the two disk devices
//!   that hand the desktop's data to the worker, [`RepoLink`] (device `repo`) is the proxy device
//!   of the repository link;
//! - [`RestoreTargetSpec`] is the never-started `init --empty` instance a restore writes into;
//! - [`check_backup_preconditions`] and [`check_restore_preconditions`] are the checks `hx-privd`
//!   makes before each job, because the design depends on Incus internals (architecture 15).
//!
//! The calls are on [`Client`](super::Client): `create_backup_helper`, `populate_backup_helper`,
//! `start_backup_helper`, `finish_backup_helper`, `force_delete_backup_helper`,
//! `list_backup_helpers`, `create_restore_target` and `delete_restore_target`.

use std::collections::BTreeMap;
use std::fmt;

use serde_json::{Value, json};

use super::error::IncusError;
use super::link::SESSION_LINK_DEVICE;
use super::marker::INSTANCE_KEY_PREFIX;
use super::types::{Instance, ServerInfo, Snapshot, StoragePool};

/// Where Incus keeps its storage pools. **This is an Incus internal** (architecture 15): the
/// backup helper mounts paths below it as disk-device sources, and the layout
/// (`containers/<name>/rootfs`, `containers-snapshots/<name>/<snapshot>/rootfs`) is not a
/// documented interface. It is verified on Incus 6.0.0 by the real-Incus test
/// (`tests/incus_real_backup.rs`) and guarded before each job
/// ([`check_backup_preconditions`]). This is the only place the path is written.
pub const STORAGE_POOLS_ROOT: &str = "/var/lib/incus/storage-pools";
/// Prefix of a helper's name (`hx-bkw-` and 8 hex digits of the job id).
pub const HELPER_PREFIX: &str = "hx-bkw-";
/// `user.hx.kind` of a helper (the marker that crash recovery looks for, ipc.md 35).
pub const HELPER_KIND_KEY: &str = "user.hx.kind";
/// Value of [`HELPER_KIND_KEY`] on a helper.
pub const HELPER_KIND: &str = "backup-worker";
/// Key that carries the job id (32 lower-case hex digits) on a helper.
pub const HELPER_JOB_KEY: &str = "user.hx.job";
/// Size of the helper's root disk.
pub const HELPER_ROOT_SIZE: &str = "256MiB";
/// Prefix of a restore target's name.
pub const RESTORE_TARGET_PREFIX: &str = "hx-restore-";
/// Prefix of the snapshots a backup job takes (the `backup` kind of `hx-<kind>-...`, ipc.md 6.10).
pub const BACKUP_SNAPSHOT_PREFIX: &str = "hx-backup-";
/// Device name of the read-only snapshot mount.
pub const SNAPSHOT_DEVICE: &str = "src";
/// Device name of the writable restore-target mount.
pub const TARGET_DEVICE: &str = "dst";
/// Device name of the repository link.
pub const REPO_DEVICE: &str = "repo";
/// Mount point of the snapshot inside the helper.
pub const SNAPSHOT_MOUNT_PATH: &str = "/src";
/// Mount point of the restore target inside the helper.
pub const TARGET_MOUNT_PATH: &str = "/dst";
/// Host directory of the repository link's listening sockets (root 0700, from
/// `systemd-tmpfiles`, ipc.md 2).
pub const REPO_LINK_HOST_DIR: &str = "/run/hx/backup";
/// The socket the worker creates inside the helper (ipc.md 24, "Worker end of the link").
pub const REPO_LINK_CONNECT: &str = "/run/hx-worker/repo.sock";
/// Permission bits of the host-side listening socket.
pub const REPO_LINK_MODE: &str = "0600";
/// Where the worker binary is placed in the helper.
pub const WORKER_INIT_PATH: &str = "/sbin/init";
/// Longest `listen` path `bind` accepts: `sun_path` has 108 bytes including the final NUL.
pub const SUN_PATH_MAX: usize = 107;

fn invalid(what: &'static str, name: &str) -> IncusError {
    IncusError::InvalidName {
        what,
        name: name.chars().take(80).collect(),
    }
}

/// `[a-z0-9]` first, then `[a-z0-9-]`, at most `max` bytes, no trailing `-`.
fn is_lower_name(s: &str, max: usize) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= max
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b[b.len() - 1] != b'-'
}

// ---------------------------------------------------------------------------------------------
// Validated names
// ---------------------------------------------------------------------------------------------

macro_rules! name_type {
    ($(#[$m:meta])* $t:ident) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $t(String);

        impl $t {
            /// The name as text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $t {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

name_type! {
    /// A storage pool name, `^[a-z0-9][a-z0-9-]{0,62}$` without a trailing `-`. It becomes one
    /// path segment under [`STORAGE_POOLS_ROOT`].
    PoolName
}

impl PoolName {
    /// Validate a pool name.
    pub fn new(name: &str) -> Result<Self, IncusError> {
        if is_lower_name(name, 63) {
            Ok(Self(name.to_string()))
        } else {
            Err(invalid("storage pool", name))
        }
    }
}

name_type! {
    /// The Incus name of a desktop instance, `^[a-z0-9][a-z0-9-]{0,62}$` without a trailing `-`.
    /// It becomes one path segment (`containers-snapshots/<desktop>`).
    DesktopName
}

impl DesktopName {
    /// Validate a desktop instance name.
    pub fn new(name: &str) -> Result<Self, IncusError> {
        if is_lower_name(name, 63) {
            Ok(Self(name.to_string()))
        } else {
            Err(invalid("desktop", name))
        }
    }
}

name_type! {
    /// The name of a backup job's snapshot: `^hx-backup-[0-9TZ-]+-[0-9a-f]{4}$` (the `backup` kind
    /// of ipc.md 6.10; for example `hx-backup-20261126T101500Z-0a1b`). One path segment.
    BackupSnapshotName
}

impl BackupSnapshotName {
    /// Validate a backup snapshot name.
    pub fn new(name: &str) -> Result<Self, IncusError> {
        let ok = name.len() <= 63
            && name
                .strip_prefix(BACKUP_SNAPSHOT_PREFIX)
                .is_some_and(|rest| {
                    rest.len() > 5
                        && rest
                            .split_at_checked(rest.len() - 5)
                            .is_some_and(|(mid, tail)| {
                                !mid.is_empty()
                                    && mid.bytes().all(|c| {
                                        c.is_ascii_digit() || c == b'T' || c == b'Z' || c == b'-'
                                    })
                                    && tail.strip_prefix('-').is_some_and(|h| {
                                        h.len() == 4
                                            && h.bytes().all(|c| {
                                                c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
                                            })
                                    })
                            })
                });
        if ok {
            Ok(Self(name.to_string()))
        } else {
            Err(invalid("backup snapshot", name))
        }
    }
}

name_type! {
    /// The name of a restore target instance: `hx-restore-` and 1 to 32 characters of
    /// `[a-z0-9]`. One path segment.
    RestoreTargetName
}

impl RestoreTargetName {
    /// Validate a restore target name.
    pub fn new(name: &str) -> Result<Self, IncusError> {
        let ok = name
            .strip_prefix(RESTORE_TARGET_PREFIX)
            .is_some_and(|rest| {
                (1..=32).contains(&rest.len())
                    && rest
                        .bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            });
        if ok {
            Ok(Self(name.to_string()))
        } else {
            Err(invalid("restore target", name))
        }
    }
}

name_type! {
    /// The name of a backup helper: `hx-bkw-` and 8 lower-case hex digits.
    HelperName
}

impl HelperName {
    /// Validate a helper name (for example one read back from Incus during crash recovery).
    pub fn new(name: &str) -> Result<Self, IncusError> {
        let ok = name
            .strip_prefix(HELPER_PREFIX)
            .is_some_and(|h| h.len() == 8 && is_lower_hex(h));
        if ok {
            Ok(Self(name.to_string()))
        } else {
            Err(invalid("backup helper", name))
        }
    }
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// A job id: 16 bytes, not all zero (a zero id means a field that was never filled in).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JobId([u8; 16]);

impl JobId {
    /// Wrap 16 bytes. The all-zero id is refused.
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, IncusError> {
        if bytes == [0u8; 16] {
            return Err(IncusError::InvalidArgument(
                "a job id must not be all zero".into(),
            ));
        }
        Ok(Self(bytes))
    }

    /// Parse 32 lower-case hex digits.
    pub fn from_hex(s: &str) -> Result<Self, IncusError> {
        if s.len() != 32 || !is_lower_hex(s) {
            return Err(IncusError::InvalidArgument(
                "a job id is 32 lower-case hex digits".into(),
            ));
        }
        let mut b = [0u8; 16];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            b[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap_or("zz"), 16)
                .map_err(|_| IncusError::InvalidArgument("a job id is hexadecimal".into()))?;
        }
        Self::from_bytes(b)
    }

    /// The id as 32 lower-case hex digits.
    pub fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The helper's name, `hx-bkw-` and the first 8 hex digits.
    pub fn helper_name(&self) -> HelperName {
        HelperName(format!("{HELPER_PREFIX}{}", &self.hex()[..8]))
    }
}

/// What a job does with the desktop's files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobKind {
    /// `BACKUP`: the snapshot is mounted read-only at `/src`.
    Backup,
    /// `RESTORE`: the target's rootfs is mounted writable at `/dst`.
    Restore,
    /// `INIT`, `SNAPSHOTS`, `RESTORE_PLAN`, `FORGET_PRUNE`, `CHECK`, `KEYS`: no mount at all, so
    /// that only repository content can reach the helper (ipc.md 24).
    RepositoryOnly,
}

impl JobKind {
    /// The helper's mount point for this kind, if any.
    pub fn mount_path(self) -> Option<&'static str> {
        match self {
            Self::Backup => Some(SNAPSHOT_MOUNT_PATH),
            Self::Restore => Some(TARGET_MOUNT_PATH),
            Self::RepositoryOnly => None,
        }
    }
}

type Device = BTreeMap<String, String>;

fn device(pairs: &[(&str, String)]) -> Device {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), v.clone()))
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------------------------

/// The `src` device: the desktop's snapshot, read-only, with `shift=true` (ipc.md 24).
///
/// The source is the snapshot's **`rootfs` subdirectory** (the snapshot's top directory is
/// `d--x------` owned by the desktop's host root id, which a helper with a different isolated map
/// cannot enter).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotMount {
    pool: PoolName,
    desktop: DesktopName,
    snapshot: BackupSnapshotName,
}

impl SnapshotMount {
    /// From a validated pool, desktop and snapshot name.
    pub fn new(pool: PoolName, desktop: DesktopName, snapshot: BackupSnapshotName) -> Self {
        Self {
            pool,
            desktop,
            snapshot,
        }
    }

    /// The pool.
    pub fn pool(&self) -> &PoolName {
        &self.pool
    }

    /// The source path on the host:
    /// `/var/lib/incus/storage-pools/<pool>/containers-snapshots/<desktop>/<snapshot>/rootfs`.
    pub fn source(&self) -> String {
        format!(
            "{STORAGE_POOLS_ROOT}/{}/containers-snapshots/{}/{}/rootfs",
            self.pool, self.desktop, self.snapshot
        )
    }

    /// The device's options.
    pub fn device(&self) -> BTreeMap<String, String> {
        device(&[
            ("type", "disk".into()),
            ("source", self.source()),
            ("path", SNAPSHOT_MOUNT_PATH.into()),
            ("readonly", "true".into()),
            ("shift", "true".into()),
        ])
    }
}

/// The `dst` device: a restore target's rootfs, writable, with `shift=true` (ipc.md 24).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetMount {
    pool: PoolName,
    target: RestoreTargetName,
}

impl TargetMount {
    /// From a validated pool and restore target name.
    pub fn new(pool: PoolName, target: RestoreTargetName) -> Self {
        Self { pool, target }
    }

    /// The pool.
    pub fn pool(&self) -> &PoolName {
        &self.pool
    }

    /// The source path on the host: `/var/lib/incus/storage-pools/<pool>/containers/<target>/rootfs`.
    pub fn source(&self) -> String {
        format!(
            "{STORAGE_POOLS_ROOT}/{}/containers/{}/rootfs",
            self.pool, self.target
        )
    }

    /// The device's options.
    pub fn device(&self) -> BTreeMap<String, String> {
        device(&[
            ("type", "disk".into()),
            ("source", self.source()),
            ("path", TARGET_MOUNT_PATH.into()),
            ("shift", "true".into()),
        ])
    }
}

/// The `repo` device: the proxy device of the repository link (ipc.md 24).
///
/// The host-side socket is `/run/hx/backup/<job id>.sock`, owned by root with mode 0600, and it
/// connects to the worker's own socket in the helper. Nothing in it can be chosen by a caller:
/// the type has no `security.uid`, no TCP, no `bind=instance`, no other connect path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoLink {
    job: JobId,
    host_dir: String,
    owner: (u32, u32),
}

impl RepoLink {
    /// The production link of a job: `/run/hx/backup/<job>.sock`, uid 0, gid 0, mode 0600.
    pub fn new(job: JobId) -> Self {
        // The production directory and a 32 digit id are far below the limit (checked by a test).
        Self {
            job,
            host_dir: REPO_LINK_HOST_DIR.to_string(),
            owner: (0, 0),
        }
    }

    /// A link whose host socket lies in `host_dir` and belongs to `owner` (uid, gid), for tests
    /// that run as an ordinary user. **`hx-privd` never calls this**: it uses [`RepoLink::new`]
    /// (rule 2 of ipc.md 7: no caller-chosen paths). `host_dir` must be an absolute path of
    /// normal components (`[A-Za-z0-9._-]`, no `.` or `..` component, no trailing slash), and
    /// the whole `listen` path must fit `sun_path` ([`SUN_PATH_MAX`]).
    pub fn in_dir(job: JobId, host_dir: &str, owner: (u32, u32)) -> Result<Self, IncusError> {
        let ok = host_dir.starts_with('/')
            && host_dir.len() > 1
            && host_dir[1..].split('/').all(|c| {
                !c.is_empty()
                    && c != "."
                    && c != ".."
                    && c.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            });
        if !ok {
            return Err(IncusError::InvalidArgument(format!(
                "repository link directory `{}` is not a plain absolute path",
                host_dir.chars().take(80).collect::<String>()
            )));
        }
        for (what, id) in [("uid", owner.0), ("gid", owner.1)] {
            if id == u32::MAX {
                return Err(IncusError::InvalidArgument(format!(
                    "repository link {what} must not be {}",
                    u32::MAX
                )));
            }
        }
        let link = Self {
            job,
            host_dir: host_dir.to_string(),
            owner,
        };
        link.check_len()?;
        Ok(link)
    }

    fn check_len(&self) -> Result<(), IncusError> {
        let n = self.socket_path().len();
        if n > SUN_PATH_MAX {
            return Err(IncusError::InvalidArgument(format!(
                "repository link socket path is {n} bytes, the limit of a unix socket is {SUN_PATH_MAX}"
            )));
        }
        Ok(())
    }

    /// The job.
    pub fn job(&self) -> JobId {
        self.job
    }

    /// The host-side socket path, `<dir>/<job id>.sock`.
    pub fn socket_path(&self) -> String {
        format!("{}/{}.sock", self.host_dir, self.job.hex())
    }

    /// The device's options.
    pub fn device(&self) -> BTreeMap<String, String> {
        device(&[
            ("type", "proxy".into()),
            ("bind", "host".into()),
            ("listen", format!("unix:{}", self.socket_path())),
            ("connect", format!("unix:{REPO_LINK_CONNECT}")),
            ("uid", self.owner.0.to_string()),
            ("gid", self.owner.1.to_string()),
            ("mode", REPO_LINK_MODE.into()),
        ])
    }
}

// ---------------------------------------------------------------------------------------------
// The helper
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Mount {
    Snapshot(SnapshotMount),
    Target(TargetMount),
}

/// The backup helper instance of one job (ipc.md 24): ephemeral, empty, no profiles, no NIC.
///
/// Constructed only through [`BackupHelperSpec::backup`], [`BackupHelperSpec::restore`] and
/// [`BackupHelperSpec::repository_only`], so the job kind and its mount always agree, the pool of
/// the mount is the pool of the root disk, and the job of the link is the job of the helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupHelperSpec {
    kind: JobKind,
    pool: PoolName,
    mount: Option<Mount>,
    link: RepoLink,
}

impl BackupHelperSpec {
    /// A `BACKUP` helper: the root disk is on the snapshot's pool.
    pub fn backup(mount: SnapshotMount, link: RepoLink) -> Self {
        Self {
            kind: JobKind::Backup,
            pool: mount.pool.clone(),
            mount: Some(Mount::Snapshot(mount)),
            link,
        }
    }

    /// A `RESTORE` helper: the root disk is on the target's pool.
    pub fn restore(mount: TargetMount, link: RepoLink) -> Self {
        Self {
            kind: JobKind::Restore,
            pool: mount.pool.clone(),
            mount: Some(Mount::Target(mount)),
            link,
        }
    }

    /// A helper of a job that only touches the repository: `root` and `repo`, nothing else.
    pub fn repository_only(pool: PoolName, link: RepoLink) -> Self {
        Self {
            kind: JobKind::RepositoryOnly,
            pool,
            mount: None,
            link,
        }
    }

    /// What the job does.
    pub fn kind(&self) -> JobKind {
        self.kind
    }

    /// The job.
    pub fn job(&self) -> JobId {
        self.link.job
    }

    /// The helper's name, `hx-bkw-<8 hex digits>`.
    pub fn name(&self) -> HelperName {
        self.link.job.helper_name()
    }

    /// The pool of the root disk.
    pub fn pool(&self) -> &PoolName {
        &self.pool
    }

    /// The repository link.
    pub fn link(&self) -> &RepoLink {
        &self.link
    }

    /// The directories the helper's rootfs needs before it starts (ipc.md 24), in creation order,
    /// with their modes; `/sbin` is there because [`WORKER_INIT_PATH`] lives in it.
    pub fn directories(&self) -> Vec<(&'static str, u32)> {
        let mut v = vec![
            ("/sbin", 0o755),
            ("/dev", 0o755),
            ("/proc", 0o755),
            ("/sys", 0o755),
            ("/tmp", 0o1777),
            ("/run", 0o755),
        ];
        if let Some(p) = self.kind.mount_path() {
            v.push((p, 0o755));
        }
        v
    }

    /// The instance configuration: exactly the table of ipc.md 24 and nothing else.
    pub fn config(&self) -> BTreeMap<String, String> {
        [
            ("security.idmap.isolated", "true"),
            ("security.privileged", "false"),
            ("security.nesting", "false"),
            ("security.guestapi", "false"),
            ("security.syscalls.deny_compat", "true"),
            ("limits.memory", "1GiB"),
            ("limits.memory.swap", "false"),
            ("limits.cpu", "2"),
            ("limits.cpu.priority", "0"),
            ("limits.disk.priority", "0"),
            ("limits.processes", "64"),
            ("boot.autostart", "false"),
            (HELPER_KIND_KEY, HELPER_KIND),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .chain([(HELPER_JOB_KEY.to_string(), self.link.job.hex())])
        .collect()
    }

    /// The devices: `root` (256 MiB on the pool), the mount if any, and `repo`. No NIC.
    pub fn devices(&self) -> BTreeMap<String, BTreeMap<String, String>> {
        let mut d = BTreeMap::new();
        d.insert(
            "root".to_string(),
            device(&[
                ("type", "disk".into()),
                ("path", "/".into()),
                ("pool", self.pool.to_string()),
                ("size", HELPER_ROOT_SIZE.into()),
            ]),
        );
        match &self.mount {
            Some(Mount::Snapshot(m)) => {
                d.insert(SNAPSHOT_DEVICE.to_string(), m.device());
            }
            Some(Mount::Target(m)) => {
                d.insert(TARGET_DEVICE.to_string(), m.device());
            }
            None => {}
        }
        d.insert(REPO_DEVICE.to_string(), self.link.device());
        d
    }

    /// The creation request body (`POST /1.0/instances`): an empty instance (`source.type` is
    /// `none`, what `incus init --empty` sends), ephemeral, with an explicit empty profile list
    /// (omitting it would apply `default`, which has a NIC).
    pub fn to_json(&self) -> Value {
        json!({
            "name": self.name().as_str(),
            "type": "container",
            "source": {"type": "none"},
            "profiles": Vec::<String>::new(),
            "config": self.config(),
            "devices": self.devices(),
            "ephemeral": true,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// The restore target
// ---------------------------------------------------------------------------------------------

/// The never-started `init --empty` instance a restore writes into (ipc.md 24, `dst`).
///
/// It is built from the desktop's own definition as read from Incus, so the restored desktop has
/// the same profiles, limits and devices. What is **not** copied, and why:
///
/// - every `volatile.*` key: they are runtime state (MAC addresses, uuids, `last_state`) and, above
///   all, `volatile.idmap.*` would give two instances the same host uid range. The target gets
///   its own isolated range at its first start; ids on disk are the container's own ids (the
///   rootfs is stored unshifted), so the range does not matter for what the worker writes;
/// - the session-link proxy device (`hx-link`): started next to the desktop it would take over
///   the desktop's host socket; privd adds the link again when the restored desktop is installed;
/// - `boot.autostart` is forced to `false`: a target that is not complete must not start by
///   itself when Incus restarts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreTargetSpec {
    name: RestoreTargetName,
    pool: PoolName,
    architecture: String,
    description: String,
    profiles: Vec<String>,
    config: BTreeMap<String, String>,
    devices: BTreeMap<String, BTreeMap<String, String>>,
}

impl RestoreTargetSpec {
    /// Build the target for `desktop` (as returned by `get_instance`) on `pool`.
    ///
    /// Refused when the desktop is not marked as ours, is not a container, or does not live on
    /// `pool` (its effective `root` device must name that pool).
    pub fn from_desktop(
        desktop: &Instance,
        name: RestoreTargetName,
        pool: &PoolName,
    ) -> Result<Self, IncusError> {
        if !super::marker::instance_is_marked(&desktop.config) {
            return Err(IncusError::InvalidArgument(
                "the desktop does not carry the hash-xcreen marker".into(),
            ));
        }
        if desktop.kind != "container" {
            return Err(IncusError::InvalidArgument(format!(
                "the desktop is a `{}`, not a container",
                desktop.kind
            )));
        }
        let root_pool = desktop
            .expanded_devices
            .get("root")
            .and_then(|r| r.get("pool"));
        if root_pool.map(String::as_str) != Some(pool.as_str()) {
            return Err(IncusError::InvalidArgument(format!(
                "the desktop's root disk is on pool {root_pool:?}, not `{pool}`"
            )));
        }
        let mut config: BTreeMap<String, String> = desktop
            .config
            .iter()
            .filter(|(k, _)| !k.starts_with("volatile."))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        config.insert("boot.autostart".into(), "false".into());
        if !config.keys().any(|k| k.starts_with(INSTANCE_KEY_PREFIX)) {
            return Err(IncusError::InvalidArgument(
                "the desktop has no user.hx.* key".into(),
            ));
        }
        let devices = desktop
            .devices
            .iter()
            .filter(|(n, d)| {
                n.as_str() != SESSION_LINK_DEVICE
                    && d.get("type").map(String::as_str) != Some("proxy")
            })
            .map(|(n, d)| (n.clone(), d.clone()))
            .collect();
        Ok(Self {
            name,
            pool: pool.clone(),
            architecture: desktop.architecture.clone(),
            description: desktop.description.clone(),
            profiles: desktop.profiles.clone(),
            config,
            devices,
        })
    }

    /// The target's name.
    pub fn name(&self) -> &RestoreTargetName {
        &self.name
    }

    /// The mount a restore helper needs for this target.
    pub fn mount(&self) -> TargetMount {
        TargetMount::new(self.pool.clone(), self.name.clone())
    }

    /// The configuration (no `volatile.*`, `boot.autostart=false`).
    pub fn config(&self) -> &BTreeMap<String, String> {
        &self.config
    }

    /// The instance-level devices (no proxy devices).
    pub fn devices(&self) -> &BTreeMap<String, BTreeMap<String, String>> {
        &self.devices
    }

    /// The creation request body: an empty, non-ephemeral container.
    pub fn to_json(&self) -> Value {
        let mut v = json!({
            "name": self.name.as_str(),
            "type": "container",
            "source": {"type": "none"},
            "profiles": self.profiles,
            "config": self.config,
            "devices": self.devices,
            "description": self.description,
            "ephemeral": false,
        });
        if !self.architecture.is_empty()
            && let Some(o) = v.as_object_mut()
        {
            o.insert(
                "architecture".into(),
                Value::String(self.architecture.clone()),
            );
        }
        v
    }
}

// ---------------------------------------------------------------------------------------------
// The checks before each job
// ---------------------------------------------------------------------------------------------

/// Which check before a job failed (ipc.md 24, "Why this mechanism is correct"). `hx-privd` maps
/// every variant to `FAILED_PRECONDITION` and never runs the job, because a backup would record
/// wrong ids.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PreconditionFailed {
    /// `kernel_features.idmapped_mounts` is not `"true"`.
    #[error("the kernel does not offer idmapped mounts (kernel_features.idmapped_mounts = {0:?})")]
    IdmappedMounts(Option<String>),
    /// The pool is not btrfs.
    #[error("storage pool `{pool}` uses driver `{driver}`, not btrfs")]
    PoolDriver {
        /// Pool name.
        pool: String,
        /// Its driver.
        driver: String,
    },
    /// The desktop's root disk is not on the pool the paths were computed for.
    #[error("desktop `{desktop}` is on pool {actual:?}, not `{pool}`")]
    DesktopPool {
        /// Desktop name.
        desktop: String,
        /// Pool the job would use.
        pool: String,
        /// The pool of the desktop's `root` device.
        actual: Option<String>,
    },
    /// `volatile.last_state.idmap` of the desktop is not `[]`: its rootfs is stored shifted.
    #[error("desktop `{desktop}`: volatile.last_state.idmap is {value:?}, not \"[]\"")]
    DesktopIdmap {
        /// Desktop name.
        desktop: String,
        /// The value, `None` when the key is missing (the desktop never ran).
        value: Option<String>,
    },
    /// `volatile.last_state.idmap` of the snapshot is not `[]`.
    #[error("snapshot `{snapshot}`: volatile.last_state.idmap is {value:?}, not \"[]\"")]
    SnapshotIdmap {
        /// Snapshot name.
        snapshot: String,
        /// The value, `None` when the key is missing.
        value: Option<String>,
    },
}

const IDMAP_EMPTY: &str = "[]";

/// What both job kinds need from the host: idmapped mounts and a btrfs pool.
pub fn check_restore_preconditions(
    server: &ServerInfo,
    pool: &StoragePool,
) -> Result<(), PreconditionFailed> {
    let feature = server.kernel_features.get("idmapped_mounts");
    if feature.map(String::as_str) != Some("true") {
        return Err(PreconditionFailed::IdmappedMounts(feature.cloned()));
    }
    if pool.driver != "btrfs" {
        return Err(PreconditionFailed::PoolDriver {
            pool: pool.name.clone(),
            driver: pool.driver.clone(),
        });
    }
    Ok(())
}

/// The checks before a `BACKUP` job: the host checks of [`check_restore_preconditions`], that the
/// desktop lives on `pool`, and that the desktop's and the snapshot's `volatile.last_state.idmap`
/// are `"[]"` (this Incus stores the rootfs unshifted and mounts it idmapped).
pub fn check_backup_preconditions(
    server: &ServerInfo,
    pool: &StoragePool,
    desktop: &Instance,
    snapshot: &Snapshot,
) -> Result<(), PreconditionFailed> {
    check_restore_preconditions(server, pool)?;
    let actual = desktop
        .expanded_devices
        .get("root")
        .and_then(|r| r.get("pool"))
        .cloned();
    if actual.as_deref() != Some(pool.name.as_str()) {
        return Err(PreconditionFailed::DesktopPool {
            desktop: desktop.name.clone(),
            pool: pool.name.clone(),
            actual,
        });
    }
    let idmap = |c: &BTreeMap<String, String>| c.get("volatile.last_state.idmap").cloned();
    let d = idmap(&desktop.config);
    if d.as_deref() != Some(IDMAP_EMPTY) {
        return Err(PreconditionFailed::DesktopIdmap {
            desktop: desktop.name.clone(),
            value: d,
        });
    }
    let s = idmap(&snapshot.config);
    if s.as_deref() != Some(IDMAP_EMPTY) {
        return Err(PreconditionFailed::SnapshotIdmap {
            snapshot: snapshot.name.clone(),
            value: s,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Results of the client calls
// ---------------------------------------------------------------------------------------------

/// How a helper ended ([`Client::finish_backup_helper`](super::Client::finish_backup_helper)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperEnd {
    /// PID 1 exited and Incus deleted the ephemeral instance; the time it took after the call.
    Exited(std::time::Duration),
    /// The helper was still there after the timeout and was stopped and deleted by force.
    ForceDeleted,
}

/// A backup helper found in Incus (crash recovery, ipc.md 35 step 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupHelperInfo {
    /// Its name.
    pub name: HelperName,
    /// The job id from `user.hx.job`, when present and well-formed.
    pub job: Option<JobId>,
    /// Run state text.
    pub status: String,
}
