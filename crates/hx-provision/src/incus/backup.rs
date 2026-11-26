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
//! - [`SnapshotMount::checked`] and [`TargetMount::checked`] are the checks `hx-privd` makes before
//!   each job, because the design depends on Incus internals (architecture 15); they are the only
//!   public way to get a mount.
//!
//! The calls are on [`Client`](super::Client): `create_backup_helper`, `populate_backup_helper`,
//! `start_backup_helper`, `finish_backup_helper`, `force_delete_backup_helper`,
//! `list_backup_helpers`, `create_restore_target`, `delete_restore_target` and
//! `list_restore_targets`.

use std::collections::BTreeMap;
use std::fmt;

use serde_json::{Value, json};

use super::error::IncusError;
use super::limits::{MAX_CPU, MAX_DISK_GIB, MAX_MEMORY_MIB};
use super::link::SESSION_LINK_DEVICE;
use super::marker::{INSTANCE_KEY_PREFIX, INSTANCE_STATE_KEY};
use super::types::{Instance, ServerInfo, Snapshot, StoragePool};
use crate::host::Naming;
use crate::orchestrate::DESKTOP_CONFIG_KEYS;

/// Where Incus keeps its storage pools. **This is an Incus internal** (architecture 15): the
/// backup helper mounts paths below it as disk-device sources, and the layout
/// (`containers/<name>/rootfs`, `containers-snapshots/<name>/<snapshot>/rootfs`) is not a
/// documented interface. It is verified on Incus 6.0.0 by the real-Incus test
/// (`tests/incus_real_backup.rs`) and guarded before each job
/// ([`SnapshotMount::checked`]). This is the only place the path is written.
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
    /// The Incus name of a desktop instance: `hx-` and a desktop id, `^hx-[a-z][a-z0-9]{0,11}$`
    /// (the id of ipc.md 6). It becomes one path segment (`containers-snapshots/<desktop>`).
    DesktopName
}

impl DesktopName {
    /// Validate a desktop instance name.
    pub fn new(name: &str) -> Result<Self, IncusError> {
        let ok = name.strip_prefix("hx-").is_some_and(|id| {
            let b = id.as_bytes();
            !b.is_empty()
                && b.len() <= 12
                && b[0].is_ascii_lowercase()
                && b[1..]
                    .iter()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        });
        if ok {
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

impl fmt::Display for JobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex())
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
// The checks before each job, and the mounts they guard
// ---------------------------------------------------------------------------------------------

/// Which check before a job failed (ipc.md 24, "Why this mechanism is correct"). `hx-privd` maps
/// every variant to `FAILED_PRECONDITION` and never runs the job, because a backup would record
/// wrong ids and a restore would write them.
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
    /// A name that would not be one safe path segment of the expected kind.
    #[error("{what} name `{name}` is not acceptable")]
    InvalidName {
        /// What kind of object.
        what: String,
        /// The rejected name (truncated).
        name: String,
    },
    /// The instance is not a hash-xcreen desktop.
    #[error("instance `{name}` is not a desktop: {reason}")]
    NotADesktop {
        /// Instance name.
        name: String,
        /// Why.
        reason: String,
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
    /// The snapshot is not an `hx-backup-...` snapshot.
    #[error("snapshot `{snapshot}` is not a backup snapshot")]
    SnapshotNotBackup {
        /// Snapshot name.
        snapshot: String,
    },
    /// The snapshot belongs to another instance (or to none that is known).
    #[error("snapshot `{snapshot}` belongs to {instance:?}, not to desktop `{desktop}`")]
    SnapshotOfOther {
        /// Snapshot name.
        snapshot: String,
        /// The instance it belongs to (empty when unknown).
        instance: String,
        /// The desktop the job is for.
        desktop: String,
    },
    /// `volatile.last_state.idmap` of the snapshot is not `[]`.
    #[error("snapshot `{snapshot}`: volatile.last_state.idmap is {value:?}, not \"[]\"")]
    SnapshotIdmap {
        /// Snapshot name.
        snapshot: String,
        /// The value, `None` when the key is missing.
        value: Option<String>,
    },
    /// The instance is not a restore target made by privd (`user.hx.kind=restore-target`).
    #[error("instance `{target}` is not a restore target ({reason})")]
    NotARestoreTarget {
        /// Instance name.
        target: String,
        /// Why.
        reason: String,
    },
    /// The target is not stopped.
    #[error("restore target `{target}` is {status}, not Stopped")]
    TargetNotStopped {
        /// Instance name.
        target: String,
        /// Its status.
        status: String,
    },
    /// The target has started before: its rootfs may no longer be in the state of a fresh empty
    /// instance.
    #[error("restore target `{target}` has been started before ({evidence})")]
    TargetStarted {
        /// Instance name.
        target: String,
        /// What showed it.
        evidence: String,
    },
    /// `volatile.last_state.idmap` of the target is not `[]`.
    #[error("restore target `{target}`: volatile.last_state.idmap is {value:?}, not \"[]\"")]
    TargetIdmap {
        /// Instance name.
        target: String,
        /// The value, `None` when the key is missing.
        value: Option<String>,
    },
    /// The target's root disk is not on the pool.
    #[error("restore target `{target}` is on pool {actual:?}, not `{pool}`")]
    TargetPool {
        /// Instance name.
        target: String,
        /// Pool the job would use.
        pool: String,
        /// The pool of its `root` device.
        actual: Option<String>,
    },
}

fn bad_name(e: IncusError) -> PreconditionFailed {
    match e {
        IncusError::InvalidName { what, name } => PreconditionFailed::InvalidName {
            what: what.to_string(),
            name,
        },
        other => PreconditionFailed::InvalidName {
            what: "name".into(),
            name: other.to_string(),
        },
    }
}

/// The value `volatile.last_state.idmap` has on an instance whose rootfs is stored unshifted
/// (and on a never-started empty instance), observed on Incus 6.0.0.
const IDMAP_EMPTY: &str = "[]";

fn root_pool(i: &Instance) -> Option<String> {
    i.expanded_devices
        .get("root")
        .and_then(|r| r.get("pool"))
        .cloned()
}

/// What every job needs from the host: idmapped mounts and a btrfs pool. [`SnapshotMount::checked`]
/// and [`TargetMount::checked`] run it; it is public so that privd can fail early, before it
/// takes a snapshot or creates a target.
pub fn check_host_preconditions(
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

/// Whether an `last_used_at` value means "never" (Incus reports the zero time).
fn never_used(t: &str) -> bool {
    t.is_empty() || t.starts_with("0001-01-01") || t.starts_with("1970-01-01")
}

/// The `src` device: the desktop's snapshot, read-only, with `shift=true` (ipc.md 24).
///
/// The source is the snapshot's **`rootfs` subdirectory** (the snapshot's top directory is
/// `d--x------` owned by the desktop's host root id, which a helper with a different isolated map
/// cannot enter). The only public way to get one is [`SnapshotMount::checked`], which runs every
/// check of ipc.md 24 on the objects the paths are derived from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotMount {
    pool: PoolName,
    desktop: DesktopName,
    snapshot: BackupSnapshotName,
}

impl SnapshotMount {
    /// The mount for `snapshot` of `desktop` on `pool`, after the checks before a `BACKUP` job:
    /// the host checks ([`check_host_preconditions`]); the desktop is a container named
    /// `hx-<desktop id>` that carries the hash-xcreen marker and no `user.hx.kind`, has its root
    /// disk on `pool` and `volatile.last_state.idmap` `[]`; the snapshot belongs to that desktop, is
    /// an `hx-backup-...` snapshot and has `volatile.last_state.idmap` `[]`. Every name in the
    /// path comes from these objects.
    pub fn checked(
        server: &ServerInfo,
        pool: &StoragePool,
        desktop: &Instance,
        snapshot: &Snapshot,
    ) -> Result<Self, PreconditionFailed> {
        check_host_preconditions(server, pool)?;
        let pool_name = PoolName::new(&pool.name).map_err(bad_name)?;
        let desktop_name = DesktopName::new(&desktop.name).map_err(bad_name)?;
        let not = |reason: &str| PreconditionFailed::NotADesktop {
            name: desktop.name.clone(),
            reason: reason.into(),
        };
        if desktop.kind != "container" {
            return Err(not("not a container"));
        }
        if !super::marker::instance_is_marked(&desktop.config) {
            return Err(not("no hash-xcreen marker"));
        }
        if desktop.config.contains_key(HELPER_KIND_KEY) {
            return Err(not(
                "carries user.hx.kind (a helper or restore target, not a desktop)",
            ));
        }
        let actual = root_pool(desktop);
        if actual.as_deref() != Some(pool.name.as_str()) {
            return Err(PreconditionFailed::DesktopPool {
                desktop: desktop.name.clone(),
                pool: pool.name.clone(),
                actual,
            });
        }
        let d = desktop.config.get("volatile.last_state.idmap").cloned();
        if d.as_deref() != Some(IDMAP_EMPTY) {
            return Err(PreconditionFailed::DesktopIdmap {
                desktop: desktop.name.clone(),
                value: d,
            });
        }
        let snapshot_name = BackupSnapshotName::new(&snapshot.name).map_err(|_| {
            PreconditionFailed::SnapshotNotBackup {
                snapshot: snapshot.name.chars().take(80).collect(),
            }
        })?;
        if snapshot.instance != desktop.name {
            return Err(PreconditionFailed::SnapshotOfOther {
                snapshot: snapshot.name.clone(),
                instance: snapshot.instance.clone(),
                desktop: desktop.name.clone(),
            });
        }
        let s = snapshot.config.get("volatile.last_state.idmap").cloned();
        if s.as_deref() != Some(IDMAP_EMPTY) {
            return Err(PreconditionFailed::SnapshotIdmap {
                snapshot: snapshot.name.clone(),
                value: s,
            });
        }
        Ok(Self {
            pool: pool_name,
            desktop: desktop_name,
            snapshot: snapshot_name,
        })
    }

    /// A mount without any check, for tests of the request shapes.
    #[cfg(any(test, feature = "test-support"))]
    pub fn unchecked(pool: PoolName, desktop: DesktopName, snapshot: BackupSnapshotName) -> Self {
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

/// The `dst` device: a restore target's rootfs, writable, with `shift=true` (ipc.md 24). The only
/// public way to get one is [`TargetMount::checked`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetMount {
    pool: PoolName,
    target: RestoreTargetName,
}

impl TargetMount {
    /// The mount for the restore target `target` on `pool`, after the checks before a `RESTORE`
    /// job: the host checks; the target is a container named `hx-restore-...` with
    /// `user.hx.kind=restore-target`; it is `Stopped` and has **never started** (`last_used_at`
    /// is the zero time, there is no `volatile.last_state.power` and no `volatile.idmap.current`);
    /// its `volatile.last_state.idmap` is exactly `[]`, the value a never-started empty instance
    /// has on Incus 6.0.0; and its root disk is on `pool`. Fails closed on anything else.
    pub fn checked(
        server: &ServerInfo,
        pool: &StoragePool,
        target: &Instance,
    ) -> Result<Self, PreconditionFailed> {
        check_host_preconditions(server, pool)?;
        let pool_name = PoolName::new(&pool.name).map_err(bad_name)?;
        let not = |reason: String| PreconditionFailed::NotARestoreTarget {
            target: target.name.chars().take(80).collect(),
            reason,
        };
        let name = RestoreTargetName::new(&target.name)
            .map_err(|_| not("the name is not hx-restore-...".into()))?;
        if target.kind != "container" {
            return Err(not("not a container".into()));
        }
        let kind = target.config.get(HELPER_KIND_KEY);
        if kind.map(String::as_str) != Some(RESTORE_TARGET_KIND) {
            return Err(not(format!("{HELPER_KIND_KEY} is {kind:?}")));
        }
        if !target.status.eq_ignore_ascii_case("stopped") {
            return Err(PreconditionFailed::TargetNotStopped {
                target: target.name.clone(),
                status: target.status.clone(),
            });
        }
        let started = |evidence: String| PreconditionFailed::TargetStarted {
            target: target.name.clone(),
            evidence,
        };
        if !never_used(&target.last_used_at) {
            return Err(started(format!("last_used_at = {}", target.last_used_at)));
        }
        for key in ["volatile.last_state.power", "volatile.idmap.current"] {
            if let Some(v) = target.config.get(key) {
                return Err(started(format!("{key} = {v}")));
            }
        }
        let idmap = target.config.get("volatile.last_state.idmap").cloned();
        if idmap.as_deref() != Some(IDMAP_EMPTY) {
            return Err(PreconditionFailed::TargetIdmap {
                target: target.name.clone(),
                value: idmap,
            });
        }
        let actual = root_pool(target);
        if actual.as_deref() != Some(pool.name.as_str()) {
            return Err(PreconditionFailed::TargetPool {
                target: target.name.clone(),
                pool: pool.name.clone(),
                actual,
            });
        }
        Ok(Self {
            pool: pool_name,
            target: name,
        })
    }

    /// A mount without any check, for tests of the request shapes.
    #[cfg(any(test, feature = "test-support"))]
    pub fn unchecked(pool: PoolName, target: RestoreTargetName) -> Self {
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
    #[cfg(any(test, feature = "test-support"))]
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

    #[cfg(any(test, feature = "test-support"))]
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

/// `user.hx.kind` of a restore target (ipc.md 24, 35). A target is never a desktop until privd
/// promotes it (architecture 9.8).
pub const RESTORE_TARGET_KIND: &str = "restore-target";
/// `user.hx.state` of a restore target.
pub const RESTORE_TARGET_STATE: &str = "restoring";

fn refuse(msg: impl fmt::Display) -> IncusError {
    IncusError::InvalidArgument(format!("restore target: {msg}"))
}

/// A canonical decimal number (no sign, no leading zero) from 1 to `max`.
fn bounded(v: &str, max: u64) -> bool {
    !v.is_empty()
        && v.len() <= 20
        && !v.starts_with('0')
        && v.bytes().all(|b| b.is_ascii_digit())
        && v.parse::<u64>().is_ok_and(|n| (1..=max).contains(&n))
}

/// Whether `v` is an acceptable value of an allowlisted desktop config key.
fn desktop_value_ok(key: &str, v: &str) -> bool {
    match key {
        "security.privileged" => v == "false",
        "security.idmap.isolated" => v == "true",
        // Bounds are the ones the rest of the crate enforces: `to_create` takes any non-zero u32
        // for `limits.processes`; `set_limits` caps cpu, memory and disk (limits.rs).
        "limits.processes" => bounded(v, u64::from(u32::MAX)),
        "limits.cpu" => bounded(v, u64::from(MAX_CPU)),
        "limits.memory" => v
            .strip_suffix("MiB")
            .is_some_and(|n| bounded(n, MAX_MEMORY_MIB)),
        "security.guestapi" => v == "false",
        _ => v == "true" || v == "false",
    }
}

/// `user.hx.<name>` keys privd keeps on a desktop are copied when key and value are plain.
fn hx_key_ok(key: &str, v: &str) -> bool {
    key.strip_prefix(INSTANCE_KEY_PREFIX).is_some_and(|k| {
        !k.is_empty()
            && k.len() <= 48
            && k.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
            })
    }) && v.len() <= 256
        && v.bytes().all(|b| (0x20..0x7f).contains(&b))
}

/// The never-started `init --empty` instance a restore writes into (ipc.md 24, `dst`).
///
/// It is built from the desktop's definition as read from Incus, but by **allowlist**: its config
/// is exactly the keys privd sets on desktops ([`DESKTOP_CONFIG_KEYS`]), the Docker add-on's
/// ([`ALLOWED_INSTANCE_CONFIG`](crate::plan::ALLOWED_INSTANCE_CONFIG)) and plain `user.hx.*` keys;
/// its profiles are the hx desktop profile (and the compat profile if the desktop has it) of the
/// given [`Naming`]; its devices are the desktop's own `root` disk, on the pool, and nothing else
/// (the desktop's `hx-link` proxy device is not copied: started beside the desktop it would take
/// over the desktop's host socket). Anything else on the desktop (`raw.*`, `security.idmap.base`,
/// `linux.*`, another device, `security.privileged` true, `security.idmap.isolated` not true, a
/// `user.hx.kind` of its own) makes [`RestoreTargetSpec::from_desktop`] refuse. Not copied, without
/// error: `volatile.*` (runtime state, and `volatile.idmap.*` would give two instances one host
/// range) and `image.*` (descriptive keys Incus adds when it unpacks an image).
///
/// The target is marked `user.hx.kind=restore-target`, `user.hx.job=<job>` and
/// `user.hx.state=restoring`, and has `boot.autostart=false`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreTargetSpec {
    name: RestoreTargetName,
    job: JobId,
    pool: PoolName,
    architecture: String,
    profiles: Vec<String>,
    config: BTreeMap<String, String>,
    devices: BTreeMap<String, BTreeMap<String, String>>,
}

impl RestoreTargetSpec {
    /// Build the target for `desktop` (as returned by `get_instance`), for `job`, on the pool of
    /// `naming`. Refused with `InvalidArgument` as described on the type.
    pub fn from_desktop(
        desktop: &Instance,
        name: RestoreTargetName,
        job: JobId,
        naming: &Naming,
    ) -> Result<Self, IncusError> {
        let pool = PoolName::new(&naming.pool)?;
        DesktopName::new(&desktop.name).map_err(|_| {
            refuse(format_args!(
                "`{}` is not named like a desktop (hx-<id>)",
                desktop.name
            ))
        })?;
        if desktop.kind != "container" {
            return Err(refuse(format_args!(
                "the desktop is a `{}`, not a container",
                desktop.kind
            )));
        }
        if !super::marker::instance_is_marked(&desktop.config) {
            return Err(refuse("the desktop does not carry the hash-xcreen marker"));
        }
        if desktop.config.contains_key(HELPER_KIND_KEY) {
            return Err(refuse(format_args!(
                "the source carries {HELPER_KIND_KEY}: it is a helper or a target, not a desktop"
            )));
        }
        if desktop
            .config
            .get("security.idmap.isolated")
            .map(String::as_str)
            != Some("true")
        {
            return Err(refuse("the desktop is not on an isolated idmap"));
        }
        if root_pool(desktop).as_deref() != Some(pool.as_str()) {
            return Err(refuse(format_args!(
                "the desktop's root disk is not on pool `{pool}`"
            )));
        }

        // Profiles: only ours, starting with the desktop profile.
        let known = [&naming.desktop_profile, &naming.compat_profile];
        if desktop.profiles.first() != Some(&naming.desktop_profile)
            || desktop.profiles.iter().any(|p| !known.contains(&p))
            || desktop.profiles.len() > 2
            || (desktop.profiles.len() == 2 && desktop.profiles[0] == desktop.profiles[1])
        {
            return Err(refuse(format_args!(
                "profiles {:?} are not the hx desktop profile (and the compat profile)",
                desktop.profiles
            )));
        }

        // Config: allowlist.
        let mut config = BTreeMap::new();
        for (k, v) in &desktop.config {
            if k.starts_with("volatile.") || k.starts_with("image.") {
                continue;
            }
            if matches!(k.as_str(), HELPER_JOB_KEY | INSTANCE_STATE_KEY) {
                continue; // replaced below
            }
            let allowed = DESKTOP_CONFIG_KEYS.contains(&k.as_str())
                || crate::plan::ALLOWED_INSTANCE_CONFIG.contains(&k.as_str());
            if allowed {
                if !desktop_value_ok(k, v) {
                    return Err(refuse(format_args!("config `{k}` has the value {v:?}")));
                }
            } else if !hx_key_ok(k, v) {
                return Err(refuse(format_args!(
                    "config key `{k}` is not one privd sets on a desktop"
                )));
            }
            config.insert(k.clone(), v.clone());
        }
        config.insert("boot.autostart".into(), "false".into());
        config.insert(HELPER_KIND_KEY.into(), RESTORE_TARGET_KIND.into());
        config.insert(HELPER_JOB_KEY.into(), job.hex());
        config.insert(INSTANCE_STATE_KEY.into(), RESTORE_TARGET_STATE.into());

        // Devices: the root disk on the pool; `hx-link` is skipped; nothing else.
        let mut devices = BTreeMap::new();
        for (n, d) in &desktop.devices {
            let ty = d.get("type").map(String::as_str);
            if n == SESSION_LINK_DEVICE && ty == Some("proxy") {
                continue;
            }
            let size_ok = |s: &str| {
                s.strip_suffix("GiB")
                    .is_some_and(|n| bounded(n, MAX_DISK_GIB))
            };
            let ok = n == "root"
                && ty == Some("disk")
                && d.get("path").map(String::as_str) == Some("/")
                && d.get("pool").map(String::as_str) == Some(pool.as_str())
                && d.keys()
                    .all(|k| matches!(k.as_str(), "type" | "path" | "pool" | "size"))
                && d.get("size").is_none_or(|s| size_ok(s));
            if !ok {
                return Err(refuse(format_args!(
                    "device `{n}` is not the root disk on the pool"
                )));
            }
            devices.insert(n.clone(), d.clone());
        }
        let architecture = if desktop.architecture.len() <= 16
            && desktop
                .architecture
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            desktop.architecture.clone()
        } else {
            return Err(refuse("the architecture is not plain"));
        };
        Ok(Self {
            name,
            job,
            pool,
            architecture,
            profiles: desktop.profiles.clone(),
            config,
            devices,
        })
    }

    /// The target's name.
    pub fn name(&self) -> &RestoreTargetName {
        &self.name
    }

    /// The job.
    pub fn job(&self) -> JobId {
        self.job
    }

    /// The pool.
    pub fn pool(&self) -> &PoolName {
        &self.pool
    }

    /// The profiles.
    pub fn profiles(&self) -> &[String] {
        &self.profiles
    }

    /// The configuration (allowlisted keys, the restore-target marker, `boot.autostart=false`).
    pub fn config(&self) -> &BTreeMap<String, String> {
        &self.config
    }

    /// The instance-level devices (the `root` disk, or none).
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

    /// What is wrong with `inst` compared to this spec (read back after creation), if anything.
    pub(crate) fn mismatch(&self, inst: &Instance) -> Option<String> {
        if inst.profiles != self.profiles {
            return Some(format!("profiles are {:?}", inst.profiles));
        }
        if inst.devices != self.devices {
            return Some(format!("devices are {:?}", inst.devices));
        }
        config_mismatch(&self.config, &inst.expanded_config)
    }
}

/// The first key of `want` that `have` lacks or has with another value.
fn config_mismatch(
    want: &BTreeMap<String, String>,
    have: &BTreeMap<String, String>,
) -> Option<String> {
    want.iter()
        .find(|(k, v)| have.get(*k) != Some(*v))
        .map(|(k, v)| format!("config `{k}` is {:?}, expected {v:?}", have.get(k)))
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

/// A backup helper found in Incus (crash recovery, ipc.md 35 step 1): marked
/// `user.hx.kind=backup-worker`, named `hx-bkw-<8 hex>` and carrying a `user.hx.job` whose first
/// 8 digits are the name's. An instance that has the marker or the name but not the rest is not
/// listed, and no helper call will touch it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupHelperInfo {
    /// Its name.
    pub name: HelperName,
    /// The job id from `user.hx.job`.
    pub job: JobId,
    /// Run state text.
    pub status: String,
}

/// A restore target found in Incus (ipc.md 35 step 4): `user.hx.kind=restore-target` and an
/// `hx-restore-...` name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreTargetInfo {
    /// Its name.
    pub name: RestoreTargetName,
    /// The job id from `user.hx.job`, when present and well-formed.
    pub job: Option<JobId>,
    /// Run state text.
    pub status: String,
}

/// What is wrong with a created helper compared to its spec, if anything (ipc.md 24: no profile,
/// the exact devices, in particular no NIC, and every config key).
pub(crate) fn helper_mismatch(spec: &BackupHelperSpec, inst: &Instance) -> Option<String> {
    if !inst.profiles.is_empty() {
        return Some(format!("profiles are {:?}", inst.profiles));
    }
    if inst.expanded_devices != spec.devices() {
        return Some(format!("devices are {:?}", inst.expanded_devices));
    }
    config_mismatch(&spec.config(), &inst.expanded_config)
}
