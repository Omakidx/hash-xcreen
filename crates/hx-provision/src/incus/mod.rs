//! A typed client for the Incus REST API over its unix socket.
//!
//! `hx-privd` talks to Incus through this module instead of scraping the `incus` CLI. The client
//! covers what provisioning needs: server version, storage pool, bridge network, network ACLs,
//! profiles, instance lifecycle, exec, file push and snapshots. Mutating calls follow Incus's
//! background-operation model and wait for completion with a deadline.

mod backup;
mod client;
mod error;
mod limits;
mod link;
mod marker;
mod operation;
mod transport;
mod types;
mod version;

pub use backup::{
    BACKUP_SNAPSHOT_PREFIX, BackupHelperInfo, BackupHelperSpec, BackupSnapshotName, DesktopName,
    HELPER_JOB_KEY, HELPER_KIND, HELPER_KIND_KEY, HELPER_PREFIX, HELPER_ROOT_SIZE, HelperEnd,
    HelperName, JobId, JobKind, PoolName, PreconditionFailed, REPO_DEVICE, REPO_LINK_CONNECT,
    REPO_LINK_HOST_DIR, REPO_LINK_MODE, RESTORE_TARGET_KIND, RESTORE_TARGET_PREFIX,
    RESTORE_TARGET_STATE, RepoLink, RestoreTargetInfo, RestoreTargetName, RestoreTargetSpec,
    SNAPSHOT_DEVICE, SNAPSHOT_MOUNT_PATH, STORAGE_POOLS_ROOT, SUN_PATH_MAX, SnapshotMount,
    TARGET_DEVICE, TARGET_MOUNT_PATH, TargetMount, WORKER_INIT_PATH, check_host_preconditions,
};
pub use client::{Client, IMAGE_ALIAS_PREFIX, PathStat};
pub use error::IncusError;
pub use limits::{LimitsApplied, LimitsUpdate, MAX_CPU, MAX_DISK_GIB, MAX_MEMORY_MIB};
pub use link::{
    LinkOutcome, SESSION_LINK_CONNECT, SESSION_LINK_DEVICE, SESSION_LINK_HOST_DIR,
    SESSION_LINK_MODE, SessionLink,
};
pub use marker::{
    INSTANCE_KEY_PREFIX, INSTANCE_STATE_KEY, MARKER, NETWORK_DESCRIPTION, POOL_DESCRIPTION,
    description_is_marked, instance_is_marked,
};
pub use operation::{OperationEnd, OperationId};
pub use transport::{MAX_BODY, Request, Response, Transport, UPLOAD_FRAME, UnixTransport};
pub use types::{
    Acl, AclAction, AclRule, ExecResult, ExecSpec, IMAGES_SERVER, ImageInfo, ImageSource,
    ImageUpload, Instance, InstanceCreate, InstanceState, MAX_OUTPUT, Network, ObjectInfo,
    Operation, ProfileSpec, ServerInfo, Snapshot, StateAction, StoragePool,
};
pub use version::{DOCKER_MIN_INCUS, IncusVersion, ParseVersionError};
