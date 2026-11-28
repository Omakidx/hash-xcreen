//! What the job runner asks of the host: Incus (through `hx-provision`'s typed helper, snapshot and
//! restore-target calls) and systemd, behind one trait so that the runner is tested without a
//! real Incus or systemd (the checks, the allowlist, and the binding of a helper to its job are
//! `hx-provision`'s, tested there: `SnapshotMount::checked`, `TargetMount::checked`,
//! `RepoLink::new`, `BackupHelperSpec`).
//!
//! [`IncusHost`] is the production implementation. It never builds a mount, a device, a config
//! key or a path itself: every one comes from an `hx-provision` constructor that checks the
//! objects it derives them from (ipc.md section 24, section 7 rule 4).

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use hx_provision::host::Naming;
use hx_provision::incus::{
    BACKUP_SNAPSHOT_PREFIX, BackupHelperInfo, BackupHelperSpec, BackupSnapshotName, Client,
    HelperEnd, IncusError, JobId, PoolName, PreconditionFailed, RepoLink, RestoreTargetInfo,
    RestoreTargetName, RestoreTargetSpec, SnapshotMount, TargetMount, Transport,
    check_host_preconditions,
};

use crate::privd::probe::HostProbe;
use crate::privd::runner::{CommandRunner, Program, Tool};

/// Why a host call failed. The text is `hx-provision`'s or Incus's, never peer data.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HostError {
    /// A check of ipc.md section 24 failed: nothing was created.
    #[error("precondition failed: {0}")]
    Precondition(String),
    /// A call failed.
    #[error("{0}")]
    Failed(String),
}

impl From<IncusError> for HostError {
    fn from(e: IncusError) -> Self {
        Self::Failed(e.to_string())
    }
}

impl From<PreconditionFailed> for HostError {
    fn from(e: PreconditionFailed) -> Self {
        Self::Precondition(e.to_string())
    }
}

/// What the manifest needs to know about the desktop (ipc.md section 28, `BACKUP`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DesktopFacts {
    /// The recipe id text (`ubuntu-24.04-xfce-basic`).
    pub recipe: String,
    /// The instance's configuration (the spec builder drops `volatile.*` and what
    /// `hx_backup::manifest` does not allow).
    pub config: BTreeMap<String, String>,
}

/// What a job does with the desktop's files (the host's view of a job kind).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKind {
    /// `BACKUP`: the snapshot is mounted read-only.
    Backup,
    /// `RESTORE`: the target is mounted writable.
    Restore,
    /// Every other kind: no mount.
    RepositoryOnly,
}

/// Everything the host needs to make one job's helper.
#[derive(Debug, Clone)]
pub struct HelperPlan {
    /// The job (names the helper and the link socket).
    pub job: JobId,
    /// What the helper mounts.
    pub kind: HostKind,
    /// The desktop's instance name (`hx-<id>`); unused for [`HostKind::RepositoryOnly`].
    pub desktop_instance: String,
    /// The snapshot of a `BACKUP`.
    pub snapshot: Option<String>,
    /// The target of a `RESTORE`; the host creates it first, unless `reuse_target`.
    pub target: Option<String>,
    /// The target already exists (a resumed restore): build the helper on it, create nothing.
    pub reuse_target: bool,
    /// The worker binary, pushed as `/sbin/init`.
    pub worker: Arc<Vec<u8>>,
}

/// The Incus and systemd calls of the runner. Every method is safe to repeat.
pub trait BackupHost: Send + Sync + 'static {
    /// Takes the snapshot `snapshot` of `instance`.
    fn create_snapshot(
        &self,
        instance: &str,
        snapshot: &str,
    ) -> impl Future<Output = Result<(), HostError>> + Send;

    /// Deletes the snapshot; already gone is success.
    fn delete_snapshot(
        &self,
        instance: &str,
        snapshot: &str,
    ) -> impl Future<Output = Result<(), HostError>> + Send;

    /// The `hx-backup-...` snapshots of `instance`.
    fn list_backup_snapshots(
        &self,
        instance: &str,
    ) -> impl Future<Output = Result<Vec<String>, HostError>> + Send;

    /// What the manifest of a backup of `instance` records; `None` when the instance is gone.
    fn desktop_facts(
        &self,
        instance: &str,
    ) -> impl Future<Output = Result<Option<DesktopFacts>, HostError>> + Send;

    /// Runs the checks of section 24, then creates the helper, verifies it and pushes the
    /// worker. For a `RESTORE` it first creates the target named in the plan.
    fn create_helper(
        &self,
        plan: &HelperPlan,
    ) -> impl Future<Output = Result<(), HostError>> + Send;

    /// Starts the helper of `job`.
    fn start_helper(&self, job: JobId) -> impl Future<Output = Result<(), HostError>> + Send;

    /// Waits at most `wait` for the helper to be gone, then force-deletes it.
    fn finish_helper(
        &self,
        job: JobId,
        wait: Duration,
    ) -> impl Future<Output = Result<HelperEnd, HostError>> + Send;

    /// Stops and deletes the helper of `job` by force; `false` when there was none.
    fn force_delete_helper(
        &self,
        job: JobId,
    ) -> impl Future<Output = Result<bool, HostError>> + Send;

    /// The backup helpers that exist (marked, named and bound to a job).
    fn list_helpers(&self)
    -> impl Future<Output = Result<Vec<BackupHelperInfo>, HostError>> + Send;

    /// The restore targets that exist (marked `user.hx.kind=restore-target`).
    fn list_restore_targets(
        &self,
    ) -> impl Future<Output = Result<Vec<RestoreTargetInfo>, HostError>> + Send;

    /// Deletes a restore target (never an instance without the marker); `false` when gone.
    fn delete_restore_target(
        &self,
        name: &RestoreTargetName,
        job: Option<JobId>,
    ) -> impl Future<Output = Result<bool, HostError>> + Send;

    /// Whether the restore target `name` exists (it is listed as a marked target).
    fn restore_target_exists(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<bool, HostError>> + Send;

    /// Stops `hx-drive.service` (crash recovery step 5).
    fn stop_drive_service(&self) -> impl Future<Output = Result<(), HostError>> + Send;

    /// `(total, free)` bytes of the pool.
    fn pool_space(&self) -> Option<(u64, u64)>;
}

/// The production host: `hx-provision`'s Incus client, the closed set of host tools, the probe.
pub struct IncusHost<T: Transport + Clone + 'static> {
    client: Client<T>,
    naming: Naming,
    runner: Arc<dyn CommandRunner>,
    probe: Arc<dyn HostProbe>,
}

impl<T: Transport + Clone + 'static> IncusHost<T> {
    /// A host over `client`, for the pool of `naming`.
    pub fn new(
        client: Client<T>,
        naming: Naming,
        runner: Arc<dyn CommandRunner>,
        probe: Arc<dyn HostProbe>,
    ) -> Self {
        Self {
            client,
            naming,
            runner,
            probe,
        }
    }

    /// A client with its own set of in-flight operations (one per call, so that one call never
    /// waits for another's).
    fn c(&self) -> Client<T> {
        self.client.scoped()
    }
}

impl<T: Transport + Clone + 'static> BackupHost for IncusHost<T> {
    async fn create_snapshot(&self, instance: &str, snapshot: &str) -> Result<(), HostError> {
        BackupSnapshotName::new(snapshot)?;
        Ok(self.c().create_snapshot(instance, snapshot).await?)
    }

    async fn delete_snapshot(&self, instance: &str, snapshot: &str) -> Result<(), HostError> {
        // Only a backup snapshot, and only when it is there: privd never deletes another kind.
        BackupSnapshotName::new(snapshot)?;
        let c = self.c();
        if c.list_snapshots(instance)
            .await?
            .iter()
            .any(|s| s.name == snapshot)
        {
            c.delete_snapshot(instance, snapshot).await?;
        }
        Ok(())
    }

    async fn list_backup_snapshots(&self, instance: &str) -> Result<Vec<String>, HostError> {
        Ok(self
            .c()
            .list_snapshots(instance)
            .await?
            .into_iter()
            .map(|s| s.name)
            .filter(|n| n.starts_with(BACKUP_SNAPSHOT_PREFIX) && BackupSnapshotName::new(n).is_ok())
            .collect())
    }

    async fn desktop_facts(&self, instance: &str) -> Result<Option<DesktopFacts>, HostError> {
        let Some(inst) = self.c().get_instance(instance).await? else {
            return Ok(None);
        };
        let mut config = inst.config.clone();
        // The root disk's size is part of what a restore recreates (hx_backup::manifest).
        if let Some(size) = inst
            .expanded_devices
            .get("root")
            .and_then(|d| d.get("size"))
        {
            config.insert("root.size".into(), size.clone());
        }
        Ok(Some(DesktopFacts {
            recipe: inst
                .config
                .get("user.hx.recipe")
                .cloned()
                .unwrap_or_default(),
            config,
        }))
    }

    async fn create_helper(&self, plan: &HelperPlan) -> Result<(), HostError> {
        let c = self.c();
        let server = c.server_info().await?;
        let pool = c
            .get_storage_pool(&self.naming.pool)
            .await?
            .ok_or_else(|| HostError::Precondition("the storage pool does not exist".into()))?;
        let link = RepoLink::new(plan.job);
        let spec =
            match plan.kind {
                HostKind::Backup => {
                    let snapshot = plan.snapshot.as_deref().ok_or_else(|| {
                        HostError::Precondition("a backup needs a snapshot".into())
                    })?;
                    let desktop = c
                        .get_instance(&plan.desktop_instance)
                        .await?
                        .ok_or_else(|| HostError::Precondition("the desktop is gone".into()))?;
                    let snap = c
                        .list_snapshots(&plan.desktop_instance)
                        .await?
                        .into_iter()
                        .find(|s| s.name == snapshot)
                        .ok_or_else(|| HostError::Precondition("the snapshot is gone".into()))?;
                    BackupHelperSpec::backup(
                        SnapshotMount::checked(&server, &pool, &desktop, &snap)?,
                        link,
                    )
                }
                HostKind::Restore => {
                    let target = plan.target.as_deref().ok_or_else(|| {
                        HostError::Precondition("a restore needs a target".into())
                    })?;
                    check_host_preconditions(&server, &pool)?;
                    let desktop = c
                        .get_instance(&plan.desktop_instance)
                        .await?
                        .ok_or_else(|| HostError::Precondition("the desktop is gone".into()))?;
                    let name = RestoreTargetName::new(target)?;
                    if !plan.reuse_target {
                        let spec = RestoreTargetSpec::from_desktop(
                            &desktop,
                            name.clone(),
                            plan.job,
                            &self.naming,
                        )?;
                        c.create_restore_target(&spec, Duration::from_secs(300))
                            .await?;
                    }
                    let made = c
                        .get_instance(name.as_str())
                        .await?
                        .ok_or_else(|| HostError::Failed("the restore target vanished".into()))?;
                    BackupHelperSpec::restore(TargetMount::checked(&server, &pool, &made)?, link)
                }
                HostKind::RepositoryOnly => {
                    check_host_preconditions(&server, &pool)?;
                    BackupHelperSpec::repository_only(PoolName::new(&pool.name)?, link)
                }
            };
        c.create_backup_helper(&spec).await?;
        c.populate_backup_helper(&spec, &plan.worker).await?;
        Ok(())
    }

    async fn start_helper(&self, job: JobId) -> Result<(), HostError> {
        Ok(self.c().start_backup_helper(job).await?)
    }

    async fn finish_helper(&self, job: JobId, wait: Duration) -> Result<HelperEnd, HostError> {
        Ok(self.c().finish_backup_helper(job, wait).await?)
    }

    async fn force_delete_helper(&self, job: JobId) -> Result<bool, HostError> {
        Ok(self.c().force_delete_backup_helper(job).await?)
    }

    async fn list_helpers(&self) -> Result<Vec<BackupHelperInfo>, HostError> {
        Ok(self.c().list_backup_helpers().await?)
    }

    async fn list_restore_targets(&self) -> Result<Vec<RestoreTargetInfo>, HostError> {
        Ok(self.c().list_restore_targets().await?)
    }

    async fn delete_restore_target(
        &self,
        name: &RestoreTargetName,
        job: Option<JobId>,
    ) -> Result<bool, HostError> {
        Ok(self.c().delete_restore_target(name, job).await?)
    }

    async fn restore_target_exists(&self, name: &str) -> Result<bool, HostError> {
        Ok(self
            .c()
            .list_restore_targets()
            .await?
            .iter()
            .any(|t| t.name.as_str() == name))
    }

    async fn stop_drive_service(&self) -> Result<(), HostError> {
        let out = self
            .runner
            .run(Program::new(Tool::Systemctl, &["stop", "hx-drive.service"]))
            .await
            .map_err(|e| HostError::Failed(format!("cannot run systemctl: {e}")))?;
        if out.success() {
            Ok(())
        } else {
            Err(HostError::Failed(
                "systemctl stop hx-drive.service failed".into(),
            ))
        }
    }

    fn pool_space(&self) -> Option<(u64, u64)> {
        self.probe.pool_space(&self.naming.pool)
    }
}
