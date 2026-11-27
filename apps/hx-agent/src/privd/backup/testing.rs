//! Fakes of the runner's two seams, for the tests of this crate and its integration tests (the
//! `test-support` feature): [`FakeHost`] (Incus and systemd) and [`FakeEnv`] (the daemon).
//!
//! The fake host never touches Incus. `start_helper` calls a hook that the test uses to start a
//! fake worker on the job's socket path, and `force_delete_helper` calls another that tells it to
//! die, so a test can see exactly what privd asked of the host (`FakeHost::log`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hx_provision::incus::{
    BackupHelperInfo, HelperEnd, HelperName, JobId, RestoreTargetInfo, RestoreTargetName,
};

use super::host::{BackupHost, DesktopFacts, HelperPlan, HostError};
use super::{Alert, BackupEnv, BoxFuture, LockGuard};
use crate::privd::cancel::CancelToken;
use crate::privd::state::Flag;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// What the fake daemon records.
pub struct FakeEnv {
    /// Every audit line.
    pub audit_lines: Mutex<Vec<String>>,
    /// Flags set, as `(desktop or None, flag)`.
    pub flags: Mutex<BTreeSet<(Option<String>, Flag)>>,
    /// Alerts raised.
    pub alerts: Mutex<Vec<Alert>>,
    /// The desktops privd manages.
    pub desktops: Mutex<Vec<String>>,
    /// Whether an uninstall has begun.
    pub uninstalling: AtomicBool,
    /// The wall clock, Unix seconds.
    pub now: AtomicU64,
    /// How many times the desktop lock was taken.
    pub locks: AtomicUsize,
}

impl FakeEnv {
    /// An env that manages `desktops`, with the wall clock at 1 800 000 000.
    pub fn new(desktops: &[&str]) -> Arc<Self> {
        Arc::new(Self {
            audit_lines: Mutex::new(Vec::new()),
            flags: Mutex::new(BTreeSet::new()),
            alerts: Mutex::new(Vec::new()),
            desktops: Mutex::new(desktops.iter().map(|s| (*s).to_string()).collect()),
            uninstalling: AtomicBool::new(false),
            now: AtomicU64::new(1_800_000_000),
            locks: AtomicUsize::new(0),
        })
    }

    /// The audit lines so far.
    pub fn audit_log(&self) -> Vec<String> {
        lock(&self.audit_lines).clone()
    }

    /// Whether a flag is set (`desktop` `None` is host-wide).
    pub fn has_flag(&self, desktop: Option<&str>, flag: Flag) -> bool {
        lock(&self.flags).contains(&(desktop.map(str::to_string), flag))
    }
}

impl BackupEnv for FakeEnv {
    fn now_unix(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }

    fn audit(&self, text: &str) {
        lock(&self.audit_lines).push(text.to_string());
    }

    fn set_flag(&self, desktop: Option<&str>, flag: Flag, on: bool) {
        let key = (desktop.map(str::to_string), flag);
        if on {
            lock(&self.flags).insert(key);
        } else {
            lock(&self.flags).remove(&key);
        }
    }

    fn flags_for(&self, desktop: &str) -> Vec<Flag> {
        lock(&self.flags)
            .iter()
            .filter(|(d, _)| d.is_none() || d.as_deref() == Some(desktop))
            .map(|(_, f)| *f)
            .collect()
    }

    fn desktop_known(&self, desktop: &str) -> bool {
        lock(&self.desktops).iter().any(|d| d == desktop)
    }

    fn desktops(&self) -> Vec<String> {
        lock(&self.desktops).clone()
    }

    fn uninstalling(&self) -> bool {
        self.uninstalling.load(Ordering::SeqCst)
    }

    fn alert(&self, alert: &Alert) {
        lock(&self.alerts).push(alert.clone());
    }

    fn lock_desktop<'a>(
        &'a self,
        _desktop: &'a str,
        _cancel: &'a CancelToken,
    ) -> BoxFuture<'a, Result<LockGuard, String>> {
        self.locks.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(Box::new(()) as LockGuard) })
    }
}

/// What the start hook is told.
#[derive(Debug, Clone)]
pub struct StartInfo {
    /// The job.
    pub job: JobId,
    /// The path of the job's socket in the run directory (`<run dir>/<job>.sock`).
    pub socket: PathBuf,
}

type StartHook = Arc<dyn Fn(StartInfo) + Send + Sync>;
type KillHook = Arc<dyn Fn(JobId) + Send + Sync>;

#[derive(Default)]
struct HostState {
    snapshots: BTreeMap<String, BTreeSet<String>>,
    helpers: BTreeMap<String, JobId>,
    targets: BTreeMap<String, Option<JobId>>,
    unmarked_targets: BTreeSet<String>,
    log: Vec<String>,
    fail: BTreeMap<String, HostError>,
    drive_stops: usize,
    pool: Option<(u64, u64)>,
    facts: Option<DesktopFacts>,
    list_fails: bool,
}

/// A fake host: Incus objects in memory, and a log of every call.
pub struct FakeHost {
    run_dir: PathBuf,
    state: Mutex<HostState>,
    on_start: Mutex<Option<StartHook>>,
    on_kill: Mutex<Option<KillHook>>,
}

impl FakeHost {
    /// A host whose job sockets are in `run_dir`, with a roomy pool and a desktop that has the
    /// facts of an Ubuntu 24.04 XFCE desktop.
    pub fn new(run_dir: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            run_dir,
            state: Mutex::new(HostState {
                pool: Some((100 << 30, 80 << 30)),
                facts: Some(DesktopFacts {
                    recipe: "ubuntu-24.04-xfce-basic".into(),
                    config: [("limits.cpu", "2"), ("limits.memory", "4GiB")]
                        .into_iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect(),
                }),
                ..HostState::default()
            }),
            on_start: Mutex::new(None),
            on_kill: Mutex::new(None),
        })
    }

    /// Called when the helper of a job is started: start the fake worker on `socket`.
    pub fn set_on_start(&self, f: impl Fn(StartInfo) + Send + Sync + 'static) {
        *lock(&self.on_start) = Some(Arc::new(f));
    }

    /// Called when a helper is force-deleted: stop the fake worker.
    pub fn set_on_kill(&self, f: impl Fn(JobId) + Send + Sync + 'static) {
        *lock(&self.on_kill) = Some(Arc::new(f));
    }

    /// Every call so far, as text (`create_snapshot hx-main hx-backup-...`).
    pub fn log(&self) -> Vec<String> {
        lock(&self.state).log.clone()
    }

    /// How many log entries start with `prefix`.
    pub fn count(&self, prefix: &str) -> usize {
        lock(&self.state)
            .log
            .iter()
            .filter(|l| l.starts_with(prefix))
            .count()
    }

    /// Makes the next call of `op` (`create_snapshot`, `create_helper`, `start_helper`,
    /// `delete_snapshot`, `force_delete_helper`, `finish_helper`, `delete_restore_target`,
    /// `stop_drive_service`) fail once.
    pub fn fail_once(&self, op: &str, e: HostError) {
        lock(&self.state).fail.insert(op.to_string(), e);
    }

    /// Makes `list_helpers` and `list_restore_targets` fail (Incus down).
    pub fn set_list_fails(&self, on: bool) {
        lock(&self.state).list_fails = on;
    }

    /// Sets `(total, free)` bytes of the pool; `None` is an unreadable pool.
    pub fn set_pool(&self, pool: Option<(u64, u64)>) {
        lock(&self.state).pool = pool;
    }

    /// Seeds a helper of `job` (a leftover of a crash).
    pub fn add_helper(&self, job: JobId) {
        lock(&self.state).helpers.insert(job.hex(), job);
    }

    /// Seeds a backup snapshot of `instance`.
    pub fn add_snapshot(&self, instance: &str, name: &str) {
        lock(&self.state)
            .snapshots
            .entry(instance.to_string())
            .or_default()
            .insert(name.to_string());
    }

    /// Seeds a marked restore target.
    pub fn add_target(&self, name: &str, job: Option<JobId>) {
        lock(&self.state).targets.insert(name.to_string(), job);
    }

    /// Seeds an `hx-restore-` instance that does not carry the marker: never listed, never
    /// touched.
    pub fn add_unmarked_target(&self, name: &str) {
        lock(&self.state).unmarked_targets.insert(name.to_string());
    }

    /// The helpers that exist (job hex).
    pub fn helpers(&self) -> Vec<String> {
        lock(&self.state).helpers.keys().cloned().collect()
    }

    /// The snapshots of `instance`.
    pub fn snapshots(&self, instance: &str) -> Vec<String> {
        lock(&self.state)
            .snapshots
            .get(instance)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// The restore targets that exist.
    pub fn targets(&self) -> Vec<String> {
        lock(&self.state).targets.keys().cloned().collect()
    }

    /// The unmarked targets (never touched).
    pub fn unmarked_targets(&self) -> Vec<String> {
        lock(&self.state).unmarked_targets.iter().cloned().collect()
    }

    /// How many times `hx-drive.service` was stopped.
    pub fn drive_stops(&self) -> usize {
        lock(&self.state).drive_stops
    }

    /// The helper exited by itself (PID 1 ended and Incus deleted the ephemeral instance).
    pub fn helper_exited(&self, job: JobId) {
        let mut s = lock(&self.state);
        s.helpers.remove(&job.hex());
        s.log.push(format!("helper_exited {}", job.helper_name()));
    }

    fn step(&self, entry: String, op: &str) -> Result<(), HostError> {
        let mut s = lock(&self.state);
        s.log.push(entry);
        match s.fail.remove(op) {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

impl BackupHost for Arc<FakeHost> {
    async fn create_snapshot(&self, instance: &str, snapshot: &str) -> Result<(), HostError> {
        self.step(
            format!("create_snapshot {instance} {snapshot}"),
            "create_snapshot",
        )?;
        lock(&self.state)
            .snapshots
            .entry(instance.to_string())
            .or_default()
            .insert(snapshot.to_string());
        Ok(())
    }

    async fn delete_snapshot(&self, instance: &str, snapshot: &str) -> Result<(), HostError> {
        self.step(
            format!("delete_snapshot {instance} {snapshot}"),
            "delete_snapshot",
        )?;
        if let Some(s) = lock(&self.state).snapshots.get_mut(instance) {
            s.remove(snapshot);
        }
        Ok(())
    }

    async fn list_backup_snapshots(&self, instance: &str) -> Result<Vec<String>, HostError> {
        let s = lock(&self.state);
        if s.list_fails {
            return Err(HostError::Failed("Incus is down".into()));
        }
        Ok(s.snapshots
            .get(instance)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default())
    }

    async fn desktop_facts(&self, instance: &str) -> Result<Option<DesktopFacts>, HostError> {
        let s = lock(&self.state);
        let _ = instance;
        Ok(s.facts.clone())
    }

    async fn create_helper(&self, plan: &HelperPlan) -> Result<(), HostError> {
        self.step(
            format!(
                "create_helper {} {:?} snapshot={:?} target={:?}",
                plan.job.helper_name(),
                plan.kind,
                plan.snapshot,
                plan.target
            ),
            "create_helper",
        )?;
        let mut s = lock(&self.state);
        if let Some(t) = &plan.target {
            s.targets.insert(t.clone(), Some(plan.job));
        }
        s.helpers.insert(plan.job.hex(), plan.job);
        Ok(())
    }

    async fn start_helper(&self, job: JobId) -> Result<(), HostError> {
        self.step(
            format!("start_helper {}", job.helper_name()),
            "start_helper",
        )?;
        let hook = lock(&self.on_start).clone();
        if let Some(h) = hook {
            h(StartInfo {
                job,
                socket: self.run_dir.join(format!("{}.sock", job.hex())),
            });
        }
        Ok(())
    }

    async fn finish_helper(&self, job: JobId, wait: Duration) -> Result<HelperEnd, HostError> {
        self.step(
            format!("finish_helper {}", job.helper_name()),
            "finish_helper",
        )?;
        // The fake worker ends its helper when it exits: give it a moment, then force.
        for _ in 0..40 {
            if !lock(&self.state).helpers.contains_key(&job.hex()) {
                return Ok(HelperEnd::Exited(Duration::ZERO));
            }
            tokio::time::sleep(Duration::from_millis(5).min(wait)).await;
        }
        lock(&self.state).log.push(format!(
            "force_delete_helper {} (after finish)",
            job.helper_name()
        ));
        lock(&self.state).helpers.remove(&job.hex());
        if let Some(k) = lock(&self.on_kill).clone() {
            k(job);
        }
        Ok(HelperEnd::ForceDeleted)
    }

    async fn force_delete_helper(&self, job: JobId) -> Result<bool, HostError> {
        self.step(
            format!("force_delete_helper {}", job.helper_name()),
            "force_delete_helper",
        )?;
        let existed = lock(&self.state).helpers.remove(&job.hex()).is_some();
        if let Some(k) = lock(&self.on_kill).clone() {
            k(job);
        }
        Ok(existed)
    }

    async fn list_helpers(&self) -> Result<Vec<BackupHelperInfo>, HostError> {
        let s = lock(&self.state);
        if s.list_fails {
            return Err(HostError::Failed("Incus is down".into()));
        }
        Ok(s.helpers
            .values()
            .map(|j| BackupHelperInfo {
                name: j.helper_name(),
                job: *j,
                status: "Running".into(),
            })
            .collect())
    }

    async fn list_restore_targets(&self) -> Result<Vec<RestoreTargetInfo>, HostError> {
        let s = lock(&self.state);
        if s.list_fails {
            return Err(HostError::Failed("Incus is down".into()));
        }
        Ok(s.targets
            .iter()
            .filter_map(|(n, j)| {
                Some(RestoreTargetInfo {
                    name: RestoreTargetName::new(n).ok()?,
                    job: *j,
                    status: "Stopped".into(),
                })
            })
            .collect())
    }

    async fn delete_restore_target(
        &self,
        name: &RestoreTargetName,
        job: Option<JobId>,
    ) -> Result<bool, HostError> {
        self.step(
            format!(
                "delete_restore_target {name} job={}",
                job.map(|j| j.hex()).unwrap_or_default()
            ),
            "delete_restore_target",
        )?;
        Ok(lock(&self.state).targets.remove(name.as_str()).is_some())
    }

    async fn stop_drive_service(&self) -> Result<(), HostError> {
        self.step("stop_drive_service".into(), "stop_drive_service")?;
        lock(&self.state).drive_stops += 1;
        Ok(())
    }

    fn pool_space(&self) -> Option<(u64, u64)> {
        lock(&self.state).pool
    }
}

/// The helper's name for a job, for assertions.
pub fn helper_name(job: JobId) -> HelperName {
    job.helper_name()
}
