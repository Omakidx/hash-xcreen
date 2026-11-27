//! The job runner: admission, the job task and the internal API (ipc.md sections 26 and 35).
//!
//! ```text
//! start(JobRequest)
//!   admission (no slot, no record, nothing in Incus until all of it passes)
//!   take the slot, write job.json
//!   task:  Drive session -> snapshot -> helper -> worker link -> relay -> cleanup -> outcome
//! ```
//!
//! The runner is generic over [`BackupHost`] (Incus and systemd) and [`BackupEnv`] (the daemon's
//! audit, flags, registry and desktop lock), so the whole path is tested with fakes; the daemon
//! holds a `JobRunner<IncusHost<T>, DaemonEnv<T>>`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hx_backup::manifest::Manifest;
use hx_ipc::repo::pb::{self, ErrorClass, JobKind, WorkerError};
use hx_provision::incus::JobId;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use zeroize::Zeroizing;

use super::completed::{CompletedRecord, entry_from_result};
use super::creds::{CredError, drive_token_present, read_backup_key};
use super::drive_link::{self, OpenParams};
use super::host::{BackupHost, HelperPlan, HostKind};
use super::progress::{JobProgress, cleanup_index};
use super::recovery::{Recovery, RecoveryReport, check_run_dir};
use super::relay::{Reporter, RunEnd, Session};
use super::slot::{
    Backoff, BackoffReason, BackupDirs, JobRecord, RecordError, ResumeRecord, SlotGuard, SlotTable,
    hex, kind_name, remove_record,
};
use super::spec::{BuildCtx, JobSecrets, JobSpec, SpecError, build_job};
use super::worker_link;
use super::{
    Alert, AlertKind, BackupConfig, BackupEnv, Failure, JOB_FRAME_SLOTS, JobOutcome, JobState,
    JobStatus, JobSuccess, RELAY_FRAME_SLOTS,
};
use crate::privd::cancel::{CancelReason, CancelToken};
use crate::privd::progress::ProgressSender;
use crate::privd::state::Flag;

const GIB: u64 = 1 << 30;

/// Where the repository password (slot 0) comes from.
pub enum RepoPassword {
    /// The host's backup key (`$CREDENTIALS_DIRECTORY/backup-key`, ipc.md section 34).
    HostBackupKey,
    /// A secret the caller holds (the recovery key on a new server).
    Provided(Zeroizing<Vec<u8>>),
}

/// What the caller asks the runner to do.
pub struct JobRequest {
    /// The desktop whose repository the job works on.
    pub desktop_id: String,
    /// The job.
    pub spec: JobSpec,
    /// Slot 0.
    pub repo_password: RepoPassword,
    /// Slot 1 (`INIT`: the recovery key; `KEYS` with `add`: the new key).
    pub new_key_password: Option<Zeroizing<Vec<u8>>>,
    /// Take the Drive lease over (the restore onto a new server, the re-claim).
    pub takeover: bool,
    /// The repository folder in Drive; `None` is privd's constant for this server and desktop
    /// (`hx-<first 8 hex digits of the server id>-<desktop id>`).
    pub folder: Option<String>,
    /// Where the §4 `Progress` frames of the job go.
    pub progress: Option<ProgressSender>,
}

/// Why a job was not admitted. Nothing was created.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StartError {
    /// Crash recovery has not finished.
    #[error("crash recovery has not finished")]
    Recovering,
    /// An uninstall has begun.
    #[error("an uninstall has begun")]
    Uninstalling,
    /// privd does not manage this desktop.
    #[error("unknown desktop")]
    UnknownDesktop,
    /// The desktop's slot is held.
    #[error("a job is already running for this desktop")]
    Busy,
    /// A back-off refuses writing jobs until then (Unix seconds).
    #[error("writing jobs are refused until {until_unix}")]
    Backoff {
        /// When it ends.
        until_unix: u64,
    },
    /// `needs_attention=BACKUP_TAKEN_OVER` is set.
    #[error("this backup is used by another server")]
    TakenOver,
    /// The Drive token credential is missing; `DRIVE_RECONNECT` was set.
    #[error("the Drive token is missing; reconnect Google Drive")]
    DriveReconnect,
    /// The pool has too little free space for a snapshot.
    #[error("the storage pool has too little free space for a snapshot")]
    DiskFull,
    /// The backup key cannot be used.
    #[error(transparent)]
    BackupKey(#[from] CredError),
    /// The spec or the secrets are not valid (the rule's name).
    #[error("invalid job: {0}")]
    Invalid(String),
    /// A restore target is kept (`resume.json`): resume it with a `resumable` restore, or tear
    /// it down first; it is never overwritten.
    #[error("a restore target is kept; resume it or remove it first")]
    ResumePending,
    /// A record cannot be read or written, or recovery of a leftover failed.
    #[error("{0}")]
    Record(String),
    /// A host call failed before the slot was taken.
    #[error("{0}")]
    Host(String),
    /// A bug.
    #[error("{0}")]
    Internal(String),
}

/// A started job.
#[derive(Clone)]
pub struct JobHandle {
    /// The job id, 32 hex digits.
    pub job_id: String,
    /// The desktop.
    pub desktop_id: String,
    status: watch::Receiver<JobStatus>,
    cancel: CancelToken,
}

impl JobHandle {
    /// The latest status.
    pub fn status(&self) -> JobStatus {
        self.status.borrow().clone()
    }

    /// The latest progress frame privd emitted.
    pub fn progress(&self) -> Option<JobProgress> {
        self.status.borrow().progress
    }

    /// A receiver that changes whenever the state, the progress or the outcome does.
    pub fn watch(&self) -> watch::Receiver<JobStatus> {
        self.status.clone()
    }

    /// Asks the job to stop (ipc.md section 32). Returns at once; `finished` waits for the end.
    pub fn cancel(&self) {
        self.cancel.cancel(CancelReason::Cancelled);
    }

    /// Waits for the outcome.
    pub async fn finished(&self) -> Arc<JobOutcome> {
        let mut rx = self.status.clone();
        loop {
            if let Some(o) = rx.borrow_and_update().outcome.clone() {
                return o;
            }
            if rx.changed().await.is_err() {
                // The task ended without a final status: only a panic does that.
                return Arc::new(JobOutcome {
                    job_id: self.job_id.clone(),
                    kind: JobKind::Unspecified,
                    desktop_id: self.desktop_id.clone(),
                    result: Err(Failure::Internal("the job task ended".into())),
                    permission_answers: 0,
                });
            }
        }
    }
}

struct Active {
    job_id: String,
    cancel: CancelToken,
    status: watch::Receiver<JobStatus>,
}

struct Inner<H: BackupHost, E: BackupEnv> {
    cfg: BackupConfig,
    host: H,
    env: Arc<E>,
    mono: Arc<dyn super::clock::Monotonic>,
    dirs: BackupDirs,
    slots: SlotTable,
    budget: Arc<Semaphore>,
    active: Mutex<HashMap<String, Active>>,
    last: Mutex<HashMap<String, JobStatus>>,
    recovered: AtomicBool,
}

/// The runner. Cloning shares it.
pub struct JobRunner<H: BackupHost, E: BackupEnv> {
    inner: Arc<Inner<H, E>>,
}

impl<H: BackupHost, E: BackupEnv> Clone for JobRunner<H, E> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Which failures end in which state of privd (ipc.md section 31, "Effects"); separated from the
/// task so that it is tested on its own.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Effects {
    /// Set `DRIVE_RECONNECT` (host-wide).
    pub drive_reconnect: bool,
    /// Set `BACKUP_TAKEN_OVER` for the desktop.
    pub taken_over: bool,
    /// A back-off for writing jobs, and why.
    pub backoff: Option<BackoffReason>,
    /// Raise the owner alert.
    pub alert_integrity: bool,
}

/// The effects of a failure.
pub fn effects_of(f: &Failure) -> Effects {
    let mut e = Effects::default();
    match f {
        Failure::Repo(ErrorClass::AuthRevoked) => e.drive_reconnect = true,
        Failure::Repo(ErrorClass::LeaseHeld) => e.taken_over = true,
        Failure::Repo(ErrorClass::DailyLimit) => e.backoff = Some(BackoffReason::DailyLimit),
        Failure::Repo(ErrorClass::PolicyDenied) | Failure::PolicyDenied => {
            e.backoff = Some(BackoffReason::PolicyDenied);
        }
        Failure::Repo(ErrorClass::Integrity) | Failure::Integrity => {
            e.backoff = Some(BackoffReason::Integrity);
            e.alert_integrity = true;
        }
        Failure::WorkerFailed(WorkerError::Integrity) => {
            e.backoff = Some(BackoffReason::Integrity);
            e.alert_integrity = true;
        }
        Failure::Repo(ErrorClass::TooLarge) | Failure::TooLarge => {
            e.backoff = Some(BackoffReason::TooLarge);
        }
        _ => {}
    }
    e
}

/// What the job loop and the setup left, turned into the outcome (ipc.md section 31: privd
/// classifies by what it relayed itself, never by the worker's claim; a success that was already
/// on its way beats a cancel or a deadline).
pub fn classify(setup: Option<Failure>, end: Option<RunEnd>) -> Result<pb::JobResult, Failure> {
    if let Some(f) = setup {
        return Err(f);
    }
    let Some(end) = end else {
        return Err(Failure::Internal("no result".into()));
    };
    // An accepted successful result wins over anything that follows it (a lost link, silence, a
    // violation after the result) as it wins over a cancel and a deadline: the backup exists and
    // is recorded, and the outcome says so.
    if let Some(r) = &end.result
        && r.ok
    {
        return Ok(r.clone());
    }
    if let Some(f) = end.forced {
        return Err(f);
    }
    match end.result {
        Some(r) if r.ok => Ok(r),
        Some(r) => {
            if let Some(d) = end.drain {
                return Err(d);
            }
            if let Some(c) = end.first_err {
                return Err(Failure::Repo(c));
            }
            Err(
                match WorkerError::try_from(r.error).unwrap_or(WorkerError::Engine) {
                    WorkerError::Repo | WorkerError::Unspecified => {
                        Failure::Repo(ErrorClass::Internal)
                    }
                    WorkerError::Cancelled => Failure::Cancelled,
                    e => Failure::WorkerFailed(e),
                },
            )
        }
        None => Err(end
            .drain
            .unwrap_or_else(|| Failure::HelperFailed("the worker ended without a result".into()))),
    }
}

impl<H: BackupHost, E: BackupEnv> JobRunner<H, E> {
    /// A runner. Crash recovery has not run: call [`JobRunner::recover`] first.
    pub fn new(
        cfg: BackupConfig,
        host: H,
        env: Arc<E>,
        mono: Arc<dyn super::clock::Monotonic>,
    ) -> Self {
        let dirs = BackupDirs::new(&cfg.state_dir);
        Self {
            inner: Arc::new(Inner {
                cfg,
                host,
                env,
                mono,
                dirs,
                slots: SlotTable::default(),
                budget: Arc::new(Semaphore::new(RELAY_FRAME_SLOTS)),
                active: Mutex::new(HashMap::new()),
                last: Mutex::new(HashMap::new()),
                recovered: AtomicBool::new(false),
            }),
        }
    }

    /// Relay frame slots not in use (16 when no job holds one; ipc.md section 25).
    pub fn relay_slots_free(&self) -> usize {
        self.inner.budget.available_permits()
    }

    /// Whether crash recovery has completed.
    pub fn is_recovered(&self) -> bool {
        self.inner.recovered.load(Ordering::SeqCst)
    }

    /// Crash recovery (ipc.md section 35). Jobs are admitted once a run reports `complete`.
    pub async fn recover(&self) -> RecoveryReport {
        let i = &self.inner;
        let rep = Recovery {
            host: &i.host,
            env: i.env.as_ref(),
            cfg: &i.cfg,
            dirs: &i.dirs,
        }
        .recover_all()
        .await;
        if rep.complete {
            i.recovered.store(true, Ordering::SeqCst);
        }
        rep
    }

    /// The cleanup for `DestroyDesktop` (`all` false: the scope is `desktops`) and `Uninstall`
    /// (`all` true: the host). Cancels and waits for the active jobs of the scope (at most
    /// 60 s), then removes the helpers, restore targets (resumable or not) and sockets of the
    /// scope and the job and resume records of `desktops` (ipc.md section 35).
    pub async fn teardown_cleanup(&self, desktops: &[String], all: bool) -> RecoveryReport {
        let i = &self.inner;
        let mut jobs = Vec::new();
        let mut scoped = Vec::new();
        for (d, a) in lock(&i.active).iter() {
            if all || desktops.contains(d) {
                a.cancel.cancel(CancelReason::Cancelled);
                jobs.push(a.job_id.clone());
                scoped.push(d.clone());
            }
        }
        let started = i.mono.now_ms();
        let wait = u64::try_from(i.cfg.timing.teardown_wait.as_millis()).unwrap_or(0);
        while {
            let a = lock(&i.active);
            scoped.iter().any(|d| a.contains_key(d))
        } && i.mono.now_ms().saturating_sub(started) < wait
        {
            tokio::time::sleep(i.cfg.timing.tick).await;
        }
        Recovery {
            host: &i.host,
            env: i.env.as_ref(),
            cfg: &i.cfg,
            dirs: &i.dirs,
        }
        .teardown(desktops, all, &jobs)
        .await
    }

    /// The status of the latest job of `desktop`: the running one, else the last that ended
    /// (in memory only).
    pub fn status(&self, desktop: &str) -> Option<JobStatus> {
        let i = &self.inner;
        if let Some(a) = lock(&i.active).get(desktop) {
            return Some(a.status.borrow().clone());
        }
        lock(&i.last).get(desktop).cloned()
    }

    /// Cancels the active job of `desktop`; `false` when there is none.
    pub fn cancel(&self, desktop: &str) -> bool {
        match lock(&self.inner.active).get(desktop) {
            Some(a) => {
                a.cancel.cancel(CancelReason::Cancelled);
                true
            }
            None => false,
        }
    }

    /// The completed-backups record of `desktop` (ipc.md section 35).
    pub fn completed(&self, desktop: &str) -> Result<CompletedRecord, RecordError> {
        let p = self
            .inner
            .dirs
            .completed_path(desktop)
            .map_err(|source| RecordError::Io {
                what: "completed.json",
                source,
            })?;
        CompletedRecord::load(&p)
    }

    /// The restore target kept for `desktop`, if any (`resume.json`).
    pub fn resume_point(&self, desktop: &str) -> Result<Option<ResumeRecord>, RecordError> {
        let p = self
            .inner
            .dirs
            .resume_path(desktop)
            .map_err(|source| RecordError::Io {
                what: "resume.json",
                source,
            })?;
        ResumeRecord::load(&p)
    }

    /// Admits a job and starts it in the background (ipc.md section 26, "Admission").
    pub async fn start(&self, mut req: JobRequest) -> Result<JobHandle, StartError> {
        let i = &self.inner;
        let desktop = req.desktop_id.clone();
        if !i.recovered.load(Ordering::SeqCst) {
            return Err(StartError::Recovering);
        }
        if i.env.uninstalling() {
            return Err(StartError::Uninstalling);
        }
        if !i.env.desktop_known(&desktop) || !crate::privd::is_safe_desktop_id(&desktop) {
            return Err(StartError::UnknownDesktop);
        }
        let rec_err = |e: RecordError| StartError::Record(e.to_string());
        // The slot first, and the relay slots of the job: everything below is checked while
        // holding them, so that two admissions cannot clean and start at once.
        let guard = i.slots.take(&desktop).ok_or(StartError::Busy)?;
        let reserved = i
            .budget
            .clone()
            .try_acquire_many_owned(JOB_FRAME_SLOTS as u32)
            .map_err(|_| StartError::Busy)?;
        // A leftover record of a job whose cleanup failed: clean it before anything else.
        let jp = i
            .dirs
            .job_path(&desktop)
            .map_err(|e| StartError::Record(e.to_string()))?;
        if jp.exists() {
            let rep = Recovery {
                host: &i.host,
                env: i.env.as_ref(),
                cfg: &i.cfg,
                dirs: &i.dirs,
            }
            .recover_desktop(&desktop)
            .await;
            if !rep.complete {
                return Err(StartError::Record(
                    "a job of this desktop left objects that cannot be removed yet".into(),
                ));
            }
        }
        let kind = req.spec.kind();
        let now = i.env.now_unix();
        if req.spec.writes()
            && let Some(b) = Backoff::load(
                &i.dirs
                    .backoff_path(&desktop)
                    .map_err(|e| StartError::Record(e.to_string()))?,
            )
            .map_err(rec_err)?
            && b.until_unix > now
        {
            return Err(StartError::Backoff {
                until_unix: b.until_unix,
            });
        }
        if kind == JobKind::Backup && i.env.flags_for(&desktop).contains(&Flag::BackupTakenOver) {
            return Err(StartError::TakenOver);
        }
        if !drive_token_present(&i.cfg.drive_cred) {
            i.env.set_flag(None, Flag::DriveReconnect, true);
            i.env
                .audit("needs_attention=DRIVE_RECONNECT (the Drive token credential is missing)");
            return Err(StartError::DriveReconnect);
        }
        if kind == JobKind::Backup {
            match i.host.pool_space() {
                Some((total, free))
                    if free >= 2 * GIB && free.saturating_mul(100) >= total.saturating_mul(15) => {}
                _ => return Err(StartError::DiskFull),
            }
        }
        // The secrets, read now and moved into the job.
        let slot0 = match std::mem::replace(&mut req.repo_password, RepoPassword::HostBackupKey) {
            RepoPassword::HostBackupKey => {
                read_backup_key(i.cfg.credentials_dir.as_deref(), i.cfg.expected_owner)?
            }
            RepoPassword::Provided(s) => s,
        };
        if req.spec.needs_new_key() && req.new_key_password.is_none() {
            return Err(StartError::Invalid("the job needs a second secret".into()));
        }
        let new_key = req.new_key_password.take();
        // Everything that is not the caller's to choose, chosen now.
        let mut raw = [0u8; 16];
        loop {
            getrandom::fill(&mut raw).map_err(|_| StartError::Internal("no randomness".into()))?;
            if raw != [0u8; 16] {
                break;
            }
        }
        let job = JobId::from_bytes(raw).map_err(|e| StartError::Internal(e.to_string()))?;
        let snapshot = (kind == JobKind::Backup).then(|| {
            let mut tail = [0u8; 2];
            let _ = getrandom::fill(&mut tail);
            format!(
                "hx-backup-{}-{:02x}{:02x}",
                crate::privd::timefmt::snapshot_stamp(now),
                tail[0],
                tail[1]
            )
        });
        // A kept restore target is resumed by a resumable restore (the helper is built on it and
        // the worker verifies what is there), and refuses any other restore: `resume.json` is
        // never silently overwritten and the older target is never abandoned.
        let mut spec = req.spec.clone();
        let (target, reuse_target) = if kind == JobKind::Restore {
            let kept = ResumeRecord::load(
                &i.dirs
                    .resume_path(&desktop)
                    .map_err(|e| StartError::Record(e.to_string()))?,
            )
            .map_err(rec_err)?;
            match (&mut spec, kept) {
                (
                    JobSpec::Restore {
                        resumable: true,
                        verify_existing,
                        ..
                    },
                    Some(k),
                ) => {
                    *verify_existing = true;
                    (Some(k.target), true)
                }
                (_, Some(_)) => return Err(StartError::ResumePending),
                (_, None) => (Some(format!("hx-restore-{}", job.hex())), false),
            }
        } else {
            (None, false)
        };
        let instance = format!("{}{desktop}", i.cfg.instance_prefix);
        let facts = if kind == JobKind::Backup {
            Some(
                i.host
                    .desktop_facts(&instance)
                    .await
                    .map_err(|e| StartError::Host(e.to_string()))?
                    .ok_or(StartError::UnknownDesktop)?,
            )
        } else {
            None
        };
        // Only a prune needs the record, so a corrupt one does not stop a backup.
        let completed = if matches!(spec, JobSpec::ForgetPrune { .. }) {
            CompletedRecord::load(
                &i.dirs
                    .completed_path(&desktop)
                    .map_err(|e| StartError::Record(e.to_string()))?,
            )
            .map_err(rec_err)?
        } else {
            CompletedRecord::default()
        };
        let job_msg = build_job(
            &spec,
            &BuildCtx {
                job_id: raw,
                facts: facts.as_ref(),
                snapshot: snapshot.as_deref(),
                completed: &completed,
                agent_version: &i.cfg.agent_version,
                slot0_len: slot0.len(),
                slot1_len: new_key.as_ref().map(|k| k.len()),
            },
        )
        .map_err(|e| match e {
            SpecError::Invalid(r) => StartError::Invalid(r),
            SpecError::NoFacts => StartError::UnknownDesktop,
        })?;
        // The encoded `Job` must fit its frame: refused here, before a snapshot or a helper.
        hx_ipc::repo::encode_message(
            &pb::RepoFrame {
                frame: Some(pb::repo_frame::Frame::Job(job_msg.clone())),
            },
            hx_ipc::repo::Endpoint::Worker,
        )
        .map_err(|_| StartError::Invalid("the job does not fit its frame".into()))?;
        check_run_dir(&i.cfg.run_dir, i.cfg.expected_owner).map_err(StartError::Host)?;
        let server_id = i
            .dirs
            .server_id()
            .map_err(|e| StartError::Record(e.to_string()))?;
        // The record.
        i.dirs
            .ensure_desktop_dir(&desktop)
            .map_err(|e| StartError::Record(e.to_string()))?;
        let record = JobRecord {
            format: super::slot::FORMAT,
            job_id: job.hex(),
            kind: kind_name(kind).to_string(),
            desktop_id: desktop.clone(),
            started_unix: now,
            helper: job.helper_name().to_string(),
            snapshot: snapshot.clone(),
            target: target.clone(),
            resumable: matches!(
                spec,
                JobSpec::Restore {
                    resumable: true,
                    ..
                }
            ),
        };
        record.store(&jp).map_err(rec_err)?;
        let deadline = hx_ipc::repo::job_deadline(kind).unwrap_or(Duration::from_secs(600));
        let cancel = CancelToken::new();
        let initial = JobStatus {
            job_id: job.hex(),
            kind,
            desktop_id: desktop.clone(),
            state: JobState::Starting,
            progress: None,
            paused_until_ms: None,
            outcome: None,
        };
        let (tx, rx) = watch::channel(initial);
        lock(&i.active).insert(
            desktop.clone(),
            Active {
                job_id: job.hex(),
                cancel: cancel.clone(),
                status: rx.clone(),
            },
        );
        let folder = req
            .folder
            .clone()
            .unwrap_or_else(|| format!("hx-{}-{desktop}", &hex(&server_id)[..8]));
        let task = JobTask {
            inner: self.inner.clone(),
            job,
            raw,
            spec,
            desktop: desktop.clone(),
            instance,
            snapshot,
            target,
            reuse_target,
            job_msg,
            secrets: JobSecrets {
                slot0,
                slot1: new_key,
            },
            open: OpenParams {
                folder,
                create: kind == JobKind::Init,
                server_id,
                takeover: req.takeover,
            },
            deadline,
            cancel: cancel.clone(),
            tx,
            progress: req.progress.take(),
            guard,
            reserved,
            resumable: record.resumable,
        };
        let handle = JobHandle {
            job_id: job.hex(),
            desktop_id: desktop,
            status: rx,
            cancel,
        };
        tokio::spawn(task.run());
        Ok(handle)
    }
}

struct JobTask<H: BackupHost, E: BackupEnv> {
    inner: Arc<Inner<H, E>>,
    job: JobId,
    raw: [u8; 16],
    spec: JobSpec,
    desktop: String,
    instance: String,
    snapshot: Option<String>,
    target: Option<String>,
    reuse_target: bool,
    job_msg: pb::Job,
    secrets: JobSecrets,
    open: OpenParams,
    deadline: Duration,
    cancel: CancelToken,
    tx: watch::Sender<JobStatus>,
    progress: Option<ProgressSender>,
    guard: SlotGuard,
    reserved: OwnedSemaphorePermit,
    resumable: bool,
}

/// What the task made, so that cleanup knows what to remove.
#[derive(Default)]
struct Made {
    snapshot: bool,
    helper_attempted: bool,
    target_attempted: bool,
    reuse_target: bool,
    helper_started_ms: Option<u64>,
}

impl<H: BackupHost, E: BackupEnv> JobTask<H, E> {
    async fn run(self) {
        let i = self.inner.clone();
        let kind = self.spec.kind();
        let job_hex = self.job.hex();
        let desktop = self.desktop.clone();
        let tx = self.tx.clone();
        i.env.audit(&format!(
            "backup job started: job={job_hex} kind={} desktop={desktop}",
            kind_name(kind)
        ));
        let outcome = self.execute().await;
        i.env.audit(&match &outcome.result {
            Ok(_) => format!(
                "backup job finished: job={job_hex} kind={} ok",
                kind_name(kind)
            ),
            Err(f) => format!(
                "backup job failed: job={job_hex} kind={} failure={}{}",
                kind_name(kind),
                f.name(),
                detail_of(f)
            ),
        });
        if outcome.permission_answers > 1 {
            i.env.audit(&format!(
                "backup job {job_hex}: the Drive helper answered PERMISSION {} times in all",
                outcome.permission_answers
            ));
        }
        let outcome = Arc::new(outcome);
        tx.send_modify(|s| {
            s.state = JobState::Finished;
            s.outcome = Some(outcome.clone());
        });
        let final_status = tx.borrow().clone();
        lock(&i.last).insert(desktop.clone(), final_status);
        // The `active` entry was removed, and the slot released, inside `execute`.
    }

    async fn execute(self) -> JobOutcome {
        let Self {
            inner: i,
            job,
            raw,
            spec,
            desktop,
            instance,
            snapshot,
            target,
            job_msg,
            secrets,
            open,
            deadline,
            cancel,
            tx,
            progress,
            guard,
            reserved,
            reuse_target,
            resumable,
        } = self;
        let kind = spec.kind();
        let job_hex = job.hex();
        let reporter = Reporter {
            status: tx.clone(),
            progress,
        };
        let mut s = Session::new(
            i.env.clone(),
            i.mono.clone(),
            i.cfg.timing,
            Arc::new(Semaphore::new(JOB_FRAME_SLOTS)),
            job_hex.clone(),
            kind,
            cancel.clone(),
            deadline,
            reporter,
        );
        if kind == JobKind::Backup {
            let dirs = i.dirs.clone();
            let env = i.env.clone();
            let (d2, j2) = (desktop.clone(), job_hex.clone());
            s.set_backup_hook(Box::new(move |r, existed| {
                // Before cleanup, with fsync (ipc.md section 35).
                let Ok(path) = dirs.completed_path(&d2) else {
                    return;
                };
                if existed {
                    env.audit(&format!(
                        "backup job {j2}: the snapshot already existed in the repository; it is not recorded"
                    ));
                    return;
                }
                // A record that cannot be read is never rewritten from nothing.
                let mut rec = match CompletedRecord::load(&path) {
                    Ok(rec) => rec,
                    Err(e) => {
                        env.audit(&format!("backup job {j2}: cannot record the backup: {e}"));
                        return;
                    }
                };
                if let Some(e) = entry_from_result(&j2, env.now_unix(), r) {
                    rec.add(e);
                    if let Err(e) = rec.store(&path) {
                        env.audit(&format!("backup job {j2}: cannot record the backup: {e}"));
                    }
                }
            }));
        }
        let mut made = Made {
            reuse_target,
            ..Made::default()
        };
        let mut setup: Option<Failure> = None;
        let mut end: Option<RunEnd> = None;

        s.enter_phase(1);
        // Step 2: the Drive session.
        if let Err(f) = drive_link::open(&mut s, &i.cfg.drive_socket, &open, raw).await {
            setup = Some(f);
        } else if open.takeover {
            // The new owner starts no write job for 2 minutes (ipc.md section 29).
            if let Ok(p) = i.dirs.backoff_path(&desktop) {
                let until = i.env.now_unix() + hx_ipc::repo::TAKEOVER_QUIET_PERIOD.as_secs();
                let _ = Backoff::extend(&p, until, BackoffReason::Takeover);
            }
        }
        if setup.is_none() {
            setup = s.abort_reason();
        }

        // Step 3: the snapshot.
        if setup.is_none()
            && let Some(name) = &snapshot
        {
            let locked = s.service(i.env.lock_desktop(&desktop, &cancel)).await;
            // A cancel or a deadline that arrived while the lock was awaited is the job's fate,
            // not a failure of the snapshot.
            match locked {
                Ok(lockg) if s.abort_reason().is_none() => {
                    let r = s.service(i.host.create_snapshot(&instance, name)).await;
                    drop(lockg);
                    made.snapshot = true;
                    if let Err(e) = r {
                        setup = Some(Failure::SnapshotFailed(e.to_string()));
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    // The lock future may end because of the cancel that the loop has not
                    // looked at yet: the cancel is the job's fate.
                    let fate = s.abort_reason().or(cancel.reason().map(|r| match r {
                        CancelReason::Deadline => Failure::Deadline,
                        _ => Failure::Cancelled,
                    }));
                    setup = Some(fate.unwrap_or(Failure::SnapshotFailed(e)));
                }
            }
            if setup.is_none() {
                setup = s.abort_reason();
            }
        }

        // Step 4: the helper.
        if setup.is_none() {
            s.enter_phase(if kind == JobKind::Backup { 2 } else { 1 });
            match std::fs::read(&i.cfg.worker_binary) {
                Ok(bytes) if !bytes.is_empty() => {
                    let plan = HelperPlan {
                        job,
                        kind: spec.host_kind(),
                        desktop_instance: instance.clone(),
                        snapshot: snapshot.clone(),
                        target: target.clone(),
                        reuse_target,
                        worker: Arc::new(bytes),
                    };
                    made.helper_attempted = true;
                    made.target_attempted = plan.kind == HostKind::Restore;
                    match s.service(i.host.create_helper(&plan)).await {
                        Ok(()) => {
                            made.helper_started_ms = Some(s.mono.now_ms());
                            if let Err(e) = s.service(i.host.start_helper(job)).await {
                                setup = Some(Failure::HelperFailed(e.to_string()));
                            }
                        }
                        Err(super::host::HostError::Precondition(p)) => {
                            setup = Some(Failure::Precondition(p));
                        }
                        Err(e) => setup = Some(Failure::HelperFailed(e.to_string())),
                    }
                }
                _ => {
                    setup = Some(Failure::Precondition(
                        "the worker binary cannot be read".into(),
                    ))
                }
            }
            if setup.is_none() {
                setup = s.abort_reason();
            }
        }

        // Steps 5 and 6: the worker link and the relay.
        if setup.is_none() {
            let started = made.helper_started_ms.unwrap_or_else(|| s.mono.now_ms());
            let sock = i.cfg.run_dir.join(format!("{job_hex}.sock"));
            match worker_link::open(&mut s, &sock, started, job_msg.clone(), secrets).await {
                Ok(()) => end = Some(s.relay().await),
                Err(f) => setup = Some(f),
            }
        }
        // A helper whose worker ended in order (a result of any kind, no failure without grace)
        // is waited for; any other is stopped by force.
        let graceful = end
            .as_ref()
            .is_some_and(|e| e.result.is_some() && e.forced.is_none());
        let forced_failure = end.as_ref().is_some_and(|e| e.forced.is_some());
        let first_err = end.as_ref().and_then(|e| e.first_err);
        let permission_answers = end.as_ref().map_or(0, |e| e.permission_answers);
        let mut result = classify(setup, end);

        // The manifest of a `RESTORE_PLAN` is untrusted input.
        if let (Ok(r), JobSpec::RestorePlan { snapshot_id }) = (&result, &spec) {
            let ok = Manifest::from_slice(&r.manifest).ok().is_some_and(|m| {
                m.rustic_snapshot_id.as_deref() == Some(hex(snapshot_id).as_str())
            });
            if !ok {
                i.env.audit(&format!(
                    "backup job {job_hex}: the manifest of the plan is not valid"
                ));
                result = Err(Failure::WorkerFailed(WorkerError::Engine));
            }
        }

        // The effects on privd's state.
        if let Err(f) = &result {
            apply_effects(&i, &desktop, &job_hex, f);
            // What the repository said counts whatever ended the job: a cancel or a deadline
            // that came while an `AUTH_REVOKED` was already relayed does not undo it.
            if let Some(c) = first_err
                && *f != Failure::Repo(c)
            {
                apply_effects(&i, &desktop, &job_hex, &Failure::Repo(c));
            }
        } else if let (Ok(r), JobSpec::ForgetPrune { .. }) = (&result, &spec) {
            let _ = r;
            if let Some(pb::job::Spec::ForgetPrune(fp)) = &job_msg.spec {
                let ids: Vec<[u8; 32]> = fp
                    .forget
                    .iter()
                    .filter_map(|b| <[u8; 32]>::try_from(b.as_ref()).ok())
                    .collect();
                if let Ok(path) = i.dirs.completed_path(&desktop) {
                    match CompletedRecord::load(&path) {
                        Ok(mut rec) => {
                            rec.remove(&ids);
                            let _ = rec.store(&path);
                        }
                        Err(e) => i.env.audit(&format!(
                            "backup job {job_hex}: cannot update the record: {e}"
                        )),
                    }
                }
            }
        }
        s.finish_progress(result.is_ok());

        // Step 7: cleanup, whatever happened.
        tx.send_modify(|st| st.state = JobState::CleaningUp);
        if let Some(n) = cleanup_index(kind) {
            s.enter_phase(n);
        }
        let kept_target = cleanup(
            &i,
            &mut s,
            &made,
            job,
            &desktop,
            &instance,
            snapshot.as_deref(),
            target.as_deref(),
            resumable,
            graceful,
            forced_failure,
        )
        .await;
        // The `active` entry goes before the slot is released, and only if it is this job's: a
        // waiter that starts the next job the moment the slot is free must find its own entry.
        {
            let mut a = lock(&i.active);
            if a.get(&desktop).is_some_and(|x| x.job_id == job_hex) {
                a.remove(&desktop);
            }
        }
        drop(guard);
        drop(reserved);
        JobOutcome {
            job_id: job_hex,
            kind,
            desktop_id: desktop,
            result: result.map(|r| JobSuccess {
                result: r,
                restore_target: kept_target,
            }),
            permission_answers,
        }
    }
}

fn detail_of(f: &Failure) -> String {
    match f {
        Failure::Precondition(t)
        | Failure::SnapshotFailed(t)
        | Failure::HelperFailed(t)
        | Failure::WorkerProtocol(t)
        | Failure::DriveProtocol(t)
        | Failure::Internal(t) => format!(" detail=\"{}\"", t.replace('"', "'")),
        Failure::Repo(c) => format!(" class={c:?}"),
        Failure::WorkerFailed(e) => format!(" worker_error={e:?}"),
        Failure::Silent(l) => format!(" link={l:?}"),
        _ => String::new(),
    }
}

fn apply_effects<H: BackupHost, E: BackupEnv>(
    i: &Inner<H, E>,
    desktop: &str,
    job_hex: &str,
    f: &Failure,
) {
    let e = effects_of(f);
    if e.drive_reconnect {
        i.env.set_flag(None, Flag::DriveReconnect, true);
        i.env
            .audit("needs_attention=DRIVE_RECONNECT (the Drive token is revoked)");
    }
    if e.taken_over {
        i.env.set_flag(Some(desktop), Flag::BackupTakenOver, true);
        i.env
            .audit("needs_attention=BACKUP_TAKEN_OVER (another server owns the repository)");
    }
    if let Some(reason) = e.backoff
        && let Ok(p) = i.dirs.backoff_path(desktop)
    {
        let until = i.env.now_unix() + i.cfg.timing.backoff.as_secs();
        if let Err(err) = Backoff::extend(&p, until, reason) {
            i.env.audit(&format!(
                "backup job {job_hex}: cannot record the back-off: {err}"
            ));
        }
    }
    if e.alert_integrity {
        i.env.alert(&Alert {
            kind: AlertKind::Integrity,
            desktop_id: desktop.to_string(),
            job_id: job_hex.to_string(),
        });
    }
}

/// Step 7 of ipc.md section 26. Returns the name of a restore target that was kept.
#[allow(clippy::too_many_arguments)]
async fn cleanup<H: BackupHost, E: BackupEnv>(
    i: &Inner<H, E>,
    s: &mut Session<E>,
    made: &Made,
    job: JobId,
    desktop: &str,
    instance: &str,
    snapshot: Option<&str>,
    target: Option<&str>,
    resumable: bool,
    graceful: bool,
    forced_failure: bool,
) -> Option<String> {
    let job_hex = job.hex();
    let mut leftovers = false;
    let note = |what: String| {
        i.env
            .audit(&format!("backup job {job_hex}: cleanup: {what}"));
    };
    // (a) the links
    let drive_ok = s.drive_lost_class().is_none();
    if let Some(l) = s.worker.as_mut() {
        l.close(false);
    }
    // `Bye` whenever the Drive session is healthy (a cancelled or failed job included), and
    // not after a failure without grace.
    if let Some(l) = s.drive.as_mut() {
        l.close(drive_ok && !forced_failure);
    }
    // (b) the helper
    if made.helper_attempted {
        let r = if graceful {
            s.service(i.host.finish_helper(job, i.cfg.timing.helper_finish))
                .await
                .map(|_| ())
        } else {
            s.service(i.host.force_delete_helper(job)).await.map(|_| ())
        };
        if let Err(e) = r {
            leftovers = true;
            note(format!("the helper could not be deleted: {e}"));
        }
    }
    // (c) the socket
    match crate::privd::cmd::uninstall::unlink_beneath(
        &i.cfg.run_dir.join(format!("{job_hex}.sock")),
    ) {
        Ok(_) => {}
        Err(e) => {
            leftovers = true;
            note(format!("the socket could not be removed: {e}"));
        }
    }
    // (d) the snapshot
    if made.snapshot
        && let Some(name) = snapshot
        && let Err(e) = s.service(i.host.delete_snapshot(instance, name)).await
    {
        leftovers = true;
        note(format!("the snapshot could not be deleted: {e}"));
    }
    // (e) the restore target
    let mut kept = None;
    // Only a target that exists is kept or deleted: a precondition that failed before the
    // target was created leaves nothing to record.
    let target_exists = match target {
        Some(t) if made.target_attempted => {
            made.reuse_target || i.host.restore_target_exists(t).await.unwrap_or(true)
        }
        _ => false,
    };
    if target_exists
        && let Some(t) = target
        && let Ok(name) = hx_provision::incus::RestoreTargetName::new(t)
    {
        if resumable {
            match i.dirs.resume_path(desktop) {
                Ok(p) => match ResumeRecord::new(job, &name).store(&p) {
                    Ok(()) => kept = Some(t.to_string()),
                    Err(e) => {
                        leftovers = true;
                        note(format!("resume.json: {e}"));
                    }
                },
                Err(e) => {
                    leftovers = true;
                    note(format!("resume.json: {e}"));
                }
            }
        } else if let Err(e) = i.host.delete_restore_target(&name, Some(job)).await {
            leftovers = true;
            note(format!("the restore target could not be deleted: {e}"));
        }
    }
    // (f) the record
    if !leftovers
        && let Ok(p) = i.dirs.job_path(desktop)
        && let Err(e) = remove_record(&p)
    {
        note(format!("job.json could not be removed: {e}"));
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    fn res(ok: bool, err: WorkerError) -> pb::JobResult {
        pb::JobResult {
            ok,
            error: if ok { 0 } else { err as i32 },
            ..Default::default()
        }
    }

    fn end(result: Option<pb::JobResult>) -> RunEnd {
        RunEnd {
            result,
            ..RunEnd::default()
        }
    }

    #[test]
    fn privd_classifies_by_what_it_relayed_not_by_the_workers_claim() {
        // The worker says ENGINE; privd relayed AUTH_REVOKED.
        let mut e = end(Some(res(false, WorkerError::Engine)));
        e.first_err = Some(ErrorClass::AuthRevoked);
        assert_eq!(
            classify(None, Some(e)),
            Err(Failure::Repo(ErrorClass::AuthRevoked))
        );
        // No relayed error: the worker's own error stands, REPO without a record is INTERNAL.
        assert_eq!(
            classify(
                None,
                Some(end(Some(res(false, WorkerError::WrongPassword))))
            ),
            Err(Failure::WorkerFailed(WorkerError::WrongPassword))
        );
        assert_eq!(
            classify(None, Some(end(Some(res(false, WorkerError::Repo))))),
            Err(Failure::Repo(ErrorClass::Internal))
        );
    }

    #[test]
    fn a_success_that_was_on_its_way_beats_a_cancel_and_a_deadline() {
        for reason in [Failure::Cancelled, Failure::Deadline] {
            let mut e = end(Some(res(true, WorkerError::Unspecified)));
            e.drain = Some(reason.clone());
            assert!(classify(None, Some(e)).is_ok());
            let mut e = end(Some(res(false, WorkerError::Cancelled)));
            e.drain = Some(reason.clone());
            assert_eq!(classify(None, Some(e)), Err(reason));
        }
    }

    #[test]
    fn forced_failures_and_setup_failures_win_and_no_result_is_a_helper_failure() {
        // A failure without grace that follows an accepted success does not undo it (L2).
        let mut e = end(Some(res(true, WorkerError::Unspecified)));
        e.forced = Some(Failure::Silent(crate::privd::backup::LinkName::Drive));
        assert!(classify(None, Some(e)).is_ok());
        let mut e = end(Some(res(false, WorkerError::Engine)));
        e.forced = Some(Failure::Integrity);
        assert_eq!(classify(None, Some(e)), Err(Failure::Integrity));
        assert_eq!(
            classify(Some(Failure::Unavailable), None),
            Err(Failure::Unavailable)
        );
        let mut e = end(None);
        e.worker_gone = true;
        assert!(matches!(
            classify(None, Some(e)),
            Err(Failure::HelperFailed(_))
        ));
        let mut e = end(None);
        e.drain = Some(Failure::Repo(ErrorClass::AuthRevoked));
        assert_eq!(
            classify(None, Some(e)),
            Err(Failure::Repo(ErrorClass::AuthRevoked))
        );
    }

    #[test]
    fn the_effects_of_each_class_are_the_table_of_section_31() {
        let e = effects_of(&Failure::Repo(ErrorClass::AuthRevoked));
        assert!(e.drive_reconnect && !e.taken_over && e.backoff.is_none());
        let e = effects_of(&Failure::Repo(ErrorClass::LeaseHeld));
        assert!(e.taken_over && !e.drive_reconnect);
        assert_eq!(
            effects_of(&Failure::Repo(ErrorClass::DailyLimit)).backoff,
            Some(BackoffReason::DailyLimit)
        );
        for f in [Failure::PolicyDenied, Failure::TooLarge] {
            assert!(effects_of(&f).backoff.is_some());
            assert!(!effects_of(&f).alert_integrity);
        }
        for f in [
            Failure::Integrity,
            Failure::WorkerFailed(WorkerError::Integrity),
        ] {
            let e = effects_of(&f);
            assert!(
                e.alert_integrity && e.backoff == Some(BackoffReason::Integrity),
                "{f:?}"
            );
        }
        for f in [
            Failure::Repo(ErrorClass::Transient),
            Failure::Repo(ErrorClass::RateLimited),
            Failure::Repo(ErrorClass::QuotaExceeded),
            Failure::Repo(ErrorClass::Permission),
            Failure::Unavailable,
            Failure::Cancelled,
            Failure::Deadline,
        ] {
            assert_eq!(effects_of(&f), Effects::default(), "{f:?}");
        }
    }
}
