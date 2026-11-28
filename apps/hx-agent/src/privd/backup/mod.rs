//! privd's side of the repository link: the backup job runner (ipc.md Part 3, sections 24 to 36).
//!
//! Given a job kind and its spec, the runner takes the job slot and writes the job record, opens
//! the job's Drive session, creates the snapshot and the ephemeral helper container, runs the
//! sandboxed worker over the repository link, relays its requests to the Drive helper (checking
//! each one against the section 30 policy and verifying the SHA-256 of every write), maps its
//! progress, enforces liveness, deadlines and cancel, and cleans up. Crash recovery runs before
//! any job is admitted.
//!
//! # Modules
//!
//! | Module | Role |
//! |---|---|
//! | [`runner`] | admission, the job task, and the internal API W5b wires to the commands of section 6.14 |
//! | [`relay`] | the job loop: policy, hash check, request ids, guard timers, cancel, deadlines |
//! | [`worker_link`], [`drive_link`] | connect and handshake of each link (`Hello`, `Job`, secrets; `Hello`, `OpenRepo`) |
//! | [`link_io`] | a reader and a writer thread per link, the relay budget, the async `Link` |
//! | [`host`] | Incus and systemd behind a trait, over `hx-provision`'s helper and restore-target calls |
//! | [`slot`] | the job slot, `job.json`, `resume.json`, `backoff.json`, the server id |
//! | [`completed`] | the completed-backups record, retention, the `FORGET_PRUNE` spec builder |
//! | [`recovery`] | crash recovery and the cleanup before `DestroyDesktop` and `Uninstall` |
//! | [`progress`] | privd's phase table, step texts and the 10 per second throttle |
//! | [`spec`], [`creds`], [`clock`] | job specs, the backup key reader, the monotonic clock |
//!
//! # Internal API (what W5b wires up)
//!
//! * [`runner::JobRunner::start`]: admission, then the job runs in the background; returns a
//!   [`runner::JobHandle`].
//! * [`runner::JobHandle`]: `job_id`, a `watch` of [`JobStatus`] (state, the latest
//!   [`progress::JobProgress`], the outcome), `cancel`, and `finished` (waits for the outcome).
//! * [`runner::JobRunner::status`], [`runner::JobRunner::cancel`]: by desktop id.
//! * [`runner::JobRunner::recover`]: crash recovery (the server starts it at start).
//! * [`runner::JobRunner::teardown_cleanup`]: for `DestroyDesktop` and `Uninstall`.
//! * [`runner::JobRunner::completed`]: the completed-backups record of a desktop.
//!
//! Nothing here is reachable from the client commands yet: every command of section 6.14 still
//! answers `UNIMPLEMENTED`.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use hx_ipc::repo::pb::{self, ErrorClass, JobKind, WorkerError};

use crate::privd::cancel::CancelToken;
use crate::privd::config::PrivdConfig;
use crate::privd::state::Flag;

pub mod clock;
pub mod completed;
pub mod creds;
pub mod drive_link;
pub mod env;
pub mod host;
pub mod link_io;
pub mod progress;
pub mod recovery;
pub mod relay;
pub mod runner;
pub mod slot;
pub mod spec;
pub mod worker_link;

#[cfg(any(test, feature = "test-support"))]
pub mod testing;

pub use progress::JobProgress;

/// The relay buffer cap across jobs: 16 frame slots of 1 MiB (ipc.md section 25).
pub const RELAY_FRAME_SLOTS: usize = 16;

/// The slots a job reserves when it starts (two readers, a frame being read and one in the
/// channel each): at most `RELAY_FRAME_SLOTS / JOB_FRAME_SLOTS` jobs run at once.
pub const JOB_FRAME_SLOTS: usize = 4;

/// A job runs on a monotonic clock with these timers (ipc.md section 32); the values are the
/// contract, and tests change only `tick` and `connect_retry` (the pace at which the loop looks
/// at the clock), never a limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// How often the job loop looks at the clock (production: 100 ms).
    pub tick: Duration,
    /// Between two connection attempts to a socket (200 ms).
    pub connect_retry: Duration,
    /// How long privd keeps trying to reach the worker's socket after the helper started (30 s).
    pub worker_connect_window: Duration,
    /// How long privd keeps trying to reach the Drive helper's socket (5 s).
    pub drive_connect_window: Duration,
    /// `HelloAck` is due this long after the helper started or the Drive socket was reached (30 s).
    pub ack_timeout: Duration,
    /// `Ping` on both links (15 s).
    pub ping_interval: Duration,
    /// A link that has read nothing for this long is dead (45 s).
    pub silence: Duration,
    /// After `Cancel` the worker answers within this long (30 s).
    pub cancel_grace: Duration,
    /// How long privd waits for the helper to be gone before it deletes it by force (10 s).
    pub helper_finish: Duration,
    /// A Drive request with no sign of life for this long is stale (31 min, ipc.md section 32).
    pub drive_guard: Duration,
    /// The back-off after a failure that asks for one (1 h).
    pub backoff: Duration,
    /// How long a teardown waits for an active job to clean up (60 s).
    pub teardown_wait: Duration,
}

impl Timing {
    /// The production timers.
    pub const fn production() -> Self {
        Self {
            tick: Duration::from_millis(100),
            connect_retry: hx_ipc::repo::CONNECT_RETRY_INTERVAL,
            worker_connect_window: hx_ipc::repo::CONNECT_RETRY_WINDOW,
            drive_connect_window: Duration::from_secs(5),
            ack_timeout: hx_ipc::repo::HELPER_ACK_TIMEOUT,
            ping_interval: hx_ipc::repo::PING_INTERVAL,
            silence: hx_ipc::repo::PEER_SILENCE_TIMEOUT,
            cancel_grace: hx_ipc::repo::CANCEL_GRACE,
            helper_finish: Duration::from_secs(10),
            drive_guard: Duration::from_secs(31 * 60),
            backoff: Duration::from_secs(60 * 60),
            teardown_wait: Duration::from_secs(60),
        }
    }

    /// The production timers with a fast loop, for tests driven by a manual clock.
    pub const fn fast() -> Self {
        let mut t = Self::production();
        t.tick = Duration::from_millis(5);
        t.connect_retry = Duration::from_millis(5);
        t
    }
}

/// Where the runner keeps and finds things, and how it paces itself.
#[derive(Debug, Clone)]
pub struct BackupConfig {
    /// privd's state directory; the runner's files are in `<state dir>/backup`.
    pub state_dir: PathBuf,
    /// The directory of the repository-link sockets (`/run/hx/backup`).
    pub run_dir: PathBuf,
    /// The Drive helper's socket (`/run/hx/drive.sock`).
    pub drive_socket: PathBuf,
    /// The sealed Drive token credential (`/etc/hx/creds/drive-token.cred`).
    pub drive_cred: PathBuf,
    /// systemd's credential directory of the privd unit, where `backup-key` is.
    pub credentials_dir: Option<PathBuf>,
    /// The worker binary pushed into the helper (`/usr/lib/hx/current/hx-backup-worker`).
    pub worker_binary: PathBuf,
    /// The owner the run directory and the backup key must have; `None` skips the check.
    pub expected_owner: Option<u32>,
    /// The instance name prefix of desktops (`hx-`).
    pub instance_prefix: String,
    /// The agent version recorded in manifests.
    pub agent_version: String,
    /// The timers.
    pub timing: Timing,
}

impl BackupConfig {
    /// The configuration that follows from privd's own: every path is a constant of
    /// [`PrivdConfig`], never an argument or an environment variable.
    pub fn from_privd(cfg: &PrivdConfig) -> Self {
        Self {
            state_dir: cfg.state_dir.clone(),
            run_dir: cfg.backup_run_dir.clone(),
            drive_socket: cfg.drive_socket.clone(),
            drive_cred: cfg.creds_dir.join("drive-token.cred"),
            credentials_dir: cfg.credentials_dir.clone(),
            worker_binary: cfg
                .session_store
                .parent()
                .map(|p| p.join("hx-backup-worker"))
                .unwrap_or_else(|| PathBuf::from("/usr/lib/hx/current/hx-backup-worker")),
            expected_owner: cfg.backup_owner,
            instance_prefix: cfg.instance_prefix.clone(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            timing: Timing::production(),
        }
    }
}

/// Which link a failure concerns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkName {
    /// The repository link to the worker.
    Worker,
    /// The link to the Drive helper.
    Drive,
}

/// Why a job failed (ipc.md section 26, "Steps and what happens when one fails"). The texts are
/// privd's own; none carries peer data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// A check of section 24 or an admission rule failed after the slot was taken.
    Precondition(String),
    /// The snapshot could not be taken.
    SnapshotFailed(String),
    /// The helper could not be made, started or reached, or exited without a result.
    HelperFailed(String),
    /// The worker broke a rule of the link.
    WorkerProtocol(String),
    /// The Drive helper broke a rule of the link.
    DriveProtocol(String),
    /// The worker reported a failure (and privd relayed no repository error of its own).
    WorkerFailed(WorkerError),
    /// A repository error that privd relayed, or a `SESSION_FAILED` event.
    Repo(ErrorClass),
    /// The job was cancelled.
    Cancelled,
    /// The job deadline passed.
    Deadline,
    /// A link was silent for 45 s.
    Silent(LinkName),
    /// A Drive request was stale (no sign of life within the guard).
    Guard,
    /// privd refused an operation of the worker (section 30).
    PolicyDenied,
    /// A write whose body did not hash to its id.
    Integrity,
    /// A request over a size cap.
    TooLarge,
    /// The Drive helper is unreachable.
    Unavailable,
    /// A bug or a failure of privd's own.
    Internal(String),
}

impl Failure {
    /// The name of the failure, as audited.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Precondition(_) => "PRECONDITION",
            Self::SnapshotFailed(_) => "SNAPSHOT_FAILED",
            Self::HelperFailed(_) => "HELPER_FAILED",
            Self::WorkerProtocol(_) => "WORKER_PROTOCOL",
            Self::DriveProtocol(_) => "DRIVE_PROTOCOL",
            Self::WorkerFailed(_) => "WORKER_FAILED",
            Self::Repo(_) => "REPO",
            Self::Cancelled => "CANCELLED",
            Self::Deadline => "DEADLINE",
            Self::Silent(_) => "SILENT",
            Self::Guard => "GUARD",
            Self::PolicyDenied => "POLICY_DENIED",
            Self::Integrity => "INTEGRITY",
            Self::TooLarge => "TOO_LARGE",
            Self::Unavailable => "UNAVAILABLE",
            Self::Internal(_) => "INTERNAL",
        }
    }

    /// The repository error class this failure stands for, where it has one (section 31).
    pub fn class(&self) -> Option<ErrorClass> {
        match self {
            Self::Repo(c) => Some(*c),
            Self::PolicyDenied => Some(ErrorClass::PolicyDenied),
            Self::Integrity => Some(ErrorClass::Integrity),
            Self::TooLarge => Some(ErrorClass::TooLarge),
            Self::Unavailable | Self::Guard => Some(ErrorClass::Unavailable),
            Self::Cancelled | Self::Deadline => Some(ErrorClass::Cancelled),
            _ => None,
        }
    }
}

/// What a job that succeeded produced.
#[derive(Debug, Clone, PartialEq)]
pub struct JobSuccess {
    /// The worker's `JobResult`, as `LinkState` accepted it (and, for `RESTORE_PLAN`, with a
    /// manifest privd validated).
    pub result: pb::JobResult,
    /// The restore target that was kept (a `RESTORE` whose `resumable` flag is set), or made
    /// and deleted (`None`).
    pub restore_target: Option<String>,
}

/// How a job ended.
#[derive(Debug, Clone, PartialEq)]
pub struct JobOutcome {
    /// The job id, 32 hex digits.
    pub job_id: String,
    /// The kind.
    pub kind: JobKind,
    /// The desktop.
    pub desktop_id: String,
    /// What it produced, or why it failed.
    pub result: Result<JobSuccess, Failure>,
    /// How many `PERMISSION` answers of the Drive helper privd relayed in the job (the first is
    /// audited when it happens, the count is in the job's last audit line).
    pub permission_answers: u32,
    /// The most control bytes that were ever queued at once on either link of the job (the
    /// bound of ipc.md section 25 is observable).
    pub peak_ctl_bytes: usize,
    /// Object bytes privd relayed in both directions in the job (what the progress frames
    /// report as `transfer_bytes`, final).
    pub transfer_bytes: u64,
    /// The phases of privd's progress table that the job entered, in order. Unlike the progress
    /// frames (at most 10 a second, the last one may be held when the job ends) it is complete.
    pub phases: Vec<u32>,
}

/// Where a job is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    /// Admitted; the Drive session, snapshot and helper are being made.
    Starting,
    /// The worker is running the job.
    Running,
    /// A cancel, a deadline or a lost Drive session has asked the worker to stop.
    Cancelling,
    /// The job is over and its objects are being removed.
    CleaningUp,
    /// Over; [`JobStatus::outcome`] is set.
    Finished,
}

/// What `status` returns (and what [`runner::JobHandle`] watches).
#[derive(Debug, Clone, PartialEq)]
pub struct JobStatus {
    /// The job id, 32 hex digits.
    pub job_id: String,
    /// The kind.
    pub kind: JobKind,
    /// The desktop.
    pub desktop_id: String,
    /// Where the job is.
    pub state: JobState,
    /// The latest progress frame privd emitted.
    pub progress: Option<JobProgress>,
    /// While the Drive helper's daily-limit gate is paused: when it will probe again (Unix ms,
    /// clamped to now + 26 h).
    pub paused_until_ms: Option<u64>,
    /// Set when the state is [`JobState::Finished`].
    pub outcome: Option<Arc<JobOutcome>>,
}

/// An alert for the owner (ipc.md section 31, "Effects"). The real ntfy and webhook alerts are
/// part 2B; today the sink writes an audit line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    /// What happened.
    pub kind: AlertKind,
    /// The desktop.
    pub desktop_id: String,
    /// The job, 32 hex digits.
    pub job_id: String,
}

/// What an [`Alert`] is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertKind {
    /// A write did not hash to its id (privd's own check), or the engine refused a prune because
    /// the repository failed its integrity check. Not retried in a loop.
    Integrity,
}

/// A boxed future, so that [`BackupEnv`] needs no generic methods.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A held lock of the daemon, released on drop.
pub type LockGuard = Box<dyn Send>;

/// What the runner needs from the daemon: time, audit, flags, alerts, the desktop lock.
pub trait BackupEnv: Send + Sync + 'static {
    /// Unix seconds now (wall clock: records and `until` times, never a timer).
    fn now_unix(&self) -> u64;
    /// One audit notice line (never peer data, never a secret).
    fn audit(&self, text: &str);
    /// Sets or clears a `needs_attention` flag, host-wide (`desktop` is `None`) or per desktop.
    fn set_flag(&self, desktop: Option<&str>, flag: Flag, on: bool);
    /// The flags that hold for a desktop (its own and the host-wide ones).
    fn flags_for(&self, desktop: &str) -> Vec<Flag>;
    /// Whether privd manages a desktop with this id.
    fn desktop_known(&self, desktop: &str) -> bool;
    /// The ids of every desktop privd manages.
    fn desktops(&self) -> Vec<String>;
    /// Whether an uninstall has begun.
    fn uninstalling(&self) -> bool;
    /// Raises an alert for the owner.
    fn alert(&self, alert: &Alert);
    /// Takes the desktop's lock (the job holds it only while it takes the snapshot);
    /// `cancel` ends the wait.
    fn lock_desktop<'a>(
        &'a self,
        desktop: &'a str,
        cancel: &'a CancelToken,
    ) -> BoxFuture<'a, Result<LockGuard, String>>;
}

/// The name of a flag in an audit line.
pub fn flag_name(f: Flag) -> &'static str {
    match f {
        Flag::DriveReconnect => "DRIVE_RECONNECT",
        Flag::BackupTakenOver => "BACKUP_TAKEN_OVER",
        _ => "OTHER",
    }
}
