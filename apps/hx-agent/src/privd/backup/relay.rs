//! The job loop (ipc.md sections 25, 26, 29 to 33): one [`Session`] owns both links of a job and
//! relays between them.
//!
//! What it does, in the order of the contract:
//!
//! * **Policy.** Every request of the worker is checked with `hx_ipc::repo::check_job_op`
//!   (section 30) before anything is forwarded. `Deny` is `POLICY_DENIED`; `AllowIfAbsent` (the
//!   `INIT` write of `CONFIG`) is allowed only after privd itself saw a `List` of `CONFIG` of this
//!   job answered with no entry.
//! * **Ids.** Each forwarded request gets privd's own `req_id` on the Drive link (counting up from
//!   2; 1 is `OpenRepo`) and the answer's id is rewritten.
//! * **Hash check.** Every `Write` except of `CONFIG` is hashed as it streams, and privd forwards
//!   the worker's final frame, the one with `END`, only after the digest equals the object's id:
//!   the Drive helper commits an upload at `END`, so an object whose hash is wrong never reaches
//!   it as a finished upload.
//! * **Liveness.** `Ping` every 15 s on both links, 45 s of silence is death, and a Drive request
//!   with no sign of life for the guard (31 minutes, restarted by every sign of life and by a
//!   daily-limit pause) is stale: there is no fixed total (section 32).
//! * **Cancel and deadline.** `Cancel` to the worker, `CancelRequest` to the Drive helper, 30 s of
//!   grace; a deadline is a cancel. A violation, silence and privd's own refusals get no grace.
//! * **End of stream.** On the Drive link a clean end at a frame boundary, or a
//!   `SESSION_FAILED` event, is the loss of the Drive session (`UNAVAILABLE`, or the class of the
//!   event); only a cut frame is a violation.
//!
//! Every frame goes through a [`LinkState`](hx_ipc::repo::LinkState) in both directions, so a
//! bug of privd's own shows as a failed job and not as a hung link. Nothing a peer sent is logged
//! or audited except the name of the rule it broke.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use hx_ipc::repo::pb::{self, ErrorClass, JobKind, ObjectType, repo_request::Op};
use hx_ipc::repo::{self, Incoming, Verdict};
use sha2::{Digest, Sha256};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};

use super::clock::Monotonic;
use super::link_io::{Link, LinkEvent, LinkParts, OutQueue, SendError, frame};
use super::progress::{JobProgress, ProgressMapper};
use super::{BackupEnv, Failure, JobState, JobStatus, LinkName, Timing};
use crate::privd::cancel::CancelToken;
use crate::privd::progress::ProgressSender;

/// Called with the accepted result of a successful `BACKUP`.
pub type BackupHook = Box<dyn Fn(&pb::JobResult) + Send + Sync>;

/// The id of the `OpenRepo` request, the first of the Drive session.
pub const OPEN_REPO_ID: u64 = 1;

/// Where progress goes.
pub struct Reporter {
    /// The status the handle watches.
    pub status: watch::Sender<JobStatus>,
    /// The caller's progress sender (the §4 frames), if it gave one.
    pub progress: Option<ProgressSender>,
}

impl Reporter {
    fn report(&self, p: JobProgress) {
        self.status.send_modify(|s| s.progress = Some(p));
        if let Some(ps) = &self.progress {
            ps.emit_job(&p);
        }
    }

    /// Sets the state of the job.
    pub fn state(&self, st: JobState) {
        self.status.send_modify(|s| s.state = st);
    }

    fn paused(&self, until_ms: Option<u64>) {
        self.status.send_modify(|s| s.paused_until_ms = until_ms);
    }
}

fn type_name(v: i32) -> &'static str {
    match ObjectType::try_from(v).unwrap_or(ObjectType::Unspecified) {
        ObjectType::Config => "CONFIG",
        ObjectType::Key => "KEY",
        ObjectType::Snapshot => "SNAPSHOT",
        ObjectType::Index => "INDEX",
        ObjectType::Pack => "PACK",
        ObjectType::Unspecified => "UNSPECIFIED",
    }
}

enum ReqOp {
    List(ObjectType),
    Read,
    Remove,
    Create,
    Write(WriteState),
}

struct WriteState {
    hasher: Option<Sha256>,
    id: [u8; 32],
    end_forwarded: bool,
}

struct WReq {
    d_id: u64,
    op: ReqOp,
    label: String,
    life: u64,
    download_begun: bool,
    /// privd has answered the worker with an error of its own.
    answered: bool,
}

struct Drain {
    reason: Failure,
    grace_until: u64,
}

/// What a job loop leaves for the runner to classify (ipc.md section 31).
#[derive(Debug, Default)]
pub struct RunEnd {
    /// A failure that has no grace: a violation, silence, a refusal of privd's own, a bug.
    pub forced: Option<Failure>,
    /// Why privd asked the worker to stop (a cancel, the deadline, a lost Drive session).
    pub drain: Option<Failure>,
    /// The worker's `JobResult`.
    pub result: Option<pb::JobResult>,
    /// The first repository error class privd relayed (not `NOT_FOUND`, not `CANCELLED`).
    pub first_err: Option<ErrorClass>,
    /// The worker link ended without a `JobResult`.
    pub worker_gone: bool,
}

/// Both links of one job and everything the loop knows about them.
pub struct Session<E: BackupEnv> {
    pub(super) env: Arc<E>,
    pub(super) mono: Arc<dyn Monotonic>,
    pub(super) timing: Timing,
    pub(super) job_hex: String,
    pub(super) kind: JobKind,
    pub(super) cancel: CancelToken,
    pub(super) deadline_at: u64,
    pub(super) reporter: Reporter,
    pub(super) mapper: ProgressMapper,
    pub(super) parts: LinkParts,
    pub(super) worker_q: Arc<OutQueue>,
    pub(super) drive_q: Arc<OutQueue>,
    pub(super) worker: Option<Link>,
    pub(super) drive: Option<Link>,
    pub(super) job_msg: Option<pb::Job>,
    reqs: HashMap<u64, WReq>,
    by_drive: HashMap<u64, u64>,
    next_drive_req: u64,
    config_absent: bool,
    list_total: HashMap<u64, u64>,
    drain: Option<Drain>,
    forced: Option<Failure>,
    result: Option<pb::JobResult>,
    over: bool,
    worker_gone: bool,
    post_result_until: Option<u64>,
    first_err: Option<ErrorClass>,
    drive_dead: Option<ErrorClass>,
    pause_end_mono: Option<u64>,
    cancel_seen: bool,
    last_tick_ms: u64,
    open_life: Option<u64>,
    pub(super) open_repo_answer: Option<pb::repo_response::Result>,
    on_backup_ok: Option<BackupHook>,
}

async fn next_event(l: &mut Option<Link>) -> Option<LinkEvent> {
    match l {
        Some(l) if l.open => l.rx.recv().await,
        _ => std::future::pending().await,
    }
}

impl<E: BackupEnv> Session<E> {
    /// A session with no link yet.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        env: Arc<E>,
        mono: Arc<dyn Monotonic>,
        timing: Timing,
        budget: Arc<Semaphore>,
        job_hex: String,
        kind: JobKind,
        cancel: CancelToken,
        deadline_after: Duration,
        reporter: Reporter,
    ) -> Self {
        let now = mono.now_ms();
        Self {
            env,
            parts: LinkParts {
                budget,
                handle: tokio::runtime::Handle::current(),
                mono: mono.clone(),
                ping_interval: timing.ping_interval,
            },
            mono,
            timing,
            job_hex,
            kind,
            cancel,
            deadline_at: now + u64::try_from(deadline_after.as_millis()).unwrap_or(u64::MAX),
            reporter,
            mapper: ProgressMapper::new(kind),
            worker_q: OutQueue::new(),
            drive_q: OutQueue::new(),
            worker: None,
            drive: None,
            job_msg: None,
            reqs: HashMap::new(),
            by_drive: HashMap::new(),
            next_drive_req: OPEN_REPO_ID + 1,
            config_absent: false,
            list_total: HashMap::new(),
            drain: None,
            forced: None,
            result: None,
            over: false,
            worker_gone: false,
            post_result_until: None,
            first_err: None,
            drive_dead: None,
            pause_end_mono: None,
            cancel_seen: false,
            last_tick_ms: now,
            open_life: None,
            open_repo_answer: None,
            on_backup_ok: None,
        }
    }

    /// Called with the accepted result of a successful `BACKUP`, as soon as it is seen and
    /// before cleanup (the completed-backups record, ipc.md section 35).
    pub fn set_backup_hook(&mut self, f: BackupHook) {
        self.on_backup_ok = Some(f);
    }

    fn now(&self) -> u64 {
        self.mono.now_ms()
    }

    /// Moves to phase `index` of privd's table and reports it if it is due.
    pub fn enter_phase(&mut self, index: u32) {
        self.mapper.enter(index);
        self.flush_progress();
    }

    fn flush_progress(&mut self) {
        let now = self.now();
        if let Some(p) = self.mapper.poll(now) {
            self.reporter.report(p);
        }
    }

    /// Ends the job's progress with `ok` (the frame goes out when the 10 per second throttle
    /// allows; the outcome is the authoritative end).
    pub fn finish_progress(&mut self, ok: bool) {
        self.mapper.finish(ok);
        self.flush_progress();
    }

    /// Why the setup should stop, if it should: a failure without grace, or a cancel.
    pub fn abort_reason(&self) -> Option<Failure> {
        self.forced
            .clone()
            .or_else(|| self.drain.as_ref().map(|d| d.reason.clone()))
    }

    /// `OpenRepo` has been sent: it is guarded like any Drive request.
    pub fn begin_open_repo(&mut self) {
        self.open_life = Some(self.now());
    }

    /// Records a repository error class that privd saw (the answer to `OpenRepo`).
    pub fn note_repo_error(&mut self, class: ErrorClass) {
        if !matches!(class, ErrorClass::NotFound | ErrorClass::Cancelled)
            && self.first_err.is_none()
        {
            self.first_err = Some(class);
        }
    }

    /// Whether the Drive session is lost.
    pub fn drive_lost_class(&self) -> Option<ErrorClass> {
        self.drive_dead
    }

    // ----- failure, drain -----------------------------------------------------------------

    /// A failure without grace: both links are closed at once and the loop ends.
    pub fn fatal(&mut self, f: Failure) {
        if self.forced.is_none() {
            self.forced = Some(f);
        }
        self.over = true;
        if let Some(l) = self.worker.as_mut() {
            l.close(false);
        }
        if let Some(l) = self.drive.as_mut() {
            l.close(false);
        }
    }

    /// Asks the worker to stop and starts the grace (a cancel, the deadline, a lost Drive
    /// session). The first reason stays.
    pub fn begin_drain(&mut self, reason: Failure) {
        if self.drain.is_some() {
            return;
        }
        self.drain = Some(Drain {
            reason,
            grace_until: self.now()
                + u64::try_from(self.timing.cancel_grace.as_millis()).unwrap_or(0),
        });
        self.reporter.state(JobState::Cancelling);
        if self
            .worker
            .as_ref()
            .is_some_and(|l| l.open && l.state.job_kind().is_some())
        {
            self.send_worker(&frame(pb::repo_frame::Frame::Cancel(pb::Cancel {})));
        }
        if self.drive_dead.is_none() {
            let ids: Vec<u64> = self
                .reqs
                .values()
                .filter(|r| !r.download_begun && !r.answered)
                .map(|r| r.d_id)
                .collect();
            for d_id in ids {
                let outstanding = self
                    .drive
                    .as_ref()
                    .is_some_and(|l| l.state.is_outstanding(d_id));
                if outstanding {
                    self.send_drive(&frame(pb::repo_frame::Frame::CancelRequest(
                        pb::CancelRequest { req_id: d_id },
                    )));
                }
            }
        }
    }

    // ----- sending ------------------------------------------------------------------------

    fn send_on(&mut self, which: LinkName, f: &pb::RepoFrame) -> bool {
        let link = match which {
            LinkName::Worker => self.worker.as_mut(),
            LinkName::Drive => self.drive.as_mut(),
        };
        let Some(link) = link else { return false };
        if !link.open {
            return false;
        }
        match link.send(f) {
            Ok(()) => true,
            Err(SendError::Closed) => false,
            Err(SendError::Rule(r)) => {
                let name = link.name;
                self.fatal(Failure::Internal(format!("{name} link: {r}")));
                false
            }
        }
    }

    pub(super) fn send_worker(&mut self, f: &pb::RepoFrame) -> bool {
        self.send_on(LinkName::Worker, f)
    }

    pub(super) fn send_drive(&mut self, f: &pb::RepoFrame) -> bool {
        self.send_on(LinkName::Drive, f)
    }

    fn send_data_on(
        &mut self,
        which: LinkName,
        stream: u64,
        end: bool,
        payload: Bytes,
        permit: Option<OwnedSemaphorePermit>,
    ) -> bool {
        let link = match which {
            LinkName::Worker => self.worker.as_mut(),
            LinkName::Drive => self.drive.as_mut(),
        };
        let Some(link) = link else { return false };
        if !link.open {
            return false;
        }
        match link.send_data(stream, end, payload, permit) {
            Ok(()) => true,
            Err(SendError::Closed) => false,
            Err(SendError::Rule(r)) => {
                let name = link.name;
                self.fatal(Failure::Internal(format!("{name} link data: {r}")));
                false
            }
        }
    }

    fn answer_error(&mut self, w_id: u64, class: ErrorClass) {
        let f = frame(pb::repo_frame::Frame::Response(pb::RepoResponse {
            req_id: w_id,
            result: Some(pb::repo_response::Result::Error(pb::RepoError {
                class: class as i32,
                retry_after_ms: 0,
            })),
        }));
        self.send_worker(&f);
        if let Some(r) = self.reqs.get_mut(&w_id) {
            r.answered = true;
        }
    }

    // ----- the loop -----------------------------------------------------------------------

    /// Runs `fut` (a call to the host) to the end while keeping the Drive session alive: events
    /// are handled, `Ping` is sent and answered, and the clock is watched. A failure the session
    /// decides on meanwhile is left in [`Session::abort_reason`] for the caller to see after the
    /// call (the call itself is never dropped half way: Incus keeps working on what it started).
    pub async fn service<F: Future>(&mut self, fut: F) -> F::Output {
        tokio::pin!(fut);
        let mut ticker = tokio::time::interval(self.timing.tick);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                out = &mut fut => return out,
                ev = next_event(&mut self.drive) => self.on_drive_event(ev),
                ev = next_event(&mut self.worker) => self.on_worker_event(ev),
                _ = ticker.tick() => self.on_tick(),
                _ = self.cancel.cancelled(), if !self.cancel_seen => {
                    self.cancel_seen = true;
                    self.begin_drain(Failure::Cancelled);
                }
            }
        }
    }

    /// Handles events until `done` holds, or the session is over or draining.
    pub async fn pump_until(&mut self, done: impl Fn(&Self) -> bool) {
        let mut ticker = tokio::time::interval(self.timing.tick);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        while !done(self) && !self.over && self.drain.is_none() {
            tokio::select! {
                ev = next_event(&mut self.drive) => self.on_drive_event(ev),
                ev = next_event(&mut self.worker) => self.on_worker_event(ev),
                _ = ticker.tick() => self.on_tick(),
                _ = self.cancel.cancelled(), if !self.cancel_seen => {
                    self.cancel_seen = true;
                    self.begin_drain(Failure::Cancelled);
                }
            }
        }
    }

    /// The relay: runs until the worker has ended the session, or a failure ends it.
    pub async fn relay(&mut self) -> RunEnd {
        self.reporter.state(JobState::Running);
        let mut ticker = tokio::time::interval(self.timing.tick);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        while !self.over {
            tokio::select! {
                ev = next_event(&mut self.worker) => self.on_worker_event(ev),
                ev = next_event(&mut self.drive) => self.on_drive_event(ev),
                _ = ticker.tick() => self.on_tick(),
                _ = self.cancel.cancelled(), if !self.cancel_seen => {
                    self.cancel_seen = true;
                    self.begin_drain(Failure::Cancelled);
                }
            }
        }
        self.end()
    }

    /// The state of the job as the runner classifies it.
    pub fn end(&mut self) -> RunEnd {
        RunEnd {
            forced: self.forced.clone(),
            drain: self.drain.as_ref().map(|d| d.reason.clone()),
            result: self.result.clone(),
            first_err: self.first_err,
            worker_gone: self.worker_gone,
        }
    }

    // ----- time ---------------------------------------------------------------------------

    fn on_tick(&mut self) {
        let now = self.now();
        // A loop that did not run for more than half the silence timeout (the host was suspended
        // or starved) could not have read from the links either: the silence baselines restart
        // instead of blaming the peers (ipc.md section 32).
        let gap = now.saturating_sub(self.last_tick_ms);
        self.last_tick_ms = now;
        if gap > u64::try_from(self.timing.silence.as_millis()).unwrap_or(u64::MAX) / 2 {
            for l in [self.worker.as_mut(), self.drive.as_mut()]
                .into_iter()
                .flatten()
            {
                l.last_rx.store(now, std::sync::atomic::Ordering::SeqCst);
                l.next_ping_ms = now;
            }
        }
        if self.forced.is_none() {
            if self.drain.is_none() && now >= self.deadline_at {
                self.begin_drain(Failure::Deadline);
            }
            if let Some(d) = &self.drain
                && now >= d.grace_until
                && self.worker.is_some()
            {
                // No `JobResult` in the grace: the helper is force-stopped by the cleanup.
                self.over = true;
            }
            if self.post_result_until.is_some_and(|t| now >= t) {
                self.over = true;
            }
            let silence = u64::try_from(self.timing.silence.as_millis()).unwrap_or(u64::MAX);
            let mut silent = None;
            for l in [self.worker.as_ref(), self.drive.as_ref()]
                .into_iter()
                .flatten()
            {
                if l.open
                    && now.saturating_sub(l.last_rx.load(std::sync::atomic::Ordering::SeqCst))
                        >= silence
                {
                    silent = Some(if l.name == "worker" {
                        LinkName::Worker
                    } else {
                        LinkName::Drive
                    });
                    break;
                }
            }
            if let Some(which) = silent {
                self.fatal(Failure::Silent(which));
                return;
            }
            let interval = u64::try_from(self.timing.ping_interval.as_millis()).unwrap_or(u64::MAX);
            for which in [LinkName::Worker, LinkName::Drive] {
                let link = match which {
                    LinkName::Worker => self.worker.as_mut(),
                    LinkName::Drive => self.drive.as_mut(),
                };
                if let Some(l) = link
                    && l.open
                    && now >= l.next_ping_ms
                {
                    l.next_ping_ms = now + interval;
                    let _ = l.ping();
                }
            }
            self.check_guard(now);
        }
        self.flush_progress();
    }

    fn check_guard(&mut self, now: u64) {
        if self.drive_dead.is_some() || self.drive.is_none() {
            return;
        }
        let guard = u64::try_from(self.timing.drive_guard.as_millis()).unwrap_or(u64::MAX);
        let pause_end = self.pause_end_mono.unwrap_or(0);
        let stale = self.reqs.values().any(|r| {
            let guarded = !r.download_begun
                && !matches!(&r.op, ReqOp::Write(w) if w.end_forwarded)
                && self
                    .drive
                    .as_ref()
                    .is_some_and(|l| l.state.is_outstanding(r.d_id));
            guarded && now >= r.life.max(pause_end).saturating_add(guard)
        });
        let open_stale = self
            .open_life
            .is_some_and(|l| now >= l.max(pause_end).saturating_add(guard));
        if stale || open_stale {
            self.drive_lost(ErrorClass::Unavailable, Failure::Guard);
        }
    }

    // ----- the worker link ----------------------------------------------------------------

    fn on_worker_event(&mut self, ev: Option<LinkEvent>) {
        match ev {
            Some(LinkEvent::Frame(incoming, permit)) => self.worker_frame(incoming, permit),
            Some(LinkEvent::Eof) | Some(LinkEvent::Io) | None => self.worker_ended(),
            Some(LinkEvent::Cut) => {
                self.fatal(Failure::WorkerProtocol("a frame was cut short".into()));
            }
            Some(LinkEvent::Violation(rule)) => self.fatal(Failure::WorkerProtocol(rule)),
            Some(LinkEvent::WriteFailed) => {
                self.worker_ended();
            }
        }
    }

    fn worker_ended(&mut self) {
        if let Some(l) = self.worker.as_mut() {
            l.open = false;
        }
        if self.result.is_none() {
            self.worker_gone = true;
        }
        self.over = true;
    }

    fn worker_frame(&mut self, incoming: Incoming, permit: OwnedSemaphorePermit) {
        let Some(link) = self.worker.as_mut() else {
            return;
        };
        let disp = match link.state.received(&incoming) {
            Ok(d) => d,
            Err(e) => {
                self.fatal(Failure::WorkerProtocol(e.0.to_string()));
                return;
            }
        };
        match incoming {
            Incoming::Message(f) => match f.frame {
                Some(pb::repo_frame::Frame::Request(r)) => self.worker_request(r),
                Some(pb::repo_frame::Frame::Progress(p)) => {
                    self.mapper.worker(&p);
                    self.flush_progress();
                }
                Some(pb::repo_frame::Frame::Result(r)) => self.on_result(r),
                Some(pb::repo_frame::Frame::Ping(p)) => {
                    let _ = self.worker.as_mut().map(|l| l.pong(p.nonce));
                }
                Some(pb::repo_frame::Frame::Bye(_)) => {
                    self.worker_over_now();
                }
                _ => {}
            },
            Incoming::Data(d) => self.worker_data(d, permit, disp.discard),
            Incoming::Secret(_) => {
                self.fatal(Failure::WorkerProtocol(
                    "a secret frame from the worker".into(),
                ));
            }
        }
        self.collect();
    }

    fn worker_over_now(&mut self) {
        self.over = true;
    }

    fn on_result(&mut self, r: pb::JobResult) {
        self.mapper.finish(r.ok);
        self.flush_progress();
        if r.ok
            && self.kind == JobKind::Backup
            && let Some(h) = &self.on_backup_ok
        {
            h(&r);
        }
        self.result = Some(r);
        // Wait for `Bye` (or the end of the stream), but not for longer than the grace: a worker
        // that skipped `Bye` after 10 s of downloads is the normal end too (section 24).
        let grace = u64::try_from(self.timing.cancel_grace.as_millis()).unwrap_or(0);
        self.post_result_until = Some(self.now() + grace);
    }

    fn policy_denied(&mut self, w_id: u64) {
        self.env.audit(&format!(
            "backup job {}: the worker asked for an operation that its {:?} job may not do (POLICY_DENIED)",
            self.job_hex, self.kind
        ));
        self.answer_error(w_id, ErrorClass::PolicyDenied);
        self.fatal(Failure::PolicyDenied);
    }

    fn worker_request(&mut self, r: pb::RepoRequest) {
        let w_id = r.req_id;
        let Some(op) = r.op else {
            self.fatal(Failure::WorkerProtocol("request: no operation".into()));
            return;
        };
        if self.drive_dead.is_some() {
            self.answer_error(w_id, ErrorClass::Unavailable);
            return;
        }
        if self.drain.is_some() {
            self.answer_error(w_id, ErrorClass::Cancelled);
            return;
        }
        let Some(job) = self.job_msg.as_ref() else {
            self.fatal(Failure::Internal(
                "a request before the job was sent".into(),
            ));
            return;
        };
        match repo::check_job_op(job, &op) {
            Verdict::Allow => {}
            Verdict::AllowIfAbsent if self.config_absent => {}
            Verdict::AllowIfAbsent | Verdict::Deny => {
                self.policy_denied(w_id);
                return;
            }
        }
        let is_write = matches!(op, Op::Write(_));
        if !self
            .drive
            .as_ref()
            .is_some_and(|l| l.open && l.state.can_request(is_write))
        {
            self.fatal(Failure::Internal(
                "the Drive link has no room for a request".into(),
            ));
            return;
        }
        let d_id = self.next_drive_req;
        self.next_drive_req += 1;
        let (rop, label) = match &op {
            Op::List(l) => (
                ReqOp::List(ObjectType::try_from(l.object_type).unwrap_or(ObjectType::Unspecified)),
                format!("list {}", type_name(l.object_type)),
            ),
            Op::ReadFull(x) => (ReqOp::Read, format!("read {}", type_name(x.object_type))),
            Op::ReadPartial(x) => (ReqOp::Read, format!("read {}", type_name(x.object_type))),
            Op::Remove(x) => (
                ReqOp::Remove,
                format!("remove {}", type_name(x.object_type)),
            ),
            Op::Create(_) => (ReqOp::Create, "create".to_string()),
            Op::Write(w) => {
                let mut id = [0u8; 32];
                if w.id.len() == 32 {
                    id.copy_from_slice(&w.id);
                }
                let hashed = w.object_type != ObjectType::Config as i32;
                (
                    ReqOp::Write(WriteState {
                        hasher: hashed.then(Sha256::new),
                        id,
                        end_forwarded: false,
                    }),
                    format!("write {}", type_name(w.object_type)),
                )
            }
            Op::OpenRepo(_) | Op::Quota(_) | Op::SetUploadRate(_) => {
                self.policy_denied(w_id);
                return;
            }
        };
        let f = frame(pb::repo_frame::Frame::Request(pb::RepoRequest {
            req_id: d_id,
            op: Some(op),
        }));
        if !self.send_drive(&f) {
            return;
        }
        let now = self.now();
        self.by_drive.insert(d_id, w_id);
        self.reqs.insert(
            w_id,
            WReq {
                d_id,
                op: rop,
                label,
                life: now,
                download_begun: false,
                answered: false,
            },
        );
    }

    fn worker_data(&mut self, d: repo::DataFrame, permit: OwnedSemaphorePermit, discard: bool) {
        if discard {
            return;
        }
        let now = self.now();
        let Some(req) = self.reqs.get_mut(&d.stream_id) else {
            return;
        };
        let ReqOp::Write(w) = &mut req.op else {
            return;
        };
        if req.answered {
            return;
        }
        req.life = now;
        let d_id = req.d_id;
        if let Some(h) = &mut w.hasher {
            h.update(&d.payload);
        }
        let len = d.payload.len() as u64;
        if !d.end {
            self.mapper.add_transfer(len);
            self.send_data_on(LinkName::Drive, d_id, false, d.payload, Some(permit));
            return;
        }
        // The last frame: forward its `END` only if the body hashes to the id.
        if let Some(h) = w.hasher.take() {
            let digest = h.finalize();
            if digest.as_slice() != w.id {
                self.env.audit(&format!(
                    "backup job {}: a write did not hash to its id (INTEGRITY)",
                    self.job_hex
                ));
                self.answer_error(d.stream_id, ErrorClass::Integrity);
                self.fatal(Failure::Integrity);
                return;
            }
        }
        w.end_forwarded = true;
        self.mapper.add_transfer(len);
        self.send_data_on(LinkName::Drive, d_id, true, d.payload, Some(permit));
    }

    // ----- the Drive link -----------------------------------------------------------------

    fn on_drive_event(&mut self, ev: Option<LinkEvent>) {
        match ev {
            Some(LinkEvent::Frame(incoming, permit)) => self.drive_frame(incoming, permit),
            // The end of the stream at a frame boundary, or a reset: the loss of the session, not
            // a violation (section 32).
            Some(LinkEvent::Eof) | Some(LinkEvent::Io) | Some(LinkEvent::WriteFailed) | None => {
                self.drive_lost(ErrorClass::Unavailable, Failure::Unavailable);
            }
            Some(LinkEvent::Cut) => {
                self.fatal(Failure::DriveProtocol("a frame was cut short".into()));
            }
            Some(LinkEvent::Violation(rule)) => self.fatal(Failure::DriveProtocol(rule)),
        }
    }

    fn drive_frame(&mut self, incoming: Incoming, permit: OwnedSemaphorePermit) {
        let Some(link) = self.drive.as_mut() else {
            return;
        };
        let disp = match link.state.received(&incoming) {
            Ok(d) => d,
            Err(e) => {
                self.fatal(Failure::DriveProtocol(e.0.to_string()));
                return;
            }
        };
        match incoming {
            Incoming::Message(f) => match f.frame {
                Some(pb::repo_frame::Frame::Response(r)) => self.drive_response(r),
                Some(pb::repo_frame::Frame::Event(e)) => self.drive_event(e),
                Some(pb::repo_frame::Frame::Ping(p)) => {
                    let _ = self.drive.as_mut().map(|l| l.pong(p.nonce));
                }
                Some(pb::repo_frame::Frame::Bye(_)) => {
                    self.drive_lost(ErrorClass::Unavailable, Failure::Unavailable);
                }
                _ => {}
            },
            Incoming::Data(d) => self.drive_data(d, permit, disp.discard),
            Incoming::Secret(_) => {
                self.fatal(Failure::DriveProtocol(
                    "a secret frame from the Drive helper".into(),
                ));
            }
        }
        self.collect();
    }

    fn drive_response(&mut self, r: pb::RepoResponse) {
        use pb::repo_response::Result as R;
        let d_id = r.req_id;
        let Some(result) = r.result else { return };
        if d_id == OPEN_REPO_ID {
            self.open_life = None;
            self.open_repo_answer = Some(result);
            return;
        }
        let now = self.now();
        let Some(&w_id) = self.by_drive.get(&d_id) else {
            return;
        };
        let is_config_list = {
            let Some(req) = self.reqs.get_mut(&w_id) else {
                return;
            };
            req.life = now;
            matches!(req.op, ReqOp::List(ObjectType::Config))
        };
        match result {
            R::ListPage(p) => {
                if is_config_list {
                    let total = self.list_total.entry(w_id).or_default();
                    *total += p.entries.len() as u64;
                    if p.last {
                        self.config_absent = *total == 0;
                    }
                }
                let f = frame(pb::repo_frame::Frame::Response(pb::RepoResponse {
                    req_id: w_id,
                    result: Some(R::ListPage(p)),
                }));
                self.send_worker(&f);
            }
            R::ReadBegin(b) => {
                if let Some(req) = self.reqs.get_mut(&w_id) {
                    req.download_begun = true;
                }
                let f = frame(pb::repo_frame::Frame::Response(pb::RepoResponse {
                    req_id: w_id,
                    result: Some(R::ReadBegin(b)),
                }));
                self.send_worker(&f);
            }
            R::Done(d) => {
                let f = frame(pb::repo_frame::Frame::Response(pb::RepoResponse {
                    req_id: w_id,
                    result: Some(R::Done(d)),
                }));
                self.send_worker(&f);
            }
            R::Error(e) => self.drive_error(w_id, e),
            R::QuotaResult(_) => {}
        }
    }

    fn drive_error(&mut self, w_id: u64, e: pb::RepoError) {
        let class = ErrorClass::try_from(e.class).unwrap_or(ErrorClass::Internal);
        let Some(req) = self.reqs.get_mut(&w_id) else {
            return;
        };
        if class == ErrorClass::Permission {
            let what = req.label.clone();
            self.env.audit(&format!(
                "backup job {}: the Drive helper answered PERMISSION to `{what}`",
                self.job_hex
            ));
        }
        if !matches!(class, ErrorClass::NotFound | ErrorClass::Cancelled)
            && self.first_err.is_none()
        {
            self.first_err = Some(class);
        }
        let req = self.reqs.get_mut(&w_id);
        let mut close_upload = None;
        if let Some(req) = req {
            req.answered = true;
            if let ReqOp::Write(w) = &req.op
                && !w.end_forwarded
            {
                close_upload = Some(req.d_id);
            }
        }
        // An error answers an upload before its `END` was forwarded: the upload is aborted, and
        // privd closes it with an empty `END` right away (section 25). The worker then closes its
        // own side with `END` and the rest of its data is discarded.
        if let Some(d_id) = close_upload {
            self.send_data_on(LinkName::Drive, d_id, true, Bytes::new(), None);
            if let Some(r) = self.reqs.get_mut(&w_id)
                && let ReqOp::Write(w) = &mut r.op
            {
                w.end_forwarded = true;
            }
        }
        let f = frame(pb::repo_frame::Frame::Response(pb::RepoResponse {
            req_id: w_id,
            result: Some(pb::repo_response::Result::Error(e)),
        }));
        self.send_worker(&f);
    }

    fn drive_data(&mut self, d: repo::DataFrame, permit: OwnedSemaphorePermit, discard: bool) {
        if discard {
            return;
        }
        let now = self.now();
        let Some(&w_id) = self.by_drive.get(&d.stream_id) else {
            return;
        };
        if let Some(r) = self.reqs.get_mut(&w_id) {
            r.life = now;
        }
        self.mapper.add_transfer(d.payload.len() as u64);
        self.send_data_on(LinkName::Worker, w_id, d.end, d.payload, Some(permit));
    }

    fn drive_event(&mut self, e: pb::Event) {
        let now = self.now();
        for r in self.reqs.values_mut() {
            r.life = now;
        }
        if self.open_life.is_some() {
            self.open_life = Some(now);
        }
        let unix_ms = self.env.now_unix().saturating_mul(1000);
        let day = 26 * 60 * 60 * 1000;
        match pb::EventKind::try_from(e.kind).unwrap_or(pb::EventKind::Unspecified) {
            pb::EventKind::PausedDailyLimit => {
                let until = if e.until_ms == 0 {
                    unix_ms + 60 * 60 * 1000
                } else {
                    e.until_ms.min(unix_ms + day)
                };
                let wait = until.saturating_sub(unix_ms);
                self.pause_end_mono = Some(now + wait);
                self.reporter.paused(Some(until));
            }
            pb::EventKind::Resumed => {
                self.pause_end_mono = None;
                self.reporter.paused(None);
            }
            pb::EventKind::SessionFailed => {
                let class = ErrorClass::try_from(e.error_class).unwrap_or(ErrorClass::Internal);
                self.drive_lost(class, Failure::Repo(class));
            }
            _ => {}
        }
    }

    /// The Drive session is gone (`class` says why): the outstanding requests that can be
    /// answered are answered `UNAVAILABLE`, later ones are too, and the worker is asked to stop.
    fn drive_lost(&mut self, class: ErrorClass, failure: Failure) {
        if self.drive_dead.is_some() {
            return;
        }
        self.drive_dead = Some(class);
        if !matches!(class, ErrorClass::NotFound | ErrorClass::Cancelled)
            && self.first_err.is_none()
        {
            self.first_err = Some(class);
        }
        if let Some(l) = self.drive.as_mut() {
            l.close(false);
        }
        let ids: Vec<u64> = self
            .reqs
            .iter()
            .filter(|(w, r)| {
                !r.download_begun
                    && !r.answered
                    && self
                        .worker
                        .as_ref()
                        .is_some_and(|l| l.open && l.state.is_outstanding(**w))
            })
            .map(|(w, _)| *w)
            .collect();
        for w_id in ids {
            self.answer_error(w_id, ErrorClass::Unavailable);
        }
        self.reporter.paused(None);
        self.begin_drain(failure);
        // The worker is gone too (or never was): nothing left to wait for.
        if self.worker.is_none() {
            self.over = true;
        }
    }

    /// Forgets the requests that neither link has outstanding any more.
    fn collect(&mut self) {
        let (w, d) = (self.worker.as_ref(), self.drive.as_ref());
        let done: Vec<u64> = self
            .reqs
            .iter()
            .filter(|(w_id, r)| {
                let w_out = w.is_some_and(|l| l.state.is_outstanding(**w_id));
                let d_out = d.is_some_and(|l| l.state.is_outstanding(r.d_id));
                !w_out && !d_out
            })
            .map(|(w_id, _)| *w_id)
            .collect();
        for w_id in done {
            if let Some(r) = self.reqs.remove(&w_id) {
                self.by_drive.remove(&r.d_id);
            }
            self.list_total.remove(&w_id);
        }
    }

    /// How many worker requests privd is tracking (tests).
    pub fn tracked_requests(&self) -> usize {
        self.reqs.len()
    }
}
