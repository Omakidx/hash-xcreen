//! The [`SetupCoordinator`]: the window, the setup binding, the one setup job and the
//! authenticator's [`SetupGate`] (`docs/ipc.md` 5.5).
//!
//! State lives behind one `std::sync::Mutex` that is **never held across an await**; the
//! persisted part (window and binding) is written to the [`SetupStore`] inside it so the file
//! and the memory cannot disagree. The job runs in its own task ([`super::job`]) and does not
//! depend on any client connection.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hx_crypto::auth::{BoxFuture, SetupAdmission, SetupGate};
use hx_crypto::{Authenticator, Clock, DeviceId, DeviceRecord, PairedWith};
use hx_ipc::privd::pb as privd_pb;
use hx_ipc::privd::pb::AuditEvent;
use hx_ipc::text::sanitize_text;
use hx_proto::channel::CloseCode;
use hx_proto::message::pin_problem;
use hx_proto::pb;
use tokio::sync::{Notify, broadcast};
use zeroize::Zeroizing;

use super::job::{self, JobRequest};
use super::store::{Persisted, SetupStore};
use super::{MIN_WINDOW_REMAINING_S, PIN_ATTEMPTS_PER_HOUR, STARTS_PER_HOUR, SetupSettings};
use crate::gateway::devices::DeviceService;
use crate::gateway::privd_client::{PrivdClient, PrivdError, PrivdLane};
use crate::gateway::util::short_id;
use crate::gateway::verifier::{self, VerifierError, VerifierStore};

/// Longest total lifetime of one setup window (docs/ipc.md 5.1).
const MAX_WINDOW_SECS: u64 = 24 * 3600;
/// Seconds in the hour of the rate limits.
const HOUR: Duration = Duration::from_secs(3600);

/// What the connections are told as it happens.
#[derive(Debug, Clone)]
pub(super) enum Event {
    /// The state changed: connections push a fresh `SetupState`.
    State,
    /// A (coalesced) progress update.
    Progress(pb::SetupProgress),
    /// The job ended.
    Result(pb::SetupResult),
    /// Close the connections of `device` (all if `None`).
    Kick {
        device: Option<DeviceId>,
        code: CloseCode,
        reason: &'static str,
    },
}

/// What a running job is told: cancel.
#[derive(Default)]
pub(super) struct JobCtl {
    pub cancelled: AtomicBool,
    pub notify: Notify,
}

impl JobCtl {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
        // A permit for a cancel that arrives before the job starts waiting.
        self.notify.notify_one();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

pub(super) struct Job {
    pub state: pb::SetupJobState,
    pub id: u32,
    pub progress: Option<pb::SetupProgress>,
    pub result: Option<pb::SetupResult>,
    pub ctl: Option<Arc<JobCtl>>,
}

pub(super) struct State {
    pub p: Persisted,
    pub finished: bool,
    pub job: Job,
    pub next_job: u32,
    pub starts: VecDeque<Instant>,
    pub pin_attempts: VecDeque<Instant>,
    pub conn_gen: u64,
    pub conn: Option<(u64, hx_transport::Connection)>,
    pub host: Option<pb::SetupHostFacts>,
    pub desktop: pb::SetupDesktopState,
    /// The running job's task, aborted when gatewayd stops.
    pub job_task: Option<tokio::task::AbortHandle>,
}

pub(super) struct Shared {
    pub store: SetupStore,
    pub st: Mutex<State>,
    pub privd: PrivdClient,
    pub lane: PrivdLane,
    pub verifiers: Arc<VerifierStore>,
    /// Weak: the authenticator holds this coordinator as its setup gate, and the device service
    /// holds the authenticator, so a strong reference would be a cycle that keeps the registry
    /// lock alive for ever.
    pub devices: std::sync::Weak<DeviceService>,
    pub clock: Arc<dyn Clock>,
    pub settings: SetupSettings,
    pub events: broadcast::Sender<Arc<Event>>,
    /// Serializes `set_pin`: the check "no PIN exists" and the store must not interleave.
    pub pin_lock: tokio::sync::Mutex<()>,
}

/// What `Status` on the admin socket reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupStatus {
    /// The window mirror says open.
    pub window_open: bool,
    /// When it ends (Unix seconds), 0 when closed.
    pub window_expires_unix: u64,
    /// A setup device is bound.
    pub device: Option<DeviceId>,
    /// The installer's token was recorded and nobody paired with it yet.
    pub token_pending: bool,
    /// The job's state.
    pub job: pb::SetupJobState,
    /// The job's id (0 before the first).
    pub job_id: u32,
}

/// The coordinator. Cheap to clone.
#[derive(Clone)]
pub struct SetupCoordinator {
    pub(super) sh: Arc<Shared>,
}

impl Shared {
    pub(super) fn now(&self) -> u64 {
        self.clock.unix_secs()
    }

    pub(super) fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(super) fn bump_version(&self) {
        if let Some(d) = self.devices.upgrade() {
            d.bump_version();
        }
    }

    /// A server-wide audit event (no device), best effort in the background.
    pub(super) fn audit(&self, event: AuditEvent, label: &str) {
        if let Some(d) = self.devices.upgrade() {
            d.audit_opt(event, None, label);
        }
    }

    pub(super) fn publish(&self, e: Event) {
        let _ = self.events.send(Arc::new(e));
    }

    fn persist(&self, st: &State) {
        if let Err(e) = self.store.save(&st.p) {
            // The in-memory state stays authoritative for this run; a restart would lose it.
            tracing::error!(error = %e, "persisting the setup state failed");
        }
    }

    /// Applies the window's expiry: everything persisted is cleared (the binding ends with the
    /// window).
    fn expire(&self, st: &mut State) {
        if st.p.window_expires != 0 && self.now() >= st.p.window_expires {
            st.p = Persisted::default();
            self.persist(st);
            self.publish(Event::State);
        }
    }

    fn open_now(&self, st: &State) -> bool {
        st.p.window_expires > self.now()
    }

    /// The window as `(open, expires)` after applying expiry.
    pub(super) fn window(&self) -> (bool, u64) {
        let mut st = self.lock();
        self.expire(&mut st);
        let open = self.open_now(&st);
        (open, if open { st.p.window_expires } else { 0 })
    }

    pub(super) fn is_bound(&self, device: &DeviceId) -> bool {
        let mut st = self.lock();
        self.expire(&mut st);
        self.open_now(&st) && st.p.device.as_ref() == Some(device)
    }

    pub(super) fn job_running(&self) -> bool {
        self.lock().job.state == pb::SetupJobState::Running
    }

    /// The `SetupState` of now (from memory only).
    pub(super) fn snapshot(&self) -> pb::SetupState {
        let mut st = self.lock();
        self.expire(&mut st);
        let open = self.open_now(&st);
        pb::SetupState {
            job: st.job.state as i32,
            job_id: st.job.id,
            pin_set: self.verifiers.has_pin(),
            desktop: st.desktop as i32,
            window_expires_unix: if open { st.p.window_expires } else { 0 },
            finished: st.finished,
            last_progress: if st.job.state == pb::SetupJobState::Running {
                st.job.progress.clone()
            } else {
                None
            },
            last_result: st.job.result.clone(),
            host: st.host.clone(),
        }
    }

    /// Re-reads the host facts and the desktop's state from privd (bounded; failures leave the
    /// desktop `UNKNOWN`).
    pub(super) async fn refresh_facts(&self) {
        let t = self.settings.privd_timeout;
        let host = tokio::time::timeout(t, self.privd.get_host_info()).await;
        let desk = tokio::time::timeout(t, self.privd.get_desktop(&self.settings.desktop_id)).await;
        let mut st = self.lock();
        if let Ok(Ok(h)) = host {
            let os = format!("{} {}", h.os_id, h.os_version);
            let pool = h.pool.unwrap_or_default();
            st.host = Some(pb::SetupHostFacts {
                cpu_count: h.cpu_count,
                memory_total_mib: h.memory_total_mib,
                pool_total_gib: pool.total_gib,
                pool_free_gib: pool.free_gib,
                docker_supported: h.incus_version.as_deref().is_some_and(|v| {
                    crate::install::stages::incus::at_least(
                        v,
                        crate::install::stages::incus::DOCKER_MIN_VERSION,
                    )
                }),
                os: sanitize_text(os.trim(), 64),
                arch: sanitize_text(&h.arch, 16),
            });
        }
        st.desktop = match desk {
            Ok(Ok(None)) => pb::SetupDesktopState::None,
            Ok(Ok(Some(d))) => desktop_state(&d),
            _ => pb::SetupDesktopState::Unknown,
        };
    }

    /// Closes the window and clears the binding (a successful `FinishSetup`).
    pub(super) fn mark_finished(&self) {
        let mut st = self.lock();
        st.finished = true;
        st.p = Persisted::default();
        self.persist(&st);
        drop(st);
        self.publish(Event::State);
    }

    /// privd says the window is closed: forget the mirror too.
    pub(super) fn mark_window_gone(&self) {
        let mut st = self.lock();
        st.p = Persisted::default();
        self.persist(&st);
        drop(st);
        self.publish(Event::State);
    }

    /// `FinishSetup` with up to 3 tries on a retryable error.
    pub(super) async fn finish_with_retries(&self) -> FinishOutcome {
        let mut last = None;
        for attempt in 0..3 {
            if attempt > 0 {
                tokio::time::sleep(self.settings.finish_retry_wait).await;
            }
            match tokio::time::timeout(Duration::from_secs(15), self.privd.finish_setup()).await {
                Ok(Ok(())) => {
                    self.mark_finished();
                    return FinishOutcome::Done;
                }
                Ok(Err(PrivdError::Remote(r)))
                    if r.code == privd_pb::ErrorCode::FailedPrecondition
                        && r.detail == privd_pb::ErrorDetail::SetupWindowClosed =>
                {
                    self.mark_window_gone();
                    return FinishOutcome::WindowClosed;
                }
                Ok(Err(e)) if e.is_retryable() => last = Some(e),
                Ok(Err(e)) => return FinishOutcome::Failed(e),
                Err(_) => last = Some(PrivdError::Timeout),
            }
        }
        FinishOutcome::Failed(last.unwrap_or(PrivdError::Timeout))
    }
}

pub(super) enum FinishOutcome {
    Done,
    WindowClosed,
    Failed(PrivdError),
}

fn desktop_state(d: &privd_pb::Desktop) -> pb::SetupDesktopState {
    use privd_pb::DesktopState as D;
    match D::try_from(d.state).unwrap_or(D::Unspecified) {
        D::Creating => pb::SetupDesktopState::Creating,
        D::Ready | D::Running | D::Stopped | D::Starting => pb::SetupDesktopState::Ready,
        D::Failed => pb::SetupDesktopState::Failed,
        D::Unspecified => pb::SetupDesktopState::Unknown,
    }
}

/// True if privd's desktop is registered and usable (the `EXISTING` path, `finish`).
pub(super) fn usable(d: &privd_pb::Desktop) -> bool {
    desktop_state(d) == pb::SetupDesktopState::Ready
}

pub(super) fn ack(status: pb::SetupAckStatus) -> pb::SetupAck {
    pb::SetupAck {
        status: status as i32,
        ..Default::default()
    }
}

fn ack_msg(status: pb::SetupAckStatus, message: &str) -> pb::SetupAck {
    pb::SetupAck {
        status: status as i32,
        message: sanitize_text(message, 256),
        ..Default::default()
    }
}

fn ack_field(status: pb::SetupAckStatus, field: &str) -> pb::SetupAck {
    pb::SetupAck {
        status: status as i32,
        field: sanitize_text(field, 64),
        ..Default::default()
    }
}

fn prune(q: &mut VecDeque<Instant>, now: Instant) {
    while q
        .front()
        .is_some_and(|t| now.saturating_duration_since(*t) >= HOUR)
    {
        q.pop_front();
    }
}

impl SetupCoordinator {
    /// Builds the coordinator over the loaded `persisted` state, and starts the task that
    /// follows revocations. Needs a running tokio runtime.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: SetupStore,
        persisted: Persisted,
        privd: PrivdClient,
        lane: PrivdLane,
        verifiers: Arc<VerifierStore>,
        devices: Arc<DeviceService>,
        auth: &Authenticator,
        clock: Arc<dyn Clock>,
        settings: SetupSettings,
    ) -> Self {
        let (events, _) = broadcast::channel(256);
        let sh = Arc::new(Shared {
            store,
            st: Mutex::new(State {
                p: persisted,
                finished: false,
                job: Job {
                    state: pb::SetupJobState::Idle,
                    id: 0,
                    progress: None,
                    result: None,
                    ctl: None,
                },
                next_job: 1,
                starts: VecDeque::new(),
                pin_attempts: VecDeque::new(),
                conn_gen: 0,
                conn: None,
                host: None,
                desktop: pb::SetupDesktopState::Unknown,
                job_task: None,
            }),
            privd,
            lane,
            verifiers,
            devices: Arc::downgrade(&devices),
            clock,
            settings,
            events,
            pin_lock: tokio::sync::Mutex::new(()),
        });
        let me = Self { sh };
        // A revocation of the setup device cancels the job and ends the binding.
        let weak = Arc::downgrade(&me.sh);
        let mut rx = auth.subscribe_revocations();
        let registry = auth.registry();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(id) => {
                        let Some(sh) = weak.upgrade() else { break };
                        SetupCoordinator { sh }.on_revoked(&id);
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // Re-check the bound device against the registry.
                        let Some(sh) = weak.upgrade() else { break };
                        let bound = sh.lock().p.device;
                        if let Some(d) = bound
                            && !matches!(registry.get(&d), Ok(Some(r)) if !r.is_revoked())
                        {
                            SetupCoordinator { sh }.on_revoked(&d);
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        me
    }

    // ------------------------------------------------------------------ window and binding

    /// Admin opened the window for `secs` (capped at 24 hours). Opening an open window keeps
    /// its start and the binding, so repeated opens cannot stretch it past 24 hours; opening a
    /// closed one starts fresh and forgets any earlier binding.
    pub fn on_window_open(&self, secs: u64) {
        let now = self.sh.now();
        let mut st = self.sh.lock();
        self.sh.expire(&mut st);
        let secs = secs.min(MAX_WINDOW_SECS);
        if self.sh.open_now(&st) {
            let cap = st.p.window_opened + MAX_WINDOW_SECS;
            st.p.window_expires = now.saturating_add(secs).min(cap);
        } else {
            st.p = Persisted {
                window_opened: now,
                window_expires: now.saturating_add(secs),
                token_id: None,
                device: None,
            };
            st.finished = false;
        }
        self.sh.persist(&st);
        drop(st);
        self.sh.publish(Event::State);
    }

    /// Extends the open window, never past 24 hours since it opened. False if it is not open.
    pub fn on_window_extend(&self, secs: u64) -> bool {
        let mut st = self.sh.lock();
        self.sh.expire(&mut st);
        if !self.sh.open_now(&st) {
            return false;
        }
        let cap = st.p.window_opened + MAX_WINDOW_SECS;
        st.p.window_expires = st.p.window_expires.saturating_add(secs).min(cap);
        self.sh.persist(&st);
        drop(st);
        self.sh.publish(Event::State);
        true
    }

    /// Admin closed the window: the binding ends. A running job continues (privd admitted it).
    pub fn on_window_close(&self) {
        let mut st = self.sh.lock();
        st.p = Persisted::default();
        self.sh.persist(&st);
        drop(st);
        self.sh.publish(Event::State);
    }

    /// `(open, expires_unix)` for the admin `Status` and `SetupWindow` replies.
    pub fn window_state(&self) -> (bool, u64) {
        self.sh.window()
    }

    /// The installer's token (public id) was installed. While the window is open its id is
    /// recorded, which is how the device that pairs with it becomes the setup device.
    pub fn on_token_installed(&self, id: [u8; 8]) {
        let mut st = self.sh.lock();
        self.sh.expire(&mut st);
        if !self.sh.open_now(&st) {
            return;
        }
        st.p.token_id = Some(id);
        self.sh.persist(&st);
        drop(st);
        self.sh.publish(Event::State);
    }

    /// A device paired. If it used the recorded token while the window is open it becomes the
    /// setup device; a previously bound device loses the binding and its live setup connection
    /// is closed with `SETUP_CLOSED`. A code, or any other token, never binds.
    pub fn on_paired(&self, device: &DeviceRecord, with: PairedWith) {
        let PairedWith::Token { id } = with else {
            return;
        };
        let mut st = self.sh.lock();
        self.sh.expire(&mut st);
        if !self.sh.open_now(&st) || st.p.token_id != Some(id) {
            return;
        }
        let old = st.p.device.replace(device.id);
        st.p.token_id = None;
        self.sh.persist(&st);
        drop(st);
        tracing::info!(device = %short_id(&device.id), "setup device bound");
        if let Some(old) = old.filter(|o| *o != device.id) {
            self.sh.publish(Event::Kick {
                device: Some(old),
                code: CloseCode::SetupClosed,
                reason: "setup device changed",
            });
        }
        self.sh.publish(Event::State);
    }

    /// A device was revoked: if it was the setup device the job is cancelled and the binding
    /// ends (the window stays for the operator).
    pub fn on_revoked(&self, device: &DeviceId) {
        let mut st = self.sh.lock();
        if st.p.device.as_ref() != Some(device) {
            return;
        }
        st.p.device = None;
        st.p.token_id = None;
        self.sh.persist(&st);
        let ctl = st.job.ctl.clone();
        drop(st);
        tracing::warn!(device = %short_id(device), "the setup device was revoked");
        if let Some(c) = ctl {
            c.cancel();
        }
        self.sh.publish(Event::State);
    }

    /// Stops a running job (gatewayd is stopping): its privd connection closes, which privd
    /// treats as a cancel and destroys the unfinished instance.
    pub fn shutdown(&self) {
        if let Some(h) = self.sh.lock().job_task.take() {
            h.abort();
        }
    }

    /// For the admin `Status`.
    pub fn status(&self) -> SetupStatus {
        let mut st = self.sh.lock();
        self.sh.expire(&mut st);
        let open = self.sh.open_now(&st);
        SetupStatus {
            window_open: open,
            window_expires_unix: if open { st.p.window_expires } else { 0 },
            device: if open { st.p.device } else { None },
            token_pending: open && st.p.token_id.is_some(),
            job: st.job.state,
            job_id: st.job.id,
        }
    }

    // ------------------------------------------------------------------ requests

    /// `set_pin`: succeeds once, while no PIN exists. Argon2id here, `PepperEnrol(PIN)` in
    /// privd, the store with target `all`, then the audit event.
    pub(super) async fn set_pin(&self, device: &DeviceId, pin: Zeroizing<Vec<u8>>) -> pb::SetupAck {
        use pb::SetupAckStatus as S;
        if pin_problem(&pin).is_some() {
            return ack_field(S::InvalidArgument, "pin");
        }
        // Every request re-checks the binding: the window and its device can change while a
        // connection stays open (it is closed by the 1 s tick or a kick, a moment later).
        if !self.sh.is_bound(device) {
            return ack_msg(S::Failed, "setup is closed for this device");
        }
        let _one = self.sh.pin_lock.lock().await;
        if self.sh.verifiers.has_pin() {
            return ack(S::PinAlreadySet);
        }
        {
            let now = self.sh.clock.now();
            let mut st = self.sh.lock();
            prune(&mut st.pin_attempts, now);
            if st.pin_attempts.len() >= PIN_ATTEMPTS_PER_HOUR {
                let wait = st
                    .pin_attempts
                    .front()
                    .map(|t| HOUR.saturating_sub(now.saturating_duration_since(*t)))
                    .unwrap_or(HOUR);
                return pb::SetupAck {
                    retry_after_ms: u32::try_from(wait.as_millis()).unwrap_or(u32::MAX),
                    ..ack(S::RateLimited)
                };
            }
            st.pin_attempts.push_back(now);
        }
        let record = match verifier::enrol(
            &self.sh.privd,
            privd_pb::LockoutPurpose::Pin,
            &pin,
            self.sh.settings.params,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => return verifier_ack(&e),
        };
        drop(pin);
        if let Err(e) = self.sh.verifiers.set_pin(None, record) {
            tracing::error!(error = %e, "storing the setup PIN failed");
            return ack_msg(S::Failed, "the PIN could not be stored");
        }
        self.sh.bump_version();
        self.sh.audit(AuditEvent::PinChanged, "setup");
        self.sh.publish(Event::State);
        ack(S::Ok)
    }

    /// `start`: validates, applies the limits and spawns the job.
    pub(super) fn start(&self, device: &DeviceId, start: pb::SetupStart) -> pb::SetupAck {
        use pb::SetupAckStatus as S;
        let pb::SetupStart {
            options, password, ..
        } = start;
        let password = Zeroizing::new(password.to_vec());
        let now = self.sh.clock.now();
        let mut st = self.sh.lock();
        self.sh.expire(&mut st);
        if !(self.sh.open_now(&st) && st.p.device.as_ref() == Some(device)) {
            return ack_msg(S::Failed, "setup is closed for this device");
        }
        if st.finished {
            return ack(S::AlreadyFinished);
        }
        if st.job.state == pb::SetupJobState::Running {
            return ack(S::Busy);
        }
        let request: JobRequest =
            match job::validate(options.as_ref(), &self.sh.settings.desktop_id, &password) {
                Ok(r) => r,
                Err(field) => return ack_field(S::InvalidArgument, field),
            };
        let remaining = st.p.window_expires.saturating_sub(self.sh.now());
        if remaining < MIN_WINDOW_REMAINING_S {
            return ack_msg(
                S::WindowTooShort,
                "less than 50 minutes of the setup window remain: run `sudo hx-agent setup extend`",
            );
        }
        prune(&mut st.starts, now);
        if st.starts.len() >= STARTS_PER_HOUR {
            let wait = st
                .starts
                .front()
                .map(|t| HOUR.saturating_sub(now.saturating_duration_since(*t)))
                .unwrap_or(HOUR);
            return pb::SetupAck {
                retry_after_ms: u32::try_from(wait.as_millis()).unwrap_or(u32::MAX),
                ..ack(S::RateLimited)
            };
        }
        st.starts.push_back(now);
        let id = st.next_job;
        st.next_job += 1;
        let ctl = Arc::new(JobCtl::default());
        st.job = Job {
            state: pb::SetupJobState::Running,
            id,
            progress: None,
            result: None,
            ctl: Some(ctl.clone()),
        };
        drop(st);
        let sh = self.sh.clone();
        let handle = tokio::spawn(job::run(sh, id, request, password, ctl));
        self.sh.lock().job_task = Some(handle.abort_handle());
        self.sh.publish(Event::State);
        pb::SetupAck {
            job_id: id,
            ..ack(S::Ok)
        }
    }

    /// `cancel`: takes effect while a privd command runs; otherwise just acknowledged.
    pub(super) fn cancel(&self, device: &DeviceId) -> pb::SetupAck {
        use pb::SetupAckStatus as S;
        if !self.sh.is_bound(device) {
            return ack_msg(S::Failed, "setup is closed for this device");
        }
        let st = self.sh.lock();
        if st.job.state != pb::SetupJobState::Running {
            return ack(S::NotRunning);
        }
        let (id, ctl) = (st.job.id, st.job.ctl.clone());
        drop(st);
        if let Some(c) = ctl {
            c.cancel();
        }
        pb::SetupAck {
            job_id: id,
            ..ack(S::Ok)
        }
    }

    /// `finish`: retries finishing setup after a transient failure. Idempotent.
    pub(super) async fn finish(&self, device: &DeviceId) -> pb::SetupAck {
        use pb::SetupAckStatus as S;
        {
            let st = self.sh.lock();
            if st.finished {
                return ack(S::AlreadyFinished);
            }
            drop(st);
            if !self.sh.is_bound(device) {
                return ack_msg(S::Failed, "setup is closed for this device");
            }
            let st = self.sh.lock();
            if st.job.state == pb::SetupJobState::Running {
                return ack(S::Busy);
            }
        }
        let t = self.sh.settings.privd_timeout;
        match tokio::time::timeout(t, self.sh.privd.get_desktop(&self.sh.settings.desktop_id)).await
        {
            Ok(Ok(Some(d))) if usable(&d) => {}
            Ok(Ok(_)) => return ack(S::DesktopNotReady),
            _ => return unavailable(),
        }
        match self.sh.finish_with_retries().await {
            FinishOutcome::Done => ack(S::Ok),
            FinishOutcome::WindowClosed => ack_msg(
                S::Failed,
                "the setup window already closed: run `sudo hx-agent setup finish`",
            ),
            FinishOutcome::Failed(_) => unavailable(),
        }
    }

    /// The `SetupState` for a connection that just started (facts refreshed first).
    pub(super) async fn state_for_new_connection(&self) -> pb::SetupState {
        self.sh.refresh_facts().await;
        self.sh.snapshot()
    }
}

fn unavailable() -> pb::SetupAck {
    pb::SetupAck {
        retry_after_ms: 2000,
        ..ack(pb::SetupAckStatus::Unavailable)
    }
}

fn verifier_ack(e: &VerifierError) -> pb::SetupAck {
    use pb::SetupAckStatus as S;
    match e {
        VerifierError::Privd(p) if p.is_locked() => ack(S::Locked),
        VerifierError::Privd(PrivdError::Remote(r))
            if r.code == privd_pb::ErrorCode::ResourceExhausted =>
        {
            pb::SetupAck {
                retry_after_ms: u32::try_from(r.retry_after.as_millis()).unwrap_or(u32::MAX),
                ..ack(S::RateLimited)
            }
        }
        VerifierError::Privd(p) if p.is_retryable() => unavailable(),
        VerifierError::InvalidSecret => ack_field(S::InvalidArgument, "pin"),
        _ => ack_msg(S::Failed, "the verifier could not be created"),
    }
}

impl SetupGate for SetupCoordinator {
    fn admit<'a>(&'a self, device: &'a DeviceId) -> BoxFuture<'a, SetupAdmission> {
        Box::pin(async move {
            // The persisted mirror and the binding first: no privd call for a device that is
            // not the setup device.
            if !self.sh.is_bound(device) {
                return SetupAdmission::Closed;
            }
            // privd is the authority on the window.
            let t = self.sh.settings.privd_timeout;
            match tokio::time::timeout(t, self.sh.privd.get_host_info()).await {
                Ok(Ok(h)) if h.phase == privd_pb::Phase::SetupOpen as i32 => {}
                Ok(Ok(_)) => return SetupAdmission::Closed,
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "setup admission: privd could not be asked");
                    return SetupAdmission::Unavailable;
                }
                Err(_) => {
                    tracing::warn!("setup admission: privd did not answer in time");
                    return SetupAdmission::Unavailable;
                }
            }
            if self.sh.verifiers.has_pin() {
                SetupAdmission::NeedsPin
            } else {
                SetupAdmission::KeyOnly
            }
        })
    }
}
