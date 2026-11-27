//! Classification of Drive failures, the retrier and the daily-limit gate (ipc.md §29, §31).
//!
//! S4's `classify` matched the text of OpenDAL's error (`Parts { status: 429 ...`), which carries
//! neither the Drive `reason` nor a trustworthy status. Here the HTTP layer ([`super::transport`])
//! records what it really saw (status, Drive `reason`, `Retry-After`, the OAuth error of the token
//! endpoint) in a task-local slot for the attempt that is running, and [`classify`] reads that.
//! OpenDAL's own error is only the fallback for failures that never reached HTTP (a missing path).
//!
//! Nothing here logs a URL, a header or a body: only the operation's name, the class, the status
//! and the Drive reason.

use std::future::Future;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hx_ipc::repo::{self, pb};
use tokio::sync::{mpsc, watch};

use pb::ErrorClass as EC;

/// What the HTTP layer saw of one request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observed {
    /// The HTTP status, or 0 for "no response" (connection error, timeout).
    pub status: u16,
    /// Drive's `error.errors[0].reason` (at most 64 bytes of `[A-Za-z0-9_]`), or empty.
    pub reason: String,
    /// The token endpoint's `error` (`invalid_grant`, ...), same shape, or empty.
    pub oauth_error: String,
    /// `Retry-After` in seconds, when present and numeric.
    pub retry_after: Option<Duration>,
    /// The request went to the token endpoint.
    pub token_endpoint: bool,
}

/// What one attempt shares with the HTTP layer: the last request's outcome, the time of the last
/// progress (the no-progress timer), the ceiling of the next media body and the request count.
pub(crate) struct AttemptState {
    budget: Arc<Budget>,
    probe: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    obs: Mutex<Option<Observed>>,
    last: Mutex<Instant>,
    body_limit: AtomicU64,
    requests: AtomicU32,
}

impl AttemptState {
    fn new(budget: Arc<Budget>) -> Self {
        Self {
            budget,
            probe: Mutex::new(None),
            obs: Mutex::new(None),
            last: Mutex::new(Instant::now()),
            body_limit: AtomicU64::new(0),
            requests: AtomicU32::new(0),
        }
    }

    fn last(&self) -> Instant {
        *self.last.lock().unwrap_or_else(|e| e.into_inner())
    }
}

tokio::task_local! {
    static ATTEMPT: Arc<AttemptState>;
}

/// Records the outcome of an HTTP request for the attempt that is running (a no-op outside one).
pub(crate) fn record(obs: Observed) {
    let _ = ATTEMPT.try_with(|s| {
        *s.obs.lock().unwrap_or_else(|e| e.into_inner()) = Some(obs);
    });
}

impl AttemptState {
    /// Time the attempt spent waiting for the upload cap: it is progress, and it does not count
    /// against the request's deadline (ipc.md §29).
    pub(crate) fn paced(&self, d: Duration) {
        self.budget.add_paused(d);
        self.touch();
    }

    /// The response is not `dailyLimitExceeded`: if this attempt is the probe after a pause, the
    /// gate reopens now, not when the attempt ends.
    pub(crate) fn not_limited(&self) {
        let cb = self.probe.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(cb) = cb {
            cb();
        }
    }

    /// Progress of the attempt: a request byte written, a response byte read, a header received, a
    /// chunk waiting for the upload cap. Resets the no-progress timer.
    pub(crate) fn touch(&self) {
        *self.last.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
    }
}

/// The attempt that is running, for tasks that outlive the call (the body relay, hyper's connection
/// task), which cannot read the task-local themselves.
pub(crate) fn current() -> Option<Arc<AttemptState>> {
    ATTEMPT.try_with(Arc::clone).ok()
}

/// Sets the ceiling of the media bodies of this attempt (the bytes the caller asked for).
pub(crate) fn set_body_limit(bytes: u64) {
    let _ = ATTEMPT.try_with(|s| s.body_limit.store(bytes, Ordering::Relaxed));
}

/// The ceiling set by [`set_body_limit`], or 0 when none is set.
pub(crate) fn body_limit() -> u64 {
    ATTEMPT
        .try_with(|s| s.body_limit.load(Ordering::Relaxed))
        .unwrap_or(0)
}

/// Counts one request of the attempt; `false` when `max` is exceeded.
pub(crate) fn count_request(max: u32) -> bool {
    ATTEMPT
        .try_with(|s| s.requests.fetch_add(1, Ordering::Relaxed) < max)
        .unwrap_or(true)
}

/// How a failure is handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// 5xx, 408, 405, network errors, timeouts: back off and retry.
    Transient {
        /// `Retry-After`, honoured.
        retry_after: Option<Duration>,
    },
    /// 429 and 403 rate-limit reasons: back off and retry.
    RateLimited {
        /// `Retry-After`, honoured.
        retry_after: Option<Duration>,
    },
    /// 403 `dailyLimitExceeded`: the shared gate.
    DailyLimit,
    /// A 401 from the API: the access token may have expired; the caller refreshes once.
    Unauthorized,
    /// No retry; the class goes to privd.
    Fatal(EC),
}

const RATE_REASONS: [&str; 3] = [
    "rateLimitExceeded",
    "userRateLimitExceeded",
    "sharingRateLimitExceeded",
];

/// Maps what was seen to an [`Outcome`] (§31).
#[must_use]
pub fn classify(obs: Option<&Observed>, e: &opendal::Error) -> Outcome {
    if let Some(o) = obs {
        let ra = o.retry_after;
        let s = o.status;
        if s == 0 {
            return Outcome::Transient { retry_after: None };
        }
        if o.token_endpoint && o.oauth_error == "invalid_grant" {
            return Outcome::Fatal(EC::AuthRevoked);
        }
        if s == 401 {
            return if o.token_endpoint {
                Outcome::Fatal(EC::AuthRevoked)
            } else {
                Outcome::Unauthorized
            };
        }
        if s == 429 {
            return Outcome::RateLimited { retry_after: ra };
        }
        if s == 403 {
            let r = o.reason.as_str();
            return if RATE_REASONS.contains(&r) {
                Outcome::RateLimited { retry_after: ra }
            } else if r == "dailyLimitExceeded" {
                Outcome::DailyLimit
            } else if r == "storageQuotaExceeded" {
                Outcome::Fatal(EC::QuotaExceeded)
            } else {
                Outcome::Fatal(EC::Permission)
            };
        }
        if s == 408 || s == 405 || (500..=599).contains(&s) {
            return Outcome::Transient { retry_after: ra };
        }
        if s == 404 {
            return Outcome::Fatal(EC::NotFound);
        }
        if s >= 300 {
            // Other 4xx, and a redirect, which this client never follows.
            return Outcome::Fatal(EC::Internal);
        }
    }
    match e.kind() {
        opendal::ErrorKind::NotFound => Outcome::Fatal(EC::NotFound),
        _ if e.is_temporary() => Outcome::Transient { retry_after: None },
        _ => Outcome::Fatal(EC::Internal),
    }
}

/// An error answer for privd: the class and the `Retry-After` hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriveError {
    /// §31.
    pub class: EC,
    /// `RepoError.retry_after_ms` (0 = none), at most 24 h.
    pub retry_after_ms: u32,
    /// The failure was a 401 of the API (not `invalid_grant`): refresh the access token and repeat
    /// the request once before it is final (ipc.md §29).
    pub unauthorized: bool,
}

impl DriveError {
    /// An error of `class` with no hint.
    #[must_use]
    pub const fn new(class: EC) -> Self {
        Self {
            class,
            retry_after_ms: 0,
            unauthorized: false,
        }
    }

    fn with_hint(class: EC, hint: Option<Duration>) -> Self {
        let ms = hint.map_or(0, |d| {
            u32::try_from(d.as_millis().min(u128::from(repo::MAX_RETRY_AFTER_MS))).unwrap_or(0)
        });
        Self {
            class,
            retry_after_ms: ms,
            unauthorized: false,
        }
    }
}

impl std::fmt::Display for DriveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.class)
    }
}

/// All the durations and counts of the helper. Production values are the contract's; tests scale
/// them down.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// First retry delay (§29: 1 s).
    pub initial: Duration,
    /// Longest retry delay (64 s).
    pub max_delay: Duration,
    /// Retries per request (8).
    pub max_retries: u32,
    /// One daily-limit pause (1 h).
    pub daily_pause: Duration,
    /// Pauses per session (26).
    pub max_pauses: u32,
    /// An attempt that makes no progress for this long fails (60 s).
    pub idle: Duration,
    /// Each address is tried for this long when connecting (5 s).
    pub connect_each: Duration,
    /// A request is given up after this long of its own time (30 min, §32).
    pub request_budget: Duration,
    /// The lease may be served from a read this old (60 s).
    pub lease_cache: Duration,
    /// Entries of one listing (100 000).
    pub max_list_entries: usize,
    /// HTTP requests of one attempt (4 096).
    pub max_requests: u32,
    /// The read budget in KiB (32 MiB).
    pub read_budget_kib: usize,
    /// Frames in the outgoing data queue (16).
    pub out_queue: usize,
}

impl Timing {
    /// The values of ipc.md §29 and §32.
    #[must_use]
    pub const fn production() -> Self {
        Self {
            initial: repo::RETRY_INITIAL,
            max_delay: repo::RETRY_MAX,
            max_retries: repo::MAX_RETRIES,
            daily_pause: repo::DAILY_LIMIT_PAUSE,
            max_pauses: repo::MAX_DAILY_LIMIT_PAUSES,
            idle: Duration::from_secs(60),
            connect_each: Duration::from_secs(5),
            request_budget: repo::REQUEST_ANSWER_BUDGET,
            lease_cache: repo::LEASE_CACHE_MAX,
            max_list_entries: 100_000,
            max_requests: 4_096,
            read_budget_kib: 32 * 1024,
            out_queue: 16,
        }
    }

    /// Every duration divided by `factor`, for tests.
    #[must_use]
    pub fn scaled(self, factor: u32) -> Self {
        Self {
            initial: self.initial / factor,
            max_delay: self.max_delay / factor,
            daily_pause: self.daily_pause / factor,
            idle: self.idle / factor,
            connect_each: self.connect_each / factor,
            request_budget: self.request_budget / factor,
            lease_cache: self.lease_cache / factor,
            ..self
        }
    }

    /// Exponential backoff with equal jitter: half of `min(max, initial * 2^(retry-1))` plus a
    /// share `u` in `[0, 1)` of the other half. `retry` counts from 1.
    #[must_use]
    pub fn delay(&self, retry: u32, u: f64) -> Duration {
        let exp = self
            .initial
            .saturating_mul(1u32 << retry.saturating_sub(1).min(20));
        exp.min(self.max_delay)
            .mul_f64(0.5 + 0.5 * u.clamp(0.0, 1.0))
    }
}

/// The one deadline of a request, carried through every Drive call it makes (ipc.md §29).
#[derive(Debug)]
pub struct Budget {
    started: Instant,
    paused: Mutex<Duration>,
    limit: Duration,
}

impl Budget {
    fn new(limit: Duration) -> Self {
        Self {
            started: Instant::now(),
            paused: Mutex::new(Duration::ZERO),
            limit,
        }
    }

    /// Time at the daily-limit gate does not count.
    fn add_paused(&self, d: Duration) {
        *self.paused.lock().unwrap_or_else(|e| e.into_inner()) += d;
    }

    fn paused(&self) -> Duration {
        *self.paused.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// What is left of the request's own time.
    #[must_use]
    pub fn remaining(&self) -> Duration {
        let paused = *self.paused.lock().unwrap_or_else(|e| e.into_inner());
        self.limit
            .saturating_sub(self.started.elapsed().saturating_sub(paused))
    }
}

/// Cancellation and the deadline of one request: set from the link's reader, awaited at every wait
/// of the work.
#[derive(Clone)]
pub struct Cancel {
    rx: watch::Receiver<bool>,
    _keep: Option<Arc<watch::Sender<bool>>>,
    budget: Arc<Budget>,
}

/// The sending side of a [`Cancel`].
pub type CancelHandle = watch::Sender<bool>;

impl Cancel {
    /// A cancel pair with the production 30 minute deadline.
    #[must_use]
    pub fn new() -> (CancelHandle, Cancel) {
        Self::with_limit(repo::REQUEST_ANSWER_BUDGET)
    }

    /// A cancel pair whose request has `limit` of its own time.
    #[must_use]
    pub fn with_limit(limit: Duration) -> (CancelHandle, Cancel) {
        let (tx, rx) = watch::channel(false);
        (
            tx,
            Cancel {
                rx,
                _keep: None,
                budget: Arc::new(Budget::new(limit)),
            },
        )
    }

    /// A cancel that never fires, with the production deadline.
    #[must_use]
    pub fn never() -> Cancel {
        Self::never_with_limit(repo::REQUEST_ANSWER_BUDGET)
    }

    /// A cancel that never fires, with `limit` of time.
    #[must_use]
    pub fn never_with_limit(limit: Duration) -> Cancel {
        let (tx, rx) = watch::channel(false);
        Cancel {
            rx,
            _keep: Some(Arc::new(tx)),
            budget: Arc::new(Budget::new(limit)),
        }
    }

    /// The request's deadline.
    #[must_use]
    pub fn budget(&self) -> &Budget {
        &self.budget
    }

    /// Has it fired?
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        *self.rx.borrow()
    }

    /// Resolves when it fires (never, if the sender is dropped without firing).
    pub async fn fired(&self) {
        let mut rx = self.rx.clone();
        if rx.wait_for(|v| *v).await.is_err() {
            std::future::pending::<()>().await;
        }
    }

    /// Runs `fut` unless cancelled first.
    ///
    /// # Errors
    /// `CANCELLED`.
    pub async fn guard<T>(&self, fut: impl Future<Output = T>) -> Result<T, DriveError> {
        tokio::select! {
            () = self.fired() => Err(DriveError::new(EC::Cancelled)),
            v = fut => Ok(v),
        }
    }
}

#[derive(Default)]
struct Gate {
    until: Option<Instant>,
    set_at: Option<Instant>,
    pauses: u32,
    exhausted: bool,
    /// A pause was started and no request has succeeded since it ended.
    pausing: bool,
    /// One request is the probe after the pause.
    probing: bool,
    /// Which probe it is: only the current one may release or reopen the gate.
    probe_gen: u64,
}

enum Entry {
    Exhausted,
    Go { probe: Option<u64> },
}

/// Releases the probe when its attempt ends any way at all (including a cancelled request).
struct ProbeGuard<'a> {
    retrier: &'a Retrier,
    /// The generation of the probe this request is, if it is one.
    active: Option<u64>,
}

impl Drop for ProbeGuard<'_> {
    fn drop(&mut self) {
        if let Some(g) = self.active {
            self.retrier.release_probe(g);
        }
    }
}

/// The gate and what wakes its waiters.
struct GateCell {
    gate: Mutex<Gate>,
    notify: tokio::sync::Notify,
}

/// Runs operations with the retry policy of §29. One per session: the daily-limit gate is shared
/// by all the requests that use it.
pub struct Retrier {
    timing: Timing,
    rng: Box<dyn Fn() -> f64 + Send + Sync>,
    cell: Arc<GateCell>,
    events: Mutex<Option<mpsc::Sender<pb::Event>>>,
}

fn unix_ms(after: Duration) -> u64 {
    SystemTime::now()
        .checked_add(after)
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn random_unit() -> f64 {
    static S: AtomicU64 = AtomicU64::new(0);
    let mut x = S.load(Ordering::Relaxed);
    if x == 0 {
        let mut b = [0u8; 8];
        let _ = rustix::rand::getrandom(&mut b, rustix::rand::GetRandomFlags::empty());
        x = u64::from_le_bytes(b) | 1;
    }
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    S.store(x, Ordering::Relaxed);
    (x >> 11) as f64 / (1u64 << 53) as f64
}

impl Retrier {
    /// A retrier with the system's randomness.
    #[must_use]
    pub fn new(timing: Timing) -> Self {
        Self::with_rng(timing, Box::new(random_unit))
    }

    /// A retrier with a given jitter source (`[0, 1)`), for tests.
    #[must_use]
    pub fn with_rng(timing: Timing, rng: Box<dyn Fn() -> f64 + Send + Sync>) -> Self {
        Self {
            timing,
            rng,
            cell: Arc::new(GateCell {
                gate: Mutex::new(Gate::default()),
                notify: tokio::sync::Notify::new(),
            }),
            events: Mutex::new(None),
        }
    }

    /// Where `Event`s go.
    pub fn set_events(&self, tx: mpsc::Sender<pb::Event>) {
        *self.events.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
    }

    /// The timing in force.
    #[must_use]
    pub fn timing(&self) -> &Timing {
        &self.timing
    }

    fn sink(&self) -> Option<mpsc::Sender<pb::Event>> {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    async fn emit(&self, kind: pb::EventKind, until_ms: u64) {
        if let Some(tx) = self.sink() {
            let _ = tx
                .send(pb::Event {
                    kind: kind as i32,
                    until_ms,
                    error_class: 0,
                })
                .await;
        }
    }

    fn emit_retrying(&self, delay: Duration) {
        if let Some(tx) = self.sink() {
            let _ = tx.try_send(pb::Event {
                kind: pb::EventKind::Retrying as i32,
                until_ms: unix_ms(delay),
                error_class: 0,
            });
        }
    }

    /// The probe `generation` is done without having reopened the gate. A probe that has been
    /// replaced (the gate reopened and paused again since) releases nothing.
    fn release_probe(&self, generation: u64) {
        {
            let mut g = self.cell.gate.lock().unwrap_or_else(|e| e.into_inner());
            if g.probe_gen != generation {
                return;
            }
            g.probing = false;
        }
        self.cell.notify.notify_waiters();
    }

    /// What the probe's attempt calls when its response is not `dailyLimitExceeded`.
    fn reopen_callback(&self, generation: u64) -> Box<dyn FnOnce() + Send> {
        let cell = self.cell.clone();
        let sink = self.sink();
        Box::new(move || {
            let was = {
                let mut g = cell.gate.lock().unwrap_or_else(|e| e.into_inner());
                if g.probe_gen != generation {
                    // A probe of an earlier pause: the gate is not its to reopen.
                    return;
                }
                let was = g.pausing;
                g.pausing = false;
                g.probing = false;
                was
            };
            cell.notify.notify_waiters();
            if was && let Some(tx) = sink {
                let _ = tx.try_send(pb::Event {
                    kind: pb::EventKind::Resumed as i32,
                    until_ms: 0,
                    error_class: 0,
                });
            }
        })
    }

    /// Waits at the daily-limit gate. After a pause one request is let through as the probe; the
    /// rest wait until it has a response that is not `dailyLimitExceeded`. An exhausted gate fails
    /// everyone without an attempt.
    async fn enter_gate(&self, cancel: &Cancel) -> Result<Entry, DriveError> {
        loop {
            // Registered before the state is read, so that a wake-up in between is not lost.
            let notified = self.cell.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let wait = {
                let mut g = self.cell.gate.lock().unwrap_or_else(|e| e.into_inner());
                if g.exhausted {
                    return Ok(Entry::Exhausted);
                }
                match g.until {
                    Some(t) if t > Instant::now() => Some(t - Instant::now()),
                    _ if g.pausing => {
                        if g.probing {
                            None
                        } else {
                            g.probing = true;
                            g.probe_gen += 1;
                            return Ok(Entry::Go {
                                probe: Some(g.probe_gen),
                            });
                        }
                    }
                    _ => return Ok(Entry::Go { probe: None }),
                }
            };
            let began = Instant::now();
            match wait {
                Some(d) => {
                    cancel.guard(tokio::time::sleep(d)).await?;
                }
                None => {
                    cancel.guard(notified).await?;
                }
            }
            cancel.budget.add_paused(began.elapsed());
        }
    }

    /// A request met `dailyLimitExceeded` in an attempt that began at `attempt_started`.
    async fn on_daily_limit(&self, attempt_started: Instant) -> Result<(), DriveError> {
        let until = {
            let mut g = self.cell.gate.lock().unwrap_or_else(|e| e.into_inner());
            if g.exhausted {
                return Err(DriveError::new(EC::DailyLimit));
            }
            let now = Instant::now();
            if let (Some(until), Some(set)) = (g.until, g.set_at)
                && (until > now || set >= attempt_started)
            {
                // The gate already covers this failure (it is closed, or it was closed after this
                // attempt began): wait at it, do not start another pause.
                return Ok(());
            }
            if g.pauses >= self.timing.max_pauses {
                g.exhausted = true;
                g.until = None;
                self.cell.notify.notify_waiters();
                return Err(DriveError::new(EC::DailyLimit));
            }
            g.pauses += 1;
            g.until = Some(now + self.timing.daily_pause);
            g.set_at = Some(now);
            g.pausing = true;
            g.probing = false;
            self.cell.notify.notify_waiters();
            self.timing.daily_pause
        };
        self.emit(pb::EventKind::PausedDailyLimit, unix_ms(until))
            .await;
        Ok(())
    }

    async fn note_success(&self) {
        let resume = {
            let mut g = self.cell.gate.lock().unwrap_or_else(|e| e.into_inner());
            let open = g.until.is_none_or(|u| u <= Instant::now());
            if g.pausing && open {
                g.pausing = false;
                g.probing = false;
                self.cell.notify.notify_waiters();
                true
            } else {
                false
            }
        };
        if resume {
            self.emit(pb::EventKind::Resumed, 0).await;
        }
    }

    /// Runs `attempt` until it ends, fails to make progress for the idle time, or `remaining` is
    /// used up.
    async fn watch<T>(
        &self,
        state: &AttemptState,
        remaining: Duration,
        attempt: impl Future<Output = T>,
    ) -> Option<T> {
        tokio::pin!(attempt);
        let started = Instant::now();
        let paused0 = state.budget.paused();
        loop {
            // The deadline moves out by the time the attempt spends waiting for the upload cap.
            let deadline = started + remaining + state.budget.paused().saturating_sub(paused0);
            let wake = (state.last() + self.timing.idle).min(deadline);
            tokio::select! {
                r = &mut attempt => return Some(r),
                () = tokio::time::sleep_until(wake.into()) => {
                    let now = Instant::now();
                    let deadline = started + remaining + state.budget.paused().saturating_sub(paused0);
                    if now >= deadline || now >= state.last() + self.timing.idle {
                        return None;
                    }
                }
            }
        }
    }

    /// Runs `f` with retries. `size` is the size of the object the attempt moves (for the log
    /// only: there is no timeout by size). `f` is called again for each attempt and must be safe
    /// to repeat (every operation of the helper is: content is addressed, a write overwrites).
    ///
    /// An attempt fails when it makes no progress for the idle time; every attempt is capped at what
    /// is left of the request's deadline ([`Cancel::budget`]), which is shared by all the calls of
    /// the request.
    ///
    /// # Errors
    /// The [`DriveError`] of the last attempt, or `CANCELLED`.
    pub async fn run<T, F, Fut>(
        &self,
        cancel: &Cancel,
        size: u64,
        what: &'static str,
        f: F,
    ) -> Result<T, DriveError>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = opendal::Result<T>>,
    {
        self.run_inner(cancel, size, what, true, f).await
    }

    /// [`Retrier::run`] for a token exchange: it retries and has its deadline and no-progress
    /// timer, but it does not wait at the daily-limit gate, is never the probe, and its success
    /// never reopens the gate. The token endpoint is not Drive's quota.
    ///
    /// # Errors
    /// As [`Retrier::run`].
    pub async fn run_token<T, F, Fut>(
        &self,
        cancel: &Cancel,
        what: &'static str,
        f: F,
    ) -> Result<T, DriveError>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = opendal::Result<T>>,
    {
        self.run_inner(cancel, 0, what, false, f).await
    }

    async fn run_inner<T, F, Fut>(
        &self,
        cancel: &Cancel,
        size: u64,
        what: &'static str,
        gated: bool,
        mut f: F,
    ) -> Result<T, DriveError>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = opendal::Result<T>>,
    {
        let mut retries = 0u32;
        let mut probe = ProbeGuard {
            retrier: self,
            active: None,
        };
        let mut last = DriveError::new(EC::Transient);
        loop {
            if gated {
                match self.enter_gate(cancel).await? {
                    Entry::Exhausted => return Err(DriveError::new(EC::DailyLimit)),
                    Entry::Go { probe: p } => probe.active = p,
                }
            }
            if cancel.is_cancelled() {
                return Err(DriveError::new(EC::Cancelled));
            }
            let remaining = cancel.budget.remaining();
            if remaining.is_zero() {
                tracing::warn!(what, "drive request out of time");
                return Err(last);
            }
            let attempt_started = Instant::now();
            let state = Arc::new(AttemptState::new(cancel.budget.clone()));
            if let Some(g) = probe.active {
                *state.probe.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some(self.reopen_callback(g));
            }
            let attempt = ATTEMPT.scope(state.clone(), f());
            let result = cancel.guard(self.watch(&state, remaining, attempt)).await?;
            let outcome = match result {
                Some(Ok(v)) => {
                    if gated {
                        self.note_success().await;
                    }
                    probe.active = None;
                    return Ok(v);
                }
                Some(Err(e)) => {
                    let obs = state.obs.lock().unwrap_or_else(|e| e.into_inner()).take();
                    let o = classify(obs.as_ref(), &e);
                    tracing::debug!(what, size, status = obs.as_ref().map_or(0, |o| o.status), reason = obs.as_ref().map_or("", |o| o.reason.as_str()), outcome = ?o, "drive attempt failed");
                    o
                }
                None => {
                    tracing::debug!(what, "drive attempt made no progress");
                    Outcome::Transient { retry_after: None }
                }
            };
            let (class, hint) = match outcome {
                Outcome::Fatal(c) => return Err(DriveError::new(c)),
                Outcome::Unauthorized => {
                    return Err(DriveError {
                        unauthorized: true,
                        ..DriveError::new(EC::AuthRevoked)
                    });
                }
                Outcome::DailyLimit if gated => {
                    // A failed probe starts the next pause (or exhausts the gate).
                    self.on_daily_limit(attempt_started).await?;
                    probe.active = None;
                    continue;
                }
                Outcome::DailyLimit => (EC::Transient, None),
                Outcome::Transient { retry_after } => (EC::Transient, retry_after),
                Outcome::RateLimited { retry_after } => (EC::RateLimited, retry_after),
            };
            if let Some(g) = probe.active.take() {
                // The probe failed for another reason: let the next waiter probe.
                self.release_probe(g);
            }
            retries += 1;
            let mut delay = self.timing.delay(retries, (self.rng)());
            if let Some(ra) = hint {
                delay = delay.max(ra);
            }
            last = DriveError::with_hint(class, hint.or(Some(delay)));
            if retries > self.timing.max_retries || cancel.budget.remaining() < delay {
                tracing::warn!(what, retries, class = ?class, "drive request given up");
                return Err(last);
            }
            tracing::warn!(what, retry = retries, class = ?class, delay_ms = u64::try_from(delay.as_millis()).unwrap_or(0), "drive retry");
            self.emit_retrying(delay);
            cancel.guard(tokio::time::sleep(delay)).await?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn obs(status: u16, reason: &str) -> Observed {
        Observed {
            status,
            reason: reason.into(),
            ..Observed::default()
        }
    }

    fn other() -> opendal::Error {
        opendal::Error::new(opendal::ErrorKind::Unexpected, "x")
    }

    #[test]
    fn classification_follows_the_error_table() {
        let c = |o: Observed| classify(Some(&o), &other());
        let ra = Observed {
            retry_after: Some(Duration::from_secs(7)),
            ..obs(429, "")
        };
        assert_eq!(
            c(ra),
            Outcome::RateLimited {
                retry_after: Some(Duration::from_secs(7))
            }
        );
        for r in ["rateLimitExceeded", "userRateLimitExceeded"] {
            assert!(matches!(c(obs(403, r)), Outcome::RateLimited { .. }), "{r}");
        }
        assert_eq!(c(obs(403, "dailyLimitExceeded")), Outcome::DailyLimit);
        assert_eq!(
            c(obs(403, "storageQuotaExceeded")),
            Outcome::Fatal(EC::QuotaExceeded)
        );
        assert_eq!(
            c(obs(403, "appNotAuthorizedToFile")),
            Outcome::Fatal(EC::Permission)
        );
        assert_eq!(c(obs(403, "")), Outcome::Fatal(EC::Permission));
        assert_eq!(c(obs(401, "")), Outcome::Unauthorized);
        let tok401 = Observed {
            token_endpoint: true,
            ..obs(401, "")
        };
        assert_eq!(c(tok401), Outcome::Fatal(EC::AuthRevoked));
        let grant = Observed {
            token_endpoint: true,
            oauth_error: "invalid_grant".into(),
            ..obs(400, "")
        };
        assert_eq!(c(grant), Outcome::Fatal(EC::AuthRevoked));
        let client = Observed {
            token_endpoint: true,
            oauth_error: "invalid_request".into(),
            ..obs(400, "")
        };
        assert_eq!(c(client), Outcome::Fatal(EC::Internal));
        for s in [500, 502, 503, 504, 408, 405] {
            assert!(matches!(c(obs(s, "")), Outcome::Transient { .. }), "{s}");
        }
        assert!(matches!(c(obs(0, "")), Outcome::Transient { .. }));
        assert_eq!(c(obs(404, "")), Outcome::Fatal(EC::NotFound));
        assert_eq!(c(obs(416, "")), Outcome::Fatal(EC::Internal));
        assert_eq!(c(obs(302, "")), Outcome::Fatal(EC::Internal));
        // no HTTP evidence: the error's own kind
        let nf = opendal::Error::new(opendal::ErrorKind::NotFound, "p");
        assert_eq!(classify(None, &nf), Outcome::Fatal(EC::NotFound));
        assert_eq!(
            classify(Some(&obs(200, "")), &nf),
            Outcome::Fatal(EC::NotFound)
        );
        assert!(matches!(
            classify(None, &other().set_temporary()),
            Outcome::Transient { .. }
        ));
        assert_eq!(classify(None, &other()), Outcome::Fatal(EC::Internal));
    }

    #[test]
    fn backoff_doubles_to_the_cap_with_equal_jitter() {
        let t = Timing::production();
        let secs = |r, u| t.delay(r, u).as_secs_f64();
        // u = 0: half of the exponential; u -> 1: the whole
        let low: Vec<f64> = (1..=8).map(|r| secs(r, 0.0)).collect();
        assert_eq!(low, [0.5, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 32.0]);
        let high: Vec<f64> = (1..=8).map(|r| secs(r, 0.999_999)).collect();
        for (h, full) in high
            .iter()
            .zip([1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 64.0])
        {
            assert!((h - full).abs() < 0.001, "{h} vs {full}");
        }
    }

    fn fast() -> Timing {
        Timing::production().scaled(1000) // 1 ms first delay, 1 h pause becomes 3.6 s: set below
    }

    fn failing(
        n: &Arc<AtomicU32>,
        o: Observed,
    ) -> impl FnMut() -> std::pin::Pin<Box<dyn Future<Output = opendal::Result<u32>> + Send>> + use<>
    {
        let n = n.clone();
        move || {
            n.fetch_add(1, Ordering::SeqCst);
            let o = o.clone();
            // recorded while the attempt is polled, as the transport does
            Box::pin(async move {
                record(o);
                Err(other())
            })
        }
    }

    #[tokio::test]
    async fn a_transient_failure_is_retried_eight_times_then_given_up_with_its_class() {
        let r = Retrier::with_rng(fast(), Box::new(|| 0.0));
        let n = Arc::new(AtomicU32::new(0));
        let e = r
            .run(
                &Cancel::never(),
                0,
                "t",
                failing(&n, obs(503, "backendError")),
            )
            .await
            .unwrap_err();
        assert_eq!(e.class, EC::Transient);
        assert_eq!(n.load(Ordering::SeqCst), 9, "one attempt and eight retries");
    }

    #[tokio::test]
    async fn retry_after_is_honoured_and_reported() {
        let mut t = fast();
        t.max_retries = 1;
        let r = Retrier::with_rng(t, Box::new(|| 0.0));
        let n = Arc::new(AtomicU32::new(0));
        let o = Observed {
            retry_after: Some(Duration::from_millis(120)),
            ..obs(429, "")
        };
        let began = Instant::now();
        let e = r
            .run(&Cancel::never(), 0, "t", failing(&n, o))
            .await
            .unwrap_err();
        assert!(began.elapsed() >= Duration::from_millis(120));
        assert_eq!(e.class, EC::RateLimited);
        assert!(e.retry_after_ms >= 120);
        assert_eq!(n.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn fatal_classes_are_not_retried() {
        let r = Retrier::new(fast());
        for (o, class) in [
            (obs(403, "storageQuotaExceeded"), EC::QuotaExceeded),
            (obs(403, "other"), EC::Permission),
        ] {
            let n = Arc::new(AtomicU32::new(0));
            let e = r
                .run(&Cancel::never(), 0, "t", failing(&n, o))
                .await
                .unwrap_err();
            assert_eq!(e.class, class);
            assert_eq!(n.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn the_daily_gate_is_shared_counted_per_session_and_gives_up_after_the_limit() {
        let mut t = fast();
        t.daily_pause = Duration::from_millis(30);
        t.max_pauses = 2;
        let r = Arc::new(Retrier::with_rng(t, Box::new(|| 0.0)));
        let (tx, mut rx) = mpsc::channel(16);
        r.set_events(tx);
        // two requests fail at the same time: one pause, not two
        let n = Arc::new(AtomicU32::new(0));
        let both_started = Arc::new(tokio::sync::Barrier::new(2));
        let mut handles = vec![];
        for _ in 0..2 {
            let (r, n, b) = (r.clone(), n.clone(), both_started.clone());
            handles.push(tokio::spawn(async move {
                let n2 = n.clone();
                r.run(&Cancel::never(), 0, "t", move || {
                    // fails with the daily limit for the first two calls overall, then succeeds;
                    // both first attempts are in flight before either fails
                    let k = n2.fetch_add(1, Ordering::SeqCst);
                    let b = b.clone();
                    async move {
                        if k < 2 {
                            b.wait().await;
                            record(obs(403, "dailyLimitExceeded"));
                            Err(other())
                        } else {
                            Ok(k)
                        }
                    }
                })
                .await
            }));
        }
        for h in handles {
            assert!(h.await.unwrap().is_ok());
        }
        let mut kinds = vec![];
        while let Ok(ev) = rx.try_recv() {
            kinds.push(ev.kind);
        }
        assert_eq!(
            kinds
                .iter()
                .filter(|k| **k == pb::EventKind::PausedDailyLimit as i32)
                .count(),
            1,
            "{kinds:?}"
        );
        assert_eq!(
            kinds
                .iter()
                .filter(|k| **k == pb::EventKind::Resumed as i32)
                .count(),
            1,
            "{kinds:?}"
        );
        // it keeps failing: one pause is left (2 of 2), then DAILY_LIMIT for everyone
        let n = Arc::new(AtomicU32::new(0));
        let e = r
            .run(
                &Cancel::never(),
                0,
                "t",
                failing(&n, obs(403, "dailyLimitExceeded")),
            )
            .await
            .unwrap_err();
        assert_eq!(e.class, EC::DailyLimit);
        assert_eq!(n.load(Ordering::SeqCst), 2, "the last pause, then give up");
        let e = r
            .run(
                &Cancel::never(),
                0,
                "t",
                failing(&n, obs(403, "dailyLimitExceeded")),
            )
            .await
            .unwrap_err();
        assert_eq!(e.class, EC::DailyLimit, "exhausted for the session");
    }

    #[tokio::test]
    async fn cancel_interrupts_a_backoff_and_a_gate() {
        let mut t = fast();
        t.initial = Duration::from_secs(30);
        t.max_delay = Duration::from_secs(30);
        t.request_budget = Duration::from_secs(3600);
        let r = Arc::new(Retrier::with_rng(t, Box::new(|| 0.0)));
        let (h, c) = Cancel::new();
        let n = Arc::new(AtomicU32::new(0));
        let task = {
            let (r, n) = (r.clone(), n.clone());
            tokio::spawn(async move { r.run(&c, 0, "t", failing(&n, obs(503, ""))).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        let began = Instant::now();
        h.send(true).unwrap();
        let e = task.await.unwrap().unwrap_err();
        assert_eq!(e.class, EC::Cancelled);
        assert!(began.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn the_deadline_belongs_to_the_request_not_to_each_call() {
        let mut t = fast();
        t.max_retries = 0;
        t.idle = Duration::from_secs(10);
        let r = Retrier::with_rng(t, Box::new(|| 0.0));
        let cancel = Cancel::never_with_limit(Duration::from_millis(250));
        let began = Instant::now();
        let slow = || async {
            tokio::time::sleep(Duration::from_millis(150)).await;
            Ok::<u32, opendal::Error>(1)
        };
        // each call alone fits in the budget...
        assert_eq!(r.run(&cancel, 0, "a", slow).await.unwrap(), 1);
        // ...but the second finds only 100 ms left and is cut off there
        let e = r.run(&cancel, 0, "b", slow).await.unwrap_err();
        assert_eq!(e.class, EC::Transient);
        assert!(
            began.elapsed() < Duration::from_millis(330),
            "{:?}",
            began.elapsed()
        );
    }

    #[tokio::test]
    async fn only_a_lack_of_progress_times_an_attempt_out() {
        let mut t = fast();
        t.max_retries = 0;
        t.idle = Duration::from_millis(120);
        let r = Retrier::with_rng(t, Box::new(|| 0.0));
        // 500 ms in all, but progress every 50 ms: fine
        let steady = || async {
            for _ in 0..10 {
                tokio::time::sleep(Duration::from_millis(50)).await;
                current().unwrap().touch();
            }
            Ok::<u32, opendal::Error>(7)
        };
        assert_eq!(r.run(&Cancel::never(), 0, "t", steady).await.unwrap(), 7);
        // 300 ms with no progress at all: out after 120 ms
        let began = Instant::now();
        let stuck = || async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            Ok::<u32, opendal::Error>(7)
        };
        let e = r.run(&Cancel::never(), 0, "t", stuck).await.unwrap_err();
        assert_eq!(e.class, EC::Transient);
        assert!(
            began.elapsed() < Duration::from_millis(250),
            "{:?}",
            began.elapsed()
        );
    }

    #[tokio::test]
    async fn an_exhausted_gate_fails_every_request_without_an_attempt() {
        let mut t = fast();
        t.daily_pause = Duration::from_millis(20);
        t.max_pauses = 1;
        let r = Retrier::with_rng(t, Box::new(|| 0.0));
        let n = Arc::new(AtomicU32::new(0));
        let e = r
            .run(
                &Cancel::never(),
                0,
                "t",
                failing(&n, obs(403, "dailyLimitExceeded")),
            )
            .await
            .unwrap_err();
        assert_eq!(e.class, EC::DailyLimit);
        let before = n.load(Ordering::SeqCst);
        for _ in 0..3 {
            let e = r
                .run(&Cancel::never(), 0, "t", failing(&n, obs(200, "")))
                .await
                .unwrap_err();
            assert_eq!(e.class, EC::DailyLimit);
        }
        assert_eq!(n.load(Ordering::SeqCst), before, "no attempt was made");
    }

    #[tokio::test]
    async fn a_probe_that_has_been_replaced_cannot_release_the_gate() {
        let mut t = fast();
        t.daily_pause = Duration::from_millis(20);
        let r = Retrier::with_rng(t, Box::new(|| 0.0));
        let cancel = Cancel::never();
        let probing = |r: &Retrier| r.cell.gate.lock().unwrap().probing;
        // a pause, and probe 1, which reopens the gate with its answer
        r.on_daily_limit(Instant::now()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        let Entry::Go { probe: Some(g1) } = r.enter_gate(&cancel).await.unwrap() else {
            panic!("probe 1")
        };
        r.reopen_callback(g1)();
        // another pause, and probe 2, which is in flight
        r.on_daily_limit(Instant::now()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        let Entry::Go { probe: Some(g2) } = r.enter_gate(&cancel).await.unwrap() else {
            panic!("probe 2")
        };
        assert_ne!(g1, g2);
        assert!(probing(&r));
        // probe 1 ends late: neither its guard nor its callback may touch probe 2's gate
        r.release_probe(g1);
        r.reopen_callback(g1)();
        assert!(probing(&r), "the old probe cleared the new probe's flag");
        assert!(
            r.cell.gate.lock().unwrap().pausing,
            "the old probe reopened the gate"
        );
        r.release_probe(g2);
        assert!(!probing(&r));
    }
}
