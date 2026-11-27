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

type Slot = Arc<Mutex<Option<Observed>>>;

tokio::task_local! {
    static ATTEMPT: Slot;
}

/// Records the outcome of an HTTP request for the attempt that is running (a no-op outside one).
pub(crate) fn record(obs: Observed) {
    let _ = ATTEMPT.try_with(|slot| {
        *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(obs);
    });
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
        if s == 401 || (o.token_endpoint && o.oauth_error == "invalid_grant") {
            return Outcome::Fatal(EC::AuthRevoked);
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
}

impl DriveError {
    /// An error of `class` with no hint.
    #[must_use]
    pub const fn new(class: EC) -> Self {
        Self {
            class,
            retry_after_ms: 0,
        }
    }

    fn with_hint(class: EC, hint: Option<Duration>) -> Self {
        let ms = hint.map_or(0, |d| {
            u32::try_from(d.as_millis().min(u128::from(repo::MAX_RETRY_AFTER_MS))).unwrap_or(0)
        });
        Self {
            class,
            retry_after_ms: ms,
        }
    }
}

impl std::fmt::Display for DriveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.class)
    }
}

/// All the durations of the helper. Production values are the contract's; tests scale them down.
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
    /// Per-attempt timeout, fixed part (60 s).
    pub attempt_base: Duration,
    /// Per-attempt timeout, per MiB of the object (4 s).
    pub attempt_per_mib: Duration,
    /// A request is given up after this long of its own time (30 min, §32).
    pub request_budget: Duration,
    /// The lease may be served from a read this old (60 s).
    pub lease_cache: Duration,
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
            attempt_base: Duration::from_secs(60),
            attempt_per_mib: Duration::from_secs(4),
            request_budget: repo::REQUEST_ANSWER_BUDGET,
            lease_cache: repo::LEASE_CACHE_MAX,
        }
    }

    /// Every duration divided by `factor`, for tests.
    #[must_use]
    pub fn scaled(self, factor: u32) -> Self {
        Self {
            initial: self.initial / factor,
            max_delay: self.max_delay / factor,
            daily_pause: self.daily_pause / factor,
            attempt_base: self.attempt_base / factor,
            attempt_per_mib: self.attempt_per_mib / factor,
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

    /// The bound of one attempt that moves `bytes`.
    #[must_use]
    pub fn attempt_timeout(&self, bytes: u64) -> Duration {
        let mib = u32::try_from(bytes.div_ceil(1024 * 1024)).unwrap_or(u32::MAX);
        self.attempt_base + self.attempt_per_mib.saturating_mul(mib)
    }
}

/// Cancellation of one request: set from the link's reader, awaited at every wait of the work.
#[derive(Clone)]
pub struct Cancel {
    rx: watch::Receiver<bool>,
    _keep: Option<Arc<watch::Sender<bool>>>,
}

/// The sending side of a [`Cancel`].
pub type CancelHandle = watch::Sender<bool>;

impl Cancel {
    /// A cancel pair.
    #[must_use]
    pub fn new() -> (CancelHandle, Cancel) {
        let (tx, rx) = watch::channel(false);
        (tx, Cancel { rx, _keep: None })
    }

    /// A cancel that never fires.
    #[must_use]
    pub fn never() -> Cancel {
        let (tx, rx) = watch::channel(false);
        Cancel {
            rx,
            _keep: Some(Arc::new(tx)),
        }
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
    resume_pending: bool,
}

/// Runs operations with the retry policy of §29. One per session: the daily-limit gate is shared
/// by all the requests that use it.
pub struct Retrier {
    timing: Timing,
    rng: Box<dyn Fn() -> f64 + Send + Sync>,
    gate: Mutex<Gate>,
    events: Mutex<Option<mpsc::Sender<pb::Event>>>,
}

fn unix_ms(after: Duration) -> u64 {
    SystemTime::now()
        .checked_add(after)
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn random_unit() -> f64 {
    use std::sync::atomic::{AtomicU64, Ordering};
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
            gate: Mutex::new(Gate::default()),
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
                })
                .await;
        }
    }

    fn emit_retrying(&self, delay: Duration) {
        if let Some(tx) = self.sink() {
            let _ = tx.try_send(pb::Event {
                kind: pb::EventKind::Retrying as i32,
                until_ms: unix_ms(delay),
            });
        }
    }

    /// Waits while the gate is closed. Returns how long it waited.
    async fn wait_gate(&self, cancel: &Cancel) -> Result<Duration, DriveError> {
        let began = Instant::now();
        loop {
            let until = self.gate.lock().unwrap_or_else(|e| e.into_inner()).until;
            match until {
                Some(t) if t > Instant::now() => {
                    cancel.guard(tokio::time::sleep_until(t.into())).await?;
                }
                _ => return Ok(began.elapsed()),
            }
        }
    }

    /// A request met `dailyLimitExceeded` in an attempt that began at `attempt_started`.
    async fn on_daily_limit(&self, attempt_started: Instant) -> Result<(), DriveError> {
        let until = {
            let mut g = self.gate.lock().unwrap_or_else(|e| e.into_inner());
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
                return Err(DriveError::new(EC::DailyLimit));
            }
            g.pauses += 1;
            g.until = Some(now + self.timing.daily_pause);
            g.set_at = Some(now);
            g.resume_pending = true;
            self.timing.daily_pause
        };
        self.emit(pb::EventKind::PausedDailyLimit, unix_ms(until))
            .await;
        Ok(())
    }

    async fn note_success(&self) {
        let resume = {
            let mut g = self.gate.lock().unwrap_or_else(|e| e.into_inner());
            let open = g.until.is_none_or(|u| u <= Instant::now());
            if g.resume_pending && open {
                g.resume_pending = false;
                true
            } else {
                false
            }
        };
        if resume {
            self.emit(pb::EventKind::Resumed, 0).await;
        }
    }

    /// Runs `f` with retries. `bytes` is the size of the object the attempt moves (0 for none):
    /// it sets the per-attempt timeout. `f` is called again for each attempt and must be safe to
    /// repeat (every operation of the helper is: content is addressed, a write overwrites).
    ///
    /// # Errors
    /// The [`DriveError`] of the last attempt, or `CANCELLED`.
    pub async fn run<T, F, Fut>(
        &self,
        cancel: &Cancel,
        bytes: u64,
        what: &'static str,
        mut f: F,
    ) -> Result<T, DriveError>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = opendal::Result<T>>,
    {
        let started = Instant::now();
        let mut gate_time = Duration::ZERO;
        let mut retries = 0u32;
        loop {
            gate_time += self.wait_gate(cancel).await?;
            if cancel.is_cancelled() {
                return Err(DriveError::new(EC::Cancelled));
            }
            let attempt_started = Instant::now();
            let slot: Slot = Arc::new(Mutex::new(None));
            let attempt = ATTEMPT.scope(slot.clone(), f());
            let timed = tokio::time::timeout(self.timing.attempt_timeout(bytes), attempt);
            let result = cancel.guard(timed).await?;
            let outcome = match result {
                Ok(Ok(v)) => {
                    self.note_success().await;
                    return Ok(v);
                }
                Ok(Err(e)) => {
                    let obs = slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                    let o = classify(obs.as_ref(), &e);
                    tracing::debug!(what, status = obs.as_ref().map_or(0, |o| o.status), reason = obs.as_ref().map_or("", |o| o.reason.as_str()), outcome = ?o, "drive attempt failed");
                    o
                }
                Err(_elapsed) => {
                    tracing::debug!(what, "drive attempt timed out");
                    Outcome::Transient { retry_after: None }
                }
            };
            let (class, hint) = match outcome {
                Outcome::Fatal(c) => return Err(DriveError::new(c)),
                Outcome::DailyLimit => {
                    self.on_daily_limit(attempt_started).await?;
                    // The next iteration waits at the gate shared with every other request.
                    continue;
                }
                Outcome::Transient { retry_after } => (EC::Transient, retry_after),
                Outcome::RateLimited { retry_after } => (EC::RateLimited, retry_after),
            };
            retries += 1;
            let spent = started.elapsed().saturating_sub(gate_time);
            let mut delay = self.timing.delay(retries, (self.rng)());
            if let Some(ra) = hint {
                delay = delay.max(ra);
            }
            if retries > self.timing.max_retries || spent + delay > self.timing.request_budget {
                tracing::warn!(what, retries, class = ?class, "drive request given up");
                return Err(DriveError::with_hint(class, hint.or(Some(delay))));
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
        assert_eq!(c(obs(401, "")), Outcome::Fatal(EC::AuthRevoked));
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
        assert_eq!(t.attempt_timeout(0), Duration::from_secs(60));
        assert_eq!(t.attempt_timeout(1), Duration::from_secs(64));
        assert_eq!(
            t.attempt_timeout(96 << 20),
            Duration::from_secs(60 + 4 * 96)
        );
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
            (obs(401, ""), EC::AuthRevoked),
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
}
