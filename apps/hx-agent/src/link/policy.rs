//! What the gateway does after a link ends or fails to start (`docs/ipc.md` sections 18 and
//! 19.2): the reconnect policy, the 30 s keep after the last client, and [`LinkKeeper`], which
//! ties them to [`LinkClient::connect`].
//!
//! The policy is a pure state machine on an injected clock ([`ReconnectPolicy`]); the gateway
//! core owns the `hx-privd` calls it advises (`RestartSession`, `InstallSession`).

use super::client::{LinkClient, LinkEvents};
use super::config::LinkConfig;
use super::shared::lock;
use super::types::{ConnectError, FailureClass, LinkClosed};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// First redial delay; doubles up to [`BACKOFF_MAX`].
pub const BACKOFF_MIN: Duration = Duration::from_secs(1);
/// Longest redial delay.
pub const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// `InstallSession` requests within [`RESTART_WINDOW`] after which the desktop is reported
/// unavailable, like restarts (review L2: a hostile session answering with another major could
/// otherwise have the gateway ask for an install for ever).
pub const INSTALLS_BEFORE_UNAVAILABLE: usize = 3;
/// Consecutive "the session closed right after the preamble" failures, on a desktop whose
/// session has worked before, that are taken for an outdated in-container binary.
pub const OUTDATED_GUESS_AFTER: u32 = 3;
/// Faults within [`FAULT_WINDOW`] that trigger a `RestartSession`.
pub const FAULTS_BEFORE_RESTART: usize = 5;
/// The window the faults are counted in.
pub const FAULT_WINDOW: Duration = Duration::from_secs(10 * 60);
/// Restarts within [`RESTART_WINDOW`] after which the desktop is reported unavailable.
pub const RESTARTS_BEFORE_UNAVAILABLE: usize = 3;
/// The window the restarts are counted in.
pub const RESTART_WINDOW: Duration = Duration::from_secs(60 * 60);
/// While unavailable the gateway retries once per this long.
pub const UNAVAILABLE_RETRY: Duration = Duration::from_secs(10 * 60);
/// The link is kept this long after the last client leaves, so a reconnect is instant.
pub const IDLE_KEEP: Duration = Duration::from_secs(30);

/// What status shows for the desktop's session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopState {
    /// Dialling works, or has not failed repeatedly.
    Available,
    /// Three `RestartSession` calls within an hour did not help (a bad session package or
    /// malware, the user's call): the gateway dials once every 10 minutes.
    SessionUnavailable,
}

/// What the gateway should do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Advice {
    /// Wait this long before dialling again (zero: no redial is needed, the close was on
    /// purpose).
    pub redial_after: Duration,
    /// Ask privd for `RestartSession` (class A, which privd rate limits itself).
    pub ask_restart: bool,
    /// Ask privd for `InstallSession`: the in-container binary is outdated or incompatible.
    pub ask_install: bool,
    /// The desktop state after this failure.
    pub state: DesktopState,
}

/// The redial policy of section 19.2 as a state machine.
///
/// * Backoff 1, 2, 4, ... up to 30 s after every failure; a clean handshake resets it.
/// * Violations and faults count; 5 within 10 minutes ask for `RestartSession`.
/// * After 3 restarts in an hour the desktop is `SessionUnavailable`: one dial per 10 minutes.
/// * `Unavailable` (refused, reset, silent) is not a fault of the session: backoff only.
/// * `Outdated` and `Incompatible` ask for `InstallSession`.
/// * `session_restarted` (privd restarted the desktop or updated the package) clears the
///   unavailable state and allows an immediate dial.
#[derive(Debug)]
pub struct ReconnectPolicy {
    backoff: Duration,
    faults: VecDeque<Instant>,
    restarts: VecDeque<Instant>,
    installs: VecDeque<Instant>,
    /// A handshake has succeeded at least once (the session worked before).
    connected_before: bool,
    closed_after_preamble: u32,
    state: DesktopState,
    next_dial: Option<Instant>,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl ReconnectPolicy {
    /// A fresh policy: available, no history.
    pub fn new() -> Self {
        Self {
            backoff: BACKOFF_MIN,
            faults: VecDeque::new(),
            restarts: VecDeque::new(),
            installs: VecDeque::new(),
            connected_before: false,
            closed_after_preamble: 0,
            state: DesktopState::Available,
            next_dial: None,
        }
    }

    /// The current state.
    pub fn state(&self) -> DesktopState {
        self.state
    }

    /// How long to wait before dialling at `now`; `None` means dial now.
    pub fn dial_wait(&self, now: Instant) -> Option<Duration> {
        self.next_dial
            .map(|t| t.saturating_duration_since(now))
            .filter(|d| !d.is_zero())
    }

    /// A clean handshake: the backoff and the unavailable state are cleared.
    pub fn on_connected(&mut self) {
        self.connected_before = true;
        self.closed_after_preamble = 0;
        self.backoff = BACKOFF_MIN;
        self.state = DesktopState::Available;
        self.next_dial = None;
    }

    /// privd restarted the desktop or the session package was updated: dial at once.
    pub fn on_session_restarted(&mut self) {
        self.backoff = BACKOFF_MIN;
        self.state = DesktopState::Available;
        self.next_dial = None;
        self.faults.clear();
    }

    /// A link ended or a dial failed with `class` at `now`.
    pub fn on_failure(&mut self, now: Instant, class: FailureClass) -> Advice {
        self.on_failure_detail(now, class, false)
    }

    /// As [`on_failure`](Self::on_failure), for a dial failure that says whether the session
    /// closed the connection right after the preamble
    /// ([`ConnectError::closed_after_preamble`]).
    ///
    /// An honest session of another major version closes without answering (ipc.md 12.2), which
    /// looks exactly like `Unavailable`. When the session has worked before and
    /// [`OUTDATED_GUESS_AFTER`] dials in a row end that way, it is taken for `Outdated`: the
    /// install is requested (rate limited like restarts).
    pub fn on_failure_detail(
        &mut self,
        now: Instant,
        class: FailureClass,
        closed_after_preamble: bool,
    ) -> Advice {
        let mut class = class;
        if class == FailureClass::Unavailable && closed_after_preamble && self.connected_before {
            self.closed_after_preamble += 1;
            if self.closed_after_preamble >= OUTDATED_GUESS_AFTER {
                self.closed_after_preamble = 0;
                class = FailureClass::Outdated;
            }
        } else if class != FailureClass::Closed {
            self.closed_after_preamble = 0;
        }
        if class == FailureClass::Closed {
            return Advice {
                redial_after: Duration::ZERO,
                ask_restart: false,
                ask_install: false,
                state: self.state,
            };
        }
        let mut ask_restart = false;
        if class.is_fault() {
            self.faults
                .retain(|t| now.saturating_duration_since(*t) < FAULT_WINDOW);
            self.faults.push_back(now);
            if self.faults.len() >= FAULTS_BEFORE_RESTART {
                self.faults.clear();
                self.restarts
                    .retain(|t| now.saturating_duration_since(*t) < RESTART_WINDOW);
                if self.restarts.len() >= RESTARTS_BEFORE_UNAVAILABLE {
                    self.state = DesktopState::SessionUnavailable;
                } else {
                    self.restarts.push_back(now);
                    ask_restart = true;
                }
            }
        }
        // Installs are rate limited like restarts: repetition ends in session_unavailable.
        let mut ask_install = false;
        if matches!(class, FailureClass::Outdated | FailureClass::Incompatible) {
            self.installs
                .retain(|t| now.saturating_duration_since(*t) < RESTART_WINDOW);
            if self.installs.len() >= INSTALLS_BEFORE_UNAVAILABLE {
                self.state = DesktopState::SessionUnavailable;
            } else {
                self.installs.push_back(now);
                ask_install = true;
            }
        }
        let redial_after = if self.state == DesktopState::SessionUnavailable {
            UNAVAILABLE_RETRY
        } else {
            let d = self.backoff;
            self.backoff = (self.backoff * 2).min(BACKOFF_MAX);
            d
        };
        self.next_dial = Some(now + redial_after);
        Advice {
            redial_after,
            ask_restart,
            ask_install,
            state: self.state,
        }
    }
}

struct Inner {
    policy: ReconnectPolicy,
    clients: usize,
    link: Option<LinkClient>,
    idle_gen: u64,
}

/// A link to one desktop, dialled on demand, kept 30 s after the last client and redialled
/// under the [`ReconnectPolicy`].
///
/// The gateway core calls [`attach`](LinkKeeper::attach) when a client is authorized and
/// [`detach`](LinkKeeper::detach) when it leaves (after sending `stop`), and reports every
/// [`LinkEvent::Closed`](super::LinkEvent::Closed) it sees to [`on_closed`](LinkKeeper::on_closed).
pub struct LinkKeeper {
    socket: PathBuf,
    cfg: LinkConfig,
    idle_keep: Duration,
    inner: Mutex<Inner>,
    dial: tokio::sync::Mutex<()>,
}

/// A successful [`LinkKeeper::attach`].
pub struct Attached {
    /// The command handle (a clone of the shared one).
    pub client: LinkClient,
    /// The event stream, present only when this attach dialled a new link: the core keeps it
    /// for the life of the link and demultiplexes it to the active client.
    pub events: Option<LinkEvents>,
}

/// Why [`LinkKeeper::attach`] did not produce a link.
#[derive(Debug)]
pub enum DialError {
    /// The policy says to wait; tell the client the desktop is starting.
    Wait(Duration),
    /// Dialling failed; the advice says what to do next.
    Failed {
        /// The classified error.
        error: ConnectError,
        /// What the policy advises.
        advice: Advice,
    },
}

impl LinkKeeper {
    /// A link to the host socket `socket` with the default 30 s keep.
    pub fn new(socket: impl Into<PathBuf>, cfg: LinkConfig) -> Arc<Self> {
        Self::with_idle_keep(socket, cfg, IDLE_KEEP)
    }

    /// As [`new`](Self::new) with another keep time (tests).
    pub fn with_idle_keep(
        socket: impl Into<PathBuf>,
        cfg: LinkConfig,
        idle_keep: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            socket: socket.into(),
            cfg,
            idle_keep,
            inner: Mutex::new(Inner {
                policy: ReconnectPolicy::new(),
                clients: 0,
                link: None,
                idle_gen: 0,
            }),
            dial: tokio::sync::Mutex::new(()),
        })
    }

    /// The desktop state for status.
    pub fn state(&self) -> DesktopState {
        lock(&self.inner).policy.state()
    }

    /// True while a live link exists.
    pub fn is_up(&self) -> bool {
        lock(&self.inner)
            .link
            .as_ref()
            .is_some_and(|l| !l.is_closed())
    }

    /// privd restarted the desktop or the session package changed: allow an immediate dial.
    pub fn session_restarted(&self) {
        lock(&self.inner).policy.on_session_restarted();
    }

    fn live(&self) -> Option<LinkClient> {
        let mut i = lock(&self.inner);
        match &i.link {
            Some(l) if !l.is_closed() => {
                let l = l.clone();
                i.clients += 1;
                i.idle_gen += 1;
                Some(l)
            }
            _ => None,
        }
    }

    /// A client needs the link: reuses the live one or dials a new one.
    pub async fn attach(self: &Arc<Self>) -> Result<Attached, DialError> {
        if let Some(client) = self.live() {
            return Ok(Attached {
                client,
                events: None,
            });
        }
        if let Some(w) = lock(&self.inner).policy.dial_wait(Instant::now()) {
            return Err(DialError::Wait(w));
        }
        let _one_dial = self.dial.lock().await;
        // Another attach may have dialled while this one waited for the dial lock.
        if let Some(client) = self.live() {
            return Ok(Attached {
                client,
                events: None,
            });
        }
        match LinkClient::connect(&self.socket, self.cfg.clone()).await {
            Ok((client, events)) => {
                let mut i = lock(&self.inner);
                i.policy.on_connected();
                i.link = Some(client.clone());
                i.clients += 1;
                i.idle_gen += 1;
                Ok(Attached {
                    client,
                    events: Some(events),
                })
            }
            Err(error) => {
                let advice = lock(&self.inner).policy.on_failure_detail(
                    Instant::now(),
                    error.class,
                    error.closed_after_preamble,
                );
                Err(DialError::Failed { error, advice })
            }
        }
    }

    /// A client of `link` left. When none remain the link is closed after the keep time unless
    /// another client attaches first. The core sends `stop` itself before calling this.
    ///
    /// A call for a link that is no longer the current one (it ended, or the keep timer closed
    /// it and a newer one was dialled) changes nothing: a stale handle must never lower the
    /// client count of the live link.
    pub fn detach(self: &Arc<Self>, link: &LinkClient) {
        let generation = {
            let mut i = lock(&self.inner);
            if !i.link.as_ref().is_some_and(|l| l.same_link(link)) {
                return;
            }
            i.clients = i.clients.saturating_sub(1);
            if i.clients > 0 {
                return;
            }
            i.idle_gen += 1;
            i.idle_gen
        };
        let me = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(me.idle_keep).await;
            let link = {
                let mut i = lock(&me.inner);
                if i.idle_gen == generation && i.clients == 0 {
                    i.link.take()
                } else {
                    None
                }
            };
            if let Some(l) = link {
                l.close();
            }
        });
    }

    /// The core saw `link` end: forget it (if it is still the current one) and learn from the
    /// way it ended. An owner's own close ([`FailureClass::Closed`], the keep timer) changes
    /// nothing and needs no redial.
    pub fn on_closed(&self, link: &LinkClient, closed: &LinkClosed) -> Advice {
        let mut i = lock(&self.inner);
        if i.link.as_ref().is_some_and(|l| l.same_link(link)) {
            i.link = None;
            i.clients = 0;
        }
        i.policy.on_failure(Instant::now(), closed.class)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(base: Instant, s: u64) -> Instant {
        base + Duration::from_secs(s)
    }

    #[test]
    fn backoff_doubles_to_30_s_and_a_clean_handshake_resets_it() {
        let t0 = Instant::now();
        let mut p = ReconnectPolicy::new();
        let waits: Vec<_> = (0..7)
            .map(|i| {
                p.on_failure(secs(t0, i), FailureClass::Unavailable)
                    .redial_after
                    .as_secs()
            })
            .collect();
        assert_eq!(waits, [1, 2, 4, 8, 16, 30, 30]);
        // Not a fault: no restart, still available.
        assert_eq!(p.state(), DesktopState::Available);
        assert!(p.dial_wait(secs(t0, 6)).is_some());
        assert!(p.dial_wait(secs(t0, 40)).is_none());
        p.on_connected();
        assert_eq!(
            p.on_failure(secs(t0, 100), FailureClass::Unavailable)
                .redial_after,
            Duration::from_secs(1)
        );
    }

    #[test]
    fn five_faults_in_ten_minutes_ask_for_a_restart_and_three_restarts_give_up() {
        let t0 = Instant::now();
        let mut p = ReconnectPolicy::new();
        let mut asked = 0;
        // Each round: 5 faults in a minute.
        for round in 0..3u64 {
            for i in 0..5u64 {
                let a = p.on_failure(secs(t0, round * 100 + i), FailureClass::Violation);
                if i < 4 {
                    assert!(!a.ask_restart);
                } else {
                    assert!(a.ask_restart, "round {round}");
                    asked += 1;
                }
            }
        }
        assert_eq!(asked, 3);
        // The fourth round within the hour: no more restarts, the desktop is unavailable.
        let mut last = None;
        for i in 0..5u64 {
            last = Some(p.on_failure(secs(t0, 400 + i), FailureClass::Fault));
        }
        let a = last.unwrap();
        assert!(!a.ask_restart);
        assert_eq!(a.state, DesktopState::SessionUnavailable);
        assert_eq!(a.redial_after, UNAVAILABLE_RETRY);
        assert_eq!(p.state(), DesktopState::SessionUnavailable);
        // A way back without an operator: privd reports a restart, or a clean handshake.
        p.on_session_restarted();
        assert_eq!(p.state(), DesktopState::Available);
        assert!(p.dial_wait(secs(t0, 410)).is_none());
    }

    #[test]
    fn faults_outside_the_window_do_not_add_up_and_unavailable_is_not_a_fault() {
        let t0 = Instant::now();
        let mut p = ReconnectPolicy::new();
        for i in 0..4u64 {
            assert!(
                !p.on_failure(secs(t0, i * 200), FailureClass::Fault)
                    .ask_restart
            );
        }
        // Many `Unavailable` never ask for a restart.
        for i in 0..20u64 {
            assert!(
                !p.on_failure(secs(t0, 1_000 + i), FailureClass::Unavailable)
                    .ask_restart
            );
        }
    }

    #[test]
    fn repeated_session_goodbyes_back_off_and_end_in_unavailable() {
        // Review M4: a goodbye used to be `Closed`, which has no backoff and no fault, so a
        // hostile session could force unthrottled redials.
        let t0 = Instant::now();
        let mut p = ReconnectPolicy::new();
        let waits: Vec<_> = (0..4)
            .map(|i| {
                p.on_failure(secs(t0, i), FailureClass::SessionGoodbye)
                    .redial_after
                    .as_secs()
            })
            .collect();
        assert_eq!(waits, [1, 2, 4, 8]);
        // The fifth within ten minutes asks for a restart, like any fault; three such rounds
        // make the desktop unavailable.
        assert!(
            p.on_failure(secs(t0, 4), FailureClass::SessionGoodbye)
                .ask_restart
        );
        for round in 1..3u64 {
            for i in 0..5 {
                p.on_failure(secs(t0, round * 100 + i), FailureClass::SessionGoodbye);
            }
        }
        let mut last = None;
        for i in 0..5 {
            last = Some(p.on_failure(secs(t0, 400 + i), FailureClass::SessionGoodbye));
        }
        assert_eq!(last.unwrap().state, DesktopState::SessionUnavailable);
        assert!(FailureClass::SessionGoodbye.is_fault());
        assert!(!FailureClass::Closed.is_fault());
    }

    #[test]
    fn an_honest_older_session_is_guessed_outdated_after_repeated_silent_closes() {
        // Review L2, case 1: an older session closes without answering, which looks like
        // `Unavailable`. Only on a desktop whose session worked before, and only when the close
        // came right after the preamble (not a refusal or a timeout).
        let t0 = Instant::now();
        let mut p = ReconnectPolicy::new();
        for i in 0..6 {
            // Never connected: the proxy may simply be down. No install, whatever the shape.
            let a = p.on_failure_detail(secs(t0, i), FailureClass::Unavailable, true);
            assert!(!a.ask_install);
        }
        p.on_connected();
        for i in 0..5 {
            // Refusals and timeouts reset the count: still no install.
            assert!(
                !p.on_failure_detail(secs(t0, 10 + i), FailureClass::Unavailable, false)
                    .ask_install
            );
        }
        let asks: Vec<_> = (0..3)
            .map(|i| {
                p.on_failure_detail(secs(t0, 20 + i), FailureClass::Unavailable, true)
                    .ask_install
            })
            .collect();
        assert_eq!(asks, [false, false, true]);
        // An interleaved refusal starts the count again.
        p.on_failure_detail(secs(t0, 30), FailureClass::Unavailable, true);
        p.on_failure_detail(secs(t0, 31), FailureClass::Unavailable, false);
        assert!(
            !p.on_failure_detail(secs(t0, 32), FailureClass::Unavailable, true)
                .ask_install
        );
    }

    #[test]
    fn install_requests_are_rate_limited_and_end_in_unavailable() {
        // Review L2, case 2: a hostile session that answers with another major used to get
        // `ask_install` for ever.
        let t0 = Instant::now();
        let mut p = ReconnectPolicy::new();
        let mut asked = 0;
        for i in 0..3 {
            let a = p.on_failure(secs(t0, i * 60), FailureClass::Outdated);
            assert!(a.ask_install, "{i}");
            asked += 1;
        }
        assert_eq!(asked, INSTALLS_BEFORE_UNAVAILABLE);
        let a = p.on_failure(secs(t0, 200), FailureClass::Outdated);
        assert!(!a.ask_install);
        assert_eq!(a.state, DesktopState::SessionUnavailable);
        assert_eq!(a.redial_after, UNAVAILABLE_RETRY);
        // Incompatible shares the same budget; an hour later it may ask again.
        assert!(
            !p.on_failure(secs(t0, 300), FailureClass::Incompatible)
                .ask_install
        );
        p.on_session_restarted();
        assert!(
            p.on_failure(secs(t0, 3_800), FailureClass::Incompatible)
                .ask_install,
            "the window has passed"
        );
    }

    #[test]
    fn outdated_asks_for_an_install_and_a_deliberate_close_needs_no_redial() {
        let t0 = Instant::now();
        let mut p = ReconnectPolicy::new();
        let a = p.on_failure(t0, FailureClass::Outdated);
        assert!(a.ask_install && !a.ask_restart);
        assert!(p.on_failure(t0, FailureClass::Incompatible).ask_install);
        let c = p.on_failure(t0, FailureClass::Closed);
        assert_eq!(c.redial_after, Duration::ZERO);
        assert!(!c.ask_install);
    }
}
