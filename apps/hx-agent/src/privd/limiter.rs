//! Rate limits, the failure caps of `PepperVerify` and the lockout (ipc.md 5.3, 6.15, 8).
//!
//! Two kinds of limit:
//!
//! * **In-memory token windows** (`admit`): per role, command and, where it matters, desktop. They
//!   are sliding windows over the last `window` milliseconds. They are not persisted: a restart
//!   resets them, which is acceptable because none of them guards a guessing attack.
//! * **Persisted security budgets** ([`Persisted`]): `PepperVerify` failures per purpose and the
//!   lock they lead to, `PepperEnrol` calls and current-password checks. They are written on every
//!   change (rarer than once per second by construction: failures are capped, enrolments are
//!   capped), so provoking a restart does not reset them.
//!
//! The decision for the failure caps (decision 1): PIN 10 failures per hour and 50 per day,
//! PASSWORD 5 per hour and 20 per day. Reaching a cap **locks** the purpose until Admin's
//! `ResetLockout`. The failure that reaches the cap is itself answered (`ok: false`); the next call
//! gets `RESOURCE_EXHAUSTED` (`LOCKED`). So an attacker never gets more than `cap` wrong guesses
//! checked.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use hx_ipc::privd::pb::LockoutPurpose;
use serde::{Deserialize, Serialize};

use super::clock::Clock;
use super::state::StateStore;

const HOUR: u64 = 3_600;
const DAY: u64 = 86_400;

/// Failure caps of one purpose: `(per hour, per day)`.
pub fn failure_caps(p: Purpose) -> (usize, usize) {
    match p {
        Purpose::Pin => (10, 50),
        Purpose::Password => (5, 20),
    }
}

/// Gateway's `PepperEnrol` allowance after setup: per day.
pub const ENROL_PER_DAY: usize = 5;
/// Gateway's `PepperEnrol` allowance during `SETUP_OPEN`: per hour.
pub const ENROL_PER_HOUR_IN_SETUP: usize = 60;
/// Current-password checks per day (ipc.md 5.3).
pub const CURRENT_CHECKS_PER_DAY: usize = 20;

/// A verifier purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Purpose {
    /// The PIN verifier.
    Pin,
    /// The Linux-password verifier.
    Password,
}

impl Purpose {
    /// From the wire enum; `None` for an unspecified value.
    pub fn from_pb(p: i32) -> Option<Self> {
        match LockoutPurpose::try_from(p).ok()? {
            LockoutPurpose::Pin => Some(Self::Pin),
            LockoutPurpose::Password => Some(Self::Password),
            LockoutPurpose::Unspecified => None,
        }
    }

    /// The label used for key derivation and the audit log.
    pub fn label(self) -> &'static str {
        match self {
            Self::Pin => "pin",
            Self::Password => "password",
        }
    }
}

/// The security budgets that survive a restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Persisted {
    /// Unix seconds of recent PIN failures (older than a day are dropped).
    #[serde(default)]
    pub pin_failures: Vec<u64>,
    /// Same for the password purpose.
    #[serde(default)]
    pub password_failures: Vec<u64>,
    /// The PIN purpose is locked until `ResetLockout`.
    #[serde(default)]
    pub pin_locked: bool,
    /// The password purpose is locked until `ResetLockout`.
    #[serde(default)]
    pub password_locked: bool,
    /// Unix seconds of Gateway `PepperEnrol` calls.
    #[serde(default)]
    pub enrol: Vec<u64>,
    /// Unix seconds of current-password checks.
    #[serde(default)]
    pub current_checks: Vec<u64>,
}

impl Persisted {
    fn failures(&mut self, p: Purpose) -> &mut Vec<u64> {
        match p {
            Purpose::Pin => &mut self.pin_failures,
            Purpose::Password => &mut self.password_failures,
        }
    }

    fn locked_mut(&mut self, p: Purpose) -> &mut bool {
        match p {
            Purpose::Pin => &mut self.pin_locked,
            Purpose::Password => &mut self.password_locked,
        }
    }
}

fn recent(v: &[u64], now: u64, window: u64) -> usize {
    v.iter()
        .filter(|t| now.saturating_sub(**t) < window)
        .count()
}

/// The security budgets could not be written to disk. privd then **fails closed**: the charge stays
/// in memory, and `PepperVerify`, `PepperEnrol` and the current-password check are refused
/// (`UNAVAILABLE`) until a save succeeds, so a full disk cannot be used to make a restart forget a
/// lockout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unsaved;

/// Why an allowance was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// Over the allowance; milliseconds until a slot frees up.
    Wait(u32),
    /// The budget cannot be persisted ([`Unsaved`]).
    Unsaved,
}

impl From<Unsaved> for Refused {
    fn from(_: Unsaved) -> Self {
        Refused::Unsaved
    }
}

/// Rate limits and security budgets.
pub struct Limiter {
    unsaved: bool,
    clock: Arc<dyn Clock>,
    store: StateStore,
    persisted: Persisted,
    windows: HashMap<String, VecDeque<u64>>,
}

impl Limiter {
    /// Loads the persisted budgets from `ratelimit`.
    pub fn load(clock: Arc<dyn Clock>, store: StateStore) -> std::io::Result<Self> {
        let persisted = store.load_json("ratelimit")?;
        Ok(Self {
            unsaved: false,
            clock,
            store,
            persisted,
            windows: HashMap::new(),
        })
    }

    fn save(&mut self) -> Result<(), Unsaved> {
        match self.store.save_json("ratelimit", &self.persisted) {
            Ok(()) => {
                self.unsaved = false;
                Ok(())
            }
            Err(e) => {
                // The in-memory budget still holds; nothing that depends on it may proceed.
                crate::privd::log::error(&format!("cannot persist the rate-limit state: {e}"));
                self.unsaved = true;
                Err(Unsaved)
            }
        }
    }

    /// Fails while an earlier change could not be written and still cannot be (it retries the
    /// save). Call it before any operation that relies on the persisted budgets.
    pub fn ensure_saved(&mut self) -> Result<(), Unsaved> {
        if self.unsaved { self.save() } else { Ok(()) }
    }

    /// A copy of the persisted budgets (tests, status).
    pub fn persisted(&self) -> &Persisted {
        &self.persisted
    }

    /// Takes one slot of the sliding window `key` (`max` per `window_ms`). `Err` carries the
    /// milliseconds until a slot frees up. A refused call consumes nothing.
    pub fn admit(&mut self, key: &str, window_ms: u64, max: usize) -> Result<(), u32> {
        let now = self.clock.unix_ms();
        let q = self.windows.entry(key.to_string()).or_default();
        while q
            .front()
            .is_some_and(|t| now.saturating_sub(*t) >= window_ms)
        {
            q.pop_front();
        }
        if q.len() >= max {
            let oldest = q.front().copied().unwrap_or(now);
            let wait = (oldest + window_ms).saturating_sub(now).max(1);
            return Err(u32::try_from(wait).unwrap_or(u32::MAX));
        }
        q.push_back(now);
        // Bound the map: a key per desktop id is already bounded by the id syntax and the
        // registry, but never let it grow without limit.
        if self.windows.len() > 1024 {
            self.windows.retain(|_, q| !q.is_empty());
        }
        Ok(())
    }

    /// Whether `p` is locked.
    pub fn is_locked(&self, p: Purpose) -> bool {
        match p {
            Purpose::Pin => self.persisted.pin_locked,
            Purpose::Password => self.persisted.password_locked,
        }
    }

    /// Records one failed verification of `p`. Returns `true` if this failure locked the purpose.
    /// Persisted before it returns.
    pub fn record_failure(&mut self, p: Purpose) -> Result<bool, Unsaved> {
        let now = self.clock.unix_secs();
        let (hour_cap, day_cap) = failure_caps(p);
        let v = self.persisted.failures(p);
        v.retain(|t| now.saturating_sub(*t) < DAY);
        v.push(now);
        let hour = recent(v, now, HOUR);
        let day = v.len();
        let newly = !*self.persisted.locked_mut(p) && (hour >= hour_cap || day >= day_cap);
        if newly {
            *self.persisted.locked_mut(p) = true;
        }
        self.save()?;
        Ok(newly)
    }

    /// Admin's `ResetLockout`: clears the failures and the lock of `p`.
    pub fn reset(&mut self, p: Purpose) -> Result<(), Unsaved> {
        self.persisted.failures(p).clear();
        *self.persisted.locked_mut(p) = false;
        self.save()
    }

    /// The Gateway's `PepperEnrol` allowance: `during_setup` selects 60 per hour, otherwise 5 per
    /// day. `Err` carries the milliseconds until the next slot. Counts and persists on success.
    pub fn admit_enrol(&mut self, during_setup: bool) -> Result<(), Refused> {
        self.ensure_saved()?;
        let now = self.clock.unix_secs();
        self.persisted
            .enrol
            .retain(|t| now.saturating_sub(*t) < DAY);
        let (window, max) = if during_setup {
            (HOUR, ENROL_PER_HOUR_IN_SETUP)
        } else {
            (DAY, ENROL_PER_DAY)
        };
        let used: Vec<u64> = self
            .persisted
            .enrol
            .iter()
            .copied()
            .filter(|t| now.saturating_sub(*t) < window)
            .collect();
        if used.len() >= max {
            let oldest = used.iter().copied().min().unwrap_or(now);
            let wait_s = (oldest + window).saturating_sub(now).max(1);
            return Err(Refused::Wait(
                u32::try_from(wait_s * 1000).unwrap_or(u32::MAX),
            ));
        }
        self.persisted.enrol.push(now);
        self.save()?;
        Ok(())
    }

    /// A current-password check: 20 per day. Counts and persists on success.
    pub fn admit_current_check(&mut self) -> Result<(), Refused> {
        self.ensure_saved()?;
        let now = self.clock.unix_secs();
        self.persisted
            .current_checks
            .retain(|t| now.saturating_sub(*t) < DAY);
        if self.persisted.current_checks.len() >= CURRENT_CHECKS_PER_DAY {
            let oldest = self
                .persisted
                .current_checks
                .iter()
                .copied()
                .min()
                .unwrap_or(now);
            let wait_s = (oldest + DAY).saturating_sub(now).max(1);
            return Err(Refused::Wait(
                u32::try_from(wait_s * 1000).unwrap_or(u32::MAX),
            ));
        }
        self.persisted.current_checks.push(now);
        self.save()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privd::clock::ManualClock;

    fn limiter() -> (Limiter, Arc<ManualClock>, tempfile::TempDir) {
        let d = tempfile::tempdir().unwrap();
        let clock = Arc::new(ManualClock::new(1_800_000_000));
        let store = StateStore::open(&d.path().join("s")).unwrap();
        (Limiter::load(clock.clone(), store).unwrap(), clock, d)
    }

    #[test]
    fn sliding_window_admits_then_refuses_then_recovers() {
        let (mut l, clock, _d) = limiter();
        for _ in 0..3 {
            l.admit("k", 60_000, 3).unwrap();
        }
        let wait = l.admit("k", 60_000, 3).unwrap_err();
        assert!((1..=60_000).contains(&wait));
        // A refusal consumed nothing: after the window the whole allowance is back.
        clock.advance_secs(61);
        for _ in 0..3 {
            l.admit("k", 60_000, 3).unwrap();
        }
        // Other keys are independent.
        l.admit("other", 60_000, 3).unwrap();
    }

    #[test]
    fn pin_locks_at_ten_failures_in_an_hour_and_never_before() {
        let (mut l, _c, _d) = limiter();
        for i in 1..=9 {
            assert!(!l.record_failure(Purpose::Pin).unwrap(), "failure {i}");
            assert!(!l.is_locked(Purpose::Pin));
        }
        assert!(
            l.record_failure(Purpose::Pin).unwrap(),
            "the tenth failure locks"
        );
        assert!(l.is_locked(Purpose::Pin));
        // The other purpose is independent.
        assert!(!l.is_locked(Purpose::Password));
    }

    #[test]
    fn password_locks_at_five_failures_in_an_hour() {
        let (mut l, _c, _d) = limiter();
        for _ in 0..4 {
            assert!(!l.record_failure(Purpose::Password).unwrap());
        }
        assert!(l.record_failure(Purpose::Password).unwrap());
        assert!(l.is_locked(Purpose::Password));
    }

    #[test]
    fn the_daily_cap_counts_failures_spread_over_hours() {
        let (mut l, c, _d) = limiter();
        // Nine failures an hour, five hours: never 10 in one hour, 45 per day, then the 50th
        // (inside 24 hours) locks.
        let mut locked_at = None;
        'outer: for hour in 0..6 {
            for n in 0..9 {
                if l.record_failure(Purpose::Pin).unwrap() {
                    locked_at = Some(hour * 9 + n + 1);
                    break 'outer;
                }
            }
            c.advance_secs(3_700);
        }
        assert_eq!(locked_at, Some(50));
    }

    #[test]
    fn failures_older_than_the_window_do_not_count() {
        let (mut l, c, _d) = limiter();
        for _ in 0..9 {
            l.record_failure(Purpose::Pin).unwrap();
        }
        c.advance_secs(3_601);
        // Nine are older than an hour: one more is the tenth of the day but the first of the hour.
        assert!(!l.record_failure(Purpose::Pin).unwrap());
    }

    #[test]
    fn reset_clears_failures_and_lock() {
        let (mut l, _c, _d) = limiter();
        for _ in 0..5 {
            l.record_failure(Purpose::Password).unwrap();
        }
        assert!(l.is_locked(Purpose::Password));
        l.reset(Purpose::Password).unwrap();
        assert!(!l.is_locked(Purpose::Password));
        assert!(!l.record_failure(Purpose::Password).unwrap());
    }

    #[test]
    fn the_lock_and_the_counts_survive_a_restart() {
        let d = tempfile::tempdir().unwrap();
        let clock = Arc::new(ManualClock::new(1_800_000_000));
        let dir = d.path().join("s");
        {
            let mut l = Limiter::load(clock.clone(), StateStore::open(&dir).unwrap()).unwrap();
            for _ in 0..10 {
                l.record_failure(Purpose::Pin).unwrap();
            }
            for _ in 0..3 {
                l.record_failure(Purpose::Password).unwrap();
            }
            l.admit_enrol(false).unwrap();
        }
        let mut l = Limiter::load(clock, StateStore::open(&dir).unwrap()).unwrap();
        assert!(l.is_locked(Purpose::Pin));
        assert!(!l.is_locked(Purpose::Password));
        // Two more password failures still reach the cap of five: the earlier three were kept.
        assert!(!l.record_failure(Purpose::Password).unwrap());
        assert!(l.record_failure(Purpose::Password).unwrap());
        assert_eq!(l.persisted().enrol.len(), 1);
    }

    #[test]
    fn enrol_allowances() {
        let (mut l, c, _d) = limiter();
        for _ in 0..ENROL_PER_DAY {
            l.admit_enrol(false).unwrap();
        }
        assert!(l.admit_enrol(false).is_err());
        // During setup the allowance is per hour and larger, counted over the same events.
        for _ in ENROL_PER_DAY..ENROL_PER_HOUR_IN_SETUP {
            l.admit_enrol(true).unwrap();
        }
        assert!(l.admit_enrol(true).is_err());
        c.advance_secs(HOUR + 1);
        l.admit_enrol(true).unwrap();
        // After setup the day window still holds all of them.
        assert!(l.admit_enrol(false).is_err());
        c.advance_secs(DAY);
        l.admit_enrol(false).unwrap();
    }

    #[test]
    fn current_password_checks_are_capped_per_day() {
        let (mut l, c, _d) = limiter();
        for _ in 0..CURRENT_CHECKS_PER_DAY {
            l.admit_current_check().unwrap();
        }
        assert!(l.admit_current_check().is_err());
        c.advance_secs(DAY + 1);
        l.admit_current_check().unwrap();
    }
}
