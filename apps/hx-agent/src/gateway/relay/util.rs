//! Small helpers of the relay: poison-proof locking, a token bucket and the limiter for the
//! privd actions the reconnect policy advises.

use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Locks `m`, ignoring poisoning (a panicking task must not wedge the relay).
pub(super) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// A token bucket: `rate` events per second with a burst of `burst`.
#[derive(Debug)]
pub(super) struct TokenBucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    pub(super) fn new(rate_per_s: u32, burst: u32) -> Self {
        Self::with_rate(f64::from(rate_per_s), burst)
    }

    /// `rate` events a second (fractions allowed) with a burst of `burst`.
    pub(super) fn with_rate(rate: f64, burst: u32) -> Self {
        Self {
            rate,
            burst: f64::from(burst.max(1)),
            tokens: f64::from(burst.max(1)),
            last: Instant::now(),
        }
    }

    /// Takes one token if there is one.
    pub(super) fn allow(&mut self, now: Instant) -> bool {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.rate).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

impl TokenBucket {
    /// Takes one token even if there is none (the bucket goes into debt) and returns how long
    /// the caller must wait before it may act: zero while the burst lasts, then the time the
    /// debt needs to be paid at the sustained rate. A caller that sleeps for the returned time
    /// never exceeds the rate for longer than the burst; one whose wait grows too long is
    /// sending faster than allowed for good.
    pub(super) fn reserve(&mut self, now: Instant) -> Duration {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.rate).min(self.burst) - 1.0;
        if self.tokens >= 0.0 || self.rate <= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-self.tokens / self.rate)
        }
    }
}

/// Bounds how often the gateway asks privd for something expensive (`RestartSession`,
/// `InstallSession`): at least `min_gap` apart and at most `per_hour` an hour. privd rate limits
/// as well; this keeps a hostile session from making the gateway spend privd's budget (or its own
/// tasks) as fast as it can fail.
#[derive(Debug)]
pub(super) struct ActionLimiter {
    min_gap: Duration,
    per_hour: usize,
    history: VecDeque<Instant>,
}

impl ActionLimiter {
    pub(super) fn new(min_gap: Duration, per_hour: usize) -> Self {
        Self {
            min_gap,
            per_hour,
            history: VecDeque::new(),
        }
    }

    /// True (and recorded) if an action may run now.
    pub(super) fn permit(&mut self, now: Instant) -> bool {
        while self
            .history
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= Duration::from_secs(3600))
        {
            self.history.pop_front();
        }
        if self.history.len() >= self.per_hour {
            return false;
        }
        if self
            .history
            .back()
            .is_some_and(|t| now.saturating_duration_since(*t) < self.min_gap)
        {
            return false;
        }
        self.history.push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_allows_a_burst_then_the_rate() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(10, 5);
        let n = (0..20).filter(|_| b.allow(t0)).count();
        assert_eq!(n, 5);
        assert!(b.allow(t0 + Duration::from_millis(150)));
        assert!(!b.allow(t0 + Duration::from_millis(150)));
    }

    #[test]
    fn reserve_allows_the_burst_then_paces_and_reports_the_lag() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(1_000, 100);
        for _ in 0..100 {
            assert_eq!(b.reserve(t0), Duration::ZERO, "the burst is free");
        }
        let w1 = b.reserve(t0);
        let w2 = b.reserve(t0);
        assert!(w1 > Duration::ZERO && w2 > w1, "debt grows: {w1:?} {w2:?}");
        // 1000 more at once is a second of lag at 1000/s.
        let mut last = Duration::ZERO;
        for _ in 0..1_000 {
            last = b.reserve(t0);
        }
        assert!(last >= Duration::from_millis(990), "{last:?}");
        // Time pays the debt back.
        assert_eq!(b.reserve(t0 + Duration::from_secs(5)), Duration::ZERO);
    }

    #[test]
    fn action_limiter_spaces_and_caps() {
        let t0 = Instant::now();
        let mut l = ActionLimiter::new(Duration::from_secs(60), 3);
        assert!(l.permit(t0));
        assert!(!l.permit(t0 + Duration::from_secs(10)), "too soon");
        assert!(l.permit(t0 + Duration::from_secs(70)));
        assert!(l.permit(t0 + Duration::from_secs(140)));
        assert!(!l.permit(t0 + Duration::from_secs(300)), "three an hour");
        assert!(l.permit(t0 + Duration::from_secs(3_700)), "the hour passed");
    }
}
