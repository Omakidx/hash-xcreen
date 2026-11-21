//! Takeover policy and rate limit (`docs/ipc.md` section 18, protocol 5.7).
//!
//! v1 has one active client per desktop. A second client that asks to view while another is
//! active **takes over**, subject to the server's policy and a limit of 3 takeovers per
//! 10 minutes per desktop (so two devices cannot fight, and a stolen device cannot keep kicking
//! the owner off). This module is the pure decision; the sequence that carries it out is in
//! [`super::session`].

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hx_crypto::Clock;
use serde::Deserialize;

/// What happens when a second client wants the desktop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TakeoverPolicy {
    /// The newcomer displaces the active client (default: a user switching devices must not be
    /// locked out by their own stale session).
    #[default]
    Allow,
    /// The newcomer is answered `BUSY`.
    Deny,
}

/// Takeovers allowed per window.
pub const MAX_TAKEOVERS: usize = 3;
/// The rate-limit window.
pub const WINDOW: Duration = Duration::from_secs(10 * 60);

/// Why a newcomer is not allowed to take over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The policy is `deny`.
    Denied,
    /// More than [`MAX_TAKEOVERS`] in [`WINDOW`].
    RateLimited,
}

/// Sliding-window limiter for one desktop.
pub struct TakeoverLimiter {
    policy: TakeoverPolicy,
    clock: Arc<dyn Clock>,
    taken: Mutex<VecDeque<std::time::Instant>>,
}

impl TakeoverLimiter {
    /// A limiter with no takeovers recorded.
    pub fn new(policy: TakeoverPolicy, clock: Arc<dyn Clock>) -> Self {
        Self {
            policy,
            clock,
            taken: Mutex::new(VecDeque::new()),
        }
    }

    /// The configured policy.
    pub fn policy(&self) -> TakeoverPolicy {
        self.policy
    }

    /// Decides whether a takeover may happen now and, if so, **records** it. A refusal records
    /// nothing, so a refused newcomer does not extend the limit against itself.
    pub fn permit(&self) -> Result<(), Refusal> {
        if self.policy == TakeoverPolicy::Deny {
            return Err(Refusal::Denied);
        }
        let now = self.clock.now();
        let mut taken = self.taken.lock().unwrap_or_else(|p| p.into_inner());
        while taken
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= WINDOW)
        {
            taken.pop_front();
        }
        if taken.len() >= MAX_TAKEOVERS {
            return Err(Refusal::RateLimited);
        }
        taken.push_back(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hx_crypto::ManualClock;

    #[test]
    fn three_per_ten_minutes_then_the_window_slides() {
        let clock = Arc::new(ManualClock::new());
        let l = TakeoverLimiter::new(TakeoverPolicy::Allow, clock.clone());
        for _ in 0..3 {
            assert_eq!(l.permit(), Ok(()));
            clock.advance(Duration::from_secs(60));
        }
        assert_eq!(l.permit(), Err(Refusal::RateLimited));
        // A refusal does not extend the window against the newcomer.
        clock.advance(Duration::from_secs(60 * 7 - 1));
        assert_eq!(l.permit(), Err(Refusal::RateLimited), "first is 599 s old");
        clock.advance(Duration::from_secs(1));
        assert_eq!(l.permit(), Ok(()), "the first one aged out");
        assert_eq!(l.permit(), Err(Refusal::RateLimited), "the second is 540 s old");
    }

    #[test]
    fn deny_never_permits_and_records_nothing() {
        let l = TakeoverLimiter::new(TakeoverPolicy::Deny, Arc::new(ManualClock::new()));
        for _ in 0..10 {
            assert_eq!(l.permit(), Err(Refusal::Denied));
        }
    }
}
