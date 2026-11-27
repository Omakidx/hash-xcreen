//! The monotonic clock of the job runner (ipc.md section 32, v0.8: every timer of a job runs on a
//! monotonic clock, so a step of the wall clock changes none of them).
//!
//! [`Monotonic`] is the seam: production uses [`SystemMono`] (`std::time::Instant`), tests use
//! [`ManualMono`], which only moves when told to, so a 45 s silence or a 12 h deadline is a call to
//! `advance`, not a sleep.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Milliseconds on a clock that never goes backwards.
pub trait Monotonic: Send + Sync + 'static {
    /// Milliseconds since an arbitrary, fixed origin.
    fn now_ms(&self) -> u64;
}

/// `Instant` since the clock was made.
#[derive(Debug)]
pub struct SystemMono {
    origin: Instant,
}

impl SystemMono {
    /// A clock whose zero is now.
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemMono {
    fn default() -> Self {
        Self::new()
    }
}

impl Monotonic for SystemMono {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// A clock that only moves when told to (tests). It starts at one hour, so that "time before the
/// start" never underflows.
#[derive(Debug)]
pub struct ManualMono(AtomicU64);

impl ManualMono {
    /// A clock at 3 600 000 ms.
    pub fn new() -> Self {
        Self(AtomicU64::new(3_600_000))
    }

    /// Moves forward.
    pub fn advance_ms(&self, ms: u64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }

    /// Moves forward by seconds.
    pub fn advance_secs(&self, secs: u64) {
        self.advance_ms(secs * 1000);
    }
}

impl Default for ManualMono {
    fn default() -> Self {
        Self::new()
    }
}

impl Monotonic for ManualMono {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_manual_clock_moves_only_when_told() {
        let c = ManualMono::new();
        let a = c.now_ms();
        assert_eq!(c.now_ms(), a);
        c.advance_secs(46);
        assert_eq!(c.now_ms(), a + 46_000);
    }

    #[test]
    fn the_system_clock_does_not_go_backwards() {
        let c = SystemMono::new();
        let a = c.now_ms();
        assert!(c.now_ms() >= a);
    }
}
