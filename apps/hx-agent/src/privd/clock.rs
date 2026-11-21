//! Wall-clock access, injectable so that windows, caps and deadlines are testable.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A source of Unix time.
pub trait Clock: Send + Sync {
    /// Milliseconds since the Unix epoch.
    fn unix_ms(&self) -> u64;

    /// Seconds since the Unix epoch.
    fn unix_secs(&self) -> u64 {
        self.unix_ms() / 1000
    }
}

/// The system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

/// A clock that only moves when told to (tests).
#[derive(Debug)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    /// Starts at `unix_secs`.
    pub fn new(unix_secs: u64) -> Self {
        Self(AtomicU64::new(unix_secs * 1000))
    }

    /// Moves forward.
    pub fn advance_secs(&self, secs: u64) {
        self.0.fetch_add(secs * 1000, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn unix_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
