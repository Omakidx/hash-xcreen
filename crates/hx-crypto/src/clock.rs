//! Time source, replaceable in tests so expiry and backoff can be proven without sleeping.

use std::{
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// A monotonic and a wall clock.
pub trait Clock: Send + Sync + 'static {
    /// Monotonic now, for expiry and backoff.
    fn now(&self) -> Instant;
    /// Seconds since the Unix epoch, for stored timestamps.
    fn unix_secs(&self) -> u64;
}

/// The real clocks.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// A clock that only moves when told to.
#[derive(Debug)]
pub struct ManualClock {
    base: Instant,
    offset: Mutex<Duration>,
}

impl ManualClock {
    /// Starts at the current time.
    pub fn new() -> Self {
        Self {
            base: Instant::now(),
            offset: Mutex::new(Duration::ZERO),
        }
    }

    /// Move both clocks forward.
    pub fn advance(&self, by: Duration) {
        if let Ok(mut o) = self.offset.lock() {
            *o += by;
        }
    }

    fn offset(&self) -> Duration {
        self.offset.lock().map(|o| *o).unwrap_or_default()
    }
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Instant {
        self.base + self.offset()
    }

    fn unix_secs(&self) -> u64 {
        SystemClock.unix_secs() + self.offset().as_secs()
    }
}
