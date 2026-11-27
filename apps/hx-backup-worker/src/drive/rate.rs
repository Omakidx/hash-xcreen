//! The upload-rate cap (ipc.md §29 g): one bucket shared by every upload of a session.
//!
//! Virtual scheduling: each chunk reserves the time its bytes take at the current rate, and a
//! chunk is released at the later of "now" and the end of the previous reservation. There is no
//! initial burst, so `n` bytes need at least `(n - first chunk) / rate`. A rate of 0 is unlimited.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Largest piece of an upload body released at once.
pub const CHUNK: usize = 64 * 1024;

/// The shared bucket.
#[derive(Debug)]
pub struct UploadRate {
    bytes_per_s: AtomicU64,
    next_free: Mutex<Instant>,
}

impl Default for UploadRate {
    fn default() -> Self {
        Self::new()
    }
}

impl UploadRate {
    /// Unlimited.
    #[must_use]
    pub fn new() -> Self {
        Self {
            bytes_per_s: AtomicU64::new(0),
            next_free: Mutex::new(Instant::now()),
        }
    }

    /// `SetUploadRate`: the rate for chunks not yet released; 0 is unlimited.
    pub fn set(&self, bytes_per_s: u64) {
        self.bytes_per_s.store(bytes_per_s, Ordering::Relaxed);
        if bytes_per_s == 0 {
            *self.next_free.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
        }
    }

    /// The current rate.
    #[must_use]
    pub fn get(&self) -> u64 {
        self.bytes_per_s.load(Ordering::Relaxed)
    }

    /// Reserves `len` bytes and returns how long to wait before writing them.
    #[must_use]
    pub fn reserve(&self, len: usize) -> Duration {
        let rate = self.get();
        if rate == 0 {
            return Duration::ZERO;
        }
        let now = Instant::now();
        let mut next = self.next_free.lock().unwrap_or_else(|e| e.into_inner());
        let start = (*next).max(now);
        *next = start + Duration::from_secs_f64(len as f64 / rate as f64);
        start - now
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlimited_never_waits() {
        let r = UploadRate::new();
        for _ in 0..100 {
            assert_eq!(r.reserve(CHUNK), Duration::ZERO);
        }
    }

    #[test]
    fn a_limited_rate_spaces_chunks_by_their_transfer_time() {
        let r = UploadRate::new();
        r.set(CHUNK as u64 * 10); // 10 chunks a second
        assert_eq!(r.reserve(CHUNK), Duration::ZERO);
        let second = r.reserve(CHUNK);
        let third = r.reserve(CHUNK);
        assert!(second > Duration::from_millis(80) && second <= Duration::from_millis(100));
        assert!(third > Duration::from_millis(180) && third <= Duration::from_millis(200));
    }

    #[test]
    fn setting_zero_releases_everything_at_once() {
        let r = UploadRate::new();
        r.set(1000);
        let _ = r.reserve(CHUNK);
        assert!(r.reserve(CHUNK) > Duration::from_secs(10));
        r.set(0);
        assert_eq!(r.reserve(CHUNK), Duration::ZERO);
        r.set(CHUNK as u64);
        assert_eq!(r.reserve(CHUNK), Duration::ZERO, "no debt is carried over");
    }
}
