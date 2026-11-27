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

/// The lowest nonzero rate: a smaller one would make one chunk wait for hours (ipc.md §29 g).
pub const MIN_RATE: u64 = 2048;

/// The shared bucket.
#[derive(Debug)]
pub struct UploadRate {
    generation: AtomicU64,
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
            generation: AtomicU64::new(0),
            bytes_per_s: AtomicU64::new(0),
            next_free: Mutex::new(Instant::now()),
        }
    }

    /// `SetUploadRate`: the rate for chunks not yet released; 0 is unlimited.
    ///
    /// A nonzero rate below [`MIN_RATE`] is raised to it. Every change starts the schedule afresh
    /// and bumps [`UploadRate::generation`], so that a chunk that is already waiting works its wait
    /// out again under the new rate.
    pub fn set(&self, bytes_per_s: u64) {
        let rate = if bytes_per_s == 0 {
            0
        } else {
            bytes_per_s.max(MIN_RATE)
        };
        self.bytes_per_s.store(rate, Ordering::Relaxed);
        *self.next_free.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
        self.generation.fetch_add(1, Ordering::Relaxed);
    }

    /// How many times the rate has been set.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
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
    fn a_tiny_rate_is_raised_to_the_minimum_and_every_change_is_counted() {
        let r = UploadRate::new();
        let g = r.generation();
        r.set(1);
        assert_eq!(r.get(), MIN_RATE);
        assert!(r.generation() > g);
        // a 64 KiB chunk at the minimum waits 32 s, not 18 hours
        let _ = r.reserve(CHUNK);
        let wait = r.reserve(CHUNK);
        assert!(wait <= Duration::from_secs(33), "{wait:?}");
        r.set(0);
        assert_eq!(r.get(), 0);
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
