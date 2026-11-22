//! Counters shared by the decode thread, the session (ClientStats) and the stats overlay.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};

/// Decode and path counters. Cheap to update from any thread.
#[derive(Default)]
pub struct Stats {
    decoded: AtomicU32,
    dropped: AtomicU32,
    presented: AtomicU32,
    decode_us: Mutex<Vec<u32>>,
    /// Last round-trip time in microseconds.
    pub rtt_us: AtomicU32,
    /// Bytes of video received since the last interval.
    bytes: AtomicU64,
}

/// One interval's numbers, as `ClientStats` carries them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Interval {
    /// Frames decoded.
    pub decoded: u32,
    /// Frames dropped (stale, undecodable, or queue full).
    pub dropped: u32,
    /// Frames shown.
    pub presented: u32,
    /// 95th percentile decode time in microseconds.
    pub decode_p95_us: u32,
    /// Video bytes received.
    pub bytes: u64,
}

impl Stats {
    /// A frame was decoded in `micros`.
    pub fn decoded(&self, micros: u32) {
        self.decoded.fetch_add(1, Relaxed);
        if let Ok(mut v) = self.decode_us.lock()
            && v.len() < 4096
        {
            v.push(micros);
        }
    }
    /// A frame was dropped.
    pub fn dropped(&self) {
        self.dropped.fetch_add(1, Relaxed);
    }
    /// A frame reached the screen.
    pub fn presented(&self) {
        self.presented.fetch_add(1, Relaxed);
    }
    /// Video bytes arrived.
    pub fn add_bytes(&self, n: u64) {
        self.bytes.fetch_add(n, Relaxed);
    }
    /// Reads and resets the interval counters.
    pub fn take_interval(&self) -> Interval {
        let mut v = self
            .decode_us
            .lock()
            .map(|mut g| std::mem::take(&mut *g))
            .unwrap_or_default();
        v.sort_unstable();
        let p95 = if v.is_empty() {
            0
        } else {
            v[((v.len() * 95).div_ceil(100)).saturating_sub(1).min(v.len() - 1)]
        };
        Interval {
            decoded: self.decoded.swap(0, Relaxed),
            dropped: self.dropped.swap(0, Relaxed),
            presented: self.presented.swap(0, Relaxed),
            decode_p95_us: p95,
            bytes: self.bytes.swap(0, Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_resets_and_computes_p95() {
        let s = Stats::default();
        for i in 1..=100 {
            s.decoded(i * 10);
        }
        s.dropped();
        s.add_bytes(1000);
        let a = s.take_interval();
        assert_eq!(a.decoded, 100);
        assert_eq!(a.dropped, 1);
        assert_eq!(a.decode_p95_us, 950);
        assert_eq!(a.bytes, 1000);
        assert_eq!(s.take_interval(), Interval::default());
    }
}
