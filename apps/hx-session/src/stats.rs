//! Lock-free pipeline statistics: per-stage latency histograms, counters, queue depths and
//! process CPU. Recording is a handful of relaxed atomic operations, so it is safe on the
//! hot path; percentiles are computed only when a snapshot is taken.

use rustix::time::{ClockId, clock_gettime};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

/// Histogram resolution and range: 50 us buckets up to 100 ms, one overflow bucket.
const BUCKET_US: u64 = 50;
const BUCKETS: usize = 2000;

struct Hist {
    buckets: Box<[AtomicU64]>,
    count: AtomicU64,
    max_us: AtomicU64,
}

impl Hist {
    fn new() -> Self {
        Self {
            buckets: (0..=BUCKETS).map(|_| AtomicU64::new(0)).collect(),
            count: AtomicU64::new(0),
            max_us: AtomicU64::new(0),
        }
    }

    fn record_ns(&self, ns: u64) {
        let us = ns / 1000;
        let i = ((us / BUCKET_US) as usize).min(BUCKETS);
        self.buckets[i].fetch_add(1, Relaxed);
        self.count.fetch_add(1, Relaxed);
        self.max_us.fetch_max(us, Relaxed);
    }

    fn snapshot(&self) -> Percentiles {
        let count = self.count.load(Relaxed);
        let max_us = self.max_us.load(Relaxed);
        let at = |q: f64| -> u64 {
            if count == 0 {
                return 0;
            }
            let target = ((count as f64 * q).ceil() as u64).max(1);
            let mut seen = 0;
            for (i, b) in self.buckets.iter().enumerate() {
                seen += b.load(Relaxed);
                if seen >= target {
                    if i == BUCKETS {
                        return max_us; // beyond the histogram range: only the maximum is known
                    }
                    // Upper edge of the bucket, never above the true maximum.
                    return ((i as u64 + 1) * BUCKET_US).min(max_us.max(BUCKET_US));
                }
            }
            max_us
        };
        Percentiles {
            count,
            p50_us: at(0.50),
            p95_us: at(0.95),
            p99_us: at(0.99),
            max_us,
        }
    }
}

/// Latency distribution of one stage, in microseconds (50 us resolution).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Percentiles {
    pub count: u64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub max_us: u64,
}

/// Where per-frame time goes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StageTimings {
    /// Damage arrival to screen read: pacing and buffer waits.
    pub damage_to_capture: Percentiles,
    /// The screen read itself (`grab`).
    pub capture: Percentiles,
    /// BGRX to YUV conversion.
    pub convert: Percentiles,
    /// x264 encode.
    pub encode: Percentiles,
    /// Damage arrival to the encoded frame being ready: the added latency before sending.
    pub total: Percentiles,
}

/// Queue between two stages: how full it got.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct QueueDepth {
    pub capacity: usize,
    pub max: u64,
    pub mean: f64,
}

/// A point-in-time copy of the statistics.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct StatsSnapshot {
    pub elapsed: Duration,
    /// Screen reads.
    pub captures: u64,
    /// Encoded frames produced.
    pub frames: u64,
    pub keyframes: u64,
    pub idr_frames: u64,
    /// Encoded bytes produced.
    pub bytes: u64,
    pub max_frame_bytes: u64,
    /// Capture attempts that found no free buffer (a stage downstream was behind).
    pub capture_buffer_waits: u64,
    /// Recoverable errors (a failed conversion or encode, a refused resize).
    pub errors: u64,
    pub stages: StageTimings,
    /// capture -> convert, convert -> encode, encode -> output.
    pub queues: [QueueDepth; 3],
    /// Process CPU time (all threads) since the pipeline started.
    pub cpu: Duration,
}

impl StatsSnapshot {
    /// Average encoded bitrate over the run, in kbit/s.
    pub fn bitrate_kbps(&self) -> f64 {
        let s = self.elapsed.as_secs_f64();
        if s > 0.0 {
            self.bytes as f64 * 8.0 / 1000.0 / s
        } else {
            0.0
        }
    }

    /// Average CPU use in cores over the run.
    pub fn cpu_cores(&self) -> f64 {
        let s = self.elapsed.as_secs_f64();
        if s > 0.0 {
            self.cpu.as_secs_f64() / s
        } else {
            0.0
        }
    }

    /// Mean encoded frame size in bytes.
    pub fn mean_frame_bytes(&self) -> f64 {
        if self.frames > 0 {
            self.bytes as f64 / self.frames as f64
        } else {
            0.0
        }
    }
}

struct Queue {
    capacity: usize,
    max: AtomicU64,
    sum: AtomicU64,
    samples: AtomicU64,
}

impl Queue {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            max: AtomicU64::new(0),
            sum: AtomicU64::new(0),
            samples: AtomicU64::new(0),
        }
    }
}

/// Which queue a depth sample belongs to.
#[derive(Clone, Copy)]
pub(crate) enum QueueId {
    CaptureToConvert = 0,
    ConvertToEncode = 1,
    EncodeToOutput = 2,
}

pub(crate) struct Stats {
    start: Instant,
    cpu_start: Duration,
    damage_to_capture: Hist,
    capture: Hist,
    convert: Hist,
    encode: Hist,
    total: Hist,
    queues: [Queue; 3],
    pub(crate) captures: AtomicU64,
    pub(crate) frames: AtomicU64,
    pub(crate) keyframes: AtomicU64,
    pub(crate) idr_frames: AtomicU64,
    pub(crate) bytes: AtomicU64,
    pub(crate) max_frame_bytes: AtomicU64,
    pub(crate) buffer_waits: AtomicU64,
    pub(crate) errors: AtomicU64,
}

impl Stats {
    pub(crate) fn new(queue_capacities: [usize; 3]) -> Self {
        Self {
            start: Instant::now(),
            cpu_start: process_cpu(),
            damage_to_capture: Hist::new(),
            capture: Hist::new(),
            convert: Hist::new(),
            encode: Hist::new(),
            total: Hist::new(),
            queues: queue_capacities.map(Queue::new),
            captures: AtomicU64::new(0),
            frames: AtomicU64::new(0),
            keyframes: AtomicU64::new(0),
            idr_frames: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            max_frame_bytes: AtomicU64::new(0),
            buffer_waits: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }

    pub(crate) fn record_capture(&self, damage_to_capture_ns: u64, grab_ns: u64) {
        self.captures.fetch_add(1, Relaxed);
        self.damage_to_capture.record_ns(damage_to_capture_ns);
        self.capture.record_ns(grab_ns);
    }

    pub(crate) fn record_convert(&self, ns: u64) {
        self.convert.record_ns(ns);
    }

    pub(crate) fn record_frame(
        &self,
        encode_ns: u64,
        total_ns: u64,
        bytes: usize,
        keyframe: bool,
        idr: bool,
    ) {
        self.encode.record_ns(encode_ns);
        self.total.record_ns(total_ns);
        self.frames.fetch_add(1, Relaxed);
        self.bytes.fetch_add(bytes as u64, Relaxed);
        self.max_frame_bytes.fetch_max(bytes as u64, Relaxed);
        if keyframe {
            self.keyframes.fetch_add(1, Relaxed);
        }
        if idr {
            self.idr_frames.fetch_add(1, Relaxed);
        }
    }

    pub(crate) fn record_queue(&self, id: QueueId, depth: usize) {
        let q = &self.queues[id as usize];
        q.max.fetch_max(depth as u64, Relaxed);
        q.sum.fetch_add(depth as u64, Relaxed);
        q.samples.fetch_add(1, Relaxed);
    }

    pub(crate) fn snapshot(&self) -> StatsSnapshot {
        let queues = [0, 1, 2].map(|i| {
            let q = &self.queues[i];
            let n = q.samples.load(Relaxed);
            QueueDepth {
                capacity: q.capacity,
                max: q.max.load(Relaxed),
                mean: if n > 0 {
                    q.sum.load(Relaxed) as f64 / n as f64
                } else {
                    0.0
                },
            }
        });
        StatsSnapshot {
            elapsed: self.start.elapsed(),
            captures: self.captures.load(Relaxed),
            frames: self.frames.load(Relaxed),
            keyframes: self.keyframes.load(Relaxed),
            idr_frames: self.idr_frames.load(Relaxed),
            bytes: self.bytes.load(Relaxed),
            max_frame_bytes: self.max_frame_bytes.load(Relaxed),
            capture_buffer_waits: self.buffer_waits.load(Relaxed),
            errors: self.errors.load(Relaxed),
            stages: StageTimings {
                damage_to_capture: self.damage_to_capture.snapshot(),
                capture: self.capture.snapshot(),
                convert: self.convert.snapshot(),
                encode: self.encode.snapshot(),
                total: self.total.snapshot(),
            },
            queues,
            cpu: process_cpu().saturating_sub(self.cpu_start),
        }
    }
}

/// CPU time consumed by this process (user and system, all threads).
pub fn process_cpu() -> Duration {
    let ts = clock_gettime(ClockId::ProcessCPUTime);
    Duration::new(ts.tv_sec.max(0) as u64, ts.tv_nsec.max(0) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_follow_the_distribution() {
        let h = Hist::new();
        for us in 1..=100u64 {
            h.record_ns(us * 1000 * 10); // 10 us .. 1000 us
        }
        let p = h.snapshot();
        assert_eq!(p.count, 100);
        assert!((450..=550).contains(&p.p50_us), "p50 {}", p.p50_us);
        assert!((900..=1000).contains(&p.p95_us), "p95 {}", p.p95_us);
        assert_eq!(p.max_us, 1000);
        assert!(p.p99_us <= p.max_us);
    }

    #[test]
    fn empty_and_overflowing_histograms_are_safe() {
        let h = Hist::new();
        assert_eq!(h.snapshot(), Percentiles::default());
        h.record_ns(5_000_000_000); // 5 s, beyond the range
        let p = h.snapshot();
        assert_eq!(p.count, 1);
        assert_eq!(p.max_us, 5_000_000);
        assert_eq!(p.p50_us, 5_000_000);
    }

    #[test]
    fn snapshot_derived_values() {
        let s = StatsSnapshot {
            elapsed: Duration::from_secs(2),
            bytes: 500_000,
            frames: 100,
            cpu: Duration::from_secs(1),
            ..StatsSnapshot::default()
        };
        assert_eq!(s.bitrate_kbps(), 2000.0);
        assert_eq!(s.cpu_cores(), 0.5);
        assert_eq!(s.mean_frame_bytes(), 5000.0);
        assert_eq!(StatsSnapshot::default().bitrate_kbps(), 0.0);
    }
}
