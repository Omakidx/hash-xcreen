//! Source-side congestion control driven by per-frame acknowledgements.
//!
//! Pure logic: no clock, no threads, no I/O. The session link reports what happens to each
//! video frame ([`CongestionController::on_frame_sent`], [`CongestionController::on_frame_ack`])
//! and calls [`CongestionController::poll`] on a timer ([`CongestionController::next_poll`]
//! says how soon); both return the [`Actions`] to carry out, normally by [`Actions::apply`]
//! on the pipeline's [`Control`] plus resetting the listed frame streams.
//!
//! Design (architecture 7.4, spike S2, with the spike's follow-ups folded in):
//!
//! * **Queueing estimate.** Each ack carries the time from handing the frame to the transport
//!   until delivery. Subtracting a windowed *minimum* baseline (10 s) and the time the frame
//!   needs at the current target rate leaves the queueing excess. The controller reacts to
//!   the median excess of the last second and to a *stall* term (the age of the oldest
//!   unacknowledged frame), so a single retransmission on a lossy link does not look like
//!   congestion and a link that stops acking cannot hide.
//! * **Jitter-adaptive thresholds.** A smoothed mean deviation of the excess scales the
//!   step-down, step-up and stale thresholds, so a link with 30 ms of jitter is not
//!   "congested" at a fixed 40 ms.
//! * **Bitrate ladder** up to 20 Mbit/s (up to the bandwidth cap when that is higher),
//!   starting at 4 Mbit/s. A level that failed is not probed again for a back-off that
//!   doubles (0.5 s to 4 s). After congestion the controller climbs quickly (one or two
//!   steps per 150 ms) back to just below the failed level, then probes slowly, and only
//!   while the link is actually being used (an application-limited stream such as typing
//!   gives no evidence that more capacity exists).
//! * **Frame rate follows the rate**: the ceiling keeps about 30 kbit per frame (10 to
//!   60 fps), so per-frame quality does not collapse before frames are shed.
//! * **Stale frames.** When the oldest unacknowledged frame is later than the stale
//!   threshold (100 ms or more, adaptive), every in-flight frame is cancelled, the rate drops
//!   two levels and a resync is requested. The next IDR must be sent flagged `RESYNC` and
//!   frames encoded before it are dropped unsent ([`CongestionController::on_frame_ready`]).
//!   Nothing already encoded is dropped otherwise.
//!
//! [`Control`]: crate::pipeline::Control

mod stale;

use crate::pipeline::{Control, PipelineError};
use std::collections::VecDeque;
use std::time::Duration;

pub use stale::FrameDisposition;

const MS: u64 = 1_000_000;

/// Bitrate ladder in kbit/s. The part at or above the active cap is cut off and the cap
/// itself is appended, so every cap is reachable exactly.
pub const LADDER_KBPS: [u32; 13] = [
    500, 1000, 1500, 2000, 3000, 4000, 6000, 8000, 10_000, 15_000, 20_000, 30_000, 50_000,
];
/// What "Auto" may reach: the top of the product ladder.
pub const AUTO_MAX_KBPS: u32 = 20_000;
/// The rate a new connection starts at.
pub const INITIAL_KBPS: u32 = 4000;
/// The frame-rate ceiling stays within these.
pub const MIN_FPS: u32 = 10;
pub const MAX_FPS: u32 = 60;
/// Bits per frame the fps ceiling tries to keep.
const FRAME_BITS: u64 = 30_000;

/// Per-device bandwidth cap (architecture 7.4).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BandwidthCap {
    /// Up to [`AUTO_MAX_KBPS`], whatever the link supports.
    #[default]
    Auto,
    Mbps5,
    Mbps10,
    Mbps25,
    Mbps50,
    /// An exact ceiling in kbit/s (the session link's `StreamConfig.bitrate_cap_kbps`, 100 to
    /// 100 000).
    Custom(u32),
}

impl BandwidthCap {
    /// Highest bitrate this cap allows, in kbit/s.
    pub fn max_kbps(self) -> u32 {
        match self {
            Self::Auto => AUTO_MAX_KBPS,
            Self::Mbps5 => 5000,
            Self::Mbps10 => 10_000,
            Self::Mbps25 => 25_000,
            Self::Mbps50 => 50_000,
            Self::Custom(k) => k.clamp(100, 100_000),
        }
    }

    /// Parse a setting in Mbit/s: 0 is Auto, otherwise 5, 10, 25 or 50.
    pub fn from_mbps(mbps: u32) -> Option<Self> {
        Some(match mbps {
            0 => Self::Auto,
            5 => Self::Mbps5,
            10 => Self::Mbps10,
            25 => Self::Mbps25,
            50 => Self::Mbps50,
            _ => return None,
        })
    }
}

/// Result of a frame, as reported by the transport (mirrors the protocol's `FrameAck`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckOutcome {
    Delivered,
    /// The frame stream was reset before delivery by the transport (cancels this controller
    /// asked for are already accounted for and ignored).
    Cancelled,
    /// The peer refused the frame (`STOP_SENDING`).
    Rejected,
    ConnectionLost,
}

/// A frame's fate; the session link builds this from the transport's own ack type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameAck {
    pub frame_number: u32,
    pub bytes: usize,
    /// From handing the frame to the transport until the outcome.
    pub elapsed: Duration,
    pub outcome: AckOutcome,
}

/// Tunables. The defaults are the product behaviour.
#[derive(Clone, Debug)]
pub struct CongestionConfig {
    pub cap: BandwidthCap,
    pub initial_kbps: u32,
    /// Step down above `down_floor + 4 * jitter`, at most `down_ceil`.
    pub down_floor: Duration,
    pub down_ceil: Duration,
    /// Stale above `stale_floor + 3 * jitter`, at most `stale_ceil`.
    pub stale_floor: Duration,
    pub stale_ceil: Duration,
}

impl Default for CongestionConfig {
    fn default() -> Self {
        Self {
            cap: BandwidthCap::Auto,
            initial_kbps: INITIAL_KBPS,
            down_floor: Duration::from_millis(30),
            down_ceil: Duration::from_millis(120),
            stale_floor: Duration::from_millis(100),
            stale_ceil: Duration::from_millis(300),
        }
    }
}

/// What the caller must do after an ack or a poll.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Actions {
    /// New encoder rate cap.
    pub bitrate_kbps: Option<u32>,
    /// New frame-rate ceiling.
    pub max_fps: Option<u32>,
    /// In-flight frames whose streams to reset with `STALE_FRAME`, oldest first. The link
    /// also drops frames it has queued but not started.
    pub cancel: Vec<u32>,
    /// Request an IDR; the next IDR goes out flagged `RESYNC`.
    pub resync: bool,
}

impl Actions {
    pub fn is_empty(&self) -> bool {
        *self == Actions::default()
    }

    /// Carry out the encoder part (rate, fps, IDR) on the pipeline. Cancelling streams is
    /// the link's job.
    pub fn apply(&self, control: &Control) -> Result<(), PipelineError> {
        if let Some(k) = self.bitrate_kbps {
            control.set_bitrate_kbps(k)?;
        }
        if let Some(f) = self.max_fps {
            control.set_max_fps(f)?;
        }
        if self.resync {
            control.request_idr();
        }
        Ok(())
    }
}

/// Estimates and counters for the stats overlay and tests.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct CongestionStats {
    pub bitrate_kbps: u32,
    pub max_fps: u32,
    pub cap_kbps: u32,
    pub in_flight: usize,
    /// Median queueing excess over the last second (or the stall), in ms.
    pub lag_ms: f64,
    pub jitter_ms: f64,
    pub base_ms: f64,
    pub down_threshold_ms: f64,
    pub stale_threshold_ms: f64,
    /// Acknowledged payload rate over the last 500 ms, kbit/s.
    pub delivered_kbps: f64,
    pub step_downs: u64,
    pub step_ups: u64,
    /// Stale events (each cancels every in-flight frame).
    pub cancels: u64,
    pub frames_cancelled: u64,
    pub resyncs: u64,
}

struct InFlight {
    frame: u32,
    sent_ns: u64,
    bytes: usize,
}

/// Baseline window: buckets of 100 ms over 10 s.
const BASE_BUCKET_NS: u64 = 100 * MS;
const BASE_WINDOW_NS: u64 = 10_000 * MS;
const SAMPLE_WINDOW_NS: u64 = 1000 * MS;
/// Recent acks the median is taken over (few, so a change shows within a handful of frames).
const SAMPLE_MAX: usize = 9;
/// Fewer samples than this say nothing about queueing.
const MIN_SAMPLES: usize = 3;
const UTIL_WINDOW_NS: u64 = 500 * MS;
const MAX_IN_FLIGHT: usize = 4096;
const BACKOFF_MIN_NS: u64 = 500 * MS;
const BACKOFF_MAX_NS: u64 = 4000 * MS;
/// Clean for this long: the back-off starts over.
const BACKOFF_RESET_NS: u64 = 5000 * MS;
/// Probing above the proven level needs this much of the current rate in use.
const MIN_UTILISATION: f64 = 0.4;
/// Idle this long: the next busy period starts from the initial rate again.
/// A level held this long without a step down counts as proven.
const PROVEN_AFTER_NS: u64 = 2000 * MS;
const IDLE_RESET_NS: u64 = 2000 * MS;

pub struct CongestionController {
    cfg: CongestionConfig,
    ladder: Vec<u32>,
    level: usize,
    start_level: usize,
    /// Climb quickly up to this level, then probe slowly.
    recover_to: usize,
    block_until: Vec<u64>,
    backoff_ns: u64,
    last_change_ns: u64,
    clean_since_ns: u64,
    last_activity_ns: u64,
    /// (bucket start, minimum elapsed) in ns.
    base_buckets: VecDeque<(u64, u64)>,
    /// (ack time, excess ns), only frames sent after the last rate change.
    samples: VecDeque<(u64, i64)>,
    /// (ack time, bytes) of delivered frames.
    delivered: VecDeque<(u64, usize)>,
    /// (send time, bytes) of frames handed to the transport.
    sent: VecDeque<(u64, usize)>,
    last_excess: Option<f64>,
    jitter_ns: f64,
    last_ack_ns: u64,
    in_flight: VecDeque<InFlight>,
    gate: stale::ResyncGate,
    stats: CongestionStats,
}

impl CongestionController {
    pub fn new(cfg: CongestionConfig, now_ns: u64) -> Self {
        let mut c = Self {
            ladder: Vec::new(),
            level: 0,
            start_level: 0,
            recover_to: 0,
            block_until: Vec::new(),
            backoff_ns: BACKOFF_MIN_NS,
            last_change_ns: now_ns,
            clean_since_ns: now_ns,
            last_activity_ns: now_ns,
            base_buckets: VecDeque::new(),
            samples: VecDeque::new(),
            delivered: VecDeque::new(),
            sent: VecDeque::new(),
            last_excess: None,
            jitter_ns: 0.0,
            last_ack_ns: now_ns,
            in_flight: VecDeque::new(),
            gate: stale::ResyncGate::default(),
            stats: CongestionStats::default(),
            cfg,
        };
        c.rebuild_ladder();
        c.start_level = c.level_at_most(c.cfg.initial_kbps);
        c.level = c.start_level;
        c.recover_to = c.start_level;
        c
    }

    /// The actions that establish the starting state (call once when the link comes up).
    pub fn initial_actions(&self) -> Actions {
        Actions {
            bitrate_kbps: Some(self.kbps()),
            max_fps: Some(self.fps()),
            ..Actions::default()
        }
    }

    /// Back to the starting rate for a new connection; every estimate is forgotten and a
    /// resync is armed (a new client needs an IDR).
    pub fn reset(&mut self, now_ns: u64) -> Actions {
        let cfg = self.cfg.clone();
        *self = Self::new(cfg, now_ns);
        self.gate.arm();
        Actions {
            resync: true,
            ..self.initial_actions()
        }
    }

    /// Current target rate in kbit/s.
    pub fn kbps(&self) -> u32 {
        self.ladder[self.level]
    }

    /// Current frame-rate ceiling.
    pub fn fps(&self) -> u32 {
        fps_for(self.kbps())
    }

    pub fn cap(&self) -> BandwidthCap {
        self.cfg.cap
    }

    /// Change the bandwidth cap; the rate is clamped at once.
    pub fn set_cap(&mut self, cap: BandwidthCap, now_ns: u64) -> Actions {
        let before = self.kbps();
        self.cfg.cap = cap;
        self.rebuild_ladder();
        self.start_level = self.level_at_most(self.cfg.initial_kbps);
        self.level = self.level_at_most(before);
        self.recover_to = self.recover_to.min(self.ladder.len() - 1);
        self.changed(now_ns);
        if self.kbps() == before {
            return Actions::default();
        }
        Actions {
            bitrate_kbps: Some(self.kbps()),
            max_fps: Some(self.fps()),
            ..Actions::default()
        }
    }

    /// A frame was handed to the transport.
    pub fn on_frame_sent(&mut self, now_ns: u64, frame_number: u32, bytes: usize) {
        if self.in_flight.len() >= MAX_IN_FLIGHT {
            self.in_flight.pop_front();
        }
        self.last_activity_ns = now_ns;
        self.sent.push_back((now_ns, bytes));
        self.in_flight.push_back(InFlight {
            frame: frame_number,
            sent_ns: now_ns,
            bytes,
        });
    }

    /// Optional transport round-trip sample (feeds the baseline only).
    pub fn on_rtt_sample(&mut self, now_ns: u64, rtt: Duration) {
        self.note_base(now_ns, saturating_ns(rtt));
    }

    /// A frame's outcome arrived. Unknown and duplicate acks are ignored, and so are the
    /// `Cancelled` acks of frames this controller cancelled. Returns actions only for
    /// outcomes that need an immediate reaction (a cancel by the transport, a lost
    /// connection); everything else is handled by [`CongestionController::poll`].
    pub fn on_frame_ack(&mut self, now_ns: u64, ack: FrameAck) -> Actions {
        let Some(i) = self
            .in_flight
            .iter()
            .position(|f| f.frame == ack.frame_number)
        else {
            return Actions::default();
        };
        let Some(f) = self.in_flight.remove(i) else {
            return Actions::default();
        };
        self.last_activity_ns = now_ns;
        match ack.outcome {
            AckOutcome::Delivered => {
                let elapsed = saturating_ns(ack.elapsed);
                self.note_base(now_ns, elapsed);
                let base = self.base_ns().unwrap_or(elapsed);
                let excess = elapsed as i64 - base as i64 - self.serialization_ns(f.bytes) as i64;
                self.last_ack_ns = now_ns;
                self.delivered.push_back((now_ns, f.bytes));
                if f.sent_ns >= self.last_change_ns {
                    self.note_excess(now_ns, excess);
                }
                Actions::default()
            }
            AckOutcome::Cancelled | AckOutcome::Rejected => {
                // Frames are being lost, which breaks the decode chain: shed rate and resync.
                self.gate.arm();
                self.stats.resyncs += 1;
                let can_step = now_ns.saturating_sub(self.last_change_ns) >= self.settle_ns();
                let mut a = if can_step {
                    self.step_down(now_ns, 1, false)
                } else {
                    Actions::default()
                };
                a.resync = true;
                a
            }
            AckOutcome::ConnectionLost => {
                self.in_flight.clear();
                let before = self.kbps();
                self.level = self.level.min(self.start_level);
                self.recover_to = self.level;
                self.changed(now_ns);
                self.gate.arm();
                self.stats.resyncs += 1;
                let moved = self.kbps() != before;
                Actions {
                    bitrate_kbps: moved.then(|| self.kbps()),
                    max_fps: moved.then(|| self.fps()),
                    cancel: Vec::new(),
                    resync: true,
                }
            }
        }
    }

    /// Run the controller. Cheap; call it every [`CongestionController::next_poll`].
    pub fn poll(&mut self, now_ns: u64) -> Actions {
        self.expire(now_ns);
        let (down_thr, stale_thr, up_thr) = self.thresholds();
        let base = self.base_ns().unwrap_or(0);
        let median = self.median_excess();
        let stall = self.stall_ns(now_ns, base);
        let lag = median.max(stall);
        self.stats.lag_ms = lag as f64 / MS as f64;
        let since_change = now_ns.saturating_sub(self.last_change_ns);
        let settled = since_change >= self.settle_ns();

        if lag > stale_thr as i64 && settled {
            return self.go_stale(now_ns, median > stale_thr as i64);
        }
        // A stall that is not yet stale does not step down by itself: with a stream per
        // frame, one frame waiting for a retransmission looks the same.
        if median > down_thr as i64 && settled {
            return self.step_down(now_ns, 1, true);
        }
        if lag > up_thr as i64 {
            self.clean_since_ns = now_ns;
            return Actions::default();
        }
        if self.is_idle(now_ns) {
            return self.idle_restart(now_ns);
        }
        if now_ns.saturating_sub(self.clean_since_ns) > BACKOFF_RESET_NS {
            self.backoff_ns = BACKOFF_MIN_NS;
        }
        if self.level + 1 >= self.ladder.len() {
            return Actions::default();
        }
        // Climb only on evidence: acks from frames sent at the current rate.
        if self.samples.len() < MIN_SAMPLES {
            return Actions::default();
        }
        let fast = self.level < self.recover_to;
        let hold = if fast {
            (150 * MS).max(base)
        } else {
            (500 * MS).max(2 * base)
        };
        if self.level > self.recover_to && since_change >= PROVEN_AFTER_NS {
            self.recover_to = self.level; // held clean for a while: this level is proven
        }
        if now_ns.saturating_sub(self.clean_since_ns) < hold || since_change < hold {
            return Actions::default();
        }
        let step = if fast && self.level + 2 <= self.recover_to {
            2
        } else {
            1
        };
        let mut target = (self.level + step).min(self.ladder.len() - 1);
        if step == 2 && now_ns < self.block_until[target] {
            target = self.level + 1;
        }
        if now_ns < self.block_until[target] || (!fast && self.utilisation() < MIN_UTILISATION) {
            return Actions::default(); // blocked, or application-limited
        }
        self.level = target;
        self.stats.step_ups += 1;
        self.changed(now_ns);
        Actions {
            bitrate_kbps: Some(self.kbps()),
            max_fps: Some(self.fps()),
            ..Actions::default()
        }
    }

    /// How long until the next [`CongestionController::poll`] is useful: frequent while
    /// frames are in flight, rare when idle so an idle desktop costs nothing.
    pub fn next_poll(&self) -> Duration {
        if self.in_flight.is_empty() {
            Duration::from_millis(100)
        } else {
            Duration::from_millis(5)
        }
    }

    /// Decide what to do with a frame the encoder has produced. After a resync was
    /// requested, frames encoded before the fresh IDR are [`FrameDisposition::Drop`]; the
    /// IDR itself is [`FrameDisposition::Send`] with `resync` set.
    pub fn on_frame_ready(&mut self, idr: bool) -> FrameDisposition {
        self.gate.on_frame_ready(idr)
    }

    /// True between a resync request and the IDR that satisfies it.
    pub fn resync_pending(&self) -> bool {
        self.gate.is_armed()
    }

    pub fn stats(&self) -> CongestionStats {
        let (down, stale, _) = self.thresholds();
        CongestionStats {
            bitrate_kbps: self.kbps(),
            max_fps: self.fps(),
            cap_kbps: self.cfg.cap.max_kbps(),
            in_flight: self.in_flight.len(),
            jitter_ms: self.jitter_ns / MS as f64,
            base_ms: self.base_ns().unwrap_or(0) as f64 / MS as f64,
            down_threshold_ms: down as f64 / MS as f64,
            stale_threshold_ms: stale as f64 / MS as f64,
            delivered_kbps: self.delivered_bits() / (UTIL_WINDOW_NS as f64 / 1e9) / 1000.0,
            ..self.stats
        }
    }

    // ---- internals ----

    fn rebuild_ladder(&mut self) {
        let top = self.cfg.cap.max_kbps();
        self.ladder = LADDER_KBPS.iter().copied().filter(|k| *k < top).collect();
        self.ladder.push(top);
        self.block_until = vec![0; self.ladder.len()];
        self.level = self.level.min(self.ladder.len() - 1);
    }

    fn level_at_most(&self, kbps: u32) -> usize {
        self.ladder.iter().rposition(|k| *k <= kbps).unwrap_or(0)
    }

    fn changed(&mut self, now_ns: u64) {
        self.last_change_ns = now_ns;
        self.clean_since_ns = now_ns;
        self.samples.clear();
    }

    /// Time a frame of `bytes` takes at the current target rate.
    fn serialization_ns(&self, bytes: usize) -> u64 {
        (bytes as u64).saturating_mul(8_000_000) / u64::from(self.kbps().max(1))
    }

    /// Minimum time between decisions: long enough for a change to show in the acks.
    fn settle_ns(&self) -> u64 {
        let base = self.base_ns().unwrap_or(0);
        (150 * MS).max(base + base / 2)
    }

    /// (step down, stale, step up) thresholds in ns.
    fn thresholds(&self) -> (u64, u64, u64) {
        let j = self.jitter_ns;
        let down = (self.cfg.down_floor.as_nanos() as f64 + 4.0 * j)
            .min(self.cfg.down_ceil.as_nanos() as f64);
        let stale = (self.cfg.stale_floor.as_nanos() as f64 + 3.0 * j)
            .min(self.cfg.stale_ceil.as_nanos() as f64);
        let up = (10.0 * MS as f64 + 2.0 * j).min(down / 2.0);
        (down as u64, stale as u64, up as u64)
    }

    fn note_base(&mut self, now_ns: u64, v_ns: u64) {
        let bucket = now_ns / BASE_BUCKET_NS * BASE_BUCKET_NS;
        match self.base_buckets.back_mut() {
            Some((b, m)) if *b == bucket => *m = (*m).min(v_ns),
            _ => self.base_buckets.push_back((bucket, v_ns)),
        }
        while self
            .base_buckets
            .front()
            .is_some_and(|(b, _)| now_ns.saturating_sub(*b) > BASE_WINDOW_NS)
        {
            self.base_buckets.pop_front();
        }
    }

    fn base_ns(&self) -> Option<u64> {
        self.base_buckets.iter().map(|(_, m)| *m).min()
    }

    fn note_excess(&mut self, now_ns: u64, excess: i64) {
        // Jitter as the smoothed difference between successive samples (RFC 3550 style):
        // a queue building up moves the excess slowly and is not "jitter"; spread is.
        let e = excess as f64;
        if let Some(prev) = self.last_excess {
            self.jitter_ns += ((e - prev).abs() - self.jitter_ns) / 16.0;
        }
        self.last_excess = Some(e);
        if self.samples.len() >= SAMPLE_MAX {
            self.samples.pop_front();
        }
        self.samples.push_back((now_ns, excess));
    }

    fn expire(&mut self, now_ns: u64) {
        while self
            .samples
            .front()
            .is_some_and(|(t, _)| now_ns.saturating_sub(*t) > SAMPLE_WINDOW_NS)
        {
            self.samples.pop_front();
        }
        while self
            .sent
            .front()
            .is_some_and(|(t, _)| now_ns.saturating_sub(*t) > UTIL_WINDOW_NS)
        {
            self.sent.pop_front();
        }
        while self
            .delivered
            .front()
            .is_some_and(|(t, _)| now_ns.saturating_sub(*t) > UTIL_WINDOW_NS)
        {
            self.delivered.pop_front();
        }
    }

    /// Median queueing excess of the recent acks; 0 until there are enough of them.
    fn median_excess(&self) -> i64 {
        if self.samples.len() < MIN_SAMPLES {
            return 0;
        }
        let mut v: Vec<i64> = self.samples.iter().map(|(_, e)| *e).collect();
        v.sort_unstable();
        v[v.len() / 2]
    }

    /// How long nothing has completed although frames are waiting, beyond what one frame
    /// needs anyway: the time since the later of the oldest frame's send and the last ack.
    /// Frames still being acknowledged behind a slow one are not a stall.
    fn stall_ns(&self, now_ns: u64, base: u64) -> i64 {
        let Some(f) = self.in_flight.front() else {
            return 0;
        };
        let since = now_ns.saturating_sub(f.sent_ns.max(self.last_ack_ns));
        since as i64 - base as i64 - self.serialization_ns(f.bytes) as i64
    }

    fn delivered_bits(&self) -> f64 {
        self.delivered.iter().map(|(_, b)| *b as f64 * 8.0).sum()
    }

    /// Fraction of the current target rate that was actually acknowledged recently.
    fn utilisation(&self) -> f64 {
        let bps = self.delivered_bits() / (UTIL_WINDOW_NS as f64 / 1e9);
        bps / (f64::from(self.kbps()) * 1000.0)
    }

    fn is_idle(&self, now_ns: u64) -> bool {
        self.in_flight.is_empty() && now_ns.saturating_sub(self.last_activity_ns) >= IDLE_RESET_NS
    }

    /// After a quiet spell a lowered rate says nothing about the link any more: start the
    /// next busy period from the initial rate.
    fn idle_restart(&mut self, now_ns: u64) -> Actions {
        if self.level >= self.start_level {
            return Actions::default();
        }
        self.level = self.start_level;
        self.recover_to = self.recover_to.max(self.level);
        self.changed(now_ns);
        Actions {
            bitrate_kbps: Some(self.kbps()),
            max_fps: Some(self.fps()),
            ..Actions::default()
        }
    }

    fn step_down(&mut self, now_ns: u64, n: usize, use_rate: bool) -> Actions {
        let failed = self.level;
        let moved = failed > 0;
        if moved {
            self.block_until[failed] = now_ns + self.backoff_ns;
            self.backoff_ns = (self.backoff_ns * 2).min(BACKOFF_MAX_NS);
            // While frames queue and acks keep flowing, they come back at the link's rate:
            // that is the capacity. Jump straight below it instead of walking down one step
            // per decision. Only meaningful when the link, not the source, limited what got
            // through.
            let delivered = self.delivered_bits() / (UTIL_WINDOW_NS as f64 / 1e9) / 1000.0;
            let sent: f64 = self.sent.iter().map(|(_, b)| *b as f64 * 8.0).sum::<f64>()
                / (UTIL_WINDOW_NS as f64 / 1e9)
                / 1000.0;
            let by_rate = if use_rate && delivered > 0.0 && delivered < 0.7 * sent {
                self.level_at_most((delivered * 0.8) as u32)
            } else {
                usize::MAX
            };
            self.level = failed.saturating_sub(n).min(by_rate);
            if by_rate != usize::MAX {
                // Measured capacity: do not climb back past it until the back-off is over.
                for b in &mut self.block_until[(self.level + 2).min(failed)..=failed] {
                    *b = now_ns + self.backoff_ns;
                }
            }
            // The level just under the failed one is the likely sustainable rate: climb
            // back to it fast, then probe. Never forget a level that was proven earlier, so
            // a link that recovers from a collapse is used again at once.
            self.recover_to = self.recover_to.max(failed.saturating_sub(1)).min(failed);
            self.stats.step_downs += 1;
        }
        self.changed(now_ns);
        Actions {
            bitrate_kbps: moved.then(|| self.kbps()),
            max_fps: moved.then(|| self.fps()),
            ..Actions::default()
        }
    }

    fn go_stale(&mut self, now_ns: u64, acks_flowing: bool) -> Actions {
        let cancel: Vec<u32> = self.in_flight.drain(..).map(|f| f.frame).collect();
        self.stats.cancels += 1;
        self.stats.frames_cancelled += cancel.len() as u64;
        self.stats.resyncs += 1;
        self.gate.arm();
        let mut a = self.step_down(now_ns, 2, acks_flowing);
        a.cancel = cancel;
        a.resync = true;
        a
    }
}

fn saturating_ns(d: Duration) -> u64 {
    d.as_nanos().min(u128::from(u64::MAX)) as u64
}

/// Frame-rate ceiling for a bitrate: about 30 kbit per frame, within 10 to 60 fps.
pub fn fps_for(kbps: u32) -> u32 {
    ((u64::from(kbps) * 1000 / FRAME_BITS) as u32).clamp(MIN_FPS, MAX_FPS)
}

#[cfg(test)]
mod sim;
#[cfg(test)]
mod tests;
