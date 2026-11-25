//! Byte budgets and message rates of `docs/ipc.md` sections 13 and 17, as sans-I/O state.
//!
//! The caller passes the current `Instant`, so behaviour is deterministic in tests. Nothing here
//! sleeps or reads a socket.
//!
//! **Byte budget (section 13).** A token bucket per lane and direction: sustained rate, burst of
//! two seconds. The reader asks [`ByteBudget::allowance`] before it reads a frame; at zero it
//! stops reading, so the kernel buffer fills and the session's writes block (backpressure)
//! rather than the gateway reading and discarding.
//!
//! **Debt is never forgiven.** A frame is read whole, and its size is charged afterwards with
//! [`ByteBudget::consume`]; the bucket may go **negative** (at most by one frame), and reading
//! waits until refills have paid the debt off. A bucket that saturated at zero instead would let
//! a peer sending frames larger than the bucket run at line speed (measured: about 1 GiB/s
//! against a 16 MiB/s budget; docs/ipc.md review M2).
//!
//! A lane whose bucket stays empty (at or below zero, never recovering above a quarter of the
//! burst) for three consecutive seconds **while the session still has data to send** is a
//! violation ([`ByteBudget::violated`]); a pause caused by downstream flow control is not, which
//! is why the caller reports whether the peer has pending data ([`ByteBudget::note_pending`]).
//!
//! **`bulk` is backpressure only** (review L1): an honest transfer from a fast disk offers more
//! than 64 MiB/s, so an empty `bulk` bucket stops the reader and never counts as starvation
//! ([`ByteBudget::for_lane`] builds it without the starvation rule). Both ends instead pace their
//! own sends with [`Pacer`] at [`BULK_SEND_RATE`], below the budget.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::{Lane, Role};

const MIB: u64 = 1024 * 1024;

/// Sustained rate that the receiver `role` accepts on `lane` (bytes per second), section 13.
///
/// `None` for the direction that must stay silent (`media` gateway to session).
pub fn lane_rate(receiver: Role, lane: Lane) -> Option<u64> {
    match (lane, receiver) {
        (Lane::Ctl, Role::Gateway) => Some(6 * MIB),
        (Lane::Ctl, Role::Session) => Some(MIB),
        (Lane::Media, Role::Gateway) => Some(16 * MIB),
        (Lane::Media, Role::Session) => None,
        (Lane::Bulk, _) => Some(64 * MIB),
    }
}

/// Cursor-shape share of the `ctl` session to gateway budget (bytes per second).
pub const CURSOR_SHAPE_BYTES_PER_SEC: u64 = 4 * MIB;
/// Unread data allowed per transfer.
pub const TRANSFER_UNREAD_LIMIT: u64 = MIB;
/// Unread data allowed per link across all transfers.
pub const LINK_UNREAD_LIMIT: u64 = 4 * MIB;
/// How long an empty bucket with pending data is tolerated before it is a violation.
pub const STARVATION_LIMIT: Duration = Duration::from_secs(3);

/// A token bucket in whole bytes.
#[derive(Debug, Clone)]
pub struct ByteBudget {
    rate: u64,
    burst: u64,
    /// Signed: negative is debt from a frame that was larger than what was left.
    tokens: i64,
    last: Instant,
    starved_since: Option<Instant>,
    /// False: an empty bucket only stops reading, it is never a violation (`bulk`).
    starvation_is_violation: bool,
}

impl ByteBudget {
    /// A full bucket: `rate` bytes per second sustained, burst of two seconds.
    pub fn new(rate_bytes_per_sec: u64, now: Instant) -> Self {
        let rate = rate_bytes_per_sec.max(1);
        let burst = rate.saturating_mul(2);
        Self {
            rate,
            burst,
            tokens: i64::try_from(burst).unwrap_or(i64::MAX),
            last: now,
            starved_since: None,
            starvation_is_violation: true,
        }
    }

    /// Like [`ByteBudget::new`], but an empty bucket is only backpressure: [`ByteBudget::violated`]
    /// is always false.
    pub fn backpressure_only(rate_bytes_per_sec: u64, now: Instant) -> Self {
        Self {
            starvation_is_violation: false,
            ..Self::new(rate_bytes_per_sec, now)
        }
    }

    /// The budget of the section 13 table for the receiver `role` on `lane`, or `None` for the
    /// silent direction. `bulk` is backpressure only.
    pub fn for_lane(receiver: Role, lane: Lane, now: Instant) -> Option<Self> {
        lane_rate(receiver, lane).map(|r| match lane {
            Lane::Bulk => Self::backpressure_only(r, now),
            _ => Self::new(r, now),
        })
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last);
        let add = elapsed.as_nanos() * u128::from(self.rate) / 1_000_000_000;
        if add == 0 {
            return;
        }
        let add = u64::try_from(add).unwrap_or(u64::MAX);
        let cap = i64::try_from(self.burst).unwrap_or(i64::MAX);
        self.tokens = self
            .tokens
            .saturating_add(i64::try_from(add).unwrap_or(i64::MAX))
            .min(cap);
        // Advance only by the time those bytes account for, so fractions are not lost.
        let used_ns = u128::from(add) * 1_000_000_000 / u128::from(self.rate);
        self.last += Duration::from_nanos(u64::try_from(used_ns).unwrap_or(u64::MAX));
        if self.tokens >= i64::try_from(self.burst).unwrap_or(i64::MAX) {
            self.last = now;
        }
    }

    /// How many bytes may be read now. Zero means stop reading this lane (the bucket is empty
    /// or in debt).
    pub fn allowance(&mut self, now: Instant) -> u64 {
        self.refill(now);
        u64::try_from(self.tokens).unwrap_or(0)
    }

    /// Records `n` bytes read. The bucket goes negative when `n` exceeds what was left: the debt
    /// is paid by later refills before anything more may be read.
    pub fn consume(&mut self, n: u64, now: Instant) {
        self.refill(now);
        self.tokens = self
            .tokens
            .saturating_sub(i64::try_from(n).unwrap_or(i64::MAX));
    }

    /// Bytes of debt (zero when the bucket is not negative).
    pub fn debt(&self) -> u64 {
        u64::try_from(self.tokens.saturating_neg()).unwrap_or(0)
    }

    /// Reports, once per loop turn, whether the peer still has data waiting (the socket is
    /// readable). Starvation starts counting when the bucket is empty (zero or in debt) and the
    /// peer has data. It resets when the peer has nothing pending, or when the bucket has
    /// recovered above a quarter of the burst. Merely touching zero between two frames does not
    /// reset it, or a peer that always has the next frame ready would never be flagged.
    pub fn note_pending(&mut self, peer_has_data: bool, now: Instant) {
        self.refill(now);
        let healthy = self.tokens > i64::try_from(self.burst / 4).unwrap_or(i64::MAX);
        if self.tokens <= 0 && peer_has_data {
            self.starved_since.get_or_insert(now);
        } else if !peer_has_data || healthy {
            self.starved_since = None;
        }
    }

    /// True if the bucket stayed empty with data pending for [`STARVATION_LIMIT`]: the session
    /// keeps sending at full speed, a violation (section 13).
    pub fn violated(&self, now: Instant) -> bool {
        self.starvation_is_violation
            && self
                .starved_since
                .is_some_and(|s| now.saturating_duration_since(s) >= STARVATION_LIMIT)
    }
}

/// The rate at which each end paces its own `bulk` sends: three quarters of the receiver's
/// budget, so the receiver's bucket does not run dry in normal operation (docs/ipc.md section 13).
pub const BULK_SEND_RATE: u64 = 3 * (64 * MIB) / 4;

/// A sender-side pacer: sans-I/O, one per lane and direction, shared by all transfers on it.
///
/// [`Pacer::reserve`] books `n` bytes and returns how long the caller must wait before writing
/// them. Idle time earns at most [`Pacer::BURST`] of credit, so a transfer after a pause cannot
/// burst above the rate for long.
#[derive(Debug, Clone)]
pub struct Pacer {
    rate: u64,
    next: Option<Instant>,
}

impl Pacer {
    /// Credit that idle time earns (10 ms of the rate).
    pub const BURST: Duration = Duration::from_millis(10);

    /// A pacer at `rate_bytes_per_sec` (at least 1).
    pub fn new(rate_bytes_per_sec: u64) -> Self {
        Self {
            rate: rate_bytes_per_sec.max(1),
            next: None,
        }
    }

    /// The pacer for the `bulk` lane ([`BULK_SEND_RATE`]).
    pub fn bulk() -> Self {
        Self::new(BULK_SEND_RATE)
    }

    /// Books `n` bytes; wait this long, then write them.
    pub fn reserve(&mut self, n: u64, now: Instant) -> Duration {
        let floor = now.checked_sub(Self::BURST).unwrap_or(now);
        let start = self.next.map_or(floor, |t| t.max(floor));
        let cost_ns = u128::from(n) * 1_000_000_000 / u128::from(self.rate);
        self.next = Some(start + Duration::from_nanos(u64::try_from(cost_ns).unwrap_or(u64::MAX)));
        start.saturating_duration_since(now)
    }
}

/// A sliding-window counter: at most `max` events in any `window`.
///
/// Used for the per-second message limits of section 13 (`stats` 4, `event` 10, `stream_format`
/// 4, `cancel_frames` 8, cursor shapes 20, `pong` 10, video frames `2 x max_fps`, IDR frames 4)
/// and for the gateway's own sends (`request_idr` 2 per second).
#[derive(Debug, Clone)]
pub struct RateWindow {
    max: usize,
    window: Duration,
    events: VecDeque<Instant>,
}

impl RateWindow {
    /// At most `max` events per `window`.
    pub fn new(max: usize, window: Duration) -> Self {
        Self {
            max,
            window,
            events: VecDeque::with_capacity(max.min(1_024)),
        }
    }

    /// At most `max` events per second.
    pub fn per_second(max: usize) -> Self {
        Self::new(max, Duration::from_secs(1))
    }

    /// Records an event at `now` and returns whether it is within the limit. A refused event is
    /// not recorded, so a flood does not extend its own penalty.
    pub fn allow(&mut self, now: Instant) -> bool {
        while let Some(&front) = self.events.front() {
            if now.saturating_duration_since(front) >= self.window {
                self.events.pop_front();
            } else {
                break;
            }
        }
        if self.events.len() >= self.max {
            return false;
        }
        self.events.push_back(now);
        true
    }
}

/// Section 13 per-second limits, for use with [`RateWindow::per_second`].
pub mod limits {
    /// `stats` messages per second.
    pub const STATS: usize = 4;
    /// `event` messages per second.
    pub const EVENT: usize = 10;
    /// `stream_format` messages per second.
    pub const STREAM_FORMAT: usize = 4;
    /// `cancel_frames` messages per second.
    pub const CANCEL_FRAMES: usize = 8;
    /// Cursor shapes per second.
    pub const CURSOR_SHAPES: usize = 20;
    /// `pong` messages per second (more is a violation).
    pub const PONG: usize = 10;
    /// IDR frames per second.
    pub const IDR_FRAMES: usize = 4;
    /// Clipboard transfers per second from the session.
    pub const CLIPBOARD_TRANSFERS: usize = 4;
    /// `request_idr` per second sent by the gateway.
    pub const REQUEST_IDR: usize = 2;
    /// Video frames in any second: twice the negotiated `max_fps`.
    pub const fn video_frames(max_fps: usize) -> usize {
        max_fps.saturating_mul(2)
    }

    // Frame-count limits. Byte budgets do not bound per-frame CPU (a flood of 5-byte frames
    // costs far more per byte than a video frame), so every lane also has a frames-per-second
    // limit. Exceeding one is a violation (docs/ipc.md section 19.2), unlike the message-class
    // limits above, where only the excess is dropped.

    /// All frames the gateway accepts on `ctl` per second. Legitimate peak: cursor positions
    /// (at most one per millisecond, 1 000) plus the capped classes above (about 50) with
    /// headroom for bursts: 2 000.
    pub const CTL_FRAMES_FROM_SESSION: usize = 2_000;
    /// All frames the session accepts on `ctl` per second. Legitimate peak: input events (the
    /// gateway's own cap is 2 000 per second) plus motion (1 000) plus feedback and stats
    /// (about 20): 4 000.
    pub const CTL_FRAMES_FROM_GATEWAY: usize = 4_000;
    /// The ceiling above which the session closes the link for `ctl` G → S frame counts.
    /// Frames are counted when read, so a reader that stalled (an XTest flush for up to the
    /// gateway's 2 s write-stall bound) sees the queued frames as a burst; going above
    /// [`CTL_FRAMES_FROM_GATEWAY`] is only counted and logged, going above this is a violation.
    pub const CTL_FRAMES_FROM_GATEWAY_HARD: usize = 5 * CTL_FRAMES_FROM_GATEWAY;
    /// All frames on `bulk` per second, per direction. A full-speed transfer is 64 MiB/s in
    /// 64 KiB chunks, 1 024 data frames per second; opens, ends and aborts are bounded by 4
    /// concurrent transfers. Twice the data rate: 2 048.
    pub const BULK_FRAMES: usize = 2_048;
    /// Audio frames per second (reserved): 10 ms Opus frames are 100 per second; twice that.
    pub const AUDIO_FRAMES: usize = 200;
    /// `ctl` frames per second that decode to no known variant (`UnknownVariant`). A negotiated
    /// peer never sends one (a newer minor sends nothing to an older negotiated minor), so any
    /// sustained rate is abuse; a little slack covers a rolling update.
    pub const UNKNOWN_VARIANTS: usize = 10;
}

/// The frame-count limit per second for the receiver `role` reading `lane` (all kinds
/// together), or `None` for the silent direction. Video has its own `2 x max_fps` limit
/// ([`limits::video_frames`]) and is not counted here.
pub fn lane_frame_limit(receiver: Role, lane: Lane) -> Option<usize> {
    match (lane, receiver) {
        (Lane::Ctl, Role::Gateway) => Some(limits::CTL_FRAMES_FROM_SESSION),
        (Lane::Ctl, Role::Session) => Some(limits::CTL_FRAMES_FROM_GATEWAY),
        (Lane::Media, Role::Gateway) => Some(limits::AUDIO_FRAMES),
        (Lane::Media, Role::Session) => None,
        (Lane::Bulk, _) => Some(limits::BULK_FRAMES),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(base: Instant, ms: u64) -> Instant {
        base + Duration::from_millis(ms)
    }

    #[test]
    fn bucket_refills_at_the_sustained_rate_with_a_two_second_burst() {
        let t0 = Instant::now();
        let mut b = ByteBudget::new(1_000, t0);
        assert_eq!(b.allowance(t0), 2_000);
        b.consume(2_000, t0);
        assert_eq!(b.allowance(t0), 0);
        assert_eq!(b.allowance(at(t0, 500)), 500);
        assert_eq!(b.allowance(at(t0, 10_000)), 2_000, "capped at the burst");
    }

    #[test]
    fn fractions_of_a_byte_are_not_lost() {
        let t0 = Instant::now();
        let mut b = ByteBudget::new(3, t0);
        b.consume(6, t0);
        // 100 ms is 0.3 bytes: nothing yet, and the time is kept for later.
        let mut total = 0;
        for i in 1..=10 {
            total += b.allowance(at(t0, i * 100));
            let n = b.allowance(at(t0, i * 100));
            b.consume(n, at(t0, i * 100));
        }
        assert_eq!(total, 3, "ten 100 ms steps are one second of 3 B/s");
    }

    #[test]
    fn media_gateway_to_session_has_no_budget() {
        assert!(lane_rate(Role::Session, Lane::Media).is_none());
        assert_eq!(lane_rate(Role::Gateway, Lane::Media), Some(16 * MIB));
        assert_eq!(lane_rate(Role::Gateway, Lane::Ctl), Some(6 * MIB));
        assert_eq!(lane_rate(Role::Session, Lane::Ctl), Some(MIB));
        assert_eq!(lane_rate(Role::Gateway, Lane::Bulk), Some(64 * MIB));
        assert_eq!(lane_rate(Role::Session, Lane::Bulk), Some(64 * MIB));
    }

    /// The peer sends at full speed: the reader drains whatever the bucket allows each turn.
    fn drain(b: &mut ByteBudget, t: Instant, pending: bool) {
        let n = b.allowance(t);
        b.consume(n, t);
        b.note_pending(pending, t);
    }

    #[test]
    fn starvation_needs_three_seconds_of_empty_bucket_with_pending_data() {
        let t0 = Instant::now();
        let mut b = ByteBudget::new(100, t0);
        for ms in (0..=2_900).step_by(100) {
            drain(&mut b, at(t0, ms), true);
        }
        assert!(!b.violated(at(t0, 2_999)));
        drain(&mut b, at(t0, 3_000), true);
        assert!(b.violated(at(t0, 3_000)));
    }

    #[test]
    fn a_downstream_pause_is_not_a_violation() {
        let t0 = Instant::now();
        let mut b = ByteBudget::new(100, t0);
        for ms in (0..=1_000).step_by(100) {
            drain(&mut b, at(t0, ms), true);
        }
        // The peer goes quiet (nothing pending, e.g. downstream flow control): the clock resets.
        drain(&mut b, at(t0, 1_100), false);
        for ms in (1_200..=4_000).step_by(100) {
            drain(&mut b, at(t0, ms), true);
        }
        assert!(!b.violated(at(t0, 4_000)), "only 2.8 s since the restart");
        drain(&mut b, at(t0, 4_200), true);
        assert!(b.violated(at(t0, 4_200)));
    }

    /// The reviewer's simulation (docs/ipc.md review M2): a reader that checks the allowance at a
    /// frame boundary, reads a whole frame, and charges it afterwards.
    fn flood(rate: u64, frame: u64, secs: u64) -> (u64, bool) {
        let t0 = Instant::now();
        let mut now = t0;
        let mut b = ByteBudget::new(rate, now);
        let (mut bytes, mut violated) = (0u64, false);
        while now < t0 + Duration::from_secs(secs) {
            if b.allowance(now) == 0 {
                b.note_pending(true, now);
                if b.violated(now) {
                    violated = true;
                    break;
                }
                now += Duration::from_millis(10);
                continue;
            }
            b.note_pending(true, now);
            b.consume(frame + 5, now);
            // The kernel hands over the next frame at once: it is already waiting.
            b.note_pending(true, now);
            bytes += frame + 5;
        }
        (bytes, violated)
    }

    #[test]
    fn debt_is_not_forgiven_so_large_frames_cannot_outrun_the_budget() {
        let t0 = Instant::now();
        let mut b = ByteBudget::new(1_000, t0);
        b.consume(2_000, t0);
        // A frame four times what was left: the bucket goes into debt and stays at zero
        // allowance until refills have paid it.
        b.consume(4_000, t0);
        assert_eq!(b.debt(), 4_000);
        assert_eq!(b.allowance(at(t0, 3_900)), 0);
        assert_eq!(b.allowance(at(t0, 4_000)), 0);
        assert!(b.allowance(at(t0, 4_500)) > 0);
        assert_eq!(b.debt(), 0);

        // 4 MiB frames against the 16 MiB/s media budget: at most the budget plus the burst
        // plus one frame passes, not line speed. (Unfixed: about 1 GiB/s.)
        let rate = lane_rate(Role::Gateway, Lane::Media).unwrap();
        let (bytes, violated) = flood(rate, 4 * MIB, 2);
        assert!(bytes <= rate * (2 + 2) + 4 * MIB + 5, "{bytes}");
        assert!(
            !violated,
            "two seconds are within the three-second tolerance"
        );
        let (bytes, violated) = flood(rate, 4 * MIB, 10);
        // The starvation rule still fires as specified: a peer that always has the next frame
        // ready is flagged after three seconds of an empty bucket.
        assert!(violated, "sustained full speed must be a violation");
        assert!(bytes <= rate * (2 + 6) + 4 * MIB, "{bytes}");
        // The same for the small-frame `ctl` lane.
        let rate = lane_rate(Role::Gateway, Lane::Ctl).unwrap();
        let (bytes, violated) = flood(rate, 64 * 1024, 10);
        assert!(violated);
        assert!(bytes <= rate * 9 + 64 * 1024, "{bytes}");
    }

    #[test]
    fn bulk_is_backpressure_only_but_stays_bounded() {
        // Review L1: a sender at line speed is slowed (the bucket stops reading), never flagged.
        let t0 = Instant::now();
        let rate = lane_rate(Role::Gateway, Lane::Bulk).unwrap();
        let mut b = ByteBudget::for_lane(Role::Gateway, Lane::Bulk, t0).unwrap();
        let mut now = t0;
        let mut bytes = 0u64;
        while now < t0 + Duration::from_secs(30) {
            if b.allowance(now) == 0 {
                b.note_pending(true, now);
                assert!(!b.violated(now), "bulk overage is never a violation");
                now += Duration::from_millis(10);
                continue;
            }
            b.note_pending(true, now);
            b.consume(64 * 1024 + 5, now);
            bytes += 64 * 1024 + 5;
        }
        assert!(
            bytes <= rate * 32 + 64 * 1024,
            "still rate limited: {bytes}"
        );
        assert!(bytes >= rate * 28, "and not starved: {bytes}");
    }

    #[test]
    fn the_pacer_stays_under_the_receiver_budget() {
        let t0 = Instant::now();
        let mut p = Pacer::bulk();
        let mut now = t0;
        let mut sent = 0u64;
        // A sender that writes as fast as it is allowed for 20 s of virtual time.
        while now < t0 + Duration::from_secs(20) {
            now += p.reserve(64 * 1024, now);
            sent += 64 * 1024;
        }
        let rate = BULK_SEND_RATE as f64;
        let achieved = sent as f64 / 20.0;
        assert!(achieved <= rate * 1.01, "{achieved}");
        assert!(achieved >= rate * 0.95, "{achieved}");
        assert!(BULK_SEND_RATE < lane_rate(Role::Gateway, Lane::Bulk).unwrap());
        // Idle credit is capped: after a long pause only about BURST worth goes out at once.
        let later = now + Duration::from_secs(60);
        let mut waits = 0;
        let mut t = later;
        for _ in 0..16 {
            let w = p.reserve(64 * 1024, t);
            if w > Duration::ZERO {
                waits += 1;
            }
            t += w;
        }
        assert!((6..=10).contains(&waits), "{waits}");
    }

    #[test]
    fn frame_count_limits_stop_floods_of_tiny_frames() {
        assert_eq!(lane_frame_limit(Role::Session, Lane::Media), None);
        let t0 = Instant::now();
        // A flood of 5-byte TransferEnd frames: 10 000 within one second.
        let mut w = RateWindow::per_second(lane_frame_limit(Role::Gateway, Lane::Bulk).unwrap());
        let allowed = (0..10_000)
            .filter(|i| w.allow(at(t0, (*i as u64) / 10)))
            .count();
        assert_eq!(allowed, limits::BULK_FRAMES);
        // A legitimate full-speed transfer (1 024 data frames per second) is never refused.
        let mut w = RateWindow::per_second(limits::BULK_FRAMES);
        assert!((0..4_096).all(|i| w.allow(at(t0, i as u64 * 1_000 / 1_024))));
        // Empty ctl frames decoding to UnknownVariant: only a trickle is tolerated.
        let mut w = RateWindow::per_second(limits::UNKNOWN_VARIANTS);
        let allowed = (0..1_000).filter(|i| w.allow(at(t0, *i as u64))).count();
        assert_eq!(allowed, limits::UNKNOWN_VARIANTS);
        assert_eq!(lane_frame_limit(Role::Gateway, Lane::Ctl), Some(2_000));
        assert_eq!(lane_frame_limit(Role::Session, Lane::Ctl), Some(4_000));
    }

    #[test]
    fn rate_window_limits_per_window_and_forgets() {
        let t0 = Instant::now();
        let mut w = RateWindow::per_second(4);
        for i in 0..4 {
            assert!(w.allow(at(t0, i * 10)), "event {i}");
        }
        assert!(!w.allow(at(t0, 100)));
        assert!(!w.allow(at(t0, 999)));
        assert!(w.allow(at(t0, 1_000)), "the first event left the window");
        assert!(!w.allow(at(t0, 1_001)));
        assert_eq!(limits::video_frames(60), 120);
    }
}
