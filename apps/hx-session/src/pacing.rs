//! Capture pacing: capture as soon as the pipeline is free after damage arrives, with the
//! frame rate ceiling as a *minimum interval between captures*, not a clock.
//!
//! Holding damage to a fixed 60 fps grid added 5 to 13 ms at p95 in spike S2, so a frame
//! is taken the moment damage exists and the ceiling has elapsed since the previous one.

use std::time::Duration;

/// How long an idle loop sleeps before re-checking for shutdown or control requests.
pub const IDLE_POLL: Duration = Duration::from_millis(50);

/// What the capture loop should do next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Damage is pending and the ceiling allows a capture now.
    Capture,
    /// Damage is pending but the previous capture was too recent; capture after this long.
    Wait(Duration),
    /// Nothing to capture. Sleep (waking early on any display event).
    Idle,
}

/// Pure pacing state: no clock of its own, the caller passes `now_ns`.
#[derive(Clone, Debug)]
pub struct Pacer {
    min_interval_ns: u64,
    last_capture_ns: Option<u64>,
}

impl Pacer {
    /// `max_fps` is clamped to 1 to 1000.
    pub fn new(max_fps: u32) -> Self {
        Self {
            min_interval_ns: interval_ns(max_fps),
            last_capture_ns: None,
        }
    }

    pub fn set_max_fps(&mut self, max_fps: u32) {
        self.min_interval_ns = interval_ns(max_fps);
    }

    pub fn min_interval(&self) -> Duration {
        Duration::from_nanos(self.min_interval_ns)
    }

    /// Record that a capture happened at `now_ns`.
    pub fn on_capture(&mut self, now_ns: u64) {
        self.last_capture_ns = Some(now_ns);
    }

    pub fn decide(&self, now_ns: u64, damage_pending: bool) -> Decision {
        if !damage_pending {
            return Decision::Idle;
        }
        let Some(last) = self.last_capture_ns else {
            return Decision::Capture;
        };
        let due = last.saturating_add(self.min_interval_ns);
        if now_ns >= due {
            Decision::Capture
        } else {
            Decision::Wait(Duration::from_nanos(due - now_ns))
        }
    }
}

fn interval_ns(max_fps: u32) -> u64 {
    1_000_000_000 / u64::from(max_fps.clamp(1, 1000))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = 1_000_000;

    #[test]
    fn idle_without_damage() {
        let p = Pacer::new(60);
        assert_eq!(p.decide(0, false), Decision::Idle);
        assert_eq!(p.decide(10 * MS, false), Decision::Idle);
    }

    #[test]
    fn first_damage_is_captured_immediately() {
        let p = Pacer::new(60);
        assert_eq!(p.decide(123, true), Decision::Capture);
    }

    #[test]
    fn ceiling_is_a_minimum_interval_not_a_grid() {
        let mut p = Pacer::new(60);
        let step = 1_000_000_000 / 60;
        p.on_capture(1_000 * MS);
        // Damage 3 ms after a capture waits out the rest of the interval...
        let Decision::Wait(d) = p.decide(1_003 * MS, true) else {
            panic!("expected a wait")
        };
        assert_eq!(d.as_nanos() as u64, step - 3 * MS);
        // ...and is taken the instant the interval has elapsed.
        assert_eq!(p.decide(1_000 * MS + step, true), Decision::Capture);
        // Damage long after the last capture is not aligned to anything: immediate.
        assert_eq!(p.decide(1_000 * MS + step + 7, true), Decision::Capture);
        assert_eq!(p.decide(5_000 * MS + 123, true), Decision::Capture);
    }

    #[test]
    fn ceiling_can_change_at_runtime() {
        let mut p = Pacer::new(60);
        p.on_capture(0);
        assert!(matches!(p.decide(20 * MS, true), Decision::Capture));
        p.set_max_fps(10);
        assert_eq!(p.min_interval(), Duration::from_millis(100));
        assert_eq!(
            p.decide(20 * MS, true),
            Decision::Wait(Duration::from_millis(80))
        );
        // Out-of-range values are clamped, never a division by zero.
        p.set_max_fps(0);
        assert_eq!(p.min_interval(), Duration::from_secs(1));
        p.set_max_fps(u32::MAX);
        assert_eq!(p.min_interval(), Duration::from_millis(1));
    }

    #[test]
    fn clock_going_backwards_does_not_underflow() {
        let mut p = Pacer::new(60);
        p.on_capture(500 * MS);
        assert!(matches!(p.decide(100 * MS, true), Decision::Wait(_)));
    }
}
