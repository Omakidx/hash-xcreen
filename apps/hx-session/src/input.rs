//! Input from the client: validation, rate limiting and injection.
//!
//! The session link decodes `InputEvent`s (reliable stream) and mouse-motion datagrams and
//! hands them to an [`InputGate`], which treats them as untrusted:
//!
//! * every event is validated again (usage range, button, coordinates) before it reaches X;
//! * **rate limits** bound what a client can make the server do: one token bucket for
//!   key/button/scroll events and one for pointer motion. Motion over the limit is dropped
//!   (the newest position wins anyway); other events over the limit are rejected and counted
//!   as violations, which the link may use to drop the client. Releases are exempt, so a
//!   limit can never leave a key stuck;
//! * motion datagrams older than the newest one seen are dropped (serial arithmetic);
//! * on focus loss, an explicit `release_all`, and [`InputGate::on_disconnect`], everything
//!   held is released.
//!
//! The injection itself is [`hx_capture::InputInjector`]; coordinates are clamped there.

use hx_capture::{Button, InputError, InputInjector};
use hx_proto::datagram::MouseMove;
use hx_proto::message::Wire;
use hx_proto::order::serial_gt;
use hx_proto::pb::{self, input_event::Event};

const MS: u64 = 1_000_000;

/// Limits for untrusted input. The defaults are far above human input (a fast typist is
/// about 15 key events a second, a high-rate mouse 1000 moves a second).
#[derive(Clone, Copy, Debug)]
pub struct InputLimits {
    /// Key, button and scroll events per second, sustained.
    pub events_per_sec: u32,
    pub event_burst: u32,
    /// Pointer motion datagrams per second, sustained.
    pub moves_per_sec: u32,
    pub move_burst: u32,
}

impl Default for InputLimits {
    fn default() -> Self {
        Self {
            events_per_sec: 500,
            event_burst: 200,
            moves_per_sec: 1500,
            move_burst: 300,
        }
    }
}

/// A token bucket on a caller-supplied clock.
#[derive(Clone, Debug)]
struct Bucket {
    rate: u64,
    burst: u64,
    /// Tokens in thousandths.
    milli: u64,
    last_ns: u64,
}

impl Bucket {
    fn new(rate: u32, burst: u32) -> Self {
        let burst = u64::from(burst.max(1));
        Self {
            rate: u64::from(rate),
            burst,
            milli: burst * 1000,
            last_ns: 0,
        }
    }

    fn allow(&mut self, now_ns: u64) -> bool {
        let dt = now_ns.saturating_sub(self.last_ns);
        self.last_ns = self.last_ns.max(now_ns);
        // rate tokens per second = rate * dt / 1e9 tokens = rate * dt / 1e6 milli-tokens.
        let add = (u128::from(self.rate) * u128::from(dt) / u128::from(MS)) as u64;
        self.milli = (self.milli.saturating_add(add)).min(self.burst * 1000);
        if self.milli >= 1000 {
            self.milli -= 1000;
            true
        } else {
            false
        }
    }
}

/// What happened to an input message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputOutcome {
    Injected,
    /// Not injected and not an error: a stale motion datagram, a motion over the limit, a key
    /// that has no meaning here.
    Dropped,
}

/// Why an event was refused.
#[derive(Debug, thiserror::Error)]
pub enum InputRejected {
    #[error("invalid input event: {0}")]
    Invalid(String),
    #[error("input rate limit exceeded")]
    RateLimited,
    #[error("injection failed: {0}")]
    Inject(InputError),
}

impl InputRejected {
    /// True for a connection to the display that is gone (the session cannot go on).
    pub fn is_fatal(&self) -> bool {
        matches!(self, InputRejected::Inject(e) if e.is_fatal())
    }
}

/// Counters for the stats overlay and for deciding to drop a misbehaving client.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InputStats {
    pub injected: u64,
    pub dropped_stale_motion: u64,
    pub dropped_rate_limited_motion: u64,
    /// Invalid events and events refused by the rate limit.
    pub violations: u64,
    pub rate_limited: u64,
    pub unmapped_keys: u64,
    pub inject_errors: u64,
}

pub struct InputGate<I: InputInjector> {
    injector: I,
    events: Bucket,
    moves: Bucket,
    last_move_seq: Option<u32>,
    stats: InputStats,
}

impl<I: InputInjector> InputGate<I> {
    pub fn new(injector: I, limits: InputLimits) -> Self {
        Self {
            injector,
            events: Bucket::new(limits.events_per_sec, limits.event_burst),
            moves: Bucket::new(limits.moves_per_sec, limits.move_burst),
            last_move_seq: None,
            stats: InputStats::default(),
        }
    }

    pub fn stats(&self) -> InputStats {
        self.stats
    }

    /// Access to the injector (tests, resize notifications).
    pub fn injector_mut(&mut self) -> &mut I {
        &mut self.injector
    }

    /// A message from the input stream. `now_ns` is any monotonic clock.
    pub fn on_input(
        &mut self,
        now_ns: u64,
        ev: &pb::InputEvent,
    ) -> Result<InputOutcome, InputRejected> {
        if let Err(e) = ev.validate() {
            self.stats.violations += 1;
            return Err(InputRejected::Invalid(e.to_string()));
        }
        let Some(event) = &ev.event else {
            self.stats.violations += 1;
            return Err(InputRejected::Invalid("no variant set".into()));
        };
        // Releases are always honoured; anything that adds input is metered.
        let is_release = match event {
            Event::Key(k) => !k.pressed,
            Event::Button(b) => !b.pressed,
            Event::ReleaseAll(_) => true,
            Event::Scroll(_) => false,
        };
        if !is_release && !self.events.allow(now_ns) {
            self.stats.rate_limited += 1;
            self.stats.violations += 1;
            return Err(InputRejected::RateLimited);
        }
        let result = match event {
            Event::Key(k) => self.injector.key(k.scancode, k.pressed),
            Event::Button(b) => {
                let button = match pb::MouseButton::try_from(b.button) {
                    Ok(pb::MouseButton::Left) => Button::Left,
                    Ok(pb::MouseButton::Right) => Button::Right,
                    Ok(pb::MouseButton::Middle) => Button::Middle,
                    Ok(pb::MouseButton::Back) => Button::Back,
                    Ok(pb::MouseButton::Forward) => Button::Forward,
                    _ => {
                        self.stats.violations += 1;
                        return Err(InputRejected::Invalid("unknown button".into()));
                    }
                };
                self.injector.button(button, b.pressed, Some((b.x, b.y)))
            }
            Event::Scroll(s) => self.injector.scroll(s.dx, s.dy),
            Event::ReleaseAll(_) => self.injector.release_all(),
        };
        self.finish(result)
    }

    /// A pointer-motion datagram.
    pub fn on_mouse_move(
        &mut self,
        now_ns: u64,
        m: &MouseMove,
    ) -> Result<InputOutcome, InputRejected> {
        if let Some(last) = self.last_move_seq
            && !serial_gt(m.seq, last)
        {
            self.stats.dropped_stale_motion += 1;
            return Ok(InputOutcome::Dropped);
        }
        self.last_move_seq = Some(m.seq);
        if !self.moves.allow(now_ns) {
            self.stats.dropped_rate_limited_motion += 1;
            return Ok(InputOutcome::Dropped);
        }
        let result = if m.relative {
            self.injector.move_by(m.x, m.y)
        } else {
            self.injector.move_to(m.x, m.y)
        };
        self.finish(result)
    }

    /// The client lost focus: release every key and button.
    pub fn on_focus_lost(&mut self) -> Result<(), InputRejected> {
        self.injector.release_all().map_err(|e| {
            self.stats.inject_errors += 1;
            InputRejected::Inject(e)
        })
    }

    /// The client is gone: release everything and forget the motion sequence so the next
    /// client starts fresh.
    pub fn on_disconnect(&mut self) -> Result<(), InputRejected> {
        self.last_move_seq = None;
        self.on_focus_lost()
    }

    fn finish(&mut self, result: Result<(), InputError>) -> Result<InputOutcome, InputRejected> {
        match result {
            Ok(()) => {
                self.stats.injected += 1;
                Ok(InputOutcome::Injected)
            }
            // A key this server has no key for is the client's problem, not a failure.
            Err(InputError::UnmappedKey(_) | InputError::NoKeycode(_)) => {
                self.stats.unmapped_keys += 1;
                Ok(InputOutcome::Dropped)
            }
            Err(e) => {
                self.stats.inject_errors += 1;
                Err(InputRejected::Inject(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hx_proto::pb::{ButtonEvent, KeyEvent, ReleaseAll, ScrollEvent};

    #[derive(Default)]
    struct Rec {
        calls: Vec<String>,
        fail_unmapped: bool,
    }

    impl InputInjector for Rec {
        fn key(&mut self, usage: u32, pressed: bool) -> Result<(), InputError> {
            if self.fail_unmapped {
                return Err(InputError::UnmappedKey(usage));
            }
            self.calls.push(format!("key {usage:#x} {pressed}"));
            Ok(())
        }
        fn button(
            &mut self,
            b: Button,
            pressed: bool,
            at: Option<(i32, i32)>,
        ) -> Result<(), InputError> {
            self.calls.push(format!("button {b:?} {pressed} {at:?}"));
            Ok(())
        }
        fn move_to(&mut self, x: i32, y: i32) -> Result<(), InputError> {
            self.calls.push(format!("to {x} {y}"));
            Ok(())
        }
        fn move_by(&mut self, dx: i32, dy: i32) -> Result<(), InputError> {
            self.calls.push(format!("by {dx} {dy}"));
            Ok(())
        }
        fn scroll(&mut self, dx: i32, dy: i32) -> Result<(), InputError> {
            self.calls.push(format!("scroll {dx} {dy}"));
            Ok(())
        }
        fn release_all(&mut self) -> Result<(), InputError> {
            self.calls.push("release_all".into());
            Ok(())
        }
    }

    fn gate() -> InputGate<Rec> {
        InputGate::new(Rec::default(), InputLimits::default())
    }

    fn key(scancode: u32, pressed: bool) -> pb::InputEvent {
        pb::InputEvent {
            event: Some(Event::Key(KeyEvent { scancode, pressed })),
        }
    }

    fn mv(seq: u32, x: i32, y: i32, relative: bool) -> MouseMove {
        MouseMove {
            relative,
            seq,
            x,
            y,
        }
    }

    #[test]
    fn valid_events_reach_the_injector() {
        let mut g = gate();
        assert_eq!(
            g.on_input(0, &key(4, true)).unwrap(),
            InputOutcome::Injected
        );
        g.on_input(0, &key(4, false)).unwrap();
        let btn = pb::InputEvent {
            event: Some(Event::Button(ButtonEvent {
                button: pb::MouseButton::Left as i32,
                pressed: true,
                x: 5,
                y: -6,
            })),
        };
        g.on_input(0, &btn).unwrap();
        let sc = pb::InputEvent {
            event: Some(Event::Scroll(ScrollEvent { dx: 0, dy: -120 })),
        };
        g.on_input(0, &sc).unwrap();
        assert_eq!(
            g.injector_mut().calls,
            vec![
                "key 0x4 true",
                "key 0x4 false",
                "button Left true Some((5, -6))",
                "scroll 0 -120"
            ]
        );
        assert_eq!(g.stats().injected, 4);
    }

    #[test]
    fn invalid_events_are_refused_before_injection() {
        let mut g = gate();
        let button = |b: i32| pb::InputEvent {
            event: Some(Event::Button(ButtonEvent {
                button: b,
                pressed: true,
                x: 0,
                y: 0,
            })),
        };
        for ev in [
            key(0xE8, true),
            key(u32::MAX, true),
            pb::InputEvent { event: None },
            button(0),
            button(99),
        ] {
            assert!(matches!(g.on_input(0, &ev), Err(InputRejected::Invalid(_))));
        }
        assert!(g.injector_mut().calls.is_empty());
        assert_eq!(g.stats().violations, 5);
    }

    #[test]
    fn unmapped_keys_are_dropped_quietly() {
        let mut g = InputGate::new(
            Rec {
                fail_unmapped: true,
                ..Rec::default()
            },
            InputLimits::default(),
        );
        assert_eq!(
            g.on_input(0, &key(0x03, true)).unwrap(),
            InputOutcome::Dropped
        );
        assert_eq!(g.stats().unmapped_keys, 1);
        assert_eq!(g.stats().violations, 0);
    }

    #[test]
    fn event_flood_is_rate_limited_but_releases_always_pass() {
        let mut g = InputGate::new(
            Rec::default(),
            InputLimits {
                events_per_sec: 10,
                event_burst: 5,
                ..InputLimits::default()
            },
        );
        let ok = (0..50)
            .filter(|_| g.on_input(0, &key(4, true)).is_ok())
            .count();
        assert_eq!(ok, 5, "the burst, then nothing within the same instant");
        assert_eq!(g.stats().rate_limited, 45);
        assert!(matches!(
            g.on_input(0, &key(5, true)),
            Err(InputRejected::RateLimited)
        ));
        // A release is never refused.
        g.on_input(0, &key(4, false)).unwrap();
        let ra = pb::InputEvent {
            event: Some(Event::ReleaseAll(ReleaseAll {})),
        };
        g.on_input(0, &ra).unwrap();
        // 200 ms later two tokens are back (10 per second).
        let t = 200 * MS;
        assert!(g.on_input(t, &key(6, true)).is_ok());
        assert!(g.on_input(t, &key(7, true)).is_ok());
        assert!(g.on_input(t, &key(8, true)).is_err());
    }

    #[test]
    fn motion_is_ordered_and_limited_without_errors() {
        let mut g = InputGate::new(
            Rec::default(),
            InputLimits {
                moves_per_sec: 100,
                move_burst: 3,
                ..InputLimits::default()
            },
        );
        let inj = InputOutcome::Injected;
        let drop = InputOutcome::Dropped;
        assert_eq!(
            g.on_mouse_move(0, &mv(u32::MAX - 2, 1, 2, false)).unwrap(),
            inj
        );
        // Older and duplicate sequence numbers are stale.
        assert_eq!(
            g.on_mouse_move(0, &mv(u32::MAX - 3, 3, 4, false)).unwrap(),
            drop
        );
        assert_eq!(
            g.on_mouse_move(0, &mv(u32::MAX - 2, 3, 4, false)).unwrap(),
            drop
        );
        assert_eq!(g.stats().dropped_stale_motion, 2);
        g.on_mouse_move(0, &mv(u32::MAX, 5, 6, true)).unwrap(); // wrap-around is newer
        g.on_mouse_move(0, &mv(0, 7, 8, true)).unwrap();
        // The burst (3) is used up: further motion is silently dropped.
        assert_eq!(g.on_mouse_move(0, &mv(1, 9, 9, false)).unwrap(), drop);
        assert_eq!(g.stats().dropped_rate_limited_motion, 1);
        assert_eq!(g.stats().violations, 0);
        assert_eq!(g.injector_mut().calls, vec!["to 1 2", "by 5 6", "by 7 8"]);
    }

    #[test]
    fn focus_loss_and_disconnect_release_everything() {
        let mut g = gate();
        g.on_input(0, &key(0xE0, true)).unwrap();
        g.on_focus_lost().unwrap();
        g.on_mouse_move(0, &mv(100, 1, 1, false)).unwrap();
        g.on_disconnect().unwrap();
        // A new client's sequence starts over.
        assert_eq!(
            g.on_mouse_move(0, &mv(1, 2, 2, false)).unwrap(),
            InputOutcome::Injected
        );
        let calls = &g.injector_mut().calls;
        assert_eq!(calls.iter().filter(|c| *c == "release_all").count(), 2);
    }

    #[test]
    fn bucket_refills_with_time_and_ignores_clock_going_back() {
        let mut b = Bucket::new(1000, 2);
        assert!(b.allow(10 * MS));
        assert!(b.allow(10 * MS));
        assert!(!b.allow(10 * MS));
        assert!(!b.allow(5 * MS), "time going backwards adds nothing");
        assert!(b.allow(11 * MS));
    }
}
