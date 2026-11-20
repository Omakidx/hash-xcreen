//! Input injection against a private Xvfb: what a second X client observes.

mod common;

use common::Xvfb;
use hx_capture::{Button, InputError, InputInjector, Size, X11Input};
use std::time::{Duration, Instant};
use x11rb::connection::Connection;
use x11rb::protocol::Event;
use x11rb::protocol::xproto::{ChangeWindowAttributesAux, ConnectionExt as _, EventMask};
use x11rb::rust_connection::RustConnection;

const W: u32 = 640;
const H: u32 = 360;
/// Modifier bits in a core event's `state`.
const SHIFT: u16 = 0x01;
const CONTROL: u16 = 0x04;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Seen {
    Key {
        press: bool,
        code: u8,
        state: u16,
    },
    Button {
        press: bool,
        detail: u8,
        x: i16,
        y: i16,
    },
}

struct Listener {
    conn: RustConnection,
    root: u32,
}

impl Listener {
    fn new(x: &Xvfb) -> Self {
        let (conn, n) = RustConnection::connect(Some(&x.display)).expect("connect");
        let root = conn.setup().roots[n].root;
        conn.change_window_attributes(
            root,
            &ChangeWindowAttributesAux::new().event_mask(
                EventMask::KEY_PRESS
                    | EventMask::KEY_RELEASE
                    | EventMask::BUTTON_PRESS
                    | EventMask::BUTTON_RELEASE
                    | EventMask::POINTER_MOTION,
            ),
        )
        .expect("select")
        .check()
        .expect("select");
        Self { conn, root }
    }

    /// Key and button events seen within `wait` (the loop ends early after `want` events).
    fn collect(&self, want: usize, wait: Duration) -> Vec<Seen> {
        let end = Instant::now() + wait;
        let mut out = Vec::new();
        while Instant::now() < end && out.len() < want {
            match self.conn.poll_for_event().expect("poll") {
                Some(Event::KeyPress(e)) => out.push(Seen::Key {
                    press: true,
                    code: e.detail,
                    state: u16::from(e.state),
                }),
                Some(Event::KeyRelease(e)) => out.push(Seen::Key {
                    press: false,
                    code: e.detail,
                    state: u16::from(e.state),
                }),
                Some(Event::ButtonPress(e)) => out.push(Seen::Button {
                    press: true,
                    detail: e.detail,
                    x: e.root_x,
                    y: e.root_y,
                }),
                Some(Event::ButtonRelease(e)) => out.push(Seen::Button {
                    press: false,
                    detail: e.detail,
                    x: e.root_x,
                    y: e.root_y,
                }),
                Some(_) => {}
                None => std::thread::sleep(Duration::from_millis(5)),
            }
        }
        out
    }

    fn pointer(&self) -> (i16, i16) {
        let p = self
            .conn
            .query_pointer(self.root)
            .expect("query")
            .reply()
            .expect("reply");
        (p.root_x, p.root_y)
    }

    fn modifiers(&self) -> u16 {
        let p = self
            .conn
            .query_pointer(self.root)
            .expect("query")
            .reply()
            .expect("reply");
        u16::from(p.mask) & (SHIFT | CONTROL | 0x08)
    }

    /// Wait until the pointer is at `at`.
    fn pointer_reaches(&self, at: (i16, i16)) -> (i16, i16) {
        let end = Instant::now() + Duration::from_secs(2);
        loop {
            let p = self.pointer();
            if p == at || Instant::now() > end {
                return p;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

const WAIT: Duration = Duration::from_secs(2);
const QUIET: Duration = Duration::from_millis(250);

fn input(x: &Xvfb) -> X11Input {
    X11Input::connect(Some(&x.display)).expect("connect input")
}

#[test]
fn physical_keys_arrive_as_evdev_keycodes() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let l = Listener::new(&x);
    let mut inp = input(&x);
    inp.key(0x04, true).unwrap(); // HID A -> evdev 30 -> X keycode 38
    inp.key(0x04, false).unwrap();
    inp.key(0x28, true).unwrap(); // Enter -> 36
    inp.key(0x28, false).unwrap();
    assert_eq!(
        l.collect(4, WAIT),
        vec![
            Seen::Key {
                press: true,
                code: 38,
                state: 0
            },
            Seen::Key {
                press: false,
                code: 38,
                state: 0
            },
            Seen::Key {
                press: true,
                code: 36,
                state: 0
            },
            Seen::Key {
                press: false,
                code: 36,
                state: 0
            },
        ]
    );
}

#[test]
fn keys_do_not_depend_on_the_keyboard_layout() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let l = Listener::new(&x);
    let mut inp = input(&x);
    let setup = l.conn.setup();
    let (min, max) = (setup.min_keycode, setup.max_keycode);
    let keysym_of = |code: u8| {
        l.conn
            .get_keyboard_mapping(code, 1)
            .unwrap()
            .reply()
            .unwrap()
            .keysyms[0]
    };
    let before = keysym_of(38);
    assert_eq!(before, 'a' as u32, "keycode 38 starts as the letter a");
    // Remap the key under the injector's feet (what switching to another layout does).
    l.conn
        .change_keyboard_mapping(1, 38, 1, &['z' as u32])
        .unwrap()
        .check()
        .unwrap();
    assert_eq!(keysym_of(38), 'z' as u32);
    assert!((min..=max).contains(&38));
    inp.key(0x04, true).unwrap();
    inp.key(0x04, false).unwrap();
    let seen = l.collect(2, WAIT);
    assert_eq!(
        seen.first(),
        Some(&Seen::Key {
            press: true,
            code: 38,
            state: 0
        }),
        "the same physical key, whatever symbol it carries now"
    );
}

#[test]
fn modifiers_apply_and_release_all_clears_them() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let l = Listener::new(&x);
    let mut inp = input(&x);
    inp.key(0xE0, true).unwrap(); // left Ctrl
    inp.key(0xE1, true).unwrap(); // left Shift
    inp.key(0x04, true).unwrap();
    let seen = l.collect(3, WAIT);
    assert_eq!(
        seen[2],
        Seen::Key {
            press: true,
            code: 38,
            state: CONTROL | SHIFT
        }
    );
    assert_eq!(l.modifiers() & (CONTROL | SHIFT), CONTROL | SHIFT);
    assert_eq!(inp.held(), (3, 0));

    // Focus lost: everything held is released, once.
    inp.release_all().unwrap();
    let rel = l.collect(3, WAIT);
    assert_eq!(rel.len(), 3);
    assert!(
        rel.iter()
            .all(|e| matches!(e, Seen::Key { press: false, .. }))
    );
    assert_eq!(l.modifiers() & (CONTROL | SHIFT), 0);
    assert_eq!(inp.held(), (0, 0));
    inp.release_all().unwrap();
    assert!(l.collect(1, QUIET).is_empty(), "nothing left to release");
}

#[test]
fn dropping_the_injector_releases_held_input() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let l = Listener::new(&x);
    {
        let mut inp = input(&x);
        inp.key(0xE0, true).unwrap();
        inp.button(Button::Left, true, Some((10, 10))).unwrap();
        assert_eq!(l.collect(2, WAIT).len(), 2);
        assert_eq!(l.modifiers() & CONTROL, CONTROL);
    } // the client vanished
    let rel = l.collect(2, WAIT);
    assert_eq!(rel.len(), 2, "{rel:?}");
    assert_eq!(l.modifiers() & CONTROL, 0);
}

#[test]
fn repeated_and_stray_key_events_are_ignored() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let l = Listener::new(&x);
    let mut inp = input(&x);
    inp.key(0x04, false).unwrap(); // release of a key that is not held
    inp.key(0x04, true).unwrap();
    inp.key(0x04, true).unwrap(); // repeat of a held key
    inp.key(0x04, false).unwrap();
    assert_eq!(l.collect(5, QUIET * 2).len(), 2);
}

#[test]
fn invalid_usages_are_rejected_without_side_effects() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let l = Listener::new(&x);
    let mut inp = input(&x);
    for usage in [0x00, 0x03, 0x82, 0xE8, 0x1_0004, u32::MAX] {
        assert!(
            matches!(inp.key(usage, true), Err(InputError::UnmappedKey(u)) if u == usage),
            "{usage:#x}"
        );
    }
    assert_eq!(inp.held(), (0, 0));
    assert!(l.collect(1, QUIET).is_empty());
}

#[test]
fn absolute_motion_is_clamped_to_the_screen() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let l = Listener::new(&x);
    let mut inp = input(&x);
    inp.move_to(100, 120).unwrap();
    assert_eq!(l.pointer_reaches((100, 120)), (100, 120));
    inp.move_to(10_000, 5_000).unwrap();
    assert_eq!(l.pointer_reaches((W as i16 - 1, H as i16 - 1)), (639, 359));
    inp.move_to(-7, i32::MIN).unwrap();
    assert_eq!(l.pointer_reaches((0, 0)), (0, 0));
    inp.move_to(i32::MAX, i32::MAX).unwrap();
    assert_eq!(l.pointer_reaches((639, 359)), (639, 359));
}

#[test]
fn relative_motion_moves_by_the_delta_and_stops_at_the_edge() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let l = Listener::new(&x);
    let mut inp = input(&x);
    inp.move_to(200, 200).unwrap();
    assert_eq!(l.pointer_reaches((200, 200)), (200, 200));
    inp.move_by(5, -7).unwrap();
    assert_eq!(l.pointer_reaches((205, 193)), (205, 193));
    inp.move_by(i32::MIN, i32::MAX).unwrap(); // clamped step, then the screen edge
    assert_eq!(l.pointer_reaches((0, 359)), (0, 359));
    inp.move_by(0, 0).unwrap();
}

#[test]
fn buttons_press_at_the_given_position_and_release() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let l = Listener::new(&x);
    let mut inp = input(&x);
    inp.button(Button::Left, true, Some((50, 60))).unwrap();
    inp.button(Button::Left, true, Some((50, 60))).unwrap(); // duplicate press
    inp.button(Button::Left, false, None).unwrap();
    inp.button(Button::Right, true, Some((9_999, -5))).unwrap(); // clamped
    inp.button(Button::Right, false, None).unwrap();
    inp.button(Button::Back, true, None).unwrap();
    inp.button(Button::Back, false, None).unwrap();
    let seen = l.collect(6, WAIT);
    assert_eq!(
        seen,
        vec![
            Seen::Button {
                press: true,
                detail: 1,
                x: 50,
                y: 60
            },
            Seen::Button {
                press: false,
                detail: 1,
                x: 50,
                y: 60
            },
            Seen::Button {
                press: true,
                detail: 3,
                x: 639,
                y: 0
            },
            Seen::Button {
                press: false,
                detail: 3,
                x: 639,
                y: 0
            },
            Seen::Button {
                press: true,
                detail: 8,
                x: 639,
                y: 0
            },
            Seen::Button {
                press: false,
                detail: 8,
                x: 639,
                y: 0
            },
        ]
    );
}

fn clicks(seen: &[Seen]) -> Vec<u8> {
    seen.iter()
        .filter_map(|e| match e {
            Seen::Button {
                press: true,
                detail,
                ..
            } => Some(*detail),
            _ => None,
        })
        .collect()
}

#[test]
fn high_resolution_scroll_accumulates_into_wheel_clicks() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let l = Listener::new(&x);
    let mut inp = input(&x);
    inp.scroll(0, 60).unwrap();
    assert!(
        l.collect(1, QUIET).is_empty(),
        "half a notch is not a click"
    );
    inp.scroll(0, 60).unwrap();
    assert_eq!(clicks(&l.collect(2, WAIT)), vec![4]);
    inp.scroll(0, -240).unwrap();
    assert_eq!(clicks(&l.collect(4, WAIT)), vec![5, 5]);
    inp.scroll(120, 0).unwrap();
    inp.scroll(-120, 0).unwrap();
    assert_eq!(clicks(&l.collect(4, WAIT)), vec![7, 6]);
    // Many small steps add up; a reversal discards the unfinished notch.
    for _ in 0..12 {
        inp.scroll(0, 10).unwrap();
    }
    assert_eq!(clicks(&l.collect(2, WAIT)), vec![4]);
    inp.scroll(0, 100).unwrap();
    inp.scroll(0, -100).unwrap();
    assert!(l.collect(1, QUIET).is_empty());
    // Hostile magnitude: bounded burst.
    inp.scroll(0, i32::MAX).unwrap();
    let burst = clicks(&l.collect(64, WAIT));
    assert_eq!(burst.len(), hx_capture::input::MAX_SCROLL_CLICKS as usize);
}

#[test]
fn clamping_follows_a_screen_resize() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let mut inp = input(&x);
    assert_eq!(inp.screen_size(), Size::new(W, H));
    inp.set_screen_size(Size::new(100, 50));
    let l = Listener::new(&x);
    inp.move_to(500, 500).unwrap();
    assert_eq!(l.pointer_reaches((99, 49)), (99, 49));
}

#[test]
fn a_dead_display_is_a_fatal_error() {
    let Some(mut x) = Xvfb::start(W, H) else {
        return;
    };
    let mut inp = input(&x);
    x.kill();
    let mut err = None;
    for _ in 0..50 {
        if let Err(e) = inp.key(0x04, true) {
            err = Some(e);
            break;
        }
        let _ = inp.key(0x04, false);
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(err.expect("an error after the server died").is_fatal());
}
