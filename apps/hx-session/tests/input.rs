//! Protocol input events through the gate into a private Xvfb: what X clients observe.

#[path = "../../../crates/hx-capture/tests/common/mod.rs"]
mod common;

use common::Xvfb;
use hx_capture::X11Input;
use hx_proto::datagram::MouseMove;
use hx_proto::pb::{self, ButtonEvent, KeyEvent, ReleaseAll, ScrollEvent, input_event::Event};
use hx_session::input::{InputGate, InputLimits, InputOutcome, InputRejected};
use std::time::{Duration, Instant};
use x11rb::connection::Connection;
use x11rb::protocol::Event as XEvent;
use x11rb::protocol::xproto::{ChangeWindowAttributesAux, ConnectionExt as _, EventMask};
use x11rb::rust_connection::RustConnection;

fn watcher(x: &Xvfb) -> (RustConnection, u32) {
    let (conn, n) = RustConnection::connect(Some(&x.display)).unwrap();
    let root = conn.setup().roots[n].root;
    conn.change_window_attributes(
        root,
        &ChangeWindowAttributesAux::new().event_mask(
            EventMask::KEY_PRESS
                | EventMask::KEY_RELEASE
                | EventMask::BUTTON_PRESS
                | EventMask::BUTTON_RELEASE,
        ),
    )
    .unwrap()
    .check()
    .unwrap();
    (conn, root)
}

/// (kind, detail) of key/button events: `kp`, `kr`, `bp`, `br`.
fn drain(conn: &RustConnection, want: usize) -> Vec<(&'static str, u8)> {
    let end = Instant::now() + Duration::from_secs(3);
    let mut out = Vec::new();
    while out.len() < want && Instant::now() < end {
        match conn.poll_for_event().unwrap() {
            Some(XEvent::KeyPress(e)) => out.push(("kp", e.detail)),
            Some(XEvent::KeyRelease(e)) => out.push(("kr", e.detail)),
            Some(XEvent::ButtonPress(e)) => out.push(("bp", e.detail)),
            Some(XEvent::ButtonRelease(e)) => out.push(("br", e.detail)),
            Some(_) => {}
            None => std::thread::sleep(Duration::from_millis(3)),
        }
    }
    out
}

fn ev(e: Event) -> pb::InputEvent {
    pb::InputEvent { event: Some(e) }
}

#[test]
fn wire_events_drive_the_display_and_disconnect_releases() {
    let Some(x) = Xvfb::start(640, 360) else {
        return;
    };
    let (w, root) = watcher(&x);
    let inj = X11Input::connect(Some(&x.display)).unwrap();
    let mut g = InputGate::new(inj, InputLimits::default());
    let t = 0;

    g.on_input(
        t,
        &ev(Event::Key(KeyEvent {
            scancode: 0x04,
            pressed: true,
        })),
    )
    .unwrap();
    g.on_input(
        t,
        &ev(Event::Key(KeyEvent {
            scancode: 0x04,
            pressed: false,
        })),
    )
    .unwrap();
    g.on_input(
        t,
        &ev(Event::Button(ButtonEvent {
            button: pb::MouseButton::Right as i32,
            pressed: true,
            x: 30,
            y: 40,
        })),
    )
    .unwrap();
    g.on_input(
        t,
        &ev(Event::Button(ButtonEvent {
            button: pb::MouseButton::Right as i32,
            pressed: false,
            x: 30,
            y: 40,
        })),
    )
    .unwrap();
    g.on_input(t, &ev(Event::Scroll(ScrollEvent { dx: 0, dy: 240 })))
        .unwrap();
    assert_eq!(
        drain(&w, 8),
        vec![
            ("kp", 38),
            ("kr", 38),
            ("bp", 3),
            ("br", 3),
            ("bp", 4),
            ("br", 4),
            ("bp", 4),
            ("br", 4)
        ]
    );

    // Pointer datagrams: clamped, ordered.
    let mv = |seq, x, y| MouseMove {
        relative: false,
        seq,
        x,
        y,
    };
    assert_eq!(
        g.on_mouse_move(t, &mv(5, 99_999, -3)).unwrap(),
        InputOutcome::Injected
    );
    assert_eq!(
        g.on_mouse_move(t, &mv(4, 1, 1)).unwrap(),
        InputOutcome::Dropped
    );
    let end = Instant::now() + Duration::from_secs(2);
    let at = loop {
        let p = w.query_pointer(root).unwrap().reply().unwrap();
        if (p.root_x, p.root_y) == (639, 0) || Instant::now() > end {
            break (p.root_x, p.root_y);
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(at, (639, 0));

    // Invalid and flooded input never reaches the display.
    assert!(matches!(
        g.on_input(
            t,
            &ev(Event::Key(KeyEvent {
                scancode: 0x1000,
                pressed: true
            }))
        ),
        Err(InputRejected::Invalid(_))
    ));

    // Hold a modifier, then the client disappears.
    g.on_input(
        t,
        &ev(Event::Key(KeyEvent {
            scancode: 0xE0,
            pressed: true,
        })),
    )
    .unwrap();
    assert_eq!(drain(&w, 1), vec![("kp", 37)]);
    g.on_disconnect().unwrap();
    assert_eq!(drain(&w, 1), vec![("kr", 37)]);
    // release_all on the wire is the same thing and idempotent.
    g.on_input(t, &ev(Event::ReleaseAll(ReleaseAll {})))
        .unwrap();
    assert!(drain(&w, 1).is_empty());
}
