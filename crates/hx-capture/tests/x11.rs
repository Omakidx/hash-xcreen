//! Integration tests against a private Xvfb.

mod common;

use common::{Xvfb, fill_root};
use hx_capture::{Capture, CaptureError, CursorEvent, Rect, Size, X11Capture, X11Config};
use std::time::{Duration, Instant};
use x11rb::connection::Connection;
use x11rb::protocol::xproto::ConnectionExt as _;
use x11rb::protocol::xtest::ConnectionExt as _;
use x11rb::rust_connection::RustConnection;

const W: u32 = 640;
const H: u32 = 360;

fn connect(x: &Xvfb) -> X11Capture {
    X11Capture::connect(&X11Config {
        display: Some(x.display.clone()),
        ..X11Config::default()
    })
    .expect("connect capture")
}

/// Poll the capture's event stream until `cond` holds or `limit` passes.
fn wait_until(
    cap: &mut X11Capture,
    limit: Duration,
    mut cond: impl FnMut(&X11Capture) -> bool,
) -> bool {
    let end = Instant::now() + limit;
    while Instant::now() < end {
        cap.wait(Some(Duration::from_millis(20))).expect("wait");
        if cond(cap) {
            return true;
        }
    }
    false
}

fn pixel(data: &[u8], stride: usize, x: usize, y: usize) -> (u8, u8, u8) {
    let o = y * stride + x * 4;
    (data[o + 2], data[o + 1], data[o])
}

#[test]
fn idle_display_produces_no_frames() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let mut cap = connect(&x);
    assert_eq!(cap.size(), Size::new(W, H));
    assert!(cap.uses_shared_memory(), "Xvfb supports MIT-SHM fd passing");
    assert!(!wait_until(&mut cap, Duration::from_millis(500), |c| {
        c.damage_pending()
    }));
    assert!(cap.grab(Duration::from_millis(5)).expect("grab").is_none());
}

#[test]
fn damage_produces_a_frame_with_the_drawn_pixels() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let mut cap = connect(&x);
    fill_root(&x.display, (100, 50, 40, 30), 0x00ff_8000);
    assert!(wait_until(&mut cap, Duration::from_secs(2), |c| {
        c.damage_pending()
    }));
    let frame = cap
        .grab(Duration::from_millis(50))
        .expect("grab")
        .expect("a frame");
    assert_eq!(frame.size(), Size::new(W, H));
    assert_eq!(frame.data().len(), frame.stride() * H as usize);
    assert_eq!(
        pixel(frame.data(), frame.stride(), 110, 60),
        (0xff, 0x80, 0x00)
    );
    let bounds = frame.damage_bounds();
    assert!(bounds.x <= 100 && bounds.y <= 50);
    assert!(bounds.x + bounds.width as i32 >= 140 && bounds.y + bounds.height as i32 >= 80);
    assert!(frame.t_capture_ns() >= frame.t_damage_ns());
    drop(frame);
    // Consumed: nothing pending until the next change.
    assert!(!cap.damage_pending());
    assert!(cap.grab(Duration::from_millis(5)).expect("grab").is_none());

    // A second change gives a second frame, damage limited to the new area.
    fill_root(&x.display, (300, 200, 20, 20), 0x0000_00ff);
    assert!(wait_until(&mut cap, Duration::from_secs(2), |c| {
        c.damage_pending()
    }));
    let frame = cap
        .grab(Duration::from_millis(50))
        .expect("grab")
        .expect("frame");
    assert_eq!(frame.seq(), 1);
    assert_eq!(frame.damage_bounds(), Rect::new(300, 200, 20, 20));
    assert_eq!(pixel(frame.data(), frame.stride(), 305, 205), (0, 0, 0xff));
}

#[test]
fn forced_frame_covers_the_whole_screen() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let mut cap = connect(&x);
    cap.force_full_frame();
    let frame = cap
        .grab(Duration::from_millis(50))
        .expect("grab")
        .expect("frame");
    assert_eq!(frame.damage(), &[Rect::full(Size::new(W, H))]);
}

#[test]
fn buffer_pool_applies_backpressure_and_recycles() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let mut cap = X11Capture::connect(&X11Config {
        display: Some(x.display.clone()),
        buffers: 2,
        ..X11Config::default()
    })
    .expect("connect");
    cap.force_full_frame();
    let a = cap
        .grab(Duration::from_millis(50))
        .expect("grab")
        .expect("a");
    cap.force_full_frame();
    let b = cap
        .grab(Duration::from_millis(50))
        .expect("grab")
        .expect("b");
    cap.force_full_frame();
    // Both buffers are out: no frame, and the pending capture is kept.
    assert!(cap.grab(Duration::from_millis(20)).expect("grab").is_none());
    assert!(cap.damage_pending());
    drop(a);
    assert!(cap.grab(Duration::from_millis(50)).expect("grab").is_some());
    drop(b);
}

#[test]
fn cursor_shape_and_position_events() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let mut cap = connect(&x);
    let mut events = Vec::new();
    cap.drain_cursor(&mut |e| events.push(e));
    assert!(
        events.iter().any(|e| matches!(
            e,
            CursorEvent::Shape(s) if s.width > 0 && s.argb.len() == usize::from(s.width) * usize::from(s.height)
        )),
        "initial cursor shape expected, got {} events",
        events.len()
    );

    // Move the pointer with XTest, which produces raw motion like a real device.
    let (conn, n) = RustConnection::connect(Some(&x.display)).expect("connect");
    let root = conn.setup().roots[n].root;
    conn.xtest_fake_input(6, 0, 0, root, 222, 111, 0)
        .expect("fake motion"); // 6 = MotionNotify
    conn.flush().expect("flush");
    conn.get_input_focus()
        .expect("sync")
        .reply()
        .expect("reply");

    let mut moved = None;
    let end = Instant::now() + Duration::from_secs(2);
    while moved.is_none() && Instant::now() < end {
        cap.wait(Some(Duration::from_millis(20))).expect("wait");
        cap.drain_cursor(&mut |e| {
            if let CursorEvent::Position(p) = e {
                moved = Some(p);
            }
        });
    }
    let p = moved.expect("a position event");
    assert_eq!((p.x, p.y), (222, 111));

    // A re-request yields the shape again.
    cap.refresh_cursor().expect("refresh");
    let mut again = false;
    cap.drain_cursor(&mut |e| again |= matches!(e, CursorEvent::Shape(_)));
    assert!(again);
}

#[test]
fn resize_changes_frame_size() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let mut cap = connect(&x);
    // Xvfb allows shrinking only (its RandR maximum is the initial size); servers with a
    // larger virtual size (Xorg dummy) also allow growing.
    cap.request_resize(Size::new(480, 270)).expect("resize");
    assert_eq!(cap.size(), Size::new(480, 270));
    let wake = cap.wait(Some(Duration::from_millis(100))).expect("wait");
    assert_eq!(wake.resized, Some(Size::new(480, 270)));
    assert!(cap.damage_pending(), "a resize forces a full frame");
    let frame = cap
        .grab(Duration::from_millis(50))
        .expect("grab")
        .expect("frame");
    assert_eq!(frame.size(), Size::new(480, 270));
    assert_eq!(frame.data().len(), 480 * 4 * 270);
}

#[test]
fn invalid_resize_is_a_typed_error() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let mut cap = connect(&x);
    let err = cap
        .request_resize(Size::new(100_000, 100_000))
        .expect_err("too large");
    assert!(matches!(err, CaptureError::InvalidSize { .. }), "{err}");
    let err = cap
        .request_resize(Size::new(W * 2, H * 2))
        .expect_err("above the server maximum");
    assert!(matches!(err, CaptureError::InvalidSize { .. }), "{err}");
}

#[test]
fn connecting_to_a_missing_display_fails_cleanly() {
    let err = X11Capture::connect(&X11Config {
        display: Some(":9999".to_string()),
        ..X11Config::default()
    })
    .err()
    .expect("no such display");
    assert!(err.is_fatal(), "{err}");
}
