//! End-to-end pipeline tests against a private Xvfb: damage becomes frames, an idle display
//! produces none, control requests take effect, shutdown is clean.

#[path = "../../../crates/hx-capture/tests/common/mod.rs"]
mod common;

use common::{Xvfb, fill_root};
use crossbeam_channel::RecvTimeoutError;
use hx_capture::{CursorEvent, Size, X11Config};
use hx_codec::{Codec, EncodedFrame};
use hx_session::pipeline::{Control, Pipeline, PipelineConfig, PipelineError};
use std::time::{Duration, Instant};

const W: u32 = 640;
const H: u32 = 360;

fn start(x: &Xvfb, tweak: impl FnOnce(&mut PipelineConfig)) -> Pipeline {
    let mut cfg = PipelineConfig {
        capture: X11Config {
            display: Some(x.display.clone()),
            ..X11Config::default()
        },
        ..PipelineConfig::default()
    };
    cfg.encoder.threads = 2;
    tweak(&mut cfg);
    Pipeline::start_x11(cfg).expect("start pipeline")
}

fn next_frame(p: &Pipeline, within: Duration) -> Option<EncodedFrame> {
    p.frames().recv_timeout(within).ok()
}

/// Keep changing the screen until `done` returns true or the time runs out.
fn draw_until(x: &Xvfb, limit: Duration, mut done: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + limit;
    let mut n = 0u32;
    while Instant::now() < end {
        fill_root(
            &x.display,
            (20 + (n % 20) as i16 * 10, 20, 30, 30),
            n.wrapping_mul(0x0001_0203),
        );
        n += 1;
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

#[test]
fn first_frame_is_a_full_idr_then_an_idle_display_produces_nothing() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let p = start(&x, |_| {});
    let first = next_frame(&p, Duration::from_secs(5)).expect("a first frame");
    assert!(first.idr && first.keyframe);
    assert_eq!(first.codec, Codec::H264);
    assert_eq!((first.width, first.height), (W, H));
    let t = first.timing;
    assert!(t.t_damage_ns <= t.t_capture_ns && t.t_capture_ns <= t.t_convert_ns);
    assert!(t.t_convert_ns <= t.t_encode_start_ns && t.t_encode_start_ns <= t.t_encode_end_ns);

    // Idle: nothing is captured, converted or encoded.
    assert!(
        matches!(
            p.frames().recv_timeout(Duration::from_millis(800)),
            Err(RecvTimeoutError::Timeout)
        ),
        "an idle display must not produce frames"
    );
    let s = p.stats();
    assert_eq!((s.captures, s.frames), (1, 1));
    let s = p.shutdown().expect("clean shutdown");
    assert_eq!(s.frames, 1);
}

#[test]
fn damage_produces_frames_with_the_cursor_shape() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let p = start(&x, |_| {});
    next_frame(&p, Duration::from_secs(5)).expect("first frame");
    let mut got = 0;
    assert!(draw_until(&x, Duration::from_secs(5), || {
        got += p.frames().try_iter().count();
        got >= 5
    }));
    let mut shape = false;
    while let Ok(ev) = p.cursor_events().try_recv() {
        shape |= matches!(ev, CursorEvent::Shape(_));
    }
    assert!(shape, "the cursor channel carries the shape");
    let s = p.shutdown().expect("shutdown");
    assert!(s.frames >= 6 && s.stages.total.count == s.frames);
}

#[test]
fn idr_can_be_requested_on_an_idle_display() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let p = start(&x, |_| {});
    next_frame(&p, Duration::from_secs(5)).expect("first frame");
    assert!(p.frames().recv_timeout(Duration::from_millis(300)).is_err());
    p.control().request_idr();
    let f = next_frame(&p, Duration::from_secs(5)).expect("a frame for the IDR request");
    assert!(f.idr, "the forced frame is an IDR");
    // The cursor shape is re-sent for the new client.
    let mut shape = 0;
    while let Ok(ev) = p.cursor_events().try_recv() {
        shape += usize::from(matches!(ev, CursorEvent::Shape(_)));
    }
    assert!(shape >= 1);
}

#[test]
fn bitrate_and_fps_controls_validate_and_apply() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let p = start(&x, |_| {});
    let c: Control = p.control();
    assert!(matches!(
        c.set_bitrate_kbps(1),
        Err(PipelineError::InvalidSetting(_))
    ));
    assert!(c.set_bitrate_kbps(1_000_000).is_err());
    assert!(c.set_max_fps(0).is_err());
    assert!(c.set_max_fps(1000).is_err());
    assert!(c.request_resize(Size::new(0, 100)).is_err());
    c.set_bitrate_kbps(2_000).expect("valid");
    c.set_max_fps(30).expect("valid");
    next_frame(&p, Duration::from_secs(5)).expect("first frame");
    let mut got = 0;
    assert!(draw_until(&x, Duration::from_secs(5), || {
        got += p.frames().try_iter().count();
        got >= 3
    }));
    assert_eq!(c.stats().errors, 0, "{:?}", c.last_error());
    assert!(c.is_running());
}

#[test]
fn frame_rate_ceiling_limits_captures() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let p = start(&x, |cfg| cfg.max_fps = 10);
    next_frame(&p, Duration::from_secs(5)).expect("first frame");
    let before = p.stats().frames;
    let t0 = Instant::now();
    draw_until(&x, Duration::from_secs(2), || false);
    let secs = t0.elapsed().as_secs_f64();
    while p.frames().try_recv().is_ok() {}
    let frames = p.stats().frames - before;
    assert!(frames >= 5, "damage must produce frames, got {frames}");
    assert!(
        frames as f64 <= secs * 10.0 + 3.0,
        "{frames} frames in {secs:.1} s exceeds the 10 fps ceiling"
    );
}

#[test]
fn display_resize_changes_the_picture_size_with_an_idr() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let p = start(&x, |_| {});
    next_frame(&p, Duration::from_secs(5)).expect("first frame");
    p.control()
        .request_resize(Size::new(480, 270))
        .expect("valid size");
    let end = Instant::now() + Duration::from_secs(5);
    let mut resized = None;
    while resized.is_none() && Instant::now() < end {
        if let Some(f) = next_frame(&p, Duration::from_millis(100))
            && (f.width, f.height) == (480, 270)
        {
            resized = Some(f);
        }
    }
    let f = resized.expect("a frame at the new size");
    assert!(f.idr, "a new encoder starts with an IDR");
    assert_eq!(
        p.control().stats().errors,
        0,
        "{:?}",
        p.control().last_error()
    );
}

#[test]
fn slow_consumer_applies_backpressure_instead_of_growing() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let p = start(&x, |cfg| {
        cfg.output_depth = 2;
        cfg.queue_depth = 1;
    });
    // Nobody reads frames while the screen keeps changing.
    draw_until(&x, Duration::from_secs(2), || false);
    assert!(p.frames().len() <= 2, "output queue is bounded");
    let s = p.stats();
    assert!(p.control().is_running(), "backpressure is not a failure");
    // A late consumer drains and the pipeline continues.
    let drained = p.frames().try_iter().count();
    assert!(drained >= 1);
    assert!(s.captures >= s.frames);
    let mut more = 0;
    assert!(draw_until(&x, Duration::from_secs(5), || {
        more += p.frames().try_iter().count();
        more >= 2
    }));
}

#[test]
fn losing_the_display_stops_the_pipeline_with_an_error() {
    let Some(mut x) = Xvfb::start(W, H) else {
        return;
    };
    let p = start(&x, |_| {});
    next_frame(&p, Duration::from_secs(5)).expect("first frame");
    x.kill();
    let end = Instant::now() + Duration::from_secs(5);
    while p.control().is_running() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !p.control().is_running(),
        "the pipeline notices the lost display"
    );
    assert!(p.control().fatal_error().is_some());
    match p.shutdown() {
        Err(PipelineError::Failed(msg)) => assert!(msg.contains("capture"), "{msg}"),
        other => panic!("expected a failure, got {other:?}"),
    }
}

#[test]
fn shutdown_is_prompt_and_disconnects_the_frame_queue() {
    let Some(x) = Xvfb::start(W, H) else { return };
    let p = start(&x, |_| {});
    let frames = p.frames().clone();
    next_frame(&p, Duration::from_secs(5)).expect("first frame");
    let t0 = Instant::now();
    p.shutdown().expect("clean");
    assert!(t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
    while frames.try_recv().is_ok() {}
    assert!(matches!(
        frames.recv_timeout(Duration::from_millis(100)),
        Err(RecvTimeoutError::Disconnected)
    ));
}

#[test]
fn starting_against_a_missing_display_fails_without_threads_left_behind() {
    let cfg = PipelineConfig {
        capture: X11Config {
            display: Some(":9998".to_string()),
            ..X11Config::default()
        },
        ..PipelineConfig::default()
    };
    assert!(matches!(
        Pipeline::start_x11(cfg),
        Err(PipelineError::Capture(_))
    ));
    // Bad encoder settings are reported before any thread starts.
    let Some(x) = Xvfb::start(W, H) else { return };
    let mut cfg = PipelineConfig {
        capture: X11Config {
            display: Some(x.display.clone()),
            ..X11Config::default()
        },
        ..PipelineConfig::default()
    };
    cfg.encoder.crf = 99;
    assert!(matches!(
        Pipeline::start_x11(cfg),
        Err(PipelineError::Encode(_))
    ));
}

/// Paint the root window with a grid of random colours: far more detail than a one frame
/// budget at a low rate holds.
fn paint_dense(display: &str) {
    use x11rb::connection::Connection;
    use x11rb::protocol::xproto::{ChangeGCAux, ConnectionExt as _, CreateGCAux, Rectangle};
    use x11rb::rust_connection::RustConnection;
    let (conn, n) = RustConnection::connect(Some(display)).expect("connect");
    let root = conn.setup().roots[n].root;
    let gc = conn.generate_id().expect("id");
    conn.create_gc(gc, root, &CreateGCAux::new()).expect("gc");
    let mut s = 0x9e37_79b9u32;
    for cy in 0..H / 16 {
        for cx in 0..W / 16 {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            conn.change_gc(gc, &ChangeGCAux::new().foreground(s & 0x00ff_ffff))
                .expect("colour");
            conn.poly_fill_rectangle(
                root,
                gc,
                &[Rectangle {
                    x: (cx * 16) as i16,
                    y: (cy * 16) as i16,
                    width: 16,
                    height: 16,
                }],
            )
            .expect("fill");
        }
    }
    conn.flush().expect("flush");
    conn.get_input_focus()
        .expect("sync")
        .reply()
        .expect("reply");
}

/// Every frame until the pipeline has been quiet for `quiet`.
fn frames_until_quiet(p: &Pipeline, quiet: Duration, limit: Duration) -> Vec<EncodedFrame> {
    let end = Instant::now() + limit;
    let mut out = Vec::new();
    while Instant::now() < end {
        match p.frames().recv_timeout(quiet) {
            Ok(f) => out.push(f),
            Err(_) => break,
        }
    }
    out
}

/// The lossy-link defect (testing.md 2.8): a key frame requested on a busy screen at a low rate
/// is starved by the rate control (a very high QP, a coarse picture), and the screen then stays
/// still, so without more frames the client keeps that picture for good. The pipeline keeps
/// encoding the unchanged screen until the picture is back at the normal quality.
#[test]
fn a_starved_key_frame_is_followed_by_refinement_frames_of_the_static_screen() {
    use hx_session::refine::{SETTLED_BYTES, STARVED_QP};
    let Some(x) = Xvfb::start(W, H) else { return };
    let p = start(&x, |cfg| cfg.encoder.bitrate_kbps = 1_000);
    next_frame(&p, Duration::from_secs(5)).expect("first frame");
    paint_dense(&x.display);
    // The painted screen is sent (and refined) first; wait until the pipeline is quiet.
    let settled = frames_until_quiet(&p, Duration::from_millis(500), Duration::from_secs(20));
    assert!(!settled.is_empty(), "the painted screen is captured");

    p.control().request_idr();
    let run = frames_until_quiet(&p, Duration::from_millis(500), Duration::from_secs(20));
    let idr = run.first().expect("a frame for the request");
    assert!(idr.idr, "the request is answered with an IDR");
    assert!(
        idr.qp.is_some_and(|q| q >= STARVED_QP),
        "the premise: the key frame of this screen at 1 Mbit/s is starved (qp {:?})",
        idr.qp
    );
    assert!(
        run.len() >= 3,
        "a starved key frame needs refinement frames of the unchanged screen, got {} frame(s)",
        run.len() - 1
    );
    assert!(run[1..].iter().all(|f| !f.idr), "refinements are P frames");
    let last = run.last().expect("last");
    assert!(
        last.qp.is_some_and(|q| q < STARVED_QP) && last.bytes().len() <= SETTLED_BYTES,
        "the run ends when a pass has nothing left to add (last qp {:?}, {} B)",
        last.qp,
        last.bytes().len()
    );
    let s = p.shutdown().expect("shutdown");
    assert_eq!(s.errors, 0);
}
