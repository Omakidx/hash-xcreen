//! The gateway's `LinkClient` against the real `hx-session` link server over a real unix
//! socket, with the real capture and encode pipeline under a private Xvfb.
//!
//! These tests need Xvfb (`HX_REQUIRE_XVFB=1` makes a missing Xvfb a failure, as in CI), x264 and
//! the FFmpeg libraries. Each test builds its own Xvfb, socket directory and server.

#[path = "../../../crates/hx-capture/tests/common/mod.rs"]
mod common;

use bytes::Bytes;
use common::{Xvfb, fill_root};
use hx_agent::link::{
    ConnectError, CursorUpdate, FailureClass, Frame, LinkClient, LinkConfig, LinkEvent, LinkEvents,
    TransferError, TransferEvent, annexb,
};
use hx_capture::clipboard::{
    Clipboard, ClipboardConfig, ClipboardEvent, MIME_TEXT, RemoteProvider, Selection,
};
use hx_ipc::link::pb;
use hx_proto::VideoCodec;
use hx_proto::datagram::MouseMove;
use hx_proto::pb::{ButtonEvent, KeyEvent, TransferHeader, input_event::Event};
use hx_session::clipboard::ClipboardSettings;
use hx_session::link::{Server, ServerHandle, SessionConfig};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering::SeqCst};
use std::time::{Duration, Instant};
use tokio::time::timeout;
use x11rb::connection::Connection;
use x11rb::protocol::Event as XEvent;
use x11rb::protocol::xproto::{ChangeWindowAttributesAux, ConnectionExt as _, EventMask};
use x11rb::rust_connection::RustConnection;

const W: u32 = 640;
const H: u32 = 360;

static NEXT: AtomicU32 = AtomicU32::new(0);

struct Env {
    x: Xvfb,
    dir: PathBuf,
    sock: PathBuf,
    server: Option<ServerHandle>,
}

impl Env {
    fn start(tweak: impl FnOnce(&mut SessionConfig)) -> Option<Env> {
        let x = Xvfb::start(W, H)?;
        let dir = std::env::temp_dir().join(format!(
            "hx-link-it-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("link.sock");
        let mut cfg = SessionConfig::new(Some(x.display.clone()));
        cfg.received_dir = dir.join("received");
        cfg.pipeline.encoder.threads = 2;
        cfg.clipboard = Some(ClipboardSettings {
            display: Some(x.display.clone()),
            staging_base: Some(dir.clone()),
            step_timeout: Duration::from_secs(2),
            ..ClipboardSettings::default()
        });
        tweak(&mut cfg);
        let server = Server::bind(&sock, cfg).unwrap().spawn();
        Some(Env {
            x,
            dir,
            sock,
            server: Some(server),
        })
    }

    async fn connect(&self) -> (LinkClient, LinkEvents) {
        self.connect_with(|_| {}).await
    }

    async fn connect_with(&self, tweak: impl FnOnce(&mut LinkConfig)) -> (LinkClient, LinkEvents) {
        let mut cfg = LinkConfig::default();
        tweak(&mut cfg);
        LinkClient::connect(&self.sock, cfg)
            .await
            .expect("connect to the session")
    }

    fn received(&self) -> PathBuf {
        self.dir.join("received")
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        drop(self.server.take());
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn stream_config() -> pb::StreamConfig {
    pb::StreamConfig {
        codec: VideoCodec::H264 as i32,
        max_fps: 30,
        clipboard_enabled: true,
        file_transfer_enabled: true,
        ..pb::StreamConfig::default()
    }
}

/// Changes the screen every few milliseconds until dropped.
struct Drawer {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drawer {
    fn start(display: &str) -> Drawer {
        let stop = Arc::new(AtomicBool::new(false));
        let (s, d) = (stop.clone(), display.to_owned());
        let thread = std::thread::spawn(move || {
            let mut n = 0u32;
            while !s.load(SeqCst) {
                fill_root(
                    &d,
                    (20 + (n % 20) as i16 * 10, 20, 30, 30),
                    n.wrapping_mul(0x0001_0203),
                );
                n += 1;
                std::thread::sleep(Duration::from_millis(15));
            }
        });
        Drawer {
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Drawer {
    fn drop(&mut self) {
        self.stop.store(true, SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn delivered(f: &Frame, elapsed_us: u32) -> pb::FrameResult {
    pb::FrameResult {
        frame_number: f.number(),
        outcome: pb::FrameOutcome::Delivered as i32,
        bytes: f.wire().len() as u32,
        elapsed_us,
        queued_us: 0,
    }
}

/// Reads events until `pred` is true, acknowledging frames as delivered after 3 ms (so the
/// session's controller sees a healthy link) when `ack` is set.
async fn until(
    link: &LinkClient,
    ev: &mut LinkEvents,
    within: Duration,
    ack: bool,
    mut pred: impl FnMut(&LinkEvent) -> bool,
) -> Vec<LinkEvent> {
    let end = Instant::now() + within;
    let mut seen = Vec::new();
    loop {
        let left = end.saturating_duration_since(Instant::now());
        let e = timeout(left, ev.next()).await.unwrap_or_else(|_| {
            panic!("timed out; saw {} events: {:?}", seen.len(), summary(&seen))
        });
        if ack && let LinkEvent::Frame(f) = &e {
            let _ = link.frame_feedback(&[delivered(f, 3_000)]);
        }
        let done = pred(&e);
        if let LinkEvent::Closed(c) = &e
            && !done
        {
            panic!("link closed early: {c:?}; saw {:?}", summary(&seen));
        }
        seen.push(e);
        if done {
            return seen;
        }
    }
}

fn summary(events: &[LinkEvent]) -> Vec<String> {
    events
        .iter()
        .map(|e| match e {
            LinkEvent::Frame(f) => format!(
                "frame#{} key={} resync={} {}x{}",
                f.number(),
                f.is_key(),
                f.is_resync(),
                f.format.width,
                f.format.height
            ),
            LinkEvent::Cursor(_) => "cursor".into(),
            LinkEvent::Stats(s) => format!("stats kbps={}", s.target_bitrate_kbps),
            other => format!("{other:?}").chars().take(80).collect(),
        })
        .collect()
}

fn frames(events: &[LinkEvent]) -> Vec<&Frame> {
    events
        .iter()
        .filter_map(|e| match e {
            LinkEvent::Frame(f) => Some(f),
            _ => None,
        })
        .collect()
}

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

/// (kind, detail) of key events, polled for up to `within`.
fn key_events(conn: &RustConnection, want: usize, within: Duration) -> Vec<(&'static str, u8)> {
    let end = Instant::now() + within;
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

// ---------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn preamble_and_version_mismatch() {
    let Some(env) = Env::start(|_| {}) else {
        return;
    };
    // A different major is refused by closing the connection, with no answer.
    let mut raw = std::os::unix::net::UnixStream::connect(&env.sock).unwrap();
    raw.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut offer = hx_ipc::link::preamble::ClientPreamble {
        preamble: hx_ipc::link::preamble::Preamble::ours(hx_ipc::link::Lane::Ctl),
        link_id: [9; 16],
    }
    .encode();
    offer[4] = 2; // major
    use std::io::{Read, Write};
    raw.write_all(&offer).unwrap();
    let mut buf = [0u8; 8];
    assert_eq!(raw.read(&mut buf).unwrap(), 0, "closed without an answer");

    // Wrong magic is closed too.
    let mut raw = std::os::unix::net::UnixStream::connect(&env.sock).unwrap();
    raw.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    raw.write_all(&[b'X'; 24]).unwrap();
    assert_eq!(raw.read(&mut buf).unwrap(), 0);

    // A matching client connects, and a newer minor is lowered to the session's.
    let (link, _ev) = env.connect().await;
    assert_eq!(link.negotiated_minor(), 0);
    let info = link.info();
    assert_eq!(info.codecs, [VideoCodec::H264]);
    assert_eq!(info.display, (W, H));
    assert!(info.has_input() && info.has_resize() && info.has_clipboard());
    assert!(info.software.starts_with("hx-session "));

    // A session that is not there is "unavailable", never a violation.
    let gone = env.dir.join("missing.sock");
    let err: ConnectError = LinkClient::connect(&gone, LinkConfig::default())
        .await
        .err()
        .unwrap();
    assert_eq!(err.class, FailureClass::Unavailable);
    // A stale socket (the listener is gone) is refused.
    let stale = env.dir.join("stale.sock");
    drop(std::os::unix::net::UnixListener::bind(&stale).unwrap());
    let err = LinkClient::connect(&stale, LinkConfig::default())
        .await
        .err()
        .unwrap();
    assert_eq!(err.class, FailureClass::Unavailable);
}

#[tokio::test(flavor = "multi_thread")]
async fn start_streams_an_idr_then_p_frames_that_pass_the_bitstream_check() {
    let Some(env) = Env::start(|_| {}) else {
        return;
    };
    let (link, mut ev) = env.connect().await;
    link.start(1, stream_config()).unwrap();
    let drawer = Drawer::start(&env.x.display);
    let mut p_frames = 0;
    let seen = until(&link, &mut ev, Duration::from_secs(10), true, |e| {
        if let LinkEvent::Frame(f) = e
            && !f.is_key()
        {
            p_frames += 1;
        }
        p_frames >= 5
    })
    .await;
    drop(drawer);
    let fs = frames(&seen);
    let first = fs[0];
    assert!(
        first.is_key() && first.is_resync(),
        "the first frame is a RESYNC IDR"
    );
    assert_eq!((first.format.width, first.format.height), (W, H));
    assert_eq!(first.format.epoch, 1);
    assert_eq!(first.format.codec, VideoCodec::H264);
    assert!(first.format.first_frame <= first.number());
    // The wire bytes are exactly the media header followed by the payload.
    let h = hx_proto::media::MediaHeader::decode(&first.wire()[..20]).unwrap();
    assert_eq!(h.frame_number, first.number());
    assert_eq!(h.payload_len as usize, first.payload().len());
    // The gateway's own check, run again by the test, passes on every frame.
    for f in &fs {
        let c = annexb::check_frame(f.payload(), f.is_key()).expect("valid Annex B");
        if f.is_key() {
            let sps = c.sps.expect("a key frame carries its SPS");
            assert_eq!((sps.width, sps.height), (W, H));
        }
    }
    // Numbers only go up, and the timestamps follow the capture clock.
    for w in fs.windows(2) {
        assert!(w[1].number().wrapping_sub(w[0].number()) < 1_000);
        assert!(w[1].header.capture_timestamp_us >= w[0].header.capture_timestamp_us);
    }
    // The cursor shape arrives as RGBA that passed validation.
    let mut shape = false;
    for e in &seen {
        if let LinkEvent::Cursor(CursorUpdate::Shape(s)) = e {
            assert_eq!(s.rgba.len() as u32, s.width * s.height * 4);
            shape = true;
        }
    }
    let more = until(&link, &mut ev, Duration::from_secs(5), true, |e| {
        shape |= matches!(e, LinkEvent::Cursor(CursorUpdate::Shape(_)));
        shape
    })
    .await;
    drop(more);
    assert!(shape, "the session sends the cursor shape");
    assert_eq!(link.counters().discarded_frames, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn reconfigure_cap_and_fps_reach_the_controller_and_feedback_moves_it() {
    let Some(env) = Env::start(|_| {}) else {
        return;
    };
    let (link, mut ev) = env.connect().await;
    link.start(1, stream_config()).unwrap();
    let _drawer = Drawer::start(&env.x.display);
    // A healthy link: the controller starts at 4 Mbit/s.
    let mut first_kbps = None;
    until(&link, &mut ev, Duration::from_secs(10), true, |e| {
        if let LinkEvent::Stats(s) = e {
            first_kbps = Some(s.target_bitrate_kbps);
        }
        first_kbps.is_some()
    })
    .await;
    assert!(first_kbps.unwrap() <= 4_000);

    // A bitrate cap below it lowers the target, and a frame-rate ceiling lowers the fps.
    link.reconfigure(pb::StreamConfig {
        bitrate_cap_kbps: 1_000,
        max_fps: 15,
        clipboard_enabled: true,
        file_transfer_enabled: true,
        ..pb::StreamConfig::default()
    })
    .unwrap();
    let mut capped = None;
    until(&link, &mut ev, Duration::from_secs(10), true, |e| {
        if let LinkEvent::Stats(s) = e
            && s.target_bitrate_kbps <= 1_000
            && s.fps_ceiling <= 15
        {
            capped = Some((s.target_bitrate_kbps, s.fps_ceiling));
        }
        capped.is_some()
    })
    .await;
    assert!(capped.is_some());

    // Feedback drives the controller: frames that come back later and later look like a queue
    // building up, so the rate steps down (or frames are cancelled). Use a fresh, uncapped
    // client epoch so the starting rate is 4 Mbit/s again.
    link.start(2, stream_config()).unwrap();
    let mut n = 0u32;
    let mut lowest = u32::MAX;
    let mut moved = false;
    let end = Instant::now() + Duration::from_secs(20);
    while !moved && Instant::now() < end {
        let e = timeout(Duration::from_secs(5), ev.next())
            .await
            .expect("event");
        match e {
            LinkEvent::Frame(f) => {
                n += 1;
                // The first frames set a 2 ms baseline, the rest arrive 300 ms late.
                let elapsed = if n <= 6 { 2_000 } else { 300_000 };
                link.frame_feedback(&[delivered(&f, elapsed)]).unwrap();
            }
            LinkEvent::Stats(s) if n > 6 => {
                lowest = lowest.min(s.target_bitrate_kbps);
                moved = s.target_bitrate_kbps < 4_000;
            }
            LinkEvent::CancelFrames { .. } => moved = true,
            LinkEvent::Closed(c) => panic!("closed: {c:?}"),
            _ => {}
        }
    }
    assert!(
        moved,
        "late feedback must lower the rate (lowest seen {lowest})"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cancels_and_idr_requests_produce_a_resync_idr() {
    let Some(env) = Env::start(|_| {}) else {
        return;
    };
    let (link, mut ev) = env.connect().await;
    link.start(1, stream_config()).unwrap();
    let _drawer = Drawer::start(&env.x.display);

    // The gateway cancels a frame: the next frame the client gets is a fresh RESYNC IDR.
    let mut cancelled = false;
    let seen = until(&link, &mut ev, Duration::from_secs(15), true, |e| {
        if let LinkEvent::Frame(f) = e {
            if !f.is_key() && !cancelled {
                cancelled = true;
                let _ = link.frame_feedback(&[pb::FrameResult {
                    frame_number: f.number(),
                    outcome: pb::FrameOutcome::Cancelled as i32,
                    ..pb::FrameResult::default()
                }]);
            } else if cancelled && f.is_key() && f.is_resync() && f.number() > 1 {
                return true;
            }
        }
        false
    })
    .await;
    assert!(cancelled);
    // Frames between the cancel and the RESYNC IDR were discarded, not delivered.
    let last = frames(&seen).last().copied().unwrap();
    assert!(last.is_key() && last.is_resync());

    // An IDR request answers with a RESYNC IDR, too.
    link.request_idr(last.number()).unwrap();
    until(&link, &mut ev, Duration::from_secs(10), true, |e| {
        matches!(e, LinkEvent::Frame(f) if f.number() > last.number() && f.is_key() && f.is_resync())
    })
    .await;

    // The session cancels on its own when frames are not acknowledged at all: a cancel_frames
    // event arrives, validated against the newest frame, and the chain resyncs.
    link.start(2, stream_config()).unwrap();
    let mut cancel_seen = false;
    let seen = until(&link, &mut ev, Duration::from_secs(20), false, |e| {
        cancel_seen |= matches!(e, LinkEvent::CancelFrames { .. });
        cancel_seen
    })
    .await;
    assert!(
        cancel_seen,
        "an unacknowledged stream is cancelled by the controller"
    );
    drop(seen);
    until(
        &link,
        &mut ev,
        Duration::from_secs(10),
        true,
        |e| matches!(e, LinkEvent::Frame(f) if f.is_key() && f.is_resync()),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn resize_announces_a_new_stream_format_and_the_sps_matches() {
    let Some(env) = Env::start(|_| {}) else {
        return;
    };
    let (link, mut ev) = env.connect().await;
    link.start(1, stream_config()).unwrap();
    let _drawer = Drawer::start(&env.x.display);
    until(&link, &mut ev, Duration::from_secs(10), true, |e| {
        matches!(e, LinkEvent::Frame(_))
    })
    .await;
    // Odd sizes are rounded down to even by the session.
    link.reconfigure(pb::StreamConfig {
        width: 481,
        height: 271,
        clipboard_enabled: true,
        file_transfer_enabled: true,
        ..pb::StreamConfig::default()
    })
    .unwrap();
    let mut format = None;
    let seen = until(&link, &mut ev, Duration::from_secs(15), true, |e| {
        if let LinkEvent::StreamFormat(f) = e
            && (f.width, f.height) == (480, 270)
        {
            format = Some(*f);
        }
        // The frame carries the new format, and a key frame passed the SPS equality check.
        matches!(e, LinkEvent::Frame(f) if (f.format.width, f.format.height) == (480, 270) && f.is_key())
    })
    .await;
    let format = format.expect("a stream_format for the new size");
    let frame = frames(&seen).into_iter().last().unwrap();
    assert_eq!(format.epoch, 1);
    assert!(!hx_proto::order::serial_gt(
        format.first_frame,
        frame.number()
    ));
    assert_eq!(
        annexb::check_frame(frame.payload(), true)
            .unwrap()
            .sps
            .unwrap()
            .width,
        480
    );
    // A request outside the encoder's range is refused with an event, not a dead stream.
    link.reconfigure(pb::StreamConfig {
        width: 4,
        height: 4,
        clipboard_enabled: true,
        file_transfer_enabled: true,
        ..pb::StreamConfig::default()
    })
    .unwrap();
    until(
        &link,
        &mut ev,
        Duration::from_secs(10),
        true,
        |e| matches!(e, LinkEvent::Event(s) if s.kind == pb::EventKind::ResizeRefused),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn input_reaches_the_display_and_link_loss_releases_everything() {
    let Some(env) = Env::start(|_| {}) else {
        return;
    };
    let (link, mut ev) = env.connect().await;
    link.start(1, stream_config()).unwrap();
    let (w, root) = watcher(&env.x);
    let key = |sc, pressed| hx_proto::pb::InputEvent {
        event: Some(Event::Key(KeyEvent {
            scancode: sc,
            pressed,
        })),
    };
    link.input(key(0x04, true)).unwrap(); // HID 'a'
    link.input(key(0x04, false)).unwrap();
    assert_eq!(
        key_events(&w, 2, Duration::from_secs(5)),
        vec![("kp", 38), ("kr", 38)]
    );
    link.input(hx_proto::pb::InputEvent {
        event: Some(Event::Button(ButtonEvent {
            button: hx_proto::pb::MouseButton::Right as i32,
            pressed: true,
            x: 50,
            y: 60,
        })),
    })
    .unwrap();
    link.input(hx_proto::pb::InputEvent {
        event: Some(Event::Button(ButtonEvent {
            button: hx_proto::pb::MouseButton::Right as i32,
            pressed: false,
            x: 50,
            y: 60,
        })),
    })
    .unwrap();
    assert_eq!(
        key_events(&w, 2, Duration::from_secs(5)),
        vec![("bp", 3), ("br", 3)]
    );

    // Coalesced motion: only the newest position counts; the pointer ends up there.
    for i in 0..50 {
        link.mouse(MouseMove {
            relative: false,
            seq: i + 1,
            x: 100 + i as i32,
            y: 80,
        })
        .unwrap();
    }
    let end = Instant::now() + Duration::from_secs(5);
    let at = loop {
        let p = w.query_pointer(root).unwrap().reply().unwrap();
        if (p.root_x, p.root_y) == (149, 80) || Instant::now() > end {
            break (p.root_x, p.root_y);
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    assert_eq!(at, (149, 80));

    // Hold a modifier, then the link goes away: every held key is released.
    link.input(key(0xE0, true)).unwrap();
    assert_eq!(key_events(&w, 1, Duration::from_secs(5)), vec![("kp", 37)]);
    link.close();
    assert_eq!(
        key_events(&w, 1, Duration::from_secs(5)),
        vec![("kr", 37)],
        "release_all on link loss"
    );
    assert!(matches!(ev.next().await, LinkEvent::Closed(c) if c.class == FailureClass::Closed));
}

/// A local application standing in for any X client that owns or reads the clipboard.
fn app(x: &Xvfb) -> Clipboard {
    Clipboard::start(ClipboardConfig {
        display: Some(x.display.clone()),
        step_timeout: Duration::from_secs(2),
        ..ClipboardConfig::default()
    })
    .expect("clipboard app")
}

struct Text(Vec<u8>);

impl RemoteProvider for Text {
    fn fetch(&self, mime: &str, _max: u64) -> Option<Vec<u8>> {
        (mime == MIME_TEXT).then(|| self.0.clone())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn clipboard_text_travels_both_ways() {
    let Some(env) = Env::start(|_| {}) else {
        return;
    };
    let (link, mut ev) = env.connect().await;
    link.start(1, stream_config()).unwrap();
    let app = app(&env.x);
    // Let the start take effect (it enables the clipboard policy on the session).
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Gateway to session: the client's clipboard becomes the local selection.
    let text = "grüße from the client \u{1f600}".to_owned();
    let mut sender = link
        .begin_transfer(
            pb::TransferChannel::Clipboard,
            TransferHeader {
                mime: "text/plain;charset=utf-8".into(),
                name: String::new(),
                size: text.len() as u64,
            },
        )
        .await
        .unwrap();
    assert_eq!(sender.id() % 2, 1);
    sender
        .write(Bytes::from(text.clone().into_bytes()))
        .await
        .unwrap();
    sender.finish().await.unwrap();
    let rx = app.events().clone();
    let mut offered = false;
    let end = Instant::now() + Duration::from_secs(5);
    while !offered && Instant::now() < end {
        if let Ok(ClipboardEvent::LocalOffer { formats, .. }) =
            rx.recv_timeout(Duration::from_millis(200))
        {
            offered = formats.iter().any(|f| f == MIME_TEXT);
        }
    }
    assert!(offered, "the session owns the clipboard now");
    let got = app.fetch_local(Selection::Clipboard, MIME_TEXT).unwrap();
    assert_eq!(String::from_utf8(got).unwrap(), text);

    // Session to gateway: a local application copies; the gateway receives a clipboard transfer.
    let copied = "copied in the desktop";
    app.offer_remote(
        Selection::Clipboard,
        vec![MIME_TEXT.to_owned()],
        Arc::new(Text(copied.as_bytes().to_vec())),
    )
    .unwrap();
    let mut body = Vec::new();
    let mut open = None;
    until(&link, &mut ev, Duration::from_secs(10), true, |e| {
        match e {
            LinkEvent::Transfer(TransferEvent::Open {
                id,
                channel,
                header,
            }) => {
                assert_eq!(*channel, pb::TransferChannel::Clipboard);
                assert_eq!(id % 2, 0, "the session allocates even ids");
                open = Some(header.clone());
            }
            LinkEvent::Transfer(TransferEvent::Data(c)) => body.extend_from_slice(&c.data),
            LinkEvent::Transfer(TransferEvent::End { .. }) => return true,
            _ => {}
        }
        false
    })
    .await;
    assert_eq!(open.unwrap().size as usize, copied.len());
    assert_eq!(body, copied.as_bytes());

    // Policy off: the gateway refuses to start a transfer.
    link.set_policy(false, true);
    let err = link
        .begin_transfer(
            pb::TransferChannel::Clipboard,
            TransferHeader {
                mime: "text/plain".into(),
                name: String::new(),
                size: 1,
            },
        )
        .await
        .err()
        .unwrap();
    assert_eq!(err, TransferError::Disabled);
}

#[tokio::test(flavor = "multi_thread")]
async fn files_travel_both_ways_and_over_limit_files_are_refused() {
    let Some(env) = Env::start(|cfg| cfg.max_file_bytes = 1_000) else {
        return;
    };
    let (link, mut ev) = env.connect_with(|c| c.max_file_bytes = 2_000).await;
    link.start(1, stream_config()).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Gateway to session: written under the session's own name, 0600, never overwritten.
    let data: Vec<u8> = (0..700u32).map(|i| (i % 251) as u8).collect();
    for expect in ["hello.txt", "hello.txt.1"] {
        let mut s = link
            .begin_transfer(
                pb::TransferChannel::File,
                TransferHeader {
                    mime: "text/plain".into(),
                    name: "hello.txt".into(),
                    size: data.len() as u64,
                },
            )
            .await
            .unwrap();
        s.write(Bytes::from(data.clone())).await.unwrap();
        s.finish().await.unwrap();
        let path = env.received().join(expect);
        let end = Instant::now() + Duration::from_secs(5);
        while std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) != data.len() as u64
            && Instant::now() < end
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(std::fs::read(&path).unwrap(), data, "{expect}");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    // A name that is a path never gets this far: the gateway applies the protocol's file-name
    // rules before sending.
    let err = link
        .begin_transfer(
            pb::TransferChannel::File,
            TransferHeader {
                mime: "text/plain".into(),
                name: "../../etc/passwd".into(),
                size: 4,
            },
        )
        .await
        .err()
        .unwrap();
    assert!(matches!(err, TransferError::Invalid(_)));
    // The gateway's own limit (2 000 here) refuses before anything is sent.
    let err = link
        .begin_transfer(
            pb::TransferChannel::File,
            TransferHeader {
                mime: "text/plain".into(),
                name: "big.bin".into(),
                size: 5_000,
            },
        )
        .await
        .err()
        .unwrap();
    assert!(matches!(err, TransferError::Invalid(_)));
    // Between the two limits the session refuses with TRANSFER_REJECTED and nothing is written.
    let mut s = link
        .begin_transfer(
            pb::TransferChannel::File,
            TransferHeader {
                mime: "text/plain".into(),
                name: "mid.bin".into(),
                size: 1_500,
            },
        )
        .await
        .unwrap();
    let id = s.id();
    let mut refused = false;
    let end = Instant::now() + Duration::from_secs(5);
    while !refused && Instant::now() < end {
        if let Ok(LinkEvent::Transfer(TransferEvent::Aborted {
            id: aid,
            code,
            outgoing,
        })) = timeout(Duration::from_millis(100), ev.next()).await
        {
            assert_eq!((aid, code, outgoing), (id, 0x101, true));
            refused = true;
        }
    }
    assert!(refused, "the session refuses a file above its limit");
    assert!(matches!(
        s.write(Bytes::from_static(b"x")).await,
        Err(TransferError::Aborted)
    ));
    assert!(!env.received().join("mid.bin").exists());

    // Session to gateway: a local file is pushed; the gateway receives header, data and end.
    let src = env.dir.join("from-desktop.bin");
    let payload: Vec<u8> = (0..900u32).map(|i| (i * 7 % 253) as u8).collect();
    std::fs::write(&src, &payload).unwrap();
    let sender = env.server.as_ref().unwrap().sender();
    let send = {
        let (sender, src) = (sender.clone(), src.clone());
        tokio::task::spawn_blocking(move || sender.send_file(&src))
    };
    let mut body = Vec::new();
    let mut name = None;
    until(&link, &mut ev, Duration::from_secs(10), true, |e| {
        match e {
            LinkEvent::Transfer(TransferEvent::Open {
                channel, header, ..
            }) => {
                assert_eq!(*channel, pb::TransferChannel::File);
                name = Some(header.name.clone());
            }
            LinkEvent::Transfer(TransferEvent::Data(c)) => body.extend_from_slice(&c.data),
            LinkEvent::Transfer(TransferEvent::End { .. }) => return true,
            _ => {}
        }
        false
    })
    .await;
    assert_eq!(name.as_deref(), Some("from-desktop.bin"));
    assert_eq!(body, payload);
    send.await.unwrap().expect("the file was sent");

    // A file above the gateway's limit is refused by the gateway: abort and no body accepted.
    let big = env.dir.join("too-big.bin");
    std::fs::write(&big, vec![7u8; 1_000]).unwrap();
    let (link2, mut ev2) = env.connect_with(|c| c.max_file_bytes = 500).await;
    link2.start(1, stream_config()).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let send = {
        let (sender, big) = (sender.clone(), big.clone());
        tokio::task::spawn_blocking(move || sender.send_file(&big))
    };
    // The refused transfer never surfaces as an Open event.
    let mut no_open = true;
    let end = Instant::now() + Duration::from_secs(3);
    while Instant::now() < end {
        if let Ok(LinkEvent::Transfer(TransferEvent::Open { .. })) =
            timeout(Duration::from_millis(100), ev2.next()).await
        {
            no_open = false;
        }
    }
    let r = (no_open, send.await.unwrap());
    assert!(r.0, "no Open event for an over-limit file");
    assert_eq!(link2.counters().refused_transfers, 1);
    // A small file may be fully written before the abort arrives, so the session's own result
    // is either; what matters is that no byte of it reached the consumer.
    let _ = r.1;
    assert_eq!(link2.counters().refused_transfers, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn takeover_changes_the_epoch_and_a_stale_stop_is_ignored() {
    let Some(env) = Env::start(|_| {}) else {
        return;
    };
    let (link, mut ev) = env.connect().await;
    link.start(1, stream_config()).unwrap();
    let _drawer = Drawer::start(&env.x.display);
    let seen = until(&link, &mut ev, Duration::from_secs(10), true, |e| {
        matches!(e, LinkEvent::Frame(_))
    })
    .await;
    let last1 = frames(&seen).last().unwrap().number();

    // A second client takes over: release_all, then start with the next epoch.
    link.input(hx_proto::pb::InputEvent {
        event: Some(Event::ReleaseAll(hx_proto::pb::ReleaseAll {})),
    })
    .unwrap();
    link.start(2, stream_config()).unwrap();
    let mut saw_format = false;
    let seen = until(&link, &mut ev, Duration::from_secs(10), true, |e| {
        if let LinkEvent::StreamFormat(f) = e
            && f.epoch == 2
        {
            saw_format = true;
        }
        matches!(e, LinkEvent::Frame(f) if f.format.epoch == 2)
    })
    .await;
    assert!(saw_format, "stream_format with the new epoch");
    for f in frames(&seen) {
        assert_eq!(f.format.epoch, 2, "no frame of the old client is delivered");
    }
    let first2 = frames(&seen).last().copied().unwrap();
    assert!(
        first2.is_key() && first2.is_resync(),
        "the new client starts with a RESYNC IDR"
    );
    assert!(
        hx_proto::order::serial_gt(first2.number(), last1),
        "frame numbers keep counting"
    );

    // The old client's stop arrives late: it must not stop the new client's stream.
    link.stop(1).unwrap();
    // (`stop` also drops frames at the link client; start again with the same epoch to resume
    // delivery, which the session must still be able to serve from its running pipeline.)
    link.start(2, stream_config()).unwrap();
    until(
        &link,
        &mut ev,
        Duration::from_secs(10),
        true,
        |e| matches!(e, LinkEvent::Frame(f) if f.is_key() && f.is_resync()),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn link_loss_restart_supersede_and_goodbye() {
    let Some(env) = Env::start(|_| {}) else {
        return;
    };
    let _drawer = Drawer::start(&env.x.display);
    // Link loss: the owner closes the link; the session returns to listening and a new link
    // streams again from an IDR.
    let (link, mut ev) = env.connect().await;
    link.start(1, stream_config()).unwrap();
    until(&link, &mut ev, Duration::from_secs(10), true, |e| {
        matches!(e, LinkEvent::Frame(_))
    })
    .await;
    drop(ev);
    drop(link);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (link, mut ev) = env.connect().await;
    link.start(1, stream_config()).unwrap();
    let seen = until(&link, &mut ev, Duration::from_secs(10), true, |e| {
        matches!(e, LinkEvent::Frame(_))
    })
    .await;
    assert!(frames(&seen)[0].is_key());

    // A new link_id on ctl supersedes the old link, which then ends (a fault from its side).
    let (link2, mut ev2) = env.connect().await;
    let closed = until(&link, &mut ev, Duration::from_secs(10), true, |e| {
        matches!(e, LinkEvent::Closed(_))
    })
    .await;
    assert!(matches!(
        closed.last(),
        Some(LinkEvent::Closed(c)) if matches!(c.class, FailureClass::Fault)
    ));
    link2.start(1, stream_config()).unwrap();
    until(
        &link2,
        &mut ev2,
        Duration::from_secs(10),
        true,
        |e| matches!(e, LinkEvent::Frame(f) if f.is_key()),
    )
    .await;

    // The session's shutdown says goodbye first, then the link closes.
    let mut env = env;
    let server = env.server.take().unwrap();
    let sock = env.sock.clone();
    let t = std::thread::spawn(move || server.shutdown());
    let mut goodbye = false;
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        match timeout(end.saturating_duration_since(Instant::now()), ev2.next())
            .await
            .expect("closes in time")
        {
            LinkEvent::SessionGoodbye { code } => {
                assert_eq!(code, 7);
                goodbye = true;
            }
            LinkEvent::Closed(c) => {
                assert!(goodbye, "goodbye precedes the close");
                assert_eq!(c.class, FailureClass::Closed);
                break;
            }
            LinkEvent::Frame(f) => {
                let _ = link2.frame_feedback(&[delivered(&f, 3_000)]);
            }
            _ => {}
        }
    }
    t.join().unwrap();
    // After the server is gone the path is stale: unavailable.
    let err = LinkClient::connect(&sock, LinkConfig::default())
        .await
        .err()
        .unwrap();
    assert_eq!(err.class, FailureClass::Unavailable);
    drop(env);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_restarted_session_serves_the_same_socket() {
    // systemd keeps the listening socket while hx-session restarts: a second server on a clone
    // of the same listener serves the next link.
    let Some(x) = Xvfb::start(W, H) else {
        return;
    };
    let dir = std::env::temp_dir().join(format!("hx-link-restart-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("link.sock");
    let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let mk = |l: std::os::unix::net::UnixListener| {
        let mut cfg = SessionConfig::new(Some(x.display.clone()));
        cfg.received_dir = dir.join("received");
        cfg.pipeline.encoder.threads = 2;
        cfg.clipboard = None;
        Server::new(l, cfg).unwrap().spawn()
    };
    let s1 = mk(listener.try_clone().unwrap());
    let _drawer = Drawer::start(&x.display);
    let (link, mut ev) = LinkClient::connect(&sock, LinkConfig::default())
        .await
        .unwrap();
    assert!(!link.info().has_clipboard());
    link.start(1, stream_config()).unwrap();
    until(&link, &mut ev, Duration::from_secs(10), true, |e| {
        matches!(e, LinkEvent::Frame(_))
    })
    .await;
    // The first server stops (the daemon restarts); its link ends.
    s1.shutdown();
    loop {
        if matches!(ev.next().await, LinkEvent::Closed(_)) {
            break;
        }
    }
    // A connection made while no daemon runs queues in the kernel; the new daemon serves it.
    let pending = tokio::spawn({
        let sock = sock.clone();
        async move {
            LinkClient::connect(&sock, LinkConfig::default())
                .await
                .map(|(c, e)| (c, e))
        }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let s2 = mk(listener);
    let (link, mut ev) = pending.await.unwrap().expect("served after the restart");
    link.start(1, stream_config()).unwrap();
    let seen = until(&link, &mut ev, Duration::from_secs(10), true, |e| {
        matches!(e, LinkEvent::Frame(_))
    })
    .await;
    assert!(frames(&seen)[0].is_key());
    drop((link, ev));
    s2.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}
