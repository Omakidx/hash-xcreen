//! The relay end to end, in one process: a real client (hx-crypto + hx-transport) talks to the
//! real gateway (`Gateway`, fake privd), which talks through the `RelayLink` and the real
//! `LinkClient` to the real hx-session link server and pipeline under a private Xvfb, over a unix
//! socket that stands in for the Incus proxy device.
//!
//! Needs Xvfb (`HX_REQUIRE_XVFB=1` makes a missing Xvfb a failure, as in CI), x264 and the
//! FFmpeg libraries. Every test builds its own Xvfb, socket directory, session and gateway.

mod gateway_common;
mod relay_common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use hx_agent::gateway::desktop::DesktopLink as _;
use hx_capture::clipboard::{
    Clipboard, ClipboardConfig, ClipboardEvent, MIME_TEXT, MIME_URI_LIST, RemoteProvider, Selection,
};
use hx_proto::VideoCodec;
use hx_proto::channel::CloseCode;
use hx_proto::order::serial_gt;
use hx_proto::pb::{
    ButtonEvent, CursorPosition, InputEvent, KeyEvent, MouseButton,
    control_message::Message as Ctl, cursor_event::Event as Cur, input_event::Event as In,
};
use hx_transport::TransferKind;
use relay_common::*;

fn key(sc: u32, pressed: bool) -> InputEvent {
    InputEvent {
        event: Some(In::Key(KeyEvent {
            scancode: sc,
            pressed,
        })),
    }
}

fn button(b: MouseButton, pressed: bool, x: i32, y: i32) -> InputEvent {
    InputEvent {
        event: Some(In::Button(ButtonEvent {
            button: b as i32,
            pressed,
            x,
            y,
        })),
    }
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

/// Any one format a local application offers.
struct Offered(&'static str, Vec<u8>);

impl RemoteProvider for Offered {
    fn fetch(&self, mime: &str, _max: u64) -> Option<Vec<u8>> {
        (mime == self.0).then(|| self.1.clone())
    }
}

/// Waits (up to `secs`) until the engine sees a local offer that has `mime`.
fn wait_offer(a: &Clipboard, mime: &str, secs: u64) -> bool {
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end {
        if let Ok(ClipboardEvent::LocalOffer { formats, .. }) =
            a.events().recv_timeout(Duration::from_millis(100))
            && formats.iter().any(|f| f == mime)
        {
            return true;
        }
    }
    false
}

fn is_annexb(p: &[u8]) -> bool {
    p.starts_with(&[0, 0, 0, 1]) || p.starts_with(&[0, 0, 1])
}

// ---------------------------------------------------------------------------------------------
// Video, cursor, stream info

#[tokio::test(flavor = "multi_thread")]
async fn video_cursor_and_stream_info_reach_the_client() {
    let Some(rig) = Rig::start(RigOptions::default()).await else {
        return;
    };
    let _drawer = Drawer::start(&rig.x.display, false);
    let dev = rig.device("laptop").await;
    let mut c = rig.client(&dev, "laptop").await;
    c.view(|_| {}).await;

    // StreamInfo comes before the first frame and describes it.
    let info = c
        .wait_ctl(15, |m| match m {
            Ctl::StreamInfo(i) => Some(*i),
            _ => None,
        })
        .await
        .expect("StreamInfo");
    assert_eq!(info.codec, VideoCodec::H264 as i32);
    assert_eq!((info.width, info.height), (W, H));
    assert!(info.fps > 0 && info.fps <= 240);

    // An IDR first (KEY | RESYNC), then P frames, numbered upward, with intact headers.
    let first = c.first_idr(15).await;
    assert!(!serial_gt(info.first_frame, first.header.frame_number));
    assert_eq!(first.header.codec, VideoCodec::H264);
    assert!(is_annexb(&first.payload) && first.payload.len() == first.header.payload_len as usize);
    let mut last = first.header.frame_number;
    let mut p_frames = 0;
    for _ in 0..30 {
        let f = c.next_frame(10).await;
        assert!(serial_gt(f.header.frame_number, last), "numbers increase");
        assert!(is_annexb(&f.payload));
        assert_eq!(f.payload.len(), f.header.payload_len as usize);
        if !f.header.is_key() {
            p_frames += 1;
        }
        last = f.header.frame_number;
    }
    assert!(p_frames > 10, "P frames follow the IDR");

    // Cursor: a shape, then positions that name a shape already sent.
    c.conn.send_mouse_move(false, 100, 80).await.unwrap();
    let mut shapes = std::collections::HashSet::new();
    let mut at: Option<CursorPosition> = None;
    let end = Instant::now() + Duration::from_secs(10);
    while at.is_none() && Instant::now() < end {
        if let Ok(Some(e)) = tokio::time::timeout(Duration::from_millis(200), c.cursor.recv()).await
        {
            match e.event {
                Some(Cur::Shape(s)) => {
                    shapes.insert(s.id);
                }
                Some(Cur::Position(p)) if (p.x, p.y) == (100, 80) => at = Some(p),
                _ => {}
            }
        }
    }
    let at = at.expect("a cursor position for the pointer");
    assert!(
        shapes.contains(&at.shape_id),
        "the position names a sent shape"
    );

    // The only control messages a client got are numeric or the ones it asked for.
    for (_, m) in c.collect_ctl(1).await {
        assert!(matches!(m, Ctl::StreamInfo(_)), "{m:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn server_stats_only_when_enabled_and_at_most_once_a_second() {
    let Some(rig) = Rig::start(RigOptions::default()).await else {
        return;
    };
    let _drawer = Drawer::start(&rig.x.display, false);
    let dev = rig.device("laptop").await;
    let mut c = rig.client(&dev, "laptop").await;
    c.view(|_| {}).await;
    c.next_frame(15).await;
    // Off by default: nothing is sent.
    let quiet = c.collect_ctl(3).await;
    assert!(
        quiet.iter().all(|(_, m)| !matches!(m, Ctl::ServerStats(_))),
        "no ServerStats until asked"
    );

    c.view(|v| v.stats_enabled = true).await;
    let msgs = c.collect_ctl(5).await;
    let stats: Vec<_> = msgs
        .iter()
        .filter_map(|(t, m)| match m {
            Ctl::ServerStats(s) => Some((*t, *s)),
            _ => None,
        })
        .collect();
    assert!(stats.len() >= 3, "about one a second: {}", stats.len());
    for w in stats.windows(2) {
        assert!(
            w[1].0.duration_since(w[0].0) >= Duration::from_millis(800),
            "at most one a second"
        );
    }
    for (_, s) in &stats {
        assert!((1..=60_000).contains(&s.interval_ms));
        assert!(s.fps_ceiling <= 240 && s.target_bitrate_kbps > 0);
    }
    assert!(stats.iter().any(|(_, s)| s.frames > 0));

    // Off again: after the last message in flight, nothing more.
    c.view(|v| v.stats_enabled = false).await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let late = c.collect_ctl(3).await;
    assert!(
        late.iter().all(|(_, m)| !matches!(m, Ctl::ServerStats(_))),
        "switched off"
    );
}

// ---------------------------------------------------------------------------------------------
// Feedback

#[tokio::test(flavor = "multi_thread")]
async fn a_bandwidth_cap_reaches_the_controller_and_a_slow_link_lowers_the_bitrate() {
    let Some(rig) = Rig::start(RigOptions::default()).await else {
        return;
    };
    let _drawer = Drawer::start(&rig.x.display, true);
    let dev = rig.device("laptop").await;
    let shaper = Shaper::start(rig.env.gw.quic_addr().unwrap()).await;
    let mut c = rig.client_at(&dev, "laptop", shaper.addr).await;
    c.view(|v| v.stats_enabled = true).await;

    let target = |m: &Ctl| match m {
        Ctl::ServerStats(s) => Some(s.target_bitrate_kbps),
        _ => None,
    };
    // A healthy link: the controller starts at 4 Mbit/s.
    let first = c.wait_ctl(15, target).await.expect("ServerStats");
    assert!((500..=4_000).contains(&first), "{first}");

    // The client's own cap goes through `reconfigure` to the session's controller.
    c.view(|v| {
        v.stats_enabled = true;
        v.bandwidth_cap_kbps = 1_000;
    })
    .await;
    let capped = c
        .wait_ctl(15, |m| target(m).filter(|t| *t <= 1_000))
        .await
        .expect("the cap lowers the target");
    assert!(capped <= 1_000);

    // Lift the cap, then make the link slow: acks come late, frames are cancelled, the rate
    // steps down and the session keeps running. (Cap 20 000 first, to start high again.)
    c.view(|v| {
        v.stats_enabled = true;
        v.bandwidth_cap_kbps = 20_000;
    })
    .await;
    let raised = c
        .wait_ctl(40, |m| target(m).filter(|t| *t > 1_000))
        .await
        .expect("healthy acks raise the rate again");
    shaper.limit(60_000); // 480 kbit/s with a 20 ms delay
    let lowered = c
        .wait_ctl(60, |m| target(m).filter(|t| *t < raised))
        .await
        .expect("a slow link lowers the rate");
    assert!(lowered < raised);
    assert!(rig.relay.keeper().is_up(), "the session link stayed up");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_slow_client_does_not_stall_the_session_or_its_input() {
    let Some(rig) = Rig::start(RigOptions::default()).await else {
        return;
    };
    let _drawer = Drawer::start(&rig.x.display, true);
    let dev = rig.device("laptop").await;
    let shaper = Shaper::start(rig.env.gw.quic_addr().unwrap()).await;
    let mut c = rig.client_at(&dev, "laptop", shaper.addr).await;
    c.view(|_| {}).await;
    c.next_frame(15).await;
    let (w, _root) = watcher(&rig.x);

    // The way back to the client is almost closed: video queues, is cancelled and dropped.
    shaper.limit(15_000);
    tokio::time::sleep(Duration::from_secs(3)).await;
    // Input still goes straight through: a key press reaches the desktop at once.
    for i in 0..5 {
        let t = Instant::now();
        c.conn.send_input(&key(0x04, true)).await.unwrap();
        c.conn.send_input(&key(0x04, false)).await.unwrap();
        let ev = key_events(&w, 2, Duration::from_secs(3));
        assert_eq!(ev, vec![("kp", 38), ("kr", 38)], "round {i}");
        assert!(t.elapsed() < Duration::from_secs(3));
    }
    // The link to the session is up and the relay holds a bounded amount: frames were cancelled
    // or dropped, and neither the queue nor the window exceeded its bound.
    assert!(rig.relay.keeper().is_up());
    let mut worst = (0u64, 0usize, 0u64);
    for _ in 0..20 {
        let s = rig.relay.snapshot().expect("the client is attached");
        worst = (
            worst.0.max(s.queued_video_bytes),
            worst.1.max(s.inflight_frames),
            worst.2.max(s.inflight_video_bytes),
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(worst.0 <= 12 << 20, "queued {}", worst.0);
    assert!(worst.1 <= 32, "in flight {}", worst.1);
    assert!(worst.2 <= 24 << 20, "in flight bytes {}", worst.2);
    let s = rig.relay.snapshot().unwrap();
    assert!(
        s.frames_cancelled + s.frames_dropped > 0,
        "the slow link made the relay cancel or drop frames: {s:?}"
    );

    // The client's link recovers: a fresh IDR (RESYNC) and frames again.
    shaper.limit(0);
    let key_frame = c
        .wait_frame(60, |f| {
            (f.header.is_key() && f.header.is_resync()).then_some(f.header)
        })
        .await;
    assert!(key_frame.is_some(), "a RESYNC IDR after the cancels");
    assert!(
        c.wait_frame(30, |f| (!f.header.is_key()).then_some(()))
            .await
            .is_some(),
        "P frames follow"
    );
}

// ---------------------------------------------------------------------------------------------
// Input

#[tokio::test(flavor = "multi_thread")]
async fn a_key_and_a_mouse_move_reach_x_and_coordinates_are_clamped() {
    let Some(rig) = Rig::start(RigOptions::default()).await else {
        return;
    };
    let dev = rig.device("laptop").await;
    let mut c = rig.client(&dev, "laptop").await;
    c.view(|_| {}).await;
    c.next_frame(15).await;
    let (w, root) = watcher(&rig.x);

    c.conn.send_input(&key(0x04, true)).await.unwrap(); // HID 'a'
    c.conn.send_input(&key(0x04, false)).await.unwrap();
    assert_eq!(
        key_events(&w, 2, Duration::from_secs(5)),
        vec![("kp", 38), ("kr", 38)]
    );
    c.conn.send_mouse_move(false, 120, 90).await.unwrap();
    assert_eq!(
        pointer_at(&w, root, (120, 90), Duration::from_secs(5)).await,
        (120, 90)
    );
    c.conn
        .send_input(&button(MouseButton::Right, true, 50, 60))
        .await
        .unwrap();
    c.conn
        .send_input(&button(MouseButton::Right, false, 50, 60))
        .await
        .unwrap();
    assert_eq!(
        key_events(&w, 2, Duration::from_secs(5)),
        vec![("bp", 3), ("br", 3)]
    );

    // Absolute coordinates outside the display are clamped to it, relative ones are bounded.
    tokio::time::sleep(Duration::from_millis(20)).await;
    c.conn
        .send_mouse_move(false, 100_000, -5_000)
        .await
        .unwrap();
    assert_eq!(
        pointer_at(&w, root, (W as i16 - 1, 0), Duration::from_secs(5)).await,
        (W as i16 - 1, 0)
    );
    c.conn
        .send_input(&button(MouseButton::Left, true, 1_000_000, 1_000_000))
        .await
        .unwrap();
    c.conn
        .send_input(&button(MouseButton::Left, false, 1_000_000, 1_000_000))
        .await
        .unwrap();
    assert_eq!(key_events(&w, 2, Duration::from_secs(5)).len(), 2);
    assert_eq!(
        pointer_at(
            &w,
            root,
            (W as i16 - 1, H as i16 - 1),
            Duration::from_secs(5)
        )
        .await,
        (W as i16 - 1, H as i16 - 1),
        "the button event's position was clamped"
    );
    // A scancode the protocol does not define never reaches X (the transport refuses it or the
    // relay drops it); the connection is not what the test is about, so only X is checked.
    let _ = c.conn.send_input(&key(0x1FF, true)).await;
    assert!(key_events(&w, 1, Duration::from_millis(300)).is_empty());
}

// ---------------------------------------------------------------------------------------------
// Resize

#[tokio::test(flavor = "multi_thread")]
async fn resize_announces_a_new_stream_info_and_input_follows_the_new_size() {
    let Some(rig) = Rig::start(RigOptions::default()).await else {
        return;
    };
    let _drawer = Drawer::start(&rig.x.display, false);
    let dev = rig.device("laptop").await;
    let mut c = rig.client(&dev, "laptop").await;
    c.view(|_| {}).await;
    c.next_frame(15).await;
    // Odd sizes are rounded down to even by the session.
    c.view(|v| {
        v.width = 481;
        v.height = 271;
    })
    .await;
    let info = c
        .wait_ctl(20, |m| match m {
            Ctl::StreamInfo(i) if (i.width, i.height) == (480, 270) => Some(*i),
            _ => None,
        })
        .await
        .expect("StreamInfo for the new size");
    // The first frame at or after `first_frame` is a key frame of the new format.
    c.wait_frame(20, |f| {
        (!serial_gt(info.first_frame, f.header.frame_number) && f.header.is_key()).then_some(())
    })
    .await
    .expect("a key frame of the new format");
    // Coordinates are now clamped to the new display.
    let (w, root) = watcher(&rig.x);
    c.conn.send_mouse_move(false, 5_000, 5_000).await.unwrap();
    assert_eq!(
        pointer_at(&w, root, (479, 269), Duration::from_secs(5)).await,
        (479, 269)
    );
}

// ---------------------------------------------------------------------------------------------
// Clipboard and files

#[tokio::test(flavor = "multi_thread")]
async fn clipboard_text_travels_both_ways_and_the_policy_applies() {
    let Some(rig) = Rig::start(RigOptions::default()).await else {
        return;
    };
    let dev = rig.device("laptop").await;
    let mut c = rig.client(&dev, "laptop").await;
    c.view(|_| {}).await;
    c.next_frame(15).await;
    let a = app(&rig.x);
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Client to desktop: the client's clipboard becomes the local selection.
    let text = "grüße from the client \u{1f600}";
    c.send_transfer(
        TransferKind::Clipboard,
        "text/plain;charset=utf-8",
        "",
        text.as_bytes(),
    )
    .await
    .expect("the clipboard transfer is accepted");
    assert!(
        wait_offer(&a, MIME_TEXT, 5),
        "the session owns the clipboard"
    );
    let got = a.fetch_local(Selection::Clipboard, MIME_TEXT).unwrap();
    assert_eq!(String::from_utf8(got).unwrap(), text);

    // Desktop to client: a local application copies, the client receives a clipboard transfer.
    let copied = "copied in the desktop";
    a.offer_remote(
        Selection::Clipboard,
        vec![MIME_TEXT.to_owned()],
        Arc::new(Text(copied.as_bytes().to_vec())),
    )
    .unwrap();
    let t = c.next_transfer(10).await.expect("a clipboard transfer");
    assert_eq!(t.kind, TransferKind::Clipboard);
    assert_eq!(t.body, copied.as_bytes());
    assert!(t.header.mime.starts_with("text/plain"));

    // The device turns the clipboard off: the client's transfer does not become the local
    // selection (a stream this small may be fully delivered before the refusal arrives, so the
    // effect is checked, not the sender's result), and what the desktop copies is not sent.
    c.view(|v| v.clipboard_enabled = false).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let _ = c
        .send_transfer(TransferKind::Clipboard, "text/plain", "", b"secret")
        .await;
    assert!(
        !wait_offer(&a, MIME_TEXT, 2),
        "the client's text did not become the selection"
    );
    let reader = app(&rig.x);
    let still = reader.fetch_local(Selection::Clipboard, MIME_TEXT).unwrap();
    assert_eq!(
        still,
        copied.as_bytes(),
        "the selection is still the desktop's own"
    );
    a.offer_remote(
        Selection::Clipboard,
        vec![MIME_TEXT.to_owned()],
        Arc::new(Text(b"not for the client".to_vec())),
    )
    .unwrap();
    assert!(c.next_transfer(2).await.is_none(), "nothing leaves");
}

#[tokio::test(flavor = "multi_thread")]
async fn clipboard_images_and_files_copied_in_the_desktop_reach_the_client() {
    let Some(rig) = Rig::start(RigOptions::default()).await else {
        return;
    };
    let dev = rig.device("laptop").await;
    let mut c = rig.client(&dev, "laptop").await;
    c.view(|_| {}).await;
    c.next_frame(15).await;
    let a = app(&rig.x);
    tokio::time::sleep(Duration::from_millis(300)).await;

    // An image from the client becomes the local image selection.
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend((0..200_000u32).map(|i| (i * 31 % 251) as u8));
    c.send_transfer(TransferKind::Clipboard, "image/png", "", &png)
        .await
        .expect("image accepted");
    assert!(wait_offer(&a, "image/png", 5), "the session owns the image");
    assert_eq!(
        a.fetch_local(Selection::Clipboard, "image/png").unwrap(),
        png
    );

    // An image copied in the desktop reaches the client as image/png.
    let mut local = b"\x89PNG\r\n\x1a\n".to_vec();
    local.extend((0..70_000u32).map(|i| (i * 13 % 247) as u8));
    a.offer_remote(
        Selection::Clipboard,
        vec!["image/png".to_owned()],
        Arc::new(Offered("image/png", local.clone())),
    )
    .unwrap();
    let t = c.next_transfer(10).await.expect("an image transfer");
    assert_eq!(t.kind, TransferKind::Clipboard);
    assert_eq!(t.header.mime, "image/png");
    assert_eq!(t.body, local);

    // Files copied in the desktop (a text/uri-list) are pushed to the client as file transfers.
    let file = rig.dir.join("copied.bin");
    let content: Vec<u8> = (0..5_000u32).map(|i| (i % 249) as u8).collect();
    std::fs::write(&file, &content).unwrap();
    a.offer_remote(
        Selection::Clipboard,
        vec![MIME_URI_LIST.to_owned()],
        Arc::new(Offered(
            MIME_URI_LIST,
            format!("file://{}\r\n", file.display()).into_bytes(),
        )),
    )
    .unwrap();
    let t = c.next_transfer(10).await.expect("a file transfer");
    assert_eq!(t.kind, TransferKind::File);
    assert_eq!(
        (t.header.name.as_str(), t.header.size),
        ("copied.bin", 5_000)
    );
    assert_eq!(t.body, content);
}

// ---------------------------------------------------------------------------------------------
// Files

#[tokio::test(flavor = "multi_thread")]
async fn files_travel_both_ways_over_limit_files_are_refused_and_pasted_files_are_a_file_list() {
    let Some(rig) = Rig::start(RigOptions {
        max_file: Some(1 << 20),
        ..RigOptions::default()
    })
    .await
    else {
        return;
    };
    let dev = rig.device("laptop").await;
    let mut c = rig.client(&dev, "laptop").await;
    c.view(|_| {}).await;
    c.next_frame(15).await;
    let a = app(&rig.x);
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Client to desktop: the file lands in the received directory under the session's own name,
    // and is offered as a file list that a file manager can paste.
    let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    c.send_transfer(
        TransferKind::File,
        "application/octet-stream",
        "hello.txt",
        &data,
    )
    .await
    .expect("file accepted");
    let path = rig.received().join("hello.txt");
    let end = Instant::now() + Duration::from_secs(10);
    while std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) != data.len() as u64
        && Instant::now() < end
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(std::fs::read(&path).unwrap(), data);
    assert!(
        wait_offer(&a, MIME_URI_LIST, 10),
        "a file-list clipboard is offered"
    );
    let list =
        String::from_utf8(a.fetch_local(Selection::Clipboard, MIME_URI_LIST).unwrap()).unwrap();
    let root = std::fs::canonicalize(rig.received()).unwrap();
    assert_eq!(
        list.lines().collect::<Vec<_>>(),
        [format!("file://{}/hello.txt", root.display())],
        "the paste points at the received file"
    );

    // Two more files sent together are one paste: both are in the list, after the first batch's
    // window has passed.
    tokio::time::sleep(Duration::from_millis(3_300)).await;
    for name in ["one.bin", "two.bin"] {
        c.send_transfer(
            TransferKind::File,
            "application/octet-stream",
            name,
            b"0123456789",
        )
        .await
        .unwrap();
    }
    let end = Instant::now() + Duration::from_secs(10);
    while !(rig.received().join("one.bin").exists() && rig.received().join("two.bin").exists())
        && Instant::now() < end
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // The engine answers one offer from its cache, so wait for the batch's final offer.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let a2 = app(&rig.x);
    let list =
        String::from_utf8(a2.fetch_local(Selection::Clipboard, MIME_URI_LIST).unwrap()).unwrap();
    assert_eq!(
        list.lines().collect::<Vec<_>>(),
        [
            format!("file://{}/one.bin", root.display()),
            format!("file://{}/two.bin", root.display()),
        ]
    );

    // A file above the limit is refused before a body byte is accepted, and nothing is stored.
    let big = vec![9u8; 2 << 20];
    let r = c
        .send_transfer(
            TransferKind::File,
            "application/octet-stream",
            "big.bin",
            &big,
        )
        .await;
    assert!(r.is_err(), "the over-limit file is refused");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!rig.received().join("big.bin").exists());
    // The connection and the next transfer are fine.
    c.send_transfer(
        TransferKind::File,
        "application/octet-stream",
        "after.bin",
        b"ok",
    )
    .await
    .expect("still works");

    // Desktop to client: a local file is pushed; the client gets header, body and the name.
    let src = rig.dir.join("from-desktop.bin");
    let payload: Vec<u8> = (0..70_000u32).map(|i| (i * 7 % 253) as u8).collect();
    std::fs::write(&src, &payload).unwrap();
    let sender = rig.server.as_ref().unwrap().sender();
    let send = {
        let (sender, src) = (sender.clone(), src.clone());
        tokio::task::spawn_blocking(move || sender.send_file(&src))
    };
    let t = c.next_transfer(15).await.expect("the file arrives");
    assert_eq!(t.kind, TransferKind::File);
    assert_eq!(t.header.name, "from-desktop.bin");
    assert_eq!(t.body, payload);
    send.await.unwrap().expect("sent");

    // A desktop file above the limit never reaches the client; a small one after it does.
    let huge = rig.dir.join("huge.bin");
    std::fs::write(&huge, vec![1u8; 2 << 20]).unwrap();
    let send = {
        let (sender, huge) = (sender.clone(), huge.clone());
        tokio::task::spawn_blocking(move || sender.send_file(&huge))
    };
    assert!(
        c.next_transfer(3).await.is_none(),
        "no transfer above the limit"
    );
    let _ = send.await;
    let small = rig.dir.join("small.txt");
    std::fs::write(&small, b"small").unwrap();
    let send = {
        let (sender, small) = (sender.clone(), small.clone());
        tokio::task::spawn_blocking(move || sender.send_file(&small))
    };
    let t = c.next_transfer(15).await.expect("the link carried on");
    assert_eq!(t.header.name, "small.txt");
    let _ = send.await;
}

// ---------------------------------------------------------------------------------------------
// Takeover, revocation, lifecycle

#[tokio::test(flavor = "multi_thread")]
async fn takeover_by_a_second_device_gets_a_new_epoch_an_idr_and_cuts_the_old_input() {
    let Some(rig) = Rig::start(RigOptions::default()).await else {
        return;
    };
    let _drawer = Drawer::start(&rig.x.display, false);
    let laptop = rig.device("laptop").await;
    let phone = rig.device("phone").await;
    let mut a = rig.client(&laptop, "laptop").await;
    a.view(|_| {}).await;
    let mut last_a = a.next_frame(15).await.header.frame_number;
    let (w, _root) = watcher(&rig.x);
    // The laptop holds Shift down.
    a.conn.send_input(&key(0xE1, true)).await.unwrap();
    assert_eq!(key_events(&w, 1, Duration::from_secs(5)), vec![("kp", 50)]);
    // The newest frame the laptop has received (the drawer keeps frames coming, so only what is
    // already queued is read).
    tokio::time::sleep(Duration::from_millis(200)).await;
    while let Ok(f) = a.frames.try_recv() {
        last_a = f.header.frame_number;
    }

    // The phone asks to view: the laptop is told, its key is released, the phone gets a new
    // stream that starts with an IDR.
    let mut b = rig.client(&phone, "phone").await;
    b.view(|_| {}).await;
    let taken = a
        .wait_ctl(15, |m| match m {
            Ctl::Goodbye(g) => Some(g.clone()),
            _ => None,
        })
        .await
        .expect("Goodbye");
    assert_eq!(taken.code, CloseCode::TakenOver.code());
    assert_eq!(taken.peer_device_name, "phone");
    let closed = within_conn(&a).await;
    assert_eq!(closed, CloseCode::TakenOver);
    assert_eq!(
        key_events(&w, 1, Duration::from_secs(5)),
        vec![("kr", 50)],
        "release_all for the displaced client's held key"
    );
    let info = b
        .wait_ctl(15, |m| match m {
            Ctl::StreamInfo(i) => Some(*i),
            _ => None,
        })
        .await
        .expect("StreamInfo for the new client");
    let first = b.first_idr(15).await;
    assert!(!serial_gt(info.first_frame, first.header.frame_number));
    assert!(
        serial_gt(first.header.frame_number, last_a),
        "frame numbers keep counting across the takeover"
    );

    // Only the new epoch's input reaches the desktop.
    b.conn.send_input(&key(0x05, true)).await.unwrap();
    b.conn.send_input(&key(0x05, false)).await.unwrap();
    assert_eq!(
        key_events(&w, 2, Duration::from_secs(5)),
        vec![("kp", 56), ("kr", 56)]
    );
    // The displaced connection cannot send anything any more.
    assert!(
        a.conn.send_input(&key(0x06, true)).await.is_err() || {
            tokio::time::sleep(Duration::from_millis(300)).await;
            key_events(&w, 1, Duration::from_millis(300)).is_empty()
        }
    );
}

async fn within_conn(c: &Client) -> CloseCode {
    tokio::time::timeout(Duration::from_secs(10), c.conn.closed())
        .await
        .expect("the connection closes")
        .code
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_device_is_cut_off_mid_stream() {
    let Some(rig) = Rig::start(RigOptions::default()).await else {
        return;
    };
    let _drawer = Drawer::start(&rig.x.display, false);
    let laptop = rig.device("laptop").await;
    let phone = rig.device("phone").await;
    let mut a = rig.client(&laptop, "laptop").await;
    a.view(|_| {}).await;
    a.next_frame(15).await;
    let (w, _root) = watcher(&rig.x);
    a.conn.send_input(&key(0xE1, true)).await.unwrap();
    assert_eq!(key_events(&w, 1, Duration::from_secs(5)), vec![("kp", 50)]);
    assert!(rig.env.gw.sessions().has_active_client().await);

    // The phone revokes the laptop: its connection is closed, the held key is released and the
    // desktop is given up.
    let status = rig
        .env
        .gw
        .devices()
        .revoke_by_device(
            gateway_common::Env::id_of(&phone),
            gateway_common::Env::id_of(&laptop),
        )
        .await;
    assert_eq!(status, hx_proto::pb::RevokeStatus::Ok);
    assert_eq!(within_conn(&a).await, CloseCode::Unauthorized);
    assert_eq!(
        key_events(&w, 1, Duration::from_secs(5)),
        vec![("kr", 50)],
        "the revoked device's keys are released"
    );
    assert!(
        gateway_common::eventually(|| async { !rig.env.gw.sessions().has_active_client().await })
            .await
    );
    // No frame arrives after the cut (what was queued before drains, then nothing).
    tokio::time::sleep(Duration::from_millis(300)).await;
    while a.frames.try_recv().is_ok() {}
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(a.frames.try_recv().is_err());
    // And the revoked device cannot come back.
    let r = tokio::time::timeout(
        Duration::from_secs(10),
        hx_crypto::connect_with_pin(
            &rig.env.target(hx_transport::TransportPreference::Quic),
            &laptop,
            rig.env.server_public(),
            &hx_crypto::Pin::new(gateway_common::PIN).unwrap(),
            &rig.env
                .session_opts(hx_transport::TransportPreference::Quic, "laptop"),
        ),
    )
    .await
    .expect("answered");
    assert!(r.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_last_client_leaving_stops_the_stream_and_the_link_is_kept_then_closed() {
    let Some(rig) = Rig::start(RigOptions {
        idle_keep: Some(Duration::from_secs(2)),
        ..RigOptions::default()
    })
    .await
    else {
        return;
    };
    let _drawer = Drawer::start(&rig.x.display, false);
    let laptop = rig.device("laptop").await;
    let mut a = rig.client(&laptop, "laptop").await;
    a.view(|_| {}).await;
    a.next_frame(15).await;
    assert!(rig.relay.keeper().is_up());
    a.conn.close(CloseCode::NoError, "bye").await;
    drop(a);
    // The link is kept for the idle time: a reconnect is instant (no new dial, same link).
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(rig.relay.keeper().is_up(), "kept during the idle time");
    let mut b = rig.client(&laptop, "laptop").await;
    b.view(|_| {}).await;
    b.first_idr(15).await; // a fresh stream starts with an IDR
    // Leaving again and staying away closes the link after the keep time.
    b.conn.close(CloseCode::NoError, "bye").await;
    drop(b);
    assert!(
        gateway_common::eventually(|| async { !rig.relay.keeper().is_up() }).await,
        "closed after the keep time"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_restarted_session_ends_the_stream_with_a_fixed_text_and_the_client_reconnects() {
    let Some(mut rig) = Rig::start(RigOptions::default()).await else {
        return;
    };
    let _drawer = Drawer::start(&rig.x.display, false);
    let laptop = rig.device("laptop").await;
    let mut a = rig.client(&laptop, "laptop").await;
    a.view(|_| {}).await;
    a.next_frame(15).await;

    // The desktop's session restarts: the client is told (a fixed text, never session text) and
    // closed; the next attach waits out the backoff of a session-initiated close.
    rig.restart_session();
    let g = a
        .wait_ctl(15, |m| match m {
            Ctl::Goodbye(g) => Some(g.clone()),
            _ => None,
        })
        .await
        .expect("Goodbye");
    assert!(
        g.code == CloseCode::Shutdown.code() || g.code == CloseCode::InternalError.code(),
        "{}",
        g.code
    );
    assert!(
        g.message == "the desktop session ended" || g.message == "the desktop connection failed",
        "fixed text only: {:?}",
        g.message
    );
    assert!(g.peer_device_name.is_empty());
    let code = within_conn(&a).await;
    assert!(code == CloseCode::Shutdown || code == CloseCode::InternalError);

    // Reconnect: the first tries may be told "unavailable" while the backoff runs; then it works.
    let end = Instant::now() + Duration::from_secs(40);
    loop {
        let mut b = rig.client(&laptop, "laptop").await;
        b.view(|_| {}).await;
        if b.wait_frame(6, |f| f.header.is_key().then_some(()))
            .await
            .is_some()
        {
            break; // video restarts from an IDR
        }
        assert!(Instant::now() < end, "no reconnect");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

// ---------------------------------------------------------------------------------------------
// A client cannot make the link fail

#[tokio::test(flavor = "multi_thread")]
async fn a_client_flooding_view_configs_input_and_motion_cannot_make_the_link_fail() {
    let Some(rig) = Rig::start(RigOptions::default()).await else {
        return;
    };
    let _drawer = Drawer::start(&rig.x.display, false);
    let dev = rig.device("laptop").await;
    let mut c = rig.client(&dev, "laptop").await;
    c.view(|_| {}).await;
    c.next_frame(15).await;

    // Continuous pointer motion for the whole test.
    let conn = c.conn.clone();
    let motion = tokio::spawn(async move {
        let end = Instant::now() + Duration::from_secs(3);
        let mut i = 0i32;
        while Instant::now() < end {
            if conn
                .send_mouse_move(false, 10 + (i % 300), 20 + (i % 200))
                .await
                .is_err()
            {
                break;
            }
            i += 1;
            tokio::task::yield_now().await;
        }
    });
    // 5000 ViewConfigs back to back (a distinct frame-rate ceiling each).
    for i in 0..5_000u32 {
        c.view(|v| v.max_fps = 10 + i % 50).await;
    }
    // An input burst of 2000 events, then about 2000 a second for 2 s.
    let key = |pressed| InputEvent {
        event: Some(In::Key(KeyEvent {
            scancode: 0x04,
            pressed,
        })),
    };
    for i in 0..2_000 {
        c.conn.send_input(&key(i % 2 == 0)).await.unwrap();
    }
    for tick in 0..200 {
        for i in 0..19 {
            c.conn.send_input(&key((tick + i) % 2 == 0)).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    motion.await.unwrap();
    c.conn
        .send_input(&InputEvent {
            event: Some(In::ReleaseAll(Default::default())),
        })
        .await
        .unwrap();

    // The link never failed: still up, still Up in the status, no restart or install was asked
    // for, the client was not closed and the stream goes on.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(rig.relay.keeper().is_up());
    assert_eq!(rig.relay.state(), hx_ipc::admin::pb::LinkState::Up);
    assert_eq!(rig.env.privd.with(|s| s.restart_session_calls), 0);
    assert_eq!(rig.env.privd.with(|s| s.install_session_calls), 0);
    assert!(c.conn.close_info().is_none(), "{:?}", c.conn.close_info());
    while c.frames.try_recv().is_ok() {}
    c.next_frame(15).await;
}
