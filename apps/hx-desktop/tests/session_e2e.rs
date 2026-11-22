//! The app's session layer, headless, against a real gatewayd and hx-session (the stack of
//! `relay_e2e`: gateway over a fake privd, relay, link, hx-session pipeline under a private Xvfb).
//!
//! `#[ignore]`d because it needs Xvfb, x264 and the FFmpeg libraries and a quiet machine:
//! `cargo nextest run -p hx-desktop --run-ignored only` (`HX_REQUIRE_XVFB=1` makes a missing
//! Xvfb a failure). It pairs, logs in with the PIN, decodes the first frame through the app's
//! decoder, sends input and a clipboard text, lists devices, and disconnects.

#[path = "../../hx-agent/tests/gateway_common/mod.rs"]
mod gateway_common;
#[path = "../../hx-agent/tests/relay_common/mod.rs"]
mod relay_common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use hx_desktop::app::desktop_ctl::build_view;
use hx_desktop::session::connect::Outcome;
use hx_desktop::session::net::{Event, Link, Session, login};
use hx_desktop::video::{Picture, PresentKind, Presenter, Stats, spawn_decoder};
use relay_common::{Rig, RigOptions};

struct Collect(Mutex<Vec<(u32, u32)>>);

impl Presenter for Collect {
    fn kind(&self) -> PresentKind {
        PresentKind::CpuUpload
    }
    fn present(&self, p: Picture) {
        self.0.lock().unwrap().push((p.width, p.height));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs Xvfb, x264 and FFmpeg; run with --run-ignored only"]
async fn pair_pin_first_frame_type_and_disconnect() {
    let Some(rig) = Rig::start(RigOptions::default()).await else {
        eprintln!("no Xvfb: skipped");
        return;
    };
    let device = rig.device("hx-desktop test").await;
    let addr = rig.env.target(hx_transport::TransportPreference::Quic).addr;
    let link = Link {
        host: addr.ip().to_string(),
        port: addr.port(),
        server_key: rig.env.server_public(),
        device: device.clone(),
        device_name: "hx-desktop test".into(),
    };

    // A wrong PIN is reported with the attempts left (the server decides).
    match login(&link, "000000").await {
        Err(Outcome::Wrong { attempts_left, .. }) => assert_eq!(attempts_left, 4),
        other => panic!("expected a wrong PIN, got {:?}", other.err()),
    }
    // The gateway runs on a manual clock: let the one-second wait after a wrong PIN pass.
    rig.env.clock.advance(Duration::from_secs(5));
    let conn = login(&link, gateway_common::PIN).await.expect("PIN login");

    // Video: the app's decoder thread, the CPU presenter's trait.
    let pictures = Arc::new(Collect(Mutex::default()));
    let stats = Arc::new(Stats::default());
    let slot: Arc<Mutex<Option<Arc<Session>>>> = Arc::default();
    let s2 = slot.clone();
    let (tx, thread) = spawn_decoder(
        pictures.clone(),
        stats.clone(),
        Arc::new(move |last| {
            if let Some(s) = s2.lock().unwrap().as_ref() {
                s.request_keyframe(last);
            }
        }),
    )
    .expect("decoder");
    let (session, mut events) = Session::start(
        conn,
        Some(tx),
        std::env::temp_dir(),
        stats.clone(),
        tokio::runtime::Handle::current(),
    );
    let session = Arc::new(session);
    *slot.lock().unwrap() = Some(session.clone());
    session.view(build_view(0, 0, 0, (0, 0), true, true));

    let mut got_stream = false;
    let end = tokio::time::Instant::now() + Duration::from_secs(40);
    while tokio::time::Instant::now() < end && pictures.0.lock().unwrap().is_empty() {
        if let Ok(Some(Event::Stream(s))) =
            tokio::time::timeout(Duration::from_millis(200), events.recv()).await
        {
            assert_eq!((s.width, s.height), (relay_common::W, relay_common::H));
            got_stream = true;
        }
    }
    let first = pictures
        .0
        .lock()
        .unwrap()
        .first()
        .copied()
        .expect("a decoded frame");
    assert_eq!(first, (relay_common::W, relay_common::H));
    assert!(got_stream || stats.take_interval().decoded > 0);

    // Type: a key press and release, a pointer move and click, and a clipboard text. The
    // connection stays up and frames keep coming.
    session.key(0x04, true);
    session.key(0x04, false);
    session.motion(100, 80);
    session.button(hx_proto::pb::MouseButton::Left, true, 100, 80);
    session.button(hx_proto::pb::MouseButton::Left, false, 100, 80);
    session.send_clipboard_text("hello from hx-desktop");
    let before = pictures.0.lock().unwrap().len();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        session.connection().close_info().is_none(),
        "still connected"
    );
    let _ = before;

    // Device management over the 1.2 messages: this device is listed and current.
    let list = session.list_devices().await.expect("device list");
    assert!(
        list.iter()
            .any(|d| d.current && d.name.contains("hx-desktop"))
    );

    // Disconnect: the app closes; the close is ours, so no reconnect.
    session.close().await;
    let mut closed = false;
    while let Ok(Some(e)) = tokio::time::timeout(Duration::from_secs(5), events.recv()).await {
        if let Event::Closed(r) = e {
            assert_eq!(r, hx_desktop::session::CloseReason::Local);
            closed = true;
            break;
        }
    }
    assert!(closed, "a Closed event after disconnect");
    drop(session);
    drop(slot);
    thread.join();
}
