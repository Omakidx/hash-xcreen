//! Every channel type over loopback, on each transport.

mod common;

use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use common::{WAIT, all_features, client_hello, pair, pair_with, server_hello};
use hx_proto::{
    VideoCodec,
    channel::CloseCode,
    media::{FLAG_KEY, FLAG_RESYNC, MediaHeader},
    pb::{
        self, ControlMessage, CursorEvent, InputEvent, TransferHeader,
        control_message::Message as Ctl, cursor_event::Event as Cur, input_event::Event as Inp,
    },
    version::{Features, ProtocolVersion, capabilities},
};
use hx_transport::{AckOutcome, Error, Role, TransferKind, TransportKind, TransportPreference};

async fn within<T>(f: impl Future<Output = T>) -> T {
    tokio::time::timeout(WAIT, f)
        .await
        .expect("operation timed out")
}

fn header(frame_number: u32, flags: u16, len: usize) -> MediaHeader {
    MediaHeader {
        codec: VideoCodec::H264,
        flags,
        frame_number,
        capture_timestamp_us: u64::from(frame_number) * 16_667,
        payload_len: len as u32,
    }
}

/// Generate one test per transport from a scenario function.
macro_rules! scenarios {
    ($($name:ident),* $(,)?) => {
        $(
            mod $name {
                use super::*;
                #[tokio::test]
                async fn quic() { super::$name(TransportPreference::Quic).await }
                #[tokio::test]
                #[ignore = "WebSocket fallback lands in the next commit"]
                async fn websocket() { super::$name(TransportPreference::WebSocket).await }
            }
        )*
    };
}

scenarios!(
    hello_and_negotiation,
    control_roundtrip_and_ping,
    input_keeps_order,
    mouse_latest_wins,
    cursor_events,
    audio_packets,
    transfers_both_directions,
    video_frames_are_acked,
    video_reorder_drops_older,
    role_and_feature_errors,
    close_code_is_reported,
);

async fn hello_and_negotiation(pref: TransportPreference) {
    let p = pair(pref).await;
    let expect_kind = if pref == TransportPreference::Quic {
        TransportKind::Quic
    } else {
        TransportKind::WebSocket
    };
    assert_eq!(p.client.transport(), expect_kind);
    assert_eq!(p.srv.transport(), expect_kind);
    assert_eq!(p.client.role(), Role::Client);
    assert_eq!(p.srv.role(), Role::Server);
    for c in [&p.client, &p.srv] {
        let n = c.negotiated();
        assert_eq!(n.version, ProtocolVersion::CURRENT);
        assert_eq!(n.features, all_features());
        assert_eq!(n.codecs, vec![VideoCodec::H264]);
    }
    assert_eq!(p.client.session_id(), p.srv.session_id());
    assert_ne!(p.client.session_id(), [0u8; 16]);
    assert_eq!(p.client.peer_info().software, "hx-test-server 0.0");
    assert_eq!(p.srv.peer_info().software, "hx-test-client 0.0");
    assert_eq!(p.srv.peer_info().device_name, "test device");
    // Server certificate was presented to the client.
    assert!(p.client.peer_certificates().is_some_and(|c| !c.is_empty()));
}

async fn control_roundtrip_and_ping(pref: TransportPreference) {
    let p = pair(pref).await;
    let view = ControlMessage::new(Ctl::ViewConfig(pb::ViewConfig {
        codec: VideoCodec::H264 as i32,
        max_fps: 60,
        width: 1920,
        height: 1080,
        scale_percent: 100,
        ..Default::default()
    }));
    p.client
        .send_control(&view)
        .await
        .expect("send view config");
    assert_eq!(within(p.srv.recv_control()).await.expect("recv"), view);

    let info = ControlMessage::new(Ctl::StreamInfo(pb::StreamInfo {
        codec: VideoCodec::H264 as i32,
        width: 1920,
        height: 1080,
        fps: 60,
        first_frame: 0,
    }));
    p.srv.send_control(&info).await.expect("send stream info");
    assert_eq!(within(p.client.recv_control()).await.expect("recv"), info);

    // Opaque pairing/auth envelopes pass through untouched.
    let opaque = ControlMessage::new(Ctl::Auth(pb::Opaque {
        data: Bytes::from_static(b"\x00\x01opaque"),
    }));
    p.client.send_control(&opaque).await.expect("send auth");
    assert_eq!(within(p.srv.recv_control()).await.expect("recv"), opaque);

    // Ping/pong is answered by the transport on both sides.
    let rtt = within(p.client.ping(WAIT)).await.expect("client ping");
    assert!(rtt < Duration::from_secs(5));
    within(p.srv.ping(WAIT)).await.expect("server ping");

    // Handshake messages and wrong-direction messages are refused locally.
    assert!(matches!(
        p.client.send_control(&info).await,
        Err(Error::WrongRole(_))
    ));
    assert!(matches!(
        p.srv.send_control(&view).await,
        Err(Error::WrongRole(_))
    ));
    let hello = ControlMessage::new(Ctl::Hello(pb::Hello::default()));
    assert!(matches!(
        p.client.send_control(&hello).await,
        Err(Error::Violation(_))
    ));
}

async fn input_keeps_order(pref: TransportPreference) {
    let p = pair(pref).await;
    let mut sent = Vec::new();
    for i in 0..100u32 {
        let e = match i % 4 {
            0 => Inp::Key(pb::KeyEvent {
                scancode: i % 0xE8,
                pressed: true,
            }),
            1 => Inp::Button(pb::ButtonEvent {
                button: 1,
                pressed: true,
                x: i as i32,
                y: -(i as i32),
            }),
            2 => Inp::Scroll(pb::ScrollEvent { dx: 0, dy: 120 }),
            _ => Inp::ReleaseAll(pb::ReleaseAll {}),
        };
        let ev = InputEvent { event: Some(e) };
        p.client.send_input(&ev).await.expect("send input");
        sent.push(ev);
    }
    for want in sent {
        assert_eq!(within(p.srv.recv_input()).await.expect("recv input"), want);
    }
    // The client may not receive input and the server may not send it.
    assert!(matches!(
        p.client.recv_input().await,
        Err(Error::WrongRole(_))
    ));
    assert!(matches!(
        p.srv.send_input(&InputEvent::default()).await,
        Err(Error::WrongRole(_))
    ));
    // An invalid event is refused before it is sent.
    let bad = InputEvent {
        event: Some(Inp::Key(pb::KeyEvent {
            scancode: 0xFFFF,
            pressed: true,
        })),
    };
    assert!(matches!(
        p.client.send_input(&bad).await,
        Err(Error::Protocol(_))
    ));
}

async fn mouse_latest_wins(pref: TransportPreference) {
    let p = pair(pref).await;
    for i in 0..200 {
        p.client
            .send_mouse_move(false, i, i * 2)
            .await
            .expect("send move");
    }
    let mut last = None;
    while last != Some((199, 398)) {
        let u = within(p.srv.recv_mouse_move()).await.expect("recv move");
        if u.absolute.is_some() {
            last = u.absolute;
        }
    }
    // Relative motion is summed, not replaced.
    for _ in 0..10 {
        p.client
            .send_mouse_move(true, 1, 2)
            .await
            .expect("send delta");
    }
    let mut sum = (0, 0);
    while sum != (10, 20) {
        let u = within(p.srv.recv_mouse_move()).await.expect("recv delta");
        let (dx, dy) = u.relative.expect("relative motion");
        sum = (sum.0 + dx, sum.1 + dy);
    }
}

async fn cursor_events(pref: TransportPreference) {
    let p = pair(pref).await;
    let shape = CursorEvent {
        event: Some(Cur::Shape(pb::CursorShape {
            id: 0xABCD,
            width: 32,
            height: 32,
            hotspot_x: 3,
            hotspot_y: 4,
            rgba: Bytes::from(vec![0x7f; 32 * 32 * 4]),
        })),
    };
    let pos = CursorEvent {
        event: Some(Cur::Position(pb::CursorPosition {
            x: 10,
            y: -5,
            shape_id: 0xABCD,
            visible: true,
        })),
    };
    p.srv.send_cursor(&shape).await.expect("send shape");
    p.srv.send_cursor(&pos).await.expect("send position");
    assert_eq!(within(p.client.recv_cursor()).await.expect("shape"), shape);
    assert_eq!(within(p.client.recv_cursor()).await.expect("position"), pos);
    assert!(matches!(
        p.client.send_cursor(&pos).await,
        Err(Error::WrongRole(_))
    ));
    // A cursor image that does not match its dimensions is refused before sending.
    let bad = CursorEvent {
        event: Some(Cur::Shape(pb::CursorShape {
            id: 1,
            width: 4,
            height: 4,
            hotspot_x: 0,
            hotspot_y: 0,
            rgba: Bytes::from_static(b"short"),
        })),
    };
    assert!(matches!(
        p.srv.send_cursor(&bad).await,
        Err(Error::Protocol(_))
    ));
}

async fn audio_packets(pref: TransportPreference) {
    let p = pair(pref).await;
    for i in 0..5u32 {
        p.srv
            .send_audio(i * 480, Bytes::from(vec![i as u8 + 1; 100]))
            .await
            .expect("send audio");
    }
    for i in 0..5u32 {
        let a = within(p.client.recv_audio()).await.expect("recv audio");
        assert_eq!((a.seq, a.timestamp), (i, i * 480));
        assert_eq!(a.payload, Bytes::from(vec![i as u8 + 1; 100]));
    }
    assert!(p.srv.send_audio(0, Bytes::new()).await.is_err());
    assert!(
        p.srv
            .send_audio(0, Bytes::from(vec![0; 1101]))
            .await
            .is_err()
    );
}

async fn transfers_both_directions(pref: TransportPreference) {
    let p = pair(pref).await;

    // Clipboard text, client to server.
    let text = b"clipboard text".to_vec();
    let h = TransferHeader {
        mime: "text/plain;charset=utf-8".into(),
        name: String::new(),
        size: text.len() as u64,
    };
    let mut tx = p
        .client
        .open_transfer(TransferKind::Clipboard, h.clone())
        .await
        .expect("open");
    tx.write(&text).await.expect("write");
    tx.finish().await.expect("finish");
    let incoming = within(p.srv.accept_transfer())
        .await
        .expect("accept transfer");
    assert_eq!(incoming.kind, TransferKind::Clipboard);
    assert_eq!(incoming.header, h);
    assert_eq!(
        within(incoming.read_to_end(1 << 20)).await.expect("read"),
        Bytes::from(text)
    );

    // A file larger than one chunk, server to client, written in odd-sized pieces.
    let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let h = TransferHeader {
        mime: "application/octet-stream".into(),
        name: "big.bin".into(),
        size: data.len() as u64,
    };
    let mut tx = p
        .srv
        .open_transfer(TransferKind::File, h.clone())
        .await
        .expect("open file");
    let writer = tokio::spawn({
        let data = data.clone();
        async move {
            for piece in data.chunks(70_001) {
                tx.write(piece).await.expect("write piece");
            }
            tx.finish().await.expect("finish file");
        }
    });
    let incoming = within(p.client.accept_transfer())
        .await
        .expect("accept file");
    assert_eq!(
        (incoming.kind, incoming.header.name.as_str()),
        (TransferKind::File, "big.bin")
    );
    let got = within(incoming.read_to_end(1 << 30))
        .await
        .expect("read file");
    assert_eq!(got, Bytes::from(data));
    within(writer).await.expect("writer");

    // Sender-side size checks.
    let h = TransferHeader {
        mime: "x/y".into(),
        name: "n".into(),
        size: 4,
    };
    let mut tx = p
        .client
        .open_transfer(TransferKind::File, h.clone())
        .await
        .expect("open");
    assert!(matches!(
        tx.write(b"toolong").await,
        Err(Error::TransferSize)
    ));
    tx.write(b"ab").await.expect("partial write");
    assert!(matches!(tx.finish().await, Err(Error::TransferSize)));

    // Header rules: clipboard transfers carry no name and respect the size cap.
    let bad = TransferHeader {
        mime: "text/plain".into(),
        name: "x".into(),
        size: 1,
    };
    assert!(
        p.client
            .open_transfer(TransferKind::Clipboard, bad)
            .await
            .is_err()
    );
    let bad = TransferHeader {
        mime: "x/y".into(),
        name: "../etc/passwd".into(),
        size: 1,
    };
    assert!(
        p.client
            .open_transfer(TransferKind::File, bad)
            .await
            .is_err()
    );
}

async fn video_frames_are_acked(pref: TransportPreference) {
    let p = pair(pref).await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    p.srv.set_ack_handler(Some(Arc::new(move |a| {
        sink.lock().expect("lock").push(a);
    })));

    let mut tickets = Vec::new();
    for n in 0..10u32 {
        let payload = Bytes::from(vec![n as u8; 1000 + n as usize * 20_000]);
        let flags = if n == 0 { FLAG_KEY } else { 0 };
        tickets.push(
            p.srv
                .send_video_frame(header(n, flags, payload.len()), payload)
                .await
                .expect("send frame"),
        );
    }
    // The client receives the frames in order and intact.
    for n in 0..10u32 {
        let f = within(p.client.recv_video_frame())
            .await
            .expect("recv frame");
        assert_eq!(f.header.frame_number, n);
        assert_eq!(
            f.payload,
            Bytes::from(vec![n as u8; 1000 + n as usize * 20_000])
        );
        assert_eq!(f.header.is_key(), n == 0);
        assert_eq!(f.header.capture_timestamp_us, u64::from(n) * 16_667);
    }
    // Every frame is acknowledged as delivered, to its ticket and to the handler.
    for (n, t) in tickets.into_iter().enumerate() {
        assert_eq!(t.frame_number(), n as u32);
        let ack = within(t.ack()).await;
        assert_eq!(ack.outcome, AckOutcome::Delivered, "frame {n}");
        assert_eq!(ack.frame_number, n as u32);
        assert_eq!(ack.bytes, 1000 + n * 20_000);
    }
    let seen = seen.lock().expect("lock");
    assert_eq!(seen.len(), 10);
    assert!(seen.iter().all(|a| a.outcome == AckOutcome::Delivered));
    drop(seen);
    let s = p.srv.stats();
    assert_eq!((s.frames_sent, s.frames_delivered), (10, 10));
    assert_eq!(p.client.stats().frames_received, 10);

    // A frame whose length does not match its header is refused before sending.
    let bad = header(99, 0, 10);
    assert!(matches!(
        p.srv
            .send_video_frame(bad, Bytes::from_static(b"abc"))
            .await,
        Err(Error::Violation(_))
    ));
    // The client cannot send video.
    assert!(matches!(
        p.client
            .send_video_frame(header(1, 0, 1), Bytes::from_static(b"x"))
            .await,
        Err(Error::WrongRole(_))
    ));
    assert!(matches!(
        p.srv.recv_video_frame().await,
        Err(Error::WrongRole(_))
    ));
}

async fn video_reorder_drops_older(pref: TransportPreference) {
    let p = pair(pref).await;
    // Frame 2 is sent a second time after 3: by then 3 is released, so the late 2 is stale.
    for n in [1u32, 2, 3, 2, 4] {
        let t = p
            .srv
            .send_video_frame(header(n, 0, 4), Bytes::from_static(b"data"))
            .await
            .expect("send");
        assert_eq!(within(t.ack()).await.outcome, AckOutcome::Delivered);
    }
    let mut got = Vec::new();
    for _ in 0..4 {
        got.push(
            within(p.client.recv_video_frame())
                .await
                .expect("frame")
                .header
                .frame_number,
        );
    }
    assert_eq!(got, vec![1, 2, 3, 4]);
    assert_eq!(p.client.stats().frames_dropped_stale, 1);
    // A resync key frame with a jump is accepted at once.
    let t = p
        .srv
        .send_video_frame(
            header(50, FLAG_KEY | FLAG_RESYNC, 1),
            Bytes::from_static(b"k"),
        )
        .await
        .expect("send");
    assert_eq!(within(t.ack()).await.outcome, AckOutcome::Delivered);
    let f = within(p.client.recv_video_frame())
        .await
        .expect("resync frame");
    assert!(f.header.is_resync() && f.header.is_key());
}

async fn role_and_feature_errors(pref: TransportPreference) {
    // The client offers no audio and no clipboard: those channels stay closed.
    let mut ch = client_hello();
    ch.capabilities = capabilities(&[VideoCodec::H264], Features::FILE_TRANSFER);
    let p = pair_with(pref, server_hello(), ch).await;
    assert_eq!(p.srv.negotiated().features, Features::FILE_TRANSFER);
    assert!(matches!(
        p.srv.send_audio(0, Bytes::from_static(b"x")).await,
        Err(Error::FeatureDisabled(_))
    ));
    let h = TransferHeader {
        mime: "text/plain".into(),
        name: String::new(),
        size: 1,
    };
    assert!(matches!(
        p.client.open_transfer(TransferKind::Clipboard, h).await,
        Err(Error::FeatureDisabled(_))
    ));
    let h = TransferHeader {
        mime: "x/y".into(),
        name: "a".into(),
        size: 0,
    };
    let tx = p
        .client
        .open_transfer(TransferKind::File, h)
        .await
        .expect("files stay available");
    tx.finish().await.expect("empty file");
}

async fn close_code_is_reported(pref: TransportPreference) {
    let p = pair(pref).await;
    p.srv.close(CloseCode::Shutdown, "maintenance").await;
    let info = within(p.client.closed()).await;
    assert_eq!(info.code, CloseCode::Shutdown);
    assert!(info.by_peer);
    assert_eq!(info.reason, "maintenance");
    assert!(
        matches!(within(p.client.recv_control()).await, Err(Error::Closed(c)) if c.code == CloseCode::Shutdown)
    );
    assert!(matches!(
        p.client.send_input(&InputEvent::default()).await,
        Err(_)
    ));
    let local = p.srv.close_info().expect("local close recorded");
    assert!(!local.by_peer);
    // Closing twice is harmless.
    p.srv.close(CloseCode::NoError, "again").await;
    assert_eq!(
        p.srv.close_info().expect("still recorded").code,
        CloseCode::Shutdown
    );
}

/// QUIC cancels a queued frame by resetting its stream; the next frame is unaffected.
#[tokio::test]
async fn quic_cancelled_frame_is_reset_and_acked_as_cancelled() {
    let p = pair(TransportPreference::Quic).await;
    let big = Bytes::from(vec![7u8; 4_000_000]);
    let t = p
        .srv
        .send_video_frame(header(1, FLAG_KEY, big.len()), big)
        .await
        .expect("send");
    // Single-threaded runtime: the writer task has not run yet, so this is deterministic.
    t.cancel();
    assert_eq!(within(t.ack()).await.outcome, AckOutcome::Cancelled);
    let t = p
        .srv
        .send_video_frame(
            header(2, FLAG_KEY | FLAG_RESYNC, 3),
            Bytes::from_static(b"new"),
        )
        .await
        .expect("send resync frame");
    assert_eq!(within(t.ack()).await.outcome, AckOutcome::Delivered);
    let f = within(p.client.recv_video_frame()).await.expect("frame");
    assert_eq!((f.header.frame_number, &f.payload[..]), (2, &b"new"[..]));
    assert_eq!(p.srv.stats().frames_cancelled, 1);
}
