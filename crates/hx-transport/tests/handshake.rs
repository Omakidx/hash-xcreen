//! Handshake, versioning, ALPN dispatch and protocol-violation behaviour over raw QUIC peers.

mod common;

use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use common::{WAIT, client, client_hello, raw_quic, server_hello, start_server, target};
use hx_proto::{
    VideoCodec,
    channel::CloseCode,
    message,
    pb::{self, ControlMessage, Intent, RefuseReason, control_message::Message as Ctl},
    version::{ProtocolVersion, capabilities},
};
use hx_transport::{Error, H3Handler, Server, ServerOptions, TransportPreference};

fn hello_message(major: u32, minor: u32) -> ControlMessage {
    ControlMessage::new(Ctl::Hello(pb::Hello {
        version: Some(pb::Version { major, minor }),
        capabilities: Some(capabilities(&[VideoCodec::H264], common::all_features())),
        intent: Intent::Session as i32,
        software: "raw".into(),
        device_name: "raw peer".into(),
    }))
}

/// Open the control stream like a client does and send `first` framed.
async fn open_control(
    conn: &quinn::Connection,
    body: &[u8],
) -> (quinn::SendStream, quinn::RecvStream) {
    let (mut s, r) = conn.open_bi().await.expect("open control");
    s.write_all(&[0x01]).await.expect("channel byte");
    s.write_all(&(body.len() as u32).to_le_bytes())
        .await
        .expect("len");
    s.write_all(body).await.expect("body");
    (s, r)
}

async fn read_reply(r: &mut quinn::RecvStream) -> ControlMessage {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await.expect("reply length");
    let mut body = vec![0u8; u32::from_le_bytes(len) as usize];
    r.read_exact(&mut body).await.expect("reply body");
    message::decode(&body).expect("valid reply")
}

async fn closed_code(conn: &quinn::Connection) -> CloseCode {
    match tokio::time::timeout(WAIT, conn.closed())
        .await
        .expect("connection closes")
    {
        quinn::ConnectionError::ApplicationClosed(ac) => {
            CloseCode::from_code(ac.error_code.into_inner())
        }
        other => panic!("unexpected close: {other}"),
    }
}

async fn no_session(server: &Server) {
    assert!(
        tokio::time::timeout(Duration::from_millis(300), server.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn different_major_is_refused_with_update_required() {
    let server = start_server(ServerOptions::default()).await;
    let (_ep, conn) = raw_quic(server.quic_addr().expect("quic"), b"hx/1")
        .await
        .expect("connect");
    let body = message::encode(&hello_message(2, 0)).expect("encode");
    let (_s, mut r) = open_control(&conn, &body).await;
    match read_reply(&mut r).await.message {
        Some(Ctl::Refuse(refuse)) => {
            assert_eq!(refuse.reason, RefuseReason::UpdateRequired as i32);
            assert_eq!(refuse.version, Some(ProtocolVersion::CURRENT.into()));
        }
        other => panic!("expected Refuse, got {other:?}"),
    }
    assert_eq!(closed_code(&conn).await, CloseCode::UpdateRequired);
    no_session(&server).await;
}

#[tokio::test]
async fn future_major_hello_with_unparseable_fields_is_still_refused_cleanly() {
    let server = start_server(ServerOptions::default()).await;
    let (_ep, conn) = raw_quic(server.quic_addr().expect("quic"), b"hx/1")
        .await
        .expect("connect");
    // ControlMessage { hello: { version: {major: 2}, field 3 as a string (we expect a varint) } }
    let inner = [0x0a, 0x02, 0x08, 0x02, 0x1a, 0x03, b'a', b'b', b'c'];
    let mut body = vec![0x0a, inner.len() as u8];
    body.extend_from_slice(&inner);
    let (_s, mut r) = open_control(&conn, &body).await;
    assert!(matches!(
        read_reply(&mut r).await.message,
        Some(Ctl::Refuse(_))
    ));
    assert_eq!(closed_code(&conn).await, CloseCode::UpdateRequired);
}

#[tokio::test]
async fn same_major_higher_minor_is_accepted_and_negotiated_down() {
    let server = start_server(ServerOptions::default()).await;
    let s2 = server.clone();
    let accepted = tokio::spawn(async move {
        let pending = s2.accept().await.expect("pending");
        assert_eq!(
            pending.hello().version,
            Some(pb::Version { major: 1, minor: 7 })
        );
        pending.accept(server_hello()).await.expect("accept")
    });
    let (_ep, conn) = raw_quic(server.quic_addr().expect("quic"), b"hx/1")
        .await
        .expect("connect");
    let body = message::encode(&hello_message(1, 7)).expect("encode");
    let (_s, mut r) = open_control(&conn, &body).await;
    match read_reply(&mut r).await.message {
        Some(Ctl::HelloAck(ack)) => assert_eq!(ack.version, Some(ProtocolVersion::CURRENT.into())),
        other => panic!("expected HelloAck, got {other:?}"),
    }
    let srv = tokio::time::timeout(WAIT, accepted)
        .await
        .expect("in time")
        .expect("join");
    // Both ends agree on the lower minor.
    assert_eq!(srv.negotiated().version, ProtocolVersion::CURRENT);
}

#[tokio::test]
async fn first_message_must_be_hello() {
    let server = start_server(ServerOptions::default()).await;
    let (_ep, conn) = raw_quic(server.quic_addr().expect("quic"), b"hx/1")
        .await
        .expect("connect");
    let ping =
        message::encode(&ControlMessage::new(Ctl::Ping(pb::Ping { nonce: 1 }))).expect("encode");
    let (_s, _r) = open_control(&conn, &ping).await;
    assert_eq!(closed_code(&conn).await, CloseCode::ProtocolError);
    no_session(&server).await;
}

#[tokio::test]
async fn first_stream_must_be_control() {
    let server = start_server(ServerOptions::default()).await;
    let (_ep, conn) = raw_quic(server.quic_addr().expect("quic"), b"hx/1")
        .await
        .expect("connect");
    let (mut s, _r) = conn.open_bi().await.expect("open");
    s.write_all(&[0x02, 0, 0, 0, 0]).await.expect("write");
    assert_eq!(closed_code(&conn).await, CloseCode::ProtocolError);
}

#[tokio::test]
async fn oversized_or_garbage_first_frame_is_a_protocol_error() {
    let server = start_server(ServerOptions::default()).await;
    for frame in [
        vec![0xFF, 0xFF, 0xFF, 0xFF],
        vec![0, 0, 0, 0],
        vec![3, 0, 0, 0, 0xFF, 0xFF, 0xFF],
    ] {
        let (_ep, conn) = raw_quic(server.quic_addr().expect("quic"), b"hx/1")
            .await
            .expect("connect");
        let (mut s, _r) = conn.open_bi().await.expect("open");
        s.write_all(&[0x01]).await.expect("channel");
        s.write_all(&frame).await.expect("frame");
        assert_eq!(
            closed_code(&conn).await,
            CloseCode::ProtocolError,
            "frame {frame:?}"
        );
    }
    no_session(&server).await;
}

#[tokio::test]
async fn silent_peer_gets_hello_timeout() {
    let opts = ServerOptions {
        handshake_timeout: Duration::from_millis(300),
        ..Default::default()
    };
    let server = start_server(opts).await;
    let (_ep, conn) = raw_quic(server.quic_addr().expect("quic"), b"hx/1")
        .await
        .expect("connect");
    assert_eq!(closed_code(&conn).await, CloseCode::HelloTimeout);
    no_session(&server).await;
}

#[tokio::test]
async fn application_can_refuse_after_inspecting_the_hello() {
    let server = start_server(ServerOptions::default()).await;
    let s2 = server.clone();
    let refuser = tokio::spawn(async move {
        let pending = s2.accept().await.expect("pending");
        assert_eq!(pending.hello().device_name, "test device");
        assert_eq!(pending.transport(), hx_transport::TransportKind::Quic);
        assert!(pending.peer_certificates().is_none());
        pending
            .refuse(RefuseReason::Unauthorized, "unknown device")
            .await
            .expect("refuse");
    });
    let err = client(TransportPreference::Quic)
        .connect(&target(&server, TransportPreference::Quic), &client_hello())
        .await
        .expect_err("refused");
    match err {
        Error::Refused {
            reason,
            message,
            server_version,
        } => {
            assert_eq!(reason, RefuseReason::Unauthorized);
            assert_eq!(message, "unknown device");
            assert_eq!(server_version, Some(ProtocolVersion::CURRENT));
        }
        other => panic!("expected Refused, got {other}"),
    }
    tokio::time::timeout(WAIT, refuser)
        .await
        .expect("in time")
        .expect("join");
}

#[tokio::test]
async fn violations_after_the_handshake_close_the_connection() {
    // Each case: a raw client completes the handshake, then breaks a rule.
    type Break = fn(&quinn::Connection) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
    let cases: Vec<(&str, Break)> = vec![
        ("client opens a video stream", |c| {
            Box::pin(async move {
                let mut s = c.open_uni().await.expect("uni");
                s.write_all(&[0x05]).await.expect("write");
            })
        }),
        ("unknown channel id", |c| {
            Box::pin(async move {
                let mut s = c.open_uni().await.expect("uni");
                s.write_all(&[0x7f]).await.expect("write");
            })
        }),
        ("garbage on the input stream", |c| {
            Box::pin(async move {
                let mut s = c.open_uni().await.expect("uni");
                s.write_all(&[0x02, 3, 0, 0, 0, 0xFF, 0xFF, 0xFF])
                    .await
                    .expect("write");
            })
        }),
        ("oversized input frame", |c| {
            Box::pin(async move {
                let mut s = c.open_uni().await.expect("uni");
                s.write_all(&[0x02, 0x00, 0x10, 0x00, 0x00])
                    .await
                    .expect("write");
            })
        }),
        ("empty cursor stream from the client", |c| {
            Box::pin(async move {
                let mut s = c.open_uni().await.expect("uni");
                s.write_all(&[0x04]).await.expect("write");
            })
        }),
    ];
    for (name, breaker) in cases {
        let server = start_server(ServerOptions::default()).await;
        let s2 = server.clone();
        let accepted = tokio::spawn(async move {
            let pending = s2.accept().await.expect("pending");
            pending.accept(server_hello()).await.expect("accept")
        });
        let (_ep, conn) = raw_quic(server.quic_addr().expect("quic"), b"hx/1")
            .await
            .expect("connect");
        let body = message::encode(&hello_message(1, 0)).expect("encode");
        let (_s, mut r) = open_control(&conn, &body).await;
        assert!(
            matches!(read_reply(&mut r).await.message, Some(Ctl::HelloAck(_))),
            "{name}"
        );
        let srv = tokio::time::timeout(WAIT, accepted)
            .await
            .expect("in time")
            .expect("join");
        breaker(&conn).await;
        assert_eq!(closed_code(&conn).await, CloseCode::ProtocolError, "{name}");
        let info = tokio::time::timeout(WAIT, srv.closed())
            .await
            .expect("server side closes");
        assert_eq!(info.code, CloseCode::ProtocolError, "{name}");
        assert!(!info.by_peer, "{name}");
    }
}

#[tokio::test]
async fn invalid_control_message_after_the_handshake_is_a_protocol_error() {
    let server = start_server(ServerOptions::default()).await;
    let s2 = server.clone();
    let accepted = tokio::spawn(async move {
        let pending = s2.accept().await.expect("pending");
        pending.accept(server_hello()).await.expect("accept")
    });
    let (_ep, conn) = raw_quic(server.quic_addr().expect("quic"), b"hx/1")
        .await
        .expect("connect");
    let body = message::encode(&hello_message(1, 0)).expect("encode");
    let (mut s, mut r) = open_control(&conn, &body).await;
    assert!(matches!(
        read_reply(&mut r).await.message,
        Some(Ctl::HelloAck(_))
    ));
    let srv = tokio::time::timeout(WAIT, accepted)
        .await
        .expect("in time")
        .expect("join");
    // A second Hello is a violation.
    let again = message::encode(&hello_message(1, 0)).expect("encode");
    s.write_all(&(again.len() as u32).to_le_bytes())
        .await
        .expect("len");
    s.write_all(&again).await.expect("body");
    assert_eq!(closed_code(&conn).await, CloseCode::ProtocolError);
    drop(srv);
}

struct RecordingH3(Arc<AtomicBool>);

impl H3Handler for RecordingH3 {
    fn handle(&self, connecting: quinn::Connecting) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let flag = self.0.clone();
        Box::pin(async move {
            if connecting.await.is_ok() {
                flag.store(true, Ordering::SeqCst);
            }
        })
    }
}

#[tokio::test]
async fn alpn_h3_is_refused_without_a_handler_and_dispatched_with_one() {
    // No handler: the endpoint offers only hx/1, so an h3-only client cannot connect.
    let server = start_server(ServerOptions::default()).await;
    assert!(
        raw_quic(server.quic_addr().expect("quic"), b"h3")
            .await
            .is_err()
    );
    drop(server);

    // With a handler: h3 reaches it, hx/1 still goes to the native path.
    let seen = Arc::new(AtomicBool::new(false));
    let opts = ServerOptions {
        h3: Some(Arc::new(RecordingH3(seen.clone()))),
        ..Default::default()
    };
    let server = start_server(opts).await;
    let (_ep, _conn) = raw_quic(server.quic_addr().expect("quic"), b"h3")
        .await
        .expect("h3 connects");
    tokio::time::timeout(WAIT, async {
        while !seen.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("handler ran");
    let s2 = server.clone();
    let accepted = tokio::spawn(async move {
        s2.accept()
            .await
            .expect("pending")
            .accept(server_hello())
            .await
    });
    let c = client(TransportPreference::Quic)
        .connect(&target(&server, TransportPreference::Quic), &client_hello())
        .await
        .expect("native client still works");
    tokio::time::timeout(WAIT, accepted)
        .await
        .expect("in time")
        .expect("join")
        .expect("accept");
    drop(c);
}

#[tokio::test]
async fn pre_auth_slots_are_bounded() {
    let opts = ServerOptions {
        max_pending: 1,
        ..Default::default()
    };
    let server = start_server(opts).await;
    // A silent peer occupies the only slot.
    let (_ep, _hog) = raw_quic(server.quic_addr().expect("quic"), b"hx/1")
        .await
        .expect("first connects");
    let second = client(TransportPreference::Quic)
        .connect_quic(&target(&server, TransportPreference::Quic), &client_hello())
        .await;
    assert!(
        second.is_err(),
        "a second pre-auth connection must be refused while the slot is taken"
    );
}
