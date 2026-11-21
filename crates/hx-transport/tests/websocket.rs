//! WebSocket fallback: protocol-level negatives with a raw socket client, and transport
//! selection (Auto) behaviour.

mod common;

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use common::{WAIT, client_hello, client_tls, server_hello, start_server, target};
use futures_util::{SinkExt, StreamExt};
use hx_proto::{
    VideoCodec,
    channel::CloseCode,
    message,
    pb::{self, ControlMessage, Intent, RefuseReason, control_message::Message as Ctl},
    version::{ALPN_WEBSOCKET, capabilities},
};
use hx_transport::{
    Client, ClientOptions, Error, Server, ServerOptions, TransportKind, TransportPreference,
};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::{WebSocketStream, client_async, tungstenite::Message};

type RawWs = WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>;

fn hello_message(major: u32, minor: u32) -> ControlMessage {
    ControlMessage::new(Ctl::Hello(pb::Hello {
        version: Some(pb::Version { major, minor }),
        capabilities: Some(capabilities(&[VideoCodec::H264], common::all_features())),
        intent: Intent::Session as i32,
        software: "raw".into(),
        device_name: "raw peer".into(),
    }))
}

async fn raw_ws(server: &Server, path: &str) -> Result<RawWs, String> {
    let addr = server.websocket_addr().expect("ws addr");
    let tcp = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let mut tls = (*client_tls()).clone();
    tls.alpn_protocols = vec![ALPN_WEBSOCKET.to_vec()];
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("name");
    let tls = TlsConnector::from(Arc::new(tls))
        .connect(name, tcp)
        .await
        .map_err(|e| e.to_string())?;
    let (ws, _) = client_async(format!("wss://localhost:{}{path}", addr.port()), tls)
        .await
        .map_err(|e| e.to_string())?;
    Ok(ws)
}

async fn send_control(ws: &mut RawWs, m: &ControlMessage) {
    let body = message::encode(m).expect("encode");
    let mut v = vec![0x01];
    v.extend_from_slice(&body);
    ws.send(Message::Binary(Bytes::from(v)))
        .await
        .expect("send");
}

/// Wait for the close frame and return its protocol close code.
async fn expect_close(ws: &mut RawWs) -> CloseCode {
    tokio::time::timeout(WAIT, async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Close(Some(f)))) => {
                    return CloseCode::from_websocket_code(u16::from(f.code))
                        .expect("a protocol close code");
                }
                Some(Ok(_)) => {}
                other => panic!("connection ended without a close frame: {other:?}"),
            }
        }
    })
    .await
    .expect("close frame in time")
}

async fn established(server: &Arc<Server>) -> (RawWs, hx_transport::Connection) {
    let s2 = server.clone();
    let accepted = tokio::spawn(async move {
        let c = s2
            .accept()
            .await
            .expect("pending")
            .accept(server_hello())
            .await
            .expect("accept");
        c.authorize(common::all_features()).expect("authorize");
        c
    });
    let mut ws = raw_ws(server, "/hx/1").await.expect("connect");
    send_control(&mut ws, &hello_message(1, 0)).await;
    match ws.next().await {
        Some(Ok(Message::Binary(b))) => {
            assert_eq!(b[0], 0x01);
            let m: ControlMessage = message::decode(&b[1..]).expect("reply");
            assert!(matches!(m.message, Some(Ctl::HelloAck(_))));
        }
        other => panic!("expected HelloAck, got {other:?}"),
    }
    let srv = tokio::time::timeout(WAIT, accepted)
        .await
        .expect("in time")
        .expect("join");
    (ws, srv)
}

#[tokio::test]
async fn different_major_is_refused_with_update_required() {
    let server = start_server(ServerOptions::default()).await;
    let mut ws = raw_ws(&server, "/hx/1").await.expect("connect");
    send_control(&mut ws, &hello_message(2, 0)).await;
    match ws.next().await {
        Some(Ok(Message::Binary(b))) => {
            let m: ControlMessage = message::decode(&b[1..]).expect("reply");
            match m.message {
                Some(Ctl::Refuse(r)) => assert_eq!(r.reason, RefuseReason::UpdateRequired as i32),
                other => panic!("expected Refuse, got {other:?}"),
            }
        }
        other => panic!("expected Refuse, got {other:?}"),
    }
    assert_eq!(expect_close(&mut ws).await, CloseCode::UpdateRequired);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), server.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn other_paths_are_not_found() {
    let server = start_server(ServerOptions::default()).await;
    let err = raw_ws(&server, "/other").await.expect_err("404");
    assert!(err.contains("404"), "{err}");
}

#[tokio::test]
async fn bad_first_messages_close_with_protocol_error() {
    let server = start_server(ServerOptions::default()).await;
    // Not a Hello.
    let mut ws = raw_ws(&server, "/hx/1").await.expect("connect");
    send_control(
        &mut ws,
        &ControlMessage::new(Ctl::Ping(pb::Ping { nonce: 1 })),
    )
    .await;
    assert_eq!(expect_close(&mut ws).await, CloseCode::ProtocolError);
    // Text instead of binary.
    let mut ws = raw_ws(&server, "/hx/1").await.expect("connect");
    ws.send(Message::Text("hello".into())).await.expect("send");
    assert_eq!(expect_close(&mut ws).await, CloseCode::ProtocolError);
    // Wrong channel.
    let mut ws = raw_ws(&server, "/hx/1").await.expect("connect");
    ws.send(Message::Binary(Bytes::from_static(&[0x02, 1, 2, 3])))
        .await
        .expect("send");
    assert_eq!(expect_close(&mut ws).await, CloseCode::ProtocolError);
    // Garbage protobuf and an oversized control message.
    let mut ws = raw_ws(&server, "/hx/1").await.expect("connect");
    ws.send(Message::Binary(Bytes::from_static(&[
        0x01, 0xFF, 0xFF, 0xFF,
    ])))
    .await
    .expect("send");
    assert_eq!(expect_close(&mut ws).await, CloseCode::ProtocolError);
    let mut ws = raw_ws(&server, "/hx/1").await.expect("connect");
    let mut big = vec![0x01];
    big.extend(std::iter::repeat_n(0u8, 70_000));
    ws.send(Message::Binary(Bytes::from(big)))
        .await
        .expect("send");
    assert_eq!(expect_close(&mut ws).await, CloseCode::ProtocolError);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), server.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn silent_peer_gets_hello_timeout() {
    let opts = ServerOptions {
        handshake_timeout: Duration::from_millis(300),
        ..Default::default()
    };
    let server = start_server(opts).await;
    let mut ws = raw_ws(&server, "/hx/1").await.expect("connect");
    assert_eq!(expect_close(&mut ws).await, CloseCode::HelloTimeout);
}

#[tokio::test]
async fn application_refusal_reaches_the_client_with_its_close_code() {
    let server = start_server(ServerOptions::default()).await;
    let s2 = server.clone();
    let refuser = tokio::spawn(async move {
        let pending = s2.accept().await.expect("pending");
        assert_eq!(pending.transport(), TransportKind::WebSocket);
        pending
            .refuse(RefuseReason::Busy, "try later")
            .await
            .expect("refuse");
    });
    let err = common::client(TransportPreference::WebSocket)
        .connect(
            &target(&server, TransportPreference::WebSocket),
            &client_hello(),
        )
        .await
        .expect_err("refused");
    assert!(
        matches!(err, Error::Refused { reason: RefuseReason::Busy, ref message, .. } if message == "try later"),
        "{err}"
    );
    tokio::time::timeout(WAIT, refuser)
        .await
        .expect("in time")
        .expect("join");
}

#[tokio::test]
async fn violations_after_the_handshake_close_the_connection() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "client sends video",
            vec![
                0x05, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        ),
        ("unknown channel", vec![0x7f, 0]),
        ("garbage input", vec![0x02, 0xFF, 0xFF, 0xFF]),
        ("cursor from client", vec![0x04, 0x0a, 0x00]),
        (
            "frame ack from nobody on the wrong side",
            vec![0x09, 1, 0, 0],
        ),
        ("second hello", {
            let mut v = vec![0x01];
            v.extend_from_slice(&message::encode(&hello_message(1, 0)).expect("encode"));
            v
        }),
        ("short transfer message", vec![0x07, 1, 0]),
        (
            "transfer id with the server's parity",
            vec![0x08, 2, 0, 0, 0, 3],
        ),
    ];
    for (name, msg) in cases {
        let server = start_server(ServerOptions::default()).await;
        let (mut ws, srv) = established(&server).await;
        ws.send(Message::Binary(Bytes::from(msg)))
            .await
            .expect("send");
        assert_eq!(
            expect_close(&mut ws).await,
            CloseCode::ProtocolError,
            "{name}"
        );
        let info = tokio::time::timeout(WAIT, srv.closed())
            .await
            .expect("server closes");
        assert_eq!(info.code, CloseCode::ProtocolError, "{name}");
    }
}

#[tokio::test]
async fn malformed_mouse_datagrams_are_dropped_not_fatal() {
    let server = start_server(ServerOptions::default()).await;
    let (mut ws, srv) = established(&server).await;
    // Reserved flag bit and wrong length: both are dropped and counted.
    ws.send(Message::Binary(Bytes::from_static(&[
        0x03, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ])))
    .await
    .expect("send");
    ws.send(Message::Binary(Bytes::from_static(&[0x03, 0x00, 1])))
        .await
        .expect("send");
    // A valid one still works afterwards.
    ws.send(Message::Binary(Bytes::from_static(&[
        0x03, 0, 1, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0,
    ])))
    .await
    .expect("send");
    let u = tokio::time::timeout(WAIT, srv.recv_mouse_move())
        .await
        .expect("in time")
        .expect("update");
    assert_eq!(u.absolute, Some((5, 6)));
    assert_eq!(srv.stats().datagrams_dropped, 2);
    assert!(srv.close_info().is_none());
}

#[tokio::test]
async fn auto_prefers_quic_and_falls_back_to_websocket() {
    // Both listeners: QUIC wins.
    let p = common::pair(TransportPreference::Auto).await;
    assert_eq!(p.client.transport(), TransportKind::Quic);
    drop(p);

    // WebSocket only: the UDP port is dead, so Auto falls back.
    let opts = ServerOptions {
        quic: false,
        ..Default::default()
    };
    let server = start_server(opts).await;
    let s2 = server.clone();
    let accepted = tokio::spawn(async move {
        s2.accept()
            .await
            .expect("pending")
            .accept(server_hello())
            .await
            .expect("accept")
    });
    let addr = server.websocket_addr().expect("ws");
    let tgt = hx_transport::Target {
        addr,
        server_name: rustls::pki_types::ServerName::try_from("localhost").expect("name"),
    };
    let client = Client::new(
        client_tls(),
        ClientOptions {
            preference: TransportPreference::Auto,
            quic_attempt_timeout: Duration::from_millis(500),
            ..Default::default()
        },
    );
    let c = client
        .connect(&tgt, &client_hello())
        .await
        .expect("falls back");
    assert_eq!(c.transport(), TransportKind::WebSocket);
    let srv = tokio::time::timeout(WAIT, accepted)
        .await
        .expect("in time")
        .expect("join");
    assert_eq!(srv.transport(), TransportKind::WebSocket);
}

#[tokio::test]
async fn auto_does_not_retry_a_refusal_over_the_other_transport() {
    let server = start_server(ServerOptions::default()).await;
    let s2 = server.clone();
    let refuser = tokio::spawn(async move {
        s2.accept()
            .await
            .expect("pending")
            .refuse(RefuseReason::Unauthorized, "no")
            .await
            .expect("refuse");
    });
    let err = common::client(TransportPreference::Auto)
        .connect(&target(&server, TransportPreference::Auto), &client_hello())
        .await
        .expect_err("refused");
    assert!(
        matches!(
            err,
            Error::Refused {
                reason: RefuseReason::Unauthorized,
                ..
            }
        ),
        "{err}"
    );
    tokio::time::timeout(WAIT, refuser)
        .await
        .expect("in time")
        .expect("join");
    // No second attempt arrives over WebSocket.
    assert!(
        tokio::time::timeout(Duration::from_millis(500), server.accept())
            .await
            .is_err()
    );
}

/// Reviewer scenario: a pre-Hello peer announcing a huge frame must be cut off at the header.
#[tokio::test]
async fn oversized_messages_are_closed_before_being_buffered() {
    let server = start_server(ServerOptions::default()).await;
    // Before the Hello: far above the 64 KiB client-to-server limit.
    let mut ws = raw_ws(&server, "/hx/1").await.expect("connect");
    let mut big = vec![0x01];
    big.extend(std::iter::repeat_n(0u8, 200 * 1024));
    let _ = ws.send(Message::Binary(Bytes::from(big))).await;
    assert_eq!(expect_close(&mut ws).await, CloseCode::ProtocolError);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), server.accept())
            .await
            .is_err()
    );
    // After the Hello: the same limit applies to an established connection.
    let (mut ws, srv) = established(&server).await;
    let mut big = vec![0x07, 1, 0, 0, 0, 2];
    big.extend(std::iter::repeat_n(0u8, 100 * 1024));
    let _ = ws.send(Message::Binary(Bytes::from(big))).await;
    assert_eq!(expect_close(&mut ws).await, CloseCode::ProtocolError);
    let info = tokio::time::timeout(WAIT, srv.closed())
        .await
        .expect("server closes");
    assert_eq!(info.code, CloseCode::ProtocolError);
}

/// The frame ack book keeps metadata for at most 256 frames, never their payloads.
#[tokio::test]
async fn unacknowledged_frames_are_capped() {
    let server = start_server(ServerOptions::default()).await;
    let (_ws, srv) = established(&server).await; // never reads, so never acks
    let mut sent = 0;
    for n in 0..400u32 {
        let header = hx_proto::media::MediaHeader {
            codec: VideoCodec::H264,
            flags: 0,
            frame_number: n,
            capture_timestamp_us: 0,
            payload_len: 4,
        };
        match srv
            .send_video_frame(header, Bytes::from_static(b"data"))
            .await
        {
            Ok(_) => sent += 1,
            Err(_) => break,
        }
    }
    assert_eq!(sent, 256);
}

/// A close frame from the server wins over a local write error. Reproduces the revoke seen on
/// real Incus (docs/spikes/1c-e2e-real-incus.md §7.2): the client's reader is behind (here: the
/// application does not take video, so the reader waits on a full video queue), the server
/// closes with `Unauthorized` and tears the TCP connection down, and the client keeps writing.
/// Its write fails before its reader has reached the close frame; the connection must still
/// report the server's code, not `InternalError` ("connection lost").
#[tokio::test]
async fn server_close_wins_over_a_write_error_behind_a_busy_reader() {
    let p = common::pair(TransportPreference::WebSocket).await;

    // Fill the client's video queue (16) and one more: its reader now waits on delivery.
    const QUEUED: u64 = 17;
    for n in 0..QUEUED as u32 {
        let header = hx_proto::media::MediaHeader {
            codec: VideoCodec::H264,
            flags: 0,
            frame_number: n,
            capture_timestamp_us: 0,
            payload_len: 4,
        };
        p.srv
            .send_video_frame(header, Bytes::from_static(b"data"))
            .await
            .expect("send frame");
    }
    tokio::time::timeout(WAIT, async {
        while p.client.stats().frames_received < QUEUED {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("client reader reaches the full video queue");

    // Revoke: the close frame goes out, then the server side goes away (its reader gives up
    // waiting for the client's close reply and the socket is dropped).
    p.srv.close(CloseCode::Unauthorized, "device revoked").await;
    drop(p.srv);

    // The client keeps sending input until its writer finds the socket gone.
    let input = pb::InputEvent {
        event: Some(pb::input_event::Event::Key(pb::KeyEvent {
            scancode: 4,
            pressed: true,
        })),
    };
    tokio::time::timeout(WAIT, async {
        while p.client.send_input(&input).await.is_ok() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("a write fails once the server is gone");

    let info = tokio::time::timeout(WAIT, p.client.closed())
        .await
        .expect("closed in time");
    assert_eq!(info.code, CloseCode::Unauthorized, "{info:?}");
    assert_eq!(info.reason, "device revoked");
    assert!(info.by_peer);
}

/// Same as above with a WebSocket `Ping` between the last frame and the close, from a raw
/// server so the order on the wire is fixed. Answering the `Ping` makes the client's reader
/// flush a `Pong` before it reads on; once the socket is gone that flush fails, and the read
/// must still reach the close frame instead of ending with the write error.
#[tokio::test]
async fn server_close_behind_a_ping_wins_over_the_failed_pong() {
    use tokio_tungstenite::tungstenite::protocol::{
        CloseFrame, frame::coding::CloseCode as WsCloseCode,
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let mut tls = (*common::server_tls()).clone();
    tls.alpn_protocols = vec![ALPN_WEBSOCKET.to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let (go_tx, go_rx) = tokio::sync::oneshot::channel::<()>();
    const QUEUED: u32 = 17;

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let tls = acceptor.accept(tcp).await.expect("TLS");
        let mut ws = tokio_tungstenite::accept_async(tls).await.expect("upgrade");
        match ws.next().await {
            Some(Ok(Message::Binary(b))) => assert_eq!(b[0], 0x01, "Hello on control"),
            other => panic!("expected Hello, got {other:?}"),
        }
        let ack = ControlMessage::new(Ctl::HelloAck(pb::HelloAck {
            version: Some(hx_proto::version::ProtocolVersion::CURRENT.into()),
            capabilities: server_hello().capabilities.into(),
            session_id: Bytes::from_static(&[7; 16]),
            software: "raw server".into(),
        }));
        let mut v = vec![0x01];
        v.extend_from_slice(&message::encode(&ack).expect("encode"));
        ws.send(Message::Binary(Bytes::from(v))).await.expect("ack");
        // Fill the client's video queue (16) and one more: its reader then waits on delivery.
        for n in 0..QUEUED {
            let header = hx_proto::media::MediaHeader {
                codec: VideoCodec::H264,
                flags: 0,
                frame_number: n,
                capture_timestamp_us: 0,
                payload_len: 4,
            };
            let mut v = vec![0x05];
            v.extend_from_slice(&header.encode().expect("header"));
            v.extend_from_slice(b"data");
            ws.send(Message::Binary(Bytes::from(v)))
                .await
                .expect("frame");
        }
        go_rx.await.expect("go");
        ws.send(Message::Ping(Bytes::new())).await.expect("ping");
        ws.send(Message::Close(Some(CloseFrame {
            code: WsCloseCode::from(CloseCode::Unauthorized.websocket_code()),
            reason: "device revoked".into(),
        })))
        .await
        .expect("close");
        // Like the real server, read on (the client's reader is stuck, so no close reply
        // comes) and then drop the socket. Dropping it with unread data would make the kernel
        // reset the connection and discard the close frame before it is sent.
        while let Ok(Some(Ok(_))) =
            tokio::time::timeout(Duration::from_millis(200), ws.next()).await
        {}
    });

    let client = common::client(TransportPreference::WebSocket)
        .connect(
            &hx_transport::Target {
                addr,
                server_name: rustls::pki_types::ServerName::try_from("localhost").expect("name"),
            },
            &client_hello(),
        )
        .await
        .expect("client connects");
    tokio::time::timeout(WAIT, async {
        while client.stats().frames_received < u64::from(QUEUED) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("client reader reaches the full video queue");
    go_tx.send(()).expect("server waits");
    tokio::time::timeout(WAIT, server)
        .await
        .expect("server in time")
        .expect("server task");

    let input = pb::InputEvent {
        event: Some(pb::input_event::Event::Key(pb::KeyEvent {
            scancode: 4,
            pressed: true,
        })),
    };
    tokio::time::timeout(WAIT, async {
        while client.send_input(&input).await.is_ok() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("a write fails once the server is gone");

    let info = tokio::time::timeout(WAIT, client.closed())
        .await
        .expect("closed in time");
    assert_eq!(info.code, CloseCode::Unauthorized, "{info:?}");
    assert_eq!(info.reason, "device revoked");
}
