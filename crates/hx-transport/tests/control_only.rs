//! Protocol 1.3 in the transport: `authorize_control_only` (the `INTENT_SETUP` connection),
//! `Intent::Setup` in `Hello`, `REFUSE_REASON_SETUP_CLOSED` as close code 10 / WebSocket 4010,
//! and a 1.2 peer.

mod common;

use std::{future::Future, sync::Arc, time::Duration};

use bytes::Bytes;
use common::{
    WAIT, all_features, client, client_hello, client_tls, pair_full, raw_quic, server_hello,
    start_server, target,
};
use futures_util::{SinkExt, StreamExt};
use hx_proto::{
    VideoCodec,
    channel::CloseCode,
    message,
    pb::{
        self, ControlMessage, CursorEvent, DeviceMgmt, InputEvent, Intent, RefuseReason,
        SetupMessage, TransferHeader, control_message::Message as Ctl, device_mgmt::Body as Dm,
        input_event::Event as Inp, setup_message::Body as Sb,
    },
    version::{ALPN_WEBSOCKET, Features, capabilities},
};
use hx_transport::{
    ClientHello, Error, Server, ServerHello, ServerOptions, TransferKind, TransportPreference,
};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::{WebSocketStream, client_async, tungstenite::Message};

async fn within<T>(f: impl Future<Output = T>) -> T {
    tokio::time::timeout(WAIT, f)
        .await
        .expect("operation timed out")
}

fn key() -> InputEvent {
    InputEvent {
        event: Some(Inp::Key(pb::KeyEvent {
            scancode: 4,
            pressed: true,
        })),
    }
}

fn setup_hello() -> ClientHello {
    ClientHello {
        capabilities: capabilities(&[], Features::SETUP.union(all_features())),
        intent: Intent::Setup,
        software: "hx-test-client 0.0".into(),
        device_name: "test device".into(),
    }
}

/// What a gateway advertises on `INTENT_SETUP`: the setup feature and nothing else.
fn setup_server_hello() -> ServerHello {
    ServerHello {
        capabilities: capabilities(&[], Features::SETUP),
        software: "hx-test-server 0.0".into(),
    }
}

fn state_push() -> ControlMessage {
    ControlMessage::new(Ctl::Setup(SetupMessage {
        request_id: 0,
        body: Some(Sb::State(pb::SetupState {
            job: pb::SetupJobState::Idle as i32,
            ..Default::default()
        })),
    }))
}

fn cancel_request() -> ControlMessage {
    ControlMessage::new(Ctl::Setup(SetupMessage {
        request_id: 9,
        body: Some(Sb::Cancel(pb::SetupCancel {})),
    }))
}

/// An accepted `INTENT_SETUP` pair; the server side is not authorized yet.
async fn setup_pair_unauthorized(pref: TransportPreference) -> common::Pair {
    pair_full(
        pref,
        ServerOptions::default(),
        setup_server_hello(),
        setup_hello(),
        false,
    )
    .await
}

async fn setup_pair(pref: TransportPreference) -> common::Pair {
    let p = setup_pair_unauthorized(pref).await;
    p.srv
        .authorize_control_only(Features::SETUP)
        .expect("authorize control only");
    p
}

macro_rules! both {
    ($($name:ident),* $(,)?) => {
        $(
            mod $name {
                use super::*;
                #[tokio::test]
                async fn quic() { super::$name(TransportPreference::Quic).await }
                #[tokio::test]
                async fn websocket() { super::$name(TransportPreference::WebSocket).await }
            }
        )*
    };
}

both!(
    setup_intent_negotiates_only_the_setup_feature,
    control_only_state_and_setup_messages_flow_both_ways,
    control_only_is_claimed_once_and_only_by_a_server,
    control_only_satisfies_the_auth_deadline,
    control_only_releases_the_pre_auth_slot,
    control_only_server_sends_are_refused,
    control_only_drops_input_and_mouse,
    control_only_accepts_only_setup_and_goodbye_from_the_peer,
    setup_before_authorization_is_a_violation,
    setup_without_the_feature_is_a_violation_and_cannot_be_sent,
    control_only_ping_and_goodbye_work,
);

async fn setup_intent_negotiates_only_the_setup_feature(pref: TransportPreference) {
    let p = setup_pair_unauthorized(pref).await;
    for c in [&p.client, &p.srv] {
        assert_eq!(c.negotiated().features, Features::SETUP);
        assert_eq!(c.negotiated().version.minor, 3);
    }
    // Before authorization nothing is enabled on the server.
    assert_eq!(p.srv.enabled_features(), Features::NONE);
    assert!(!p.srv.is_authorized());
    assert!(!p.srv.is_control_only());
    p.srv
        .authorize_control_only(Features::SETUP)
        .expect("authorize");
    assert_eq!(p.srv.enabled_features(), Features::SETUP);
    assert!(p.srv.is_authorized() && p.srv.is_control_only());
    assert!(!p.client.is_control_only());
}

async fn control_only_state_and_setup_messages_flow_both_ways(pref: TransportPreference) {
    let p = setup_pair(pref).await;
    p.srv.send_control(&state_push()).await.expect("state");
    assert_eq!(
        within(p.client.recv_control()).await.expect("recv"),
        state_push()
    );
    p.client
        .send_control(&cancel_request())
        .await
        .expect("request");
    assert_eq!(
        within(p.srv.recv_control()).await.expect("recv"),
        cancel_request()
    );
    assert!(p.srv.close_info().is_none() && p.client.close_info().is_none());
}

async fn control_only_is_claimed_once_and_only_by_a_server(pref: TransportPreference) {
    let p = setup_pair(pref).await;
    assert!(p.srv.authorize_control_only(Features::SETUP).is_err());
    // It cannot be widened afterwards, by either call.
    assert!(p.srv.authorize(all_features()).is_err());
    assert_eq!(p.srv.enabled_features(), Features::SETUP);
    assert!(p.srv.is_control_only());
    assert!(matches!(
        p.client.authorize_control_only(Features::SETUP),
        Err(Error::WrongRole(_))
    ));
    // And the other way round: a fully authorized connection cannot become control-only.
    let q = pair_full(
        pref,
        ServerOptions::default(),
        server_hello(),
        client_hello(),
        true,
    )
    .await;
    assert!(q.srv.authorize_control_only(Features::SETUP).is_err());
    assert!(!q.srv.is_control_only());
}

async fn control_only_satisfies_the_auth_deadline(pref: TransportPreference) {
    let opts = ServerOptions {
        auth_timeout: Some(Duration::from_millis(300)),
        ..Default::default()
    };
    let p = pair_full(pref, opts, setup_server_hello(), setup_hello(), false).await;
    p.srv
        .authorize_control_only(Features::SETUP)
        .expect("authorize");
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(p.srv.close_info().is_none(), "deadline must not fire");
    assert!(p.client.close_info().is_none());
    // Control still works afterwards.
    p.srv.send_control(&state_push()).await.expect("state");
    assert_eq!(
        within(p.client.recv_control()).await.expect("recv"),
        state_push()
    );
}

async fn control_only_releases_the_pre_auth_slot(pref: TransportPreference) {
    let opts = ServerOptions {
        max_pending: 1,
        ..Default::default()
    };
    let server = start_server(opts).await;
    let s2 = server.clone();
    let first = tokio::spawn(async move {
        let c = s2
            .accept()
            .await
            .expect("pending")
            .accept(setup_server_hello())
            .await
            .expect("accept");
        c.authorize_control_only(Features::SETUP)
            .expect("authorize");
        c
    });
    let c1 = client(pref)
        .connect(&target(&server, pref), &setup_hello())
        .await
        .expect("first connects");
    let _srv1 = within(first).await.expect("join");
    // The slot is free again although the first connection is still open.
    let s3 = server.clone();
    let second = tokio::spawn(async move {
        let p = s3.accept().await.expect("pending");
        p.accept(setup_server_hello()).await
    });
    let c2 = client(pref)
        .connect(&target(&server, pref), &setup_hello())
        .await
        .expect("second connects: the slot was released");
    within(second).await.expect("join").expect("accepted");
    drop((c1, c2));
}

async fn control_only_server_sends_are_refused(pref: TransportPreference) {
    let p = setup_pair(pref).await;
    let cursor = CursorEvent {
        event: Some(pb::cursor_event::Event::Position(pb::CursorPosition {
            x: 1,
            y: 1,
            shape_id: 0,
            visible: true,
        })),
    };
    assert!(matches!(
        p.srv.send_cursor(&cursor).await,
        Err(Error::NotAuthorized)
    ));
    assert!(matches!(
        p.srv.send_audio(0, Bytes::from_static(b"x")).await,
        Err(Error::NotAuthorized)
    ));
    let header = hx_proto::media::MediaHeader {
        frame_number: 1,
        capture_timestamp_us: 0,
        flags: 0,
        codec: VideoCodec::H264,
        payload_len: 1,
    };
    assert!(matches!(
        p.srv
            .send_video_frame(header, Bytes::from_static(b"x"))
            .await,
        Err(Error::NotAuthorized)
    ));
    let h = TransferHeader {
        mime: "x/y".into(),
        name: "a".into(),
        size: 0,
    };
    assert!(matches!(
        p.srv.open_transfer(TransferKind::File, h).await,
        Err(Error::NotAuthorized)
    ));
    // The refusals are local: the connection stays up.
    assert!(p.srv.close_info().is_none());
}

async fn control_only_drops_input_and_mouse(pref: TransportPreference) {
    let p = setup_pair(pref).await;
    let wait = Duration::from_millis(300);
    match pref {
        TransportPreference::Quic => {
            // The server granted no unidirectional streams and never will: input cannot even
            // be started, and neither can a transfer.
            assert!(
                tokio::time::timeout(wait, p.client.send_input(&key()))
                    .await
                    .is_err()
            );
            let h = TransferHeader {
                mime: "x/y".into(),
                name: "a".into(),
                size: 1,
            };
            // (The client refuses locally here, since only SETUP was negotiated; either way
            // no transfer stream is opened.)
            assert!(
                !matches!(
                    tokio::time::timeout(wait, p.client.open_transfer(TransferKind::File, h)).await,
                    Ok(Ok(_))
                ),
                "no transfer may open"
            );
        }
        _ => {
            for _ in 0..50 {
                p.client.send_input(&key()).await.expect("send input");
            }
            for i in 0..10 {
                p.client.send_mouse_move(false, i, i).await.expect("mouse");
            }
        }
    }
    // Control sent afterwards still arrives, and nothing was queued as input.
    p.client
        .send_control(&cancel_request())
        .await
        .expect("request");
    assert_eq!(
        within(p.srv.recv_control()).await.expect("recv"),
        cancel_request()
    );
    assert!(
        tokio::time::timeout(wait, p.srv.recv_input())
            .await
            .is_err(),
        "no input is ever queued"
    );
    assert!(
        tokio::time::timeout(wait, p.srv.recv_mouse_move())
            .await
            .is_err(),
        "no mouse motion is ever queued"
    );
    if pref == TransportPreference::WebSocket {
        assert_eq!(p.srv.stats().input_dropped_unauthorized, 50);
    }
    assert!(p.srv.close_info().is_none());
}

/// Messages a control-only peer must not send: each closes the connection with PROTOCOL_ERROR.
async fn control_only_accepts_only_setup_and_goodbye_from_the_peer(pref: TransportPreference) {
    let forbidden: Vec<ControlMessage> = vec![
        ControlMessage::new(Ctl::Auth(pb::Opaque {
            data: Bytes::from_static(b"pin"),
        })),
        ControlMessage::new(Ctl::Pairing(pb::Opaque {
            data: Bytes::from_static(b"x"),
        })),
        ControlMessage::new(Ctl::ViewConfig(pb::ViewConfig::default())),
        ControlMessage::new(Ctl::RequestKeyframe(pb::RequestKeyframe::default())),
        ControlMessage::new(Ctl::Stats(pb::ClientStats::default())),
        // Device management, including the pairing-code request: never on a setup connection.
        ControlMessage::new(Ctl::DeviceMgmt(DeviceMgmt {
            request_id: 1,
            body: Some(Dm::List(pb::ListDevices {})),
        })),
        ControlMessage::new(Ctl::DeviceMgmt(DeviceMgmt {
            request_id: 1,
            body: Some(Dm::CreatePairingCode(pb::CreatePairingCode {
                expires_in_s: 600,
            })),
        })),
    ];
    for m in forbidden {
        // The client offers every feature so that it is allowed to send these; the server
        // enabled only SETUP.
        let p = setup_pair(pref).await;
        let sent = p.client.send_control(&m).await;
        assert!(sent.is_ok(), "client side accepts {m:?}: {sent:?}");
        let info = within(p.srv.closed()).await;
        assert_eq!(info.code, CloseCode::ProtocolError, "{m:?}");
    }
}

async fn setup_before_authorization_is_a_violation(pref: TransportPreference) {
    let p = setup_pair_unauthorized(pref).await;
    p.client
        .send_control(&cancel_request())
        .await
        .expect("client sends");
    assert_eq!(within(p.srv.closed()).await.code, CloseCode::ProtocolError);
}

/// The SETUP feature is a precondition on both ends, not only a convention.
async fn setup_without_the_feature_is_a_violation_and_cannot_be_sent(pref: TransportPreference) {
    // A normal session negotiates no SETUP: neither side may send a setup message.
    let p = pair_full(
        pref,
        ServerOptions::default(),
        server_hello(),
        client_hello(),
        true,
    )
    .await;
    assert!(matches!(
        p.client.send_control(&cancel_request()).await,
        Err(Error::FeatureDisabled(_))
    ));
    assert!(matches!(
        p.srv.send_control(&state_push()).await,
        Err(Error::FeatureDisabled(_))
    ));
    // A server that negotiated SETUP but did not enable it for this connection treats an
    // incoming setup message as a protocol violation.
    let q = setup_pair_unauthorized(pref).await;
    q.srv
        .authorize(Features::AUDIO)
        .expect("authorize without SETUP");
    q.client
        .send_control(&cancel_request())
        .await
        .expect("client has the feature");
    assert_eq!(within(q.srv.closed()).await.code, CloseCode::ProtocolError);
}

async fn control_only_ping_and_goodbye_work(pref: TransportPreference) {
    let p = setup_pair(pref).await;
    within(p.client.ping(WAIT)).await.expect("ping");
    let bye = ControlMessage::new(Ctl::Goodbye(pb::Goodbye {
        code: 0,
        message: "done".into(),
        ..Default::default()
    }));
    p.client.send_control(&bye).await.expect("goodbye");
    assert_eq!(within(p.srv.recv_control()).await.expect("recv"), bye);
    assert!(p.srv.close_info().is_none());
}

#[tokio::test]
async fn websocket_transfers_on_a_control_only_connection_are_a_violation() {
    let p = setup_pair(TransportPreference::WebSocket).await;
    let h = TransferHeader {
        mime: "x/y".into(),
        name: "a".into(),
        size: 1,
    };
    // The client offered file transfer in its Hello but the server advertised only SETUP, so
    // the client refuses locally; send the bytes of a transfer through a second connection
    // that negotiated it to prove the server-side rule rather than the client-side one.
    let _ = p.client.open_transfer(TransferKind::File, h).await;
    let q = pair_full(
        TransportPreference::WebSocket,
        ServerOptions::default(),
        ServerHello {
            capabilities: capabilities(&[], Features::SETUP.union(all_features())),
            software: "t".into(),
        },
        setup_hello(),
        false,
    )
    .await;
    q.srv
        .authorize_control_only(Features::SETUP.union(all_features()))
        .expect("authorize");
    // Even with the transfer features enabled, a control-only connection refuses transfers.
    let h = TransferHeader {
        mime: "x/y".into(),
        name: "a".into(),
        size: 1,
    };
    let _ = q.client.open_transfer(TransferKind::File, h).await;
    assert_eq!(within(q.srv.closed()).await.code, CloseCode::ProtocolError);
    assert!(q.srv.is_control_only());
    // The server side cannot open one either.
    assert!(
        q.srv
            .open_transfer(
                TransferKind::File,
                TransferHeader {
                    mime: "x/y".into(),
                    name: "a".into(),
                    size: 0,
                }
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn quic_uni_stream_credit_stays_zero_after_control_only_authorization() {
    let p = setup_pair(TransportPreference::Quic).await;
    // Even a fully-negotiated client cannot open a unidirectional stream: the server never
    // lifted its limit of 0, which is what bounds a setup peer to the control stream.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let blocked = tokio::time::timeout(Duration::from_millis(500), p.client.send_input(&key()))
        .await
        .is_err();
    assert!(blocked, "uni-stream credit must stay 0");
    // Whereas the fully authorized sibling gets its credit.
    let q = pair_full(
        TransportPreference::Quic,
        ServerOptions::default(),
        server_hello(),
        client_hello(),
        true,
    )
    .await;
    within(q.client.send_input(&key()))
        .await
        .expect("a fully authorized connection gets credit");
}

// ---------------------------------------------------------------- refuse and close codes

#[tokio::test]
async fn setup_closed_refusal_reaches_the_client_and_closes_with_code_10_over_quic() {
    let server = start_server(ServerOptions::default()).await;
    let s2 = server.clone();
    let refuser = tokio::spawn(async move {
        let pending = s2.accept().await.expect("pending");
        assert_eq!(pending.hello().intent, Intent::Setup as i32);
        pending
            .refuse(RefuseReason::SetupClosed, "setup is closed")
            .await
            .expect("refuse");
    });
    let err = client(TransportPreference::Quic)
        .connect(&target(&server, TransportPreference::Quic), &setup_hello())
        .await
        .expect_err("refused");
    match err {
        Error::Refused {
            reason, message, ..
        } => {
            assert_eq!(reason, RefuseReason::SetupClosed);
            assert_eq!(message, "setup is closed");
        }
        other => panic!("expected Refused, got {other}"),
    }
    within(refuser).await.expect("join");

    // The raw QUIC close code on the wire is 10.
    let s3 = server.clone();
    let refuser = tokio::spawn(async move {
        let pending = s3.accept().await.expect("pending");
        pending
            .refuse(RefuseReason::SetupClosed, "closed")
            .await
            .expect("refuse");
    });
    let (_ep, conn) = raw_quic(server.quic_addr().expect("quic"), b"hx/1")
        .await
        .expect("connect");
    let hello = ControlMessage::new(Ctl::Hello(pb::Hello {
        version: Some(hx_proto::version::ProtocolVersion::CURRENT.into()),
        capabilities: Some(capabilities(&[], Features::SETUP)),
        intent: Intent::Setup as i32,
        software: "raw".into(),
        device_name: "raw".into(),
    }));
    let body = message::encode(&hello).expect("encode");
    let (mut s, _r) = conn.open_bi().await.expect("open control");
    s.write_all(&[0x01]).await.expect("channel");
    s.write_all(&(body.len() as u32).to_le_bytes())
        .await
        .expect("len");
    s.write_all(&body).await.expect("body");
    let code = match within(conn.closed()).await {
        quinn::ConnectionError::ApplicationClosed(ac) => ac.error_code.into_inner(),
        other => panic!("unexpected close: {other}"),
    };
    assert_eq!(code, 10);
    assert_eq!(CloseCode::from_code(code), CloseCode::SetupClosed);
    within(refuser).await.expect("join");
}

#[tokio::test]
async fn setup_closed_refusal_closes_websocket_with_4010() {
    let server = start_server(ServerOptions::default()).await;
    let s2 = server.clone();
    let refuser = tokio::spawn(async move {
        let pending = s2.accept().await.expect("pending");
        pending
            .refuse(RefuseReason::SetupClosed, "closed")
            .await
            .expect("refuse");
    });
    let mut ws = raw_ws(&server).await;
    let hello = ControlMessage::new(Ctl::Hello(pb::Hello {
        version: Some(hx_proto::version::ProtocolVersion::CURRENT.into()),
        capabilities: Some(capabilities(&[], Features::SETUP)),
        intent: Intent::Setup as i32,
        software: "raw".into(),
        device_name: "raw".into(),
    }));
    let mut v = vec![0x01];
    v.extend_from_slice(&message::encode(&hello).expect("encode"));
    ws.send(Message::Binary(Bytes::from(v)))
        .await
        .expect("send");
    let (refuse_seen, code) = within(async {
        let mut refuse_seen = false;
        loop {
            match ws.next().await {
                Some(Ok(Message::Binary(b))) => {
                    let m: ControlMessage = message::decode(&b[1..]).expect("reply");
                    if let Some(Ctl::Refuse(r)) = m.message {
                        refuse_seen = r.reason == RefuseReason::SetupClosed as i32;
                    }
                }
                Some(Ok(Message::Close(Some(f)))) => break (refuse_seen, u16::from(f.code)),
                Some(Ok(_)) => {}
                other => panic!("ended without a close frame: {other:?}"),
            }
        }
    })
    .await;
    assert!(refuse_seen, "Refuse{{SETUP_CLOSED}} precedes the close");
    assert_eq!(code, 4010);
    assert_eq!(
        CloseCode::from_websocket_code(code),
        Some(CloseCode::SetupClosed)
    );
    within(refuser).await.expect("join");
}

type RawWs = WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>;

async fn raw_ws(server: &Arc<Server>) -> RawWs {
    let addr = server.websocket_addr().expect("ws addr");
    let tcp = TcpStream::connect(addr).await.expect("tcp");
    let mut tls = (*client_tls()).clone();
    tls.alpn_protocols = vec![ALPN_WEBSOCKET.to_vec()];
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("name");
    let tls = TlsConnector::from(Arc::new(tls))
        .connect(name, tcp)
        .await
        .expect("tls");
    let (ws, _) = client_async(format!("wss://localhost:{}/hx/1", addr.port()), tls)
        .await
        .expect("upgrade");
    ws
}

// ---------------------------------------------------------------- a 1.2 peer

#[tokio::test]
async fn a_1_2_client_still_interoperates_with_a_1_3_server() {
    let server = start_server(ServerOptions::default()).await;
    let s2 = server.clone();
    let accepted = tokio::spawn(async move {
        let pending = s2.accept().await.expect("pending");
        // The server offers everything it has, including DeviceMgmt (1.2) and SETUP (1.3).
        let c = pending
            .accept(ServerHello {
                capabilities: capabilities(&[VideoCodec::H264], Features::defined_up_to(3)),
                software: "hx-test-server".into(),
            })
            .await
            .expect("accept");
        c.authorize(Features::defined_up_to(3).without(Features::SETUP))
            .expect("authorize");
        c
    });
    let (_ep, conn) = raw_quic(server.quic_addr().expect("quic"), b"hx/1")
        .await
        .expect("connect");
    // A 1.2 client: its own minor and the bits it knows (it has never heard of bit 5).
    let hello = ControlMessage::new(Ctl::Hello(pb::Hello {
        version: Some(pb::Version { major: 1, minor: 2 }),
        capabilities: Some(capabilities(
            &[VideoCodec::H264],
            Features::defined_up_to(2),
        )),
        intent: Intent::Session as i32,
        software: "hx-1.2".into(),
        device_name: "old".into(),
    }));
    let body = message::encode(&hello).expect("encode");
    let (mut s, mut r) = conn.open_bi().await.expect("open control");
    s.write_all(&[0x01]).await.expect("channel");
    s.write_all(&(body.len() as u32).to_le_bytes())
        .await
        .expect("len");
    s.write_all(&body).await.expect("body");
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await.expect("reply length");
    let mut buf = vec![0u8; u32::from_le_bytes(len) as usize];
    r.read_exact(&mut buf).await.expect("reply body");
    let ack: ControlMessage = message::decode(&buf).expect("a valid HelloAck");
    let Some(Ctl::HelloAck(ack)) = ack.message else {
        panic!("expected HelloAck")
    };
    // The server announces 1.3; the 1.2 client negotiates down by itself (lowest minor).
    assert_eq!(ack.version, Some(pb::Version { major: 1, minor: 3 }));
    let srv = within(accepted).await.expect("join");
    assert_eq!(srv.negotiated().version.minor, 2);
    assert!(!srv.negotiated().features.contains(Features::SETUP));
    assert!(
        srv.negotiated()
            .features
            .contains(Features::DEVICE_MANAGEMENT)
    );
    // A setup message is not sendable on it, and the 1.2 conversation (control) works.
    assert!(matches!(
        srv.send_control(&state_push()).await,
        Err(Error::FeatureDisabled(_))
    ));
    let devices = ControlMessage::new(Ctl::DeviceMgmt(DeviceMgmt {
        request_id: 1,
        body: Some(Dm::List(pb::ListDevices {})),
    }));
    let body = message::encode(&devices).expect("encode");
    s.write_all(&(body.len() as u32).to_le_bytes())
        .await
        .expect("len");
    s.write_all(&body).await.expect("body");
    assert_eq!(within(srv.recv_control()).await.expect("recv"), devices);
}
