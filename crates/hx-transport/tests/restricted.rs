//! The restricted (unauthorized) connection state, pre-authentication limits and budgets.

mod common;

use std::{future::Future, time::Duration};

use bytes::Bytes;
use common::{
    WAIT, all_features, client, client_hello, pair_full, server_hello, start_server, target,
};
use hx_proto::{
    channel::CloseCode,
    pb::{
        self, ControlMessage, InputEvent, Intent, RefuseReason, TransferHeader,
        control_message::Message as Ctl, input_event::Event as Inp,
    },
    version::Features,
};
use hx_transport::{Error, ServerOptions, TransferKind, TransportPreference};

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

fn auth_message() -> ControlMessage {
    ControlMessage::new(Ctl::Auth(pb::Opaque {
        data: Bytes::from_static(b"pin"),
    }))
}

async fn unauthorized_pair(pref: TransportPreference) -> common::Pair {
    pair_full(
        pref,
        ServerOptions::default(),
        server_hello(),
        client_hello(),
        false,
    )
    .await
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
    server_sends_need_authorization,
    pre_auth_control_is_limited,
    auth_deadline_closes_unauthorized_connections,
    pair_intent_gets_no_features,
    unauthorized_connections_hold_their_slot,
    undecided_sessions_are_refused_busy,
);

async fn server_sends_need_authorization(pref: TransportPreference) {
    let p = unauthorized_pair(pref).await;
    assert!(!p.srv.is_authorized());
    assert_eq!(p.srv.enabled_features(), Features::NONE);
    assert!(p.client.is_authorized());
    let cursor = hx_proto::pb::CursorEvent {
        event: Some(hx_proto::pb::cursor_event::Event::Position(
            pb::CursorPosition {
                x: 1,
                y: 1,
                shape_id: 0,
                visible: true,
            },
        )),
    };
    assert!(matches!(
        p.srv.send_cursor(&cursor).await,
        Err(Error::NotAuthorized)
    ));
    assert!(matches!(
        p.srv.send_audio(0, Bytes::from_static(b"x")).await,
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
    // Authorization enables the channels, once, and only on a server.
    assert!(matches!(
        p.client.authorize(all_features()),
        Err(Error::WrongRole(_))
    ));
    p.srv.authorize(all_features()).expect("authorize");
    assert_eq!(p.srv.enabled_features(), all_features());
    assert!(p.srv.authorize(all_features()).is_err());
    p.srv.send_cursor(&cursor).await.expect("cursor works now");
    assert_eq!(
        within(p.client.recv_cursor()).await.expect("cursor"),
        cursor
    );
}

async fn pre_auth_control_is_limited(pref: TransportPreference) {
    // Pairing/auth envelopes, ping and goodbye work before authorization...
    let p = unauthorized_pair(pref).await;
    p.client
        .send_control(&auth_message())
        .await
        .expect("send auth");
    assert_eq!(
        within(p.srv.recv_control()).await.expect("auth arrives"),
        auth_message()
    );
    within(p.client.ping(WAIT)).await.expect("ping works");
    p.srv
        .send_control(&auth_message())
        .await
        .expect("server may answer");
    assert_eq!(
        within(p.client.recv_control()).await.expect("answer"),
        auth_message()
    );
    // ...anything else is a protocol violation.
    let view = ControlMessage::new(Ctl::ViewConfig(pb::ViewConfig::default()));
    p.client.send_control(&view).await.expect("sent");
    let info = within(p.srv.closed()).await;
    assert_eq!(info.code, CloseCode::ProtocolError);
    assert_eq!(
        within(p.client.closed()).await.code,
        CloseCode::ProtocolError
    );
}

async fn auth_deadline_closes_unauthorized_connections(pref: TransportPreference) {
    let opts = ServerOptions {
        auth_timeout: Some(Duration::from_millis(300)),
        ..Default::default()
    };
    let p = pair_full(pref, opts, server_hello(), client_hello(), false).await;
    let info = within(p.client.closed()).await;
    assert_eq!((info.code, info.by_peer), (CloseCode::Unauthorized, true));
    assert_eq!(within(p.srv.closed()).await.code, CloseCode::Unauthorized);

    // An authorized connection is not touched by the deadline.
    let opts = ServerOptions {
        auth_timeout: Some(Duration::from_millis(300)),
        ..Default::default()
    };
    let p = pair_full(pref, opts, server_hello(), client_hello(), true).await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(p.srv.close_info().is_none());
}

async fn pair_intent_gets_no_features(pref: TransportPreference) {
    let mut ch = client_hello();
    ch.intent = Intent::Pair;
    let p = pair_full(pref, ServerOptions::default(), server_hello(), ch, true).await;
    for c in [&p.client, &p.srv] {
        assert_eq!(c.negotiated().features, Features::NONE);
        assert!(c.negotiated().codecs.is_empty());
    }
    assert_eq!(p.srv.enabled_features(), Features::NONE);
    assert!(matches!(
        p.srv.send_audio(0, Bytes::from_static(b"x")).await,
        Err(Error::FeatureDisabled(_))
    ));
}

async fn unauthorized_connections_hold_their_slot(pref: TransportPreference) {
    let opts = ServerOptions {
        max_pending: 1,
        ..Default::default()
    };
    let server = start_server(opts).await;
    let s2 = server.clone();
    let first = tokio::spawn(async move {
        s2.accept()
            .await
            .expect("pending")
            .accept(server_hello())
            .await
            .expect("accept")
    });
    let c1 = client(pref)
        .connect(&target(&server, pref), &client_hello())
        .await
        .expect("first connects");
    let srv1 = within(first).await.expect("join");
    // The accepted but unauthorized connection still occupies the only slot.
    assert!(
        client(pref)
            .connect(&target(&server, pref), &client_hello())
            .await
            .is_err()
    );
    // Authorizing releases it.
    srv1.authorize(all_features()).expect("authorize");
    let s3 = server.clone();
    let second = tokio::spawn(async move {
        s3.accept()
            .await
            .expect("pending")
            .accept(server_hello())
            .await
            .expect("accept")
    });
    let c2 = client(pref)
        .connect(&target(&server, pref), &client_hello())
        .await
        .expect("second connects");
    within(second).await.expect("join");
    drop((c1, c2));
}

async fn undecided_sessions_are_refused_busy(pref: TransportPreference) {
    let opts = ServerOptions {
        decision_timeout: Duration::from_millis(300),
        ..Default::default()
    };
    let server = start_server(opts).await;
    let s2 = server.clone();
    let slow = tokio::spawn(async move {
        let pending = s2.accept().await.expect("pending");
        tokio::time::sleep(Duration::from_millis(900)).await;
        pending.accept(server_hello()).await
    });
    let err = client(pref)
        .connect(&target(&server, pref), &client_hello())
        .await
        .expect_err("refused automatically");
    assert!(
        matches!(
            err,
            Error::Refused {
                reason: RefuseReason::Busy,
                ..
            }
        ),
        "{err}"
    );
    assert!(matches!(
        within(slow).await.expect("join"),
        Err(Error::Timeout(_))
    ));
}

// ---------------------------------------------------------------- QUIC

#[tokio::test]
async fn quic_streams_wait_for_authorization() {
    let p = unauthorized_pair(TransportPreference::Quic).await;
    let wait = Duration::from_millis(300);
    // The server grants no unidirectional streams yet: input and transfers cannot even start.
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
    assert!(
        tokio::time::timeout(wait, p.client.open_transfer(TransferKind::File, h.clone()))
            .await
            .is_err()
    );
    p.srv.authorize(all_features()).expect("authorize");
    within(p.client.send_input(&key()))
        .await
        .expect("input now flows");
    assert_eq!(within(p.srv.recv_input()).await.expect("input"), key());
    let mut tx = within(p.client.open_transfer(TransferKind::File, h))
        .await
        .expect("transfer opens");
    tx.write(b"x").await.expect("write");
    tx.finish().await.expect("finish");
    assert_eq!(
        within(
            within(p.srv.accept_transfer())
                .await
                .expect("incoming")
                .read_to_end(10)
        )
        .await
        .expect("body"),
        Bytes::from_static(b"x")
    );
}

// ---------------------------------------------------------------- WebSocket

#[tokio::test]
async fn websocket_drops_input_before_authorization_and_keeps_control_flowing() {
    let p = unauthorized_pair(TransportPreference::WebSocket).await;
    for _ in 0..5000 {
        p.client.send_input(&key()).await.expect("send input");
    }
    // Control sent after thousands of dropped input events is delivered, and nothing was queued.
    p.client
        .send_control(&auth_message())
        .await
        .expect("send auth");
    assert_eq!(
        within(p.srv.recv_control()).await.expect("auth arrives"),
        auth_message()
    );
    assert_eq!(p.srv.stats().input_dropped_unauthorized, 5000);
    p.srv.authorize(all_features()).expect("authorize");
    p.client.send_input(&key()).await.expect("send");
    assert_eq!(
        within(p.srv.recv_input())
            .await
            .expect("input after authorize"),
        key()
    );
}

#[tokio::test]
async fn websocket_transfer_before_authorization_is_a_violation() {
    let p = unauthorized_pair(TransportPreference::WebSocket).await;
    let h = TransferHeader {
        mime: "x/y".into(),
        name: "a".into(),
        size: 1,
    };
    let _ = p.client.open_transfer(TransferKind::File, h).await;
    assert_eq!(within(p.srv.closed()).await.code, CloseCode::ProtocolError);
}

#[tokio::test]
async fn websocket_unread_input_never_blocks_control_and_overflow_closes() {
    let p = pair_full(
        TransportPreference::WebSocket,
        ServerOptions::default(),
        server_hello(),
        client_hello(),
        true,
    )
    .await;
    for _ in 0..200 {
        p.client.send_input(&key()).await.expect("send");
    }
    p.client
        .send_control(&auth_message())
        .await
        .expect("send control");
    assert_eq!(
        within(p.srv.recv_control())
            .await
            .expect("control is not stuck behind input"),
        auth_message()
    );
    // A peer that outpaces an application which is not reading is cut off, not buffered.
    for _ in 0..2000 {
        if p.client.send_input(&key()).await.is_err() {
            break;
        }
    }
    let info = within(p.srv.closed()).await;
    assert_eq!(info.code, CloseCode::ProtocolError);
    assert!(matches!(
        within(p.srv.recv_control()).await,
        Err(Error::Closed(_))
    ));
}

/// Reviewer scenario: 16 unread file transfers must not buffer more than the budget.
#[tokio::test]
async fn websocket_unread_transfers_stay_within_the_byte_budget() {
    let p = pair_full(
        TransportPreference::WebSocket,
        ServerOptions::default(),
        server_hello(),
        client_hello(),
        true,
    )
    .await;
    let chunk = vec![0xAB; 64 * 1024];
    for i in 0..16 {
        let h = TransferHeader {
            mime: "application/octet-stream".into(),
            name: format!("f{i}.bin"),
            size: 2 * 1024 * 1024,
        };
        let Ok(mut tx) = p.client.open_transfer(TransferKind::File, h).await else {
            break;
        };
        for _ in 0..32 {
            if tx.write(&chunk).await.is_err() {
                break;
            }
        }
        let peak = p.srv.stats().queued_transfer_bytes;
        assert!(peak <= 4 * 1024 * 1024, "queued {peak} bytes");
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let queued = p.srv.stats().queued_transfer_bytes;
    assert!(
        queued > 0 && queued <= 4 * 1024 * 1024,
        "queued {queued} bytes"
    );
    assert!(
        p.srv.close_info().is_none(),
        "over-budget transfers are aborted, not fatal"
    );
}

// ---------------------------------------------------------------- per-source limit

/// Reviewer scenario: one host holding every pre-auth slot must not lock out others.
#[tokio::test]
async fn one_source_cannot_exhaust_the_pre_auth_slots() {
    let server = start_server(ServerOptions::default()).await;
    let addr = server.websocket_addr().expect("ws");
    let mut hogs = Vec::new();
    for _ in 0..64 {
        let sock = tokio::net::TcpSocket::new_v4().expect("socket");
        sock.bind("127.0.0.2:0".parse().expect("addr"))
            .expect("bind source");
        if let Ok(s) = sock.connect(addr).await {
            hogs.push(s);
        }
    }
    assert!(hogs.len() >= 8, "the hog connections were opened");
    let s2 = server.clone();
    let accepted = tokio::spawn(async move {
        s2.accept()
            .await
            .expect("pending")
            .accept(server_hello())
            .await
            .expect("accept")
    });
    let c = client(TransportPreference::WebSocket)
        .connect(
            &target(&server, TransportPreference::WebSocket),
            &client_hello(),
        )
        .await
        .expect("a client from another address still connects");
    within(accepted).await.expect("join");
    drop((c, hogs));
}
