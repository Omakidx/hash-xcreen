//! TLS behaviour: client certificates, no resumption, refusal text, error surfacing.

mod common;

use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use common::{
    WAIT, client_hello, client_tls_with_cert, mtls_server_tls, rejecting_client_tls, server_hello,
    start_server, start_server_with, target,
};
use hx_proto::pb::RefuseReason;
use hx_transport::{
    Client, ClientOptions, Error, ServerOptions, TransportKind, TransportPreference,
};
use rustls::pki_types::ServerName;

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
    client_certificates_reach_the_pending_session,
    resumption_never_skips_the_verifier,
    refusals_are_truncated_on_a_char_boundary_and_never_close_with_code_zero,
    verification_failures_are_a_distinct_error,
    reloaded_tls_serves_new_connections,
);

async fn client_certificates_reach_the_pending_session(pref: TransportPreference) {
    let (server_tls, count) = mtls_server_tls();
    let server = start_server_with(server_tls, ServerOptions::default()).await;
    let (client_tls, client_cert) = client_tls_with_cert();
    let s2 = server.clone();
    let expected = client_cert.clone();
    let accepted = tokio::spawn(async move {
        let pending = s2.accept().await.expect("pending");
        let seen = pending
            .peer_certificates()
            .expect("a client certificate is presented")
            .to_vec();
        assert_eq!(seen, vec![expected]);
        pending.accept(server_hello()).await.expect("accept")
    });
    let client = Client::new(
        client_tls,
        ClientOptions {
            preference: pref,
            ..Default::default()
        },
    );
    let c = client
        .connect(&target(&server, pref), &client_hello())
        .await
        .expect("mutual TLS connects");
    let srv = tokio::time::timeout(WAIT, accepted)
        .await
        .expect("in time")
        .expect("join");
    assert_eq!(
        srv.peer_certificates().map(<[_]>::to_vec),
        Some(vec![client_cert])
    );
    assert!(c.peer_certificates().is_some_and(|c| c.len() == 1));
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

/// A resumed TLS handshake skips the client-certificate verifier; the transport must not
/// allow it, so the verifier runs for every connection.
async fn resumption_never_skips_the_verifier(pref: TransportPreference) {
    let (server_tls, count) = mtls_server_tls();
    let server = start_server_with(server_tls, ServerOptions::default()).await;
    let (client_tls, _) = client_tls_with_cert(); // default settings: offers tickets it holds
    for round in 1..=3 {
        match pref {
            TransportPreference::WebSocket => {
                let mut cfg = (*client_tls).clone(); // shares the session store
                cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
                let tcp = tokio::net::TcpStream::connect(server.websocket_addr().expect("ws"))
                    .await
                    .expect("tcp");
                let name = ServerName::try_from("localhost").expect("name");
                let mut tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
                    .connect(name, tcp)
                    .await
                    .expect("TLS");
                // Reading lets the client process any session ticket the server sent.
                let _ = tokio::time::timeout(
                    Duration::from_millis(150),
                    tokio::io::AsyncReadExt::read(&mut tls, &mut [0u8; 1]),
                )
                .await;
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
            _ => {
                let mut cfg = (*client_tls).clone();
                cfg.alpn_protocols = vec![b"hx/1".to_vec()];
                let q = quinn::crypto::rustls::QuicClientConfig::try_from(cfg).expect("quic tls");
                let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().expect("addr"))
                    .expect("endpoint");
                ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(q)));
                let _conn = ep
                    .connect(server.quic_addr().expect("quic"), "localhost")
                    .expect("connect")
                    .await
                    .expect("handshake");
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
        assert_eq!(
            count.load(Ordering::SeqCst),
            round,
            "handshake {round} must run the verifier"
        );
    }
}

async fn refusals_are_truncated_on_a_char_boundary_and_never_close_with_code_zero(
    pref: TransportPreference,
) {
    let server = start_server(ServerOptions::default()).await;
    let s2 = server.clone();
    let long = "é日本語🙂".repeat(100); // far above 256 bytes, every char multi-byte
    let sent = long.clone();
    let refuser = tokio::spawn(async move {
        let pending = s2.accept().await.expect("pending");
        pending
            .refuse(RefuseReason::Unspecified, &sent)
            .await
            .expect("refuse");
    });
    let err = common::client(pref)
        .connect(&target(&server, pref), &client_hello())
        .await
        .expect_err("refused");
    match err {
        Error::Refused {
            reason, message, ..
        } => {
            assert_eq!(
                reason,
                RefuseReason::Unauthorized,
                "Unspecified is sent as Unauthorized"
            );
            assert!(message.len() <= 256 && !message.is_empty());
            assert!(
                long.starts_with(&message),
                "a clean prefix of the original text"
            );
        }
        other => panic!("expected Refused, got {other}"),
    }
    tokio::time::timeout(WAIT, refuser)
        .await
        .expect("in time")
        .expect("join");
}

async fn verification_failures_are_a_distinct_error(pref: TransportPreference) {
    let server = start_server(ServerOptions::default()).await;
    let client = Client::new(
        rejecting_client_tls(),
        ClientOptions {
            preference: pref,
            ..Default::default()
        },
    );
    let err = client
        .connect(&target(&server, pref), &client_hello())
        .await
        .expect_err("rejected");
    assert!(matches!(err, Error::PeerRejected(_)), "{err}");
    assert!(
        tokio::time::timeout(Duration::from_millis(200), server.accept())
            .await
            .is_err()
    );
}

async fn reloaded_tls_serves_new_connections(pref: TransportPreference) {
    let server = start_server(ServerOptions::default()).await;
    server.reload_tls(common::server_tls()).expect("reload");
    let s2 = server.clone();
    let accepted = tokio::spawn(async move {
        s2.accept()
            .await
            .expect("pending")
            .accept(server_hello())
            .await
            .expect("accept")
    });
    let c = common::client(pref)
        .connect(&target(&server, pref), &client_hello())
        .await
        .expect("connects after reload");
    tokio::time::timeout(WAIT, accepted)
        .await
        .expect("in time")
        .expect("join");
    assert_eq!(
        c.transport(),
        if pref == TransportPreference::Quic {
            TransportKind::Quic
        } else {
            TransportKind::WebSocket
        }
    );
}

/// Auto mode must not paper over a failed security check by trying another transport.
#[tokio::test]
async fn auto_does_not_fall_back_on_certificate_errors() {
    let server = start_server(ServerOptions::default()).await;
    let client = Client::new(
        rejecting_client_tls(),
        ClientOptions {
            preference: TransportPreference::Auto,
            ..Default::default()
        },
    );
    let started = std::time::Instant::now();
    let err = client
        .connect(&target(&server, TransportPreference::Auto), &client_hello())
        .await
        .expect_err("rejected");
    assert!(matches!(err, Error::PeerRejected(_)), "{err}");
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(
        tokio::time::timeout(Duration::from_millis(200), server.accept())
            .await
            .is_err()
    );
}
