//! `Server::from_listeners_paused` serves on sockets somebody else bound (systemd socket
//! activation), reads nothing until `start`, and refuses a configuration that serves nothing.

mod common;

use std::{sync::Arc, time::Duration};

use common::{WAIT, client, client_hello, server_hello, server_tls, target};
use hx_transport::{Server, ServerOptions, TransportPreference};

/// A TCP listener and a UDP socket on the same ephemeral loopback port.
fn sockets() -> (std::net::UdpSocket, std::net::TcpListener) {
    for _ in 0..32 {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").expect("tcp");
        let port = tcp.local_addr().expect("addr").port();
        if let Ok(udp) = std::net::UdpSocket::bind(("127.0.0.1", port)) {
            return (udp, tcp);
        }
    }
    panic!("no port free for both TCP and UDP");
}

async fn served_only_after_start(pref: TransportPreference) {
    let (udp, tcp) = sockets();
    let port = tcp.local_addr().expect("addr").port();
    let server = Arc::new(
        Server::from_listeners_paused(udp, tcp, server_tls(), ServerOptions::default())
            .expect("from listeners"),
    );
    assert_eq!(server.quic_addr().map(|a| a.port()), Some(port));
    assert_eq!(server.websocket_addr().map(|a| a.port()), Some(port));

    let (c, t) = (client(pref), target(&server, pref));
    let mut connect = tokio::spawn(async move { c.connect(&t, &client_hello()).await });
    assert!(
        tokio::time::timeout(Duration::from_millis(500), &mut connect)
            .await
            .is_err(),
        "a paused server answered a client"
    );

    server.start();
    let s2 = server.clone();
    let accepted = tokio::spawn(async move {
        s2.accept()
            .await
            .expect("pending")
            .accept(server_hello())
            .await
    });
    tokio::time::timeout(WAIT, connect)
        .await
        .expect("connect after start")
        .expect("join")
        .expect("connected");
    tokio::time::timeout(WAIT, accepted)
        .await
        .expect("accept")
        .expect("join")
        .expect("accepted");
}

#[tokio::test]
async fn quic_on_a_handed_over_socket() {
    served_only_after_start(TransportPreference::Quic).await;
}

#[tokio::test]
async fn websocket_on_a_handed_over_socket() {
    served_only_after_start(TransportPreference::WebSocket).await;
}

#[tokio::test]
async fn a_server_that_serves_nothing_is_refused() {
    let (udp, tcp) = sockets();
    let opts = ServerOptions {
        quic: false,
        websocket: false,
        ..ServerOptions::default()
    };
    assert!(Server::from_listeners_paused(udp, tcp, server_tls(), opts).is_err());
}
