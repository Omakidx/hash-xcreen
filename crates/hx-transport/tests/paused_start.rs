//! `Server::bind_paused` binds the sockets but reads nothing until `start`: a process that
//! hardens itself (seccomp, mlockall, PR_SET_DUMPABLE) between bind and start never parses a
//! network byte before the hardening is in force.

mod common;

use std::{sync::Arc, time::Duration};

use common::{WAIT, client, client_hello, server_hello, server_tls, target};
use hx_transport::{Server, ServerOptions, TransportPreference};

async fn nothing_is_served_before_start(pref: TransportPreference) {
    let server = Arc::new(
        Server::bind_paused(
            "127.0.0.1:0".parse().expect("addr"),
            server_tls(),
            ServerOptions::default(),
        )
        .await
        .expect("bind"),
    );
    let (c, t) = (client(pref), target(&server, pref));
    let mut connect = tokio::spawn(async move { c.connect(&t, &client_hello()).await });

    // No TLS, no HelloAck, no refusal: the client is still waiting after 500 ms.
    assert!(
        tokio::time::timeout(Duration::from_millis(500), &mut connect)
            .await
            .is_err(),
        "a paused server answered a client"
    );

    // After start the very same attempt is served.
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
async fn quic_waits_for_start() {
    nothing_is_served_before_start(TransportPreference::Quic).await;
}

#[tokio::test]
async fn websocket_waits_for_start() {
    nothing_is_served_before_start(TransportPreference::WebSocket).await;
}

#[tokio::test]
async fn closing_a_paused_server_frees_its_ports_and_start_is_then_a_no_op() {
    let server = Server::bind_paused(
        "127.0.0.1:0".parse().expect("addr"),
        server_tls(),
        ServerOptions::default(),
    )
    .await
    .expect("bind");
    let addr = server.websocket_addr().expect("tcp");
    server.close();
    server.start();
    // The TCP port can be bound again: the listener was dropped by close.
    tokio::net::TcpListener::bind(addr)
        .await
        .expect("the port is free");
}
