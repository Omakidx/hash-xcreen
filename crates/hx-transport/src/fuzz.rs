//! Entry points for the cargo-fuzz targets in `fuzz/` (feature `fuzzing`, never part of a
//! product build).
//!
//! This is a child of the `ws` module so that it can reach the WebSocket reader's private
//! pieces without widening their visibility. Nothing here opens a socket: the bytes a peer
//! would send are served from memory.

use std::{
    cell::RefCell,
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use futures_util::StreamExt;
use hx_proto::version::{Features, ProtocolVersion};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::protocol::Role as WsRole;

use super::{
    AckBook, Backend, Connection, GuardedIo, Inner, Message, Parts, PeerInfo, Role, TransportKind,
    WebSocketStream, WsBackend, handle_binary, mpsc, read_first_control, watch, ws_config,
};
use crate::ConnectionOptions;
use crate::server::{HelloCheck, check_hello as check_hello_inner};

/// Serves a fixed byte string, then end of stream; writes are discarded.
struct SliceIo {
    data: Vec<u8>,
    at: usize,
}

impl AsyncRead for SliceIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let n = (self.data.len() - self.at).min(buf.remaining());
        buf.put_slice(&self.data[self.at..self.at + n]);
        self.at += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for SliceIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(b.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

thread_local! {
    static RT: RefCell<Option<tokio::runtime::Runtime>> = const { RefCell::new(None) };
}

fn block_on<F: Future>(f: F) -> F::Output {
    RT.with(|cell| {
        let mut rt = cell.borrow_mut();
        let rt = rt.get_or_insert_with(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a runtime")
        });
        rt.block_on(f)
    })
}

/// The first control message of a connection: `Hello` check on arbitrary bytes (what a QUIC
/// control stream or the first WebSocket message carries).
pub fn check_hello(data: &[u8]) {
    if let Ok(HelloCheck::Ok(h)) = check_hello_inner(data) {
        // A `Hello` that passed is a `Hello` the codec round-trips.
        let again = hx_proto::message::encode(&hx_proto::pb::ControlMessage::new(
            hx_proto::pb::control_message::Message::Hello(h.clone()),
        ))
        .expect("a decoded Hello encodes");
        let back: hx_proto::pb::ControlMessage =
            hx_proto::message::decode(&again).expect("and decodes again");
        assert_eq!(
            back.message,
            Some(hx_proto::pb::control_message::Message::Hello(h))
        );
    }
}

/// Raw bytes as the peer's side of a WebSocket (frames the server end must read, i.e. masked),
/// with the size limits of the reading `role`.
fn ws_over(data: &[u8], role: Role) -> WebSocketStream<GuardedIo> {
    let io = GuardedIo::new(Box::new(SliceIo {
        data: data.to_vec(),
        at: 0,
    }));
    futures_util::FutureExt::now_or_never(WebSocketStream::from_raw_socket(
        io,
        WsRole::Server,
        Some(ws_config(role)),
    ))
    .expect("from_raw_socket does not wait")
}

/// The first message of a WebSocket connection, from raw bytes on the wire: tungstenite's
/// framing with the server's size limits, then the `Hello` path (`read_first_control` and
/// `check_hello`).
pub fn ws_first_message(data: &[u8]) {
    block_on(async {
        let mut ws = ws_over(data, Role::Server);
        if let Ok(first) = read_first_control(&mut ws).await {
            let _ = check_hello_inner(&first);
        }
    });
}

fn inner_for(role: Role) -> Arc<Inner> {
    let (hi, _hi_rx) = mpsc::channel(256);
    let (lo, _lo_rx) = mpsc::channel(8);
    let (_done_tx, done) = watch::channel(false);
    let backend = Backend::Ws(WsBackend {
        hi,
        lo,
        acks: std::sync::Mutex::new(AckBook::default()),
        incoming: std::sync::Mutex::new(Default::default()),
        outgoing: Arc::new(std::sync::Mutex::new(Default::default())),
        next_transfer_id: std::sync::atomic::AtomicU32::new(2),
        done,
        write_failed: Arc::new(watch::channel(false).0),
    });
    let parts = Parts {
        role,
        kind: TransportKind::WebSocket,
        negotiated: hx_proto::version::Negotiated {
            version: ProtocolVersion { major: 1, minor: 2 },
            features: Features::defined_up_to(2),
            codecs: vec![hx_proto::VideoCodec::H264],
            max_file_bytes: 4 << 30,
        },
        peer: PeerInfo {
            software: String::new(),
            device_name: String::new(),
        },
        session_id: [0; 16],
        peer_certs: None,
        remote_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
        options: ConnectionOptions::default(),
        slot: None,
        auth_timeout: Some(Duration::from_secs(60)),
    };
    Inner::new(parts, backend)
}

/// An established, authorized connection reading what a peer sends: WebSocket framing, then the
/// channel router (`handle_binary`: control, input, cursor, mouse and audio datagrams, video,
/// frame acks, clipboard and file transfers). `data[0]` picks the role that reads: the server
/// (what a client can send) or the client (what a server can send).
pub fn ws_session(data: &[u8]) {
    let (&sel, rest) = data.split_first().unwrap_or((&0, &[]));
    let role = if sel % 2 == 0 {
        Role::Server
    } else {
        Role::Client
    };
    block_on(async {
        let inner = inner_for(role);
        if role == Role::Server {
            Connection::from_inner(inner.clone())
                .authorize(Features::defined_up_to(2))
                .expect("authorize a fresh server connection");
        }
        let mut ws = ws_over(rest, role);
        // A client's video queue holds 16 frames and its reader would wait for the application;
        // stop short of that, as a closed connection would.
        for _ in 0..15 {
            match ws.next().await {
                Some(Ok(Message::Binary(b))) => {
                    if handle_binary(&inner, b).await.is_err() {
                        break;
                    }
                }
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                Some(Ok(_)) => {}
            }
        }
    });
}
