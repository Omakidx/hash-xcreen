//! WebSocket-over-TLS fallback: the same channels multiplexed on one ordered socket
//! (protocol §9).

use std::{
    collections::{HashMap, VecDeque},
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use futures_util::{
    SinkExt, StreamExt,
    stream::{SplitSink, SplitStream},
};
use hx_proto::{
    channel::{
        ChannelId, CloseCode, MAX_CONTROL_MESSAGE, MAX_CURSOR_MESSAGE, MAX_INPUT_MESSAGE,
        MAX_TRANSFER_CHUNK,
    },
    media::{MAX_VIDEO_PAYLOAD, MEDIA_HEADER_LEN, MediaHeader},
    message,
    pb::{
        ControlMessage, CursorEvent, InputEvent, RefuseReason, TransferHeader,
        control_message::Message as Ctl,
    },
    version::{ALPN_WEBSOCKET, Features, WEBSOCKET_PATH},
};
use rustls::pki_types::CertificateDer;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{
        mpsc::{self, error::TrySendError},
        watch,
    },
    time::Instant,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_tungstenite::{
    WebSocketStream, accept_hdr_async_with_config, client_async_with_config,
    tungstenite::{
        Message,
        handshake::server::{ErrorResponse, Request, Response},
        protocol::{CloseFrame, WebSocketConfig, frame::coding::CloseCode as WsCloseCode},
    },
};

use crate::{
    ack::AckOutcome,
    client::{ClientHello, ClientOptions, Target, build_hello, process_reply},
    conn::{
        Backend, Connection, Inner, Parts, PeerInfo, Role, TransportKind, VideoFrame, VideoJob,
        VideoMeta, wait_closed,
    },
    error::{CloseInfo, Error, Result, transport},
    server::{
        HelloCheck, PendingInner, PendingSession, PreAuthSlot, ServerCtx, check_hello,
        refuse_message,
    },
    transfer::{
        IncomingBody, IncomingTransfer, SenderBody, TransferKind, TransferSender, WsReceiver,
    },
};

pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
type BoxIo = Box<dyn Io>;
type Ws = WebSocketStream<GuardedIo>;

/// The socket under a WebSocket connection. The first failed write raises `failed`; from then
/// on writes stay pending instead of failing again. Tungstenite flushes its automatic replies
/// (a Pong) at the start of every read and abandons the read if that flush fails, which would
/// lose a close frame the peer sent before the socket went away; a pending write lets it read
/// on. The writer task learns of the failure from `failed`. Only armed once the connection's
/// tasks run: during the handshake a failed write is an ordinary error.
pub(crate) struct GuardedIo {
    io: BoxIo,
    armed: bool,
    failed: Arc<watch::Sender<bool>>,
}

impl GuardedIo {
    fn new(io: BoxIo) -> Self {
        Self {
            io,
            armed: false,
            failed: Arc::new(watch::Sender::new(false)),
        }
    }

    /// Armed, and a write has failed.
    fn dead(&self) -> bool {
        self.armed && *self.failed.borrow()
    }

    fn guard<T>(&self, r: Poll<std::io::Result<T>>) -> Poll<std::io::Result<T>> {
        match r {
            Poll::Ready(Err(e)) if self.armed && e.kind() != std::io::ErrorKind::WouldBlock => {
                tracing::debug!(error = %e, "websocket write failed");
                self.failed.send_replace(true);
                Poll::Pending
            }
            r => r,
        }
    }
}

impl AsyncRead for GuardedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for GuardedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.dead() {
            return Poll::Pending;
        }
        let r = Pin::new(&mut self.io).poll_write(cx, buf);
        self.guard(r)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.dead() {
            return Poll::Pending;
        }
        let r = Pin::new(&mut self.io).poll_flush(cx);
        self.guard(r)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.dead() {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const KEEPALIVE: Duration = Duration::from_secs(5);
const CLOSE_GRACE: Duration = Duration::from_secs(1);
/// Frames written but not yet acknowledged (metadata only, no payloads).
const MAX_UNACKED_FRAMES: usize = 256;
const MAX_INCOMING_TRANSFERS: usize = 16;

/// Largest legitimate client-to-server message: a control message (64 KiB) or a transfer
/// chunk (64 KiB plus 6 bytes of tagging), with a little slack for framing.
const CLIENT_TO_SERVER_MAX: usize = 64 * 1024 + 64;

/// WebSocket limits for the side that **receives**: a server only ever receives small
/// messages (so an unauthenticated peer cannot make it buffer megabytes), a client receives
/// video frames up to 16 MiB.
fn ws_config(receiver: Role) -> WebSocketConfig {
    let max = match receiver {
        Role::Server => CLIENT_TO_SERVER_MAX,
        Role::Client => MAX_VIDEO_PAYLOAD as usize + 64,
    };
    WebSocketConfig::default()
        .max_message_size(Some(max))
        .max_frame_size(Some(max))
}

// ---------------------------------------------------------------- shared state

/// Something to put on the socket.
enum Out {
    Binary(Bytes),
    Video {
        msg: Bytes,
        frame_number: u32,
        cancel: Arc<crate::ack::CancelFlag>,
    },
    Close(CloseCode, String),
}

/// Chunks of an incoming transfer, as delivered to [`IncomingTransfer`].
pub(crate) enum WsChunk {
    Data(Bytes),
    End,
    Aborted,
}

struct IncomingState {
    tx: mpsc::Sender<WsChunk>,
    /// Bytes of this transfer queued and not yet read by the application.
    queued: Arc<AtomicUsize>,
}

/// Queued incoming transfer data allowed per transfer and per connection (protocol §3.1).
const TRANSFER_BUDGET: usize = 1024 * 1024;
const CONNECTION_TRANSFER_BUDGET: usize = 4 * 1024 * 1024;

#[derive(Default)]
struct AckBook {
    by_frame: HashMap<u32, VecDeque<VideoMeta>>,
    total: usize,
}

pub(crate) struct WsBackend {
    hi: mpsc::Sender<Out>,
    lo: mpsc::Sender<Out>,
    acks: StdMutex<AckBook>,
    incoming: StdMutex<HashMap<u32, IncomingState>>,
    /// Outgoing transfer ids mapped to an "aborted by the receiver" flag.
    outgoing: Arc<StdMutex<HashMap<u32, Arc<AtomicBool>>>>,
    next_transfer_id: AtomicU32,
    done: watch::Receiver<bool>,
    /// Raised when a write fails (by [`GuardedIo`] or the writer): the writer stops, and the
    /// reader stops waiting on the application and reads on to a close frame the peer may have
    /// sent before the socket went away.
    write_failed: Arc<watch::Sender<bool>>,
}

fn frame(ch: ChannelId, parts: &[&[u8]]) -> Bytes {
    let mut v = Vec::with_capacity(1 + parts.iter().map(|p| p.len()).sum::<usize>());
    v.push(ch as u8);
    for p in parts {
        v.extend_from_slice(p);
    }
    Bytes::from(v)
}

impl WsBackend {
    pub(crate) fn close(&self, code: CloseCode, reason: &str) {
        let _ = self.hi.try_send(Out::Close(code, reason.to_string()));
    }

    pub(crate) async fn flush_close(&self) {
        let mut done = self.done.clone();
        let _ = tokio::time::timeout(CLOSE_GRACE, done.wait_for(|d| *d)).await;
    }

    pub(crate) async fn send_reliable(&self, ch: ChannelId, body: Bytes) -> Result<()> {
        match ch {
            ChannelId::Control | ChannelId::Input | ChannelId::Cursor => {}
            _ => return Err(Error::Violation("not a message channel".into())),
        }
        self.hi
            .send(Out::Binary(frame(ch, &[&body])))
            .await
            .map_err(|_| Error::ChannelClosed)
    }

    pub(crate) async fn send_datagram(&self, dg: Bytes) -> Result<()> {
        // Datagram bytes already start with their channel id; on WebSocket they are messages.
        self.hi
            .send(Out::Binary(dg))
            .await
            .map_err(|_| Error::ChannelClosed)
    }

    pub(crate) async fn send_video(&self, _inner: Arc<Inner>, job: VideoJob) -> Result<()> {
        let msg = frame(ChannelId::Video, &[&job.head, &job.payload]);
        let (frame_number, cancel) = (job.frame_number, job.cancel.clone());
        {
            let mut book = self.acks.lock().map_err(|_| Error::ChannelClosed)?;
            if book.total >= MAX_UNACKED_FRAMES {
                return Err(Error::Transport(
                    "peer is not acknowledging video frames".into(),
                ));
            }
            book.total += 1;
            book.by_frame
                .entry(frame_number)
                .or_default()
                .push_back(job.into_meta());
        }
        self.lo
            .send(Out::Video {
                msg,
                frame_number,
                cancel,
            })
            .await
            .map_err(|_| Error::ChannelClosed)
    }

    /// Resolve the oldest pending frame with this number.
    fn resolve_frame(&self, inner: &Inner, frame_number: u32, outcome: AckOutcome) {
        let job = {
            let Ok(mut book) = self.acks.lock() else {
                return;
            };
            let job = book
                .by_frame
                .get_mut(&frame_number)
                .and_then(VecDeque::pop_front);
            if job.is_some() {
                book.total -= 1;
            }
            if book
                .by_frame
                .get(&frame_number)
                .is_some_and(VecDeque::is_empty)
            {
                book.by_frame.remove(&frame_number);
            }
            job
        };
        if let Some(j) = job {
            j.finish(inner, outcome);
        }
    }

    fn drain_pending(&self, inner: &Inner) {
        let jobs: Vec<VideoMeta> = match self.acks.lock() {
            Ok(mut book) => {
                book.total = 0;
                book.by_frame.drain().flat_map(|(_, q)| q).collect()
            }
            Err(_) => return,
        };
        for j in jobs {
            j.finish(inner, AckOutcome::ConnectionLost);
        }
    }

    pub(crate) async fn open_transfer(
        &self,
        kind: TransferKind,
        header: TransferHeader,
    ) -> Result<TransferSender> {
        // Clients allocate odd ids, servers even ids (protocol §9.4); the parity is applied by
        // `Inner` role through `next_transfer_id`'s starting value.
        let id = self.next_transfer_id.fetch_add(2, Ordering::Relaxed);
        let aborted = Arc::new(AtomicBool::new(false));
        if let Ok(mut m) = self.outgoing.lock() {
            if m.len() >= 64 {
                return Err(Error::Violation(
                    "too many concurrent outgoing transfers".into(),
                ));
            }
            m.insert(id, aborted.clone());
        }
        let body = message::encode(&header)?;
        let msg = frame(kind.channel(), &[&id.to_le_bytes(), &[1], &body]);
        self.lo
            .send(Out::Binary(msg))
            .await
            .map_err(|_| Error::ChannelClosed)?;
        Ok(TransferSender::new(
            SenderBody::Ws(WsTransferSender {
                lo: self.lo.clone(),
                id,
                kind,
                aborted,
                outgoing: self.outgoing.clone(),
            }),
            header.size,
        ))
    }
}

/// Sending half of a WebSocket transfer.
pub(crate) struct WsTransferSender {
    lo: mpsc::Sender<Out>,
    id: u32,
    kind: TransferKind,
    aborted: Arc<AtomicBool>,
    outgoing: Arc<StdMutex<HashMap<u32, Arc<AtomicBool>>>>,
}

impl WsTransferSender {
    fn forget(&self) {
        if let Ok(mut m) = self.outgoing.lock() {
            m.remove(&self.id);
        }
    }

    fn msg(&self, kind: u8, body: &[u8]) -> Bytes {
        frame(
            self.kind.channel(),
            &[&self.id.to_le_bytes(), &[kind], body],
        )
    }

    pub(crate) async fn send_data(&mut self, b: Bytes) -> Result<()> {
        if self.aborted.load(Ordering::SeqCst) {
            return Err(Error::Violation("receiver stopped the transfer".into()));
        }
        self.lo
            .send(Out::Binary(self.msg(2, &b)))
            .await
            .map_err(|_| Error::ChannelClosed)
    }

    pub(crate) async fn send_end(&mut self) -> Result<()> {
        let r = if self.aborted.load(Ordering::SeqCst) {
            Err(Error::Violation("receiver stopped the transfer".into()))
        } else {
            self.lo
                .send(Out::Binary(self.msg(3, &[])))
                .await
                .map_err(|_| Error::ChannelClosed)
        };
        self.forget();
        r
    }

    pub(crate) fn abort(self) {
        let _ = self.lo.try_send(Out::Binary(self.msg(4, &[])));
        self.forget();
    }
}

// ---------------------------------------------------------------- tasks

/// Split the socket and start the writer and reader.
fn start(mut ws: Ws, parts: Parts) -> Connection {
    ws.get_mut().armed = true;
    let write_failed = ws.get_ref().failed.clone();
    let (sink, stream) = ws.split();
    let (hi_tx, hi_rx) = mpsc::channel(256);
    let (lo_tx, lo_rx) = mpsc::channel(8);
    let (done_tx, done_rx) = watch::channel(false);
    // Client transfer ids are odd, server ids even.
    let first_id = if parts.role == Role::Client { 1 } else { 2 };
    let backend = Backend::Ws(WsBackend {
        hi: hi_tx,
        lo: lo_tx,
        acks: StdMutex::new(AckBook::default()),
        incoming: StdMutex::new(HashMap::new()),
        outgoing: Arc::new(StdMutex::new(HashMap::new())),
        next_transfer_id: AtomicU32::new(first_id),
        done: done_rx,
        write_failed,
    });
    let inner = Inner::new(parts, backend);
    tokio::spawn(writer(inner.clone(), sink, hi_rx, lo_rx, done_tx));
    tokio::spawn(reader(inner.clone(), stream));
    Connection::from_inner(inner)
}

fn backend(inner: &Inner) -> Option<&WsBackend> {
    match &inner.backend {
        Backend::Ws(w) => Some(w),
        Backend::Quic(_) => None,
    }
}

fn close_frame(code: CloseCode, reason: &str) -> Message {
    Message::Close(Some(CloseFrame {
        code: WsCloseCode::from(code.websocket_code()),
        reason: reason.to_string().into(),
    }))
}

async fn writer(
    inner: Arc<Inner>,
    mut sink: SplitSink<Ws, Message>,
    mut hi: mpsc::Receiver<Out>,
    mut lo: mpsc::Receiver<Out>,
    done: watch::Sender<bool>,
) {
    let mut keepalive = tokio::time::interval(KEEPALIVE);
    let mut closed = inner.subscribe_closed();
    let mut failed = backend(&inner).map(|w| w.write_failed.subscribe());
    let mut peer_gone = false;
    loop {
        let out = tokio::select! {
            biased;
            Some(o) = hi.recv() => o,
            Some(o) = lo.recv() => o,
            _ = keepalive.tick() => {
                if !put(&mut sink, Message::Ping(Bytes::new()), &mut failed).await {
                    peer_gone = true;
                    break;
                }
                continue;
            }
            info = wait_closed(&mut closed) => {
                // A local close normally reaches us as `Out::Close`; send its frame from the
                // record if this branch won the race against it, or `hi` was full.
                if let Some(c) = info.filter(|c| !c.by_peer) {
                    put(&mut sink, close_frame(c.code, &c.reason), &mut failed).await;
                }
                break;
            }
        };
        let sent = match out {
            Out::Binary(b) => put(&mut sink, Message::Binary(b), &mut failed).await,
            Out::Video {
                msg,
                frame_number,
                cancel,
            } => {
                if cancel.is_cancelled() {
                    if let Some(w) = backend(&inner) {
                        w.resolve_frame(&inner, frame_number, AckOutcome::Cancelled);
                    }
                    continue;
                }
                put(&mut sink, Message::Binary(msg), &mut failed).await
            }
            Out::Close(code, reason) => {
                put(&mut sink, close_frame(code, &reason), &mut failed).await;
                break;
            }
        };
        if !sent {
            peer_gone = true;
            break;
        }
    }
    if peer_gone {
        // The write may have failed because the peer closed: its close frame can be read, or
        // still be queued behind messages the reader has not processed yet. That close frame
        // is the reason the connection ended; let the reader find it before recording a loss.
        if let Some(w) = backend(&inner) {
            w.write_failed.send_replace(true);
        }
        hi.close();
        lo.close();
        let _ = tokio::time::timeout(CLOSE_GRACE, wait_closed(&mut closed)).await;
        inner.record_close(CloseInfo {
            code: CloseCode::InternalError,
            reason: "connection lost".into(),
            by_peer: true,
        });
    }
    if let Some(w) = backend(&inner) {
        w.drain_pending(&inner);
    }
    let _ = done.send(true);
}

/// Send one message; false if the socket can no longer be written (a [`GuardedIo`] write
/// failure leaves the send pending, so it is raced against the flag).
async fn put(
    sink: &mut SplitSink<Ws, Message>,
    msg: Message,
    failed: &mut Option<watch::Receiver<bool>>,
) -> bool {
    tokio::select! {
        biased;
        r = sink.send(msg) => r.is_ok(),
        _ = write_failed(failed) => false,
    }
}

/// Resolves once a write has failed (never if there is no WebSocket backend).
async fn write_failed(rx: &mut Option<watch::Receiver<bool>>) {
    match rx {
        Some(rx) => {
            if rx.wait_for(|f| *f).await.is_err() {
                std::future::pending::<()>().await;
            }
        }
        None => std::future::pending().await,
    }
}

async fn reader(inner: Arc<Inner>, mut stream: SplitStream<Ws>) {
    let mut closed = inner.subscribe_closed();
    let mut write_dead = backend(&inner).map(|w| w.write_failed.subscribe());
    // Once the connection is closed (or can no longer be written), the peer gets one grace
    // period in total to deliver its close frame: a peer that keeps sending must not keep the
    // socket open.
    let mut grace_until: Option<Instant> = None;
    loop {
        let limit = grace_until.unwrap_or_else(|| Instant::now() + IDLE_TIMEOUT);
        let next = tokio::select! {
            biased;
            n = stream.next() => Some(n),
            _ = wait_closed(&mut closed), if grace_until.is_none() => {
                grace_until = Some(Instant::now() + CLOSE_GRACE);
                continue;
            }
            _ = write_failed(&mut write_dead), if grace_until.is_none() => {
                grace_until = Some(Instant::now() + CLOSE_GRACE);
                continue;
            }
            _ = tokio::time::sleep_until(limit) => None,
        };
        let next = match next {
            Some(n) => n,
            None => {
                inner.record_close(CloseInfo {
                    code: CloseCode::InternalError,
                    reason: if grace_until.is_some() {
                        "connection lost"
                    } else {
                        "idle timeout"
                    }
                    .into(),
                    by_peer: true,
                });
                break;
            }
        };
        match next {
            None => {
                inner.record_close(CloseInfo {
                    code: CloseCode::InternalError,
                    reason: "connection lost".into(),
                    by_peer: true,
                });
                break;
            }
            Some(Err(e)) => {
                use tokio_tungstenite::tungstenite::Error as E;
                match e {
                    E::Capacity(_) | E::Protocol(_) | E::Utf8(_) => {
                        inner.fail(&format!("websocket: {e}"))
                    }
                    other => {
                        inner.record_close(CloseInfo {
                            code: CloseCode::InternalError,
                            reason: other.to_string().chars().take(120).collect(),
                            by_peer: true,
                        });
                    }
                }
                break;
            }
            Some(Ok(Message::Binary(b))) => {
                // Once the writer has failed the connection is gone: deliver what the
                // application has room for, drop what would wait, and read on to the close.
                let handled = tokio::select! {
                    biased;
                    r = handle_binary(&inner, b) => r,
                    _ = write_failed(&mut write_dead) => continue,
                };
                if let Err(e) = handled {
                    match e {
                        Error::Protocol(_) | Error::Violation(_) => inner.fail(&e.to_string()),
                        other => tracing::debug!(error = %other, "websocket reader ended"),
                    }
                    break;
                }
            }
            Some(Ok(Message::Text(_))) => {
                inner.fail("text message on a binary protocol");
                break;
            }
            Some(Ok(Message::Close(frame))) => {
                let info = match frame {
                    Some(f) => CloseInfo {
                        code: CloseCode::from_websocket_code(u16::from(f.code))
                            .unwrap_or(CloseCode::InternalError),
                        reason: f.reason.as_str().chars().take(120).collect(),
                        by_peer: true,
                    },
                    None => CloseInfo {
                        code: CloseCode::NoError,
                        reason: String::new(),
                        by_peer: true,
                    },
                };
                inner.record_close(info);
                break;
            }
            Some(Ok(_)) => {}
        }
    }
}

async fn handle_binary(inner: &Arc<Inner>, b: Bytes) -> Result<()> {
    let (&first, body) = b
        .split_first()
        .ok_or_else(|| Error::Violation("empty websocket message".into()))?;
    let ch = ChannelId::from_u8(first)?;
    match (inner.role, ch) {
        (_, ChannelId::Control) => {
            check_len(body, MAX_CONTROL_MESSAGE)?;
            let m: ControlMessage = message::decode(body)?;
            inner.deliver_control(m).await
        }
        (Role::Server, ChannelId::Input) => {
            check_len(body, MAX_INPUT_MESSAGE)?;
            let e: InputEvent = message::decode(body)?;
            inner.deliver_input(e).await
        }
        (Role::Client, ChannelId::Cursor) => {
            check_len(body, MAX_CURSOR_MESSAGE)?;
            let e: CursorEvent = message::decode(body)?;
            inner.deliver_cursor(e).await
        }
        (Role::Server, ChannelId::MouseMove) | (Role::Client, ChannelId::Audio) => {
            crate::quic::handle_datagram(inner, &b);
            Ok(())
        }
        (Role::Client, ChannelId::Video) => {
            let (header, _payload) = MediaHeader::decode_frame(body)?;
            // Acknowledge receipt (best effort: a full queue only delays the sender's estimate).
            if let Some(w) = backend(inner) {
                let _ = w.hi.try_send(Out::Binary(frame(
                    ChannelId::FrameAck,
                    &[&header.frame_number.to_le_bytes()],
                )));
            }
            inner
                .deliver_video(VideoFrame {
                    header,
                    payload: b.slice(1 + MEDIA_HEADER_LEN..),
                })
                .await
        }
        (Role::Server, ChannelId::FrameAck) => {
            let n: [u8; 4] = body
                .try_into()
                .map_err(|_| Error::Violation("frame ack must be 4 bytes".into()))?;
            if let Some(w) = backend(inner) {
                w.resolve_frame(inner, u32::from_le_bytes(n), AckOutcome::Delivered);
            }
            Ok(())
        }
        (_, ChannelId::Clipboard | ChannelId::File) => handle_transfer(inner, ch, body).await,
        _ => Err(Error::Violation(format!(
            "channel {ch:?} is not allowed towards this role"
        ))),
    }
}

fn check_len(body: &[u8], max: usize) -> Result<()> {
    if body.len() > max {
        return Err(Error::Violation("message above its channel limit".into()));
    }
    Ok(())
}

async fn handle_transfer(inner: &Arc<Inner>, ch: ChannelId, body: &[u8]) -> Result<()> {
    let Some(w) = backend(inner) else {
        return Ok(());
    };
    let (kind, feature, name) = match ch {
        ChannelId::Clipboard => (TransferKind::Clipboard, Features::CLIPBOARD, "clipboard"),
        _ => (TransferKind::File, Features::FILE_TRANSFER, "file transfer"),
    };
    inner
        .require_feature(feature, name)
        .map_err(|e| Error::Violation(e.to_string()))?;
    if body.len() < 5 {
        return Err(Error::Violation("short transfer message".into()));
    }
    let id = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
    let (msg_type, payload) = (body[4], &body[5..]);
    // The peer's ids have the opposite parity of ours.
    let peer_is_client = inner.role == Role::Server;
    if (id % 2 == 1) != peer_is_client {
        // An abort for one of *our* transfers: the receiver stopped it.
        if msg_type == 4 {
            if let Ok(m) = w.outgoing.lock()
                && let Some(flag) = m.get(&id)
            {
                flag.store(true, Ordering::SeqCst);
            }
            return Ok(());
        }
        return Err(Error::Violation("transfer id with the wrong parity".into()));
    }
    let abort_msg = || Out::Binary(frame(ch, &[&id.to_le_bytes(), &[4]]));
    match msg_type {
        1 => {
            check_len(payload, hx_proto::channel::MAX_TRANSFER_HEADER)?;
            let header: TransferHeader = message::decode(payload)?;
            if kind == TransferKind::Clipboard {
                header.validate_clipboard()?;
            }
            let (tx, rx) = mpsc::channel(256);
            let queued = Arc::new(AtomicUsize::new(0));
            {
                let mut m = w.incoming.lock().map_err(|_| Error::ChannelClosed)?;
                if m.contains_key(&id) {
                    return Err(Error::Violation("duplicate transfer id".into()));
                }
                if m.len() >= MAX_INCOMING_TRANSFERS {
                    drop(m);
                    let _ = w.hi.try_send(abort_msg());
                    return Ok(());
                }
                m.insert(
                    id,
                    IncomingState {
                        tx,
                        queued: queued.clone(),
                    },
                );
            }
            let t = IncomingTransfer::new(
                kind,
                header,
                IncomingBody::Ws(WsReceiver {
                    rx,
                    queued,
                    conn_queued: inner.transfer_budget.clone(),
                }),
            );
            if inner.router.transfers.try_send(t).is_err() {
                if let Ok(mut m) = w.incoming.lock() {
                    m.remove(&id);
                }
                let _ = w.hi.try_send(abort_msg());
            }
            Ok(())
        }
        2..=4 => {
            if msg_type == 2 && payload.len() > MAX_TRANSFER_CHUNK {
                return Err(Error::Violation("transfer chunk above 64 KiB".into()));
            }
            if msg_type == 3 && !payload.is_empty() {
                return Err(Error::Violation("transfer end carries a body".into()));
            }
            let finished = msg_type != 2;
            let entry = {
                let mut m = w.incoming.lock().map_err(|_| Error::ChannelClosed)?;
                if finished {
                    m.remove(&id).map(|s| (s.tx, s.queued))
                } else {
                    m.get(&id).map(|s| (s.tx.clone(), s.queued.clone()))
                }
            };
            // Unknown ids are transfers we already dropped or aborted: ignore the rest of them.
            let Some((tx, queued)) = entry else {
                return Ok(());
            };
            if msg_type != 2 {
                let _ = tx.try_send(if msg_type == 3 {
                    WsChunk::End
                } else {
                    WsChunk::Aborted
                });
                return Ok(());
            }
            // Data: enforce the byte budgets before queueing anything.
            let len = payload.len();
            let per = queued.fetch_add(len, Ordering::SeqCst) + len;
            let all = inner.transfer_budget.fetch_add(len, Ordering::SeqCst) + len;
            let over = per > TRANSFER_BUDGET || all > CONNECTION_TRANSFER_BUDGET;
            if over
                || tx
                    .try_send(WsChunk::Data(Bytes::copy_from_slice(payload)))
                    .is_err()
            {
                queued.fetch_sub(len, Ordering::SeqCst);
                inner.transfer_budget.fetch_sub(len, Ordering::SeqCst);
                // The consumer is too slow or gone: stop the transfer.
                if let Ok(mut m) = w.incoming.lock() {
                    m.remove(&id);
                }
                let _ = w.hi.try_send(abort_msg());
            }
            Ok(())
        }
        _ => Err(Error::Violation("unknown transfer message type".into())),
    }
}

// ---------------------------------------------------------------- server side

pub(crate) struct WsPending {
    ws: Ws,
}

pub(crate) async fn accept_loop(listener: TcpListener, ctx: Arc<ServerCtx>) {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error = %e, "TCP accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Some(permit) = ctx.acquire(peer.ip()) else {
            drop(tcp);
            continue;
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = incoming(tcp, peer, &ctx, permit).await {
                tracing::debug!(error = %e, %peer, "incoming WebSocket connection dropped");
            }
        });
    }
}

struct PathCheck;

impl tokio_tungstenite::tungstenite::handshake::server::Callback for PathCheck {
    fn on_request(
        self,
        req: &Request,
        resp: Response,
    ) -> std::result::Result<Response, ErrorResponse> {
        if req.uri().path() == WEBSOCKET_PATH {
            Ok(resp)
        } else {
            let mut r = ErrorResponse::new(Some("not found".to_string()));
            *r.status_mut() = tokio_tungstenite::tungstenite::http::StatusCode::NOT_FOUND;
            Err(r)
        }
    }
}

/// A TLS handshake failure; a rejected certificate or alert is a [`Error::PeerRejected`].
fn tls_error(e: std::io::Error) -> Error {
    let rejected = matches!(
        e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()),
        Some(
            rustls::Error::InvalidCertificate(_)
                | rustls::Error::AlertReceived(_)
                | rustls::Error::PeerIncompatible(_)
        )
    );
    if rejected {
        Error::PeerRejected(e.to_string())
    } else {
        Error::Tls(e.to_string())
    }
}

/// The protocol is TLS 1.3 only; a configuration that also allows 1.2 is not honoured.
fn require_tls13(v: Option<rustls::ProtocolVersion>) -> Result<()> {
    if v == Some(rustls::ProtocolVersion::TLSv1_3) {
        Ok(())
    } else {
        Err(Error::Tls("TLS 1.3 is required".into()))
    }
}

fn owned_certs(c: Option<&[CertificateDer<'_>]>) -> Option<Vec<CertificateDer<'static>>> {
    c.map(|c| c.iter().map(|d| d.clone().into_owned()).collect())
}

async fn incoming(
    tcp: TcpStream,
    peer: std::net::SocketAddr,
    ctx: &ServerCtx,
    slot: PreAuthSlot,
) -> Result<()> {
    let start = Instant::now();
    let deadline = start + ctx.opts.handshake_timeout;
    // TLS and the HTTP upgrade must finish sooner than the whole hello exchange.
    let tls_deadline = start + ctx.opts.handshake_timeout.min(ctx.opts.transport_timeout);
    let _ = tcp.set_nodelay(true);
    let tls_cfg = ctx.ws_tls.read().map_err(|_| Error::ChannelClosed)?.clone();
    let tls = tokio::time::timeout_at(tls_deadline, TlsAcceptor::from(tls_cfg).accept(tcp))
        .await
        .map_err(|_| Error::Timeout("TLS handshake"))?
        .map_err(tls_error)?;
    require_tls13(tls.get_ref().1.protocol_version())?;
    let certs = owned_certs(tls.get_ref().1.peer_certificates());
    let io = GuardedIo::new(Box::new(tls));
    let mut ws = tokio::time::timeout_at(
        tls_deadline,
        accept_hdr_async_with_config(io, PathCheck, Some(ws_config(Role::Server))),
    )
    .await
    .map_err(|_| Error::Timeout("WebSocket upgrade"))?
    .map_err(transport)?;

    let first = match tokio::time::timeout_at(deadline, read_first_control(&mut ws)).await {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => {
            let _ = ws
                .send(close_frame(
                    CloseCode::ProtocolError,
                    "invalid first message",
                ))
                .await;
            return Err(e);
        }
        Err(_) => {
            let _ = ws
                .send(close_frame(CloseCode::HelloTimeout, "no hello"))
                .await;
            return Err(Error::Timeout("Hello"));
        }
    };
    let hello = match check_hello(&first) {
        Ok(HelloCheck::Ok(h)) => h,
        Ok(HelloCheck::UpdateRequired) => {
            let body = message::encode(&refuse_message(
                RefuseReason::UpdateRequired,
                "update required",
            ))?;
            return refuse_server(WsPending { ws }, body, CloseCode::UpdateRequired).await;
        }
        Err(e) => {
            let _ = ws
                .send(close_frame(CloseCode::ProtocolError, "invalid Hello"))
                .await;
            return Err(e);
        }
    };
    let pending = PendingSession::new(
        ctx,
        hello,
        TransportKind::WebSocket,
        peer,
        certs,
        PendingInner::Ws(Box::new(WsPending { ws })),
        slot,
    );
    if let Err(e) = ctx.tx.try_send(pending) {
        let (TrySendError::Full(p) | TrySendError::Closed(p)) = e;
        let _ = p.refuse(RefuseReason::Busy, "server busy").await;
    }
    Ok(())
}

/// Read the first message: a binary control message (without its channel byte).
async fn read_first_control(ws: &mut Ws) -> Result<Vec<u8>> {
    loop {
        match ws.next().await {
            Some(Ok(Message::Binary(b))) => {
                let (&first, body) = b
                    .split_first()
                    .ok_or_else(|| Error::Violation("empty message".into()))?;
                if ChannelId::from_u8(first)? != ChannelId::Control {
                    return Err(Error::Violation(
                        "first message must be on the control channel".into(),
                    ));
                }
                check_len(body, MAX_CONTROL_MESSAGE)?;
                return Ok(body.to_vec());
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            Some(Ok(_)) => return Err(Error::Violation("first message must be binary".into())),
            Some(Err(e)) => return Err(transport(e)),
            None => return Err(Error::ChannelClosed),
        }
    }
}

pub(crate) async fn establish_server(w: WsPending, ack: Bytes, parts: Parts) -> Result<Connection> {
    let mut ws = w.ws;
    ws.send(Message::Binary(frame(ChannelId::Control, &[&ack])))
        .await
        .map_err(transport)?;
    Ok(start(ws, parts))
}

/// Close an undecided socket with an explicit close code and no `Refuse`.
pub(crate) async fn close_server(w: WsPending, code: CloseCode) {
    let mut ws = w.ws;
    let _ = tokio::time::timeout(
        Duration::from_secs(1),
        ws.send(close_frame(code, "accept failed")),
    )
    .await;
}

pub(crate) async fn refuse_server(w: WsPending, body: Bytes, code: CloseCode) -> Result<()> {
    let mut ws = w.ws;
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        let _ = ws
            .send(Message::Binary(frame(ChannelId::Control, &[&body])))
            .await;
        let _ = ws.send(close_frame(code, "refused")).await;
        // Let the peer's close frame arrive so the TCP connection ends cleanly.
        while ws.next().await.is_some_and(|m| m.is_ok()) {}
    })
    .await;
    Ok(())
}

// ---------------------------------------------------------------- client side

pub(crate) async fn connect(
    tls: &Arc<rustls::ClientConfig>,
    opts: &ClientOptions,
    target: &Target,
    hello: &ClientHello,
) -> Result<Connection> {
    let mut cfg = (**tls).clone();
    cfg.alpn_protocols = vec![ALPN_WEBSOCKET.to_vec()];
    // Every connection verifies the server afresh (pinning must not be skipped by resumption).
    cfg.resumption = rustls::client::Resumption::disabled();
    let tcp = tokio::time::timeout(opts.connect_timeout, TcpStream::connect(target.addr))
        .await
        .map_err(|_| Error::Timeout("TCP connect"))??;
    let _ = tcp.set_nodelay(true);
    let tls_stream = tokio::time::timeout(
        opts.connect_timeout,
        TlsConnector::from(Arc::new(cfg)).connect(target.server_name.clone(), tcp),
    )
    .await
    .map_err(|_| Error::Timeout("TLS handshake"))?
    .map_err(tls_error)?;
    require_tls13(tls_stream.get_ref().1.protocol_version())?;
    let certs = owned_certs(tls_stream.get_ref().1.peer_certificates());
    let io = GuardedIo::new(Box::new(tls_stream));

    let host = target.server_name.to_str();
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.into_owned()
    };
    let url = format!("wss://{host}:{}{WEBSOCKET_PATH}", target.addr.port());
    let (mut ws, _) = tokio::time::timeout(
        opts.connect_timeout,
        client_async_with_config(url, io, Some(ws_config(Role::Client))),
    )
    .await
    .map_err(|_| Error::Timeout("WebSocket upgrade"))?
    .map_err(transport)?;

    let hello_msg = build_hello(hello);
    let body = message::encode(&ControlMessage::new(Ctl::Hello(hello_msg.clone())))?;
    ws.send(Message::Binary(frame(ChannelId::Control, &[&body])))
        .await
        .map_err(transport)?;

    let reply = tokio::time::timeout(opts.handshake_timeout, async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Binary(b))) => {
                    let (&first, body) = b
                        .split_first()
                        .ok_or_else(|| Error::Violation("empty message".into()))?;
                    if ChannelId::from_u8(first)? != ChannelId::Control {
                        return Err(Error::Violation(
                            "reply must be on the control channel".into(),
                        ));
                    }
                    check_len(body, MAX_CONTROL_MESSAGE)?;
                    return Ok(body.to_vec());
                }
                Some(Ok(Message::Close(Some(f)))) => {
                    return Err(Error::Closed(CloseInfo {
                        code: CloseCode::from_websocket_code(u16::from(f.code))
                            .unwrap_or(CloseCode::InternalError),
                        reason: f.reason.as_str().chars().take(120).collect(),
                        by_peer: true,
                    }));
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(_)) => return Err(Error::Violation("unexpected message type".into())),
                Some(Err(e)) => return Err(transport(e)),
                None => return Err(Error::ChannelClosed),
            }
        }
    })
    .await
    .map_err(|_| Error::Timeout("server reply"))??;

    let (ack, negotiated, session_id) = match process_reply(&reply, &hello_msg) {
        Ok(x) => x,
        Err(e) => {
            let code = match &e {
                Error::Version(_) => CloseCode::UpdateRequired,
                Error::Refused { .. } => CloseCode::NoError,
                _ => CloseCode::ProtocolError,
            };
            let _ = ws.send(close_frame(code, "handshake failed")).await;
            return Err(e);
        }
    };
    let parts = Parts {
        role: Role::Client,
        kind: TransportKind::WebSocket,
        negotiated,
        peer: PeerInfo {
            software: ack.software,
            device_name: String::new(),
        },
        session_id,
        peer_certs: certs,
        remote_addr: target.addr,
        options: opts.connection.clone(),
        slot: None,
        auth_timeout: None,
    };
    Ok(start(ws, parts))
}
