//! The transport-independent [`Connection`]: typed send/receive per channel.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use hx_proto::{
    channel::CloseCode,
    datagram::{AudioPacket, MouseCoalescer, MouseMove, MouseUpdate},
    media::MediaHeader,
    message,
    order::ReorderWindow,
    pb::{
        self, ControlMessage, CursorEvent, InputEvent, TransferHeader,
        control_message::Message as Ctl,
    },
    version::{Features, Negotiated},
};
use rustls::pki_types::CertificateDer;
use tokio::sync::{Mutex, Notify, mpsc, oneshot, watch};

use crate::{
    ack::{AckHandler, AckOutcome, CancelFlag, FrameAck, FrameTicket},
    error::{CloseInfo, Error, Result},
    quic::QuicBackend,
    server::PreAuthSlot,
    transfer::{IncomingTransfer, TransferKind, TransferSender},
    ws::WsBackend,
};

/// Which side of the connection this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Streams video (agent / session side).
    Server,
    /// Views and sends input.
    Client,
}

/// Which transport carries the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// QUIC, ALPN `hx/1`.
    Quic,
    /// WebSocket over TLS on TCP.
    WebSocket,
}

/// What the peer said about itself in the hello exchange (informational, never trusted).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerInfo {
    /// Peer software string.
    pub software: String,
    /// Client's device label (empty for a server peer).
    pub device_name: String,
}

/// Tunables shared by both sides.
#[derive(Debug, Clone)]
pub struct ConnectionOptions {
    /// Frames the client reorder window may hold back (protocol §6.1).
    pub reorder_capacity: usize,
    /// How long a held frame waits for its predecessors.
    pub reorder_hold: Duration,
}

impl Default for ConnectionOptions {
    fn default() -> Self {
        Self {
            reorder_capacity: 4,
            reorder_hold: Duration::from_millis(10),
        }
    }
}

/// A completed video frame received from the peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoFrame {
    /// Validated media header.
    pub header: MediaHeader,
    /// Encoded payload, exactly `header.payload_len` bytes.
    pub payload: Bytes,
}

/// Counters and path metrics.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ConnectionStats {
    /// Frames handed to the transport.
    pub frames_sent: u64,
    /// Frames acknowledged as delivered.
    pub frames_delivered: u64,
    /// Frames cancelled by the sender.
    pub frames_cancelled: u64,
    /// Frames fully received.
    pub frames_received: u64,
    /// Frames dropped by the reorder window as older than the newest released.
    pub frames_dropped_stale: u64,
    /// Frame streams the peer reset (cancelled) before completion.
    pub frames_reset_by_peer: u64,
    /// Malformed or unexpected datagrams dropped.
    pub datagrams_dropped: u64,
    /// Mouse datagrams dropped as stale (reordered/duplicated).
    pub mouse_dropped_stale: u64,
    /// Audio packets dropped because the application was not consuming them.
    pub audio_dropped: u64,
    /// Input events dropped because the connection was not authorized yet.
    pub input_dropped_unauthorized: u64,
    /// Bytes of incoming transfer data queued and not yet read by the application
    /// (WebSocket; bounded per transfer and per connection).
    pub queued_transfer_bytes: u64,
    /// Round-trip estimate (QUIC only).
    pub rtt: Option<Duration>,
}

#[derive(Default)]
pub(crate) struct Counters {
    pub frames_sent: AtomicU64,
    pub frames_delivered: AtomicU64,
    pub frames_cancelled: AtomicU64,
    pub frames_received: AtomicU64,
    pub frames_reset_by_peer: AtomicU64,
    pub datagrams_dropped: AtomicU64,
    pub audio_dropped: AtomicU64,
    pub input_dropped: AtomicU64,
}

pub(crate) enum Backend {
    Quic(QuicBackend),
    Ws(WsBackend),
}

/// Unread input events a connection may queue (generous: key and button events are tiny).
/// WebSocket peers that outpace an application beyond this are closed (protocol §3.1).
const INPUT_QUEUE: usize = 4096;
/// Queued cursor events; position updates beyond this coalesce, shapes beyond it are an overflow.
const CURSOR_QUEUE: usize = 256;

/// Cursor events with latest-wins coalescing of positions: a burst of pointer positions the
/// application has not consumed collapses into the newest one, while shapes are never lost
/// or reordered relative to the positions that follow them.
#[derive(Default)]
pub(crate) struct CursorQueue {
    q: StdMutex<std::collections::VecDeque<CursorEvent>>,
    notify: Notify,
}

impl CursorQueue {
    fn push(&self, e: CursorEvent) -> Result<()> {
        let is_position =
            |e: &CursorEvent| matches!(e.event, Some(pb::cursor_event::Event::Position(_)));
        let mut q = self.q.lock().map_err(|_| Error::ChannelClosed)?;
        if is_position(&e) {
            if let Some(back) = q.back_mut().filter(|b| is_position(b)) {
                *back = e;
                self.notify.notify_one();
                return Ok(());
            }
            if q.len() >= CURSOR_QUEUE {
                return Ok(()); // a newer position will follow
            }
        } else if q.len() >= CURSOR_QUEUE {
            return Err(Error::Violation("cursor shape queue overflow".into()));
        }
        q.push_back(e);
        self.notify.notify_one();
        Ok(())
    }

    fn pop(&self) -> Option<CursorEvent> {
        self.q.lock().ok().and_then(|mut q| q.pop_front())
    }
}

/// Sender halves used by the transport's reader tasks.
pub(crate) struct Router {
    control: mpsc::Sender<ControlMessage>,
    input: mpsc::Sender<InputEvent>,
    cursor: CursorQueue,
    video: mpsc::Sender<VideoFrame>,
    audio: mpsc::Sender<AudioPacket>,
    pub(crate) transfers: mpsc::Sender<IncomingTransfer>,
    mouse: StdMutex<MouseCoalescer>,
    mouse_notify: Notify,
}

struct VideoRx {
    raw: mpsc::Receiver<VideoFrame>,
    window: ReorderWindow<VideoFrame>,
    ready: std::collections::VecDeque<VideoFrame>,
    hold: Duration,
    held_since: Option<Instant>,
}

struct Rx {
    control: Mutex<mpsc::Receiver<ControlMessage>>,
    input: Mutex<mpsc::Receiver<InputEvent>>,
    video: Mutex<VideoRx>,
    audio: Mutex<mpsc::Receiver<AudioPacket>>,
    transfers: Mutex<mpsc::Receiver<IncomingTransfer>>,
}

pub(crate) struct Inner {
    pub role: Role,
    pub kind: TransportKind,
    pub negotiated: Negotiated,
    pub peer: PeerInfo,
    pub session_id: [u8; 16],
    pub peer_certs: Option<Vec<CertificateDer<'static>>>,
    pub remote_addr: SocketAddr,
    pub backend: Backend,
    pub router: Router,
    rx: Rx,
    closed: watch::Sender<Option<CloseInfo>>,
    ack_handler: StdMutex<Option<AckHandler>>,
    pub counters: Counters,
    mouse_seq: AtomicU32,
    audio_seq: AtomicU32,
    pings: StdMutex<HashMap<u64, oneshot::Sender<()>>>,
    ping_nonce: AtomicU64,
    pub claimed_input: AtomicBool,
    pub claimed_cursor: AtomicBool,
    /// Server side: false until the application calls `Connection::authorize`.
    authorized: AtomicBool,
    /// Set by the first `authorize` call, before the features are stored.
    auth_claimed: AtomicBool,
    /// Server side: set by `authorize_control_only`, before `authorized`. Input, media,
    /// transfers and audio stay shut for the whole life of the connection.
    control_only: AtomicBool,
    /// Features usable now: all negotiated ones for a client, none until `authorize` for a server.
    effective_features: AtomicU64,
    /// Pre-authentication slot, released on authorize or close.
    slot: StdMutex<Option<PreAuthSlot>>,
    auth_timeout: Option<Duration>,
    /// Bytes of incoming transfer data queued (shared with the WebSocket receivers).
    pub transfer_budget: Arc<AtomicUsize>,
}

/// Everything needed to build a [`Connection`] once the hello exchange is done.
pub(crate) struct Parts {
    pub role: Role,
    pub kind: TransportKind,
    pub negotiated: Negotiated,
    pub peer: PeerInfo,
    pub session_id: [u8; 16],
    pub peer_certs: Option<Vec<CertificateDer<'static>>>,
    pub remote_addr: SocketAddr,
    pub options: ConnectionOptions,
    /// Server only: the pre-authentication slot to hold until `authorize`.
    pub slot: Option<PreAuthSlot>,
    /// Server only: close with `UNAUTHORIZED` if not authorized within this time.
    pub auth_timeout: Option<Duration>,
}

impl Inner {
    pub(crate) fn new(p: Parts, backend: Backend) -> Arc<Self> {
        let (control_tx, control_rx) = mpsc::channel(64);
        let (input_tx, input_rx) = mpsc::channel(INPUT_QUEUE);
        let (video_tx, video_rx) = mpsc::channel(16);
        let (audio_tx, audio_rx) = mpsc::channel(64);
        let (transfer_tx, transfer_rx) = mpsc::channel(16);
        let (closed, _) = watch::channel(None);
        let is_client = p.role == Role::Client;
        let effective = if is_client {
            p.negotiated.features.0
        } else {
            0
        };
        Arc::new(Self {
            role: p.role,
            kind: p.kind,
            negotiated: p.negotiated,
            peer: p.peer,
            session_id: p.session_id,
            peer_certs: p.peer_certs,
            remote_addr: p.remote_addr,
            backend,
            router: Router {
                control: control_tx,
                input: input_tx,
                cursor: CursorQueue::default(),
                video: video_tx,
                audio: audio_tx,
                transfers: transfer_tx,
                mouse: StdMutex::new(MouseCoalescer::new()),
                mouse_notify: Notify::new(),
            },
            rx: Rx {
                control: Mutex::new(control_rx),
                input: Mutex::new(input_rx),
                video: Mutex::new(VideoRx {
                    raw: video_rx,
                    window: ReorderWindow::new(p.options.reorder_capacity),
                    ready: Default::default(),
                    hold: p.options.reorder_hold,
                    held_since: None,
                }),
                audio: Mutex::new(audio_rx),
                transfers: Mutex::new(transfer_rx),
            },
            closed,
            ack_handler: StdMutex::new(None),
            counters: Counters::default(),
            mouse_seq: AtomicU32::new(0),
            audio_seq: AtomicU32::new(0),
            pings: StdMutex::new(HashMap::new()),
            ping_nonce: AtomicU64::new(1),
            claimed_input: AtomicBool::new(false),
            claimed_cursor: AtomicBool::new(false),
            authorized: AtomicBool::new(is_client),
            auth_claimed: AtomicBool::new(is_client),
            control_only: AtomicBool::new(false),
            effective_features: AtomicU64::new(effective),
            slot: StdMutex::new(p.slot),
            auth_timeout: p.auth_timeout,
            transfer_budget: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub(crate) fn subscribe_closed(&self) -> watch::Receiver<Option<CloseInfo>> {
        self.closed.subscribe()
    }

    pub(crate) fn closed_info(&self) -> Option<CloseInfo> {
        self.closed.borrow().clone()
    }

    /// Record how the connection ended; the first call wins. Returns true if this call recorded it.
    pub(crate) fn record_close(&self, info: CloseInfo) -> bool {
        if let Ok(mut s) = self.slot.lock() {
            s.take();
        }
        self.closed.send_if_modified(|slot| {
            if slot.is_none() {
                *slot = Some(info);
                true
            } else {
                false
            }
        })
    }

    /// Close the connection from this side (non-blocking; idempotent).
    pub(crate) fn close(&self, code: CloseCode, reason: &str) {
        let reason: String = reason.chars().take(120).collect();
        if self.record_close(CloseInfo {
            code,
            reason: reason.clone(),
            by_peer: false,
        }) {
            match &self.backend {
                Backend::Quic(q) => q.close(code, &reason),
                Backend::Ws(w) => w.close(code, &reason),
            }
        }
    }

    /// A reader task met a rule violation: close with `PROTOCOL_ERROR`.
    pub(crate) fn fail(&self, reason: &str) {
        tracing::debug!(reason, "closing connection after protocol violation");
        self.close(CloseCode::ProtocolError, reason);
    }

    /// Error to return when a channel ended: the close info if the connection closed.
    async fn ended(&self) -> Error {
        let mut rx = self.closed.subscribe();
        match tokio::time::timeout(Duration::from_millis(500), wait_closed(&mut rx)).await {
            Ok(Some(c)) => Error::Closed(c),
            _ => Error::ChannelClosed,
        }
    }

    /// Next queued item, or `None` once the connection is closed and the queue is drained.
    async fn recv_opt<T>(&self, rx: &mut mpsc::Receiver<T>) -> Option<T> {
        if let Ok(v) = rx.try_recv() {
            return Some(v);
        }
        let mut closed = self.closed.subscribe();
        tokio::select! {
            v = rx.recv() => v,
            _ = wait_closed(&mut closed) => rx.try_recv().ok(),
        }
    }

    async fn recv_or_closed<T>(&self, rx: &mut mpsc::Receiver<T>) -> Result<T> {
        match self.recv_opt(rx).await {
            Some(v) => Ok(v),
            None => Err(self.ended().await),
        }
    }

    fn closed_or(&self, e: Error) -> Error {
        match self.closed_info() {
            Some(c) => Error::Closed(c),
            None => e,
        }
    }

    pub(crate) fn resolve_ack(&self, ack: FrameAck) {
        match ack.outcome {
            AckOutcome::Delivered => self
                .counters
                .frames_delivered
                .fetch_add(1, Ordering::Relaxed),
            AckOutcome::Cancelled => self
                .counters
                .frames_cancelled
                .fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
        let handler = self.ack_handler.lock().ok().and_then(|h| h.clone());
        if let Some(h) = handler {
            h(ack);
        }
    }

    // ------------------------------------------------------------ inbound delivery

    pub(crate) async fn deliver_control(&self, m: ControlMessage) -> Result<()> {
        let Some(variant) = &m.message else {
            return Err(Error::Violation("empty control message".into()));
        };
        let from_client = self.role == Role::Server;
        match variant {
            Ctl::Hello(_) | Ctl::HelloAck(_) | Ctl::Refuse(_) => {
                return Err(Error::Violation(
                    "handshake message after the handshake".into(),
                ));
            }
            Ctl::ViewConfig(_) | Ctl::RequestKeyframe(_) | Ctl::Stats(_) if !from_client => {
                return Err(Error::Violation(
                    "client-only control message received by client".into(),
                ));
            }
            Ctl::StreamInfo(_) if from_client => {
                return Err(Error::Violation(
                    "server-only control message received by server".into(),
                ));
            }
            Ctl::Ping(p) => {
                let pong = ControlMessage::new(Ctl::Pong(pb::Pong { nonce: p.nonce }));
                // Best effort: a failing send means the connection is ending anyway.
                let _ = self.send_control(&pong).await;
                return Ok(());
            }
            Ctl::Pong(p) => {
                let waiter = self.pings.lock().ok().and_then(|mut m| m.remove(&p.nonce));
                if let Some(w) = waiter {
                    let _ = w.send(());
                }
                return Ok(());
            }
            _ => {}
        }
        if self.role == Role::Server
            && !self.is_authorized()
            && !matches!(variant, Ctl::Pairing(_) | Ctl::Auth(_) | Ctl::Goodbye(_))
        {
            return Err(Error::Violation(
                "only pairing, auth and goodbye are accepted before authorization".into(),
            ));
        }
        // A control-only connection (protocol 1.3 setup) takes setup messages and goodbye and
        // nothing else: not view config, not device management, not a second auth exchange.
        if self.is_control_only() && !matches!(variant, Ctl::Setup(_) | Ctl::Goodbye(_)) {
            return Err(Error::Violation(
                "only setup and goodbye are accepted on a control-only connection".into(),
            ));
        }
        // Setup messages exist only where the SETUP feature was negotiated (and, on a server,
        // only after authorization: the gate above already refuses them before it).
        if matches!(variant, Ctl::Setup(_)) && !self.features().contains(Features::SETUP) {
            return Err(Error::Violation(
                "setup message without the SETUP feature".into(),
            ));
        }
        // Server management exists only where `SERVER_MANAGEMENT` was negotiated (and, on a
        // server, only after authorization: the gate above already refuses it before it).
        if matches!(variant, Ctl::ServerMgmt(_))
            && !self.features().contains(Features::SERVER_MANAGEMENT)
        {
            return Err(Error::Violation(
                "server management message without the SERVER_MANAGEMENT feature".into(),
            ));
        }
        self.router
            .control
            .send(m)
            .await
            .map_err(|_| Error::ChannelClosed)
    }

    pub(crate) async fn deliver_input(&self, e: InputEvent) -> Result<()> {
        if !self.is_authorized() || self.is_control_only() {
            // Never queue input from a peer that has not been authorized.
            self.counters.input_dropped.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        self.deliver_bounded(&self.router.input, e, "input").await
    }

    pub(crate) async fn deliver_cursor(&self, e: CursorEvent) -> Result<()> {
        self.router.cursor.push(e)
    }

    /// QUIC: await space (per-stream flow control is the backpressure). WebSocket: one reader
    /// serves every channel, so a full queue must not stall control; the peer outpacing the
    /// application is a protocol violation.
    async fn deliver_bounded<T>(&self, tx: &mpsc::Sender<T>, v: T, what: &str) -> Result<()> {
        match &self.backend {
            Backend::Quic(_) => tx.send(v).await.map_err(|_| Error::ChannelClosed),
            Backend::Ws(_) => match tx.try_send(v) {
                Ok(()) => Ok(()),
                Err(mpsc::error::TrySendError::Full(_)) => {
                    Err(Error::Violation(format!("{what} queue overflow")))
                }
                Err(mpsc::error::TrySendError::Closed(_)) => Err(Error::ChannelClosed),
            },
        }
    }

    pub(crate) async fn deliver_video(&self, f: VideoFrame) -> Result<()> {
        self.counters
            .frames_received
            .fetch_add(1, Ordering::Relaxed);
        self.router
            .video
            .send(f)
            .await
            .map_err(|_| Error::ChannelClosed)
    }

    pub(crate) fn deliver_mouse(&self, m: MouseMove) {
        if !self.is_authorized() || self.is_control_only() {
            self.counters
                .datagrams_dropped
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        let accepted = self
            .router
            .mouse
            .lock()
            .map(|mut c| c.push(m))
            .unwrap_or(false);
        if accepted {
            self.router.mouse_notify.notify_one();
        }
    }

    pub(crate) fn deliver_audio(&self, a: AudioPacket) {
        if self.router.audio.try_send(a).is_err() {
            self.counters.audio_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn is_authorized(&self) -> bool {
        self.authorized.load(Ordering::SeqCst)
    }

    pub(crate) fn is_control_only(&self) -> bool {
        self.control_only.load(Ordering::SeqCst)
    }

    pub(crate) fn features(&self) -> Features {
        Features(self.effective_features.load(Ordering::SeqCst))
    }

    pub(crate) fn require_feature(&self, f: Features, name: &'static str) -> Result<()> {
        if self.features().contains(f) {
            Ok(())
        } else {
            Err(Error::FeatureDisabled(name))
        }
    }

    /// Server-initiated channels need authorization first, and never exist on a control-only
    /// connection.
    pub(crate) fn require_authorized(&self) -> Result<()> {
        if self.is_authorized() && !self.is_control_only() {
            Ok(())
        } else {
            Err(Error::NotAuthorized)
        }
    }

    // ------------------------------------------------------------ outbound

    pub(crate) async fn send_control(&self, m: &ControlMessage) -> Result<()> {
        let body = message::encode(m)?;
        self.send_reliable(hx_proto::channel::ChannelId::Control, body)
            .await
    }

    pub(crate) async fn send_reliable(
        &self,
        ch: hx_proto::channel::ChannelId,
        body: Bytes,
    ) -> Result<()> {
        let r = match &self.backend {
            Backend::Quic(q) => q.send_reliable(ch, body).await,
            Backend::Ws(w) => w.send_reliable(ch, body).await,
        };
        r.map_err(|e| self.closed_or(e))
    }
}

/// Owner handle: when the last clone of [`Connection`] is dropped, the connection is closed.
struct Handle {
    inner: Arc<Inner>,
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.inner.close(CloseCode::NoError, "connection dropped");
    }
}

/// An established, negotiated connection (either transport, either role).
///
/// Cheap to clone; clones share the connection. Dropping the last clone closes it with
/// `NO_ERROR`; call [`close`](Self::close) to choose the code and wait for delivery.
/// Receive methods may be called from one task per channel at a time (concurrent callers on
/// the same channel are serialised).
#[derive(Clone)]
pub struct Connection(Arc<Handle>);

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("role", &self.0.inner.role)
            .field("transport", &self.0.inner.kind)
            .field("remote", &self.0.inner.remote_addr)
            .finish()
    }
}

impl Connection {
    pub(crate) fn from_inner(inner: Arc<Inner>) -> Self {
        if inner.role == Role::Server
            && let Some(limit) = inner.auth_timeout
        {
            let i = inner.clone();
            tokio::spawn(async move {
                let mut closed = i.subscribe_closed();
                tokio::select! {
                    () = tokio::time::sleep(limit) => {
                        if !i.is_authorized() {
                            i.close(CloseCode::Unauthorized, "authorization timed out");
                        }
                    }
                    _ = wait_closed(&mut closed) => {}
                }
            });
        }
        Self(Arc::new(Handle { inner }))
    }

    /// Server side: declare the peer authenticated (the application has verified its pinned
    /// key, PIN or pairing) and enable the channels. `allowed` is intersected with the
    /// negotiated features (for example to switch the clipboard off for one device).
    ///
    /// Until this is called the connection is **restricted**: only control messages
    /// (`pairing`, `auth`, `goodbye`, `ping`/`pong`) are processed. Input and mouse data are
    /// dropped without queueing, and QUIC peers cannot open unidirectional streams at all.
    /// A connection that is never authorized is closed with `UNAUTHORIZED` after
    /// [`ServerOptions::auth_timeout`](crate::ServerOptions). Authorizing releases the
    /// connection's pre-authentication slot. Calling it twice, or on a client, is an error.
    pub fn authorize(&self, allowed: Features) -> Result<()> {
        let i = self.inner();
        self.require_role(Role::Server, "authorize")?;
        if let Some(c) = i.closed_info() {
            return Err(Error::Closed(c));
        }
        // Claim first, so a second call can neither widen nor replace the features.
        if i.auth_claimed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(Error::Violation("already authorized".into()));
        }
        let effective = i.negotiated.features.intersect(allowed);
        i.effective_features.store(effective.0, Ordering::SeqCst);
        i.authorized.store(true, Ordering::SeqCst);
        if let Backend::Quic(q) = &i.backend {
            q.lift_restrictions();
        }
        if let Ok(mut s) = i.slot.lock() {
            s.take();
        }
        Ok(())
    }

    /// Server side: declare the peer authenticated for **control messages only** (protocol
    /// 1.3 `INTENT_SETUP`). It satisfies the authorization deadline and releases the
    /// pre-authentication slot like [`authorize`](Self::authorize), but nothing else opens:
    ///
    /// * QUIC: the peer's unidirectional-stream credit stays 0 and the receive window is not
    ///   raised, so it can send nothing but control messages and can receive no media;
    /// * input and mouse data are dropped without queueing;
    /// * the server-side send calls for cursor, video, audio and transfers fail with
    ///   [`Error::NotAuthorized`];
    /// * WebSocket: a transfer, file, frame-ack or any other non-control, non-input channel is
    ///   a protocol violation (`PROTOCOL_ERROR`);
    /// * control messages other than `setup` and `goodbye` (ping and pong are handled by the
    ///   transport) are protocol violations.
    ///
    /// `allowed` is intersected with the negotiated features as in `authorize`; the `setup`
    /// message additionally needs `Features::SETUP` in the result. Calling it twice, after
    /// `authorize`, or on a client, is an error. The connection cannot be widened later.
    pub fn authorize_control_only(&self, allowed: Features) -> Result<()> {
        let i = self.inner();
        self.require_role(Role::Server, "authorize_control_only")?;
        if let Some(c) = i.closed_info() {
            return Err(Error::Closed(c));
        }
        if i.auth_claimed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(Error::Violation("already authorized".into()));
        }
        let effective = i.negotiated.features.intersect(allowed);
        i.effective_features.store(effective.0, Ordering::SeqCst);
        // Before `authorized`, so no reader can observe an authorized, unrestricted connection.
        i.control_only.store(true, Ordering::SeqCst);
        i.authorized.store(true, Ordering::SeqCst);
        // Deliberately no `lift_restrictions`: QUIC credit and windows stay at their
        // pre-authentication values.
        if let Ok(mut s) = i.slot.lock() {
            s.take();
        }
        Ok(())
    }

    /// True once the connection may use every negotiated channel (always for a client). A
    /// control-only connection (see [`authorize_control_only`](Self::authorize_control_only))
    /// also reports `true` here: check [`is_control_only`](Self::is_control_only) to tell them
    /// apart.
    pub fn is_authorized(&self) -> bool {
        self.inner().is_authorized()
    }

    /// True if the server authorized this connection with `authorize_control_only`.
    pub fn is_control_only(&self) -> bool {
        self.inner().is_control_only()
    }

    /// Features usable now: the negotiated set after authorization (restricted by the
    /// `allowed` argument of [`authorize`](Self::authorize)), none before it on a server.
    pub fn enabled_features(&self) -> Features {
        self.inner().features()
    }

    fn inner(&self) -> &Arc<Inner> {
        &self.0.inner
    }

    fn require_role(&self, role: Role, op: &'static str) -> Result<()> {
        if self.inner().role == role {
            Ok(())
        } else {
            Err(Error::WrongRole(op))
        }
    }

    /// Which side this is.
    pub fn role(&self) -> Role {
        self.inner().role
    }

    /// Which transport carries it.
    pub fn transport(&self) -> TransportKind {
        self.inner().kind
    }

    /// The agreed version, features and codecs.
    pub fn negotiated(&self) -> &Negotiated {
        &self.inner().negotiated
    }

    /// Peer-provided software and device labels (informational only).
    pub fn peer_info(&self) -> &PeerInfo {
        &self.inner().peer
    }

    /// Session id chosen by the server (16 random bytes), identical on both sides.
    pub fn session_id(&self) -> [u8; 16] {
        self.inner().session_id
    }

    /// The peer's address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.inner().remote_addr
    }

    /// The certificate chain the peer presented in the TLS handshake, if any (for a server:
    /// the client certificate). Identity decisions belong to the injected TLS verifier.
    pub fn peer_certificates(&self) -> Option<&[CertificateDer<'static>]> {
        self.inner().peer_certs.as_deref()
    }

    /// How the connection ended, if it has.
    pub fn close_info(&self) -> Option<CloseInfo> {
        self.inner().closed_info()
    }

    /// Wait until the connection is closed and return how.
    pub async fn closed(&self) -> CloseInfo {
        let mut rx = self.inner().closed.subscribe();
        wait_closed(&mut rx).await.unwrap_or(CloseInfo {
            code: CloseCode::InternalError,
            reason: "closed".into(),
            by_peer: false,
        })
    }

    /// Close with `code` and a short reason (at most 120 characters, never secrets), then wait
    /// briefly for the close to be delivered.
    pub async fn close(&self, code: CloseCode, reason: &str) {
        self.inner().close(code, reason);
        match &self.inner().backend {
            Backend::Quic(q) => q.flush_close().await,
            Backend::Ws(w) => w.flush_close().await,
        }
    }

    /// Counters and the current round-trip estimate.
    pub fn stats(&self) -> ConnectionStats {
        let i = self.inner();
        let c = &i.counters;
        let (frames_dropped_stale, mouse_dropped_stale) = (
            i.rx.video
                .try_lock()
                .map(|v| v.window.dropped_stale())
                .unwrap_or(0),
            i.router
                .mouse
                .lock()
                .map(|m| m.dropped_stale())
                .unwrap_or(0),
        );
        ConnectionStats {
            frames_sent: c.frames_sent.load(Ordering::Relaxed),
            frames_delivered: c.frames_delivered.load(Ordering::Relaxed),
            frames_cancelled: c.frames_cancelled.load(Ordering::Relaxed),
            frames_received: c.frames_received.load(Ordering::Relaxed),
            frames_dropped_stale,
            frames_reset_by_peer: c.frames_reset_by_peer.load(Ordering::Relaxed),
            datagrams_dropped: c.datagrams_dropped.load(Ordering::Relaxed),
            mouse_dropped_stale,
            audio_dropped: c.audio_dropped.load(Ordering::Relaxed),
            input_dropped_unauthorized: c.input_dropped.load(Ordering::Relaxed),
            queued_transfer_bytes: i.transfer_budget.load(Ordering::Relaxed) as u64,
            rtt: match &i.backend {
                Backend::Quic(q) => Some(q.rtt()),
                Backend::Ws(_) => None,
            },
        }
    }

    /// Register the callback that receives every [`FrameAck`] (replaces any previous one).
    /// This is the hook for the sender's congestion controller.
    pub fn set_ack_handler(&self, handler: Option<AckHandler>) {
        if let Ok(mut h) = self.inner().ack_handler.lock() {
            *h = handler;
        }
    }

    // ------------------------------------------------------------ control

    /// Send a control message (validated first).
    pub async fn send_control(&self, m: &ControlMessage) -> Result<()> {
        match &m.message {
            Some(Ctl::Hello(_) | Ctl::HelloAck(_) | Ctl::Refuse(_)) => {
                return Err(Error::Violation(
                    "handshake messages are sent by the transport".into(),
                ));
            }
            Some(Ctl::ViewConfig(_) | Ctl::RequestKeyframe(_) | Ctl::Stats(_)) => {
                self.require_role(Role::Client, "sending a client-only control message")?;
            }
            Some(Ctl::StreamInfo(_)) => self.require_role(Role::Server, "sending StreamInfo")?,
            Some(Ctl::Setup(_)) => self.inner().require_feature(Features::SETUP, "setup")?,
            Some(Ctl::ServerMgmt(_)) => self
                .inner()
                .require_feature(Features::SERVER_MANAGEMENT, "server management")?,
            _ => {}
        }
        self.inner().send_control(m).await
    }

    /// Receive the next control message. `Ping` and `Pong` are handled by the transport and
    /// never surface here.
    pub async fn recv_control(&self) -> Result<ControlMessage> {
        let i = self.inner();
        let mut g = i.rx.control.lock().await;
        i.recv_or_closed(&mut g).await
    }

    /// Measure the round-trip time over the control channel (works on both transports).
    pub async fn ping(&self, timeout: Duration) -> Result<Duration> {
        let i = self.inner();
        let nonce = i.ping_nonce.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        if let Ok(mut m) = i.pings.lock() {
            if m.len() >= 64 {
                return Err(Error::Violation("too many outstanding pings".into()));
            }
            m.insert(nonce, tx);
        }
        let start = Instant::now();
        i.send_control(&ControlMessage::new(Ctl::Ping(pb::Ping { nonce })))
            .await?;
        let r = tokio::time::timeout(timeout, rx).await;
        if let Ok(mut m) = i.pings.lock() {
            m.remove(&nonce);
        }
        match r {
            Ok(Ok(())) => Ok(start.elapsed()),
            Ok(Err(_)) => Err(i.ended().await),
            Err(_) => Err(Error::Timeout("ping")),
        }
    }

    // ------------------------------------------------------------ input and mouse (client to server)

    /// Send a key, button, scroll or release-all event on the reliable input channel.
    pub async fn send_input(&self, e: &InputEvent) -> Result<()> {
        self.require_role(Role::Client, "send_input")?;
        let body = message::encode(e)?;
        self.inner()
            .send_reliable(hx_proto::channel::ChannelId::Input, body)
            .await
    }

    /// Receive the next input event.
    pub async fn recv_input(&self) -> Result<InputEvent> {
        self.require_role(Role::Server, "recv_input")?;
        let i = self.inner();
        let mut g = i.rx.input.lock().await;
        i.recv_or_closed(&mut g).await
    }

    /// Send a mouse-motion datagram (latest wins; may be lost). `relative` selects deltas.
    pub async fn send_mouse_move(&self, relative: bool, x: i32, y: i32) -> Result<()> {
        self.require_role(Role::Client, "send_mouse_move")?;
        let i = self.inner();
        let seq = i.mouse_seq.fetch_add(1, Ordering::Relaxed);
        let dg = Bytes::copy_from_slice(
            &MouseMove {
                relative,
                seq,
                x,
                y,
            }
            .encode(),
        );
        self.send_datagram(dg).await
    }

    /// Wait for coalesced mouse motion (absolute: latest wins; relative: summed).
    pub async fn recv_mouse_move(&self) -> Result<MouseUpdate> {
        self.require_role(Role::Server, "recv_mouse_move")?;
        let i = self.inner();
        let mut closed = i.closed.subscribe();
        loop {
            let taken = i.router.mouse.lock().ok().and_then(|mut c| c.take());
            if let Some(u) = taken {
                return Ok(u);
            }
            tokio::select! {
                _ = i.router.mouse_notify.notified() => {}
                r = wait_closed(&mut closed) => {
                    return Err(r.map_or(Error::ChannelClosed, Error::Closed));
                }
            }
        }
    }

    // ------------------------------------------------------------ cursor (server to client)

    /// Send a cursor shape or position on the reliable cursor channel.
    pub async fn send_cursor(&self, e: &CursorEvent) -> Result<()> {
        self.require_role(Role::Server, "send_cursor")?;
        self.inner().require_authorized()?;
        let body = message::encode(e)?;
        self.inner()
            .send_reliable(hx_proto::channel::ChannelId::Cursor, body)
            .await
    }

    /// Receive the next cursor event.
    pub async fn recv_cursor(&self) -> Result<CursorEvent> {
        self.require_role(Role::Client, "recv_cursor")?;
        let i = self.inner();
        let mut closed = i.subscribe_closed();
        loop {
            if let Some(e) = i.router.cursor.pop() {
                return Ok(e);
            }
            tokio::select! {
                () = i.router.cursor.notify.notified() => {}
                r = wait_closed(&mut closed) => {
                    // Deliver what was queued before the close.
                    if let Some(e) = i.router.cursor.pop() {
                        return Ok(e);
                    }
                    return Err(r.map_or(Error::ChannelClosed, Error::Closed));
                }
            }
        }
    }

    // ------------------------------------------------------------ video (server to client)

    /// Send one encoded frame as its own unidirectional stream (QUIC) or message (WebSocket).
    ///
    /// Returns once the frame is queued; the returned [`FrameTicket`] resolves to its
    /// [`FrameAck`] and can cancel it. `header.payload_len` must equal `payload.len()`.
    pub async fn send_video_frame(
        &self,
        header: MediaHeader,
        payload: Bytes,
    ) -> Result<FrameTicket> {
        self.require_role(Role::Server, "send_video_frame")?;
        self.inner().require_authorized()?;
        if header.payload_len as usize != payload.len() {
            return Err(Error::Violation(
                "payload_len does not match the payload".into(),
            ));
        }
        let head = header.encode()?;
        let cancel = Arc::new(CancelFlag::default());
        let (tx, rx) = oneshot::channel();
        let job = VideoJob {
            frame_number: header.frame_number,
            head,
            payload_len: payload.len(),
            payload,
            cancel: cancel.clone(),
            done: tx,
            started: Instant::now(),
        };
        let bytes = job.payload.len();
        let i = self.inner();
        let r = match &i.backend {
            Backend::Quic(q) => q.send_video(i.clone(), job).await,
            Backend::Ws(w) => w.send_video(i.clone(), job).await,
        };
        r.map_err(|e| i.closed_or(e))?;
        i.counters.frames_sent.fetch_add(1, Ordering::Relaxed);
        Ok(FrameTicket {
            frame_number: header.frame_number,
            bytes,
            cancel,
            done: rx,
        })
    }

    /// Receive the next video frame in decode order: frames that completed out of order are
    /// reordered and frames older than the newest released are dropped (protocol §6.1).
    pub async fn recv_video_frame(&self) -> Result<VideoFrame> {
        self.require_role(Role::Client, "recv_video_frame")?;
        let i = self.inner();
        let mut g = i.rx.video.lock().await;
        loop {
            if let Some(f) = g.ready.pop_front() {
                return Ok(f);
            }
            let wait = match (g.window.held(), g.held_since) {
                (0, _) => None,
                (_, Some(since)) => Some(g.hold.saturating_sub(since.elapsed())),
                (_, None) => Some(g.hold),
            };
            let before = g.window.last_released();
            let next = match wait {
                None => Ok(i.recv_opt(&mut g.raw).await),
                Some(d) => tokio::time::timeout(d, i.recv_opt(&mut g.raw)).await,
            };
            match next {
                Ok(Some(f)) => {
                    let (n, key) = (
                        f.header.frame_number,
                        f.header.is_key() || f.header.is_resync(),
                    );
                    let out = g.window.push(n, key, f);
                    g.ready.extend(out);
                }
                Ok(None) => {
                    // Connection ended: flush what is held, then report the end.
                    while g.window.held() > 0 {
                        let out = g.window.release_lowest();
                        g.ready.extend(out);
                    }
                    if g.ready.is_empty() {
                        drop(g);
                        return Err(i.ended().await);
                    }
                }
                Err(_) => {
                    let out = g.window.release_lowest();
                    g.ready.extend(out);
                }
            }
            // The hold timer restarts whenever the window released something.
            g.held_since = match g.window.held() {
                0 => None,
                _ if before != g.window.last_released() => Some(Instant::now()),
                _ => g.held_since.or_else(|| Some(Instant::now())),
            };
        }
    }

    // ------------------------------------------------------------ audio (server to client)

    /// Send one Opus packet as a datagram (`timestamp` is the 48 kHz sample clock).
    pub async fn send_audio(&self, timestamp: u32, payload: Bytes) -> Result<()> {
        self.require_role(Role::Server, "send_audio")?;
        self.inner().require_authorized()?;
        self.inner().require_feature(Features::AUDIO, "audio")?;
        let seq = self.inner().audio_seq.fetch_add(1, Ordering::Relaxed);
        let dg = AudioPacket {
            seq,
            timestamp,
            payload,
        }
        .encode()?;
        self.send_datagram(dg).await
    }

    /// Receive the next audio packet (late and duplicate packets are the caller's jitter
    /// buffer's business).
    pub async fn recv_audio(&self) -> Result<AudioPacket> {
        self.require_role(Role::Client, "recv_audio")?;
        let i = self.inner();
        let mut g = i.rx.audio.lock().await;
        i.recv_or_closed(&mut g).await
    }

    async fn send_datagram(&self, dg: Bytes) -> Result<()> {
        let i = self.inner();
        let r = match &i.backend {
            Backend::Quic(q) => q.send_datagram(dg),
            Backend::Ws(w) => w.send_datagram(dg).await,
        };
        r.map_err(|e| i.closed_or(e))
    }

    // ------------------------------------------------------------ clipboard and files

    /// Start a transfer of `kind` described by `header`; write the body with the returned
    /// [`TransferSender`]. Requires the matching negotiated feature.
    pub async fn open_transfer(
        &self,
        kind: TransferKind,
        header: TransferHeader,
    ) -> Result<TransferSender> {
        let i = self.inner();
        if i.role == Role::Server {
            i.require_authorized()?;
        }
        match kind {
            TransferKind::Clipboard => {
                i.require_feature(Features::CLIPBOARD, "clipboard")?;
                header.validate_clipboard()?;
            }
            TransferKind::File => i.require_feature(Features::FILE_TRANSFER, "file transfer")?,
        }
        let _ = message::encode(&header)?;
        let r = match &i.backend {
            Backend::Quic(q) => q.open_transfer(kind, header).await,
            Backend::Ws(w) => w.open_transfer(kind, header).await,
        };
        r.map_err(|e| i.closed_or(e))
    }

    /// Wait for the peer to start a transfer.
    pub async fn accept_transfer(&self) -> Result<IncomingTransfer> {
        let i = self.inner();
        let mut g = i.rx.transfers.lock().await;
        i.recv_or_closed(&mut g).await
    }
}

/// Wait until a close is recorded (the guard is dropped before any await, keeping futures `Send`).
pub(crate) async fn wait_closed(rx: &mut watch::Receiver<Option<CloseInfo>>) -> Option<CloseInfo> {
    let r = rx.wait_for(|c| c.is_some()).await;
    r.ok().and_then(|g| g.clone())
}

/// One frame on its way out (shared by both backends).
pub(crate) struct VideoJob {
    pub frame_number: u32,
    pub head: [u8; hx_proto::media::MEDIA_HEADER_LEN],
    pub payload: Bytes,
    pub payload_len: usize,
    pub cancel: Arc<CancelFlag>,
    pub done: oneshot::Sender<FrameAck>,
    pub started: Instant,
}

/// What is kept of a frame once its bytes are on the wire: enough to report its outcome,
/// none of the payload.
pub(crate) struct VideoMeta {
    frame_number: u32,
    bytes: usize,
    started: Instant,
    done: oneshot::Sender<FrameAck>,
}

impl VideoMeta {
    pub(crate) fn finish(self, inner: &Inner, outcome: AckOutcome) {
        let ack = FrameAck {
            frame_number: self.frame_number,
            bytes: self.bytes,
            elapsed: self.started.elapsed(),
            outcome,
        };
        inner.resolve_ack(ack);
        let _ = self.done.send(ack);
    }
}

impl VideoJob {
    /// Drop the payload and keep only the outcome bookkeeping.
    pub(crate) fn into_meta(self) -> VideoMeta {
        VideoMeta {
            frame_number: self.frame_number,
            bytes: self.payload_len,
            started: self.started,
            done: self.done,
        }
    }

    pub(crate) fn finish(self, inner: &Inner, outcome: AckOutcome) {
        self.into_meta().finish(inner, outcome);
    }
}
