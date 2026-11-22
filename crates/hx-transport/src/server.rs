//! The server side: one endpoint, ALPN dispatch, pre-authentication bounds, and the
//! [`PendingSession`] hook where the application decides accept or refuse.

use std::{
    collections::HashMap,
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex as StdMutex, RwLock},
    time::Duration,
};

use bytes::Bytes;
use hx_proto::{
    channel::{ChannelId, CloseCode, MAX_CONTROL_MESSAGE},
    message,
    pb::{self, ControlMessage, RefuseReason, control_message::Message as Ctl},
    version::{
        ALPN, ALPN_H3, Features, Negotiated, PROTOCOL_MAJOR, ProtocolVersion, capabilities,
        negotiate, peek_hello_version,
    },
};
use quinn::crypto::rustls::{HandshakeData, QuicServerConfig};
use rustls::pki_types::CertificateDer;
use tokio::{
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc},
    task::JoinHandle,
    time::Instant,
};

use crate::{
    conn::{Connection, ConnectionOptions, Parts, PeerInfo, Role, TransportKind},
    error::{Error, Result, transport},
    quic::{self, read_message, write_message},
    ws::{self, WsPending},
};

/// Plug-in point for the browser transport: receives every QUIC connection that negotiated
/// ALPN `h3`. Phase 1 has no implementation; without one the endpoint offers only `hx/1`.
pub trait H3Handler: Send + Sync + 'static {
    /// Take over a connecting QUIC connection whose ALPN is `h3`.
    fn handle(&self, connecting: quinn::Connecting) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

/// Server tunables.
#[derive(Clone)]
pub struct ServerOptions {
    /// Serve QUIC on UDP.
    pub quic: bool,
    /// Serve the WebSocket-over-TLS fallback on TCP (same port number).
    pub websocket: bool,
    /// Time allowed from transport accept to a valid `Hello` (protocol §1: 10 s).
    pub handshake_timeout: Duration,
    /// Time allowed for TLS and (WebSocket) the HTTP upgrade, counted from the transport
    /// accept; must not exceed `handshake_timeout` (default 5 s).
    pub transport_timeout: Duration,
    /// Connections that may be unauthenticated at once: from transport accept until
    /// `Connection::authorize` (or refusal/close). Protocol §1: 64.
    pub max_pending: usize,
    /// The same limit per source address (IPv6: per /64). Default 4.
    pub max_pending_per_ip: usize,
    /// The same limit per IPv6 /48 (a site), so one network cannot hold every slot with many
    /// /64s. Default 16. IPv4 is limited per address only.
    pub max_pending_per_v6_48: usize,
    /// How long the application may take to accept or refuse a [`PendingSession`] before the
    /// transport refuses it with `BUSY` (default 10 s).
    pub decision_timeout: Duration,
    /// Close an accepted connection that is still not authorized after this long with
    /// `UNAUTHORIZED` (default 30 s). `None` disables the deadline.
    pub auth_timeout: Option<Duration>,
    /// Require QUIC address validation (a Retry round trip) before spending handshake state.
    pub require_retry: bool,
    /// Per-connection tunables.
    pub connection: ConnectionOptions,
    /// Optional handler for ALPN `h3` (WebTransport), see [`H3Handler`].
    pub h3: Option<Arc<dyn H3Handler>>,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            quic: true,
            websocket: true,
            handshake_timeout: Duration::from_secs(10),
            transport_timeout: Duration::from_secs(5),
            max_pending: 64,
            max_pending_per_ip: 4,
            max_pending_per_v6_48: 16,
            decision_timeout: Duration::from_secs(10),
            auth_timeout: Some(Duration::from_secs(30)),
            require_retry: true,
            connection: ConnectionOptions::default(),
            h3: None,
        }
    }
}

/// The application's answer to an accepted `Hello`.
#[derive(Debug, Clone)]
pub struct ServerHello {
    /// What this server can encode and do.
    pub capabilities: pb::Capabilities,
    /// Software string, e.g. `hx-session 0.1.0` (at most 128 bytes).
    pub software: String,
}

pub(crate) struct ServerCtx {
    pub opts: ServerOptions,
    pub sem: Arc<Semaphore>,
    pub ips: Arc<StdMutex<HashMap<IpKey, usize>>>,
    pub tx: mpsc::Sender<PendingSession>,
    pub ws_tls: RwLock<Arc<rustls::ServerConfig>>,
}

/// The listening server: a QUIC endpoint and a TCP listener on the same port number.
pub struct Server {
    quic_addr: Option<SocketAddr>,
    tcp_addr: Option<SocketAddr>,
    endpoint: Option<quinn::Endpoint>,
    pending: Mutex<mpsc::Receiver<PendingSession>>,
    ctx: Arc<ServerCtx>,
    /// The accept loops, once started.
    tasks: StdMutex<Vec<JoinHandle<()>>>,
    /// Sockets bound by [`Server::bind_paused`] that no loop reads yet.
    unstarted: StdMutex<Option<Unstarted>>,
}

/// What [`Server::start`] spawns the accept loops on.
struct Unstarted {
    endpoint: Option<quinn::Endpoint>,
    listener: Option<tokio::net::TcpListener>,
}

/// A ticket producer that never produces tickets, so stateless resumption stays off even if
/// the injected configuration enables it.
#[derive(Debug)]
struct NoTickets;

impl rustls::server::ProducesTickets for NoTickets {
    fn enabled(&self) -> bool {
        false
    }
    fn lifetime(&self) -> u32 {
        0
    }
    fn encrypt(&self, _plain: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn decrypt(&self, _cipher: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

/// Prepare an injected TLS configuration for serving: set the ALPN values and switch off every
/// form of session resumption and early data. A resumed handshake skips the client-certificate
/// verifier (and the session cache would be shared between QUIC and WebSocket), so a revoked
/// or unpinned key could otherwise reconnect on a cached session. Applications still must
/// re-check the peer key on every `PendingSession` (protocol §11).
fn alpn_config(tls: &rustls::ServerConfig, alpn: &[&[u8]]) -> rustls::ServerConfig {
    let mut c = tls.clone();
    c.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    c.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    c.ticketer = Arc::new(NoTickets);
    c.send_tls13_tickets = 0;
    c.max_early_data_size = 0;
    c
}

fn quic_server_config(tls: &rustls::ServerConfig, h3: bool) -> Result<quinn::ServerConfig> {
    let alpn: &[&[u8]] = if h3 { &[ALPN, ALPN_H3] } else { &[ALPN] };
    let q = QuicServerConfig::try_from(alpn_config(tls, alpn))
        .map_err(|e| Error::Tls(e.to_string()))?;
    let mut c = quinn::ServerConfig::with_crypto(Arc::new(q));
    c.transport_config(Arc::new(quic::transport_config(Role::Server)?));
    Ok(c)
}

impl Server {
    /// Bind the QUIC endpoint (UDP) and the WebSocket listener (TCP) on `addr`. With port 0 an
    /// ephemeral port is chosen for UDP and TCP uses the same number.
    ///
    /// `tls` is injected by the caller (identity, client-certificate verification); it must
    /// allow TLS 1.3 and should allow nothing else (TLS 1.2 handshakes are dropped). ALPN
    /// values are set by this crate, and session resumption and early data are forced off.
    ///
    /// This is [`bind_paused`](Self::bind_paused) followed by [`start`](Self::start).
    pub async fn bind(
        addr: SocketAddr,
        tls: Arc<rustls::ServerConfig>,
        opts: ServerOptions,
    ) -> Result<Self> {
        let server = Self::bind_paused(addr, tls, opts).await?;
        server.start();
        Ok(server)
    }

    /// Binds the sockets like [`bind`](Self::bind) but **does not read them**: no TLS or QUIC
    /// handshake runs and no `Hello` is decoded until [`start`](Self::start). Connection
    /// attempts queue in the kernel (TCP backlog) and in the QUIC endpoint (initial packets)
    /// and are served after `start`. A process that must apply hardening (seccomp,
    /// `mlockall`, `PR_SET_DUMPABLE`) before it parses anything from the network calls this,
    /// hardens, then starts.
    pub async fn bind_paused(
        addr: SocketAddr,
        tls: Arc<rustls::ServerConfig>,
        opts: ServerOptions,
    ) -> Result<Self> {
        let (ctx, rx) = Self::new_ctx(&tls, opts.clone())?;

        // Bind UDP first so port 0 resolves, then TCP on the same number (retry on a collision).
        let mut attempts = if addr.port() == 0 { 16 } else { 1 };
        loop {
            attempts -= 1;
            let endpoint = if opts.quic {
                Some(quinn::Endpoint::server(
                    quic_server_config(&tls, opts.h3.is_some())?,
                    addr,
                )?)
            } else {
                None
            };
            let quic_addr = endpoint
                .as_ref()
                .map(quinn::Endpoint::local_addr)
                .transpose()?;
            let tcp_bind = SocketAddr::new(addr.ip(), quic_addr.map_or(addr.port(), |a| a.port()));
            let listener = if opts.websocket {
                match tokio::net::TcpListener::bind(tcp_bind).await {
                    Ok(l) => Some(l),
                    Err(e) if attempts > 0 && e.kind() == std::io::ErrorKind::AddrInUse => continue,
                    Err(e) => return Err(e.into()),
                }
            } else {
                None
            };
            let tcp_addr = listener
                .as_ref()
                .map(tokio::net::TcpListener::local_addr)
                .transpose()?;

            return Ok(Self {
                quic_addr,
                tcp_addr,
                endpoint: endpoint.clone(),
                pending: Mutex::new(rx),
                ctx,
                tasks: StdMutex::new(Vec::new()),
                unstarted: StdMutex::new(Some(Unstarted { endpoint, listener })),
            });
        }
    }

    /// The shared state and the pending-session channel (both constructors).
    fn new_ctx(
        tls: &rustls::ServerConfig,
        opts: ServerOptions,
    ) -> Result<(Arc<ServerCtx>, mpsc::Receiver<PendingSession>)> {
        if !opts.quic && !opts.websocket {
            return Err(Error::Config(
                "enable at least one of quic and websocket".into(),
            ));
        }
        let (tx, rx) = mpsc::channel(16);
        let ctx = Arc::new(ServerCtx {
            sem: Arc::new(Semaphore::new(opts.max_pending.max(1))),
            ips: Arc::new(StdMutex::new(HashMap::new())),
            tx,
            ws_tls: RwLock::new(Arc::new(alpn_config(
                tls,
                &[hx_proto::version::ALPN_WEBSOCKET],
            ))),
            opts,
        });
        Ok((ctx, rx))
    }

    /// Like [`bind_paused`](Self::bind_paused), but on sockets somebody else created and
    /// bound: a service manager's socket activation (systemd hands the process a listening
    /// TCP socket and a bound UDP socket) or a test. Nothing is read until
    /// [`start`](Self::start).
    ///
    /// The caller has already checked what the sockets are (type, family, listening); this
    /// takes them as given. Both sockets are switched to non-blocking mode. A socket whose
    /// transport `opts` disables is dropped (closed). Because it registers the sockets with
    /// the reactor, it must be called inside a Tokio runtime.
    pub fn from_listeners_paused(
        udp: std::net::UdpSocket,
        tcp: std::net::TcpListener,
        tls: Arc<rustls::ServerConfig>,
        opts: ServerOptions,
    ) -> Result<Self> {
        let (ctx, rx) = Self::new_ctx(&tls, opts.clone())?;
        let endpoint = if opts.quic {
            let runtime = quinn::default_runtime()
                .ok_or_else(|| Error::Transport("no async runtime found".into()))?;
            Some(quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(quic_server_config(&tls, opts.h3.is_some())?),
                udp,
                runtime,
            )?)
        } else {
            None
        };
        let listener = if opts.websocket {
            tcp.set_nonblocking(true)?;
            Some(tokio::net::TcpListener::from_std(tcp)?)
        } else {
            None
        };
        let quic_addr = endpoint
            .as_ref()
            .map(quinn::Endpoint::local_addr)
            .transpose()?;
        let tcp_addr = listener
            .as_ref()
            .map(tokio::net::TcpListener::local_addr)
            .transpose()?;
        Ok(Self {
            quic_addr,
            tcp_addr,
            endpoint: endpoint.clone(),
            pending: Mutex::new(rx),
            ctx,
            tasks: StdMutex::new(Vec::new()),
            unstarted: StdMutex::new(Some(Unstarted { endpoint, listener })),
        })
    }

    /// Starts the accept loops of a server made with [`bind_paused`](Self::bind_paused). Does
    /// nothing if they already run (or after [`close`](Self::close)).
    pub fn start(&self) {
        let Some(u) = self
            .unstarted
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
        else {
            return;
        };
        let mut tasks = self.tasks.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(ep) = u.endpoint {
            tasks.push(tokio::spawn(quic_accept_loop(ep, self.ctx.clone())));
        }
        if let Some(l) = u.listener {
            tasks.push(tokio::spawn(ws::accept_loop(l, self.ctx.clone())));
        }
    }

    /// Address of the QUIC endpoint (UDP), if enabled.
    pub fn quic_addr(&self) -> Option<SocketAddr> {
        self.quic_addr
    }

    /// Address of the WebSocket listener (TCP), if enabled.
    pub fn websocket_addr(&self) -> Option<SocketAddr> {
        self.tcp_addr
    }

    /// Replace the TLS configuration for new connections (certificate hot reload). Existing
    /// connections are untouched: **revoking a device must also close its live sessions**,
    /// because neither a reload nor a changed verifier affects connections already
    /// established. Only TLS 1.3 sessions are served (anything else is dropped at the handshake).
    pub fn reload_tls(&self, tls: Arc<rustls::ServerConfig>) -> Result<()> {
        if let Some(ep) = &self.endpoint {
            ep.set_server_config(Some(quic_server_config(&tls, self.ctx.opts.h3.is_some())?));
        }
        let mut w = self
            .ctx
            .ws_tls
            .write()
            .map_err(|_| Error::Config("TLS configuration lock is poisoned".into()))?;
        *w = Arc::new(alpn_config(&tls, &[hx_proto::version::ALPN_WEBSOCKET]));
        Ok(())
    }

    /// Wait for the next client whose transport and `Hello` are valid and whose major version
    /// matches. A different major is refused automatically and never surfaces here. Returns
    /// `None` after [`close`](Self::close).
    pub async fn accept(&self) -> Option<PendingSession> {
        self.pending.lock().await.recv().await
    }

    /// Stop listening and close the endpoint (existing connections get `SHUTDOWN`).
    pub fn close(&self) {
        if let Some(ep) = &self.endpoint {
            ep.close(quic_code(CloseCode::Shutdown), b"server shutdown");
        }
        // A server that was never started drops its sockets here.
        self.unstarted
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        for t in self.tasks.lock().unwrap_or_else(|p| p.into_inner()).iter() {
            t.abort();
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.close();
    }
}

fn quic_code(code: CloseCode) -> quinn::VarInt {
    quinn::VarInt::from_u32(code.code())
}

pub(crate) enum PendingInner {
    Quic {
        conn: quinn::Connection,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    },
    Ws(Box<WsPending>),
}

/// Pre-authentication resources held by one connection: a global slot and a per-source slot.
/// Released when the connection is authorized, refused, closed or dropped.
pub(crate) struct PreAuthSlot {
    _permit: OwnedSemaphorePermit,
    _ip: IpGuard,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct IpKey(u128);

/// The counters a source address is charged to, with each one's limit: an IPv4 address
/// individually; an IPv6 address per /64 and per /48 (one site must not hold every slot).
fn ip_keys(ip: IpAddr, per_64: usize, per_48: usize) -> Vec<(IpKey, usize)> {
    match ip.to_canonical() {
        IpAddr::V4(a) => vec![(IpKey(u128::from(u32::from(a))), per_64)],
        IpAddr::V6(a) => {
            let bits = u128::from(a);
            vec![
                (IpKey((bits >> 64) | (1 << 64)), per_64),
                (IpKey((bits >> 80) | (1 << 65)), per_48),
            ]
        }
    }
}

struct IpGuard {
    map: Arc<StdMutex<HashMap<IpKey, usize>>>,
    keys: Vec<IpKey>,
}

impl Drop for IpGuard {
    fn drop(&mut self) {
        if let Ok(mut m) = self.map.lock() {
            for key in &self.keys {
                if let Some(c) = m.get_mut(key) {
                    *c = c.saturating_sub(1);
                    if *c == 0 {
                        m.remove(key);
                    }
                }
            }
        }
    }
}

impl ServerCtx {
    /// Take a pre-authentication slot for a new connection from `ip`, or `None` if the global
    /// or the per-source limit is reached.
    pub(crate) fn acquire(&self, ip: IpAddr) -> Option<PreAuthSlot> {
        let limits = ip_keys(
            ip,
            self.opts.max_pending_per_ip.max(1),
            self.opts.max_pending_per_v6_48.max(1),
        );
        {
            let mut m = self.ips.lock().ok()?;
            if limits
                .iter()
                .any(|(k, cap)| m.get(k).copied().unwrap_or(0) >= *cap)
            {
                return None;
            }
            for (k, _) in &limits {
                *m.entry(*k).or_insert(0) += 1;
            }
        }
        let guard = IpGuard {
            map: self.ips.clone(),
            keys: limits.iter().map(|(k, _)| *k).collect(),
        };
        let permit = self.sem.clone().try_acquire_owned().ok()?;
        Some(PreAuthSlot {
            _permit: permit,
            _ip: guard,
        })
    }
}

struct PendingState {
    inner: PendingInner,
    slot: PreAuthSlot,
}

/// A client that passed the transport and version checks and waits for the application's
/// decision. It holds a pre-authentication slot and must be answered within
/// [`ServerOptions::decision_timeout`], after which it is refused with `BUSY` automatically.
pub struct PendingSession {
    pub(crate) hello: pb::Hello,
    pub(crate) transport: TransportKind,
    pub(crate) remote: SocketAddr,
    pub(crate) peer_certs: Option<Vec<CertificateDer<'static>>>,
    pub(crate) options: ConnectionOptions,
    auth_timeout: Option<Duration>,
    accept_timeout: Duration,
    state: Arc<StdMutex<Option<PendingState>>>,
}

/// Outcome of looking at a first control message.
pub(crate) enum HelloCheck {
    Ok(pb::Hello),
    UpdateRequired,
}

/// Decide what to do with the first control message (protocol §4.2, §4.4).
pub(crate) fn check_hello(buf: &[u8]) -> Result<HelloCheck> {
    if let Some(v) = peek_hello_version(buf)
        && v.major != PROTOCOL_MAJOR
    {
        return Ok(HelloCheck::UpdateRequired);
    }
    let m: ControlMessage = message::decode(buf)?;
    match m.message {
        Some(Ctl::Hello(h)) => Ok(HelloCheck::Ok(h)),
        _ => Err(Error::Violation(
            "the first control message must be Hello".into(),
        )),
    }
}

/// Longest prefix of `s` that fits in `max` bytes without splitting a character.
fn truncate_bytes(s: &str, max: usize) -> &str {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

pub(crate) fn refuse_message(reason: RefuseReason, text: &str) -> ControlMessage {
    ControlMessage::new(Ctl::Refuse(pb::Refuse {
        reason: effective_reason(reason) as i32,
        message: truncate_bytes(text, 256).to_string(),
        version: Some(ProtocolVersion::CURRENT.into()),
    }))
}

/// `Unspecified` is not a valid wire value: refusing without a reason means "not authorized".
fn effective_reason(reason: RefuseReason) -> RefuseReason {
    match reason {
        RefuseReason::Unspecified => RefuseReason::Unauthorized,
        other => other,
    }
}

pub(crate) fn close_code_for(reason: RefuseReason) -> CloseCode {
    match effective_reason(reason) {
        RefuseReason::UpdateRequired => CloseCode::UpdateRequired,
        RefuseReason::Busy => CloseCode::Busy,
        RefuseReason::PairingClosed => CloseCode::PairingClosed,
        RefuseReason::SetupClosed => CloseCode::SetupClosed,
        _ => CloseCode::Unauthorized,
    }
}

fn random_session_id() -> Result<[u8; 16]> {
    let mut id = [0u8; 16];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut id)
        .map_err(|_| Error::Tls("system random number generator failed".into()))?;
    Ok(id)
}

impl PendingSession {
    pub(crate) fn new(
        ctx: &ServerCtx,
        hello: pb::Hello,
        transport: TransportKind,
        remote: SocketAddr,
        peer_certs: Option<Vec<CertificateDer<'static>>>,
        inner: PendingInner,
        slot: PreAuthSlot,
    ) -> Self {
        let state = Arc::new(StdMutex::new(Some(PendingState { inner, slot })));
        // Automatic BUSY refusal if the application never decides.
        let watch = state.clone();
        let wait = ctx.opts.decision_timeout;
        tokio::spawn(async move {
            tokio::time::sleep(wait).await;
            let st = watch.lock().ok().and_then(|mut s| s.take());
            if let Some(st) = st {
                let _ = refuse_inner(st.inner, RefuseReason::Busy, "no decision in time").await;
                drop(st.slot);
            }
        });
        Self {
            hello,
            transport,
            remote,
            peer_certs,
            options: ctx.opts.connection.clone(),
            auth_timeout: ctx.opts.auth_timeout,
            accept_timeout: ctx.opts.decision_timeout,
            state,
        }
    }

    fn take_state(&self) -> Result<PendingState> {
        self.state
            .lock()
            .ok()
            .and_then(|mut s| s.take())
            .ok_or(Error::Timeout("decision window expired"))
    }

    /// The client's `Hello` (validated, same major version).
    pub fn hello(&self) -> &pb::Hello {
        &self.hello
    }

    /// The client's address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote
    }

    /// Which transport the client used.
    pub fn transport(&self) -> TransportKind {
        self.transport
    }

    /// The certificate chain the client presented during TLS (`None` without client auth).
    /// The application MUST re-check the peer key against its current pinned and revoked
    /// set on every `PendingSession` (TLS resumption is disabled, but revocation can happen
    /// at any time).
    pub fn peer_certificates(&self) -> Option<&[CertificateDer<'static>]> {
        self.peer_certs.as_deref()
    }

    /// Accept: answer `HelloAck` and return the established [`Connection`], which is
    /// **restricted** until [`Connection::authorize`] or
    /// [`Connection::authorize_control_only`] is called (see there). For an `INTENT_PAIR` hello
    /// the advertised features and codecs are empty.
    pub async fn accept(self, reply: ServerHello) -> Result<Connection> {
        // Everything that can fail locally is checked before the transport is touched, and a
        // failure closes the connection with an explicit code (never 0).
        let (negotiated, session_id, body) = match self.prepare(reply) {
            Ok(p) => p,
            Err(e) => {
                self.abort(CloseCode::InternalError).await;
                return Err(e);
            }
        };
        let st = self.take_state()?;
        let parts = Parts {
            role: Role::Server,
            kind: self.transport,
            negotiated,
            peer: PeerInfo {
                software: self.hello.software.clone(),
                device_name: self.hello.device_name.clone(),
            },
            session_id,
            peer_certs: self.peer_certs.clone(),
            remote_addr: self.remote,
            options: self.options.clone(),
            slot: Some(st.slot),
            auth_timeout: self.auth_timeout,
        };
        let quic_conn = match &st.inner {
            PendingInner::Quic { conn, .. } => Some(conn.clone()),
            PendingInner::Ws(_) => None,
        };
        // A peer that never reads (zero flow-control window) must not hold the slot, and the
        // caller's accept loop, forever: the whole answer is bounded.
        let establish = async move {
            match st.inner {
                PendingInner::Quic {
                    conn,
                    mut send,
                    recv,
                } => {
                    write_message(&mut send, &body).await?;
                    quic::establish(conn, send, recv, None, parts).await
                }
                PendingInner::Ws(w) => ws::establish_server(*w, body, parts).await,
            }
        };
        match tokio::time::timeout(self.accept_timeout, establish).await {
            Ok(Ok(c)) => Ok(c),
            Ok(Err(e)) => {
                if let Some(c) = quic_conn {
                    c.close(quic_code(CloseCode::InternalError), b"accept failed");
                }
                Err(e)
            }
            Err(_) => {
                if let Some(c) = quic_conn {
                    c.close(quic_code(CloseCode::Busy), b"accept timed out");
                }
                Err(Error::Timeout("HelloAck"))
            }
        }
    }

    /// Negotiate and encode the `HelloAck`; fails before anything is sent.
    fn prepare(&self, reply: ServerHello) -> Result<(Negotiated, [u8; 16], Bytes)> {
        let client_version = self
            .hello
            .version
            .as_ref()
            .map(ProtocolVersion::from)
            .unwrap_or(ProtocolVersion { major: 0, minor: 0 });
        let client_caps = self.hello.capabilities.clone().unwrap_or_default();
        let capabilities = if self.hello.intent == pb::Intent::Pair as i32 {
            capabilities(&[], Features::NONE)
        } else {
            reply.capabilities
        };
        let negotiated = negotiate(
            ProtocolVersion::CURRENT,
            &capabilities,
            client_version,
            &client_caps,
        )?;
        let session_id = random_session_id()?;
        let ack = ControlMessage::new(Ctl::HelloAck(pb::HelloAck {
            version: Some(ProtocolVersion::CURRENT.into()),
            capabilities: Some(capabilities),
            session_id: Bytes::copy_from_slice(&session_id),
            software: reply.software,
        }));
        // Validates `ServerHello` (software length, codec list) up front.
        let body = message::encode(&ack)?;
        Ok((negotiated, session_id, body))
    }

    /// Close an undecided session with an explicit code (no `Refuse`), releasing its slot.
    async fn abort(&self, code: CloseCode) {
        if let Ok(st) = self.take_state() {
            match st.inner {
                PendingInner::Quic { conn, .. } => conn.close(quic_code(code), b"accept failed"),
                PendingInner::Ws(w) => ws::close_server(*w, code).await,
            }
        }
    }

    /// Refuse: send `Refuse` with `reason` and `message` (safe to show to the user; cut to 256
    /// bytes on a character boundary), then close the connection with the matching close code.
    /// `RefuseReason::Unspecified` is sent as `Unauthorized`.
    pub async fn refuse(self, reason: RefuseReason, message_text: &str) -> Result<()> {
        let st = self.take_state()?;
        let r = refuse_inner(st.inner, reason, message_text).await;
        drop(st.slot);
        r
    }
}

/// Dropping a session without deciding refuses it with `BUSY` at once (instead of waiting for
/// the decision window), so a forgotten `PendingSession` cannot keep its slot or its peer
/// waiting.
impl Drop for PendingSession {
    fn drop(&mut self) {
        let st = self.state.lock().ok().and_then(|mut s| s.take());
        if let Some(st) = st
            && let Ok(rt) = tokio::runtime::Handle::try_current()
        {
            rt.spawn(async move {
                let _ = refuse_inner(st.inner, RefuseReason::Busy, "session dropped").await;
                drop(st.slot);
            });
        }
    }
}

async fn refuse_inner(inner: PendingInner, reason: RefuseReason, text: &str) -> Result<()> {
    let body = message::encode(&refuse_message(reason, text))?;
    let code = close_code_for(reason);
    match inner {
        PendingInner::Quic { conn, send, .. } => refuse_quic(&conn, send, &body, code).await,
        PendingInner::Ws(w) => ws::refuse_server(*w, body, code).await,
    }
}

/// Deliver `Refuse` reliably (finish the stream and wait for the ack), then close.
async fn refuse_quic(
    conn: &quinn::Connection,
    mut send: quinn::SendStream,
    body: &Bytes,
    code: CloseCode,
) -> Result<()> {
    let delivered = async {
        write_message(&mut send, body).await?;
        send.finish().map_err(transport)?;
        send.stopped().await.map_err(transport)?;
        Ok::<(), Error>(())
    };
    let _ = tokio::time::timeout(Duration::from_secs(2), delivered).await;
    conn.close(quic_code(code), b"refused");
    Ok(())
}

// ---------------------------------------------------------------- QUIC accept path

async fn quic_accept_loop(endpoint: quinn::Endpoint, ctx: Arc<ServerCtx>) {
    while let Some(incoming) = endpoint.accept().await {
        if ctx.opts.require_retry && !incoming.remote_address_validated() && incoming.may_retry() {
            let _ = incoming.retry();
            continue;
        }
        let Some(slot) = ctx.acquire(incoming.remote_address().ip()) else {
            incoming.refuse();
            continue;
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = quic_incoming(incoming, &ctx, slot).await {
                tracing::debug!(error = %e, "incoming QUIC connection dropped");
            }
        });
    }
}

async fn quic_incoming(
    incoming: quinn::Incoming,
    ctx: &ServerCtx,
    slot: PreAuthSlot,
) -> Result<()> {
    let start = Instant::now();
    let deadline = start + ctx.opts.handshake_timeout;
    // TLS must complete sooner than the whole hello exchange.
    let tls_deadline = start + ctx.opts.handshake_timeout.min(ctx.opts.transport_timeout);
    let mut connecting = incoming.accept().map_err(transport)?;
    let hd = tokio::time::timeout_at(tls_deadline, connecting.handshake_data())
        .await
        .map_err(|_| Error::Timeout("TLS handshake"))?
        .map_err(transport)?;
    let alpn = hd
        .downcast::<HandshakeData>()
        .map_err(|_| Error::Tls("unexpected handshake data".into()))?
        .protocol
        .clone()
        .unwrap_or_default();

    // ALPN dispatch (protocol §1): `hx/1` is native; `h3` goes to the pluggable handler.
    if alpn.as_slice() == ALPN_H3 {
        return match &ctx.opts.h3 {
            Some(h) => {
                h.handle(connecting).await;
                Ok(())
            }
            None => Err(Error::Violation("h3 negotiated without a handler".into())),
        };
    }
    if alpn.as_slice() != ALPN {
        return Err(Error::Violation("unexpected ALPN".into()));
    }

    let conn = tokio::time::timeout_at(tls_deadline, connecting)
        .await
        .map_err(|_| Error::Timeout("QUIC handshake"))?
        .map_err(transport)?;
    let remote = conn.remote_address();
    let peer_certs = quic::peer_certs(&conn)?;

    let hello_phase = async {
        let (send, mut recv) = conn.accept_bi().await.map_err(transport)?;
        let mut first = [0u8; 1];
        recv.read_exact(&mut first).await.map_err(transport)?;
        if ChannelId::from_u8(first[0])? != ChannelId::Control {
            return Err(Error::Violation(
                "first stream must be the control stream".into(),
            ));
        }
        let Some(buf) = read_message(&mut recv, MAX_CONTROL_MESSAGE).await? else {
            return Err(Error::Violation("control stream ended before Hello".into()));
        };
        Ok((send, recv, buf))
    };
    let (send, recv, buf) = match tokio::time::timeout_at(deadline, hello_phase).await {
        Ok(Ok(x)) => x,
        Ok(Err(e)) => {
            if matches!(e, Error::Violation(_) | Error::Protocol(_)) {
                conn.close(
                    quic_code(CloseCode::ProtocolError),
                    b"invalid first message",
                );
            }
            return Err(e);
        }
        Err(_) => {
            conn.close(quic_code(CloseCode::HelloTimeout), b"no hello");
            return Err(Error::Timeout("Hello"));
        }
    };

    let hello = match check_hello(&buf) {
        Ok(HelloCheck::Ok(h)) => h,
        Ok(HelloCheck::UpdateRequired) => {
            let body = message::encode(&refuse_message(
                RefuseReason::UpdateRequired,
                "update required",
            ))?;
            return refuse_quic(&conn, send, &body, CloseCode::UpdateRequired).await;
        }
        Err(e) => {
            conn.close(quic_code(CloseCode::ProtocolError), b"invalid Hello");
            return Err(e);
        }
    };

    let pending = PendingSession::new(
        ctx,
        hello,
        TransportKind::Quic,
        remote,
        peer_certs,
        PendingInner::Quic {
            conn: conn.clone(),
            send,
            recv,
        },
        slot,
    );
    if let Err(e) = ctx.tx.try_send(pending) {
        let (mpsc::error::TrySendError::Full(p) | mpsc::error::TrySendError::Closed(p)) = e;
        let _ = p.refuse(RefuseReason::Busy, "server busy").await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> ServerCtx {
        let (tx, _rx) = mpsc::channel(1);
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new()));
        ServerCtx {
            opts: ServerOptions::default(),
            sem: Arc::new(Semaphore::new(64)),
            ips: Arc::new(StdMutex::new(HashMap::new())),
            tx,
            ws_tls: RwLock::new(Arc::new(tls)),
        }
    }

    fn v6(site: u16, subnet: u16) -> IpAddr {
        format!("2001:db8:{site:x}:{subnet:x}::1")
            .parse()
            .expect("address")
    }

    #[test]
    fn one_ipv6_site_cannot_hold_all_slots() {
        let ctx = ctx();
        // One /48 may hold 16 slots spread over different /64s, not more.
        let held: Vec<_> = (0..16)
            .map(|n| ctx.acquire(v6(1, n)).expect("within the /48 cap"))
            .collect();
        assert!(ctx.acquire(v6(1, 99)).is_none(), "the /48 is full");
        // Another site is unaffected, and so is IPv4.
        assert!(ctx.acquire(v6(2, 0)).is_some());
        assert!(ctx.acquire("192.0.2.1".parse().expect("v4")).is_some());
        // Releasing one frees a place.
        drop(held);
        assert!(ctx.acquire(v6(1, 99)).is_some());
    }

    #[test]
    fn per_64_and_per_ipv4_address_caps_apply() {
        let ctx = ctx();
        let _a: Vec<_> = (0..4)
            .map(|_| ctx.acquire(v6(3, 0)).expect("within the /64 cap"))
            .collect();
        assert!(ctx.acquire(v6(3, 0)).is_none());
        let v4: IpAddr = "192.0.2.7".parse().expect("v4");
        let _b: Vec<_> = (0..4)
            .map(|_| ctx.acquire(v4).expect("within the address cap"))
            .collect();
        assert!(ctx.acquire(v4).is_none());
    }
}
