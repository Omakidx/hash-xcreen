//! The server side: one endpoint, ALPN dispatch, pre-authentication bounds, and the
//! [`PendingSession`] hook where the application decides accept or refuse.

use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, RwLock},
    time::Duration,
};

use bytes::Bytes;
use hx_proto::{
    channel::{ChannelId, CloseCode, MAX_CONTROL_MESSAGE},
    message,
    pb::{self, ControlMessage, RefuseReason, control_message::Message as Ctl},
    version::{ALPN, ALPN_H3, PROTOCOL_MAJOR, ProtocolVersion, negotiate, peek_hello_version},
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
    /// Connections that may be in the pre-`HelloAck` state at once (protocol §1: 64).
    pub max_pending: usize,
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
            max_pending: 64,
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
    tasks: Vec<JoinHandle<()>>,
}

fn alpn_config(tls: &rustls::ServerConfig, alpn: &[&[u8]]) -> rustls::ServerConfig {
    let mut c = tls.clone();
    c.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
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
    /// allow TLS 1.3. ALPN values are set by this crate.
    pub async fn bind(
        addr: SocketAddr,
        tls: Arc<rustls::ServerConfig>,
        opts: ServerOptions,
    ) -> Result<Self> {
        if !opts.quic && !opts.websocket {
            return Err(Error::Config(
                "enable at least one of quic and websocket".into(),
            ));
        }
        let (tx, rx) = mpsc::channel(16);
        let ctx = Arc::new(ServerCtx {
            sem: Arc::new(Semaphore::new(opts.max_pending.max(1))),
            tx,
            ws_tls: RwLock::new(Arc::new(alpn_config(
                &tls,
                &[hx_proto::version::ALPN_WEBSOCKET],
            ))),
            opts: opts.clone(),
        });

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

            let mut tasks = Vec::new();
            if let Some(ep) = endpoint.clone() {
                tasks.push(tokio::spawn(quic_accept_loop(ep, ctx.clone())));
            }
            if let Some(l) = listener {
                tasks.push(tokio::spawn(ws::accept_loop(l, ctx.clone())));
            }
            return Ok(Self {
                quic_addr,
                tcp_addr,
                endpoint,
                pending: Mutex::new(rx),
                ctx,
                tasks,
            });
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
    /// connections are untouched.
    pub fn reload_tls(&self, tls: Arc<rustls::ServerConfig>) -> Result<()> {
        if let Some(ep) = &self.endpoint {
            ep.set_server_config(Some(quic_server_config(&tls, self.ctx.opts.h3.is_some())?));
        }
        if let Ok(mut w) = self.ctx.ws_tls.write() {
            *w = Arc::new(alpn_config(&tls, &[hx_proto::version::ALPN_WEBSOCKET]));
        }
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
        for t in &self.tasks {
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

/// A client that passed the transport and version checks and waits for the application's
/// decision. Holds one of the bounded pre-authentication slots until accepted, refused or
/// dropped.
pub struct PendingSession {
    pub(crate) hello: pb::Hello,
    pub(crate) transport: TransportKind,
    pub(crate) remote: SocketAddr,
    pub(crate) peer_certs: Option<Vec<CertificateDer<'static>>>,
    pub(crate) inner: PendingInner,
    pub(crate) options: ConnectionOptions,
    pub(crate) _permit: OwnedSemaphorePermit,
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

pub(crate) fn refuse_message(reason: RefuseReason, text: &str) -> ControlMessage {
    ControlMessage::new(Ctl::Refuse(pb::Refuse {
        reason: reason as i32,
        message: text.chars().take(200).collect(),
        version: Some(ProtocolVersion::CURRENT.into()),
    }))
}

pub(crate) fn close_code_for(reason: RefuseReason) -> CloseCode {
    match reason {
        RefuseReason::UpdateRequired => CloseCode::UpdateRequired,
        RefuseReason::Unauthorized => CloseCode::Unauthorized,
        RefuseReason::Busy => CloseCode::Busy,
        RefuseReason::PairingClosed => CloseCode::PairingClosed,
        RefuseReason::Unspecified => CloseCode::InternalError,
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

    /// The certificate chain the client presented during TLS (empty for no client auth).
    /// The identity decision itself belongs to the injected TLS verifier (workstream 1B).
    pub fn peer_certificates(&self) -> Option<&[CertificateDer<'static>]> {
        self.peer_certs.as_deref()
    }

    /// Accept: answer `HelloAck` and return the established [`Connection`].
    pub async fn accept(self, reply: ServerHello) -> Result<Connection> {
        let client_version = self
            .hello
            .version
            .as_ref()
            .map(ProtocolVersion::from)
            .unwrap_or(ProtocolVersion { major: 0, minor: 0 });
        let client_caps = self.hello.capabilities.clone().unwrap_or_default();
        let negotiated = negotiate(
            ProtocolVersion::CURRENT,
            &reply.capabilities,
            client_version,
            &client_caps,
        )?;
        let session_id = random_session_id()?;
        let ack = ControlMessage::new(Ctl::HelloAck(pb::HelloAck {
            version: Some(ProtocolVersion::CURRENT.into()),
            capabilities: Some(reply.capabilities),
            session_id: Bytes::copy_from_slice(&session_id),
            software: reply.software,
        }));
        let body = message::encode(&ack)?;
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
        };
        match self.inner {
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
    }

    /// Refuse: send `Refuse` with `reason` and `message` (safe to show to the user), then close
    /// the connection with the matching close code.
    pub async fn refuse(self, reason: RefuseReason, message_text: &str) -> Result<()> {
        let body = message::encode(&refuse_message(reason, message_text))?;
        let code = close_code_for(reason);
        match self.inner {
            PendingInner::Quic { conn, send, .. } => refuse_quic(&conn, send, &body, code).await,
            PendingInner::Ws(w) => ws::refuse_server(*w, body, code).await,
        }
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
        let Ok(permit) = ctx.sem.clone().try_acquire_owned() else {
            incoming.refuse();
            continue;
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = quic_incoming(incoming, &ctx, permit).await {
                tracing::debug!(error = %e, "incoming QUIC connection dropped");
            }
        });
    }
}

async fn quic_incoming(
    incoming: quinn::Incoming,
    ctx: &ServerCtx,
    permit: OwnedSemaphorePermit,
) -> Result<()> {
    let deadline = Instant::now() + ctx.opts.handshake_timeout;
    let mut connecting = incoming.accept().map_err(transport)?;
    let hd = tokio::time::timeout_at(deadline, connecting.handshake_data())
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

    let conn = tokio::time::timeout_at(deadline, connecting)
        .await
        .map_err(|_| Error::Timeout("QUIC handshake"))?
        .map_err(transport)?;
    let remote = conn.remote_address();
    let peer_certs = conn
        .peer_identity()
        .and_then(|i| i.downcast::<Vec<CertificateDer<'static>>>().ok())
        .map(|b| *b);

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

    let pending = PendingSession {
        hello,
        transport: TransportKind::Quic,
        remote,
        peer_certs,
        inner: PendingInner::Quic {
            conn: conn.clone(),
            send,
            recv,
        },
        options: ctx.opts.connection.clone(),
        _permit: permit,
    };
    if ctx.tx.try_send(pending).is_err() {
        conn.close(quic_code(CloseCode::Busy), b"server busy");
    }
    Ok(())
}
