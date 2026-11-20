//! The client side: connect over QUIC, over the WebSocket fallback, or QUIC with fallback.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use hx_proto::{
    channel::{ChannelId, CloseCode, MAX_CONTROL_MESSAGE},
    message,
    pb::{self, ControlMessage, control_message::Message as Ctl},
    version::{ALPN, ProtocolVersion, negotiate},
};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::{CertificateDer, ServerName};

use crate::{
    conn::{Connection, ConnectionOptions, Parts, PeerInfo, Role, TransportKind},
    error::{Error, Result, transport},
    quic::{self, read_message, write_message},
    ws,
};

/// Where to connect.
#[derive(Debug, Clone)]
pub struct Target {
    /// Socket address (UDP for QUIC, the same port number over TCP for WebSocket).
    pub addr: SocketAddr,
    /// Name used for TLS (SNI and certificate verification, as the injected verifier sees it).
    pub server_name: ServerName<'static>,
}

/// What the client says about itself in the `Hello`.
#[derive(Debug, Clone)]
pub struct ClientHello {
    /// What this client can decode and do.
    pub capabilities: pb::Capabilities,
    /// Session or pairing (protocol §11).
    pub intent: pb::Intent,
    /// Software string, e.g. `hx-desktop 0.1.0` (at most 128 bytes).
    pub software: String,
    /// Human device label (at most 64 bytes).
    pub device_name: String,
}

/// Which transport to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportPreference {
    /// QUIC only.
    Quic,
    /// WebSocket over TLS only.
    WebSocket,
    /// QUIC first; WebSocket if QUIC cannot be established in time. A refusal by the server
    /// is final and is not retried over the other transport.
    Auto,
}

/// Client tunables.
#[derive(Debug, Clone)]
pub struct ClientOptions {
    /// Transport choice.
    pub preference: TransportPreference,
    /// Transport connect (TCP/QUIC/TLS) timeout.
    pub connect_timeout: Duration,
    /// Time allowed for the server's `HelloAck` or `Refuse`.
    pub handshake_timeout: Duration,
    /// With [`TransportPreference::Auto`]: how long QUIC may take before falling back.
    pub quic_attempt_timeout: Duration,
    /// Per-connection tunables.
    pub connection: ConnectionOptions,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            preference: TransportPreference::Auto,
            connect_timeout: Duration::from_secs(5),
            handshake_timeout: Duration::from_secs(10),
            quic_attempt_timeout: Duration::from_secs(3),
            connection: ConnectionOptions::default(),
        }
    }
}

/// A connector holding the injected TLS configuration.
#[derive(Clone)]
pub struct Client {
    tls: Arc<rustls::ClientConfig>,
    options: ClientOptions,
}

pub(crate) fn build_hello(h: &ClientHello) -> pb::Hello {
    pb::Hello {
        version: Some(ProtocolVersion::CURRENT.into()),
        capabilities: Some(h.capabilities.clone()),
        intent: h.intent as i32,
        software: h.software.clone(),
        device_name: h.device_name.clone(),
    }
}

/// Interpret the server's reply to `Hello`.
pub(crate) fn process_reply(
    buf: &[u8],
    hello: &pb::Hello,
) -> Result<(pb::HelloAck, hx_proto::version::Negotiated, [u8; 16])> {
    let m: ControlMessage = message::decode(buf)?;
    match m.message {
        Some(Ctl::HelloAck(ack)) => {
            let server_version = ack
                .version
                .as_ref()
                .map(ProtocolVersion::from)
                .unwrap_or(ProtocolVersion { major: 0, minor: 0 });
            let server_caps = ack.capabilities.clone().unwrap_or_default();
            let client_caps = hello.capabilities.clone().unwrap_or_default();
            let negotiated = negotiate(
                server_version,
                &server_caps,
                ProtocolVersion::CURRENT,
                &client_caps,
            )?;
            let mut id = [0u8; 16];
            // Validated to be exactly 16 bytes by `message::decode`.
            id.copy_from_slice(&ack.session_id);
            Ok((ack, negotiated, id))
        }
        Some(Ctl::Refuse(r)) => Err(Error::Refused {
            reason: pb::RefuseReason::try_from(r.reason).unwrap_or(pb::RefuseReason::Unspecified),
            message: r.message,
            server_version: r.version.as_ref().map(ProtocolVersion::from),
        }),
        _ => Err(Error::Violation("expected HelloAck or Refuse".into())),
    }
}

impl Client {
    /// A connector using `tls` (identity, server verification, pinning: injected by the
    /// caller; ALPN values are set by this crate) and `options`.
    pub fn new(tls: Arc<rustls::ClientConfig>, options: ClientOptions) -> Self {
        Self { tls, options }
    }

    /// Connect according to the configured [`TransportPreference`].
    pub async fn connect(&self, target: &Target, hello: &ClientHello) -> Result<Connection> {
        match self.options.preference {
            TransportPreference::Quic => self.connect_quic(target, hello).await,
            TransportPreference::WebSocket => self.connect_websocket(target, hello).await,
            TransportPreference::Auto => {
                let attempt = tokio::time::timeout(
                    self.options.quic_attempt_timeout,
                    self.connect_quic(target, hello),
                );
                match attempt.await {
                    Ok(Ok(c)) => Ok(c),
                    // The server answered: do not second-guess it over another transport.
                    Ok(Err(e @ (Error::Refused { .. } | Error::Closed(_) | Error::Version(_)))) => {
                        Err(e)
                    }
                    Ok(Err(e)) => {
                        tracing::debug!(error = %e, "QUIC failed, falling back to WebSocket");
                        self.connect_websocket(target, hello).await
                    }
                    Err(_) => {
                        tracing::debug!("QUIC attempt timed out, falling back to WebSocket");
                        self.connect_websocket(target, hello).await
                    }
                }
            }
        }
    }

    /// Connect over QUIC (ALPN `hx/1`).
    pub async fn connect_quic(&self, target: &Target, hello: &ClientHello) -> Result<Connection> {
        let mut tls = (*self.tls).clone();
        tls.alpn_protocols = vec![ALPN.to_vec()];
        let quic_tls = QuicClientConfig::try_from(tls).map_err(|e| Error::Tls(e.to_string()))?;
        let mut cfg = quinn::ClientConfig::new(Arc::new(quic_tls));
        cfg.transport_config(Arc::new(quic::transport_config(Role::Client)?));

        let bind: SocketAddr = if target.addr.is_ipv4() {
            ([0, 0, 0, 0], 0).into()
        } else {
            ([0u16; 8], 0).into()
        };
        let mut endpoint = quinn::Endpoint::client(bind)?;
        endpoint.set_default_client_config(cfg);

        let name = target.server_name.to_str().into_owned();
        let connecting = endpoint.connect(target.addr, &name).map_err(transport)?;
        let conn = tokio::time::timeout(self.options.connect_timeout, connecting)
            .await
            .map_err(|_| Error::Timeout("QUIC connect"))?
            .map_err(transport)?;

        let hello_msg = build_hello(hello);
        let body = message::encode(&ControlMessage::new(Ctl::Hello(hello_msg.clone())))?;
        let exchange = async {
            let (mut send, mut recv) = conn.open_bi().await.map_err(transport)?;
            send.write_all(&[ChannelId::Control as u8])
                .await
                .map_err(transport)?;
            write_message(&mut send, &body).await?;
            let reply = read_message(&mut recv, MAX_CONTROL_MESSAGE).await?;
            Ok::<_, Error>((send, recv, reply))
        };
        let (send, recv, reply) =
            match tokio::time::timeout(self.options.handshake_timeout, exchange).await {
                Ok(Ok(x)) => x,
                Ok(Err(e)) => return Err(closed_or(&conn, e)),
                Err(_) => {
                    conn.close(quinn_code(CloseCode::HelloTimeout), b"no reply");
                    return Err(Error::Timeout("server reply"));
                }
            };
        let Some(reply) = reply else {
            return Err(closed_or(&conn, Error::ChannelClosed));
        };
        let (ack, negotiated, session_id) = match process_reply(&reply, &hello_msg) {
            Ok(x) => x,
            Err(e) => {
                let code = match &e {
                    Error::Version(_) => CloseCode::UpdateRequired,
                    Error::Refused { .. } => CloseCode::NoError,
                    _ => CloseCode::ProtocolError,
                };
                conn.close(quinn_code(code), b"handshake failed");
                return Err(e);
            }
        };
        let parts = Parts {
            role: Role::Client,
            kind: TransportKind::Quic,
            negotiated,
            peer: PeerInfo {
                software: ack.software,
                device_name: String::new(),
            },
            session_id,
            peer_certs: conn
                .peer_identity()
                .and_then(|i| i.downcast::<Vec<CertificateDer<'static>>>().ok())
                .map(|b| *b),
            remote_addr: conn.remote_address(),
            options: self.options.connection.clone(),
            slot: None,
            auth_timeout: None,
        };
        quic::establish(conn, send, recv, Some(endpoint), parts).await
    }

    /// Connect over the WebSocket-over-TLS fallback.
    pub async fn connect_websocket(
        &self,
        target: &Target,
        hello: &ClientHello,
    ) -> Result<Connection> {
        ws::connect(&self.tls, &self.options, target, hello).await
    }
}

fn quinn_code(code: CloseCode) -> quinn::VarInt {
    quinn::VarInt::from_u32(code.code())
}

/// If the server closed the connection while we waited, report that instead of a read error.
fn closed_or(conn: &quinn::Connection, e: Error) -> Error {
    match conn.close_reason() {
        Some(reason) => {
            let info = quic::close_info_from_error(&reason);
            Error::Closed(info)
        }
        None => e,
    }
}
