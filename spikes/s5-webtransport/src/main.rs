//! Spike S5: one UDP port for native QUIC (ALPN `hx/1`) and WebTransport (ALPN `h3`),
//! plus a TLS WebSocket fallback on the same TCP port number. Not production code.
//!
//! Subcommands:
//!   serve [--port P] [--http-port H] [--report FILE]   run the server (loopback, self-signed)
//!   serve --cert PEM --key PEM --bind ADDR [--port P] [--https-port H] [--ws-port W] [--report FILE]
//!                                                      public mode: CA certificate, HTTPS page
//!   native-check PORT HASH_HEX|ca [--host H]           native `hx/1` client ping
//!   ws-check PORT HASH_HEX|ca [--host H]               WebSocket-over-TLS client ping
//!   acme / acme-info                                   Let's Encrypt IP certificates (acme.rs)

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use futures_util::{SinkExt, StreamExt};
use quinn::crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms, ring};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tracing::{info, warn};
use wtransport::endpoint::IncomingSessionFuture;

mod acme;

const ALPN_NATIVE: &[u8] = b"hx/1";
const ALPN_H3: &[u8] = b"h3";
const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
const FRAME_HEADER: usize = 24;
const INDEX_HTML: &str = include_str!("../web/index.html");

fn now_us() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0)
}

// ---------------------------------------------------------------- certificates

struct Identity {
    chain: Vec<CertificateDer<'static>>,
    key_der: Vec<u8>,
    sha256: [u8; 32],
}

/// Self-signed ECDSA P-256 certificate, valid 13 days, as required for `serverCertificateHashes`.
fn make_identity() -> Result<Identity> {
    use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ECDSA_P256_SHA256, SanType};
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, "hash-xcreen spike s5");
    params.subject_alt_names = vec![
        SanType::DnsName("localhost".try_into()?),
        SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        SanType::IpAddress(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
    ];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::minutes(5);
    params.not_after = now + time::Duration::days(13);
    let cert = params.self_signed(&key)?;
    let der = cert.der().clone();
    let sha256: [u8; 32] = Sha256::digest(der.as_ref()).into();
    Ok(Identity { chain: vec![der], key_der: key.serialize_der(), sha256 })
}

/// Load a CA-issued certificate chain and PKCS#8 key from PEM files (public mode).
fn load_identity(cert_path: &str, key_path: &str) -> Result<Identity> {
    use rustls::pki_types::pem::PemObject;
    let chain = CertificateDer::pem_file_iter(cert_path)?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(key_path)?;
    let PrivateKeyDer::Pkcs8(pk) = key else { bail!("expected a PKCS#8 key") };
    let sha256: [u8; 32] = Sha256::digest(chain.first().context("empty chain")?.as_ref()).into();
    Ok(Identity { chain, key_der: pk.secret_pkcs8_der().to_vec(), sha256 })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        bail!("odd-length hex");
    }
    (0..s.len()).step_by(2).map(|i| Ok(u8::from_str_radix(&s[i..i + 2], 16)?)).collect()
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

fn server_tls(id: &Identity, alpn: &[&[u8]]) -> Result<rustls::ServerConfig> {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(id.key_der.clone()));
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(id.chain.clone(), key)?;
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    Ok(cfg)
}

/// Client-side verifier that pins the SHA-256 of the leaf certificate (what the browser does
/// with `serverCertificateHashes`).
#[derive(Debug)]
struct PinVerifier {
    hash: Vec<u8>,
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if Sha256::digest(end_entity.as_ref()).as_slice() == self.hash.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("certificate hash mismatch".into()))
        }
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.algs)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.algs)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algs.supported_schemes()
    }
}

fn client_tls(hash_hex: &str, alpn: &[&[u8]]) -> Result<rustls::ClientConfig> {
    let p = provider();
    if hash_hex == "ca" {
        // Normal WebPKI validation against the Mozilla root set (no pinning).
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned());
        let mut cfg = rustls::ClientConfig::builder_with_provider(p)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
        return Ok(cfg);
    }
    let verifier = PinVerifier { hash: unhex(hash_hex)?, algs: p.signature_verification_algorithms };
    let mut cfg = rustls::ClientConfig::builder_with_provider(p)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    Ok(cfg)
}

// ---------------------------------------------------------------- UDP: one quinn endpoint

fn quinn_server(id: &Identity, addr: SocketAddr) -> Result<quinn::Endpoint> {
    // Both ALPNs are offered on the same endpoint; the accept loop dispatches on the result.
    let tls = server_tls(id, &[ALPN_H3, ALPN_NATIVE])?;
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_uni_streams(2048u32.into());
    transport.max_concurrent_bidi_streams(128u32.into());
    transport.keep_alive_interval(Some(Duration::from_secs(5)));
    cfg.transport_config(Arc::new(transport));
    Ok(quinn::Endpoint::server(cfg, addr)?)
}

async fn accept_loop(endpoint: quinn::Endpoint, report_path: Arc<Option<String>>) {
    while let Some(incoming) = endpoint.accept().await {
        let report_path = report_path.clone();
        tokio::spawn(async move {
            if let Err(e) = dispatch(incoming, report_path).await {
                warn!("connection ended with error: {e:#}");
            }
        });
    }
}

/// ALPN dispatch: the handshake data is available before the handshake completes.
async fn dispatch(incoming: quinn::Incoming, _report: Arc<Option<String>>) -> Result<()> {
    let mut connecting = incoming.accept()?;
    let hd = connecting.handshake_data().await?;
    let hd = hd.downcast::<HandshakeData>().map_err(|_| anyhow::anyhow!("not rustls"))?;
    let alpn = hd.protocol.clone().unwrap_or_default();
    match alpn.as_slice() {
        ALPN_H3 => {
            let req = IncomingSessionFuture::with_quic_connecting(connecting).await?;
            info!(path = req.path(), origin = ?req.origin(), ua = ?req.user_agent(), "WebTransport session request");
            if req.path() != "/wt" {
                req.not_found().await;
                return Ok(());
            }
            let conn = req.accept().await?;
            webtransport_session(conn).await
        }
        ALPN_NATIVE => {
            let conn = connecting.await?;
            info!(remote = %conn.remote_address(), "native hx/1 connection");
            native_session(conn).await
        }
        other => bail!("unexpected ALPN {:?}", String::from_utf8_lossy(other)),
    }
}

/// Trivial native protocol: bidirectional stream echo with a `pong:` prefix, datagram echo.
async fn native_session(conn: quinn::Connection) -> Result<()> {
    let dg = conn.clone();
    tokio::spawn(async move {
        while let Ok(d) = dg.read_datagram().await {
            let _ = dg.send_datagram(d);
        }
    });
    loop {
        let (mut tx, mut rx) = match conn.accept_bi().await {
            Ok(s) => s,
            Err(_) => return Ok(()),
        };
        let data = rx.read_to_end(64 * 1024).await?;
        let mut out = b"pong:".to_vec();
        out.extend_from_slice(&data);
        tx.write_all(&out).await?;
        tx.finish()?;
    }
}

/// WebTransport session: echo every client uni stream back on a fresh server uni stream
/// (one frame per stream), and echo datagrams.
async fn webtransport_session(conn: wtransport::Connection) -> Result<()> {
    info!(max_datagram = ?conn.max_datagram_size(), "WebTransport session accepted");
    let dconn = conn.clone();
    tokio::spawn(async move {
        while let Ok(d) = dconn.receive_datagram().await {
            let _ = dconn.send_datagram(d.payload());
        }
    });
    loop {
        let mut rx = match conn.accept_uni().await {
            Ok(r) => r,
            Err(e) => {
                info!("session closed: {e}");
                return Ok(());
            }
        };
        let conn = conn.clone();
        tokio::spawn(async move {
            if let Err(e) = echo_frame(&conn, &mut rx).await {
                warn!("frame echo failed: {e:#}");
            }
        });
    }
}

async fn echo_frame(conn: &wtransport::Connection, rx: &mut wtransport::RecvStream) -> Result<()> {
    let mut buf = Vec::with_capacity(64 * 1024);
    let mut chunk = vec![0u8; 64 * 1024];
    while let Some(n) = rx.read(&mut chunk).await? {
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_FRAME_BYTES {
            bail!("frame too large");
        }
    }
    if buf.len() < FRAME_HEADER {
        bail!("short frame header");
    }
    // Header: u32 idx | u32 flags | u64 client_ts_us | u64 server_ts_us (filled in here).
    buf[16..24].copy_from_slice(&now_us().to_le_bytes());
    let mut tx = conn.open_uni().await?.await?;
    tx.write_all(&buf).await?;
    tx.finish().await?;
    Ok(())
}

// ---------------------------------------------------------------- TCP: page, report, WebSocket

async fn http_server(
    addr: SocketAddr,
    tls: Option<Arc<rustls::ServerConfig>>,
    info_json: String,
    report: Arc<Option<String>>,
) -> Result<()> {
    let l = TcpListener::bind(addr).await?;
    let acceptor = tls.map(tokio_rustls::TlsAcceptor::from);
    info!("page server on {}://{addr}/", if acceptor.is_some() { "https" } else { "http" });
    loop {
        let (tcp, _) = l.accept().await?;
        let info_json = info_json.clone();
        let report = report.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let res = async {
                match acceptor {
                    Some(a) => {
                        let mut s = tokio::time::timeout(Duration::from_secs(10), a.accept(tcp)).await??;
                        http_conn(&mut s, &info_json, &report).await
                    }
                    None => {
                        let mut tcp = tcp;
                        http_conn(&mut tcp, &info_json, &report).await
                    }
                }
            }
            .await;
            if let Err(e) = res {
                warn!("http error: {e:#}");
            }
        });
    }
}

async fn http_conn<S: AsyncReadExt + AsyncWriteExt + Unpin>(s: &mut S, info_json: &str, report: &Option<String>) -> Result<()> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let head_end = loop {
        let n = tokio::time::timeout(Duration::from_secs(10), s.read(&mut tmp)).await??;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        if buf.len() > 64 * 1024 {
            bail!("header too large");
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.lines();
    let mut first = lines.next().unwrap_or("").split(' ');
    let method = first.next().unwrap_or("");
    let path = first.next().unwrap_or("").split('?').next().unwrap_or("");
    let clen: usize = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0);
    let (status, ctype, body): (&str, &str, Vec<u8>) = match (method, path) {
        ("GET", "/") => ("200 OK", "text/html; charset=utf-8", INDEX_HTML.as_bytes().to_vec()),
        ("GET", "/info") => ("200 OK", "application/json", info_json.as_bytes().to_vec()),
        ("POST", "/report") => {
            if clen > 4 * 1024 * 1024 {
                bail!("report too large");
            }
            while buf.len() < head_end + clen {
                let n = s.read(&mut tmp).await?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            let body = String::from_utf8_lossy(&buf[head_end..]).to_string();
            info!("BROWSER REPORT {body}");
            if let Some(p) = report {
                std::fs::write(p, &body)?;
            }
            ("200 OK", "text/plain", b"ok".to_vec())
        }
        ("POST", "/log") => {
            while buf.len() < head_end + clen {
                let n = s.read(&mut tmp).await?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            info!("BROWSER LOG {}", String::from_utf8_lossy(&buf[head_end..]));
            ("200 OK", "text/plain", b"ok".to_vec())
        }
        _ => ("404 Not Found", "text/plain", b"not found".to_vec()),
    };
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(resp.as_bytes()).await?;
    s.write_all(&body).await?;
    s.shutdown().await.ok();
    Ok(())
}

/// WebSocket over TLS on TCP, same port number as the UDP endpoint.
async fn ws_server(id: &Identity, addr: SocketAddr) -> Result<()> {
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls(id, &[b"http/1.1"])?));
    let l = TcpListener::bind(addr).await?;
    info!("WebSocket-over-TLS on tcp://{addr}");
    loop {
        let (tcp, peer) = l.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let res: Result<()> = async {
                let tls = acceptor.accept(tcp).await?;
                let mut ws = tokio_tungstenite::accept_async(tls).await?;
                info!(%peer, "websocket connected");
                while let Some(m) = ws.next().await {
                    match m? {
                        m @ (Message::Text(_) | Message::Binary(_)) => ws.send(m).await?,
                        Message::Close(_) => break,
                        _ => {}
                    }
                }
                Ok(())
            }
            .await;
            if let Err(e) = res {
                warn!("ws error: {e:#}");
            }
        });
    }
}

// ---------------------------------------------------------------- client checks

/// Resolve `--host` (default `localhost`) to a socket address plus the TLS server name.
fn target(host: &str, port: u16) -> Result<(SocketAddr, ServerName<'static>)> {
    let ip: IpAddr = if host == "localhost" { Ipv4Addr::LOCALHOST.into() } else { host.parse()? };
    let name = if host == "localhost" { ServerName::try_from("localhost")? } else { ServerName::IpAddress(ip.into()) };
    Ok((SocketAddr::new(ip, port), name))
}

async fn native_check(port: u16, hash: &str, host: &str) -> Result<()> {
    let tls = client_tls(hash, &[ALPN_NATIVE])?;
    let (addr, name) = target(host, port)?;
    let bind: SocketAddr = if addr.is_ipv6() { (std::net::Ipv6Addr::UNSPECIFIED, 0).into() } else { (Ipv4Addr::UNSPECIFIED, 0).into() };
    let mut ep = quinn::Endpoint::client(bind)?;
    ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?)));
    let t0 = std::time::Instant::now();
    let name_str = match &name {
        ServerName::IpAddress(ip) => std::net::IpAddr::from(*ip).to_string(),
        other => other.to_str().to_string(),
    };
    let conn = ep.connect(addr, &name_str)?.await?;
    println!("native hx/1 connect (QUIC handshake): {} ms", t0.elapsed().as_millis());
    let (mut tx, mut rx) = conn.open_bi().await?;
    tx.write_all(b"ping").await?;
    tx.finish()?;
    let reply = rx.read_to_end(1024).await?;
    println!("native hx/1 stream reply: {}", String::from_utf8_lossy(&reply));
    let mut rtts = Vec::new();
    for _ in 0..20 {
        let t = std::time::Instant::now();
        conn.send_datagram(bytes_of(b"dgram"))?;
        let d = tokio::time::timeout(Duration::from_secs(3), conn.read_datagram()).await??;
        assert_eq!(&d[..], b"dgram");
        rtts.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    rtts.sort_by(|a, b| a.total_cmp(b));
    println!("native hx/1 datagram echo OK x20: rtt min {:.1} median {:.1} max {:.1} ms", rtts[0], rtts[10], rtts[19]);
    println!("negotiated ALPN: hx/1 (client offered only hx/1)");
    conn.close(0u32.into(), b"done");
    ep.wait_idle().await;
    Ok(())
}

fn bytes_of(b: &[u8]) -> bytes::Bytes {
    bytes::Bytes::copy_from_slice(b)
}

async fn ws_check(port: u16, hash: &str, host: &str) -> Result<()> {
    let tls = Arc::new(client_tls(hash, &[b"http/1.1"])?);
    let (addr, name) = target(host, port)?;
    let t0 = std::time::Instant::now();
    let tcp = TcpStream::connect(addr).await?;
    let tls = tokio_rustls::TlsConnector::from(tls).connect(name, tcp).await?;
    let url_host = if addr.is_ipv6() { format!("[{}]", addr.ip()) } else { addr.ip().to_string() };
    let (mut ws, _) = tokio_tungstenite::client_async(format!("wss://{url_host}:{port}/ws"), tls).await?;
    println!("websocket-over-TLS connect (TCP+TLS+upgrade): {} ms", t0.elapsed().as_millis());
    let t1 = std::time::Instant::now();
    ws.send(Message::text("ping")).await?;
    let reply = ws.next().await.context("no reply")??;
    println!("websocket-over-TLS echo: {reply} (rtt {} ms)", t1.elapsed().as_millis());
    ws.close(None).await.ok();
    Ok(())
}

// ---------------------------------------------------------------- main

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("acme") => acme::run_acme(&args).await,
        Some("acme-info") => acme::run_info(&args).await,
        Some("native-check") => {
            let host = arg(&args, "--host").unwrap_or_else(|| "localhost".into());
            native_check(args.get(1).context("PORT")?.parse()?, args.get(2).context("HASH")?, &host).await
        }
        Some("ws-check") => {
            let host = arg(&args, "--host").unwrap_or_else(|| "localhost".into());
            ws_check(args.get(1).context("PORT")?.parse()?, args.get(2).context("HASH")?, &host).await
        }
        Some("serve") => {
            let port: u16 = arg(&args, "--port").map(|p| p.parse()).transpose()?.unwrap_or(4433);
            let http_port: u16 = arg(&args, "--http-port").map(|p| p.parse()).transpose()?.unwrap_or(8080);
            let report = Arc::new(arg(&args, "--report"));
            // Public mode: CA certificate from PEM files, HTTPS page, bind address from --bind
            // ("::" is dual-stack on Linux). Local mode: self-signed, page on loopback HTTP.
            let public = arg(&args, "--cert").zip(arg(&args, "--key"));
            let (id, bind_ip, page_tls) = match &public {
                Some((c, k)) => {
                    let id = load_identity(c, k)?;
                    let ip: IpAddr = arg(&args, "--bind").unwrap_or_else(|| "::".into()).parse()?;
                    let tls = Arc::new(server_tls(&id, &[b"http/1.1"])?);
                    (id, ip, Some(tls))
                }
                None => (make_identity()?, Ipv4Addr::UNSPECIFIED.into(), None),
            };
            let hash = hex(&id.sha256);
            println!("CERT_SHA256={hash}");
            let endpoint = quinn_server(&id, SocketAddr::new(bind_ip, port))?;
            let local = endpoint.local_addr()?;
            info!("QUIC endpoint (h3 + hx/1) on udp://{local}");
            let info_json = format!("{{\"udpPort\":{},\"hash\":\"{hash}\",\"public\":{}}}", local.port(), public.is_some());
            let page_addr = match page_tls {
                Some(_) => SocketAddr::new(bind_ip, arg(&args, "--https-port").map(|p| p.parse()).transpose()?.unwrap_or(443)),
                None => SocketAddr::from((Ipv4Addr::LOCALHOST, http_port)),
            };
            tokio::spawn(accept_loop(endpoint, report.clone()));
            tokio::spawn(async move {
                if let Err(e) = http_server(page_addr, page_tls, info_json, report).await {
                    warn!("page server stopped: {e:#}");
                }
            });
            let ws_port: u16 = arg(&args, "--ws-port").map(|p| p.parse()).transpose()?.unwrap_or(local.port());
            ws_server(&id, SocketAddr::new(bind_ip, ws_port)).await
        }
        _ => bail!("usage: serve | native-check PORT HASH | ws-check PORT HASH"),
    }
}
