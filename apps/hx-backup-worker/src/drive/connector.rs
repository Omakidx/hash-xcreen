//! The helper's connections to Google: TCP, then TLS 1.3 (`rustls`, `ring`), nothing else.
//!
//! A hand-written connector for `hyper-util`'s pooled client instead of `reqwest`, because
//! `reqwest`'s rustls stack turns on `rustls`'s `tls12` feature (which `deny.toml` bans: the wire
//! protocols here are TLS 1.3 only) and brings a certificate bundle under a licence outside the
//! allowlist. The client built on this connector has no redirect following, no proxy support and
//! no HTTP/2 to begin with.
//!
//! Every connection is checked again here, whatever the caller did: only `https` to
//! `www.googleapis.com` or `oauth2.googleapis.com` on the default port, resolved by this module to
//! global unicast addresses only (the unit's `IPAddressDeny` is the second layer).

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use super::transport::{check_uri, is_global_unicast};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// How the client is built. Production uses [`HttpConfig::default`]; the tests of this package
/// (feature `test-hooks`) add a root and an address override.
#[derive(Debug, Clone, Default)]
pub struct HttpConfig {
    /// PEM of additional trusted roots (tests).
    #[cfg(feature = "test-hooks")]
    pub extra_roots_pem: Option<Vec<u8>>,
    /// Send requests for either Google host to this `host:port` (tests); the host check runs first.
    #[cfg(feature = "test-hooks")]
    pub api_addr: Option<String>,
}

/// The client could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("cannot build the HTTP client: {0}")]
pub struct BuildError(pub &'static str);

fn tls_config(cfg: &HttpConfig) -> Result<rustls::ClientConfig, BuildError> {
    let mut roots = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    roots.add_parsable_certificates(native.certs);
    #[cfg(feature = "test-hooks")]
    if let Some(pem) = &cfg.extra_roots_pem {
        use rustls::pki_types::{CertificateDer, pem::PemObject};
        for der in CertificateDer::pem_slice_iter(pem) {
            let der = der.map_err(|_| BuildError("test root is not PEM"))?;
            roots
                .add(der)
                .map_err(|_| BuildError("test root is not a certificate"))?;
        }
    }
    #[cfg(not(feature = "test-hooks"))]
    let _ = cfg;
    if roots.is_empty() {
        return Err(BuildError("no trusted root certificates"));
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| BuildError("TLS 1.3 is unavailable"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// The connector service of the pooled client.
#[derive(Clone)]
pub struct Connector {
    tls: TlsConnector,
    connect_timeout: Duration,
    #[cfg(feature = "test-hooks")]
    addr: Option<SocketAddr>,
}

/// Alternates the address families, so that a blackholed one (typically IPv6 on a host with no
/// route for it) costs one short connect timeout, not all of them.
#[must_use]
pub fn interleave(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let (mut v6, mut v4): (Vec<_>, Vec<_>) = addrs.into_iter().partition(SocketAddr::is_ipv6);
    let mut out = Vec::with_capacity(v4.len() + v6.len());
    v4.reverse();
    v6.reverse();
    while !v4.is_empty() || !v6.is_empty() {
        out.extend(v6.pop());
        out.extend(v4.pop());
    }
    out
}

impl Connector {
    /// # Errors
    /// [`BuildError`] when TLS cannot be set up (for example no root certificates).
    pub fn new(cfg: &HttpConfig, connect_timeout: Duration) -> Result<Self, BuildError> {
        #[cfg(feature = "test-hooks")]
        let addr = match &cfg.api_addr {
            Some(a) => Some(
                a.parse::<SocketAddr>()
                    .map_err(|_| BuildError("test address"))?,
            ),
            None => None,
        };
        Ok(Self {
            tls: TlsConnector::from(Arc::new(tls_config(cfg)?)),
            connect_timeout,
            #[cfg(feature = "test-hooks")]
            addr,
        })
    }

    async fn addresses(&self, uri: &http::Uri) -> Result<Vec<SocketAddr>, BoxError> {
        #[cfg(feature = "test-hooks")]
        if let Some(a) = self.addr {
            return Ok(vec![a]);
        }
        check_uri(uri)?;
        let host = uri.host().ok_or("no host")?;
        let found: Vec<SocketAddr> = tokio::net::lookup_host((host, 443))
            .await?
            .filter(|a| is_global_unicast(a.ip()))
            .collect();
        if found.is_empty() {
            return Err("no global address".into());
        }
        Ok(interleave(found))
    }

    async fn connect(&self, uri: http::Uri) -> Result<Conn, BoxError> {
        let addrs = self.addresses(&uri).await?;
        let name = ServerName::try_from(uri.host().ok_or("no host")?.to_owned())?;
        self.dial(addrs, name).await
    }

    /// Tries the addresses in turn, each with the per-address bound, TCP and TLS both.
    async fn dial(
        &self,
        addrs: Vec<SocketAddr>,
        name: ServerName<'static>,
    ) -> Result<Conn, BoxError> {
        let mut last: Option<io::Error> = None;
        for addr in addrs {
            match tokio::time::timeout(self.connect_timeout, TcpStream::connect(addr)).await {
                Ok(Ok(tcp)) => {
                    let _ = tcp.set_nodelay(true);
                    // A handshake that fails or stalls is a reason to try the next address too.
                    match tokio::time::timeout(
                        self.connect_timeout,
                        self.tls.connect(name.clone(), tcp),
                    )
                    .await
                    {
                        Ok(Ok(tls)) => return Ok(Conn(TokioIo::new(tls))),
                        Ok(Err(e)) => last = Some(e),
                        Err(_) => last = Some(io::ErrorKind::TimedOut.into()),
                    }
                }
                Ok(Err(e)) => last = Some(e),
                Err(_) => last = Some(io::ErrorKind::TimedOut.into()),
            }
        }
        Err(last
            .unwrap_or_else(|| io::ErrorKind::NotFound.into())
            .into())
    }
}

impl tower_service::Service<http::Uri> for Connector {
    type Response = Conn;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Conn, BoxError>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: http::Uri) -> Self::Future {
        let this = self.clone();
        Box::pin(async move { this.connect(uri).await })
    }
}

/// A TLS connection to Google.
pub struct Conn(TokioIo<TlsStream<TcpStream>>);

impl Read for Conn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl Write for Conn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl Connection for Conn {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn families_alternate_so_one_dead_family_costs_one_timeout() {
        let a = |s: &str| s.parse::<SocketAddr>().unwrap();
        let got = interleave(vec![
            a("[2001:db8::1]:443"),
            a("[2001:db8::2]:443"),
            a("1.1.1.1:443"),
            a("1.1.1.2:443"),
            a("1.1.1.3:443"),
        ]);
        let fam: Vec<bool> = got.iter().map(SocketAddr::is_ipv6).collect();
        assert_eq!(fam, [true, false, true, false, false]);
        assert_eq!(got.len(), 5);
        assert!(interleave(vec![]).is_empty());
    }

    #[tokio::test]
    async fn a_failed_handshake_on_one_address_moves_on_to_the_next() {
        use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
        use tokio::io::AsyncWriteExt;

        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names = vec![rcgen::SanType::IpAddress(
            std::net::Ipv4Addr::LOCALHOST.into(),
        )];
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let der: CertificateDer<'static> = cert.der().clone();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![der.clone()],
                PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        // the first address accepts and talks garbage (a failed handshake), the second is right
        let bad = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (bad_addr, good_addr) = (bad.local_addr().unwrap(), good.local_addr().unwrap());
        tokio::spawn(async move {
            loop {
                if let Ok((mut c, _)) = bad.accept().await {
                    let _ = c.write_all(b"not tls at all\r\n").await;
                }
            }
        });
        tokio::spawn(async move {
            loop {
                if let Ok((c, _)) = good.accept().await {
                    let a = acceptor.clone();
                    tokio::spawn(async move {
                        let _ = a.accept(c).await;
                    });
                }
            }
        });
        let cfg = HttpConfig {
            extra_roots_pem: Some(rcgen_pem(&der)),
            api_addr: None,
        };
        let conn = Connector::new(&cfg, Duration::from_secs(5)).unwrap();
        let name = ServerName::try_from("127.0.0.1".to_owned()).unwrap();
        assert!(conn.dial(vec![bad_addr, good_addr], name).await.is_ok());
    }

    fn rcgen_pem(der: &rustls::pki_types::CertificateDer<'_>) -> Vec<u8> {
        use std::fmt::Write;
        let b64: String = {
            const T: &[u8; 64] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut o = String::new();
            for c in der.as_ref().chunks(3) {
                let n = (u32::from(c[0]) << 16)
                    | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
                    | u32::from(*c.get(2).unwrap_or(&0));
                for i in 0..4 {
                    o.push(if i <= c.len() {
                        char::from(T[((n >> (18 - 6 * i)) & 63) as usize])
                    } else {
                        '='
                    });
                }
            }
            o
        };
        let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
        for l in b64.as_bytes().chunks(64) {
            let _ = writeln!(out, "{}", std::str::from_utf8(l).unwrap());
        }
        out.push_str("-----END CERTIFICATE-----\n");
        out.into_bytes()
    }
}
