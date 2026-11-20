//! Test fixtures: a self-signed certificate generated at test time, a test-only certificate
//! verifier that accepts it, and helpers to bring up a connected pair over either transport.
//! Nothing here is shipped: the insecure verifier lives only in the test tree.

#![allow(dead_code)]

use std::{sync::Arc, time::Duration};

use hx_proto::{
    VideoCodec,
    pb::Intent,
    version::{Features, capabilities},
};
use hx_transport::{
    Client, ClientHello, ClientOptions, Connection, Server, ServerHello, ServerOptions, Target,
    TransportPreference,
};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, ring},
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
};

pub const WAIT: Duration = Duration::from_secs(10);

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

/// A fresh self-signed certificate for `localhost` and its PKCS#8 key.
pub fn self_signed() -> (CertificateDer<'static>, PrivatePkcs8KeyDer<'static>) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate certificate");
    (
        ck.cert.der().clone(),
        PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()),
    )
}

pub fn server_tls() -> Arc<rustls::ServerConfig> {
    let (cert, key) = self_signed();
    let cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .expect("server certificate");
    Arc::new(cfg)
}

/// Test-only verifier: accepts any server certificate.
#[derive(Debug)]
pub struct AcceptAnyServer(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAnyServer {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

pub fn client_tls() -> Arc<rustls::ClientConfig> {
    let p = provider();
    let cfg = rustls::ClientConfig::builder_with_provider(p.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServer(p)))
        .with_no_client_auth();
    Arc::new(cfg)
}

pub fn all_features() -> Features {
    Features::AUDIO
        .union(Features::CLIPBOARD)
        .union(Features::FILE_TRANSFER)
}

pub fn client_hello() -> ClientHello {
    ClientHello {
        capabilities: capabilities(&[VideoCodec::H264], all_features()),
        intent: Intent::Session,
        software: "hx-test-client 0.0".into(),
        device_name: "test device".into(),
    }
}

pub fn server_hello() -> ServerHello {
    ServerHello {
        capabilities: capabilities(&[VideoCodec::Av1, VideoCodec::H264], all_features()),
        software: "hx-test-server 0.0".into(),
    }
}

pub async fn start_server(opts: ServerOptions) -> Arc<Server> {
    Arc::new(
        Server::bind("127.0.0.1:0".parse().expect("addr"), server_tls(), opts)
            .await
            .expect("bind"),
    )
}

pub fn target(server: &Server, pref: TransportPreference) -> Target {
    let addr = match pref {
        TransportPreference::WebSocket => server.websocket_addr().expect("ws"),
        _ => server.quic_addr().expect("quic"),
    };
    Target {
        addr,
        server_name: ServerName::try_from("localhost").expect("name"),
    }
}

pub fn client(pref: TransportPreference) -> Client {
    Client::new(
        client_tls(),
        ClientOptions {
            preference: pref,
            ..Default::default()
        },
    )
}

pub struct Pair {
    pub server: Arc<Server>,
    pub client: Connection,
    pub srv: Connection,
}

/// Bring up a server and one connected client over `pref`. The server accepts with the given
/// reply and, if `authorize` is set, authorizes the connection with every feature.
pub async fn pair_full(
    pref: TransportPreference,
    opts: ServerOptions,
    server_hello: ServerHello,
    client_hello: ClientHello,
    authorize: bool,
) -> Pair {
    let server = start_server(opts).await;
    let s2 = server.clone();
    let accept = tokio::spawn(async move {
        let pending = s2.accept().await.expect("pending session");
        let c = pending.accept(server_hello).await?;
        if authorize {
            c.authorize(all_features())?;
        }
        Ok::<_, hx_transport::Error>(c)
    });
    let c = client(pref)
        .connect(&target(&server, pref), &client_hello)
        .await
        .expect("client connects");
    let srv = tokio::time::timeout(WAIT, accept)
        .await
        .expect("accept in time")
        .expect("join")
        .expect("server accepts");
    Pair {
        server,
        client: c,
        srv,
    }
}

pub async fn pair_with(
    pref: TransportPreference,
    server_hello: ServerHello,
    client_hello: ClientHello,
) -> Pair {
    pair_full(
        pref,
        ServerOptions::default(),
        server_hello,
        client_hello,
        true,
    )
    .await
}

pub async fn pair(pref: TransportPreference) -> Pair {
    pair_with(pref, server_hello(), client_hello()).await
}

/// Raw QUIC client (no `hx-transport` handshake logic) with the given ALPN, for protocol-level
/// negative tests.
pub async fn raw_quic(
    addr: std::net::SocketAddr,
    alpn: &[u8],
) -> Result<(quinn::Endpoint, quinn::Connection), String> {
    let mut tls = (*client_tls()).clone();
    tls.alpn_protocols = vec![alpn.to_vec()];
    let q = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|e| e.to_string())?;
    let mut ep =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("addr")).map_err(|e| e.to_string())?;
    ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(q)));
    let conn = ep
        .connect(addr, "localhost")
        .map_err(|e| e.to_string())?
        .await
        .map_err(|e| e.to_string())?;
    Ok((ep, conn))
}
