//! Pinned-key TLS over the real transports: both QUIC and WebSocket.

use std::{sync::Arc, time::Duration};

use hx_crypto::{IdentityKey, tls};
use hx_proto::{
    VideoCodec,
    pb::Intent,
    version::{Features, capabilities},
};
use hx_transport::{
    Client, ClientHello, ClientOptions, Server, ServerHello, ServerOptions, Target,
    TransportPreference,
};
use rustls::pki_types::ServerName;

const WAIT: Duration = Duration::from_secs(10);
const BOTH: [TransportPreference; 2] = [TransportPreference::Quic, TransportPreference::WebSocket];

fn key() -> Arc<IdentityKey> {
    Arc::new(IdentityKey::generate().expect("key"))
}

fn hello() -> ClientHello {
    ClientHello {
        capabilities: capabilities(&[VideoCodec::H264], Features::NONE),
        intent: Intent::Session,
        software: "test".into(),
        device_name: "dev".into(),
    }
}

async fn server(identity: &Arc<IdentityKey>) -> Arc<Server> {
    Arc::new(
        Server::bind(
            "127.0.0.1:0".parse().expect("addr"),
            tls::server_config(identity).expect("server tls"),
            ServerOptions::default(),
        )
        .await
        .expect("bind"),
    )
}

fn target(s: &Server, pref: TransportPreference) -> Target {
    let addr = if pref == TransportPreference::WebSocket {
        s.websocket_addr().expect("ws addr")
    } else {
        s.quic_addr().expect("quic addr")
    };
    Target {
        addr,
        server_name: ServerName::try_from("hx.invalid").expect("name"),
    }
}

fn client(cfg: Arc<rustls::ClientConfig>, pref: TransportPreference) -> Client {
    Client::new(
        cfg,
        ClientOptions {
            preference: pref,
            ..Default::default()
        },
    )
}

fn reply() -> ServerHello {
    ServerHello {
        capabilities: capabilities(&[VideoCodec::H264], Features::NONE),
        software: "test".into(),
    }
}

#[tokio::test]
async fn pinned_mutual_tls_connects_and_exposes_both_keys() {
    for pref in BOTH {
        let (srv_key, dev_key) = (key(), key());
        let s = server(&srv_key).await;
        let s2 = s.clone();
        let accept = tokio::spawn(async move {
            let p = s2.accept().await.expect("pending");
            let seen = tls::peer_key(p.peer_certificates()).expect("client key");
            let c = p.accept(reply()).await.expect("accept");
            (seen, c)
        });
        let cfg = tls::client_config_session(&dev_key, srv_key.public()).expect("cfg");
        let conn =
            tokio::time::timeout(WAIT, client(cfg, pref).connect(&target(&s, pref), &hello()))
                .await
                .expect("in time")
                .expect("connects");
        let (seen, _srv_conn) = tokio::time::timeout(WAIT, accept)
            .await
            .expect("in time")
            .expect("join");
        assert_eq!(seen, dev_key.public(), "{pref:?}");
        assert_eq!(
            tls::peer_key(conn.peer_certificates()).expect("server key"),
            srv_key.public(),
            "{pref:?}"
        );
    }
}

#[tokio::test]
async fn wrong_pinned_server_key_fails_closed() {
    for pref in BOTH {
        let (srv_key, dev_key, other) = (key(), key(), key());
        let s = server(&srv_key).await;
        let cfg = tls::client_config_session(&dev_key, other.public()).expect("cfg");
        let r = tokio::time::timeout(WAIT, client(cfg, pref).connect(&target(&s, pref), &hello()))
            .await
            .expect("in time");
        assert!(
            r.is_err(),
            "{pref:?}: a server with another key must be rejected"
        );
        // The server never produced a pending session for it.
        assert!(
            tokio::time::timeout(Duration::from_millis(300), s.accept())
                .await
                .is_err(),
            "{pref:?}"
        );
    }
}

#[tokio::test]
async fn pairing_config_takes_any_server_key_and_reports_it() {
    for pref in BOTH {
        let (srv_key, dev_key) = (key(), key());
        let s = server(&srv_key).await;
        let s2 = s.clone();
        let accept = tokio::spawn(async move {
            let p = s2.accept().await.expect("pending");
            p.accept(reply()).await.expect("accept")
        });
        let cfg = tls::client_config_pairing(&dev_key).expect("cfg");
        let conn =
            tokio::time::timeout(WAIT, client(cfg, pref).connect(&target(&s, pref), &hello()))
                .await
                .expect("in time")
                .expect("connects");
        let _srv = accept.await.expect("join");
        assert_eq!(
            tls::peer_key(conn.peer_certificates()).expect("key"),
            srv_key.public()
        );
    }
}

#[tokio::test]
async fn x509_clients_and_servers_are_not_accepted() {
    // A client with an ordinary certificate (no raw public keys) cannot connect.
    for pref in BOTH {
        let srv_key = key();
        let s = server(&srv_key).await;
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("cert");
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("tls13")
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_client_auth_cert(
                vec![ck.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()).into(),
            )
            .expect("client cert");
        let r = tokio::time::timeout(
            WAIT,
            client(Arc::new(cfg), pref).connect(&target(&s, pref), &hello()),
        )
        .await
        .expect("in time");
        assert!(r.is_err(), "{pref:?}");
    }
}

#[tokio::test]
async fn a_client_without_a_key_is_rejected_by_the_server() {
    // Server requires client authentication: a client that offers none fails in TLS.
    for pref in BOTH {
        let srv_key = key();
        let s = server(&srv_key).await;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("tls13")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyRpk(provider)))
            .with_no_client_auth();
        let r = tokio::time::timeout(
            WAIT,
            client(Arc::new(cfg), pref).connect(&target(&s, pref), &hello()),
        )
        .await
        .expect("in time");
        assert!(r.is_err(), "{pref:?}");
    }
}

/// Test-only verifier that accepts any raw public key (to isolate the server's own checks).
#[derive(Debug)]
struct AcceptAnyRpk(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptAnyRpk {
    fn verify_server_cert(
        &self,
        _e: &rustls::pki_types::CertificateDer<'_>,
        _i: &[rustls::pki_types::CertificateDer<'_>],
        _n: &ServerName<'_>,
        _o: &[u8],
        _t: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("no".into()))
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature_with_raw_key(
            m,
            &rustls::pki_types::SubjectPublicKeyInfoDer::from(c.as_ref()),
            d,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}
