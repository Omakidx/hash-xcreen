//! Pinned-key mutual TLS 1.3 with raw public keys (RFC 7250), no certificate authority
//! (protocol §11.1).
//!
//! The "certificate" on the wire is the 44-byte Ed25519 `SubjectPublicKeyInfo`. Three
//! verifier behaviours exist, all strict (TLS 1.3, `ED25519` only, signature checked, one
//! well-formed key, nothing else) and all failing closed:
//!
//! * [`server_config`]: requires a client key and accepts **any** valid one (the application
//!   decides pairing versus session from the key afterwards);
//! * [`client_config_session`]: accepts exactly the pinned server key;
//! * [`client_config_pairing`]: accepts any valid server key provisionally; the key is
//!   authenticated by the SPAKE2 confirmation, never by TLS.

use std::sync::Arc;

use rustls::{
    DigitallySignedStruct, DistinguishedName, SignatureAlgorithm, SignatureScheme,
    client::{
        ResolvesClientCert,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::{
        CryptoProvider, WebPkiSupportedAlgorithms, ring, verify_tls13_signature_with_raw_key,
    },
    pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime},
    server::{
        ResolvesServerCert,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
    sign::{CertifiedKey, Signer, SigningKey},
};

use crate::{
    error::{Error, Result},
    keys::{IdentityKey, PublicKey},
};

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

fn tls_err(e: rustls::Error) -> Error {
    Error::Tls(e.to_string())
}

/// The one signature scheme in use.
const SCHEME: SignatureScheme = SignatureScheme::ED25519;

// ------------------------------------------------------------------ signing side

/// An [`IdentityKey`] as a rustls signing key. The secret stays inside `IdentityKey`.
struct RpkSigningKey(Arc<IdentityKey>);

impl std::fmt::Debug for RpkSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RpkSigningKey([redacted])")
    }
}

struct RpkSigner(Arc<IdentityKey>);

impl std::fmt::Debug for RpkSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RpkSigner([redacted])")
    }
}

impl Signer for RpkSigner {
    fn sign(&self, message: &[u8]) -> std::result::Result<Vec<u8>, rustls::Error> {
        Ok(self.0.sign(message).to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SCHEME
    }
}

impl SigningKey for RpkSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SCHEME)
            .then(|| Box::new(RpkSigner(self.0.clone())) as Box<dyn Signer>)
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(
            self.0.public().spki().to_vec(),
        ))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

fn certified_key(identity: &Arc<IdentityKey>) -> Arc<CertifiedKey> {
    Arc::new(CertifiedKey::new(
        vec![CertificateDer::from(identity.public().spki().to_vec())],
        Arc::new(RpkSigningKey(identity.clone())),
    ))
}

#[derive(Debug)]
struct RpkServerResolver(Arc<CertifiedKey>);

impl ResolvesServerCert for RpkServerResolver {
    fn resolve(&self, hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        hello
            .signature_schemes()
            .contains(&SCHEME)
            .then(|| self.0.clone())
    }

    fn only_raw_public_keys(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct RpkClientResolver(Arc<CertifiedKey>);

impl ResolvesClientCert for RpkClientResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        sigschemes.contains(&SCHEME).then(|| self.0.clone())
    }

    fn only_raw_public_keys(&self) -> bool {
        true
    }

    fn has_certs(&self) -> bool {
        true
    }
}

// ------------------------------------------------------------------ verifying side

/// Decode the single raw public key a peer presented.
fn presented_key(
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
) -> std::result::Result<PublicKey, rustls::Error> {
    if !intermediates.is_empty() {
        return Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::BadEncoding,
        ));
    }
    PublicKey::from_spki(end_entity.as_ref())
        .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))
}

/// Check a TLS 1.3 handshake signature made by the key in `cert`.
fn verify_signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
    algs: &WebPkiSupportedAlgorithms,
) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
    if dss.scheme != SCHEME {
        return Err(rustls::Error::PeerMisbehaved(
            rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
        ));
    }
    presented_key(cert, &[])?;
    verify_tls13_signature_with_raw_key(
        message,
        &SubjectPublicKeyInfoDer::from(cert.as_ref()),
        dss,
        algs,
    )
}

fn no_tls12() -> rustls::Error {
    rustls::Error::General("TLS 1.2 is not supported".into())
}

/// Server side: any well-formed client key, proven by its handshake signature.
#[derive(Debug)]
struct AnyClientKey(WebPkiSupportedAlgorithms);

impl ClientCertVerifier for AnyClientKey {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        presented_key(end_entity, intermediates)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(no_tls12())
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_signature(m, c, d, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SCHEME]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// Client side: the pinned server key, or (pairing) any valid key.
#[derive(Debug)]
struct ServerKeyVerifier {
    /// `Some` in session mode; `None` only for the first pairing.
    pinned: Option<PublicKey>,
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for ServerKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let key = presented_key(end_entity, intermediates)?;
        match &self.pinned {
            Some(pinned) if *pinned != key => Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            )),
            _ => Ok(ServerCertVerified::assertion()),
        }
    }

    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(no_tls12())
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_signature(m, c, d, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SCHEME]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

// ------------------------------------------------------------------ config builders

/// TLS configuration for `hx-transport::Server`: presents `identity`, requires and accepts
/// any valid client key. The transport adds ALPN and switches resumption off.
pub fn server_config(identity: &Arc<IdentityKey>) -> Result<Arc<rustls::ServerConfig>> {
    let p = provider();
    let cfg = rustls::ServerConfig::builder_with_provider(p.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls_err)?
        .with_client_cert_verifier(Arc::new(AnyClientKey(p.signature_verification_algorithms)))
        .with_cert_resolver(Arc::new(RpkServerResolver(certified_key(identity))));
    Ok(Arc::new(cfg))
}

fn client_config(
    device: &Arc<IdentityKey>,
    pinned: Option<PublicKey>,
) -> Result<Arc<rustls::ClientConfig>> {
    let p = provider();
    let verifier = ServerKeyVerifier {
        pinned,
        algs: p.signature_verification_algorithms,
    };
    let mut cfg = rustls::ClientConfig::builder_with_provider(p)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls_err)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_cert_resolver(Arc::new(RpkClientResolver(certified_key(device))));
    cfg.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(cfg))
}

/// TLS configuration for a paired device: presents `device`, accepts only the `server` key.
pub fn client_config_session(
    device: &Arc<IdentityKey>,
    server: PublicKey,
) -> Result<Arc<rustls::ClientConfig>> {
    client_config(device, Some(server))
}

/// TLS configuration for the first pairing: presents `device` and accepts any valid server
/// key **provisionally**. The caller must complete the SPAKE2 confirmation
/// (`pair_device` does) before trusting or storing that key.
pub fn client_config_pairing(device: &Arc<IdentityKey>) -> Result<Arc<rustls::ClientConfig>> {
    client_config(device, None)
}

/// The key a peer presented, from `Connection::peer_certificates()` / `PendingSession::
/// peer_certificates()`: exactly one raw-public-key entry holding a valid Ed25519 SPKI.
pub fn peer_key(certs: Option<&[CertificateDer<'static>]>) -> Result<PublicKey> {
    match certs {
        Some([one]) => PublicKey::from_spki(one.as_ref()),
        _ => Err(Error::InvalidKey),
    }
}
