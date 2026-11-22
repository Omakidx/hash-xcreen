//! After the install: pair with the app's own token, cross-check the server key, log in with the
//! PIN. Thin helpers over `hx_crypto`.
//!
//! The installer reports `server_public_key` over the SSH-authenticated channel. Pairing pins
//! whatever key the server shows over QUIC/WebSocket (TLS, bound into the SPAKE2 confirmation),
//! so comparing the two proves that the endpoint the app reached is the machine it just
//! installed, not something in between. A mismatch closes the pairing connection and nothing
//! is returned to store.

use std::net::SocketAddr;
use std::sync::Arc;

use hx_crypto::{
    IdentityKey, PairClientOptions, PairedServer, PairingCredential, Pin, PublicKey, SessionOptions,
};
use hx_transport::{Connection, Target};

use crate::error::{Result, SshSetupError};
use crate::progress::InstallResult;

/// Reads the 64 hex digits the installer reported as a key.
pub fn parse_server_key(hex: &str) -> Result<PublicKey> {
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(SshSetupError::Protocol(
            "the server key is not 64 hex digits".into(),
        ));
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| SshSetupError::Protocol("the server key is not hex".into()))?;
    }
    PublicKey::from_bytes(&out).map_err(SshSetupError::from)
}

/// The key the installer reported, as a typed key.
pub fn reported_key(result: &InstallResult) -> Result<PublicKey> {
    parse_server_key(&result.server_public_key)
}

/// `Ok` only when `seen` (the key presented while pairing) is the key the installer reported.
pub fn cross_check(result: &InstallResult, seen: &PublicKey) -> Result<()> {
    if reported_key(result)? == *seen {
        Ok(())
    } else {
        Err(SshSetupError::ServerKeyMismatch)
    }
}

/// The addresses of a result as socket addresses with the result's port (IPv6 included;
/// entries that do not parse are skipped).
pub fn socket_addrs(result: &InstallResult) -> Vec<SocketAddr> {
    result
        .addresses
        .iter()
        .filter_map(|a| a.parse::<std::net::IpAddr>().ok())
        .map(|ip| SocketAddr::new(ip, result.port))
        .collect()
}

/// Pairs this device with the token the app gave the installer (`hxt1-...`), then cross-checks
/// the server key against `result`. On success the caller owns the paired connection (send what
/// must follow, then `finish().await`) and should store `server_key` as the pin. On a mismatch
/// the connection is closed and [`SshSetupError::ServerKeyMismatch`] is returned.
pub async fn pair_and_cross_check(
    target: &Target,
    device: &Arc<IdentityKey>,
    token: &str,
    result: &InstallResult,
    opts: &PairClientOptions,
) -> Result<PairedServer> {
    // Parse both inputs before touching the network.
    let expected = reported_key(result)?;
    let cred = PairingCredential::parse(token)?;
    let paired = hx_crypto::pair_device(target, device, &cred, opts).await?;
    if paired.server_key != expected {
        paired.finish().await;
        return Err(SshSetupError::ServerKeyMismatch);
    }
    Ok(paired)
}

/// The PIN login against the pinned key (one attempt). A wrong PIN is
/// `SshSetupError::Pairing(hx_crypto::Error::WrongPin { .. })` with the attempts left.
pub async fn login_with_pin(
    target: &Target,
    device: &Arc<IdentityKey>,
    server_key: PublicKey,
    pin: &Pin,
    opts: &SessionOptions,
) -> Result<Connection> {
    Ok(hx_crypto::connect_with_pin(target, device, server_key, pin, opts).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::progress::PairingKind;

    fn result(key: &str) -> InstallResult {
        InstallResult {
            install_id: "a".repeat(32),
            agent_version: "0.1.0".into(),
            server_public_key: key.into(),
            addresses: vec!["203.0.113.9".into(), "2001:db8::1".into(), "junk".into()],
            port: 443,
            desktop: None,
            pairing: PairingKind::Token,
            pairing_expires_at_unix_s: 0,
            port_rule: "none".into(),
            warnings: vec![],
        }
    }

    fn some_key(seed: u8) -> (PublicKey, String) {
        let id = IdentityKey::generate().expect("key");
        let _ = seed;
        let pk = id.public();
        let hex: String = pk.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        (pk, hex)
    }

    #[test]
    fn cross_check_accepts_only_the_reported_key() {
        let (k1, h1) = some_key(1);
        let (k2, _) = some_key(2);
        let r = result(&h1);
        assert!(cross_check(&r, &k1).is_ok());
        assert!(matches!(
            cross_check(&r, &k2),
            Err(SshSetupError::ServerKeyMismatch)
        ));
    }

    #[test]
    fn a_malformed_reported_key_is_a_protocol_error() {
        assert!(parse_server_key("zz").is_err());
        assert!(parse_server_key(&"g".repeat(64)).is_err());
    }

    #[test]
    fn addresses_carry_the_port() {
        let (_, h) = some_key(1);
        let a = socket_addrs(&result(&h));
        assert_eq!(a.len(), 2);
        assert!(a.iter().all(|s| s.port() == 443));
    }
}
