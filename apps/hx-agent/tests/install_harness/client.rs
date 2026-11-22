//! The test client: pairing and PIN login against a real installed server with `hx_crypto` and
//! `hx_transport`, over QUIC or WebSocket, from outside the machine that runs the server. Shared
//! by the local nested-container test and by the CI VM client (`installer_vm_client.rs`).
//!
//! The including test crate must declare `mod relay_common;` and `mod gateway_common;` (the
//! first-frame check uses `relay_common::Client`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hx_crypto::{IdentityKey, PairClientOptions, PairingCredential, Pin, PublicKey};
use hx_transport::{Connection, Target, TransportPreference};
use rustls::pki_types::ServerName;

pub fn target(addr: SocketAddr) -> Target {
    Target {
        addr,
        server_name: ServerName::try_from("hx.invalid").expect("server name"),
    }
}

pub fn hex_to_key(h: &str) -> PublicKey {
    assert_eq!(h.len(), 64, "a server key is 64 hex digits: {h}");
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).expect("hex");
    }
    PublicKey::from_bytes(&out).expect("server key")
}

/// Pairs a new device with `cred` (a token `hxt1-...` or a code `XXXX-XXXX`) when given, pinning
/// `server`, then logs in with the PIN. Panics with the reason on any failure.
pub async fn pair_and_login(
    addr: SocketAddr,
    server: PublicKey,
    pref: TransportPreference,
    name: &str,
    pin: &str,
    cred: Option<&str>,
) -> Connection {
    let t = target(addr);
    let device = Arc::new(IdentityKey::generate().expect("device key"));
    if let Some(c) = cred {
        let cred = PairingCredential::parse(c).expect("credential");
        let paired = tokio::time::timeout(
            Duration::from_secs(60),
            hx_crypto::pair_device(
                &t,
                &device,
                &cred,
                &PairClientOptions {
                    preference: pref,
                    device_name: name.into(),
                    ..Default::default()
                },
            ),
        )
        .await
        .expect("pairing in time")
        .expect("pairing");
        assert_eq!(
            paired.server_key, server,
            "the pinned server key is the one the installer reported"
        );
        paired.finish().await;
    }
    let opts = {
        use hx_proto::VideoCodec;
        use hx_proto::version::{Features, PROTOCOL_MINOR, capabilities};
        hx_crypto::SessionOptions {
            preference: pref,
            device_name: name.into(),
            capabilities: capabilities(
                &[VideoCodec::H264],
                Features::defined_up_to(PROTOCOL_MINOR),
            ),
            ..Default::default()
        }
    };
    tokio::time::timeout(
        Duration::from_secs(60),
        hx_crypto::connect_with_pin(&t, &device, server, &Pin::new(pin).expect("pin"), &opts),
    )
    .await
    .expect("login in time")
    .expect("PIN login")
}

/// A pairing attempt that is expected to be refused (a used token): true when it was.
pub async fn pairing_is_refused(addr: SocketAddr, pref: TransportPreference, cred: &str) -> bool {
    let t = target(addr);
    let device = Arc::new(IdentityKey::generate().expect("device key"));
    let cred = PairingCredential::parse(cred).expect("credential");
    let r = tokio::time::timeout(
        Duration::from_secs(60),
        hx_crypto::pair_device(
            &t,
            &device,
            &cred,
            &PairClientOptions {
                preference: pref,
                device_name: "refused".into(),
                ..Default::default()
            },
        ),
    )
    .await;
    !matches!(r, Ok(Ok(_)))
}

/// `ViewConfig`, then the IDR that answers it: `(bytes, milliseconds)` or `None` after `secs`.
pub async fn first_frame(conn: Connection, secs: u64) -> Option<(usize, u128)> {
    let mut s = crate::relay_common::Client::new(conn);
    s.view(|_| {}).await;
    let t0 = Instant::now();
    tokio::time::timeout(Duration::from_secs(secs), s.first_idr(secs))
        .await
        .ok()
        .map(|f| (f.payload.len(), t0.elapsed().as_millis()))
}
