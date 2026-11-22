//! Entry points for the cargo-fuzz targets in `fuzz/` (feature `fuzzing`, never part of a
//! product build). Each function takes bytes a peer (or the registry file) can supply, must
//! never panic, and asserts the cheap invariants of the code it drives.

use std::sync::Arc;

use hx_proto::pb::ControlMessage;
use spake2::{Ed25519Group, Identity, Password, Spake2};

use crate::{
    keys::{DeviceId, PublicKey},
    pairing::MAX_NAME,
    registry::{DeviceRegistry, MemoryRegistry},
    secrets::{PairingCode, PairingCredential, PairingToken, Pin},
    text::sanitize_label,
    wire::{AuthMessage, PairingMessage, auth_message, pairing_message::Body},
};

const SPAKE_LEN: usize = 33;

/// A control message carrying a pairing or auth envelope, and what the two sides of the
/// exchange do with its contents: the envelope decode, the SPAKE2 element a peer sends
/// (`finish` must reject a bad point, never panic), and the PIN check.
pub fn pairing_envelope(data: &[u8]) {
    let Ok(m) = hx_proto::message::decode::<ControlMessage>(data) else {
        return;
    };
    if let Ok(a) = AuthMessage::from_control(&m) {
        if let Ok(c) = a.clone().into_control() {
            assert_eq!(AuthMessage::from_control(&c).expect("round trip"), a);
        }
        if let Some(auth_message::Body::Pin(p)) = &a.body {
            // The server accepts a PIN only if it is 6 to 16 ASCII digits.
            if let Ok(pin) = Pin::from_bytes(&p.pin) {
                assert!((6..=16).contains(&pin.as_bytes().len()));
                assert!(pin.as_bytes().iter().all(u8::is_ascii_digit));
            }
        }
    }
    let Ok(p) = PairingMessage::from_control(&m) else {
        return;
    };
    if let Ok(c) = p.clone().into_control() {
        assert_eq!(PairingMessage::from_control(&c).expect("round trip"), p);
    }
    match &p.body {
        Some(Body::Start(start)) => {
            // Server side: the label sanitiser, then the peer's SPAKE2 element.
            let _ = sanitize_label(&start.device_name, MAX_NAME, "unnamed device");
            if start.spake.len() == SPAKE_LEN {
                let (s, _msg) = Spake2::<Ed25519Group>::start_b(
                    &Password::new(b"fuzz password"),
                    &Identity::new(b"hx-pair-client"),
                    &Identity::new(b"hx-pair-server"),
                );
                let _ = s.finish(&start.spake);
            }
        }
        Some(Body::ServerHello(h)) => {
            // Client side: the server's SPAKE2 element and label.
            let _ = sanitize_label(&h.server_name, MAX_NAME, "server");
            if h.spake.len() == SPAKE_LEN {
                let (s, _msg) = Spake2::<Ed25519Group>::start_a(
                    &Password::new(b"fuzz password"),
                    &Identity::new(b"hx-pair-client"),
                    &Identity::new(b"hx-pair-server"),
                );
                let _ = s.finish(&h.spake);
            }
        }
        _ => {}
    }
}

/// The token, code, PIN and device-id parsers (pairing credentials come from a QR code, a
/// typed code or `hx-agent install` stdin; the PIN and device id from the wire).
pub fn secrets(data: &[u8]) {
    let (&sel, rest) = data.split_first().unwrap_or((&0, &[]));
    if sel % 2 == 0 {
        // Raw bytes into the PIN parser (the network form).
        let _ = Pin::from_bytes(data);
    }
    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };
    if let Ok(t) = PairingToken::parse(text) {
        // A parsed token re-encodes to something that parses to the same id.
        let again = PairingToken::parse(&t.to_text()).expect("a token's text parses");
        assert_eq!(again.id(), t.id());
    }
    if let Ok(c) = PairingCode::parse(text) {
        assert!(PairingCode::parse(&c.to_text()).is_ok());
    }
    let _ = PairingCredential::parse(text);
    if let Ok(id) = DeviceId::parse(text) {
        assert_eq!(
            DeviceId::parse(&id.to_string()).expect("id text parses"),
            id
        );
    }
    let out = sanitize_label(text, MAX_NAME, "fallback");
    assert!(out.len() <= MAX_NAME && !out.is_empty());
}

/// The registry lookup a `PendingSession` triggers: the client's TLS key (a 44-byte SPKI the
/// peer chose) into a [`PublicKey`], and the lookup by key and by id. The registry also decodes
/// its file, which `FileRegistry::open` hands to the same code.
pub fn registry(data: &[u8]) {
    let (&sel, rest) = data.split_first().unwrap_or((&0, &[]));
    if sel % 4 == 0 {
        let _ = crate::registry::decode_file(rest);
        return;
    }
    let reg: Arc<dyn DeviceRegistry> = Arc::new(MemoryRegistry::new());
    let known = crate::keys::IdentityKey::from_seed(&[7u8; 32]).expect("seed key");
    reg.upsert_paired(&known.public(), "known", 1)
        .expect("upsert into memory");
    if let Ok(key) = PublicKey::from_spki(rest) {
        assert_eq!(key.spki().as_slice(), rest, "an SPKI round-trips exactly");
        let found = reg.find_by_key(&key).expect("lookup");
        assert_eq!(found.is_some(), key == known.public());
    }
    if let Some(id) = DeviceId::from_slice(rest.get(..16).unwrap_or(&[])) {
        let _ = reg.get(&id);
    }
}

/// The stored PIN hash record (`PinHash::from_storage_string`).
pub fn pin_record(data: &[u8]) {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(h) = crate::pin::PinHash::from_storage_string(s) {
        // Whatever parses was within the cost bounds and re-encodes to a record that parses to
        // the same hash.
        let again = crate::pin::PinHash::from_storage_string(&h.to_storage_string())
            .expect("a record's text parses");
        assert_eq!(again, h);
    }
}
