//! The C2 encoder against the server-side parser (`hx_agent::install::stdin::read_frames`).

use std::io::Cursor;

use hx_agent::install::stdin::{MAX_TOTAL, read_frames};
use hx_sshsetup::Secrets;
use zeroize::Zeroizing;

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

fn token() -> String {
    // A well-formed token as the installer's parser wants it.
    let t = hx_crypto::PairingToken::generate().expect("token");
    t.to_text().to_string()
}

#[test]
fn required_secrets_round_trip() {
    let s = Secrets::new(z("correct horse battery staple"), z("482915")).unwrap();
    let bytes = s.encode().unwrap();
    let f = read_frames(&mut Cursor::new(bytes.to_vec()), true).expect("server parser");
    assert_eq!(
        f.password.as_deref().map(Vec::as_slice),
        Some(&b"correct horse battery staple"[..])
    );
    assert_eq!(f.pin.as_deref().map(Vec::as_slice), Some(&b"482915"[..]));
    assert!(f.token.is_none() && f.owner_key.is_none());
}

#[test]
fn every_optional_record_round_trips() {
    let t = token();
    let key = [7u8; 32];
    let s = Secrets::new(z("pw with spaces and ünïcode"), z("1234567890123456"))
        .unwrap()
        .with_pairing_token(z(&t))
        .unwrap()
        .with_owner_key(key);
    let f = read_frames(&mut Cursor::new(s.encode().unwrap().to_vec()), true).expect("parse");
    assert_eq!(f.token.as_deref().map(Vec::as_slice), Some(t.as_bytes()));
    assert_eq!(f.owner_key.as_deref().map(Vec::as_slice), Some(&key[..]));
    assert_eq!(
        f.pin.as_deref().map(Vec::as_slice),
        Some(&b"1234567890123456"[..])
    );
}

#[test]
fn the_longest_password_round_trips() {
    let pw = "p".repeat(511);
    let s = Secrets::new(z(&pw), z("123456")).unwrap();
    let f = read_frames(&mut Cursor::new(s.encode().unwrap().to_vec()), true).expect("parse");
    assert_eq!(f.password.as_ref().map(|p| p.len()), Some(511));
}

#[test]
fn client_checks_are_at_least_as_strict_as_the_server() {
    // Everything the client refuses is also refused by the server parser, and everything the
    // client accepts is accepted: probe the boundaries by hand-built streams.
    for (pw, ok) in [
        ("", false),
        ("a", true),
        (&"x".repeat(511)[..], true),
        (&"x".repeat(512)[..], false),
        ("a\nb", false),
    ] {
        let client_ok = Secrets::new(z(pw), z("123456")).is_ok();
        assert_eq!(client_ok, ok, "client on {:?}", pw.len());
        let mut raw = b"HXI1".to_vec();
        if !pw.is_empty() {
            raw.push(1);
            raw.extend_from_slice(&u16::try_from(pw.len()).unwrap().to_le_bytes());
            raw.extend_from_slice(pw.as_bytes());
        }
        raw.extend_from_slice(&[2, 6, 0]);
        raw.extend_from_slice(b"123456");
        raw.extend_from_slice(&[0, 0, 0]);
        let server_ok = read_frames(&mut Cursor::new(raw), true).is_ok();
        assert_eq!(server_ok, ok, "server on {:?}", pw.len());
    }
    for (pin, ok) in [
        ("12345", false),
        ("123456", true),
        ("1234567890123456", true),
        ("12345678901234567", false),
        ("12a456", false),
    ] {
        assert_eq!(
            Secrets::new(z("pw"), z(pin)).is_ok(),
            ok,
            "client pin {pin}"
        );
    }
}

#[test]
fn the_encoding_fits_the_servers_limit() {
    let s = Secrets::new(z(&"p".repeat(511)), z("1234567890123456"))
        .unwrap()
        .with_pairing_token(z(&token()))
        .unwrap()
        .with_owner_key([1; 32]);
    assert!(s.encode().unwrap().len() < MAX_TOTAL);
}
