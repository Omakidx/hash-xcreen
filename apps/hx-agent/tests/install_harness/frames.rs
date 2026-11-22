//! The secret frames of `--ssh` (design C2), as the 1G app will write them. The harness is the
//! first producer outside the agent's own tests, so this encoder is written from the contract in
//! `docs/ipc.md` and not shared with `hx_agent::install::stdin`.
//!
//! ```text
//! "HXI1" | { kind u8 | len u16 LE | bytes[len] }* | kind 0, len 0
//! ```

pub const KIND_PASSWORD: u8 = 1;
pub const KIND_PIN: u8 = 2;
pub const KIND_TOKEN: u8 = 3;
pub const KIND_OWNER_KEY: u8 = 4;

fn record(out: &mut Vec<u8>, kind: u8, bytes: &[u8]) {
    out.push(kind);
    out.extend_from_slice(
        &u16::try_from(bytes.len())
            .expect("record too long")
            .to_le_bytes(),
    );
    out.extend_from_slice(bytes);
}

/// The whole stdin of one `install.sh --ssh` run.
pub fn stream(
    password: &str,
    pin: &str,
    token: Option<&str>,
    owner_key: Option<&[u8; 32]>,
) -> Vec<u8> {
    let mut out = b"HXI1".to_vec();
    record(&mut out, KIND_PASSWORD, password.as_bytes());
    record(&mut out, KIND_PIN, pin.as_bytes());
    if let Some(t) = token {
        record(&mut out, KIND_TOKEN, t.as_bytes());
    }
    if let Some(k) = owner_key {
        record(&mut out, KIND_OWNER_KEY, k);
    }
    out.extend_from_slice(&[0, 0, 0]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stream_has_magic_records_and_an_end_record() {
        let s = stream("pw", "123456", Some("hxt1-x"), None);
        assert_eq!(&s[..4], b"HXI1");
        assert_eq!(&s[4..9], &[1, 2, 0, b'p', b'w']);
        assert_eq!(&s[s.len() - 3..], &[0, 0, 0]);
        assert_eq!(s.len(), 4 + 5 + 9 + 9 + 3);
    }
}
