//! Small helpers shared by the gateway modules.

use hx_crypto::DeviceId;
use hx_ipc::text::sanitize_text;
use zeroize::Zeroizing;

/// Lowercase hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[usize::from(b >> 4)] as char);
        s.push(DIGITS[usize::from(b & 15)] as char);
    }
    s
}

/// Decodes lowercase or uppercase hex; `None` on any other character or an odd length.
///
/// The output buffer is allocated once at its final size and wiped on drop (and on failure),
/// so decoding a key leaves no grown-and-abandoned copy behind. Callers that hold the bytes
/// copy them into a fixed array or another `Zeroizing` buffer.
pub fn unhex(s: &str) -> Option<Zeroizing<Vec<u8>>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let mut out = Zeroizing::new(Vec::with_capacity(b.len() / 2));
    for pair in b.chunks(2) {
        out.push(nib(pair[0])? << 4 | nib(pair[1])?);
    }
    Some(out)
}

/// A [`DeviceId`] from exactly 16 bytes (the type has no public constructor from bytes).
pub fn device_id(bytes: &[u8]) -> Option<DeviceId> {
    if bytes.len() != 16 {
        return None;
    }
    DeviceId::parse(&hex(bytes)).ok()
}

/// Seconds since the Unix epoch.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Peer-supplied text made safe for a log line (controls, ANSI, bidi and invisible characters
/// removed, cut to `max` bytes). Never shown in a UI as-is, never used for a decision.
pub fn log_text(raw: &str, max: usize) -> String {
    sanitize_text(raw, max)
}

/// First 8 hex digits of a device id: how the logs and the takeover notice name a device.
pub fn short_id(id: &DeviceId) -> String {
    hex(&id.as_bytes()[..4])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unhex_is_allocated_once_and_rejects_bad_input() {
        let v = unhex("00ff7A").unwrap();
        assert_eq!(&v[..], &[0x00, 0xff, 0x7a]);
        assert_eq!(v.capacity(), v.len(), "no spare capacity, no regrowth");
        let long = "ab".repeat(1000);
        let v = unhex(&long).unwrap();
        assert_eq!(v.capacity(), 1000);
        assert!(unhex("abc").is_none());
        assert!(unhex("zz").is_none());
        assert_eq!(hex(&[1, 2, 255]), "0102ff");
    }
}
