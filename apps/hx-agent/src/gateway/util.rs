//! Small helpers shared by the gateway modules.

use hx_crypto::DeviceId;
use hx_ipc::text::sanitize_text;

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
pub fn unhex(s: &str) -> Option<Vec<u8>> {
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
    b.chunks(2)
        .map(|p| Some(nib(p[0])? << 4 | nib(p[1])?))
        .collect()
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
