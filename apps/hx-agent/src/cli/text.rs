//! Terminal safety. Every string that came from a peer (gatewayd, privd, Incus through privd,
//! journald) is untrusted: it can carry ANSI escapes that rewrite the operator's terminal, bidi
//! controls that reorder what they read, or newlines that forge output lines.
//!
//! Two layers:
//!
//! 1. [`peer`] is applied where a peer string enters the CLI (it is `hx_ipc::text::sanitize_text`
//!    with a bound);
//! 2. [`scrub_output`] and [`scrub_json`] are applied to **everything** written to stdout, so a
//!    string that skipped layer 1 still cannot reach the terminal raw.

use hx_ipc::text::{is_unsafe_char, sanitize_text};
use serde_json::Value;

/// Longest peer string kept by default (free text such as a device name or an error message).
pub const DEFAULT_MAX: usize = 256;

/// Sanitizes a peer-supplied string: control characters (including ESC), format characters
/// (bidi, zero-width, tags) and line separators are removed, and the result is cut to at most
/// `max_bytes` on a character boundary.
pub fn peer(s: &str, max_bytes: usize) -> String {
    sanitize_text(s, max_bytes)
}

/// Sanitizes with [`DEFAULT_MAX`].
pub fn peer_default(s: &str) -> String {
    peer(s, DEFAULT_MAX)
}

/// Removes every unsafe character from `text` except `\n` and `\t`, which the CLI itself uses
/// for layout. This is the last step before a write to stdout or stderr.
pub fn scrub_output(text: &str) -> String {
    text.chars()
        .filter(|c| *c == '\n' || *c == '\t' || !is_unsafe_char(*c))
        .collect()
}

/// Sanitizes every string (keys included) of a JSON tree. `serde_json` escapes controls but
/// writes bidi and zero-width characters as they are, so they are removed here.
pub fn scrub_json(v: &mut Value) {
    match v {
        Value::String(s) => {
            if s.chars().any(is_unsafe_char) {
                *s = s.chars().filter(|c| !is_unsafe_char(*c)).collect();
            }
        }
        Value::Array(a) => a.iter_mut().for_each(scrub_json),
        Value::Object(m) => {
            let old = std::mem::take(m);
            for (k, mut val) in old {
                scrub_json(&mut val);
                let k: String = k.chars().filter(|c| !is_unsafe_char(*c)).collect();
                m.insert(k, val);
            }
        }
        _ => {}
    }
}

/// Lower-case hex.
pub fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// Seconds since the epoch as `2026-11-21T10:15:00Z`; `0` is shown as `-`.
pub fn time(unix: u64) -> String {
    if unix == 0 {
        "-".into()
    } else {
        crate::privd::timefmt::rfc3339(unix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_text_loses_escapes_bidi_and_newlines() {
        let s = peer_default("a\x1b[2J\x1b]0;pwned\x07b\u{202E}c\nd\u{200B}e\r");
        assert_eq!(s, "a[2J]0;pwnedbcde");
    }

    #[test]
    fn scrub_output_keeps_layout_only() {
        assert_eq!(scrub_output("a\tb\nc\x1b[0m\u{202E}d\x07"), "a\tb\nc[0md");
    }

    #[test]
    fn scrub_json_cleans_values_and_keys() {
        let mut v = serde_json::json!({"k\u{202E}": ["a\u{200B}b", {"x": "y\x1bz"}]});
        scrub_json(&mut v);
        assert_eq!(v, serde_json::json!({"k": ["ab", {"x": "yz"}]}));
    }

    #[test]
    fn times() {
        assert_eq!(time(0), "-");
        assert_eq!(time(1_800_000_000), "2027-01-15T08:00:00Z");
    }
}
