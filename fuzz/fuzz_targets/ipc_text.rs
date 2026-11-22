//! `sanitize_text`: the only thing between session-supplied text and the gateway's logs.
#![no_main]

use hx_ipc::text::{is_unsafe_char, sanitize_text};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let [max, rest @ ..] = data else {
        return;
    };
    let Ok(s) = std::str::from_utf8(rest) else {
        return;
    };
    let max = usize::from(*max) * 2;
    let out = sanitize_text(s, max);
    assert!(out.len() <= max);
    assert!(!out.chars().any(is_unsafe_char));
    // Idempotent, and a prefix-closed filter of the input's safe characters.
    assert_eq!(sanitize_text(&out, max), out);
    let safe: String = s.chars().filter(|c| !is_unsafe_char(*c)).collect();
    assert!(safe.starts_with(&out));
});
