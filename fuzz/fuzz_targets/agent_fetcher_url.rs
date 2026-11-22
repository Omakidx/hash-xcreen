//! The URL the update fetcher parses out of a redirect's `Location` header (server supplied).
#![no_main]

use hx_agent::fetcher::parse_url;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(u) = parse_url(s) {
        assert!(u.path.starts_with('/'));
        assert!(u.host.is_ascii() && !u.host.is_empty());
        assert!(
            !u.host
                .contains(|c: char| c.is_whitespace() || c == '/' || c == '@' || c == ':')
        );
        assert!(!u.path.bytes().any(|b| b < 0x21 || b == 0x7f));
    }
});
