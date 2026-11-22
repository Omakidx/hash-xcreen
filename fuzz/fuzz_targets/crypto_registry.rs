//! The registry lookup of a `PendingSession` (the client's key from its TLS certificate) and the
//! registry file decoder.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    hx_crypto::fuzz::registry(data);
});
