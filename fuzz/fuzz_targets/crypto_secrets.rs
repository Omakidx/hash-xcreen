//! Pairing token, pairing code, PIN, device id and label parsers.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    hx_crypto::fuzz::secrets(data);
});
