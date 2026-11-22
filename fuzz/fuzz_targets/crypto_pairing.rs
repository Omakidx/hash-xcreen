//! Pairing and auth envelopes, the SPAKE2 elements a peer sends, and the PIN check.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    hx_crypto::fuzz::pairing_envelope(data);
});
