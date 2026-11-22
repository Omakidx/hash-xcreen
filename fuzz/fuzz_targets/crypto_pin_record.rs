//! The stored PIN hash record.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    hx_crypto::fuzz::pin_record(data);
});
