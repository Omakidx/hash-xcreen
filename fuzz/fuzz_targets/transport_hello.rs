//! The `Hello` check of a connection: the first control message, before any authentication.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    hx_transport::fuzz::check_hello(data);
});
