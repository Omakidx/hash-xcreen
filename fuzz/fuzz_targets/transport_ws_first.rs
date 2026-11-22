//! The first message of a WebSocket connection, from raw wire bytes: framing under the server's
//! size limits, the channel byte, then the `Hello` check.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    hx_transport::fuzz::ws_first_message(data);
});
