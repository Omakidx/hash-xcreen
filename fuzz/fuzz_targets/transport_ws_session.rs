//! An established WebSocket connection reading raw wire bytes: framing, then the channel router
//! (control, input, cursor, datagrams, video, acks, clipboard and file transfers), for the
//! server (what a client can send) and the client (what a server can send).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    hx_transport::fuzz::ws_session(data);
});
