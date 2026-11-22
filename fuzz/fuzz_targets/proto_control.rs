//! `ControlMessage` is the first thing a pre-authentication peer's bytes are decoded as (the
//! `Hello`), and every later control message after that.
#![no_main]

use hx_proto::{message, pb::ControlMessage, version::peek_hello_version};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = peek_hello_version(data);
    if let Ok(m) = message::decode::<ControlMessage>(data) {
        // Decoded means validated: it encodes again, and decodes to the same value.
        let wire = message::encode(&m).expect("a decoded message encodes");
        assert_eq!(
            message::decode::<ControlMessage>(&wire).expect("round trip"),
            m
        );
        let framed = message::encode_framed(&m).expect("a decoded message frames");
        let (back, rest) =
            message::decode_framed::<ControlMessage>(&framed).expect("framed round trip");
        assert!(rest.is_empty());
        assert_eq!(back, m);
    }
    let _ = message::decode_framed::<ControlMessage>(data);
});
