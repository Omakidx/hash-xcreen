//! The fixed media header and the datagram formats (video on the wire, mouse and audio).
#![no_main]

use hx_proto::{
    datagram::{Datagram, decode_datagram},
    media::{MEDIA_HEADER_LEN, MediaHeader},
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(h) = MediaHeader::decode(data) {
        // A header that decoded encodes to exactly the bytes it came from.
        assert_eq!(&h.encode().expect("a decoded header encodes")[..], data);
    }
    if let Ok((h, payload)) = MediaHeader::decode_frame(data) {
        assert_eq!(payload.len(), h.payload_len as usize);
        assert_eq!(data.len(), MEDIA_HEADER_LEN + payload.len());
    }
    match decode_datagram(data) {
        Ok(Datagram::MouseMove(m)) => assert_eq!(&m.encode()[..], data),
        Ok(Datagram::Audio(a)) => {
            assert_eq!(&a.encode().expect("a decoded packet encodes")[..], data)
        }
        Err(_) => {}
    }
});
