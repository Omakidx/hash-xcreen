//! The other channel messages (input, cursor, transfer headers), the length prefix and the text
//! rules that guard names and MIME types.
#![no_main]

use hx_proto::{
    message::{
        self, FRAME_PREFIX_LEN, device_name_problem, file_name_problem, mime_problem,
        sanitize_device_name,
    },
    pb::{CursorEvent, InputEvent, TransferHeader},
};
use libfuzzer_sys::fuzz_target;

fn round_trip<M: message::Wire + PartialEq + std::fmt::Debug>(body: &[u8]) {
    if let Ok(m) = message::decode::<M>(body) {
        let wire = message::encode(&m).expect("a decoded message encodes");
        assert_eq!(message::decode::<M>(&wire).expect("round trip"), m);
    }
    let _ = message::decode_framed::<M>(body);
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, body)) = data.split_first() else {
        return;
    };
    match sel % 5 {
        0 => round_trip::<InputEvent>(body),
        1 => round_trip::<CursorEvent>(body),
        2 => {
            round_trip::<TransferHeader>(body);
            if let Ok(h) = message::decode::<TransferHeader>(body) {
                let _ = h.validate_file(1 << 30);
                let _ = h.validate_clipboard();
            }
        }
        3 => {
            if let Some(p) = body.first_chunk::<FRAME_PREFIX_LEN>()
                && let Ok(n) = message::parse_frame_len(*p, 64 * 1024)
            {
                assert!(n <= 64 * 1024);
            }
        }
        _ => {
            let Ok(s) = std::str::from_utf8(body) else {
                return;
            };
            let _ = file_name_problem(s);
            let _ = mime_problem(s);
            let _ = device_name_problem(s);
            let clean = sanitize_device_name(s);
            assert!(
                device_name_problem(&clean).is_none(),
                "a sanitised name is acceptable"
            );
        }
    }
});
