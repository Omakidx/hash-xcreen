//! The secrets `hx-agent install --ssh` reads from stdin (design C2): magic, records, limits.
//! Runs as root-adjacent installer code on the server, fed by the desktop app over SSH.
#![no_main]

use std::io::Cursor;

use hx_agent::install::stdin::{MAX_TOTAL, read_frames};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let [flag, stream @ ..] = data else {
        return;
    };
    let mut r = Cursor::new(stream);
    if let Ok(frames) = read_frames(&mut r, flag & 1 == 1) {
        // Accepted means the whole stream was within the 8 KiB frame and the checks of each record.
        assert!(stream.len() <= MAX_TOTAL + 1);
        if let Some(pin) = &frames.pin {
            assert!((6..=16).contains(&pin.len()) && pin.iter().all(u8::is_ascii_digit));
        }
        if let Some(key) = &frames.owner_key {
            assert_eq!(key.len(), 32);
        }
        if let Some(pw) = &frames.password {
            assert!(!pw.is_empty() && pw.len() <= 511);
            assert!(!pw.iter().any(|b| matches!(b, 0 | b'\r' | b'\n')));
        }
        if *flag & 1 == 1 {
            assert!(frames.password.is_some() && frames.pin.is_some());
        }
    }
});
