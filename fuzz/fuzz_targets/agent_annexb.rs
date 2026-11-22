//! The gateway's bitstream sanity check of a video frame from the session: Annex B structure,
//! NAL headers and the SPS exp-Golomb reader. Input: `key flag byte | payload`.
#![no_main]

use hx_agent::link::annexb::check_frame;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let [flag, payload @ ..] = data else {
        return;
    };
    if let Ok(checked) = check_frame(payload, flag & 1 == 1) {
        if let Some(sps) = checked.sps {
            // Within the pixel cap of docs/ipc.md section 15.1.
            assert!(u64::from(sps.width) * u64::from(sps.height) <= 7680 * 4320);
        }
    }
});
