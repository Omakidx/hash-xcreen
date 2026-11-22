//! The gateway's three session-link lane readers fed what a hostile `hx-session` could write
//! (`u16 ctl_len | u16 media_len | ctl | media | bulk`; see `hx_agent::link::fuzz::split`).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    hx_agent::link::fuzz::session_link(data);
});
