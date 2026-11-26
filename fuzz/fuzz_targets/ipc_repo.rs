//! The repository link of `docs/ipc.md` Part 3 as each of its four ends reads it: the incremental
//! decoder under the endpoint's frame policy (kind 1 everywhere, kind 2 only at the worker, kind 3
//! everywhere), the direction and repeated-field pre-scans, `decode` and its validation, the
//! data-frame split, the operation policy and the link state tracker.
//!
//! The harness (`src/ipc_repo_harness.rs`, shared with `gen-seeds`) completes the handshake and
//! plays the local end's own frames, so the tracker's later states are reachable from bytes.
//! Input: `selector | chunk size | stream`; `selector & 3` picks the endpoint (worker, privd on
//! the worker link, privd on the Drive link, Drive helper), bit 2 makes the harness respond or
//! send requests, bits 3 to 5 pick the job kind.
#![no_main]

#[path = "../src/ipc_repo_harness.rs"]
mod harness;

use hx_ipc::repo::Endpoint;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let [sel, chunk, stream @ ..] = data else {
        return;
    };
    let endpoint = Endpoint::ALL[usize::from(*sel & 3)];
    let kind = harness::KINDS[usize::from((*sel >> 3) & 7)];
    // A violation or a refused frame just ends this input; panics are the findings.
    let _ = harness::run(
        endpoint,
        sel & 4 != 0,
        kind,
        usize::from(*chunk).max(1),
        stream,
    );
});
