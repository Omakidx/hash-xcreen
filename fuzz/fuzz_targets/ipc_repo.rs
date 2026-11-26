//! The repository link of `docs/ipc.md` Part 3 as each of its four ends reads it: the incremental
//! decoder under the endpoint's frame policy (kind 1 everywhere, kind 2 only at the worker, kind 3
//! everywhere), the repeated-field prescan, `decode` and its validation, the data-frame split, the
//! operation policy and the link state tracker. Input: `selector | chunk size | stream`.
//!
//! `selector & 3` picks the endpoint (worker, privd on the worker link, privd on the Drive link,
//! Drive helper). Bit 2 makes the harness play the responder: it answers each request it receives
//! with an `Error`, so that request slots are recycled and the tracker's later states are
//! reachable from arbitrary bytes.
#![no_main]

use hx_ipc::frame::Decoder;
use hx_ipc::repo::{
    self, Endpoint, Incoming, LinkState, MAX_DATA_PAYLOAD, MAX_OUTSTANDING_REQUESTS,
    MAX_OUTSTANDING_WRITES, RepoFramePolicy, check_op, pb,
};
use libfuzzer_sys::fuzz_target;

fn answer(req_id: u64) -> pb::RepoFrame {
    pb::RepoFrame {
        frame: Some(pb::repo_frame::Frame::Response(pb::RepoResponse {
            req_id,
            result: Some(pb::repo_response::Result::Error(pb::RepoError {
                class: pb::ErrorClass::Internal as i32,
                retry_after_ms: 0,
            })),
        })),
    }
}

fn run(endpoint: Endpoint, respond: bool, chunk: usize, stream: &[u8]) {
    let mut decoder = Decoder::new(RepoFramePolicy::new(endpoint));
    let mut link = LinkState::new(endpoint);
    let mut rest = stream;
    while !rest.is_empty() {
        let take = rest.len().min(chunk);
        let mut piece = &rest[..take];
        while !piece.is_empty() {
            let (used, raw) = match decoder.feed(piece) {
                Ok(x) => x,
                Err(_) => return,
            };
            piece = &piece[used..];
            let Some(raw) = raw else { continue };
            let incoming = match repo::decode(raw, endpoint) {
                Ok(i) => i,
                Err(_) => return,
            };
            match &incoming {
                Incoming::Message(frame) => {
                    // Accepted means re-encodable for the same peer, and stable through the codec.
                    let wire =
                        repo::encode_message(frame, endpoint).expect("an accepted frame encodes");
                    let again = repo::decode(
                        hx_ipc::frame::RawFrame {
                            kind: wire[4],
                            body: wire[5..].into(),
                        },
                        endpoint,
                    )
                    .expect("and decodes");
                    match again {
                        Incoming::Message(f2) => assert_eq!(&f2, frame),
                        _ => panic!("a message became something else"),
                    }
                    // The operation policy is total: no panic for any accepted request.
                    if let Some(pb::repo_frame::Frame::Request(r)) = &frame.frame
                        && let Some(op) = &r.op
                    {
                        for kind in 0..=8 {
                            if let Ok(k) = pb::JobKind::try_from(kind) {
                                let _ = check_op(k, None, op);
                            }
                        }
                    }
                }
                Incoming::Secret(s) => {
                    assert_eq!(endpoint, Endpoint::Worker);
                    let _ = format!("{s:?}");
                }
                Incoming::Data(d) => {
                    assert!(d.stream_id != 0);
                    assert!(d.payload.len() <= MAX_DATA_PAYLOAD);
                    let _ = format!("{d:?}");
                }
            }
            if link.received(&incoming).is_err() {
                return;
            }
            assert!(link.outstanding() <= MAX_OUTSTANDING_REQUESTS);
            assert!(link.outstanding_writes() <= MAX_OUTSTANDING_WRITES);
            if respond
                && matches!(endpoint, Endpoint::PrivdWorkerLink | Endpoint::DriveHelper)
                && let Incoming::Message(pb::RepoFrame {
                    frame: Some(pb::repo_frame::Frame::Request(r)),
                }) = &incoming
            {
                // Our own frame: a violation here would be a tracker bug, not the input's.
                let _ = link.sent_message(&answer(r.req_id));
            }
        }
        rest = &rest[take..];
    }
    let _ = decoder.finish();
}

fuzz_target!(|data: &[u8]| {
    let [sel, chunk, stream @ ..] = data else {
        return;
    };
    let endpoint = Endpoint::ALL[usize::from(*sel & 3)];
    run(endpoint, sel & 4 != 0, usize::from(*chunk).max(1), stream);
});
