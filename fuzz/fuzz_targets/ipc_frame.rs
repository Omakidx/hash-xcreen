//! The incremental frame decoder under every policy of the internal IPC: the privd and admin
//! sockets (both sides) and every lane of the session link (both roles). The input is
//! `policy byte | chunk size byte | stream`; the stream is fed in chunks of the chosen size.
#![no_main]

use hx_ipc::{
    Decoder, FramePolicy,
    frame::PREFIX_LEN,
    link::{Lane, LinkPolicy, Role},
    privd::{PrivdPolicy, Side},
};
use libfuzzer_sys::fuzz_target;

fn drive<P: FramePolicy>(policy: P, chunk: usize, stream: &[u8]) {
    let ceiling = policy.absolute_max_length() as usize;
    let mut d = Decoder::new(policy);
    let mut rest = stream;
    while !rest.is_empty() {
        let take = rest.len().min(chunk);
        let mut piece = &rest[..take];
        loop {
            // The decoder never asks for more than one frame's remainder.
            assert!(d.wants() <= ceiling + PREFIX_LEN);
            match d.feed(piece) {
                Ok((used, frame)) => {
                    if let Some(f) = frame {
                        // `length` counts the kind byte, so the body is one shorter.
                        assert!(f.body.len() < ceiling.max(1));
                    }
                    piece = &piece[used..];
                    if piece.is_empty() {
                        break;
                    }
                    if used == 0 {
                        break;
                    }
                }
                Err(_) => return,
            }
        }
        rest = &rest[take..];
    }
    let _ = d.finish();
}

fuzz_target!(|data: &[u8]| {
    let [sel, chunk, stream @ ..] = data else {
        return;
    };
    let chunk = usize::from(*chunk).max(1);
    match *sel % 8 {
        0 => drive(PrivdPolicy::new(Side::Server), chunk, stream),
        1 => drive(PrivdPolicy::new(Side::Client), chunk, stream),
        n => {
            let role = if n % 2 == 0 {
                Role::Gateway
            } else {
                Role::Session
            };
            let lane = [Lane::Ctl, Lane::Media, Lane::Bulk][usize::from(*sel / 8) % 3];
            drive(LinkPolicy::new(role, lane), chunk, stream);
        }
    }
});
