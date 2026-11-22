//! A privd or admin-socket frame body decoded and validated for either side: the protobuf
//! decode, the repeated-field prescan, the contract's field rules, the secret frame, and the
//! command table. Input: `selector | kind | body`.
#![no_main]

use hx_ipc::{
    admin,
    link::frames::raw,
    privd::{self, Side},
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let [sel, kind, body @ ..] = data else {
        return;
    };
    let side = if sel & 1 == 0 {
        Side::Server
    } else {
        Side::Client
    };
    if sel & 2 == 0 {
        match privd::decode(raw(*kind, body), side) {
            Ok(privd::Incoming::Message(frame)) => {
                // Accepted means re-encodable for the same peer, and stable through the codec.
                let wire = privd::encode_message(&frame, side).expect("an accepted frame encodes");
                let again = privd::decode(raw(wire[4], &wire[5..]), side).expect("and decodes");
                match again {
                    privd::Incoming::Message(f2) => assert_eq!(f2, frame),
                    privd::Incoming::Secret(_) => panic!("a message became a secret"),
                }
                if let Some(privd::pb::frame::Frame::Request(req)) = &frame.frame {
                    let _ = privd::validate_request(req);
                    if let Some(cmd) = &req.command {
                        let info = privd::command_info(cmd);
                        let _ = info.effective_deadline_ms(u32::MAX);
                        let _ = privd::admin_only_argument(cmd);
                    }
                    let _ = privd::gateway_denied(req, privd::pb::Phase::Unspecified);
                }
            }
            Ok(privd::Incoming::Secret(s)) => {
                assert_eq!(side, Side::Server);
                let _ = format!("{s:?}");
            }
            Err(_) => {}
        }
    } else {
        match admin::decode(raw(*kind, body), side) {
            Ok(admin::Incoming::Message(frame)) => {
                let wire = admin::encode_message(&frame, side).expect("an accepted frame encodes");
                match admin::decode(raw(wire[4], &wire[5..]), side).expect("and decodes") {
                    admin::Incoming::Message(f2) => assert_eq!(f2, frame),
                    admin::Incoming::Secret(_) => panic!("a message became a secret"),
                }
                if let Some(admin::pb::frame::Frame::Request(req)) = &frame.frame {
                    let _ = admin::validate_request(req);
                    if let Some(cmd) = &req.command {
                        let _ = admin::command_name(cmd);
                    }
                }
            }
            Ok(admin::Incoming::Secret(s)) => {
                assert_eq!(side, Side::Server);
                let _ = format!("{s:?}");
            }
            Err(_) => {}
        }
    }
});
