//! A session-link frame body, as the gateway (hostile session) or the session (gateway) parses
//! it: protobuf decode with the repeated-field prescan, the contract's validation, the media
//! header, audio and transfer frames. Input: `selector | kind | body`.
#![no_main]

use hx_ipc::link::{
    Lane, LinkPolicy, Role,
    frames::{LinkFrame, parse, raw},
    validate,
};
use libfuzzer_sys::fuzz_target;
use prost::Message;

fuzz_target!(|data: &[u8]| {
    let [sel, kind, body @ ..] = data else {
        return;
    };
    let role = if sel & 1 == 0 {
        Role::Gateway
    } else {
        Role::Session
    };
    let lane = [Lane::Ctl, Lane::Media, Lane::Bulk][usize::from(*sel >> 1) % 3];
    let policy = LinkPolicy::new(role, lane);
    // The file-size limit of the gateway's configuration (4 GiB by default), or a small one.
    let max_file = if sel & 0x80 == 0 { 4 << 30 } else { 1 << 20 };
    match parse(&policy, raw(*kind, body), max_file) {
        Ok(LinkFrame::Video(v)) => {
            assert_eq!(v.payload().len(), v.header.payload_len as usize);
            assert!(v.header.payload_len <= policy.max_frame_bytes());
        }
        Ok(LinkFrame::FromSession(m)) => {
            validate::validate_session_message(&m).expect("a parsed message validates");
            let wire = m.encode_to_vec();
            assert_eq!(
                hx_ipc::link::pb::SessionToGateway::decode(wire.as_slice()).expect("round trip"),
                m
            );
        }
        Ok(LinkFrame::FromGateway(m)) => {
            validate::validate_gateway_message(&m).expect("a parsed message validates");
        }
        Ok(LinkFrame::TransferData { data, .. }) => assert!(!data.is_empty()),
        Ok(_) | Err(_) => {}
    }
    // The bare validators on whatever decodes (no framing in front of them).
    if let Ok(c) = hx_ipc::link::pb::StreamConfig::decode(body) {
        let _ = validate::validate_stream_config(&c);
        let _ = validate::config_codec_supported(&c);
    }
    if let Ok(i) = hx_ipc::link::pb::Info::decode(body) {
        let _ = validate::validate_info(&i);
    }
});
