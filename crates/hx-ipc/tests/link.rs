#![cfg(feature = "link")]
//! Contract tests for the session link (docs/ipc.md Part 2): lane policy, frame limits, every
//! message of sections 14 and 16, media header rules, transfer rules and budgets.

use bytes::BytesMut;
use hx_ipc::error::FrameError;
use hx_ipc::frame::{Decoder, FramePolicy, RawFrame};
use hx_ipc::link::frames::{self, LinkFrame};
use hx_ipc::link::validate::{self, DEFAULT_MAX_FILE_BYTES};
use hx_ipc::link::{
    DEFAULT_MAX_FRAME_BYTES, KIND_AUDIO, KIND_GATEWAY_TO_SESSION, KIND_SESSION_TO_GATEWAY,
    KIND_TRANSFER_ABORT, KIND_TRANSFER_DATA, KIND_TRANSFER_END, KIND_TRANSFER_OPEN, KIND_VIDEO,
    Lane, LinkPolicy, MAX_CTL_G2S_LENGTH, MAX_CTL_S2G_LENGTH, Role, pb,
};
use hx_proto::media::{FLAG_KEY, FLAG_RESYNC, MediaHeader};
use hx_proto::pb as hx;
use proptest::prelude::*;

const FILE_MAX: u64 = DEFAULT_MAX_FILE_BYTES;

fn policy(receiver: Role, lane: Lane) -> LinkPolicy {
    LinkPolicy::new(receiver, lane)
}

fn head(length: u32, kind: u8) -> Vec<u8> {
    let mut v = length.to_le_bytes().to_vec();
    v.push(kind);
    v
}

fn parse_wire(receiver: Role, lane: Lane, wire: &[u8]) -> Result<LinkFrame, FrameError> {
    let p = policy(receiver, lane);
    let mut d = Decoder::new(p);
    let raw = match d.read_from(&mut &wire[..]) {
        Ok(Some(r)) => r,
        Ok(None) => panic!("no frame"),
        Err(hx_ipc::ReadError::Frame(e)) => return Err(e),
        Err(e) => panic!("{e}"),
    };
    frames::parse(&p, raw, FILE_MAX)
}

fn video_header(payload: u32, flags: u16, frame_number: u32) -> MediaHeader {
    MediaHeader {
        codec: hx_proto::VideoCodec::H264,
        flags,
        frame_number,
        capture_timestamp_us: 123_456,
        payload_len: payload,
    }
}

fn video_wire(header: &MediaHeader, payload: &[u8]) -> Vec<u8> {
    let mut w = frames::encode_video_prefix(header, DEFAULT_MAX_FRAME_BYTES)
        .unwrap()
        .to_vec();
    w.extend_from_slice(payload);
    w
}

// ---------- lane policy ----------

#[test]
fn lane_and_direction_table_of_section_13() {
    use Lane::*;
    use Role::*;
    let kinds = [
        KIND_SESSION_TO_GATEWAY,
        KIND_GATEWAY_TO_SESSION,
        KIND_VIDEO,
        KIND_AUDIO,
        KIND_TRANSFER_OPEN,
        KIND_TRANSFER_DATA,
        KIND_TRANSFER_END,
        KIND_TRANSFER_ABORT,
    ];
    let allowed = |r, l| -> Vec<u8> {
        kinds
            .iter()
            .copied()
            .filter(|k| policy(r, l).max_length(*k).is_ok())
            .collect()
    };
    assert_eq!(allowed(Gateway, Ctl), [KIND_SESSION_TO_GATEWAY]);
    assert_eq!(allowed(Session, Ctl), [KIND_GATEWAY_TO_SESSION]);
    assert_eq!(allowed(Gateway, Media), [KIND_VIDEO, KIND_AUDIO]);
    assert_eq!(allowed(Session, Media), Vec::<u8>::new());
    for r in [Gateway, Session] {
        assert_eq!(
            allowed(r, Bulk),
            [
                KIND_TRANSFER_OPEN,
                KIND_TRANSFER_DATA,
                KIND_TRANSFER_END,
                KIND_TRANSFER_ABORT
            ]
        );
    }
    // limits
    assert_eq!(
        policy(Gateway, Ctl).max_length(KIND_SESSION_TO_GATEWAY),
        Ok(327_685)
    );
    assert_eq!(
        policy(Session, Ctl).max_length(KIND_GATEWAY_TO_SESSION),
        Ok(16_384)
    );
    assert_eq!(policy(Gateway, Media).max_length(KIND_VIDEO), Ok(4_194_325));
    assert_eq!(policy(Gateway, Media).max_length(KIND_AUDIO), Ok(1_110));
    assert_eq!(
        policy(Gateway, Bulk).max_length(KIND_TRANSFER_OPEN),
        Ok(4_200)
    );
    assert_eq!(
        policy(Gateway, Bulk).max_length(KIND_TRANSFER_DATA),
        Ok(65_541)
    );
    assert_eq!(policy(Gateway, Bulk).max_length(KIND_TRANSFER_END), Ok(5));
    assert_eq!(policy(Gateway, Bulk).max_length(KIND_TRANSFER_ABORT), Ok(9));
    // a wrong-lane kind is "not allowed", an undefined kind "unknown"
    assert_eq!(
        policy(Gateway, Ctl).max_length(KIND_VIDEO),
        Err(FrameError::KindNotAllowed(KIND_VIDEO))
    );
    assert_eq!(
        policy(Gateway, Ctl).max_length(0x7f),
        Err(FrameError::UnknownKind(0x7f))
    );
}

#[test]
fn max_frame_bytes_is_configurable_up_to_16_mib() {
    let p = policy(Role::Gateway, Lane::Media);
    assert_eq!(p.max_length(KIND_VIDEO), Ok(DEFAULT_MAX_FRAME_BYTES + 21));
    let big = p.with_max_frame_bytes(16 * 1024 * 1024).unwrap();
    assert_eq!(
        big.max_length(KIND_VIDEO),
        Ok(16_777_237),
        "the protocol's 16 MiB plus 21"
    );
    assert!(p.with_max_frame_bytes(0).is_err());
    assert!(p.with_max_frame_bytes(16 * 1024 * 1024 + 1).is_err());
}

#[test]
fn a_byte_on_media_gateway_to_session_is_a_violation() {
    let mut d = Decoder::new(policy(Role::Session, Lane::Media));
    assert_eq!(d.feed(&[0x10]).unwrap_err(), FrameError::ForbiddenDirection);
    let mut d = Decoder::new(policy(Role::Session, Lane::Media));
    let wire = frames::encode_audio(1, 2, &[1, 2, 3]).unwrap();
    assert!(matches!(
        d.read_from(&mut &wire[..]),
        Err(hx_ipc::ReadError::Frame(FrameError::ForbiddenDirection))
    ));
}

#[test]
fn oversize_lengths_die_before_allocation_on_every_lane() {
    let cases = [
        (
            Role::Gateway,
            Lane::Ctl,
            KIND_SESSION_TO_GATEWAY,
            MAX_CTL_S2G_LENGTH,
        ),
        (
            Role::Session,
            Lane::Ctl,
            KIND_GATEWAY_TO_SESSION,
            MAX_CTL_G2S_LENGTH,
        ),
        (
            Role::Gateway,
            Lane::Media,
            KIND_VIDEO,
            DEFAULT_MAX_FRAME_BYTES + 21,
        ),
        (Role::Gateway, Lane::Media, KIND_AUDIO, 1_110),
        (Role::Gateway, Lane::Bulk, KIND_TRANSFER_OPEN, 4_200),
        (Role::Session, Lane::Bulk, KIND_TRANSFER_DATA, 65_541),
        (Role::Session, Lane::Bulk, KIND_TRANSFER_END, 5),
        (Role::Session, Lane::Bulk, KIND_TRANSFER_ABORT, 9),
    ];
    for (r, l, kind, max) in cases {
        let mut d = Decoder::new(policy(r, l));
        assert!(
            d.feed(&head(max, kind)).is_ok(),
            "{l:?} {kind:#x} at the limit"
        );
        let mut d = Decoder::new(policy(r, l));
        assert!(
            matches!(
                d.feed(&head(max + 1, kind)),
                Err(FrameError::TooLong { .. })
            ),
            "{l:?} {kind:#x} one over"
        );
    }
    // a 4 GiB length is refused from the prefix alone on a lane that allows 4 MiB
    let mut d = Decoder::new(policy(Role::Gateway, Lane::Media));
    assert!(matches!(
        d.feed(&u32::MAX.to_le_bytes()),
        Err(FrameError::TooLong { .. })
    ));
}

#[test]
fn truncated_unknown_and_zero_length_frames() {
    let wire = frames::encode_transfer_end(5).unwrap();
    for cut in 1..wire.len() {
        let mut d = Decoder::new(policy(Role::Gateway, Lane::Bulk));
        assert!(matches!(
            d.read_from(&mut &wire[..cut]),
            Err(hx_ipc::ReadError::Frame(FrameError::Truncated))
        ));
    }
    assert_eq!(
        Decoder::new(policy(Role::Gateway, Lane::Ctl))
            .feed(&[0; 4])
            .unwrap_err(),
        FrameError::ZeroLength
    );
    assert_eq!(
        Decoder::new(policy(Role::Gateway, Lane::Ctl))
            .feed(&head(2, 0xEE))
            .unwrap_err(),
        FrameError::UnknownKind(0xEE)
    );
}

// ---------- control lane ----------

fn every_gateway_message() -> Vec<pb::gateway_to_session::Message> {
    use pb::gateway_to_session::Message as M;
    let cfg = pb::StreamConfig {
        codec: hx::VideoCodec::H264 as i32,
        max_fps: 60,
        bitrate_cap_kbps: 20_000,
        width: 1920,
        height: 1080,
        scale_percent: 100,
        audio_enabled: false,
        clipboard_enabled: true,
        file_transfer_enabled: true,
    };
    vec![
        M::Start(pb::Start {
            epoch: 1,
            config: Some(cfg),
        }),
        M::Stop(pb::Stop { epoch: 1 }),
        M::Reconfigure(pb::Reconfigure { config: Some(cfg) }),
        M::RequestIdr(pb::RequestIdr {
            epoch: 1,
            last_decoded_frame: 77,
        }),
        M::Input(hx::InputEvent {
            event: Some(hx::input_event::Event::ReleaseAll(hx::ReleaseAll {})),
        }),
        M::Input(hx::InputEvent {
            event: Some(hx::input_event::Event::Key(hx::KeyEvent {
                scancode: 4,
                pressed: true,
            })),
        }),
        M::Mouse(pb::Mouse {
            seq: 9,
            relative: true,
            x: -5,
            y: 6,
        }),
        M::FrameFeedback(pb::FrameFeedback {
            results: [
                pb::FrameOutcome::Delivered,
                pb::FrameOutcome::Cancelled,
                pb::FrameOutcome::Rejected,
                pb::FrameOutcome::Dropped,
            ]
            .into_iter()
            .enumerate()
            .map(|(i, o)| pb::FrameResult {
                frame_number: i as u32,
                outcome: o as i32,
                bytes: 10,
                elapsed_us: 20,
                queued_us: 30,
            })
            .collect(),
        }),
        M::TransportStats(pb::TransportStats {
            rtt_us: 20_000,
            delivery_rate_kbps: 5_000,
        }),
        M::ClientStats(hx::ClientStats {
            interval_ms: 1000,
            decoded_frames: 60,
            dropped_frames: 0,
            decode_p95_us: 4000,
        }),
        M::Ping(pb::Ping { nonce: u64::MAX }),
        M::Goodbye(pb::Goodbye {
            code: 3,
            message: "bye".into(),
        }),
    ]
}

fn every_session_message() -> Vec<pb::session_to_gateway::Message> {
    use pb::session_to_gateway::Message as M;
    let shape = hx::CursorShape {
        id: 1,
        width: 2,
        height: 2,
        hotspot_x: 1,
        hotspot_y: 1,
        rgba: vec![255; 16].into(),
    };
    vec![
        M::Info(pb::Info {
            software: "hx-session 1.0".into(),
            features: validate::FEATURE_CLIPBOARD
                | validate::FEATURE_FILE_TRANSFER
                | validate::FEATURE_INPUT
                | validate::FEATURE_RESIZE,
            codecs: vec![hx::VideoCodec::H264 as i32],
            display: Some(pb::Display {
                width: 1920,
                height: 1080,
            }),
            max_fps: 60,
        }),
        M::StreamFormat(pb::StreamFormat {
            epoch: 1,
            codec: 1,
            width: 1920,
            height: 1080,
            fps: 60,
            first_frame: 12,
        }),
        M::Cursor(hx::CursorEvent {
            event: Some(hx::cursor_event::Event::Shape(shape)),
        }),
        M::Cursor(hx::CursorEvent {
            event: Some(hx::cursor_event::Event::Position(hx::CursorPosition {
                x: 1,
                y: 2,
                shape_id: 1,
                visible: true,
            })),
        }),
        M::CancelFrames(pb::CancelFrames { up_to_frame: 5 }),
        M::Stats(pb::SessionStats {
            interval_ms: 1000,
            captures: 1,
            frames: 2,
            keyframes: 3,
            idr_frames: 4,
            bytes: 5,
            max_frame_bytes: 6,
            errors: 7,
            capture_buffer_waits: 8,
            encode_p50_us: 9,
            encode_p95_us: 10,
            total_p95_us: 11,
            cpu_ms: 12,
            target_bitrate_kbps: 13,
            fps_ceiling: 14,
            queue_depth_max: 15,
        }),
        M::Event(pb::Event {
            kind: pb::EventKind::Fatal as i32,
            message: "x".into(),
        }),
        M::Pong(pb::Pong { nonce: 0 }),
        M::Goodbye(pb::Goodbye {
            code: 1,
            message: String::new(),
        }),
    ]
}

#[test]
fn every_ctl_message_round_trips_in_its_own_direction() {
    for m in every_gateway_message() {
        let msg = pb::GatewayToSession { message: Some(m) };
        let wire = frames::encode_gateway_message(&msg).unwrap();
        match parse_wire(Role::Session, Lane::Ctl, &wire).unwrap() {
            LinkFrame::FromGateway(got) => assert_eq!(got, msg),
            other => panic!("{other:?}"),
        }
        // the gateway never accepts that kind
        assert!(matches!(
            parse_wire(Role::Gateway, Lane::Ctl, &wire),
            Err(FrameError::KindNotAllowed(_))
        ));
    }
    for m in every_session_message() {
        let msg = pb::SessionToGateway { message: Some(m) };
        let wire = frames::encode_session_message(&msg).unwrap();
        match parse_wire(Role::Gateway, Lane::Ctl, &wire).unwrap() {
            LinkFrame::FromSession(got) => assert_eq!(got, msg),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            parse_wire(Role::Session, Lane::Ctl, &wire),
            Err(FrameError::KindNotAllowed(_))
        ));
    }
}

#[test]
fn schema_names_cover_section_14() {
    for n in [
        "FATAL",
        "DISPLAY_CHANGED",
        "CAPTURE_ERROR",
        "CLIPBOARD_ERROR",
        "RESIZE_REFUSED",
    ] {
        assert!(
            pb::EventKind::from_str_name(&format!("EVENT_KIND_{n}")).is_some(),
            "{n}"
        );
    }
    for n in ["DELIVERED", "CANCELLED", "REJECTED", "DROPPED"] {
        assert!(
            pb::FrameOutcome::from_str_name(&format!("FRAME_OUTCOME_{n}")).is_some(),
            "{n}"
        );
    }
    for n in ["CLIPBOARD", "FILE"] {
        assert!(
            pb::TransferChannel::from_str_name(&format!("TRANSFER_CHANNEL_{n}")).is_some(),
            "{n}"
        );
    }
    assert_eq!(validate::FEATURE_AUDIO, 1);
    assert_eq!(validate::FEATURE_RESIZE, 1 << 9);
}

#[test]
fn unknown_variants_and_fields_are_ignored_not_violations() {
    // empty body: no variant set
    let raw = RawFrame {
        kind: KIND_SESSION_TO_GATEWAY,
        body: BytesMut::new(),
    };
    let p = policy(Role::Gateway, Lane::Ctl);
    assert_eq!(
        frames::parse(&p, raw, FILE_MAX).unwrap(),
        LinkFrame::UnknownVariant
    );
    // a oneof variant number this version does not know (field 60, length-delimited)
    let mut body = Vec::new();
    prost::encoding::encode_key(60, prost::encoding::WireType::LengthDelimited, &mut body);
    prost::encoding::encode_varint(2, &mut body);
    body.extend_from_slice(&[1, 2]);
    let raw = RawFrame {
        kind: KIND_SESSION_TO_GATEWAY,
        body: BytesMut::from(&body[..]),
    };
    assert_eq!(
        frames::parse(&p, raw, FILE_MAX).unwrap(),
        LinkFrame::UnknownVariant
    );
    // undecodable bodies are violations
    let raw = RawFrame {
        kind: KIND_SESSION_TO_GATEWAY,
        body: BytesMut::from(&[0xff, 0xff, 0xff][..]),
    };
    assert!(matches!(
        frames::parse(&p, raw, FILE_MAX),
        Err(FrameError::Decode(_))
    ));
}

#[test]
fn ctl_messages_over_the_16_kib_gateway_limit_are_refused_by_the_sender() {
    let big = pb::GatewayToSession {
        message: Some(pb::gateway_to_session::Message::Goodbye(pb::Goodbye {
            code: 1,
            message: "x".repeat(256),
        })),
    };
    assert!(frames::encode_gateway_message(&big).is_ok());
    let too_long = pb::GatewayToSession {
        message: Some(pb::gateway_to_session::Message::Goodbye(pb::Goodbye {
            code: 1,
            message: "x".repeat(300),
        })),
    };
    assert!(
        frames::encode_gateway_message(&too_long).is_err(),
        "string limit"
    );
    let feedback = pb::GatewayToSession {
        message: Some(pb::gateway_to_session::Message::FrameFeedback(
            pb::FrameFeedback {
                results: vec![
                    pb::FrameResult {
                        frame_number: u32::MAX,
                        outcome: 1,
                        bytes: u32::MAX,
                        elapsed_us: u32::MAX,
                        queued_us: u32::MAX
                    };
                    64
                ],
            },
        )),
    };
    let wire = frames::encode_gateway_message(&feedback).unwrap();
    assert!(
        wire.len() as u32 - 4 <= MAX_CTL_G2S_LENGTH,
        "64 results fit comfortably"
    );
}

#[test]
fn message_level_validation() {
    use pb::gateway_to_session::Message as G;
    let ok = |m: G| {
        validate::validate_gateway_message(&pb::GatewayToSession { message: Some(m) }).is_ok()
    };
    let cfg = |f: fn(&mut pb::StreamConfig)| {
        let mut c = pb::StreamConfig {
            codec: 1,
            max_fps: 60,
            bitrate_cap_kbps: 5_000,
            width: 1280,
            height: 720,
            scale_percent: 100,
            ..Default::default()
        };
        f(&mut c);
        c
    };
    assert!(ok(G::Start(pb::Start {
        epoch: 1,
        config: Some(cfg(|_| {}))
    })));
    assert!(!ok(G::Start(pb::Start {
        epoch: 1,
        config: Some(cfg(|c| c.max_fps = 241))
    })));
    assert!(!ok(G::Start(pb::Start {
        epoch: 1,
        config: Some(cfg(|c| c.bitrate_cap_kbps = 99))
    })));
    assert!(!ok(G::Start(pb::Start {
        epoch: 1,
        config: Some(cfg(|c| c.bitrate_cap_kbps = 100_001))
    })));
    assert!(ok(G::Start(pb::Start {
        epoch: 1,
        config: Some(cfg(|c| c.bitrate_cap_kbps = 0))
    })));
    assert!(!ok(G::Reconfigure(pb::Reconfigure {
        config: Some(cfg(|c| c.width = 16_385))
    })));
    assert!(
        !ok(G::Reconfigure(pb::Reconfigure {
            config: Some(cfg(|c| c.height = 0))
        })),
        "one side set, the other zero"
    );
    assert!(ok(G::Reconfigure(pb::Reconfigure {
        config: Some(cfg(|c| {
            c.width = 0;
            c.height = 0;
        }))
    })));
    assert!(!ok(G::Reconfigure(pb::Reconfigure {
        config: Some(cfg(|c| c.scale_percent = 49))
    })));
    assert!(!ok(G::Reconfigure(pb::Reconfigure {
        config: Some(cfg(|c| c.scale_percent = 401))
    })));
    assert!(validate::config_codec_supported(&cfg(|_| {})));
    assert!(!validate::config_codec_supported(&cfg(
        |c| c.codec = hx::VideoCodec::Av1 as i32
    )));
    // input goes through hx-proto's rules (scancode at most 0xE7, known buttons)
    let key = |scancode| {
        G::Input(hx::InputEvent {
            event: Some(hx::input_event::Event::Key(hx::KeyEvent {
                scancode,
                pressed: true,
            })),
        })
    };
    assert!(ok(key(0xE7)));
    assert!(!ok(key(0xE8)));
    assert!(!ok(G::Input(hx::InputEvent { event: None })));
    // feedback: at most 64 results, defined outcomes only
    let fb = |n: usize, outcome| {
        G::FrameFeedback(pb::FrameFeedback {
            results: vec![
                pb::FrameResult {
                    outcome,
                    ..Default::default()
                };
                n
            ],
        })
    };
    assert!(ok(fb(64, 1)));
    assert!(!ok(fb(65, 1)));
    assert!(!ok(fb(1, 0)));
    assert!(!ok(fb(1, 9)));
    assert!(!ok(G::Goodbye(pb::Goodbye {
        code: 1,
        message: "x".repeat(257)
    })));

    use pb::session_to_gateway::Message as S;
    let s_ok = |m: S| {
        validate::validate_session_message(&pb::SessionToGateway { message: Some(m) }).is_ok()
    };
    let info = |f: fn(&mut pb::Info)| {
        let mut i = pb::Info {
            software: "s".into(),
            features: 0,
            codecs: vec![1],
            display: Some(pb::Display {
                width: 800,
                height: 600,
            }),
            max_fps: 60,
        };
        f(&mut i);
        S::Info(i)
    };
    assert!(s_ok(info(|_| {})));
    assert!(s_ok(info(|i| i.software = "x".repeat(128))));
    assert!(!s_ok(info(|i| i.software = "x".repeat(129))));
    assert!(!s_ok(info(|i| i.codecs = vec![1; 5])));
    assert!(s_ok(info(|i| i.max_fps = 240)));
    assert!(!s_ok(info(|i| i.max_fps = 241)));
    assert!(!s_ok(info(|i| i.max_fps = u32::MAX)));
    assert!(!s_ok(info(|i| i.display = None)));
    assert!(!s_ok(info(|i| i.display = Some(pb::Display {
        width: 0,
        height: 10
    }))));
    assert!(!s_ok(info(|i| i.display = Some(pb::Display {
        width: 10,
        height: 16_385
    }))));
    assert!(
        s_ok(info(|i| i.features = u64::MAX)),
        "unknown feature bits are ignored"
    );
    assert!(!s_ok(S::Event(pb::Event {
        kind: 1,
        message: "x".repeat(257)
    })));
    assert!(!s_ok(S::Event(pb::Event {
        kind: 0,
        message: String::new()
    })));
    // cursor shapes: 256 x 256 RGBA is the largest, hotspot inside, exact length
    let cursor = |w: u32, h: u32, len: usize, hx_: u32| {
        S::Cursor(hx::CursorEvent {
            event: Some(hx::cursor_event::Event::Shape(hx::CursorShape {
                id: 1,
                width: w,
                height: h,
                hotspot_x: hx_,
                hotspot_y: 0,
                rgba: vec![0; len].into(),
            })),
        })
    };
    assert!(s_ok(cursor(256, 256, 262_144, 0)));
    assert!(!s_ok(cursor(257, 1, 257 * 4, 0)));
    assert!(!s_ok(cursor(2, 2, 15, 0)));
    assert!(!s_ok(cursor(2, 2, 16, 2)));
}

#[test]
fn a_256_by_256_cursor_fits_the_ctl_limit_and_a_larger_frame_does_not() {
    let shape = hx::CursorShape {
        id: 9,
        width: 256,
        height: 256,
        hotspot_x: 0,
        hotspot_y: 0,
        rgba: vec![7; 262_144].into(),
    };
    let msg = pb::SessionToGateway {
        message: Some(pb::session_to_gateway::Message::Cursor(hx::CursorEvent {
            event: Some(hx::cursor_event::Event::Shape(shape)),
        })),
    };
    let wire = frames::encode_session_message(&msg).unwrap();
    assert!(wire.len() - 4 <= MAX_CTL_S2G_LENGTH as usize);
    assert!(matches!(
        parse_wire(Role::Gateway, Lane::Ctl, &wire).unwrap(),
        LinkFrame::FromSession(_)
    ));
}

// ---------- media lane ----------

#[test]
fn video_frames_round_trip_and_keep_the_body_unchanged() {
    for (payload, flags) in [
        (0usize, 0u16),
        (1, FLAG_KEY),
        (1_000, FLAG_KEY | FLAG_RESYNC),
        (100_000, 0),
    ] {
        let h = video_header(payload as u32, flags, 0xFFFF_FFF0);
        let data: Vec<u8> = (0..payload).map(|i| i as u8).collect();
        let wire = video_wire(&h, &data);
        match parse_wire(Role::Gateway, Lane::Media, &wire).unwrap() {
            LinkFrame::Video(v) => {
                assert_eq!(v.header, h);
                assert_eq!(v.payload(), &data[..]);
                assert_eq!(
                    &v.body[..20],
                    &h.encode().unwrap()[..],
                    "header forwarded unchanged"
                );
                assert_eq!(v.body.len(), 20 + payload);
            }
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn a_frame_of_exactly_the_cap_is_accepted_and_one_more_is_not() {
    let cap = DEFAULT_MAX_FRAME_BYTES as usize;
    let h = video_header(cap as u32, FLAG_KEY, 1);
    let wire = video_wire(&h, &vec![0xAB; cap]);
    assert_eq!(wire.len(), 5 + 20 + cap);
    assert!(matches!(
        parse_wire(Role::Gateway, Lane::Media, &wire).unwrap(),
        LinkFrame::Video(_)
    ));
    // The sender refuses to build it, the receiver refuses its prefix.
    assert!(
        frames::encode_video_prefix(&video_header(cap as u32 + 1, 0, 1), DEFAULT_MAX_FRAME_BYTES)
            .is_err()
    );
    let mut d = Decoder::new(policy(Role::Gateway, Lane::Media));
    assert!(matches!(
        d.feed(&head(DEFAULT_MAX_FRAME_BYTES + 22, KIND_VIDEO)),
        Err(FrameError::TooLong { .. })
    ));
}

#[test]
fn video_header_rules_of_section_15_1() {
    let p = policy(Role::Gateway, Lane::Media);
    let good = video_header(4, FLAG_KEY, 5);
    let enc = good.encode().unwrap();
    let mk = |header: &[u8], payload: &[u8]| {
        let mut body = header.to_vec();
        body.extend_from_slice(payload);
        RawFrame {
            kind: KIND_VIDEO,
            body: BytesMut::from(&body[..]),
        }
    };
    assert!(frames::parse(&p, mk(&enc, &[0; 4]), FILE_MAX).is_ok());
    // payload_len must equal length - 21
    assert!(frames::parse(&p, mk(&enc, &[0; 3]), FILE_MAX).is_err());
    assert!(frames::parse(&p, mk(&enc, &[0; 5]), FILE_MAX).is_err());
    // short header
    assert!(frames::parse(&p, mk(&enc[..19], &[]), FILE_MAX).is_err());
    assert!(frames::parse(&p, mk(&[], &[]), FILE_MAX).is_err());
    // wrong version, unknown codec, reserved flag bits
    let mut bad = enc;
    bad[0] = 2;
    assert!(frames::parse(&p, mk(&bad, &[0; 4]), FILE_MAX).is_err());
    let mut bad = enc;
    bad[1] = 0;
    assert!(frames::parse(&p, mk(&bad, &[0; 4]), FILE_MAX).is_err());
    let mut bad = enc;
    bad[2] |= 0x80;
    assert!(frames::parse(&p, mk(&bad, &[0; 4]), FILE_MAX).is_err());
    // a smaller configured cap rejects a bigger payload even though the length limit allows it
    let small = p.with_max_frame_bytes(2).unwrap();
    assert!(frames::parse(&small, mk(&enc, &[0; 4]), FILE_MAX).is_err());
}

#[test]
fn audio_frames() {
    let wire = frames::encode_audio(7, 9, &[5; 1_100]).unwrap();
    match parse_wire(Role::Gateway, Lane::Media, &wire).unwrap() {
        LinkFrame::Audio(a) => assert_eq!((a.seq, a.timestamp, a.packet.len()), (7, 9, 1_100)),
        other => panic!("{other:?}"),
    }
    assert!(frames::encode_audio(1, 1, &[]).is_err());
    assert!(frames::encode_audio(1, 1, &[0; 1_101]).is_err());
    let p = policy(Role::Gateway, Lane::Media);
    for len in [0usize, 8] {
        let raw = RawFrame {
            kind: KIND_AUDIO,
            body: BytesMut::from(&vec![0u8; len][..]),
        };
        assert!(
            frames::parse(&p, raw, FILE_MAX).is_err(),
            "body of {len} bytes"
        );
    }
}

// ---------- bulk lane ----------

fn open(
    id: u32,
    channel: pb::TransferChannel,
    mime: &str,
    name: &str,
    size: u64,
) -> pb::TransferOpen {
    pb::TransferOpen {
        id,
        channel: channel as i32,
        header: Some(hx::TransferHeader {
            mime: mime.into(),
            name: name.into(),
            size,
        }),
    }
}

#[test]
fn transfer_frames_round_trip() {
    // gateway sends odd ids
    let o = open(
        1,
        pb::TransferChannel::File,
        "application/pdf",
        "report.pdf",
        5_000,
    );
    let wire = frames::encode_transfer_open(Role::Gateway, &o, FILE_MAX).unwrap();
    assert_eq!(
        parse_wire(Role::Session, Lane::Bulk, &wire).unwrap(),
        LinkFrame::TransferOpen(o)
    );
    // session sends even ids
    let o = open(2, pb::TransferChannel::Clipboard, "text/plain", "", 11);
    let wire = frames::encode_transfer_open(Role::Session, &o, FILE_MAX).unwrap();
    assert_eq!(
        parse_wire(Role::Gateway, Lane::Bulk, &wire).unwrap(),
        LinkFrame::TransferOpen(o)
    );

    let mut wire = frames::encode_transfer_data_prefix(3, 5).unwrap().to_vec();
    wire.extend_from_slice(b"hello");
    match parse_wire(Role::Gateway, Lane::Bulk, &wire).unwrap() {
        LinkFrame::TransferData { id, data } => assert_eq!((id, &data[..]), (3, &b"hello"[..])),
        other => panic!("{other:?}"),
    }
    let wire = frames::encode_transfer_end(9).unwrap();
    assert_eq!(
        parse_wire(Role::Session, Lane::Bulk, &wire).unwrap(),
        LinkFrame::TransferEnd { id: 9 }
    );
    let wire = frames::encode_transfer_abort(4, 0x100).unwrap();
    assert_eq!(
        parse_wire(Role::Gateway, Lane::Bulk, &wire).unwrap(),
        LinkFrame::TransferAbort { id: 4, code: 0x100 }
    );
}

#[test]
fn transfer_rules() {
    let v = |sender, o: &pb::TransferOpen, max| {
        validate::validate_transfer_open(o, sender, max).is_ok()
    };
    use Role::{Gateway, Session};
    // id parity: odd from the gateway, even from the session, never 0
    assert!(v(
        Gateway,
        &open(1, pb::TransferChannel::File, "a/b", "f.txt", 1),
        FILE_MAX
    ));
    assert!(!v(
        Gateway,
        &open(2, pb::TransferChannel::File, "a/b", "f.txt", 1),
        FILE_MAX
    ));
    assert!(!v(
        Session,
        &open(1, pb::TransferChannel::File, "a/b", "f.txt", 1),
        FILE_MAX
    ));
    assert!(v(
        Session,
        &open(2, pb::TransferChannel::File, "a/b", "f.txt", 1),
        FILE_MAX
    ));
    assert!(!v(
        Session,
        &open(0, pb::TransferChannel::File, "a/b", "f.txt", 1),
        FILE_MAX
    ));
    // file names are hints under the protocol rules
    for bad in ["", "../x", "a/b", "a\\b", "CON", "x\0y", ".."] {
        assert!(
            !v(
                Gateway,
                &open(1, pb::TransferChannel::File, "a/b", bad, 1),
                FILE_MAX
            ),
            "{bad:?}"
        );
    }
    // mime must be a type/subtype
    assert!(!v(
        Gateway,
        &open(1, pb::TransferChannel::File, "nonsense", "f", 1),
        FILE_MAX
    ));
    assert!(!v(
        Gateway,
        &open(1, pb::TransferChannel::File, "a/b\n", "f", 1),
        FILE_MAX
    ));
    // clipboard: no name, at most 64 MiB; file: at most max_file_bytes
    assert!(v(
        Gateway,
        &open(
            1,
            pb::TransferChannel::Clipboard,
            "text/plain",
            "",
            64 * 1024 * 1024
        ),
        FILE_MAX
    ));
    assert!(!v(
        Gateway,
        &open(
            1,
            pb::TransferChannel::Clipboard,
            "text/plain",
            "",
            64 * 1024 * 1024 + 1
        ),
        FILE_MAX
    ));
    assert!(!v(
        Gateway,
        &open(1, pb::TransferChannel::Clipboard, "text/plain", "n", 1),
        FILE_MAX
    ));
    assert!(v(
        Gateway,
        &open(1, pb::TransferChannel::File, "a/b", "f", 1_000),
        1_000
    ));
    assert!(!v(
        Gateway,
        &open(1, pb::TransferChannel::File, "a/b", "f", 1_001),
        1_000
    ));
    assert!(!v(
        Gateway,
        &open(1, pb::TransferChannel::Unspecified, "a/b", "f", 1),
        FILE_MAX
    ));
    assert!(!v(
        Gateway,
        &pb::TransferOpen {
            id: 1,
            channel: 1,
            header: None
        },
        FILE_MAX
    ));
    // an unknown id parity direction is also enforced on receipt, from the receiver's view
    let o = open(2, pb::TransferChannel::File, "a/b", "f", 1);
    let wire = frames::encode_transfer_open(Role::Session, &o, FILE_MAX).unwrap();
    assert!(
        parse_wire(Role::Session, Lane::Bulk, &wire).is_err(),
        "the session cannot receive an even id: it sent that id space"
    );
}

#[test]
fn transfer_data_end_abort_layouts_are_exact() {
    let p = policy(Role::Gateway, Lane::Bulk);
    let raw = |kind, body: &[u8]| RawFrame {
        kind,
        body: BytesMut::from(body),
    };
    let id = 7u32.to_le_bytes();
    // data: id + 1..=65536 bytes
    assert!(
        frames::parse(
            &p,
            raw(KIND_TRANSFER_DATA, &[id.as_slice(), &[1]].concat()),
            FILE_MAX
        )
        .is_ok()
    );
    assert!(
        frames::parse(&p, raw(KIND_TRANSFER_DATA, &id), FILE_MAX).is_err(),
        "no data"
    );
    assert!(
        frames::parse(
            &p,
            raw(KIND_TRANSFER_DATA, &[id.as_slice(), &[0; 65_536]].concat()),
            FILE_MAX
        )
        .is_ok()
    );
    assert!(
        frames::parse(
            &p,
            raw(KIND_TRANSFER_DATA, &[id.as_slice(), &[0; 65_537]].concat()),
            FILE_MAX
        )
        .is_err()
    );
    assert!(
        frames::parse(&p, raw(KIND_TRANSFER_DATA, &[0, 0, 0, 0, 1]), FILE_MAX).is_err(),
        "id 0"
    );
    assert!(
        frames::parse(&p, raw(KIND_TRANSFER_DATA, &[1, 2]), FILE_MAX).is_err(),
        "short"
    );
    // end: exactly the id
    assert!(frames::parse(&p, raw(KIND_TRANSFER_END, &id), FILE_MAX).is_ok());
    assert!(frames::parse(&p, raw(KIND_TRANSFER_END, &[1, 2, 3]), FILE_MAX).is_err());
    assert!(
        frames::parse(
            &p,
            raw(KIND_TRANSFER_END, &[id.as_slice(), &[0]].concat()),
            FILE_MAX
        )
        .is_err()
    );
    // abort: id + code
    assert!(
        frames::parse(
            &p,
            raw(
                KIND_TRANSFER_ABORT,
                &[id.as_slice(), &[1, 0, 0, 0]].concat()
            ),
            FILE_MAX
        )
        .is_ok()
    );
    assert!(frames::parse(&p, raw(KIND_TRANSFER_ABORT, &id), FILE_MAX).is_err());
    assert!(frames::encode_transfer_data_prefix(1, 0).is_err());
    assert!(frames::encode_transfer_data_prefix(1, 65_537).is_err());
    assert!(frames::encode_transfer_data_prefix(0, 1).is_err());
    assert!(frames::encode_transfer_end(0).is_err());
}

// ---------- properties ----------

proptest! {
    #[test]
    fn mouse_and_ping_round_trip(seq in any::<u32>(), x in any::<i32>(), y in any::<i32>(), rel in any::<bool>(), nonce in any::<u64>()) {
        for m in [
            pb::gateway_to_session::Message::Mouse(pb::Mouse { seq, relative: rel, x, y }),
            pb::gateway_to_session::Message::Ping(pb::Ping { nonce }),
        ] {
            let msg = pb::GatewayToSession { message: Some(m) };
            let wire = frames::encode_gateway_message(&msg).unwrap();
            match parse_wire(Role::Session, Lane::Ctl, &wire).unwrap() {
                LinkFrame::FromGateway(got) => prop_assert_eq!(got, msg),
                _ => prop_assert!(false),
            }
        }
    }

    #[test]
    fn video_round_trips_for_any_payload(
        payload in proptest::collection::vec(any::<u8>(), 0..2_000),
        number in any::<u32>(), ts in any::<u64>(), key in any::<bool>(), resync in any::<bool>(),
    ) {
        let flags = if key { FLAG_KEY } else { 0 } | if resync { FLAG_RESYNC } else { 0 };
        let h = MediaHeader { codec: hx_proto::VideoCodec::H264, flags, frame_number: number, capture_timestamp_us: ts, payload_len: payload.len() as u32 };
        let wire = video_wire(&h, &payload);
        match parse_wire(Role::Gateway, Lane::Media, &wire).unwrap() {
            LinkFrame::Video(v) => { prop_assert_eq!(v.header, h); prop_assert_eq!(v.payload(), &payload[..]); }
            _ => prop_assert!(false),
        }
    }

    #[test]
    fn transfer_data_round_trips(id in 1u32.., data in proptest::collection::vec(any::<u8>(), 1..3_000)) {
        let mut wire = frames::encode_transfer_data_prefix(id, data.len()).unwrap().to_vec();
        wire.extend_from_slice(&data);
        match parse_wire(Role::Session, Lane::Bulk, &wire).unwrap() {
            LinkFrame::TransferData { id: got, data: d } => { prop_assert_eq!(got, id); prop_assert_eq!(&d[..], &data[..]); }
            _ => prop_assert!(false),
        }
    }

    #[test]
    fn abort_round_trips(id in 1u32.., code in any::<u32>()) {
        let wire = frames::encode_transfer_abort(id, code).unwrap();
        prop_assert_eq!(parse_wire(Role::Gateway, Lane::Bulk, &wire).unwrap(), LinkFrame::TransferAbort { id, code });
    }

    /// Arbitrary bytes on any lane, in either direction, never panic and never yield a frame
    /// beyond the lane's limits.
    #[test]
    fn arbitrary_lane_input_is_total(data in proptest::collection::vec(any::<u8>(), 0..600), lane in 0u8..3, gw in any::<bool>()) {
        let lane = [Lane::Ctl, Lane::Media, Lane::Bulk][lane as usize];
        let role = if gw { Role::Gateway } else { Role::Session };
        let p = policy(role, lane);
        let mut d = Decoder::new(p);
        let mut rest = &data[..];
        while !rest.is_empty() {
            match d.feed(rest) {
                Ok((used, f)) => {
                    rest = &rest[used..];
                    if let Some(f) = f {
                        prop_assert!((f.body.len() as u32) < p.absolute_max_length());
                        let _ = frames::parse(&p, f, FILE_MAX);
                    }
                }
                Err(_) => break,
            }
        }
    }
}
