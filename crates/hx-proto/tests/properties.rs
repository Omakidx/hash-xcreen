//! Property tests: every message round-trips, decoders are total, windows keep their invariants.

use bytes::Bytes;
use hx_proto::{
    ProtoError, VideoCodec,
    channel::{ChannelId, CloseCode, MAX_CURSOR_MESSAGE, MAX_DEVICE_NAME, MAX_FILE_SIZE},
    datagram::{
        AudioPacket, Datagram, MAX_AUDIO_PAYLOAD, MouseCoalescer, MouseMove, decode_datagram,
    },
    media::{FLAGS_KNOWN, MAX_VIDEO_PAYLOAD, MEDIA_HEADER_LEN, MediaHeader},
    message::{self, Wire, device_name_problem, sanitize_device_name},
    order::{ReorderWindow, serial_gt},
    pb::{
        self, ControlMessage, CursorEvent, InputEvent, TransferHeader,
        control_message::Message as Ctl, cursor_event::Event as Cur, input_event::Event as Inp,
    },
    version::{Features, ProtocolVersion, negotiate, peek_hello_version},
};
use proptest::prelude::*;

// ---------------------------------------------------------------- strategies

fn text(max: usize) -> impl Strategy<Value = String> {
    proptest::collection::vec(any::<char>(), 0..=max / 4).prop_map(|v| {
        // Keep the byte length within `max` (a char is at most 4 bytes).
        v.into_iter().filter(|c| *c != '\0').collect()
    })
}

fn codec() -> impl Strategy<Value = i32> {
    prop_oneof![Just(1i32), Just(2), Just(3)]
}

fn version() -> impl Strategy<Value = pb::Version> {
    (any::<u32>(), any::<u32>()).prop_map(|(major, minor)| pb::Version { major, minor })
}

fn caps() -> impl Strategy<Value = pb::Capabilities> {
    (
        proptest::collection::vec(codec(), 0..=8),
        any::<u64>(),
        prop_oneof![Just(0u64), 1u64..=MAX_FILE_SIZE],
    )
        .prop_map(
            |(video_codecs, features, max_file_bytes)| pb::Capabilities {
                video_codecs,
                features,
                max_file_bytes,
            },
        )
}

fn device_id() -> impl Strategy<Value = Bytes> {
    proptest::collection::vec(any::<u8>(), 16..=16).prop_map(Bytes::from)
}

/// A valid `DeviceInfo`: a sanitised name, and a revocation only on revoked devices.
fn device_info() -> impl Strategy<Value = pb::DeviceInfo> {
    (
        device_id(),
        any::<String>(),
        (any::<u64>(), any::<u64>()),
        prop_oneof![
            Just((1i32, 0i32, 0u64)),
            (1i32..=2, any::<u64>()).prop_map(|(r, t)| (2i32, r, t)),
        ],
        any::<bool>(),
    )
        .prop_map(
            |(
                device_id,
                name,
                (created_unix, last_seen_unix),
                (status, revoke_reason, revoked_unix),
                current,
            )| {
                pb::DeviceInfo {
                    device_id,
                    name: sanitize_device_name(&name),
                    created_unix,
                    last_seen_unix,
                    status,
                    revoke_reason,
                    revoked_unix,
                    current,
                }
            },
        )
}

fn device_mgmt() -> impl Strategy<Value = pb::DeviceMgmt> {
    use pb::device_mgmt::Body as B;
    let id = 1u32..=u32::MAX;
    prop_oneof![
        id.clone().prop_map(|request_id| pb::DeviceMgmt {
            request_id,
            body: Some(B::List(pb::ListDevices {})),
        }),
        (id.clone(), device_id()).prop_map(|(request_id, device_id)| pb::DeviceMgmt {
            request_id,
            body: Some(B::Revoke(pb::RevokeDevice { device_id })),
        }),
        (id.clone(), 1i32..=6).prop_map(|(request_id, status)| pb::DeviceMgmt {
            request_id,
            body: Some(B::RevokeResult(pb::RevokeResult { status })),
        }),
        (
            id,
            proptest::collection::vec(device_info(), 0..=8),
            any::<bool>()
        )
            .prop_map(|(request_id, mut devices, truncated)| {
                // At most one device is "current".
                for d in devices.iter_mut().skip(1) {
                    d.current = false;
                }
                pb::DeviceMgmt {
                    request_id,
                    body: Some(B::DeviceList(pb::DeviceList { devices, truncated })),
                }
            }),
        (
            1i32..=3,
            device_info(),
            prop_oneof![Just(Bytes::new()), device_id()]
        )
            .prop_map(|(kind, device, by_device_id)| pb::DeviceMgmt {
                request_id: 0,
                body: Some(B::Event(pb::DeviceEvent {
                    kind,
                    device: Some(device),
                    by_device_id,
                })),
            }),
    ]
}

fn server_stats() -> impl Strategy<Value = pb::ServerStats> {
    (
        1u32..=60_000,
        0u32..=240,
        proptest::collection::vec(any::<u32>(), 9..=9),
    )
        .prop_map(|(interval_ms, fps_ceiling, v)| pb::ServerStats {
            interval_ms,
            frames: v[0],
            keyframes: v[1],
            dropped_frames: v[2],
            bitrate_kbps: v[3],
            target_bitrate_kbps: v[4],
            fps_ceiling,
            encode_p95_us: v[5],
            total_p95_us: v[6],
            queue_depth_max: v[7],
            rtt_us: v[8],
        })
}

fn control() -> impl Strategy<Value = ControlMessage> {
    let hello = (
        version(),
        proptest::option::of(caps()),
        1i32..=2,
        text(128),
        text(64),
    )
        .prop_map(|(version, capabilities, intent, software, device_name)| {
            Ctl::Hello(pb::Hello {
                version: Some(version),
                capabilities,
                intent,
                software,
                device_name,
            })
        });
    let ack = (
        version(),
        proptest::option::of(caps()),
        proptest::collection::vec(any::<u8>(), 16),
        text(128),
    )
        .prop_map(|(version, capabilities, sid, software)| {
            Ctl::HelloAck(pb::HelloAck {
                version: Some(version),
                capabilities,
                session_id: Bytes::from(sid),
                software,
            })
        });
    let refuse = (1i32..=4, text(256), proptest::option::of(version())).prop_map(
        |(reason, message, version)| {
            Ctl::Refuse(pb::Refuse {
                reason,
                message,
                version,
            })
        },
    );
    let view = (
        prop_oneof![Just(0i32), codec()],
        0u32..=240,
        any::<u32>(),
        prop_oneof![Just((0u32, 0u32)), (1u32..=16384, 1u32..=16384)],
        prop_oneof![Just(0u32), 50u32..=400],
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(
            |(codec, max_fps, bandwidth_cap_kbps, (width, height), scale_percent, a, c, st)| {
                Ctl::ViewConfig(pb::ViewConfig {
                    codec,
                    max_fps,
                    bandwidth_cap_kbps,
                    width,
                    height,
                    scale_percent,
                    audio_enabled: a,
                    clipboard_enabled: c,
                    stats_enabled: st,
                })
            },
        );
    let info = (
        codec(),
        1u32..=16384,
        1u32..=16384,
        0u32..=240,
        any::<u32>(),
    )
        .prop_map(|(codec, width, height, fps, first_frame)| {
            Ctl::StreamInfo(pb::StreamInfo {
                codec,
                width,
                height,
                fps,
                first_frame,
            })
        });
    let misc = prop_oneof![
        any::<u32>().prop_map(|v| Ctl::RequestKeyframe(pb::RequestKeyframe {
            last_decoded_frame: v
        })),
        any::<u64>().prop_map(|nonce| Ctl::Ping(pb::Ping { nonce })),
        any::<u64>().prop_map(|nonce| Ctl::Pong(pb::Pong { nonce })),
        (any::<u32>(), any::<u32>(), any::<u32>(), any::<u32>()).prop_map(|(a, b, c, d)| {
            Ctl::Stats(pb::ClientStats {
                interval_ms: a,
                decoded_frames: b,
                dropped_frames: c,
                decode_p95_us: d,
            })
        }),
        (any::<u32>(), text(256)).prop_map(|(code, message)| Ctl::Goodbye(pb::Goodbye {
            code,
            message,
            ..Default::default()
        })),
        (
            any::<u32>(),
            any::<String>(),
            prop_oneof![
                Just(Vec::new()),
                proptest::collection::vec(any::<u8>(), 16..=16)
            ],
        )
            .prop_map(|(code, name, id)| Ctl::Goodbye(pb::Goodbye {
                code,
                message: String::new(),
                peer_device_name: sanitize_device_name(&name),
                peer_device_id: Bytes::from(id),
            })),
        server_stats().prop_map(Ctl::ServerStats),
        device_mgmt().prop_map(Ctl::DeviceMgmt),
        proptest::collection::vec(any::<u8>(), 0..=4096).prop_map(|d| Ctl::Pairing(pb::Opaque {
            data: Bytes::from(d)
        })),
        proptest::collection::vec(any::<u8>(), 0..=4096).prop_map(|d| Ctl::Auth(pb::Opaque {
            data: Bytes::from(d)
        })),
    ];
    prop_oneof![hello, ack, refuse, view, info, misc].prop_map(ControlMessage::new)
}

fn input() -> impl Strategy<Value = InputEvent> {
    let key = (0u32..=0xE7, any::<bool>())
        .prop_map(|(scancode, pressed)| Inp::Key(pb::KeyEvent { scancode, pressed }));
    let button = (1i32..=5, any::<bool>(), any::<i32>(), any::<i32>()).prop_map(
        |(button, pressed, x, y)| {
            Inp::Button(pb::ButtonEvent {
                button,
                pressed,
                x,
                y,
            })
        },
    );
    let scroll =
        (any::<i32>(), any::<i32>()).prop_map(|(dx, dy)| Inp::Scroll(pb::ScrollEvent { dx, dy }));
    prop_oneof![
        key,
        button,
        scroll,
        Just(Inp::ReleaseAll(pb::ReleaseAll {}))
    ]
    .prop_map(|e| InputEvent { event: Some(e) })
}

fn cursor() -> impl Strategy<Value = CursorEvent> {
    let shape = (any::<u64>(), 1u32..=16, 1u32..=16).prop_flat_map(|(id, w, h)| {
        (
            Just((id, w, h)),
            0..w,
            0..h,
            proptest::collection::vec(any::<u8>(), (w * h * 4) as usize),
        )
    });
    let shape = shape.prop_map(|((id, width, height), hotspot_x, hotspot_y, rgba)| {
        Cur::Shape(pb::CursorShape {
            id,
            width,
            height,
            hotspot_x,
            hotspot_y,
            rgba: Bytes::from(rgba),
        })
    });
    let pos = (any::<i32>(), any::<i32>(), any::<u64>(), any::<bool>()).prop_map(
        |(x, y, shape_id, visible)| {
            Cur::Position(pb::CursorPosition {
                x,
                y,
                shape_id,
                visible,
            })
        },
    );
    prop_oneof![shape, pos].prop_map(|e| CursorEvent { event: Some(e) })
}

fn transfer() -> impl Strategy<Value = TransferHeader> {
    let name = "f[a-z0-9_-]{0,40}(\\.[a-z]{1,4})?";
    (
        "[a-z]{1,8}/[a-z0-9.+-]{1,8}(;[a-z]+=[a-z0-9-]+)?",
        name,
        any::<u64>(),
    )
        .prop_map(|(mime, name, size)| TransferHeader { mime, name, size })
}

fn media_header() -> impl Strategy<Value = MediaHeader> {
    (
        codec(),
        0u16..=FLAGS_KNOWN,
        any::<u32>(),
        any::<u64>(),
        0u32..=MAX_VIDEO_PAYLOAD,
    )
        .prop_map(
            |(c, flags, frame_number, capture_timestamp_us, payload_len)| MediaHeader {
                codec: VideoCodec::try_from(c).expect("strategy yields defined codecs"),
                flags,
                frame_number,
                capture_timestamp_us,
                payload_len,
            },
        )
}

fn assert_roundtrip<M: Wire + PartialEq + std::fmt::Debug>(m: &M) -> Result<(), TestCaseError> {
    let enc = message::encode(m).expect("valid message encodes");
    prop_assert_eq!(&message::decode::<M>(&enc).expect("decodes"), m);
    let framed = message::encode_framed(m).expect("frames");
    let (back, rest) = message::decode_framed::<M>(&framed).expect("framed decodes");
    prop_assert_eq!(&back, m);
    prop_assert!(rest.is_empty());
    Ok(())
}

// ---------------------------------------------------------------- round trips

proptest! {
    #[test]
    fn control_roundtrip(m in control()) { assert_roundtrip(&m)?; }

    #[test]
    fn input_roundtrip(m in input()) { assert_roundtrip(&m)?; }

    #[test]
    fn cursor_roundtrip(m in cursor()) { assert_roundtrip(&m)?; }

    #[test]
    fn transfer_roundtrip(m in transfer()) { assert_roundtrip(&m)?; }

    #[test]
    fn media_header_roundtrip(h in media_header()) {
        let enc = h.encode().expect("valid header");
        prop_assert_eq!(enc.len(), MEDIA_HEADER_LEN);
        prop_assert_eq!(MediaHeader::decode(&enc).expect("decodes"), h);
    }

    #[test]
    fn media_frame_roundtrip(mut h in media_header(), payload in proptest::collection::vec(any::<u8>(), 0..512)) {
        h.payload_len = payload.len() as u32;
        let mut buf = h.encode().expect("valid").to_vec();
        buf.extend_from_slice(&payload);
        let (back, body) = MediaHeader::decode_frame(&buf).expect("frame decodes");
        prop_assert_eq!(back, h);
        prop_assert_eq!(body, &payload[..]);
    }

    #[test]
    fn mouse_roundtrip(relative in any::<bool>(), seq in any::<u32>(), x in any::<i32>(), y in any::<i32>()) {
        let m = MouseMove { relative, seq, x, y };
        prop_assert_eq!(decode_datagram(&m.encode()), Ok(Datagram::MouseMove(m)));
    }

    #[test]
    fn audio_roundtrip(seq in any::<u32>(), ts in any::<u32>(), p in proptest::collection::vec(any::<u8>(), 1..=MAX_AUDIO_PAYLOAD)) {
        let a = AudioPacket { seq, timestamp: ts, payload: Bytes::from(p) };
        let enc = a.encode().expect("encodes");
        prop_assert_eq!(decode_datagram(&enc), Ok(Datagram::Audio(a)));
    }

    #[test]
    fn hello_version_is_peekable(m in control()) {
        let enc = message::encode(&m).expect("encodes");
        let expect = match &m.message {
            Some(Ctl::Hello(h)) => h.version.as_ref().map(ProtocolVersion::from),
            _ => None,
        };
        prop_assert_eq!(peek_hello_version(&enc), expect);
    }
}

// ---------------------------------------------------------------- totality and negatives

proptest! {
    /// Arbitrary bytes never panic any decoder; accepted output re-encodes and decodes equal.
    #[test]
    fn decoders_are_total(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = MediaHeader::decode(&bytes);
        let _ = MediaHeader::decode_frame(&bytes);
        let _ = decode_datagram(&bytes);
        let _ = peek_hello_version(&bytes);
        let _ = message::decode_framed::<ControlMessage>(&bytes);
        if let Ok(m) = message::decode::<ControlMessage>(&bytes) {
            let again = message::encode(&m).expect("accepted message re-encodes");
            prop_assert_eq!(message::decode::<ControlMessage>(&again).expect("decodes"), m);
        }
        if let Ok(m) = message::decode::<InputEvent>(&bytes) {
            prop_assert!(message::encode(&m).is_ok());
        }
        if let Ok(m) = message::decode::<CursorEvent>(&bytes) {
            prop_assert!(message::encode(&m).is_ok());
        }
        if let Ok(m) = message::decode::<TransferHeader>(&bytes) {
            prop_assert!(message::encode(&m).is_ok());
        }
    }

    /// Any prefix of a valid header is rejected as truncated; any extension as trailing bytes.
    #[test]
    fn media_header_wrong_lengths(h in media_header(), cut in 0usize..MEDIA_HEADER_LEN, extra in 1usize..64) {
        let enc = h.encode().expect("valid");
        let ok = matches!(MediaHeader::decode(&enc[..cut]), Err(ProtoError::Truncated { .. }));
        prop_assert!(ok);
        let mut longer = enc.to_vec();
        longer.extend(std::iter::repeat_n(0u8, extra));
        let ok = matches!(MediaHeader::decode(&longer), Err(ProtoError::TrailingBytes { .. }));
        prop_assert!(ok);
    }

    #[test]
    fn media_header_rejects_bad_fields(h in media_header(), bad_ver in 2u8..=255, bad_codec in 4u8..=255, bad_flags in 4u16..=u16::MAX) {
        let enc = h.encode().expect("valid");
        let mut b = enc;
        b[0] = bad_ver;
        prop_assert_eq!(MediaHeader::decode(&b), Err(ProtoError::UnsupportedVersion(bad_ver)));
        let mut b = enc;
        b[1] = bad_codec;
        prop_assert_eq!(MediaHeader::decode(&b), Err(ProtoError::UnknownCodec(bad_codec)));
        let mut b = enc;
        b[2..4].copy_from_slice(&bad_flags.to_le_bytes());
        if bad_flags & !FLAGS_KNOWN != 0 {
            let ok = matches!(MediaHeader::decode(&b), Err(ProtoError::ReservedFlags(_)));
            prop_assert!(ok);
        }
    }

    #[test]
    fn media_header_rejects_oversized_payload(h in media_header(), len in (MAX_VIDEO_PAYLOAD + 1)..=u32::MAX) {
        let mut b = h.encode().expect("valid");
        b[16..20].copy_from_slice(&len.to_le_bytes());
        let is_too_large = matches!(MediaHeader::decode(&b), Err(ProtoError::TooLarge { .. }));
        prop_assert!(is_too_large);
    }

    #[test]
    fn framed_truncation_is_an_error(m in input(), cut in 0usize..1) {
        let framed = message::encode_framed(&m).expect("frames");
        let n = framed.len().saturating_sub(1 + cut);
        prop_assert!(message::decode_framed::<InputEvent>(&framed[..n]).is_err());
    }
}

#[test]
fn media_header_edge_cases() {
    let good = MediaHeader {
        codec: VideoCodec::H264,
        flags: 0,
        frame_number: 1,
        capture_timestamp_us: 2,
        payload_len: 3,
    };
    let enc = good.encode().expect("valid");
    // Layout is the documented one.
    assert_eq!(enc[0], 1);
    assert_eq!(enc[1], 1);
    assert_eq!(&enc[4..8], &1u32.to_le_bytes());
    assert_eq!(&enc[8..16], &2u64.to_le_bytes());
    assert_eq!(&enc[16..20], &3u32.to_le_bytes());
    assert_eq!(
        MediaHeader::decode(&[]),
        Err(ProtoError::Truncated { need: 20, have: 0 })
    );
    let mut zero_codec = enc;
    zero_codec[1] = 0;
    assert_eq!(
        MediaHeader::decode(&zero_codec),
        Err(ProtoError::UnknownCodec(0))
    );
    // Frame body shorter or longer than payload_len.
    let mut short = enc.to_vec();
    short.extend_from_slice(&[0, 0]);
    assert!(matches!(
        MediaHeader::decode_frame(&short),
        Err(ProtoError::Truncated { .. })
    ));
    short.extend_from_slice(&[0, 0]);
    assert!(matches!(
        MediaHeader::decode_frame(&short),
        Err(ProtoError::TrailingBytes { extra: 1 })
    ));
    // Encoding an invalid header fails instead of producing something undecodable.
    let bad = MediaHeader {
        payload_len: MAX_VIDEO_PAYLOAD + 1,
        ..good
    };
    assert!(bad.encode().is_err());
    let bad = MediaHeader {
        flags: 0x8000,
        ..good
    };
    assert!(bad.encode().is_err());
    let bad = MediaHeader {
        codec: VideoCodec::Unspecified,
        ..good
    };
    assert!(bad.encode().is_err());
}

#[test]
fn malformed_messages_are_rejected() {
    // Empty envelope.
    assert!(matches!(
        message::decode::<ControlMessage>(&[]),
        Err(ProtoError::Empty { .. })
    ));
    assert!(message::encode(&ControlMessage { message: None }).is_err());
    // Hello without version, with bad intent, with oversized strings.
    let hello = |version: Option<pb::Version>, intent: i32, software: String| {
        ControlMessage::new(Ctl::Hello(pb::Hello {
            version,
            capabilities: None,
            intent,
            software,
            device_name: String::new(),
        }))
    };
    let v = Some(pb::Version { major: 1, minor: 0 });
    assert!(hello(None, 1, String::new()).validate().is_err());
    assert!(hello(v, 0, String::new()).validate().is_err());
    assert!(hello(v, 5, String::new()).validate().is_err());
    assert!(hello(v, 4, String::new()).validate().is_ok());
    assert!(
        hello(v, 3, String::new()).validate().is_ok(),
        "INTENT_SETUP exists from 1.3"
    );
    assert!(hello(v, 1, "x".repeat(129)).validate().is_err());
    assert!(hello(v, 1, "x".repeat(128)).validate().is_ok());
    // Unknown codec in capabilities.
    let caps = pb::Capabilities {
        video_codecs: vec![99],
        features: 0,
        max_file_bytes: 0,
    };
    let m = ControlMessage::new(Ctl::Hello(pb::Hello {
        version: v,
        capabilities: Some(caps),
        intent: 1,
        software: String::new(),
        device_name: String::new(),
    }));
    assert!(m.validate().is_err());
    // ViewConfig constraints.
    let view = |width, height, scale_percent, max_fps| {
        ControlMessage::new(Ctl::ViewConfig(pb::ViewConfig {
            width,
            height,
            scale_percent,
            max_fps,
            ..Default::default()
        }))
    };
    assert!(view(1920, 0, 0, 0).validate().is_err());
    assert!(view(0, 0, 49, 0).validate().is_err());
    assert!(view(0, 0, 401, 0).validate().is_err());
    assert!(view(0, 0, 0, 241).validate().is_err());
    assert!(view(16385, 10, 0, 0).validate().is_err());
    assert!(view(1920, 1080, 200, 60).validate().is_ok());
    // Input.
    let key = |scancode| InputEvent {
        event: Some(Inp::Key(pb::KeyEvent {
            scancode,
            pressed: true,
        })),
    };
    assert!(key(0xE8).validate().is_err());
    assert!(key(0xE7).validate().is_ok());
    assert!(InputEvent { event: None }.validate().is_err());
    let btn = |button| InputEvent {
        event: Some(Inp::Button(pb::ButtonEvent {
            button,
            pressed: true,
            x: 0,
            y: 0,
        })),
    };
    assert!(btn(0).validate().is_err());
    assert!(btn(6).validate().is_err());
    // Cursor shape.
    let shape = |w, h, len: usize, hx, hy| CursorEvent {
        event: Some(Cur::Shape(pb::CursorShape {
            id: 1,
            width: w,
            height: h,
            hotspot_x: hx,
            hotspot_y: hy,
            rgba: Bytes::from(vec![0u8; len]),
        })),
    };
    assert!(shape(2, 2, 16, 1, 1).validate().is_ok());
    assert!(shape(2, 2, 15, 0, 0).validate().is_err());
    assert!(shape(0, 2, 0, 0, 0).validate().is_err());
    assert!(shape(257, 1, 257 * 4, 0, 0).validate().is_err());
    assert!(shape(2, 2, 16, 2, 0).validate().is_err());
    // Transfer header names.
    assert!(
        TransferHeader {
            mime: String::new(),
            name: String::new(),
            size: 0
        }
        .validate()
        .is_err()
    );
    let t = |name: &str| TransferHeader {
        mime: "x/y".into(),
        name: name.into(),
        size: 1,
    };
    assert!(t("a.txt").validate().is_ok());
    assert!(t("../a").validate().is_err());
    assert!(t("a\\b").validate().is_err());
    assert!(t("a\0b").validate().is_err());
    for bad in [
        ".",
        "..",
        "a:b",
        "C:",
        "a\u{1}b",
        "a\u{7f}b",
        "a\u{85}b",
        "a\u{202E}txt.exe",
        "a\u{2066}b",
        "a\u{2069}",
        "name.",
        "name ",
        "CON",
        "con",
        "Nul.txt",
        "aux.tar.gz",
        "COM1",
        "lpt9.log",
        "COM1 .txt",
    ] {
        assert!(t(bad).validate().is_err(), "{bad:?} must be rejected");
    }
    for bad in [
        "CONIN$",
        "conout$",
        "COM\u{B9}",
        "LPT\u{B2}.txt",
        "COM\u{B3}",
        "a\u{200B}b",
        "a\u{200D}",
        "\u{FEFF}a",
        "a\u{2060}b",
        "a\u{180E}",
    ] {
        assert!(t(bad).validate().is_err(), "{bad:?} must be rejected");
    }
    for ok in [
        "a.txt",
        "...hidden",
        ".bashrc",
        "CONSOLE",
        "COM10",
        "COM0",
        "LPT",
        "report v2.pdf",
        "naïve.txt",
        "日本語.txt",
    ] {
        assert!(t(ok).validate().is_ok(), "{ok:?} must be accepted");
    }
    assert!(t(&"n".repeat(256)).validate().is_err());
    let clip = TransferHeader {
        mime: "text/plain".into(),
        name: String::new(),
        size: 64 * 1024 * 1024 + 1,
    };
    assert!(clip.validate_clipboard().is_err());
    // Media types.
    let m = |mime: &str| TransferHeader {
        mime: mime.into(),
        name: String::new(),
        size: 1,
    };
    for ok in [
        "text/plain",
        "text/plain;charset=utf-8",
        "image/png",
        "application/vnd.x+json",
        "text/uri-list",
    ] {
        assert!(m(ok).validate().is_ok(), "{ok:?}");
    }
    for bad in [
        "",
        "text",
        "/plain",
        "text/",
        "text/pl ain",
        "a/b/c",
        "te\nxt/plain",
        "text/plain;\u{1}",
        "tëxt/plain",
        "text/plain;é",
        "te(xt/plain",
    ] {
        assert!(m(bad).validate().is_err(), "{bad:?}");
    }
    assert!(
        m(&"a/b;".repeat(80)).validate().is_err(),
        "mime above 255 bytes"
    );
    // Opaque envelope limit.
    let big = ControlMessage::new(Ctl::Pairing(pb::Opaque {
        data: Bytes::from(vec![0u8; 4097]),
    }));
    assert!(big.validate().is_err());
    // Framing: zero length and oversized length.
    assert!(message::decode_framed::<InputEvent>(&[0, 0, 0, 0]).is_err());
    assert!(message::decode_framed::<InputEvent>(&u32::MAX.to_le_bytes()).is_err());
    assert!(message::decode_framed::<InputEvent>(&[1, 0, 0]).is_err());
    assert!(message::decode::<CursorEvent>(&vec![0u8; MAX_CURSOR_MESSAGE + 1]).is_err());
    // Garbage protobuf.
    assert!(matches!(
        message::decode::<ControlMessage>(&[0xff, 0xff, 0xff]),
        Err(ProtoError::Decode(_))
    ));
}

#[test]
fn datagram_negatives() {
    assert!(matches!(
        decode_datagram(&[]),
        Err(ProtoError::Truncated { .. })
    ));
    assert_eq!(
        decode_datagram(&[0x7f]),
        Err(ProtoError::UnknownChannel(0x7f))
    );
    // Non-datagram channel.
    assert!(decode_datagram(&[ChannelId::Video as u8, 0, 0]).is_err());
    // Mouse: wrong length and reserved flags.
    let enc = MouseMove {
        relative: false,
        seq: 1,
        x: 2,
        y: 3,
    }
    .encode();
    assert!(matches!(
        decode_datagram(&enc[..13]),
        Err(ProtoError::Truncated { .. })
    ));
    let mut longer = enc.to_vec();
    longer.push(0);
    assert!(matches!(
        decode_datagram(&longer),
        Err(ProtoError::TrailingBytes { .. })
    ));
    let mut flags = enc;
    flags[1] = 0x02;
    assert!(matches!(
        decode_datagram(&flags),
        Err(ProtoError::ReservedFlags(_))
    ));
    // Audio: header only (empty payload), oversized payload.
    assert!(decode_datagram(&[ChannelId::Audio as u8; 9]).is_err());
    assert!(decode_datagram(&[ChannelId::Audio as u8; 5]).is_err());
    let mut big = vec![ChannelId::Audio as u8; 9];
    big.extend(std::iter::repeat_n(1u8, MAX_AUDIO_PAYLOAD + 1));
    assert!(matches!(
        decode_datagram(&big),
        Err(ProtoError::TooLarge { .. })
    ));
    assert!(
        AudioPacket {
            seq: 0,
            timestamp: 0,
            payload: Bytes::new()
        }
        .encode()
        .is_err()
    );
    assert!(
        AudioPacket {
            seq: 0,
            timestamp: 0,
            payload: Bytes::from(vec![0u8; MAX_AUDIO_PAYLOAD + 1])
        }
        .encode()
        .is_err()
    );
}

#[test]
fn close_codes_roundtrip() {
    for c in [
        CloseCode::NoError,
        CloseCode::ProtocolError,
        CloseCode::UpdateRequired,
        CloseCode::HelloTimeout,
        CloseCode::Unauthorized,
        CloseCode::Busy,
        CloseCode::PairingClosed,
        CloseCode::Shutdown,
        CloseCode::InternalError,
        CloseCode::TakenOver,
        CloseCode::SetupClosed,
    ] {
        assert_eq!(CloseCode::from_code(u64::from(c.code())), c);
        assert_eq!(CloseCode::from_websocket_code(c.websocket_code()), Some(c));
    }
    assert_eq!(CloseCode::from_code(12345), CloseCode::InternalError);
    assert_eq!(CloseCode::TakenOver.code(), 9);
    assert_eq!(CloseCode::TakenOver.websocket_code(), 4009);
    // Codes after the defined ones are unknown, not aliases of TakenOver.
    assert_eq!(CloseCode::from_code(11), CloseCode::InternalError);
    assert_eq!(CloseCode::from_websocket_code(1000), None);
    assert!(ChannelId::from_u8(0).is_err());
}

// ---------------------------------------------------------------- negotiation

proptest! {
    #[test]
    fn negotiation_is_symmetric_and_bounded(
        sv in (0u32..4, 0u32..6), cv in (0u32..4, 0u32..6), sc in caps(), cc in caps(),
    ) {
        let sv = ProtocolVersion { major: sv.0, minor: sv.1 };
        let cv = ProtocolVersion { major: cv.0, minor: cv.1 };
        let r = negotiate(sv, &sc, cv, &cc);
        if sv.major != cv.major {
            prop_assert!(r.is_err());
        } else {
            let n = r.expect("same major negotiates");
            prop_assert_eq!(n.version.minor, sv.minor.min(cv.minor));
            prop_assert!(Features(sc.features).contains(n.features));
            prop_assert!(Features(cc.features).contains(n.features));
            prop_assert!(Features::defined_up_to(n.version.minor).contains(n.features));
            for c in &n.codecs {
                prop_assert!(sc.video_codecs.contains(&(*c as i32)));
                prop_assert!(cc.video_codecs.contains(&(*c as i32)));
            }
            let mut seen = n.codecs.clone();
            seen.dedup();
            prop_assert_eq!(seen.len(), n.codecs.len());
        }
    }
}

#[test]
fn negotiation_examples() {
    let both =
        hx_proto::version::capabilities(&[VideoCodec::Av1, VideoCodec::H264], Features::AUDIO);
    let client = hx_proto::version::capabilities(
        &[VideoCodec::H264],
        Features::AUDIO.union(Features::CLIPBOARD),
    );
    let s = ProtocolVersion { major: 1, minor: 3 };
    let c = ProtocolVersion { major: 1, minor: 0 };
    let n = negotiate(s, &both, c, &client).expect("same major");
    assert_eq!(n.version, ProtocolVersion { major: 1, minor: 0 });
    assert_eq!(n.features, Features::AUDIO);
    assert_eq!(n.codecs, vec![VideoCodec::H264]);
    assert!(negotiate(s, &both, ProtocolVersion { major: 2, minor: 0 }, &client).is_err());
}

// ---------------------------------------------------------------- windows

proptest! {
    /// Released frames are strictly increasing (serial), never repeated, and every pushed frame
    /// is accounted for as released, held or dropped.
    #[test]
    fn reorder_window_invariants(
        start in any::<u32>(),
        ops in proptest::collection::vec((0u32..12, any::<bool>(), 0u8..4), 1..80),
        cap in 1usize..6,
    ) {
        let mut w = ReorderWindow::<u32>::new(cap);
        let mut released: Vec<u32> = Vec::new();
        let mut pushed = 0u64;
        for (off, key, kind) in ops {
            let n = start.wrapping_add(off);
            let out = if kind == 0 { w.release_lowest() } else { pushed += 1; w.push(n, key && kind == 1, n) };
            released.extend(out);
            prop_assert!(w.held() <= cap);
        }
        for pair in released.windows(2) {
            prop_assert!(serial_gt(pair[1], pair[0]), "not increasing: {:?}", pair);
        }
        prop_assert_eq!(pushed, released.len() as u64 + w.held() as u64 + w.dropped_stale());
    }

    #[test]
    fn reorder_window_in_order_is_passthrough(start in any::<u32>(), n in 1usize..64) {
        let mut w = ReorderWindow::<u32>::new(4);
        for i in 0..n as u32 {
            let f = start.wrapping_add(i);
            prop_assert_eq!(w.push(f, false, f), vec![f]);
        }
        prop_assert_eq!(w.dropped_stale(), 0);
    }

    #[test]
    fn mouse_coalescer_sums_relative_and_keeps_latest_absolute(
        start in any::<u32>(), moves in proptest::collection::vec((any::<bool>(), -1000i32..1000, -1000i32..1000), 1..40),
    ) {
        let mut c = MouseCoalescer::new();
        let (mut sx, mut sy) = (0i32, 0i32);
        let mut last_abs = None;
        for (i, (rel, x, y)) in moves.iter().enumerate() {
            let accepted = c.push(MouseMove { relative: *rel, seq: start.wrapping_add(i as u32), x: *x, y: *y });
            prop_assert!(accepted);
            if *rel { sx += x; sy += y; } else { last_abs = Some((*x, *y)); }
        }
        let u = c.take().expect("something pending");
        prop_assert_eq!(u.absolute, last_abs);
        prop_assert_eq!(u.relative, if moves.iter().any(|m| m.0) { Some((sx, sy)) } else { None });
        prop_assert_eq!(c.take(), None);
    }
}

#[test]
fn reorder_window_examples() {
    let mut w = ReorderWindow::new(2);
    assert_eq!(w.push(10, true, "k10"), vec!["k10"]);
    // 12 arrives before 11: held.
    assert!(w.push(12, false, "f12").is_empty());
    // 11 releases itself and 12.
    assert_eq!(w.push(11, false, "f11"), vec!["f11", "f12"]);
    // Older and duplicate frames are dropped.
    assert!(w.push(11, false, "again").is_empty());
    assert!(w.push(3, false, "old").is_empty());
    assert_eq!(w.dropped_stale(), 2);
    // A gap: 14, 15, 16 overflow the capacity of 2 and release 14.. without 13.
    assert!(w.push(14, false, "f14").is_empty() || w.held() > 0);
    let _ = w.push(15, false, "f15");
    let out = w.push(16, false, "f16");
    assert!(out.contains(&"f14"));
    // The missing frame is now stale.
    assert!(w.push(13, false, "f13").is_empty());
    // A key frame discards older held frames.
    let mut w = ReorderWindow::new(4);
    assert_eq!(w.push(1, false, 1), vec![1]);
    assert!(w.push(5, false, 5).is_empty());
    assert!(w.push(7, false, 7).is_empty());
    assert_eq!(w.push(9, true, 9), vec![9]);
    assert_eq!(w.held(), 0);
    // Wraparound.
    let mut w = ReorderWindow::new(4);
    assert_eq!(w.push(u32::MAX, false, 0), vec![0]);
    assert_eq!(w.push(0, false, 1), vec![1]);
    assert!(w.push(u32::MAX, false, 2).is_empty());
}

#[test]
fn mouse_coalescer_drops_stale() {
    let mut c = MouseCoalescer::new();
    assert!(c.push(MouseMove {
        relative: false,
        seq: 5,
        x: 1,
        y: 1
    }));
    assert!(!c.push(MouseMove {
        relative: false,
        seq: 4,
        x: 9,
        y: 9
    }));
    assert!(!c.push(MouseMove {
        relative: false,
        seq: 5,
        x: 9,
        y: 9
    }));
    assert_eq!(c.dropped_stale(), 2);
    assert_eq!(c.take().map(|u| u.absolute), Some(Some((1, 1))));
}

// ---------------------------------------------------------------- protocol 1.1

fn ctl(m: Ctl) -> ControlMessage {
    ControlMessage::new(m)
}

fn goodbye(name: &str, id: &[u8]) -> ControlMessage {
    ctl(Ctl::Goodbye(pb::Goodbye {
        code: CloseCode::TakenOver.code(),
        message: String::new(),
        peer_device_name: name.to_owned(),
        peer_device_id: Bytes::copy_from_slice(id),
    }))
}

proptest! {
    #[test]
    fn sanitized_names_are_valid_and_bounded(name in any::<String>()) {
        let s = sanitize_device_name(&name);
        prop_assert!(s.len() <= MAX_DEVICE_NAME);
        prop_assert!(device_name_problem(&s).is_none());
        prop_assert_eq!(s.trim(), s.as_str());
        // Idempotent.
        prop_assert_eq!(sanitize_device_name(&s), s.clone());
        prop_assert!(goodbye(&s, &[]).validate().is_ok());
    }

    #[test]
    fn server_stats_range_checks(
        s in server_stats(), bad_interval in (60_001u32..=u32::MAX), bad_fps in 241u32..=u32::MAX,
    ) {
        let mut x = s;
        x.interval_ms = bad_interval;
        prop_assert!(ctl(Ctl::ServerStats(x)).validate().is_err());
        let mut x = s;
        x.interval_ms = 0;
        prop_assert!(ctl(Ctl::ServerStats(x)).validate().is_err());
        let mut x = s;
        x.fps_ceiling = bad_fps;
        prop_assert!(ctl(Ctl::ServerStats(x)).validate().is_err());
    }

    #[test]
    fn effective_file_limit_is_the_minimum(
        sv in 0u32..3, cv in 0u32..3, sl in prop_oneof![Just(0u64), 1u64..=MAX_FILE_SIZE],
        cl in prop_oneof![Just(0u64), 1u64..=MAX_FILE_SIZE],
    ) {
        let mut sc = hx_proto::version::capabilities(&[], Features::NONE);
        sc.max_file_bytes = sl;
        let mut cc = hx_proto::version::capabilities(&[], Features::NONE);
        cc.max_file_bytes = cl;
        let (s, c) = (ProtocolVersion { major: 1, minor: sv }, ProtocolVersion { major: 1, minor: cv });
        let n = negotiate(s, &sc, c, &cc).expect("same major");
        let n2 = negotiate(c, &cc, s, &sc).expect("same major");
        prop_assert_eq!(n.max_file_bytes, n2.max_file_bytes);
        prop_assert!(n.max_file_bytes <= MAX_FILE_SIZE && n.max_file_bytes >= 1);
        if sv.min(cv) == 0 {
            prop_assert_eq!(n.max_file_bytes, MAX_FILE_SIZE);
        } else {
            let want = [sl, cl].into_iter().filter(|v| *v != 0).min().unwrap_or(MAX_FILE_SIZE);
            prop_assert_eq!(n.max_file_bytes, want);
        }
    }

    #[test]
    fn file_header_size_check(size in any::<u64>(), limit in 1u64..=MAX_FILE_SIZE) {
        let h = TransferHeader { mime: "a/b".into(), name: "f".into(), size };
        prop_assert_eq!(h.validate_file(limit).is_ok(), size <= limit);
        // A limit above the ceiling never raises it.
        prop_assert_eq!(h.validate_file(u64::MAX).is_ok(), size <= MAX_FILE_SIZE);
    }
}

#[test]
fn takeover_goodbye_edges() {
    let id = [7u8; 16];
    assert!(goodbye("Anna's phone", &id).validate().is_ok());
    assert!(goodbye("", &[]).validate().is_ok());
    // Name length: exactly 64 bytes passes, 65 fails.
    assert!(goodbye(&"n".repeat(64), &id).validate().is_ok());
    assert!(goodbye(&"n".repeat(65), &id).validate().is_err());
    // Multi-byte characters count in bytes.
    assert!(goodbye(&"é".repeat(32), &id).validate().is_ok());
    assert!(goodbye(&"é".repeat(33), &id).validate().is_err());
    // Unsanitised names are rejected.
    for bad in [
        "a\nb",
        "a\u{1b}[31m",
        "a\u{202E}b",
        "a\u{200B}b",
        "a\u{7f}",
        "a\u{85}",
    ] {
        assert!(goodbye(bad, &id).validate().is_err(), "{bad:?}");
    }
    // Id length: 0 or 16 only.
    for n in [1usize, 15, 17, 32] {
        assert!(goodbye("x", &vec![1u8; n]).validate().is_err(), "{n}");
    }
    // The sanitiser fixes what the validator rejects and cuts on a char boundary.
    assert_eq!(sanitize_device_name("  a\u{202E}b\nc \u{200B}"), "abc");
    let long = "é".repeat(100);
    let s = sanitize_device_name(&long);
    assert_eq!(s.len(), 64);
    assert!(s.chars().all(|c| c == 'é'));
    assert_eq!(sanitize_device_name("\u{1b}\u{202E}"), "");
}

#[test]
fn takeover_goodbye_is_additive_for_old_peers() {
    // A 1.0 peer ignores fields 3 and 4: the same bytes decode as a plain Goodbye there.
    #[derive(Clone, PartialEq, prost::Message)]
    struct OldGoodbye {
        #[prost(uint32, tag = "1")]
        code: u32,
        #[prost(string, tag = "2")]
        message: String,
    }
    let g = pb::Goodbye {
        code: 9,
        message: "taken over".into(),
        peer_device_name: "Laptop".into(),
        peer_device_id: Bytes::from_static(&[1; 16]),
    };
    let old = <OldGoodbye as prost::Message>::decode(prost::Message::encode_to_vec(&g).as_slice())
        .expect("old decoder skips unknown fields");
    assert_eq!((old.code, old.message.as_str()), (9, "taken over"));
}

#[test]
fn server_stats_is_numeric_only_and_sized() {
    let s = pb::ServerStats {
        interval_ms: 1000,
        frames: u32::MAX,
        keyframes: u32::MAX,
        dropped_frames: u32::MAX,
        bitrate_kbps: u32::MAX,
        target_bitrate_kbps: u32::MAX,
        fps_ceiling: 240,
        encode_p95_us: u32::MAX,
        total_p95_us: u32::MAX,
        queue_depth_max: u32::MAX,
        rtt_us: u32::MAX,
    };
    let m = ctl(Ctl::ServerStats(s));
    let bytes = message::encode(&m).expect("valid");
    // Eleven varint fields: a small, fixed bound, nowhere near the control limit.
    assert!(bytes.len() <= 11 * 6 + 2, "{}", bytes.len());
    assert_eq!(
        message::decode::<ControlMessage>(&bytes).expect("decodes"),
        m
    );
    // The boundary values themselves.
    for (interval, fps, ok) in [
        (1, 0, true),
        (60_000, 240, true),
        (0, 0, false),
        (60_001, 0, false),
        (1000, 241, false),
    ] {
        let m = ctl(Ctl::ServerStats(pb::ServerStats {
            interval_ms: interval,
            fps_ceiling: fps,
            ..Default::default()
        }));
        assert_eq!(m.validate().is_ok(), ok, "{interval} {fps}");
    }
}

#[test]
fn server_stats_variant_is_unknown_to_a_1_0_peer() {
    // Why the feature is gated by minor (protocol 4.5): a peer that does not know field 11 sees
    // an envelope without a variant.
    #[derive(Clone, PartialEq, prost::Message)]
    struct Old {
        #[prost(oneof = "OldBody", tags = "7")]
        message: Option<OldBody>,
    }
    #[derive(Clone, PartialEq, prost::Oneof)]
    enum OldBody {
        #[prost(message, tag = "7")]
        Ping(pb::Ping),
    }
    let m = ctl(Ctl::ServerStats(pb::ServerStats {
        interval_ms: 1000,
        ..Default::default()
    }));
    let old = <Old as prost::Message>::decode(prost::Message::encode_to_vec(&m).as_slice())
        .expect("decodes");
    assert!(old.message.is_none());
}

#[test]
fn file_limit_edges_and_capabilities() {
    let header = |size| TransferHeader {
        mime: "application/zip".into(),
        name: "a.zip".into(),
        size,
    };
    assert!(header(0).validate_file(1).is_ok());
    assert!(header(MAX_FILE_SIZE).validate_file(MAX_FILE_SIZE).is_ok());
    assert!(
        header(MAX_FILE_SIZE + 1)
            .validate_file(MAX_FILE_SIZE)
            .is_err()
    );
    assert!(header(1024).validate_file(1023).is_err());
    assert!(header(u64::MAX).validate_file(u64::MAX).is_err());
    // Advertised limits above the ceiling are invalid, the ceiling itself is fine.
    let hello = |limit| {
        ctl(Ctl::Hello(pb::Hello {
            version: Some(pb::Version { major: 1, minor: 1 }),
            capabilities: Some(pb::Capabilities {
                max_file_bytes: limit,
                ..Default::default()
            }),
            intent: 1,
            software: String::new(),
            device_name: String::new(),
        }))
    };
    assert!(hello(MAX_FILE_SIZE).validate().is_ok());
    assert!(hello(MAX_FILE_SIZE + 1).validate().is_err());
    assert!(hello(u64::MAX).validate().is_err());
    // A 1.0 peer states no limit and the 1.1 side still ends up at the ceiling or its own.
    let mut server = hx_proto::version::capabilities(&[], Features::NONE);
    server.max_file_bytes = 1 << 30;
    let client = hx_proto::version::capabilities(&[], Features::NONE);
    let n = negotiate(
        ProtocolVersion::CURRENT,
        &server,
        ProtocolVersion { major: 1, minor: 0 },
        &client,
    )
    .unwrap();
    assert_eq!(
        n.max_file_bytes, MAX_FILE_SIZE,
        "minor 0 ignores stated limits"
    );
    let n = negotiate(
        ProtocolVersion::CURRENT,
        &server,
        ProtocolVersion::CURRENT,
        &client,
    )
    .unwrap();
    assert_eq!(n.max_file_bytes, 1 << 30);
}

#[test]
fn server_stats_feature_exists_from_1_1_only() {
    assert!(!Features::defined_up_to(0).contains(Features::SERVER_STATS));
    assert!(Features::defined_up_to(1).contains(Features::SERVER_STATS));
    let all = hx_proto::version::capabilities(&[], Features(u64::MAX));
    let v10 = ProtocolVersion { major: 1, minor: 0 };
    let n = negotiate(ProtocolVersion::CURRENT, &all, v10, &all).unwrap();
    assert!(!n.features.contains(Features::SERVER_STATS));
    let n = negotiate(
        ProtocolVersion::CURRENT,
        &all,
        ProtocolVersion::CURRENT,
        &all,
    )
    .unwrap();
    assert!(n.features.contains(Features::SERVER_STATS));
}

#[test]
fn view_config_stats_flag_defaults_off() {
    let v = pb::ViewConfig::default();
    assert!(!v.stats_enabled);
    let m = ctl(Ctl::ViewConfig(pb::ViewConfig {
        stats_enabled: true,
        ..Default::default()
    }));
    assert_eq!(
        message::decode::<ControlMessage>(&message::encode(&m).unwrap()).unwrap(),
        m
    );
}

// ---------------------------------------------------------------- 1.2 device management

fn mgmt(request_id: u32, body: pb::device_mgmt::Body) -> ControlMessage {
    ControlMessage::new(Ctl::DeviceMgmt(pb::DeviceMgmt {
        request_id,
        body: Some(body),
    }))
}

fn info(status: i32, reason: i32) -> pb::DeviceInfo {
    pb::DeviceInfo {
        device_id: Bytes::from(vec![7u8; 16]),
        name: "phone".into(),
        status,
        revoke_reason: reason,
        revoked_unix: if status == 2 { 5 } else { 0 },
        ..Default::default()
    }
}

fn device_list(devices: Vec<pb::DeviceInfo>) -> ControlMessage {
    mgmt(
        1,
        pb::device_mgmt::Body::DeviceList(pb::DeviceList {
            devices,
            truncated: false,
        }),
    )
}

proptest! {
    /// Every valid device-management message survives encode and decode unchanged, and the
    /// direction helper agrees with the variant.
    #[test]
    fn device_mgmt_round_trips(m in device_mgmt()) {
        let c = ControlMessage::new(Ctl::DeviceMgmt(m.clone()));
        let bytes = message::encode(&c).unwrap();
        prop_assert_eq!(message::decode::<ControlMessage>(&bytes).unwrap(), c);
        use pb::device_mgmt::Body as B;
        let server_sends = matches!(
            m.body,
            Some(B::DeviceList(_) | B::RevokeResult(_) | B::Event(_))
        );
        prop_assert_eq!(
            m.direction(),
            Some(if server_sends {
                message::MgmtDirection::ServerToClient
            } else {
                message::MgmtDirection::ClientToServer
            })
        );
    }

    /// Request ids: a request or its answer needs a non-zero id, an event must have none.
    #[test]
    fn device_mgmt_request_id_rules(m in device_mgmt(), other in 1u32..=u32::MAX) {
        use pb::device_mgmt::Body as B;
        let is_event = matches!(m.body, Some(B::Event(_)));
        let mut wrong = m.clone();
        wrong.request_id = if is_event { other } else { 0 };
        prop_assert!(ControlMessage::new(Ctl::DeviceMgmt(wrong)).validate().is_err());
    }

    /// A device id of any length but 16 is rejected in a revoke request and in every device.
    #[test]
    fn device_ids_must_be_16_bytes(len in (0usize..64).prop_filter("not 16", |l| *l != 16)) {
        let id = Bytes::from(vec![1u8; len]);
        let revoke = mgmt(
            1,
            pb::device_mgmt::Body::Revoke(pb::RevokeDevice { device_id: id.clone() }),
        );
        prop_assert!(revoke.validate().is_err());
        let mut d = info(1, 0);
        d.device_id = id;
        prop_assert!(device_list(vec![d]).validate().is_err());
    }

    /// Names that are too long or carry control, bidi or invisible characters are rejected.
    #[test]
    fn device_names_are_checked(
        extra in 1usize..64,
        bad in prop_oneof![
            Just('\u{1b}'), Just('\u{202E}'), Just('\u{200B}'), Just('\n'), Just('\u{85}')
        ],
    ) {
        let mut long = info(1, 0);
        long.name = "a".repeat(MAX_DEVICE_NAME + extra);
        prop_assert!(device_list(vec![long]).validate().is_err());
        let mut tricky = info(1, 0);
        tricky.name = format!("ph{bad}one");
        prop_assert!(device_list(vec![tricky]).validate().is_err());
    }

    /// The decoders stay total on arbitrary bytes inside the new envelope.
    #[test]
    fn device_mgmt_decode_is_total(body in proptest::collection::vec(any::<u8>(), 0..127)) {
        // field 12 (device_mgmt), length-delimited
        let mut buf = vec![0x62u8, body.len() as u8];
        buf.extend_from_slice(&body);
        let _ = message::decode::<ControlMessage>(&buf);
    }
}

#[test]
fn device_mgmt_status_and_revocation_must_agree() {
    assert!(device_list(vec![info(1, 0)]).validate().is_ok());
    assert!(device_list(vec![info(2, 1)]).validate().is_ok());
    assert!(device_list(vec![info(2, 2)]).validate().is_ok());
    assert!(
        device_list(vec![info(2, 0)]).validate().is_err(),
        "revoked without a reason"
    );
    assert!(
        device_list(vec![info(1, 1)]).validate().is_err(),
        "active with a reason"
    );
    assert!(
        device_list(vec![info(0, 0)]).validate().is_err(),
        "unspecified status"
    );
    assert!(
        device_list(vec![info(3, 0)]).validate().is_err(),
        "unknown status"
    );
    assert!(
        device_list(vec![info(2, 9)]).validate().is_err(),
        "unknown reason"
    );
    let mut active_with_time = info(1, 0);
    active_with_time.revoked_unix = 1;
    assert!(device_list(vec![active_with_time]).validate().is_err());
}

#[test]
fn device_list_limits() {
    let many = |n: usize, current: usize| {
        device_list(
            (0..n)
                .map(|i| {
                    let mut d = info(1, 0);
                    d.device_id = Bytes::from(vec![i as u8; 16]);
                    d.current = i < current;
                    d
                })
                .collect(),
        )
    };
    let max = hx_proto::channel::MAX_DEVICE_LIST;
    assert!(many(max, 1).validate().is_ok());
    assert!(many(max + 1, 0).validate().is_err());
    assert!(many(3, 2).validate().is_err(), "two current devices");
    // The largest legal list fits one control message.
    let worst = (0..max)
        .map(|i| pb::DeviceInfo {
            device_id: Bytes::from(vec![i as u8; 16]),
            name: "n".repeat(MAX_DEVICE_NAME),
            created_unix: u64::MAX,
            last_seen_unix: u64::MAX,
            status: 2,
            revoke_reason: 2,
            revoked_unix: u64::MAX,
            current: false,
        })
        .collect();
    assert!(
        message::encode(&device_list(worst)).is_ok(),
        "128 worst-case devices fit 64 KiB"
    );
}

#[test]
fn device_event_rules() {
    use pb::device_mgmt::Body as B;
    let event = |kind, device: Option<pb::DeviceInfo>, by: Vec<u8>| {
        mgmt(
            0,
            B::Event(pb::DeviceEvent {
                kind,
                device,
                by_device_id: Bytes::from(by),
            }),
        )
    };
    assert!(event(2, Some(info(2, 1)), vec![]).validate().is_ok());
    assert!(event(1, Some(info(1, 0)), vec![3; 16]).validate().is_ok());
    assert!(event(0, Some(info(1, 0)), vec![]).validate().is_err());
    assert!(event(4, Some(info(1, 0)), vec![]).validate().is_err());
    assert!(event(1, None, vec![]).validate().is_err());
    assert!(event(1, Some(info(1, 0)), vec![3; 15]).validate().is_err());
    // An empty body is not a message.
    let empty = ControlMessage::new(Ctl::DeviceMgmt(pb::DeviceMgmt {
        request_id: 1,
        body: None,
    }));
    assert!(empty.validate().is_err());
    assert_eq!(pb::DeviceMgmt::default().direction(), None);
}

#[test]
fn revoke_result_status_must_be_known() {
    use pb::device_mgmt::Body as B;
    for status in 1..=6 {
        assert!(
            mgmt(1, B::RevokeResult(pb::RevokeResult { status }))
                .validate()
                .is_ok()
        );
    }
    for status in [0, 7, -1] {
        assert!(
            mgmt(1, B::RevokeResult(pb::RevokeResult { status }))
                .validate()
                .is_err()
        );
    }
}

#[test]
fn device_mgmt_variant_is_unknown_to_a_1_1_peer() {
    // Why the variant is gated by minor and feature bit (protocol 4.6): a peer that does not
    // know field 12 decodes an envelope without a variant and would close the connection.
    #[derive(Clone, PartialEq, prost::Message)]
    struct Old {
        #[prost(oneof = "OldBody", tags = "7")]
        message: Option<OldBody>,
    }
    #[derive(Clone, PartialEq, prost::Oneof)]
    enum OldBody {
        #[prost(message, tag = "7")]
        Ping(pb::Ping),
    }
    let m = mgmt(1, pb::device_mgmt::Body::List(pb::ListDevices {}));
    let old = <Old as prost::Message>::decode(prost::Message::encode_to_vec(&m).as_slice())
        .expect("decodes");
    assert!(old.message.is_none());
}

#[test]
fn device_management_feature_exists_from_1_2_only() {
    assert!(!Features::defined_up_to(0).contains(Features::DEVICE_MANAGEMENT));
    assert!(!Features::defined_up_to(1).contains(Features::DEVICE_MANAGEMENT));
    assert!(Features::defined_up_to(2).contains(Features::DEVICE_MANAGEMENT));
    assert!(Features::defined_up_to(2).contains(Features::SERVER_STATS));
    assert_eq!(ProtocolVersion::CURRENT.minor, 3);
    let all = hx_proto::version::capabilities(&[], Features(u64::MAX));
    for minor in [0, 1] {
        let older = ProtocolVersion { major: 1, minor };
        let n = negotiate(ProtocolVersion::CURRENT, &all, older, &all).unwrap();
        assert!(
            !n.features.contains(Features::DEVICE_MANAGEMENT),
            "a 1.{minor} peer never gets the bit"
        );
    }
    let n = negotiate(
        ProtocolVersion::CURRENT,
        &all,
        ProtocolVersion::CURRENT,
        &all,
    )
    .unwrap();
    assert!(n.features.contains(Features::DEVICE_MANAGEMENT));
    // A 1.2 client that only offers some bits gets exactly those.
    let client = hx_proto::version::capabilities(&[], Features::CLIPBOARD);
    let n = negotiate(
        ProtocolVersion::CURRENT,
        &all,
        ProtocolVersion::CURRENT,
        &client,
    )
    .unwrap();
    assert!(!n.features.contains(Features::DEVICE_MANAGEMENT));
}
