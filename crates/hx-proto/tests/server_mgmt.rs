//! Protocol 1.3: `ServerMgmt` (protocol §5.11): the feature bit, validation, directions, the size
//! of the largest answer, and the redacting `Debug` of the messages that carry a PIN or password.

use bytes::Bytes;
use hx_proto::{
    ProtoError,
    channel::MAX_CONTROL_MESSAGE,
    message::{self, MgmtDirection, Wire},
    pb::{
        self, ControlMessage, ServerMgmt, control_message::Message as Ctl, server_mgmt::Body as B,
    },
    version::{Features, ProtocolVersion, capabilities, negotiate},
};

fn m(request_id: u32, body: B) -> ControlMessage {
    ControlMessage::new(Ctl::ServerMgmt(ServerMgmt {
        request_id,
        body: Some(body),
    }))
}

fn roundtrips(x: &ControlMessage) {
    let bytes = message::encode(x).unwrap_or_else(|e| panic!("encode {x:?}: {e}"));
    assert_eq!(&message::decode::<ControlMessage>(&bytes).unwrap(), x);
}

fn invalid(x: &ControlMessage, field: &str) {
    match x.validate() {
        Err(ProtoError::Invalid { field: f, .. }) => assert!(f.contains(field), "{f} vs {field}"),
        other => panic!("expected invalid {field}, got {other:?}"),
    }
}

fn limits() -> pb::SetupLimits {
    pb::SetupLimits {
        cpu: 2,
        memory_mib: 4096,
        disk_gib: 40,
    }
}

#[test]
fn the_feature_bit_is_6_from_1_3_and_a_1_2_peer_never_negotiates_it() {
    assert_eq!(Features::SERVER_MANAGEMENT.0, 1 << 6);
    assert!(Features::defined_up_to(3).contains(Features::SERVER_MANAGEMENT));
    assert!(!Features::defined_up_to(2).contains(Features::SERVER_MANAGEMENT));
    let v13 = ProtocolVersion { major: 1, minor: 3 };
    let v12 = ProtocolVersion { major: 1, minor: 2 };
    let server = capabilities(&[], Features::defined_up_to(3).without(Features::SETUP));
    let client = capabilities(
        &[],
        Features(Features::defined_up_to(2).0 | Features::SERVER_MANAGEMENT.0),
    );
    let n = negotiate(v13, &server, v12, &client).unwrap();
    assert!(
        !n.features.contains(Features::SERVER_MANAGEMENT),
        "masked by the minor"
    );
    let both = negotiate(v13, &server, v13, &server).unwrap();
    assert!(both.features.contains(Features::SERVER_MANAGEMENT));
}

#[test]
fn every_request_and_answer_roundtrips_and_validates() {
    let all = [
        m(1, B::GetOverview(pb::ServerGetOverview {})),
        m(
            2,
            B::ChangePin(pb::ServerChangePin {
                current: Bytes::from_static(b"123456"),
                new: Bytes::from_static(b"654321"),
            }),
        ),
        m(
            3,
            B::ChangePassword(pb::ServerChangePassword {
                current: Bytes::from_static(b"old"),
                new: Bytes::from_static(b"new"),
            }),
        ),
        m(
            4,
            B::RestartDesktop(pb::ServerRestartDesktop { force: true }),
        ),
        m(5, B::SetDocker(pb::ServerSetDocker { enable: false })),
        m(
            6,
            B::SetLimits(pb::ServerSetLimits {
                limits: Some(limits()),
            }),
        ),
        m(7, B::CheckUpdate(pb::ServerCheckUpdate {})),
        m(
            8,
            B::ApplyUpdate(pb::ServerApplyUpdate {
                version: "1.2.3".into(),
            }),
        ),
        m(
            9,
            B::Overview(pb::ServerOverview {
                agent_version: "0.1.0".into(),
                desktop: Some(pb::ServerDesktop {
                    state: pb::ServerDesktopState::Running as i32,
                    username: "alice".into(),
                    limits: Some(limits()),
                    needs_attention: vec![pb::ServerAttention::PinLocked as i32],
                    ..Default::default()
                }),
                ..Default::default()
            }),
        ),
        m(
            10,
            B::Result(pb::ServerResult {
                status: pb::ServerStatus::Ok as i32,
                ..Default::default()
            }),
        ),
    ];
    for x in &all {
        roundtrips(x);
        x.validate().unwrap();
    }
}

#[test]
fn request_ids_bodies_and_size_caps_are_enforced() {
    // No push exists: id 0 is never valid, in either direction.
    invalid(
        &m(0, B::GetOverview(pb::ServerGetOverview {})),
        "request_id",
    );
    invalid(
        &m(
            0,
            B::Result(pb::ServerResult {
                status: 1,
                ..Default::default()
            }),
        ),
        "request_id",
    );
    // A body must be set.
    invalid(
        &ControlMessage::new(Ctl::ServerMgmt(ServerMgmt {
            request_id: 1,
            body: None,
        })),
        "server_mgmt",
    );
    // Hard caps.
    invalid(
        &m(
            1,
            B::ChangePin(pb::ServerChangePin {
                current: Bytes::from(vec![b'1'; 17]),
                new: Bytes::new(),
            }),
        ),
        "change_pin",
    );
    invalid(
        &m(
            1,
            B::ChangePassword(pb::ServerChangePassword {
                current: Bytes::new(),
                new: Bytes::from(vec![b'x'; 1025]),
            }),
        ),
        "change_password",
    );
    invalid(
        &m(
            1,
            B::ApplyUpdate(pb::ServerApplyUpdate {
                version: "1".repeat(33),
            }),
        ),
        "version",
    );
    invalid(
        &m(
            1,
            B::SetLimits(pb::ServerSetLimits {
                limits: Some(pb::SetupLimits {
                    cpu: 1025,
                    memory_mib: 1,
                    disk_gib: 1,
                }),
            }),
        ),
        "cpu",
    );
    // An answer needs a real status and bounded text.
    invalid(
        &m(
            1,
            B::Result(pb::ServerResult {
                status: 0,
                ..Default::default()
            }),
        ),
        "status",
    );
    invalid(
        &m(
            1,
            B::Result(pb::ServerResult {
                status: 99,
                ..Default::default()
            }),
        ),
        "status",
    );
    invalid(
        &m(
            1,
            B::Result(pb::ServerResult {
                status: 1,
                message: "x".repeat(257),
                ..Default::default()
            }),
        ),
        "message",
    );
    invalid(
        &m(
            1,
            B::Overview(pb::ServerOverview {
                host_attention: vec![1; 9],
                ..Default::default()
            }),
        ),
        "host_attention",
    );
    // The semantic checks (PIN digits, password content) are the receiver's, not validation's:
    // a PIN of letters is a well-formed message.
    m(
        1,
        B::ChangePin(pb::ServerChangePin {
            current: Bytes::from_static(b"abcdef"),
            new: Bytes::from_static(b"abcdef"),
        }),
    )
    .validate()
    .unwrap();
}

#[test]
fn directions_tell_a_receiver_which_way_a_body_may_travel() {
    let dir = |b: B| {
        ServerMgmt {
            request_id: 1,
            body: Some(b),
        }
        .direction()
    };
    for b in [
        B::GetOverview(Default::default()),
        B::ChangePin(Default::default()),
        B::ChangePassword(Default::default()),
        B::RestartDesktop(Default::default()),
        B::SetDocker(Default::default()),
        B::SetLimits(Default::default()),
        B::CheckUpdate(Default::default()),
        B::ApplyUpdate(Default::default()),
    ] {
        assert_eq!(dir(b), Some(MgmtDirection::ClientToServer));
    }
    assert_eq!(
        dir(B::Overview(Default::default())),
        Some(MgmtDirection::ServerToClient)
    );
    assert_eq!(
        dir(B::Result(Default::default())),
        Some(MgmtDirection::ServerToClient)
    );
    assert_eq!(
        ServerMgmt {
            request_id: 1,
            body: None
        }
        .direction(),
        None
    );
}

#[test]
fn the_largest_overview_stays_below_the_control_message_limit() {
    let big = pb::ServerUpdateInfo {
        current: "9".repeat(32),
        available: "9".repeat(32),
        channel: 2,
        verified: true,
        rolled_back_version: "9".repeat(32),
        rolled_back_reason: "r".repeat(256),
        checked_unix: u64::MAX,
    };
    let x = m(
        u32::MAX,
        B::Overview(pb::ServerOverview {
            agent_version: "a".repeat(64),
            privd_version: "p".repeat(64),
            server_time_unix: u64::MAX,
            agent_uptime_s: u64::MAX,
            update: Some(big.clone()),
            desktop: Some(pb::ServerDesktop {
                state: 8,
                username: "u".repeat(32),
                distro: 4,
                preset: 2,
                limits: Some(pb::SetupLimits {
                    cpu: u32::MAX,
                    memory_mib: u64::MAX,
                    disk_gib: u64::MAX,
                }),
                docker: 3,
                needs_attention: vec![7; 8],
                created_unix: u64::MAX,
            }),
            host: Some(pb::SetupHostFacts {
                cpu_count: u32::MAX,
                memory_total_mib: u64::MAX,
                pool_total_gib: u64::MAX,
                pool_free_gib: u64::MAX,
                docker_supported: true,
                os: "o".repeat(64),
                arch: "a".repeat(16),
            }),
            host_attention: vec![7; 8],
            session_active: true,
        }),
    );
    x.validate().unwrap();
    assert!(message::encode(&x).unwrap().len() < MAX_CONTROL_MESSAGE);
    let r = m(
        1,
        B::Result(pb::ServerResult {
            status: 1,
            retry_after_s: u32::MAX,
            attempts_left: u32::MAX,
            message: "m".repeat(256),
            restart_required: true,
            update: Some(big),
            version: "9".repeat(32),
        }),
    );
    r.validate().unwrap();
    assert!(message::encode(&r).unwrap().len() < MAX_CONTROL_MESSAGE);
}

#[test]
fn debug_never_prints_a_pin_or_a_password() {
    let pin = pb::ServerChangePin {
        current: Bytes::from_static(b"482913"),
        new: Bytes::from_static(b"135790"),
    };
    let pw = pb::ServerChangePassword {
        current: Bytes::from_static(b"correct horse"),
        new: Bytes::from_static(b"battery staple"),
    };
    for text in [
        format!("{pin:?}"),
        format!("{pw:?}"),
        format!("{:?}", m(1, B::ChangePin(pin.clone()))),
        format!("{:#?}", m(2, B::ChangePassword(pw.clone()))),
    ] {
        for secret in ["482913", "135790", "correct", "horse", "battery", "staple"] {
            assert!(!text.contains(secret), "{text}");
        }
        // Not even a length: the bytes' decimal values are absent too.
        assert!(!text.contains("52, 56") && !text.contains("[99"), "{text}");
    }
}
