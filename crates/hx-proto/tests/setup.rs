//! Protocol 1.3: the setup messages, `CreatePairingCode`, the new intent, refuse reason, close
//! code and feature bit, and the redacting `Debug` of every type that carries a secret.

use bytes::Bytes;
use hx_proto::{
    ProtoError,
    channel::{CloseCode, MAX_CONTROL_MESSAGE},
    message::{self, MgmtDirection, Wire, password_problem, pin_problem},
    pb::{
        self, ControlMessage, DeviceMgmt, SetupMessage, control_message::Message as Ctl,
        device_mgmt::Body as Dm, setup_message::Body as Sb,
    },
    version::{Features, PROTOCOL_MAJOR, PROTOCOL_MINOR, ProtocolVersion, capabilities, negotiate},
};

fn setup(request_id: u32, body: Sb) -> ControlMessage {
    ControlMessage::new(Ctl::Setup(SetupMessage {
        request_id,
        body: Some(body),
    }))
}

fn mgmt(request_id: u32, body: Dm) -> ControlMessage {
    ControlMessage::new(Ctl::DeviceMgmt(DeviceMgmt {
        request_id,
        body: Some(body),
    }))
}

fn ok(m: &ControlMessage) {
    let bytes = message::encode(m).unwrap_or_else(|e| panic!("encode {m:?}: {e}"));
    let back: ControlMessage = message::decode(&bytes).unwrap();
    assert_eq!(&back, m);
}

fn bad(m: &ControlMessage, field: &str) {
    match m.validate() {
        Err(ProtoError::Invalid { field: f, .. }) => {
            assert!(f.contains(field), "wrong field {f} for {field}")
        }
        other => panic!("expected Invalid({field}), got {other:?}"),
    }
}

fn options() -> pb::SetupOptions {
    pb::SetupOptions {
        distro: pb::SetupDistro::Debian13 as i32,
        desktop: pb::SetupDesktop::Xfce as i32,
        preset: pb::SetupPreset::Developer as i32,
        username: "alice".into(),
        image_mode: pb::SetupImageMode::Auto as i32,
        limits: Some(pb::SetupLimits {
            cpu: 4,
            memory_mib: 8192,
            disk_gib: 100,
        }),
        docker: true,
        docker_isolation_acknowledged: true,
        settings: Some(pb::SetupDesktopSettings {
            hostname: "box".into(),
            timezone: "Europe/Berlin".into(),
            locale: "en_US.UTF-8".into(),
            keyboard: "us".into(),
        }),
    }
}

fn start() -> pb::SetupStart {
    pb::SetupStart {
        options: Some(options()),
        password: Bytes::from_static(b"correct horse battery staple"),
    }
}

// ---------------------------------------------------------------------------- version

#[test]
fn version_constants_and_feature_bit() {
    assert_eq!((PROTOCOL_MAJOR, PROTOCOL_MINOR), (1, 3));
    assert_eq!(Features::SETUP.0, 1 << 5);
    assert!(Features::defined_up_to(3).contains(Features::SETUP));
    assert!(!Features::defined_up_to(2).contains(Features::SETUP));
    assert!(Features::defined_up_to(2).contains(Features::DEVICE_MANAGEMENT));
    assert_eq!(
        Features::defined_up_to(3).0,
        Features::defined_up_to(2).0 | Features::SETUP.0
    );
    let normal = Features::defined_up_to(3).without(Features::SETUP);
    assert!(!normal.contains(Features::SETUP));
    assert!(normal.contains(Features::DEVICE_MANAGEMENT));
    assert_eq!(normal.without(Features::SETUP), normal);
    assert_eq!(Features::NONE.without(Features::SETUP), Features::NONE);
}

#[test]
fn negotiation_with_a_1_2_peer_never_yields_setup() {
    let v13 = ProtocolVersion { major: 1, minor: 3 };
    let v12 = ProtocolVersion { major: 1, minor: 2 };
    let server = capabilities(&[], Features::defined_up_to(3));
    // A 1.2 client states every bit it knows; even if it set bit 5 the minor masks it.
    let client = capabilities(
        &[],
        Features(Features::defined_up_to(2).0 | Features::SETUP.0),
    );
    let n = negotiate(v13, &server, v12, &client).unwrap();
    assert_eq!(n.version, v12);
    assert!(!n.features.contains(Features::SETUP));
    assert!(n.features.contains(Features::DEVICE_MANAGEMENT));
    // Two 1.3 peers do get it.
    let both = negotiate(v13, &server, v13, &server).unwrap();
    assert!(both.features.contains(Features::SETUP));
}

#[test]
fn close_code_10_and_websocket_4010() {
    assert_eq!(CloseCode::SetupClosed.code(), 10);
    assert_eq!(CloseCode::SetupClosed.websocket_code(), 4010);
    assert_eq!(CloseCode::from_code(10), CloseCode::SetupClosed);
    assert_eq!(
        CloseCode::from_websocket_code(4010),
        Some(CloseCode::SetupClosed)
    );
    // Unknown codes stay INTERNAL_ERROR.
    assert_eq!(CloseCode::from_code(11), CloseCode::InternalError);
    assert_eq!(CloseCode::from_code(8), CloseCode::InternalError);
}

// ---------------------------------------------------------------------------- hello, refuse

fn hello(intent: i32) -> ControlMessage {
    ControlMessage::new(Ctl::Hello(pb::Hello {
        version: Some(ProtocolVersion::CURRENT.into()),
        capabilities: Some(capabilities(&[], Features::SETUP)),
        intent,
        software: "t".into(),
        device_name: "d".into(),
    }))
}

#[test]
fn intent_setup_is_accepted_and_garbage_intents_are_not() {
    ok(&hello(pb::Intent::Setup as i32));
    ok(&hello(pb::Intent::Session as i32));
    ok(&hello(pb::Intent::Pair as i32));
    bad(&hello(0), "hello.intent");
    ok(&hello(pb::Intent::Reinstate as i32));
    assert_eq!(pb::Intent::Reinstate as i32, 4);
    bad(&hello(5), "hello.intent");
}

#[test]
fn refuse_setup_closed_is_accepted() {
    let refuse = |reason: i32| {
        ControlMessage::new(Ctl::Refuse(pb::Refuse {
            reason,
            message: String::new(),
            version: None,
        }))
    };
    ok(&refuse(pb::RefuseReason::SetupClosed as i32));
    assert_eq!(pb::RefuseReason::SetupClosed as i32, 5);
    bad(&refuse(6), "refuse.reason");
}

// ---------------------------------------------------------------------------- setup messages

#[test]
fn every_setup_variant_roundtrips_with_the_right_request_id() {
    ok(&setup(
        1,
        Sb::SetPin(pb::SetupSetPin {
            pin: Bytes::from_static(b"123456"),
        }),
    ));
    ok(&setup(2, Sb::Start(start())));
    ok(&setup(3, Sb::Cancel(pb::SetupCancel {})));
    ok(&setup(4, Sb::Finish(pb::SetupFinish {})));
    ok(&setup(
        4,
        Sb::Ack(pb::SetupAck {
            status: pb::SetupAckStatus::Ok as i32,
            field: String::new(),
            message: String::new(),
            retry_after_ms: 0,
            job_id: 7,
        }),
    ));
    ok(&setup(
        0,
        Sb::State(pb::SetupState {
            job: pb::SetupJobState::Idle as i32,
            pin_set: true,
            ..Default::default()
        }),
    ));
    ok(&setup(
        0,
        Sb::Progress(pb::SetupProgress {
            job_id: 1,
            stage: pb::SetupStage::Build as i32,
            percent: 255,
            ..Default::default()
        }),
    ));
    ok(&setup(
        0,
        Sb::Result(pb::SetupResult {
            job_id: 1,
            status: pb::SetupJobState::Succeeded as i32,
            finished: true,
            ..Default::default()
        }),
    ));
}

#[test]
fn request_id_rules() {
    // Requests and acks: non-zero.
    for body in [
        Sb::SetPin(pb::SetupSetPin::default()),
        Sb::Start(start()),
        Sb::Cancel(pb::SetupCancel {}),
        Sb::Finish(pb::SetupFinish {}),
        Sb::Ack(pb::SetupAck::default()),
    ] {
        bad(&setup(0, body), "setup.request_id");
    }
    // Pushes: zero.
    for body in [
        Sb::State(pb::SetupState::default()),
        Sb::Progress(pb::SetupProgress::default()),
        Sb::Result(pb::SetupResult::default()),
    ] {
        bad(&setup(1, body), "setup.request_id");
    }
    // No body at all.
    let empty = ControlMessage::new(Ctl::Setup(SetupMessage {
        request_id: 1,
        body: None,
    }));
    bad(&empty, "setup");
}

#[test]
fn direction_of_every_variant() {
    let dir = |b: Sb| {
        SetupMessage {
            request_id: 1,
            body: Some(b),
        }
        .direction()
    };
    use MgmtDirection::{ClientToServer as C, ServerToClient as S};
    assert_eq!(dir(Sb::SetPin(Default::default())), Some(C));
    assert_eq!(dir(Sb::Start(start())), Some(C));
    assert_eq!(dir(Sb::Cancel(Default::default())), Some(C));
    assert_eq!(dir(Sb::Finish(Default::default())), Some(C));
    assert_eq!(dir(Sb::State(Default::default())), Some(S));
    assert_eq!(dir(Sb::Ack(Default::default())), Some(S));
    assert_eq!(dir(Sb::Progress(Default::default())), Some(S));
    assert_eq!(dir(Sb::Result(Default::default())), Some(S));
    assert_eq!(SetupMessage::default().direction(), None);
}

#[test]
fn hard_caps_are_protocol_errors() {
    let long = |n: usize| "a".repeat(n);
    // PIN: 16 passes, 17 fails (the digits rule is semantic: a short or alphabetic PIN is fine
    // on the wire and answered with SetupAck).
    ok(&setup(
        1,
        Sb::SetPin(pb::SetupSetPin {
            pin: Bytes::from(vec![b'1'; 16]),
        }),
    ));
    ok(&setup(
        1,
        Sb::SetPin(pb::SetupSetPin {
            pin: Bytes::from_static(b"abc"),
        }),
    ));
    bad(
        &setup(
            1,
            Sb::SetPin(pb::SetupSetPin {
                pin: Bytes::from(vec![b'1'; 17]),
            }),
        ),
        "set_pin",
    );
    // Password: 1024 passes, 1025 fails; a bad password is semantic.
    let with_pw = |n: usize| {
        let mut s = start();
        s.password = Bytes::from(vec![b'x'; n]);
        setup(1, Sb::Start(s))
    };
    ok(&with_pw(1024));
    ok(&with_pw(0));
    bad(&with_pw(1025), "start.password");
    // Options: user name 32 passes, 33 fails; settings caps; limits caps.
    let with_opts = |f: &dyn Fn(&mut pb::SetupOptions)| {
        let mut o = options();
        f(&mut o);
        setup(
            1,
            Sb::Start(pb::SetupStart {
                options: Some(o),
                password: Bytes::from_static(b"p"),
            }),
        )
    };
    ok(&with_opts(&|o| o.username = long(32)));
    bad(&with_opts(&|o| o.username = long(33)), "username");
    ok(&with_opts(&|o| {
        o.settings.as_mut().unwrap().hostname = long(63)
    }));
    bad(
        &with_opts(&|o| o.settings.as_mut().unwrap().hostname = long(64)),
        "hostname",
    );
    ok(&with_opts(&|o| {
        o.settings.as_mut().unwrap().timezone = long(64)
    }));
    bad(
        &with_opts(&|o| o.settings.as_mut().unwrap().timezone = long(65)),
        "timezone",
    );
    ok(&with_opts(&|o| {
        o.settings.as_mut().unwrap().locale = long(32)
    }));
    bad(
        &with_opts(&|o| o.settings.as_mut().unwrap().locale = long(33)),
        "locale",
    );
    ok(&with_opts(&|o| {
        o.settings.as_mut().unwrap().keyboard = long(40)
    }));
    bad(
        &with_opts(&|o| o.settings.as_mut().unwrap().keyboard = long(41)),
        "keyboard",
    );
    ok(&with_opts(&|o| o.limits.as_mut().unwrap().cpu = 1024));
    bad(
        &with_opts(&|o| o.limits.as_mut().unwrap().cpu = 1025),
        "cpu",
    );
    ok(&with_opts(&|o| {
        o.limits.as_mut().unwrap().memory_mib = 16_777_216
    }));
    bad(
        &with_opts(&|o| o.limits.as_mut().unwrap().memory_mib = 16_777_217),
        "memory_mib",
    );
    ok(&with_opts(&|o| {
        o.limits.as_mut().unwrap().disk_gib = 65_536
    }));
    bad(
        &with_opts(&|o| o.limits.as_mut().unwrap().disk_gib = 65_537),
        "disk_gib",
    );
    // Unknown enum numbers and missing options are the server's semantic business.
    ok(&with_opts(&|o| o.distro = 99));
    ok(&setup(
        1,
        Sb::Start(pb::SetupStart {
            options: None,
            password: Bytes::new(),
        }),
    ));
    // Server to client strings.
    let ack = |field: usize, msg: usize| {
        setup(
            1,
            Sb::Ack(pb::SetupAck {
                field: long(field),
                message: long(msg),
                ..Default::default()
            }),
        )
    };
    ok(&ack(64, 256));
    bad(&ack(65, 0), "ack.field");
    bad(&ack(0, 257), "ack.message");
    let prog = |step: usize, percent: u32| {
        setup(
            0,
            Sb::Progress(pb::SetupProgress {
                step: long(step),
                percent,
                ..Default::default()
            }),
        )
    };
    ok(&prog(128, 100));
    ok(&prog(0, 255));
    bad(&prog(129, 0), "progress.step");
    bad(&prog(0, 101), "progress.percent");
    bad(&prog(0, 254), "progress.percent");
}

#[test]
fn result_caps() {
    let result = |f: &dyn Fn(&mut pb::SetupResult)| {
        let mut r = pb::SetupResult::default();
        f(&mut r);
        setup(0, Sb::Result(r))
    };
    ok(&result(&|r| r.warnings = vec!["w".repeat(256); 16]));
    bad(
        &result(&|r| r.warnings = vec![String::new(); 17]),
        "warnings",
    );
    bad(&result(&|r| r.warnings = vec!["w".repeat(257)]), "warnings");
    bad(&result(&|r| r.reason = "r".repeat(257)), "reason");
    bad(
        &result(&|r| {
            r.docker = Some(pb::SetupDocker {
                hint: "h".repeat(257),
                ..Default::default()
            })
        }),
        "docker.hint",
    );
    bad(
        &result(&|r| {
            r.docker = Some(pb::SetupDocker {
                found: "h".repeat(65),
                ..Default::default()
            })
        }),
        "docker.found",
    );
    bad(
        &result(&|r| {
            r.error = Some(pb::SetupError {
                message: "e".repeat(257),
                ..Default::default()
            })
        }),
        "error.message",
    );
    // The same caps apply to the result and progress embedded in a state.
    let state = |r: pb::SetupResult| {
        setup(
            0,
            Sb::State(pb::SetupState {
                last_result: Some(r),
                ..Default::default()
            }),
        )
    };
    bad(
        &state(pb::SetupResult {
            reason: "r".repeat(257),
            ..Default::default()
        }),
        "reason",
    );
    let host = |os: usize, arch: usize| {
        setup(
            0,
            Sb::State(pb::SetupState {
                host: Some(pb::SetupHostFacts {
                    os: "o".repeat(os),
                    arch: "a".repeat(arch),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        )
    };
    ok(&host(64, 16));
    bad(&host(65, 0), "host.os");
    bad(&host(0, 17), "host.arch");
}

fn worst_result() -> pb::SetupResult {
    pb::SetupResult {
        job_id: u32::MAX,
        status: i32::MAX,
        path_taken: i32::MAX,
        reason: "r".repeat(256),
        warnings: vec!["w".repeat(256); 16],
        docker: Some(pb::SetupDocker {
            status: i32::MAX,
            docker_version: "v".repeat(64),
            found: "f".repeat(64),
            required: "q".repeat(64),
            isolation_restored: true,
            hint: "h".repeat(256),
        }),
        error: Some(pb::SetupError {
            code: i32::MAX,
            stage: i32::MAX,
            message: "m".repeat(256),
            retryable: true,
            retry_after_ms: u32::MAX,
        }),
        finished: true,
        elapsed_ms: u32::MAX,
    }
}

#[test]
fn worst_case_result_and_state_stay_far_below_64_kib() {
    let m = setup(0, Sb::Result(worst_result()));
    let bytes = message::encode(&m).unwrap();
    assert!(bytes.len() < 64 * 1024, "{}", bytes.len());
    assert!(bytes.len() <= MAX_CONTROL_MESSAGE);
    // A state embeds a full result, a full progress and the host facts.
    let state = setup(
        0,
        Sb::State(pb::SetupState {
            job: i32::MAX,
            job_id: u32::MAX,
            pin_set: true,
            desktop: i32::MAX,
            window_expires_unix: u64::MAX,
            finished: true,
            last_progress: Some(pb::SetupProgress {
                job_id: u32::MAX,
                stage: i32::MAX,
                index: u32::MAX,
                total: u32::MAX,
                step: "s".repeat(128),
                percent: 255,
                ok: true,
                elapsed_ms: u32::MAX,
            }),
            last_result: Some(worst_result()),
            host: Some(pb::SetupHostFacts {
                cpu_count: u32::MAX,
                memory_total_mib: u64::MAX,
                pool_total_gib: u64::MAX,
                pool_free_gib: u64::MAX,
                docker_supported: true,
                os: "o".repeat(64),
                arch: "a".repeat(16),
            }),
        }),
    );
    let bytes = message::encode(&state).unwrap();
    assert!(bytes.len() < 64 * 1024, "{}", bytes.len());
    // ... and it round-trips through the framed decoder.
    let framed = message::encode_framed(&state).unwrap();
    let (back, rest): (ControlMessage, _) = message::decode_framed(&framed).unwrap();
    assert!(rest.is_empty());
    assert_eq!(back, state);
}

#[test]
fn decoding_checks_hard_caps_from_the_wire() {
    // Build a message with an oversized password by hand and make sure decode refuses it.
    let mut s = start();
    s.password = Bytes::from(vec![b'x'; 2000]);
    let m = setup(1, Sb::Start(s));
    use prost::Message;
    let raw = m.encode_to_vec();
    assert!(matches!(
        message::decode::<ControlMessage>(&raw),
        Err(ProtoError::Invalid { .. })
    ));
}

#[test]
fn password_and_pin_helpers() {
    assert_eq!(password_problem(b"hunter2"), None);
    assert_eq!(password_problem("pässwörd ✓".as_bytes()), None);
    assert_eq!(password_problem(&vec![b'a'; 511]), None);
    assert!(password_problem(&vec![b'a'; 512]).is_some());
    assert!(password_problem(b"").is_some());
    assert!(password_problem(b"a\0b").is_some());
    assert!(password_problem(b"a\nb").is_some());
    assert!(password_problem(b"a\rb").is_some());
    assert!(password_problem(&[0xff, 0xfe, b'a']).is_some());
    // The message never contains the value.
    assert!(!password_problem(b"a\nsecret").unwrap().contains("secret"));
    assert_eq!(pin_problem(b"123456"), None);
    assert_eq!(pin_problem(&[b'7'; 16]), None);
    assert!(pin_problem(b"12345").is_some());
    assert!(pin_problem(&[b'7'; 17]).is_some());
    assert!(pin_problem(b"12345a").is_some());
    assert!(pin_problem("١٢٣٤٥٦".as_bytes()).is_some());
}

// ---------------------------------------------------------------------------- CreatePairingCode

#[test]
fn create_pairing_code_range_direction_and_request_id() {
    let req = |id: u32, ttl: u32| {
        mgmt(
            id,
            Dm::CreatePairingCode(pb::CreatePairingCode { expires_in_s: ttl }),
        )
    };
    ok(&req(1, 60));
    ok(&req(1, 600));
    ok(&req(u32::MAX, 900));
    bad(&req(1, 0), "expires_in_s");
    bad(&req(1, 59), "expires_in_s");
    bad(&req(1, 901), "expires_in_s");
    bad(&req(1, u32::MAX), "expires_in_s");
    bad(&req(0, 600), "request_id");
    assert_eq!(
        DeviceMgmt {
            request_id: 1,
            body: Some(Dm::CreatePairingCode(Default::default()))
        }
        .direction(),
        Some(MgmtDirection::ClientToServer)
    );
}

#[test]
fn pairing_code_issued_validation_and_direction() {
    use pb::PairingCodeStatus as St;
    let with = |id: u32, code: &str, status: i32, retry: u32| {
        mgmt(
            id,
            Dm::PairingCodeIssued(pb::PairingCodeIssued {
                code: code.into(),
                expires_at_unix: 1_900_000_000,
                status,
                retry_after_s: retry,
            }),
        )
    };
    let issued = |id: u32, code: &str| with(id, code, St::Ok as i32, 0);
    // Refusals carry no code; only RATE_LIMITED carries a wait.
    ok(&with(5, "", St::RateLimited as i32, 1800));
    ok(&with(5, "", St::RateLimited as i32, 0));
    ok(&with(5, "", St::InvalidArgument as i32, 0));
    ok(&with(5, "", St::Failed as i32, 0));
    bad(&with(5, "", St::Unspecified as i32, 0), "status");
    bad(&with(5, "ABCD-2345", 0, 0), "status");
    bad(&with(5, "ABCD-2345", 99, 0), "status");
    bad(&with(5, "ABCD-2345", St::RateLimited as i32, 5), "code");
    bad(&with(5, "ABCD-2345", St::Failed as i32, 0), "code");
    bad(&with(5, "ABCD-2345", St::InvalidArgument as i32, 0), "code");
    bad(&with(5, "", St::InvalidArgument as i32, 5), "retry_after_s");
    bad(&with(5, "", St::Failed as i32, 5), "retry_after_s");
    bad(&with(5, "ABCD-2345", St::Ok as i32, 5), "retry_after_s");
    ok(&issued(5, "ABCD-2345"));
    bad(&issued(0, "ABCD-2345"), "request_id");
    bad(&issued(5, ""), "pairing_code_issued.code");
    bad(&issued(5, &"A".repeat(17)), "pairing_code_issued.code");
    bad(&issued(5, "ABCD 2345"), "pairing_code_issued.code");
    bad(&issued(5, "ABCD\n2345"), "pairing_code_issued.code");
    assert_eq!(
        DeviceMgmt {
            request_id: 1,
            body: Some(Dm::PairingCodeIssued(Default::default()))
        }
        .direction(),
        Some(MgmtDirection::ServerToClient)
    );
}

// ---------------------------------------------------------------------------- redaction

#[test]
fn debug_of_every_secret_type_is_redacted() {
    let secret_pin = "493817650";
    let secret_pw = "tr0ub4dor&3-horse";
    let secret_code = "QZ7K-M2XP";
    let secret_data = "SPAKE2-bytes-visible";

    let pin = pb::SetupSetPin {
        pin: Bytes::from(secret_pin),
    };
    let st = pb::SetupStart {
        options: Some(options()),
        password: Bytes::from(secret_pw),
    };
    let opaque = pb::Opaque {
        data: Bytes::from(secret_data),
    };
    let issued = pb::PairingCodeIssued {
        code: secret_code.into(),
        expires_at_unix: 42,
        status: pb::PairingCodeStatus::Ok as i32,
        retry_after_s: 0,
    };

    let dumps = [
        format!("{pin:?}"),
        format!("{pin:#?}"),
        format!("{st:?}"),
        format!("{st:#?}"),
        format!("{opaque:?}"),
        format!("{opaque:#?}"),
        format!("{issued:?}"),
        format!("{issued:#?}"),
        // Through every container up to the control message.
        format!(
            "{:?}",
            SetupMessage {
                request_id: 1,
                body: Some(Sb::SetPin(pin.clone()))
            }
        ),
        format!("{:?}", setup(1, Sb::Start(st.clone()))),
        format!("{:?}", ControlMessage::new(Ctl::Pairing(opaque.clone()))),
        format!("{:?}", ControlMessage::new(Ctl::Auth(opaque.clone()))),
        format!("{:?}", mgmt(1, Dm::PairingCodeIssued(issued.clone()))),
        format!("{:#?}", mgmt(1, Dm::PairingCodeIssued(issued.clone()))),
    ];
    for d in &dumps {
        for needle in [
            secret_pin,
            secret_pw,
            secret_code,
            secret_data,
            // bytes printed as a list or as an escaped string
            "52, 57",
            "\\x",
        ] {
            assert!(!d.contains(needle), "{needle:?} leaked in {d}");
        }
        assert!(d.contains("<redacted>"), "{d}");
    }
    // Non-secret context survives: the options and the expiry stay debuggable.
    assert!(format!("{st:?}").contains("alice"));
    assert!(format!("{issued:?}").contains("42"));
    // The status is shown (and the wait), the code is not.
    let refused = pb::PairingCodeIssued {
        status: pb::PairingCodeStatus::RateLimited as i32,
        retry_after_s: 1800,
        ..Default::default()
    };
    let d = format!("{refused:?}");
    assert!(d.contains("RateLimited") && d.contains("1800"), "{d}");
    assert!(format!("{issued:?}").contains("Ok"));
    // No length leaks either.
    assert!(!format!("{pin:?}").contains(&secret_pin.len().to_string()));
}
