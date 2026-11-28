//! privd running in-process on a temporary socket, driven by a raw `hx-ipc` client: the role from
//! the real peer uid, descriptor passing, frame limits, unknown commands, the secret-frame
//! protocol, one request in flight, cancellation and deadlines.
//!
//! The test process is an ordinary user, so a connection's peer uid is that user's: it is
//! `Gateway` when the harness is configured with that uid as the gateway uid (the test-only
//! constructor) and refused when it is configured with another. Admin (uid 0) needs root; Admin
//! behaviour is covered in `privd_commands.rs` through `Ctx`.

use std::io::IoSlice;
use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::time::{Duration, Instant};

use hx_agent::privd::daemon::Ctx;
use hx_agent::privd::testing::{ExecRule, Harness, RawClient, error_of, request};
use hx_ipc::privd::pb::{self, ErrorCode, ErrorDetail, Role, frame::Frame as F, request::Command};
use prost::Message;
use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};

fn me() -> u32 {
    rustix::process::getuid().as_raw()
}

fn ok_or_panic(r: &pb::Response) {
    if let Some(pb::response::Result::Error(e)) = &r.result {
        panic!("{:?} {:?}: {}", e.code(), e.detail(), e.message);
    }
}

async fn admin(h: &Harness, command: Command) -> pb::Response {
    h.daemon
        .handle(request(1, command), Ctx::new(Role::Admin))
        .await
}

async fn open_window(h: &Harness) {
    ok_or_panic(&admin(h, Command::BeginSetup(Default::default())).await);
}

/// A frame whose protobuf body is `body` (bypasses the client-side validation of `hx-ipc`).
fn raw_frame(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut v = ((body.len() + 1) as u32).to_le_bytes().to_vec();
    v.push(kind);
    v.extend_from_slice(body);
    v
}

fn closed(c: &mut RawClient) -> bool {
    c.try_recv().is_none()
}

fn ping(c: &mut RawClient, nonce: u64) {
    c.send(F::Ping(pb::Ping { nonce }));
}

fn expect_pong(c: &mut RawClient, nonce: u64) {
    match c.recv().frame {
        Some(F::Pong(p)) => assert_eq!(p.nonce, nonce),
        other => panic!("expected Pong, got {other:?}"),
    }
}

fn err_of(r: &pb::Response) -> (ErrorCode, ErrorDetail) {
    let e = error_of(r).unwrap_or_else(|| panic!("expected an error: {r:?}"));
    (e.code(), e.detail())
}

// ----- roles and the handshake ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_role_is_derived_from_the_real_peer_uid_and_echoed_in_hello_ack() {
    let h = Harness::start(me());
    let mut c = h.connect();
    let ack = c.hello();
    assert_eq!(ack.role(), Role::Gateway);
    assert_eq!(ack.phase(), pb::Phase::Uninitialized);
    assert_eq!(ack.major, hx_ipc::privd::VERSION_MAJOR);
    assert!(!ack.privd_version.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_is_not_root_or_the_gateway_is_closed_without_a_reply() {
    // Configured gateway uid is someone else's; this process is neither root nor that user.
    let h = Harness::start(me() + 1);
    let mut c = h.connect();
    // privd may close before this write: the Hello is best effort, the close is what is tested.
    c.send_maybe_closed(F::Hello(pb::Hello {
        major: hx_ipc::privd::VERSION_MAJOR,
        minor: 0,
        software: "x".into(),
    }));
    assert!(closed(&mut c), "no reply, only a close");
    // It is logged.
    for _ in 0..50 {
        if h.audit
            .lines()
            .iter()
            .any(|l| l.contains("refused a connection"))
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the refusal was not audited: {:?}", h.audit.lines());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_role_is_never_a_message_field_a_gateway_cannot_call_admin_commands() {
    let h = Harness::start(me());
    let mut c = h.connect();
    c.hello();
    let r = c.call(Command::BeginSetup(Default::default()), &[]);
    assert_eq!(err_of(&r).0, ErrorCode::PermissionDenied);
    let r = c.call(Command::GetHostInfo(Default::default()), &[]);
    ok_or_panic(&r);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_different_major_version_is_a_failed_precondition_and_a_close() {
    let h = Harness::start(me());
    let mut c = h.connect();
    c.send(F::Hello(pb::Hello {
        major: hx_ipc::privd::VERSION_MAJOR + 1,
        minor: 0,
        software: "future".into(),
    }));
    match c.recv().frame {
        Some(F::Response(r)) => assert_eq!(err_of(&r).0, ErrorCode::FailedPrecondition),
        other => panic!("{other:?}"),
    }
    assert!(closed(&mut c));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_before_hello_closes_the_connection() {
    let h = Harness::start(me());
    let mut c = h.connect();
    c.send(F::Request(pb::Request {
        request_id: 1,
        command: Some(Command::GetHostInfo(Default::default())),
        ..Default::default()
    }));
    assert!(closed(&mut c));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hello_must_arrive_within_five_seconds() {
    let h = Harness::start(me());
    let mut c = h.connect();
    let started = Instant::now();
    assert!(closed(&mut c));
    let t = started.elapsed();
    assert!(
        t >= Duration::from_secs(4) && t < Duration::from_secs(9),
        "{t:?}"
    );
}

// ----- ipc.md 7 rule 13 and framing --------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rule_13_a_descriptor_sent_with_scm_rights_closes_the_connection() {
    let h = Harness::start(me());
    let mut c = h.connect();
    c.hello();
    // A perfectly valid Ping frame, with a file descriptor attached.
    let bytes = hx_ipc::privd::encode_message(
        &pb::Frame {
            frame: Some(F::Ping(pb::Ping { nonce: 1 })),
        },
        hx_ipc::privd::Side::Server,
    )
    .unwrap();
    let f = std::fs::File::open("/dev/null").unwrap();
    let fds = [f.as_fd()];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ctl = SendAncillaryBuffer::new(&mut space);
    assert!(ctl.push(SendAncillaryMessage::ScmRights(&fds)));
    sendmsg(
        &c.stream,
        &[IoSlice::new(&bytes)],
        &mut ctl,
        SendFlags::empty(),
    )
    .unwrap();
    // No Pong: the connection is closed, the descriptor never installed.
    assert!(closed(&mut c));
    // And privd itself is fine: a new connection works.
    let mut c2 = h.connect();
    c2.hello();
    // privd holds no leaked descriptor for it (best effort: its open fd count stays small).
    let fds_open = std::fs::read_dir("/proc/self/fd").unwrap().count();
    assert!(fds_open < 200, "{fds_open} descriptors open");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversize_zero_length_and_unknown_kind_frames_close_the_connection() {
    let h = Harness::start(me());
    let big = hx_ipc::privd::MAX_MESSAGE_LENGTH + 1;
    for (what, bytes) in [
        ("message above 65 536", {
            let mut v = big.to_le_bytes().to_vec();
            v.push(1);
            v
        }),
        ("zero length", vec![0, 0, 0, 0, 1]),
        ("secret above 8 192", {
            let mut v = (hx_ipc::privd::MAX_SECRET_LENGTH + 1)
                .to_le_bytes()
                .to_vec();
            v.push(2);
            v
        }),
        ("unknown kind", {
            let mut v = 5u32.to_le_bytes().to_vec();
            v.push(9);
            v.extend_from_slice(&[0; 4]);
            v
        }),
        (
            "garbage protobuf",
            raw_frame(1, &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        ),
    ] {
        let mut c = h.connect();
        c.hello();
        c.send_raw(&bytes);
        assert!(closed(&mut c), "{what}");
    }
    // Nothing was allocated from the announced length: the daemon is still up.
    let mut c = h.connect();
    c.hello();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frame_body_that_stalls_is_dropped_after_five_seconds() {
    let h = Harness::start(me());
    let mut c = h.connect();
    c.hello();
    // A header that promises 100 bytes and then silence.
    c.send_raw(&[101, 0, 0, 0, 1, 1, 2, 3]);
    let started = Instant::now();
    assert!(closed(&mut c));
    let t = started.elapsed();
    assert!(
        t >= Duration::from_secs(4) && t < Duration::from_secs(9),
        "{t:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unknown_command_is_invalid_argument_and_the_connection_stays_usable() {
    let h = Harness::start(me());
    let mut c = h.connect();
    c.hello();
    // A Request whose command is a field number privd does not know: prost ignores the unknown
    // field, so no command is set. (Hand-encoded: the field is 99, length-delimited, empty.)
    let body = pb::Frame {
        frame: Some(F::Request(pb::Request {
            request_id: 77,
            ..Default::default()
        })),
    }
    .encode_to_vec();
    // Append an unknown field to the inner Request: re-encode by hand.
    let mut inner = pb::Request {
        request_id: 77,
        ..Default::default()
    }
    .encode_to_vec();
    inner.extend_from_slice(&[0x9a, 0x06, 0x00]); // field 99, wire type 2, length 0
    let mut frame = vec![0x1a, inner.len() as u8]; // Frame.request = 3, length-delimited
    frame.extend_from_slice(&inner);
    assert_ne!(body, frame);
    c.send_raw(&raw_frame(1, &frame));
    match c.recv().frame {
        Some(F::Response(r)) => {
            assert_eq!(r.request_id, 77);
            assert_eq!(err_of(&r).0, ErrorCode::InvalidArgument);
        }
        other => panic!("{other:?}"),
    }
    ping(&mut c, 5);
    expect_pong(&mut c, 5);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_field_rule_violation_is_invalid_argument_naming_the_field() {
    let h = Harness::start(me());
    open_window(&h).await;
    let mut c = h.connect();
    c.hello();
    // desktop_id with a forbidden character, hand-encoded to get past the client-side check.
    let req = pb::Request {
        request_id: 12,
        command: Some(Command::GetDesktop(pb::GetDesktopRequest {
            desktop_id: "Bad Id".into(),
        })),
        ..Default::default()
    };
    let body = pb::Frame {
        frame: Some(F::Request(req)),
    }
    .encode_to_vec();
    c.send_raw(&raw_frame(1, &body));
    match c.recv().frame {
        Some(F::Response(r)) => {
            assert_eq!(r.request_id, 12);
            let e = error_of(&r).unwrap();
            assert_eq!(e.code(), ErrorCode::InvalidArgument);
            assert!(e.message.contains("desktop_id"), "{}", e.message);
        }
        other => panic!("{other:?}"),
    }
    ping(&mut c, 1);
    expect_pong(&mut c, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeated_request_id_is_invalid_argument() {
    let h = Harness::start(me());
    let mut c = h.connect();
    c.hello();
    let r = c.call_with_id(9, Command::GetHostInfo(Default::default()), &[], 0);
    ok_or_panic(&r);
    let r = c.call_with_id(9, Command::GetHostInfo(Default::default()), &[], 0);
    assert_eq!(err_of(&r).0, ErrorCode::InvalidArgument);
    // Request id 0 is invalid too (hand-encoded: the typed encoder refuses it).
    let body = pb::Frame {
        frame: Some(F::Request(pb::Request {
            request_id: 0,
            command: Some(Command::GetHostInfo(Default::default())),
            ..Default::default()
        })),
    }
    .encode_to_vec();
    c.send_raw(&raw_frame(1, &body));
    assert!(closed(&mut c), "no id to answer: the connection is closed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ping_is_answered_at_once_and_rate_limited() {
    let h = Harness::start(me());
    let mut c = h.connect();
    c.hello();
    for n in 0..40 {
        ping(&mut c, n);
    }
    let id = c.fresh_id();
    c.send_request(id, Command::GetHostInfo(Default::default()), &[], 0);
    let mut pongs = 0;
    loop {
        match c.recv().frame {
            Some(F::Pong(_)) => pongs += 1,
            Some(F::Response(r)) if r.request_id == id => break,
            other => panic!("{other:?}"),
        }
    }
    assert!((1..40).contains(&pongs), "{pongs} pongs for 40 pings");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn at_most_four_connections_per_role() {
    let h = Harness::start(me());
    let mut held = Vec::new();
    for _ in 0..4 {
        let mut c = h.connect();
        c.hello();
        held.push(c);
    }
    let mut fifth = h.connect();
    // Closed at accept, possibly before this write lands.
    fifth.send_maybe_closed(F::Hello(pb::Hello {
        major: hx_ipc::privd::VERSION_MAJOR,
        minor: 0,
        software: "x".into(),
    }));
    assert!(
        closed(&mut fifth),
        "the fifth Gateway connection is closed at accept"
    );
    // Closing one frees the slot.
    drop(held.pop());
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut again = h.connect();
    again.hello();
}

// ----- secrets (ipc.md 5.2, 7 rule 9) ---------------------------------------------------------------------

fn enrol_slots(len: u32) -> Vec<pb::SecretSlot> {
    vec![pb::SecretSlot {
        slot: 0,
        kind: pb::SecretKind::MacInput as i32,
        length: len,
        ..Default::default()
    }]
}

fn enrol_request(id: u64, slots: Vec<pb::SecretSlot>) -> F {
    F::Request(pb::Request {
        request_id: id,
        secret_slots: slots,
        command: Some(Command::PepperEnrol(pb::PepperEnrolRequest {
            purpose: pb::LockoutPurpose::Pin as i32,
        })),
        ..Default::default()
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_secret_that_matches_its_slot_is_accepted_and_used() {
    let h = Harness::start(me());
    open_window(&h).await;
    let mut c = h.connect();
    c.hello();
    let r = c.call(
        Command::PepperEnrol(pb::PepperEnrolRequest {
            purpose: pb::LockoutPurpose::Pin as i32,
        }),
        &[(pb::SecretKind::MacInput, &[1u8; 32])],
    );
    match r.result {
        Some(pb::response::Result::PepperEnrol(e)) => assert_eq!(e.mac.len(), 32),
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn secret_frames_that_do_not_match_the_pending_request_reject_it() {
    let h = Harness::start(me());
    open_window(&h).await;
    // (what, request id of the secret frame, slot, bytes)
    let cases: Vec<(&str, u64, u8, Vec<u8>)> = vec![
        ("another request's id", 999, 0, vec![1; 32]),
        ("an undeclared slot", 5, 1, vec![1; 32]),
        (
            "a length different from the declared one",
            5,
            0,
            vec![1; 31],
        ),
    ];
    for (what, id, slot, bytes) in cases {
        let mut c = h.connect();
        c.hello();
        c.send(enrol_request(5, enrol_slots(32)));
        c.send_secret(id, slot, &bytes);
        let r = c.wait_response(5);
        assert_eq!(err_of(&r).0, ErrorCode::InvalidArgument, "{what}");
        // The framing after a bad secret cannot be trusted: the connection is closed.
        assert!(closed(&mut c), "{what}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frame_that_is_not_the_secret_rejects_the_request() {
    let h = Harness::start(me());
    open_window(&h).await;
    let mut c = h.connect();
    c.hello();
    c.send(enrol_request(5, enrol_slots(32)));
    ping(&mut c, 1); // not a secret frame
    let r = c.wait_response(5);
    assert_eq!(err_of(&r).0, ErrorCode::InvalidArgument);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_secret_frame_that_comes_late_rejects_the_request() {
    let h = Harness::start(me());
    open_window(&h).await;
    let mut c = h.connect();
    c.hello();
    c.send(enrol_request(5, enrol_slots(32)));
    let started = Instant::now();
    // Sent after the 5 s limit.
    std::thread::sleep(Duration::from_millis(5_500));
    {
        // privd has already answered and closed: the late write may fail, which is fine.
        use std::io::Write;
        let late = hx_ipc::privd::encode_secret(5, 0, &[1; 32]).unwrap();
        let _ = c.stream.write_all(&late);
    }
    let r = c.wait_response(5);
    assert_eq!(err_of(&r).0, ErrorCode::InvalidArgument);
    assert!(started.elapsed() < Duration::from_secs(9));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_secret_frame_without_a_request_closes_the_connection() {
    let h = Harness::start(me());
    let mut c = h.connect();
    c.hello();
    c.send_secret(1, 0, &[1; 32]);
    assert!(closed(&mut c));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rule_9_a_secret_of_the_wrong_kind_or_a_plain_token_is_invalid_and_the_stream_stays_in_sync()
 {
    let h = Harness::start(me());
    open_window(&h).await;
    let mut c = h.connect();
    c.hello();
    // SetUserPassword expects USER_PASSWORD in slot 0; a MAC_INPUT there is the wrong kind.
    let wrong = F::Request(pb::Request {
        request_id: 3,
        secret_slots: enrol_slots(32),
        command: Some(Command::SetUserPassword(pb::SetUserPasswordRequest {
            desktop_id: "main".into(),
        })),
        ..Default::default()
    });
    // Hand-encoded: the typed encoder would refuse it.
    let body = pb::Frame { frame: Some(wrong) }.encode_to_vec();
    c.send_raw(&raw_frame(1, &body));
    c.send_secret(3, 0, &[7; 32]);
    let r = c.wait_response(3);
    assert_eq!(err_of(&r).0, ErrorCode::InvalidArgument);
    // The announced secret frame was swallowed: the connection is still in sync.
    ping(&mut c, 8);
    expect_pong(&mut c, 8);

    // A plain DRIVE_TOKEN (Phase 2 secrets are sealed only) is invalid, too.
    let plain = F::Request(pb::Request {
        request_id: 4,
        secret_slots: vec![pb::SecretSlot {
            slot: 0,
            kind: pb::SecretKind::DriveToken as i32,
            sealed: false,
            length: 10,
            ..Default::default()
        }],
        command: Some(Command::SetBackupCredentials(Default::default())),
        ..Default::default()
    });
    let body = pb::Frame { frame: Some(plain) }.encode_to_vec();
    c.send_raw(&raw_frame(1, &body));
    c.send_secret(4, 0, &[7; 10]);
    let r = c.wait_response(4);
    assert_eq!(err_of(&r).0, ErrorCode::InvalidArgument);
    ping(&mut c, 9);
    expect_pong(&mut c, 9);
}

// ----- one request in flight, cancel and deadlines -------------------------------------------------------------

fn add_ready_desktop(h: &Harness) {
    h.incus
        .add_desktop("hx-main", "ubuntu-24.04-xfce-basic", "alice", true);
    h.daemon.register_desktop("main").unwrap();
}

fn slow_password_change(h: &Harness, delay: Duration) {
    h.incus.with(|s| {
        s.exec_rules.insert(
            0,
            ExecRule {
                needle: "chpasswd".into(),
                exit: 0,
                stdout: String::new(),
                delay: Some(delay),
            },
        );
    });
}

fn set_password(c: &mut RawClient, id: u64, password: &[u8]) {
    c.send_request(
        id,
        Command::SetUserPassword(pb::SetUserPasswordRequest {
            desktop_id: "main".into(),
        }),
        &[(pb::SecretKind::UserPassword, password)],
        0,
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_request_while_one_runs_is_resource_exhausted_but_ping_still_answers() {
    let h = Harness::start(me());
    open_window(&h).await;
    add_ready_desktop(&h);
    slow_password_change(&h, Duration::from_millis(600));
    let mut c = h.connect();
    c.hello();
    set_password(&mut c, 10, b"Correct-Horse-Battery-9");
    std::thread::sleep(Duration::from_millis(150));
    ping(&mut c, 3);
    expect_pong(&mut c, 3);
    c.send_request(11, Command::GetHostInfo(Default::default()), &[], 0);
    let second = c.wait_response(11);
    assert_eq!(err_of(&second).0, ErrorCode::ResourceExhausted);
    let first = c.wait_response(10);
    ok_or_panic(&first);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_password_section_is_shielded_from_cancel_and_holds_the_desktop_lock() {
    let h = Harness::start(me());
    open_window(&h).await;
    add_ready_desktop(&h);
    slow_password_change(&h, Duration::from_millis(900));
    let password = b"Correct-Horse-Battery-9";
    let mut c = h.connect();
    c.hello();
    set_password(&mut c, 10, password);
    std::thread::sleep(Duration::from_millis(250));
    // While the password is being set, nothing else may touch the desktop: a stop on a second
    // connection waits for the lock and gives up at its own deadline.
    let mut other = h.connect();
    other.hello();
    let started = Instant::now();
    let stop = other.call_with_id(
        1,
        Command::StopDesktop(pb::StopDesktopRequest {
            desktop_id: "main".into(),
            force: false,
        }),
        &[],
        300,
    );
    assert_eq!(err_of(&stop).0, ErrorCode::DeadlineExceeded);
    assert!(started.elapsed() < Duration::from_millis(800));
    assert!(
        !h.incus
            .log()
            .iter()
            .any(|l| l.ends_with("/instances/hx-main/state") && l.starts_with("PUT")),
        "the stop must not have run: {:?}",
        h.incus.log()
    );
    // Cancel: keep polling and hold the lock; CANCELLED only after chpasswd really ended.
    let cancelled_at = Instant::now();
    c.send(F::Cancel(pb::Cancel { request_id: 10 }));
    let r = c.wait_response(10);
    assert_eq!(err_of(&r).0, ErrorCode::Cancelled);
    assert!(
        cancelled_at.elapsed() >= Duration::from_millis(300),
        "answered before the shielded section ended ({:?})",
        cancelled_at.elapsed()
    );
    // The shielded section ran to the end: chpasswd was executed and the stdin file is gone.
    assert!(
        h.incus
            .with(|s| s.execs.iter().any(|e| e.contains("chpasswd")))
    );
    assert!(
        h.incus
            .with(|s| !s.files.keys().any(|k| k.contains("stdin")))
    );
    // The password is in no argv and no audit line.
    assert!(
        h.incus
            .with(|s| !s.execs.iter().any(|e| e.contains("Correct-Horse")))
    );
    assert!(h.audit.lines().iter().all(|l| !l.contains("Correct-Horse")));
    // The lock is free again afterwards.
    let r = other.call(
        Command::StopDesktop(pb::StopDesktopRequest {
            desktop_id: "main".into(),
            force: false,
        }),
        &[],
    );
    ok_or_panic(&r);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deadline_shortens_the_command_and_expires_as_deadline_exceeded() {
    let h = Harness::start(me());
    open_window(&h).await;
    add_ready_desktop(&h);
    h.incus.with(|s| {
        s.instances.get_mut("hx-main").unwrap().status = "Stopped".into();
        // The readiness probe answers "starting" after 700 ms: a start never completes in time.
        s.exec_rules[0].stdout = "starting\n".into();
        s.exec_rules[0].delay = Some(Duration::from_millis(700));
    });
    let mut c = h.connect();
    c.hello();
    let started = Instant::now();
    let r = c.call_with_id(
        4,
        Command::StartDesktop(pb::StartDesktopRequest {
            desktop_id: "main".into(),
        }),
        &[],
        250,
    );
    assert_eq!(err_of(&r).0, ErrorCode::DeadlineExceeded);
    let t = started.elapsed();
    // Not before the deadline, and only after the operation ended (the probe's 700 ms).
    assert!(t >= Duration::from_millis(250), "{t:?}");
    assert!(t < Duration::from_secs(5), "{t:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_force_stops_the_unfinished_desktop_and_answers_only_after_cleanup() {
    let h = Harness::start(me());
    open_window(&h).await;
    // Every command in the build stage hangs until the instance is stopped (Incus 6.0.0 refuses
    // to cancel exec operations; a forced stop is what ends them).
    h.incus.with(|s| {
        s.exec_rules.push(ExecRule {
            needle: "".into(),
            exit: 0,
            stdout: String::new(),
            delay: None,
        });
    });
    let mut c = h.connect();
    c.hello();
    let id = c.fresh_id();
    c.send_request(
        id,
        Command::CreateDesktop(pb::CreateDesktopRequest {
            desktop_id: "main".into(),
            distro: pb::Distro::Ubuntu2404 as i32,
            desktop: pb::DesktopKind::Xfce as i32,
            preset: pb::Preset::Basic as i32,
            username: "alice".into(),
            ..Default::default()
        }),
        &[(pb::SecretKind::UserPassword, b"Correct-Horse-Battery-9")],
        0,
    );
    // Wait until the build is hanging inside the container.
    let started = Instant::now();
    loop {
        if h.incus
            .with(|s| s.execs.len() > 1 && s.instances.contains_key("hx-main"))
        {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the build never started"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    c.send(F::Cancel(pb::Cancel { request_id: id }));
    let r = c.wait_response(id);
    assert_eq!(err_of(&r).0, ErrorCode::Cancelled);
    // The answer came after the work really ended: the instance is stopped and deleted, its
    // operations are over and the record is gone.
    let log = h.incus.log();
    let stop = log
        .iter()
        .position(|l| l == "PUT /1.0/instances/hx-main/state")
        .expect("a forced stop");
    let delete = log
        .iter()
        .position(|l| l == "DELETE /1.0/instances/hx-main")
        .expect("a delete");
    assert!(stop < delete);
    assert!(h.incus.instance_names().is_empty());
    assert!(h.daemon.read_state(|s| s.desktops.is_empty()));
    // The exec operations were asked to cancel first (and refused, as on a real 6.0.0 daemon).
    assert!(log.iter().any(|l| l.starts_with("DELETE /1.0/operations/")));
    assert!(started.elapsed() < Duration::from_secs(20));
    // The desktop id can be created again straight away.
    h.incus.with(|s| s.exec_rules.pop());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_closed_connection_cancels_the_running_command() {
    let h = Harness::start(me());
    open_window(&h).await;
    add_ready_desktop(&h);
    slow_password_change(&h, Duration::from_millis(400));
    {
        let mut c = h.connect();
        c.hello();
        set_password(&mut c, 10, b"Correct-Horse-Battery-9");
        std::thread::sleep(Duration::from_millis(150));
    } // dropped: the connection closes while the shielded section runs
    // The section still ends (shielded) and releases the lock; a new connection can use the desktop.
    let mut c = h.connect();
    c.hello();
    let r = c.call(
        Command::StopDesktop(pb::StopDesktopRequest {
            desktop_id: "main".into(),
            force: false,
        }),
        &[],
    );
    ok_or_panic(&r);
    assert!(
        h.incus
            .with(|s| !s.files.keys().any(|k| k.contains("stdin")))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_stays_usable_after_a_request_that_streamed_progress() {
    let h = Harness::start(me());
    open_window(&h).await;
    // Slow every command in the container a little, so that progress frames are due.
    h.incus.with(|s| {
        s.exec_rules.push(ExecRule {
            needle: "".into(),
            exit: 0,
            stdout: String::new(),
            delay: Some(Duration::from_millis(25)),
        });
    });
    let mut c = h.connect();
    c.hello();
    let id = c.fresh_id();
    c.send_request(
        id,
        Command::CreateDesktop(pb::CreateDesktopRequest {
            desktop_id: "main".into(),
            distro: pb::Distro::Ubuntu2404 as i32,
            desktop: pb::DesktopKind::Xfce as i32,
            preset: pb::Preset::Basic as i32,
            username: "alice".into(),
            ..Default::default()
        }),
        &[(pb::SecretKind::UserPassword, b"Correct-Horse-Battery-9")],
        0,
    );
    let mut progress = 0;
    loop {
        match c.recv().frame {
            Some(F::Progress(_)) => progress += 1,
            Some(F::Response(r)) if r.request_id == id => {
                ok_or_panic(&r);
                break;
            }
            other => panic!("{other:?}"),
        }
    }
    assert!(progress > 0, "the create streamed progress");
    // The same connection serves the next requests.
    for _ in 0..3 {
        let r = c.call(
            Command::GetDesktop(pb::GetDesktopRequest {
                desktop_id: "main".into(),
            }),
            &[],
        );
        ok_or_panic(&r);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l1_a_cancel_during_the_create_post_stage_waits_for_the_sweep_before_the_destroy() {
    let h = Harness::start(me());
    open_window(&h).await;
    // The password step takes a while (and so is cancellable-looking for a long time).
    h.incus.with(|s| {
        s.exec_rules.insert(
            0,
            ExecRule {
                needle: "chpasswd".into(),
                exit: 0,
                stdout: String::new(),
                delay: Some(Duration::from_millis(800)),
            },
        );
    });
    let mut c = h.connect();
    c.hello();
    let id = c.fresh_id();
    c.send_request(
        id,
        Command::CreateDesktop(pb::CreateDesktopRequest {
            desktop_id: "main".into(),
            distro: pb::Distro::Ubuntu2404 as i32,
            desktop: pb::DesktopKind::Xfce as i32,
            preset: pb::Preset::Basic as i32,
            username: "alice".into(),
            ..Default::default()
        }),
        &[(pb::SecretKind::UserPassword, b"Correct-Horse-Battery-9")],
        0,
    );
    let started = Instant::now();
    while !h
        .incus
        .with(|s| s.execs.iter().any(|e| e.contains("chpasswd")))
    {
        assert!(started.elapsed() < Duration::from_secs(10));
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    c.send(F::Cancel(pb::Cancel { request_id: id }));
    let r = c.wait_response(id);
    assert_eq!(err_of(&r).0, ErrorCode::Cancelled);
    let log = h.incus.log();
    let chpasswd = log
        .iter()
        .position(|l| l.starts_with("EXEC") && l.contains("chpasswd"))
        .unwrap();
    let sweep_after = log
        .iter()
        .rposition(|l| l.starts_with("EXEC find /run/hx-provision"))
        .unwrap();
    let delete = log
        .iter()
        .position(|l| l == "DELETE /1.0/instances/hx-main")
        .unwrap();
    assert!(
        chpasswd < sweep_after,
        "the sweep after the password step ran"
    );
    assert!(
        sweep_after < delete,
        "and it ran before the instance was destroyed"
    );
    assert!(h.incus.instance_names().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l6_a_gateway_peer_holding_a_forbidden_group_is_refused_at_accept() {
    let h = Harness::start(me());
    let mut ok_client = h.connect();
    assert_eq!(ok_client.hello().role(), Role::Gateway);
    // One of this process's own gids becomes a forbidden group in the account files.
    let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut gids = hx_agent::privd::peergroups::peer_groups(&a).unwrap();
    gids.push(rustix::process::getgid().as_raw());
    let gid = gids[0];
    std::fs::write(
        h.dir.path().join("group"),
        format!("root:x:0:\nhx-gatewayd:x:{}:\ndocker:x:{gid}:\n", me()),
    )
    .unwrap();
    let mut c = h.connect();
    // Refused at accept, possibly before this write lands.
    c.send_maybe_closed(F::Hello(pb::Hello {
        major: hx_ipc::privd::VERSION_MAJOR,
        minor: 0,
        software: "x".into(),
    }));
    assert!(
        closed(&mut c),
        "no reply for a peer holding a forbidden group"
    );
    assert!(
        h.audit
            .lines()
            .iter()
            .any(|l| l.contains("refused a Gateway connection"))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n11_a_slow_host_refresh_at_start_does_not_block_the_accept_loop() {
    use hx_agent::privd::activation::bind_path;
    use hx_agent::privd::runner::{RunOutput, Tool};
    use hx_agent::privd::testing::{FakeIncus, FakeProbe, FakeRunner};
    use std::sync::atomic::{AtomicBool, Ordering};
    let slow = std::sync::Arc::new(AtomicBool::new(false));
    let s2 = slow.clone();
    let runner = FakeRunner::with(move |p| {
        if p.tool == Tool::Ip && s2.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_secs(3));
        }
        RunOutput {
            code: Some(0),
            stdout: if p.tool == Tool::Ip {
                r#"[{"ifname":"eth0","addr_info":[{"family":"inet","local":"203.0.113.9"}]}]"#
                    .into()
            } else {
                String::new()
            },
            ..Default::default()
        }
    });
    let h = Harness::start_with(me(), FakeProbe::default(), FakeIncus::new(), runner);
    // SetupHost records what a refresh would re-apply.
    ok_or_panic(&admin(&h, Command::SetupHost(Default::default())).await);
    // A second daemon, "restarted" over the same state, whose refresh takes 3 s.
    slow.store(true, Ordering::SeqCst);
    let d2 = h.restart_daemon();
    let path = h.dir.path().join("second.sock");
    let listener = bind_path(&path).unwrap();
    tokio::spawn(hx_agent::privd::serve(
        d2,
        listener,
        hx_agent::privd::ServeOptions {
            background_tasks: true,
        },
        std::future::pending::<()>(),
    ));
    let started = Instant::now();
    let mut c = RawClient::connect(&path);
    c.hello();
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the first Hello waited {:?} for the refresh",
        started.elapsed()
    );
}
