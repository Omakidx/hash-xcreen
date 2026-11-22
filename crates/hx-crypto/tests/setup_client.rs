//! The setup client (`hx_crypto::setup`) against the real `Authenticator` with fake gates and
//! a scripted gateway on the authorized control-only connection.

mod common;

use std::time::Duration;

use common::{Env, Gate, PREF, Verifier, config, within};
use hx_crypto::{
    Error, Outcome, PinReply, PinVerdict, SetupAdmission,
    pin::MAX_PIN_FAILURES,
    secrets::Pin,
    setup::{Password, SetupAuth, SetupConnectOptions, SetupEvent, SetupSession, connect_setup},
};
use hx_proto::{
    channel::CloseCode,
    pb::{self, control_message::Message as Ctl, setup_message::Body as Sb},
    version::ProtocolVersion,
};
use hx_transport::Connection;
use tokio::task::JoinHandle;

fn opts(e: &Env) -> SetupConnectOptions {
    SetupConnectOptions {
        confirmed_server_version: Some(e.paired_version),
        preference: PREF,
        device_name: "laptop".into(),
        request_timeout: Duration::from_secs(5),
        ..Default::default()
    }
}

fn pin(s: &str) -> Pin {
    Pin::new(s).expect("pin")
}

fn setup_options() -> pb::SetupOptions {
    pb::SetupOptions {
        distro: pb::SetupDistro::Ubuntu2404 as i32,
        preset: pb::SetupPreset::Basic as i32,
        username: "alice".into(),
        ..Default::default()
    }
}

// ------------------------------------------------------------------ fake gateway

fn setup_msg(request_id: u32, body: Sb) -> pb::ControlMessage {
    pb::ControlMessage::new(Ctl::Setup(pb::SetupMessage {
        request_id,
        body: Some(body),
    }))
}

async fn push(c: &Connection, body: Sb) {
    c.send_control(&setup_msg(0, body)).await.expect("push");
}

async fn ack(c: &Connection, id: u32, status: pb::SetupAckStatus, job_id: u32) {
    c.send_control(&setup_msg(
        id,
        Sb::Ack(pb::SetupAck {
            status: status as i32,
            job_id,
            ..Default::default()
        }),
    ))
    .await
    .expect("ack");
}

async fn recv_request(c: &Connection) -> pb::SetupMessage {
    match within(c.recv_control()).await.expect("request").message {
        Some(Ctl::Setup(m)) => m,
        other => panic!("expected a setup message, got {other:?}"),
    }
}

fn state(pin_set: bool, job: pb::SetupJobState) -> pb::SetupState {
    pb::SetupState {
        job: job as i32,
        pin_set,
        ..Default::default()
    }
}

fn progress(job_id: u32, index: u32) -> pb::SetupProgress {
    pb::SetupProgress {
        job_id,
        index,
        total: 2,
        step: format!("step {index}"),
        percent: 50,
        ok: true,
        ..Default::default()
    }
}

fn result(finished: bool) -> pb::SetupResult {
    pb::SetupResult {
        job_id: 1,
        status: pb::SetupJobState::Succeeded as i32,
        finished,
        ..Default::default()
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    /// Answers each request in order; `start` pushes progress and a result after the ack.
    Normal,
    /// Pushes arrive between the request and its ack.
    PushesFirst,
    /// The first request is answered only together with the second (the client gave up on
    /// the first); both answers arrive back to back.
    LateFirstAck,
    /// Answers a request with an id that was never used.
    Unsolicited,
    /// Closes with SETUP_CLOSED on the first request.
    CloseOnRequest,
}

/// The gateway's side of an authorized setup connection: send the first state, then serve
/// requests according to `mode`.
fn serve(c: Connection, pin_set: bool, mode: Mode) -> JoinHandle<()> {
    tokio::spawn(async move {
        push(&c, Sb::State(state(pin_set, pb::SetupJobState::Idle))).await;
        let mut first: Option<u32> = None;
        loop {
            let Ok(Ok(m)) = tokio::time::timeout(Duration::from_secs(30), c.recv_control()).await
            else {
                return;
            };
            let Some(Ctl::Setup(req)) = m.message else {
                if matches!(m.message, Some(Ctl::Goodbye(_))) {
                    continue;
                }
                return;
            };
            let id = req.request_id;
            match (mode, req.body) {
                (Mode::CloseOnRequest, _) => {
                    c.close(CloseCode::SetupClosed, "window closed").await;
                    return;
                }
                (Mode::Unsolicited, _) => {
                    ack(&c, id + 100, pb::SetupAckStatus::Ok, 0).await;
                }
                (Mode::LateFirstAck, _) => match first {
                    None => first = Some(id),
                    Some(f) => {
                        ack(&c, f, pb::SetupAckStatus::Ok, 111).await;
                        ack(&c, id, pb::SetupAckStatus::Ok, 222).await;
                    }
                },
                (Mode::PushesFirst, Some(Sb::Start(_))) => {
                    push(&c, Sb::Progress(progress(1, 1))).await;
                    push(&c, Sb::State(state(true, pb::SetupJobState::Running))).await;
                    ack(&c, id, pb::SetupAckStatus::Ok, 1).await;
                    push(&c, Sb::Progress(progress(1, 2))).await;
                }
                (_, Some(Sb::SetPin(p))) => {
                    assert!(p.pin.len() >= 6);
                    ack(&c, id, pb::SetupAckStatus::Ok, 0).await;
                    push(&c, Sb::State(state(true, pb::SetupJobState::Idle))).await;
                }
                (_, Some(Sb::Start(s))) => {
                    assert_eq!(s.options.expect("options").username, "alice");
                    assert_eq!(s.password, b"correct horse"[..]);
                    ack(&c, id, pb::SetupAckStatus::Ok, 1).await;
                    push(&c, Sb::State(state(true, pb::SetupJobState::Running))).await;
                    push(&c, Sb::Progress(progress(1, 1))).await;
                    push(&c, Sb::Progress(progress(1, 2))).await;
                    push(&c, Sb::Result(result(false))).await;
                }
                (_, Some(Sb::Cancel(_))) => {
                    ack(&c, id, pb::SetupAckStatus::Ok, 0).await;
                }
                (_, Some(Sb::Finish(_))) => {
                    ack(&c, id, pb::SetupAckStatus::Ok, 0).await;
                    push(&c, Sb::Result(result(true))).await;
                    // QUIC drops stream data the peer has not read yet when the connection
                    // closes: a server lets the client read its last messages first.
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    c.close(CloseCode::NoError, "setup finished").await;
                    return;
                }
                _ => return,
            }
        }
    })
}

/// Connect with the client while the authenticator side runs; returns the client's answer and
/// the server's outcome.
async fn connect(e: &mut Env) -> (Result<SetupAuth, Error>, Outcome) {
    let o = opts(e);
    connect_with(e, o).await
}

async fn connect_with(e: &mut Env, o: SetupConnectOptions) -> (Result<SetupAuth, Error>, Outcome) {
    let (target, device, key) = (e.target(), e.device.clone(), e.server_key.public());
    let client = tokio::spawn(async move { connect_setup(&target, &device, key, &o).await });
    let outcome = e.next().await.expect("outcome");
    if let Outcome::Setup { connection, .. } = &outcome {
        // The gateway sends SetupState right after the authenticator authorized the
        // connection: do it here so the client's first read completes.
        push(connection, Sb::State(state(false, pb::SetupJobState::Idle))).await;
    }
    (within(client).await.expect("join"), outcome)
}

async fn ready(auth: Result<SetupAuth, Error>) -> SetupSession {
    match auth.expect("connects") {
        SetupAuth::Ready(s) => s,
        SetupAuth::NeedsPin(_) => panic!("expected Ready"),
    }
}

// ------------------------------------------------------------------ KeyOnly

#[tokio::test]
async fn key_only_then_set_pin_start_progress_result_and_finish() {
    let mut e = Env::new(config()).await;
    e.auth.set_setup_gate(Gate::new(SetupAdmission::KeyOnly));
    let (auth, outcome) = connect(&mut e).await;
    let Outcome::Setup {
        connection,
        pin_verified,
        ..
    } = outcome
    else {
        panic!("expected Setup");
    };
    assert!(!pin_verified);
    let mut s = ready(auth).await;
    assert!(!s.state().pin_set);
    // From here the gateway serves requests (its first state was already sent above).
    // `serve` pushes a state of its own; the client reads it as an event.
    let server = serve(connection.clone(), false, Mode::Normal);

    let a = s.set_pin(&pin("482913")).await.expect("set_pin");
    assert_eq!(a.status, pb::SetupAckStatus::Ok as i32);
    let a = s
        .start(
            setup_options(),
            &Password::new("correct horse").expect("password"),
        )
        .await
        .expect("start");
    assert_eq!((a.status, a.job_id), (pb::SetupAckStatus::Ok as i32, 1));

    // Pushes in order: serve's initial state, the pin_set state, running, two steps, result.
    let mut kinds = Vec::new();
    loop {
        let ev = within(s.next_event()).await.expect("event");
        kinds.push(match &ev {
            SetupEvent::State(_) => "state",
            SetupEvent::Progress(p) => {
                assert_eq!(p.job_id, 1);
                "progress"
            }
            SetupEvent::Result(r) => {
                assert!(!r.finished);
                "result"
            }
            SetupEvent::Closed(_) => panic!("closed too early"),
        });
        if kinds.last() == Some(&"result") {
            break;
        }
    }
    assert_eq!(
        kinds,
        ["state", "state", "state", "progress", "progress", "result"]
    );
    assert_eq!(s.state().job, pb::SetupJobState::Running as i32);
    assert!(s.state().pin_set);

    let a = s.finish().await.expect("finish");
    assert_eq!(a.status, pb::SetupAckStatus::Ok as i32);
    let SetupEvent::Result(r) = within(s.next_event()).await.expect("event") else {
        panic!("expected the final result");
    };
    assert!(r.finished);
    let SetupEvent::Closed(info) = within(s.next_event()).await.expect("event") else {
        panic!("expected a close");
    };
    assert_eq!(info.code, CloseCode::NoError);
    // And it stays closed.
    assert!(matches!(s.next_event().await, Ok(SetupEvent::Closed(_))));
    assert!(s.set_pin(&pin("482913")).await.is_err());
    server.abort();
}

// ------------------------------------------------------------------ NeedsPin

#[tokio::test]
async fn needs_pin_resumes_after_a_wrong_pin_and_a_backoff() {
    let mut e = Env::new(config()).await;
    e.auth.set_setup_gate(Gate::new(SetupAdmission::NeedsPin));
    let v = Verifier::new(&[PinVerdict::Wrong], PinVerdict::Right);
    e.auth.set_pin_verifier(v.clone());
    let (target, device, key, o) = (
        e.target(),
        e.device.clone(),
        e.server_key.public(),
        opts(&e),
    );
    let client = tokio::spawn(async move { connect_setup(&target, &device, key, &o).await });

    let SetupAuth::NeedsPin(mut awaiting) = within(client).await.expect("join").expect("auth")
    else {
        panic!("expected NeedsPin");
    };
    assert!(!awaiting.is_accepted(), "no session before the PIN");

    let wrong = awaiting.submit_pin(&pin("111111")).await.expect("reply");
    let PinReply::Wrong {
        attempts_left,
        retry_after,
    } = wrong
    else {
        panic!("expected Wrong, got {wrong:?}");
    };
    assert_eq!(attempts_left, MAX_PIN_FAILURES - 1);
    assert!(retry_after > Duration::ZERO);
    // Too soon: not evaluated, not counted.
    assert!(matches!(
        awaiting.submit_pin(&pin("482913")).await.expect("reply"),
        PinReply::Backoff { .. }
    ));
    e.clock.advance(Duration::from_secs(5));
    let accepted = tokio::spawn(async move {
        let r = awaiting.submit_pin(&pin("482913")).await;
        (awaiting, r)
    });
    let Outcome::Setup {
        connection,
        pin_verified,
        ..
    } = e.next().await.expect("outcome")
    else {
        panic!("expected Setup");
    };
    assert!(pin_verified);
    push(&connection, Sb::State(state(true, pb::SetupJobState::Idle))).await;
    let (awaiting, r) = within(accepted).await.expect("join");
    assert_eq!(r.expect("reply"), PinReply::Accepted);
    let mut s = awaiting.into_session().expect("session");
    assert!(s.state().pin_set);

    // The resumed session works: a running job's state and progress flow in.
    push(
        &connection,
        Sb::State(pb::SetupState {
            job: pb::SetupJobState::Running as i32,
            pin_set: true,
            last_progress: Some(progress(7, 1)),
            ..Default::default()
        }),
    )
    .await;
    let SetupEvent::State(st) = within(s.next_event()).await.expect("event") else {
        panic!("expected a state");
    };
    assert_eq!(st.last_progress.expect("progress").job_id, 7);
    // The PIN went through the verifier exactly as typed.
    assert_eq!(v.seen.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn the_fifth_wrong_pin_revokes_and_surfaces_as_revoked() {
    let e = Env::new(config()).await;
    e.auth.set_setup_gate(Gate::new(SetupAdmission::NeedsPin));
    e.auth
        .set_pin_verifier(Verifier::new(&[], PinVerdict::Wrong));
    let (target, device, key, o) = (
        e.target(),
        e.device.clone(),
        e.server_key.public(),
        opts(&e),
    );
    let SetupAuth::NeedsPin(mut a) = connect_setup(&target, &device, key, &o)
        .await
        .expect("auth")
    else {
        panic!("expected NeedsPin");
    };
    let mut last = None;
    for _ in 0..MAX_PIN_FAILURES {
        e.clock.advance(Duration::from_secs(60));
        last = Some(a.submit_pin(&pin("111111")).await);
    }
    assert!(matches!(last, Some(Err(Error::Revoked))), "{last:?}");
}

// ------------------------------------------------------------------ closing and refusing

#[tokio::test]
async fn setup_closed_refusal_maps_to_setup_closed() {
    let mut e = Env::new(config()).await;
    e.auth.set_setup_gate(Gate::new(SetupAdmission::Closed));
    let r = connect_setup(&e.target(), &e.device, e.server_key.public(), &opts(&e)).await;
    assert!(matches!(r, Err(Error::SetupClosed)), "{r:?}");
    assert!(matches!(e.next().await, Ok(Outcome::Refused(_))));
}

#[tokio::test]
async fn a_busy_gate_is_a_refusal_not_setup_closed() {
    let e = Env::new(config()).await;
    e.auth
        .set_setup_gate(Gate::new(SetupAdmission::Unavailable));
    let r = connect_setup(&e.target(), &e.device, e.server_key.public(), &opts(&e)).await;
    assert!(
        matches!(
            r,
            Err(Error::Refused {
                reason: pb::RefuseReason::Busy,
                ..
            })
        ),
        "{r:?}"
    );
}

#[tokio::test]
async fn a_setup_closed_close_mid_session_maps_to_setup_closed() {
    let mut e = Env::new(config()).await;
    e.auth.set_setup_gate(Gate::new(SetupAdmission::KeyOnly));
    let (auth, outcome) = connect(&mut e).await;
    let Outcome::Setup { connection, .. } = outcome else {
        panic!("expected Setup");
    };
    let mut s = ready(auth).await;
    let server = serve(connection, false, Mode::CloseOnRequest);
    // The request is answered by the close.
    let r = s.cancel().await;
    assert!(matches!(r, Err(Error::SetupClosed)), "{r:?}");
    // Events: whatever was pushed first, then the close with its code.
    let mut last = None;
    for _ in 0..4 {
        let ev = within(s.next_event()).await.expect("event");
        let closed = matches!(ev, SetupEvent::Closed(_));
        last = Some(ev);
        if closed {
            break;
        }
    }
    let Some(SetupEvent::Closed(info)) = last else {
        panic!("expected a close");
    };
    assert_eq!(info.code, CloseCode::SetupClosed);
    assert!(info.by_peer);
    let _ = server.await;
}

// ------------------------------------------------------------------ versioning

#[tokio::test]
async fn an_unconfirmed_or_old_server_means_update_required_and_nothing_is_sent() {
    let mut e = Env::new(config()).await;
    let gate = Gate::new(SetupAdmission::KeyOnly);
    e.auth.set_setup_gate(gate.clone());
    for v in [
        None,
        Some(ProtocolVersion { major: 1, minor: 2 }),
        Some(ProtocolVersion { major: 1, minor: 0 }),
        Some(ProtocolVersion { major: 2, minor: 9 }),
    ] {
        let mut o = opts(&e);
        o.confirmed_server_version = v;
        let r = connect_setup(&e.target(), &e.device, e.server_key.public(), &o).await;
        assert!(matches!(r, Err(Error::UpdateRequired)), "{v:?}: {r:?}");
    }
    assert!(e.no_outcome(), "no connection reached the server");
    assert_eq!(gate.calls(), 0);
    assert!(hx_crypto::setup::server_supports_setup(ProtocolVersion {
        major: 1,
        minor: 3
    }));
    assert!(hx_crypto::setup::server_supports_setup(&pb::Version {
        major: 1,
        minor: 4
    }));
    assert!(!hx_crypto::setup::server_supports_setup(&pb::Version {
        major: 1,
        minor: 2
    }));
    // The version a real confirmed pairing reports is what unlocks it.
    assert!(hx_crypto::setup::server_supports_setup(e.paired_version));
}

// ------------------------------------------------------------------ request/ack matching

#[tokio::test]
async fn pushes_between_a_request_and_its_ack_are_queued_in_order_and_the_ack_matches() {
    let mut e = Env::new(config()).await;
    e.auth.set_setup_gate(Gate::new(SetupAdmission::KeyOnly));
    let (auth, outcome) = connect(&mut e).await;
    let Outcome::Setup { connection, .. } = outcome else {
        panic!("expected Setup");
    };
    let mut s = ready(auth).await;
    let _server = serve(connection, false, Mode::PushesFirst);
    // serve's own initial state is the first queued push.
    let a = s
        .start(
            setup_options(),
            &Password::new("correct horse").expect("password"),
        )
        .await
        .expect("start");
    assert_eq!((a.status, a.job_id), (pb::SetupAckStatus::Ok as i32, 1));
    // Queued in arrival order: state (serve), progress 1, state (running), then, after the
    // ack, progress 2.
    let mut seen = Vec::new();
    for _ in 0..4 {
        match within(s.next_event()).await.expect("event") {
            SetupEvent::State(st) => seen.push(format!("state:{}", st.job)),
            SetupEvent::Progress(p) => seen.push(format!("progress:{}", p.index)),
            other => panic!("unexpected {other:?}"),
        }
    }
    let running = pb::SetupJobState::Running as i32;
    let idle = pb::SetupJobState::Idle as i32;
    assert_eq!(
        seen,
        [
            format!("state:{idle}"),
            "progress:1".to_string(),
            format!("state:{running}"),
            "progress:2".to_string()
        ]
    );
}

#[tokio::test]
async fn the_answer_of_an_abandoned_request_is_dropped_and_the_next_ack_still_matches() {
    let mut e = Env::new(config()).await;
    e.auth.set_setup_gate(Gate::new(SetupAdmission::KeyOnly));
    let (auth, outcome) = connect(&mut e).await;
    let Outcome::Setup { connection, .. } = outcome else {
        panic!("expected Setup");
    };
    let mut s = ready(auth).await;
    let _server = serve(connection, false, Mode::LateFirstAck);
    // The first request is dropped before its answer exists.
    let gave_up = tokio::time::timeout(Duration::from_millis(300), s.finish()).await;
    assert!(gave_up.is_err());
    // The second request: the server now answers both, the first (job 111) first.
    let a = s.cancel().await.expect("cancel");
    assert_eq!(a.job_id, 222, "matched by request id, not by arrival order");
}

#[tokio::test]
async fn an_unsolicited_ack_is_a_protocol_violation() {
    let mut e = Env::new(config()).await;
    e.auth.set_setup_gate(Gate::new(SetupAdmission::KeyOnly));
    let (auth, outcome) = connect(&mut e).await;
    let Outcome::Setup { connection, .. } = outcome else {
        panic!("expected Setup");
    };
    let mut s = ready(auth).await;
    let _server = serve(connection, false, Mode::Unsolicited);
    let r = s.cancel().await;
    assert!(matches!(r, Err(Error::Protocol(_))), "{r:?}");
}

// ------------------------------------------------------------------ the password

#[test]
fn a_password_is_validated_like_the_gateway_does_and_never_printed() {
    assert!(Password::new("correct horse").is_ok());
    assert!(Password::new("pässwörd 🔑").is_ok());
    assert!(Password::new(&"x".repeat(511)).is_ok());
    for bad in [
        "".to_string(),
        "x".repeat(512),
        "hunter2\nx".to_string(),
        "hunter2\rx".to_string(),
        "hunter2\0x".to_string(),
    ] {
        let err = Password::new(&bad).expect_err("rejected");
        assert!(matches!(err, Error::InvalidSecret(_)));
        let text = format!("{err} {err:?}");
        assert!(!text.contains("hunter2"), "{text}");
    }
    assert!(Password::from_bytes(&[0xff, 0xfe]).is_err(), "not UTF-8");

    let p = Password::new("hunter2-secret").expect("password");
    assert_eq!(format!("{p:?}"), "Password([redacted])");
    assert!(!format!("{p:#?}").contains("hunter2"));
    assert_eq!(p.as_bytes(), b"hunter2-secret");
}

#[tokio::test]
async fn a_request_without_an_answer_times_out_instead_of_hanging() {
    let mut e = Env::new(config()).await;
    e.auth.set_setup_gate(Gate::new(SetupAdmission::KeyOnly));
    let mut o = opts(&e);
    o.request_timeout = Duration::from_millis(300);
    let (auth, outcome) = connect_with(&mut e, o).await;
    let Outcome::Setup { connection, .. } = outcome else {
        panic!("expected Setup");
    };
    let mut s = ready(auth).await;
    let server = tokio::spawn(async move {
        let _ = recv_request(&connection).await;
        tokio::time::sleep(Duration::from_secs(5)).await;
    });
    let r = s.cancel().await;
    assert!(matches!(r, Err(Error::Timeout(_))), "{r:?}");
    server.abort();
}
