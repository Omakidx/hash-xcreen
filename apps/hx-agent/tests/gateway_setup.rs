//! The gateway's post-pairing setup (protocol 1.3, `docs/ipc.md` 5.5): a real `Gateway` in
//! front of a real privd daemon on `FakeIncus`, the admin socket for the window and the token,
//! and the real client library. Each test is one scenario of the design's testability list.

mod gateway_common;

use std::time::Duration;

use gateway_common::setup::*;
use gateway_common::{PIN, new_key, within};
use hx_crypto::setup::SetupAuth;
use hx_crypto::{Error, PairingCredential, Pin};
use hx_ipc::admin::pb as apb;
use hx_proto::channel::CloseCode;
use hx_proto::pb as wire;
use hx_proto::pb::control_message::Message as Ctl;
use wire::{SetupAckStatus as A, SetupErrorCode as E, SetupJobState as J};

fn refused_options() -> wire::SetupOptions {
    wire::SetupOptions {
        limits: Some(wire::SetupLimits {
            disk_gib: 60_000,
            ..Default::default()
        }),
        ..options()
    }
}

fn status_of(a: &wire::SetupAck) -> A {
    A::try_from(a.status).unwrap()
}

async fn job_state(e: &SetupEnv) -> apb::SetupJobState {
    apb::SetupJobState::try_from(e.status().await.setup_job).unwrap()
}

async fn wait_job(e: &SetupEnv, want: apb::SetupJobState) {
    for _ in 0..800 {
        if job_state(e).await == want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("the job never reached {want:?}");
}

fn no_secrets_in_logs() {
    let logs = captured_logs();
    for secret in [PIN, PASSWORD] {
        assert!(!logs.contains(secret), "a secret reached a log line");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_happy_path_sets_the_pin_builds_the_desktop_and_finishes() {
    capture_logs();
    let e = SetupEnv::start().await;
    e.open_window(7200).await;
    let version = e.pair_app().await;

    // The installer's token bound the app as the setup device.
    let st = e.status().await;
    assert!(st.setup_device_bound);
    assert_eq!(
        st.setup_device_id.as_ref(),
        e.app.public().device_id().as_bytes()
    );
    assert!(!st.setup_token_pending);

    let mut s = e.key_only(version).await;
    assert_eq!(s.state().job, J::Idle as i32);
    assert!(!s.state().pin_set);
    assert!(s.state().window_expires_unix > 0);
    assert_eq!(
        s.state().desktop,
        wire::SetupDesktopState::None as i32,
        "no desktop yet"
    );
    assert!(s.state().host.is_some());

    assert_eq!(status_of(&within(s.set_pin(&pin())).await.unwrap()), A::Ok);
    let ack = within(s.start(options(), &password())).await.unwrap();
    assert_eq!(status_of(&ack), A::Ok);
    assert_eq!(ack.job_id, 1);

    let (result, stages, close) = until_result(&mut s).await;
    assert_eq!(result.status, J::Succeeded as i32, "{result:?}");
    assert!(result.finished);
    assert_eq!(result.path_taken, wire::SetupPathTaken::Build as i32);
    assert_eq!(result.job_id, 1);
    assert!(!stages.is_empty(), "privd's progress was forwarded");
    let close = close.expect("the server closes after a finished setup");
    assert_eq!(close.code, CloseCode::NoError);
    assert_eq!(close.reason, "setup finished");

    // Both verifiers are stored, the desktop exists and privd is READY.
    assert!(e.gw().verifiers().has_pin());
    assert!(e.gw().verifiers().password().is_some());
    assert!(e.h.daemon.read_state(|s| s.desktops.contains_key("main")));
    assert_eq!(e.phase().await, hx_ipc::privd::pb::Phase::Ready);
    let audit = e.h.audit.lines().join("\n");
    assert!(audit.contains("PIN_CHANGED"), "{audit}");
    assert!(audit.contains("PASSWORD_VERIFIER_CHANGED"), "{audit}");
    // The window and the binding ended with the setup.
    let st = e.status().await;
    assert!(!st.setup_window.unwrap().open);
    assert!(!st.setup_device_bound);
    assert_eq!(
        apb::SetupJobState::try_from(st.setup_job).unwrap(),
        apb::SetupJobState::Succeeded
    );

    // A normal PIN login works, and setup is closed now.
    let conn = e.login(&e.app, PIN).await.expect("PIN login");
    assert!(conn.is_authorized());
    match e.connect_setup_as(&e.app, version).await {
        Err(Error::SetupClosed) => {}
        other => panic!("expected SETUP_CLOSED, got {other:?}"),
    }
    // Neither the password nor the PIN reached the desktop's command lines or the audit log.
    assert!(e.h.incus.with(|s| {
        s.execs
            .iter()
            .all(|x| !x.contains(PASSWORD) && !x.contains(PIN))
    }));
    assert!(
        e.h.audit
            .lines()
            .iter()
            .all(|l| !l.contains(PASSWORD) && !l.contains(PIN))
    );
    no_secrets_in_logs();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_only_connection_may_only_set_the_pin() {
    let e = SetupEnv::start().await;
    e.open_window(7200).await;
    let version = e.pair_app().await;
    let mut s = e.key_only(version).await;
    for (name, ack) in [
        ("start", s.start(options(), &password()).await),
        ("cancel", s.cancel().await),
        ("finish", s.finish().await),
    ] {
        assert_eq!(status_of(&ack.unwrap()), A::PinRequired, "{name}");
    }
    let short = Pin::new("123456").unwrap();
    assert_eq!(status_of(&s.set_pin(&short).await.unwrap()), A::Ok);
    // Once set, it cannot be set again, by anyone.
    assert_eq!(
        status_of(&s.set_pin(&Pin::new("654321").unwrap()).await.unwrap()),
        A::PinAlreadySet
    );
    // The connection is SetupAuthorized now: start passes the PIN gate and meets its own checks.
    let mut bad = options();
    bad.username = "root".into();
    let ack = s.start(bad, &password()).await.unwrap();
    assert_eq!(status_of(&ack), A::InvalidArgument);
    assert_eq!(ack.field, "options.username");
    let mut docker = options();
    docker.docker = true;
    let ack = s.start(docker, &password()).await.unwrap();
    assert_eq!(status_of(&ack), A::InvalidArgument);
    assert_eq!(ack.field, "options.docker_isolation_acknowledged");
    let mut distro = options();
    distro.distro = 0;
    assert_eq!(
        s.start(distro, &password()).await.unwrap().field,
        "options.distro"
    );
    // A second device that connects for setup now has to prove the PIN.
    let next = e.connect_setup_as(&e.app, version).await.unwrap();
    assert!(matches!(next, SetupAuth::NeedsPin(_)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dropped_connection_resumes_a_running_job_without_the_password() {
    capture_logs();
    let e = SetupEnv::start().await;
    e.open_window(7200).await;
    let version = e.pair_app().await;
    e.slow_build(120);
    {
        let mut s = e.key_only(version).await;
        s.set_pin(&pin()).await.unwrap();
        assert_eq!(
            status_of(&s.start(options(), &password()).await.unwrap()),
            A::Ok
        );
        e.wait_building().await;
    } // dropped mid-build: the job does not care
    assert_eq!(job_state(&e).await, apb::SetupJobState::Running);

    // Reconnecting needs the PIN; the state says RUNNING with the job's id and progress.
    let mut s = e.with_pin(version).await;
    assert_eq!(s.state().job, J::Running as i32);
    assert_eq!(s.state().job_id, 1);
    assert!(s.state().pin_set);
    // A second start is BUSY; nothing is re-sent to watch.
    assert_eq!(
        status_of(&s.start(options(), &password()).await.unwrap()),
        A::Busy
    );
    let (result, _, close) = until_result(&mut s).await;
    assert_eq!(result.status, J::Succeeded as i32, "{result:?}");
    assert!(result.finished);
    assert!(close.is_some());
    assert!(e.gw().verifiers().password().is_some());
    no_secrets_in_logs();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_job_completes_even_if_nobody_is_connected_at_the_end() {
    let e = SetupEnv::start().await;
    e.open_window(7200).await;
    let version = e.pair_app().await;
    e.slow_build(60);
    {
        let mut s = e.key_only(version).await;
        s.set_pin(&pin()).await.unwrap();
        s.start(options(), &password()).await.unwrap();
    }
    wait_job(&e, apb::SetupJobState::Succeeded).await;
    assert_eq!(
        e.phase().await,
        hx_ipc::privd::pb::Phase::Ready,
        "the job finished setup itself"
    );
    assert!(e.gw().verifiers().password().is_some());
    assert!(e.h.daemon.read_state(|s| s.desktops.contains_key("main")));
    match e.connect_setup_as(&e.app, version).await {
        Err(Error::SetupClosed) => {}
        other => panic!("{other:?}"),
    }
    assert!(e.login(&e.app, PIN).await.unwrap().is_authorized());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_destroys_the_unfinished_desktop_and_setup_can_start_again() {
    let e = SetupEnv::start().await;
    e.open_window(7200).await;
    let version = e.pair_app().await;
    let mut s = e.key_only(version).await;
    // Nothing runs yet.
    s.set_pin(&pin()).await.unwrap();
    assert_eq!(status_of(&s.cancel().await.unwrap()), A::NotRunning);

    e.hang_build();
    assert_eq!(
        status_of(&s.start(options(), &password()).await.unwrap()),
        A::Ok
    );
    e.wait_building().await;
    assert_eq!(status_of(&s.cancel().await.unwrap()), A::Ok);
    let (result, _, close) = until_result(&mut s).await;
    assert_eq!(result.status, J::Cancelled as i32, "{result:?}");
    assert!(!result.finished);
    assert!(close.is_none(), "the connection stays open after a cancel");
    // privd destroyed the instance and forgot it; the window is still open.
    assert!(e.h.incus.instance_names().is_empty());
    assert!(e.h.daemon.read_state(|s| s.desktops.is_empty()));
    assert_eq!(e.phase().await, hx_ipc::privd::pb::Phase::SetupOpen);
    assert!(
        e.gw().verifiers().password().is_none(),
        "no verifier without a desktop"
    );

    // Start again and finish.
    e.clear_build_rules();
    assert_eq!(
        status_of(&s.start(options(), &password()).await.unwrap()),
        A::Ok
    );
    let (result, _, _) = until_result(&mut s).await;
    assert_eq!(result.status, J::Succeeded as i32, "{result:?}");
    assert!(result.finished);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_build_reports_the_error_and_a_retry_succeeds() {
    let e = SetupEnv::start().await;
    e.open_window(7200).await;
    let version = e.pair_app().await;
    let mut s = e.key_only(version).await;
    s.set_pin(&pin()).await.unwrap();
    // privd refuses desktop settings it has no recipe variables for: a failure at once.
    assert_eq!(
        status_of(&s.start(refused_options(), &password()).await.unwrap()),
        A::Ok
    );
    let (result, _, close) = until_result(&mut s).await;
    assert_eq!(result.status, J::Failed as i32, "{result:?}");
    assert!(close.is_none());
    let err = result.error.expect("an error");
    assert_ne!(err.code, E::Unspecified as i32);
    assert!(err.message.len() <= 256);
    assert!(!err.message.contains(PASSWORD));
    assert!(
        e.gw().verifiers().password().is_none(),
        "a failed job leaves no verifier"
    );
    assert_eq!(e.phase().await, hx_ipc::privd::pb::Phase::SetupOpen);

    // The password and the record were dropped: a retry carries the password again.
    let ack = s.start(options(), &password()).await.unwrap();
    assert_eq!(status_of(&ack), A::Ok);
    assert_eq!(ack.job_id, 2);
    let (result, _, _) = until_result(&mut s).await;
    assert_eq!(result.status, J::Succeeded as i32, "{result:?}");
}

fn add_existing(e: &SetupEnv, running: bool) {
    e.h.incus
        .add_desktop("hx-main", "ubuntu-24.04-xfce-basic", "alice", running);
    e.h.daemon.register_desktop("main").unwrap();
}

fn chpasswd_count(e: &SetupEnv) -> usize {
    e.h.incus
        .with(|s| s.execs.iter().filter(|x| x.contains("chpasswd")).count())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_existing_desktop_gets_the_password_and_matching_options_are_accepted() {
    let e = SetupEnv::start().await;
    add_existing(&e, false); // stopped: the job starts it
    e.open_window(7200).await;
    let version = e.pair_app().await;
    let mut s = e.key_only(version).await;
    assert_eq!(s.state().desktop, wire::SetupDesktopState::Ready as i32);
    s.set_pin(&pin()).await.unwrap();
    let before = chpasswd_count(&e);
    assert_eq!(
        status_of(&s.start(options(), &password()).await.unwrap()),
        A::Ok
    );
    let (result, _, close) = until_result(&mut s).await;
    assert_eq!(result.status, J::Succeeded as i32, "{result:?}");
    assert_eq!(result.path_taken, wire::SetupPathTaken::Existing as i32);
    assert!(result.finished && close.is_some());
    assert_eq!(chpasswd_count(&e), before + 1, "SetUserPassword ran once");
    assert_eq!(
        e.h.incus.with(|s| s.instances["hx-main"].status.clone()),
        "Running"
    );
    assert!(e.gw().verifiers().password().is_some());
    assert_eq!(e.phase().await, hx_ipc::privd::pb::Phase::Ready);
    assert!(
        e.h.incus
            .with(|s| s.execs.iter().all(|x| !x.contains(PASSWORD)))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_existing_desktop_with_other_options_is_refused_and_left_alone() {
    let e = SetupEnv::start().await;
    add_existing(&e, true);
    e.open_window(7200).await;
    let version = e.pair_app().await;
    let mut s = e.key_only(version).await;
    s.set_pin(&pin()).await.unwrap();
    let before = chpasswd_count(&e);
    for tweak in [
        (|o: &mut wire::SetupOptions| o.username = "bob".into()) as fn(&mut wire::SetupOptions),
        |o| o.distro = wire::SetupDistro::Debian13 as i32,
        |o| o.preset = wire::SetupPreset::Developer as i32,
    ] {
        let mut o = options();
        tweak(&mut o);
        assert_eq!(status_of(&s.start(o, &password()).await.unwrap()), A::Ok);
        let (result, _, close) = until_result(&mut s).await;
        assert_eq!(result.status, J::Failed as i32, "{result:?}");
        assert_eq!(result.error.unwrap().code, E::DesktopExists as i32);
        assert!(close.is_none());
    }
    assert_eq!(chpasswd_count(&e), before, "no password was set");
    assert!(e.gw().verifiers().password().is_none());
    assert_eq!(
        e.phase().await,
        hx_ipc::privd::pb::Phase::SetupOpen,
        "setup is not finished"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_is_refused_when_less_than_fifty_minutes_of_the_window_remain() {
    let e = SetupEnv::start().await;
    e.open_window(2400).await;
    let version = e.pair_app().await;
    let mut s = e.key_only(version).await;
    s.set_pin(&pin()).await.unwrap();
    let ack = s.start(options(), &password()).await.unwrap();
    assert_eq!(status_of(&ack), A::WindowTooShort);
    assert!(
        ack.message.contains("sudo hx-agent setup extend"),
        "{}",
        ack.message
    );
    assert_eq!(job_state(&e).await, apb::SetupJobState::Idle);
    // The operator extends the window (privd and the mirror) and start passes.
    let r = e
        .privd_admin(hx_ipc::privd::pb::request::Command::ExtendSetup(
            hx_ipc::privd::pb::ExtendSetupRequest { extend_by_s: 3000 },
        ))
        .await;
    assert!(r.result.is_some());
    let mut a = e.admin().await;
    a.call(
        apb::request::Command::SetupWindow(apb::SetupWindowRequest {
            action: apb::SetupWindowAction::Extend as i32,
            expires_in_s: 3000,
        }),
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        status_of(&s.start(options(), &password()).await.unwrap()),
        A::Ok
    );
    let (result, _, _) = until_result(&mut s).await;
    assert_eq!(result.status, J::Succeeded as i32, "{result:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_window_rule_follows_the_gateways_clock() {
    let e = SetupEnv::start().await;
    e.open_window(4000).await;
    let version = e.pair_app().await;
    let mut s = e.key_only(version).await;
    s.set_pin(&pin()).await.unwrap();
    e.clock.advance(Duration::from_secs(1100)); // 2900 s left: under 50 minutes
    assert_eq!(
        status_of(&s.start(options(), &password()).await.unwrap()),
        A::WindowTooShort
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_gatewayd_restart_mid_build_destroys_the_instance_and_the_next_job_converges() {
    let mut e = SetupEnv::start().await;
    e.open_window(7200).await;
    let version = e.pair_app().await;
    {
        let mut s = e.key_only(version).await;
        s.set_pin(&pin()).await.unwrap();
        e.hang_build();
        assert_eq!(
            status_of(&s.start(options(), &password()).await.unwrap()),
            A::Ok
        );
        e.wait_building().await;
    }
    e.stop_gateway().await;
    // The dedicated connection closed: privd cancels at a safe point, destroys and forgets.
    let mut gone = false;
    for _ in 0..800 {
        if e.h.incus.instance_names().is_empty() && e.h.daemon.read_state(|s| s.desktops.is_empty())
        {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(gone, "privd destroyed the unfinished instance");
    e.clear_build_rules();

    e.start_gateway().await;
    // The window and the binding came back from the store; the job did not.
    let st = e.status().await;
    assert!(st.setup_window.unwrap().open);
    assert!(st.setup_device_bound);
    assert_eq!(
        apb::SetupJobState::try_from(st.setup_job).unwrap(),
        apb::SetupJobState::Idle
    );
    let mut s = e.with_pin(version).await;
    assert_eq!(s.state().job, J::Idle as i32);
    assert_eq!(s.state().desktop, wire::SetupDesktopState::None as i32);
    assert_eq!(
        status_of(&s.start(options(), &password()).await.unwrap()),
        A::Ok
    );
    let (result, _, _) = until_result(&mut s).await;
    assert_eq!(result.status, J::Succeeded as i32, "{result:?}");
    assert!(result.finished);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_token_moves_the_binding_and_a_code_paired_device_is_refused() {
    let e = SetupEnv::start().await;
    e.open_window(7200).await;
    let version = e.pair_app().await;
    let mut a = e.key_only(version).await;

    // Admin installs another token while the window is open; the device that pairs with it is
    // bound instead, and the first one's live setup connection is closed SETUP_CLOSED.
    let second = new_key();
    let cred = e.install_token().await;
    assert!(e.status().await.setup_token_pending);
    e.pair_with(&second, "second", &cred).await;
    let st = e.status().await;
    assert!(!st.setup_token_pending);
    assert_eq!(
        st.setup_device_id.as_ref(),
        second.public().device_id().as_bytes()
    );
    match within(a.next_event()).await {
        Ok(hx_crypto::setup::SetupEvent::State(_))
        | Ok(hx_crypto::setup::SetupEvent::Progress(_)) => {
            // Pushes may arrive first; the close follows.
            match within(a.next_event()).await {
                Ok(hx_crypto::setup::SetupEvent::Closed(c)) => {
                    assert_eq!(c.code, CloseCode::SetupClosed)
                }
                other => panic!("{other:?}"),
            }
        }
        Ok(hx_crypto::setup::SetupEvent::Closed(c)) => assert_eq!(c.code, CloseCode::SetupClosed),
        other => panic!("{other:?}"),
    }
    match e.connect_setup_as(&e.app, version).await {
        Err(Error::SetupClosed) => {}
        other => panic!("the old setup device is refused SETUP_CLOSED, got {other:?}"),
    }
    assert!(matches!(
        e.connect_setup_as(&second, version).await.unwrap(),
        SetupAuth::Ready(_)
    ));

    // A device paired with a short code never binds and can never open setup.
    let mut admin = e.admin().await;
    let code = match admin
        .call(
            apb::request::Command::CreatePairingCode(apb::CreatePairingCodeRequest {
                expires_in_s: 300,
            }),
            None,
        )
        .await
        .unwrap()
    {
        apb::response::Result::CreatePairingCode(c) => c.code,
        other => panic!("{other:?}"),
    };
    let third = new_key();
    e.pair_with(&third, "third", &PairingCredential::parse(&code).unwrap())
        .await;
    match e.connect_setup_as(&third, version).await {
        Err(Error::SetupClosed) => {}
        other => panic!("{other:?}"),
    }
    // A token that the installer did not record (not created through the admin socket while
    // the window was open) does not bind either.
    let stray = e.gw().authenticator().pairing().issue_token().unwrap();
    let fourth = new_key();
    e.pair_with(
        &fourth,
        "fourth",
        &PairingCredential::parse(&stray.to_text()).unwrap(),
    )
    .await;
    assert!(matches!(
        e.connect_setup_as(&fourth, version).await,
        Err(Error::SetupClosed)
    ));
    // The second device is still the setup device.
    assert_eq!(
        e.status().await.setup_device_id.as_ref(),
        second.public().device_id().as_bytes()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_setup_device_cancels_the_job_and_loses_the_binding() {
    let e = SetupEnv::start().await;
    e.open_window(7200).await;
    let version = e.pair_app().await;
    let mut s = e.key_only(version).await;
    s.set_pin(&pin()).await.unwrap();
    e.hang_build();
    assert_eq!(
        status_of(&s.start(options(), &password()).await.unwrap()),
        A::Ok
    );
    e.wait_building().await;
    let mut a = e.admin().await;
    a.call(
        apb::request::Command::RevokeDevice(apb::RevokeDeviceRequest {
            device_id: e.app.public().device_id().as_bytes().to_vec().into(),
        }),
        None,
    )
    .await
    .unwrap();
    wait_job(&e, apb::SetupJobState::Cancelled).await;
    assert!(!e.status().await.setup_device_bound);
    assert!(e.h.incus.instance_names().is_empty());
    assert!(matches!(
        e.connect_setup_as(&e.app, version).await,
        Err(Error::Refused { .. })
            | Err(Error::Revoked)
            | Err(Error::Transport(_))
            | Err(Error::UnknownDevice)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_setup_message_on_a_normal_session_is_a_protocol_error() {
    use hx_proto::version::{Features, PROTOCOL_MINOR, capabilities};
    let e = SetupEnv::start().await;
    e.open_window(7200).await;
    let version = e.pair_app().await;
    let mut s = e.key_only(version).await;
    s.set_pin(&pin()).await.unwrap();
    drop(s);
    // The real client library refuses to send the variant on a session; a raw client sends it.
    let mut raw =
        gateway_common::RawClient::connect(e.gw().quic_addr().unwrap(), &e.app, e.server_public())
            .await;
    let hello = hx_proto::pb::ControlMessage::new(Ctl::Hello(hx_proto::pb::Hello {
        version: Some(hx_proto::pb::Version {
            major: 1,
            minor: PROTOCOL_MINOR,
        }),
        capabilities: Some(capabilities(
            &[hx_proto::VideoCodec::H264],
            Features::defined_up_to(PROTOCOL_MINOR),
        )),
        intent: hx_proto::pb::Intent::Session as i32,
        software: "raw".into(),
        device_name: "raw".into(),
    }));
    raw.send_ctl(&hello).await;
    let ack = match raw.recv_ctl().await.and_then(|m| m.message) {
        Some(Ctl::HelloAck(a)) => a,
        other => panic!("{other:?}"),
    };
    // SETUP is not offered to a session (protocol 4.7).
    assert_eq!(
        ack.capabilities
            .map(|c| c.features & Features::SETUP.0)
            .unwrap_or(0),
        0
    );
    assert_eq!(raw.submit_pin(PIN).await, hx_crypto::wire::AuthStatus::Ok);
    raw.send_ctl(&hx_proto::pb::ControlMessage::new(Ctl::Setup(
        wire::SetupMessage {
            request_id: 1,
            body: Some(wire::setup_message::Body::Cancel(wire::SetupCancel {})),
        },
    )))
    .await;
    // No answer: the connection is closed with PROTOCOL_ERROR.
    let reason = within(raw.conn.closed()).await;
    match reason {
        quinn::ConnectionError::ApplicationClosed(c) => {
            assert_eq!(
                u64::from(c.error_code),
                u64::from(CloseCode::ProtocolError.code())
            );
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_and_request_rates_are_limited() {
    let e = SetupEnv::start().await;
    e.open_window(7200).await;
    let version = e.pair_app().await;
    let mut s = e.key_only(version).await;
    s.set_pin(&pin()).await.unwrap();
    // Builds that fail at once: 6 starts are accepted (privd's own cap of 3 CreateDesktop per
    // hour answers the later ones), the 7th is refused by the gateway.
    for n in 1..=6 {
        let ack = s.start(refused_options(), &password()).await.unwrap();
        assert_eq!(status_of(&ack), A::Ok, "start {n}");
        // Pace the requests under the per-connection limit.
        let (result, _, _) = until_result(&mut s).await;
        assert_eq!(result.status, J::Failed as i32, "{result:?}");
        tokio::time::sleep(Duration::from_millis(600)).await;
        // privd's per-second read limit runs on its own (manual) clock in this harness.
        e.h.clock.advance_secs(2);
    }
    let ack = s.start(refused_options(), &password()).await.unwrap();
    assert_eq!(status_of(&ack), A::RateLimited);
    assert!(ack.retry_after_ms > 0 && ack.retry_after_ms <= 3_600_000);
    // An hour later the gateway accepts again.
    e.clock.advance(Duration::from_secs(3601));
    assert_eq!(
        status_of(&s.start(options(), &password()).await.unwrap()),
        A::Ok
    );
    let _ = until_result(&mut s).await;

    // More than 2 requests a second (burst 8) on one connection closes it BUSY.
    e.h.clock.advance_secs(2);
    let mut s2 = e.with_pin(version).await;
    let mut closed = false;
    for _ in 0..40 {
        if s2.cancel().await.is_err() {
            closed = true;
            break;
        }
    }
    assert!(closed, "the flood was not cut off");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn setup_is_closed_when_the_window_is_not_open_or_privd_says_so() {
    let e = SetupEnv::start().await;
    // No window at all: the key is unknown to setup (not bound).
    let cred = e.install_token().await;
    let v = e.pair_with(&e.app, "app", &cred).await;
    assert!(matches!(
        e.connect_setup_as(&e.app, v).await,
        Err(Error::SetupClosed)
    ));
    // A window opened in the mirror only (privd stayed UNINITIALIZED): privd is the authority.
    let mut a = e.admin().await;
    a.call(
        apb::request::Command::SetupWindow(apb::SetupWindowRequest {
            action: apb::SetupWindowAction::Open as i32,
            expires_in_s: 7200,
        }),
        None,
    )
    .await
    .unwrap();
    let cred = e.install_token().await;
    let other = new_key();
    e.pair_with(&other, "other", &cred).await;
    assert!(matches!(
        e.connect_setup_as(&other, v).await,
        Err(Error::SetupClosed)
    ));
    // An old server is never sent the intent.
    let r = hx_crypto::setup::connect_setup(
        &e.target(hx_transport::TransportPreference::Quic),
        &other,
        e.server_public(),
        &hx_crypto::setup::SetupConnectOptions {
            confirmed_server_version: Some(hx_proto::version::ProtocolVersion {
                major: 1,
                minor: 2,
            }),
            ..Default::default()
        },
    )
    .await;
    assert!(matches!(r, Err(Error::UpdateRequired)));
    // An expired window closes setup and ends the binding.
    a.call(
        apb::request::Command::SetupWindow(apb::SetupWindowRequest {
            action: apb::SetupWindowAction::Close as i32,
            expires_in_s: 0,
        }),
        None,
    )
    .await
    .unwrap();
    let st = e.status().await;
    assert!(!st.setup_window.unwrap().open);
    assert!(!st.setup_device_bound);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_window_is_capped_at_24_hours_and_expiry_ends_the_binding() {
    let e = SetupEnv::start().await;
    let mut a = e.admin().await;
    let open = |secs| {
        apb::request::Command::SetupWindow(apb::SetupWindowRequest {
            action: apb::SetupWindowAction::Open as i32,
            expires_in_s: secs,
        })
    };
    let r = a.call(open(86_400), None).await.unwrap();
    let apb::response::Result::SetupWindow(w) = r else {
        panic!()
    };
    let first = w.state.unwrap().expires_at_unix_s;
    // Reopening an open window cannot stretch it past 24 hours since it first opened.
    e.clock.advance(Duration::from_secs(20 * 3600));
    let r = a.call(open(86_400), None).await.unwrap();
    let apb::response::Result::SetupWindow(w) = r else {
        panic!()
    };
    assert!(w.state.unwrap().expires_at_unix_s <= first + 1);
    // Expiry closes it.
    e.clock.advance(Duration::from_secs(5 * 3600));
    assert!(!e.status().await.setup_window.unwrap().open);
    // Extending needs an open window.
    let r = a
        .call(
            apb::request::Command::SetupWindow(apb::SetupWindowRequest {
                action: apb::SetupWindowAction::Extend as i32,
                expires_in_s: 60,
            }),
            None,
        )
        .await
        .unwrap();
    assert!(matches!(r, apb::response::Result::Error(_)));
}

/// The final ack, the `SetupResult` and the close must reach the client in that order on both
/// transports (a QUIC close discards unread data; the server flushes with a ping and gives the
/// client a moment to close first).
async fn final_messages_arrive_before_the_close(pref: hx_transport::TransportPreference) {
    let mut e = SetupEnv::start().await;
    e.pref = pref;
    e.open_window(7200).await;
    let version = e.pair_app().await;
    for round in 0..3 {
        if round > 0 {
            // Fresh environment per round: the window closes with each finished setup.
            e = SetupEnv::start().await;
            e.pref = pref;
            e.open_window(7200).await;
        }
        let version = if round == 0 {
            version
        } else {
            e.pair_app().await
        };
        let mut s = e.key_only(version).await;
        s.set_pin(&pin()).await.unwrap();
        assert_eq!(
            status_of(&s.start(options(), &password()).await.unwrap()),
            A::Ok
        );
        let (result, _, close) = until_result(&mut s).await;
        assert_eq!(result.status, J::Succeeded as i32, "{result:?}");
        assert!(result.finished);
        let close = close.expect("the close follows the result");
        assert_eq!(close.code, CloseCode::NoError);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_result_arrives_before_the_close_over_quic() {
    final_messages_arrive_before_the_close(hx_transport::TransportPreference::Quic).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_result_arrives_before_the_close_over_websocket() {
    final_messages_arrive_before_the_close(hx_transport::TransportPreference::WebSocket).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn finish_needs_a_usable_desktop_and_then_ends_the_setup() {
    let e = SetupEnv::start().await;
    e.open_window(7200).await;
    let version = e.pair_app().await;
    let mut s = e.key_only(version).await;
    s.set_pin(&pin()).await.unwrap();
    // No desktop yet.
    assert_eq!(status_of(&s.finish().await.unwrap()), A::DesktopNotReady);
    // A desktop exists but the job never ran (say it finished everything but `FinishSetup`).
    add_existing(&e, true);
    assert_eq!(status_of(&s.finish().await.unwrap()), A::Ok);
    assert_eq!(e.phase().await, hx_ipc::privd::pb::Phase::Ready);
    let c = within(async {
        loop {
            match s.next_event().await {
                Ok(hx_crypto::setup::SetupEvent::Closed(c)) => return c,
                Ok(_) => {}
                Err(e) => panic!("{e:?}"),
            }
        }
    })
    .await;
    assert_eq!(
        (c.code, c.reason.as_str()),
        (CloseCode::NoError, "setup finished")
    );
    // Idempotent in effect: setup is closed now.
    assert!(matches!(
        e.connect_setup_as(&e.app, version).await,
        Err(Error::SetupClosed)
    ));
}
