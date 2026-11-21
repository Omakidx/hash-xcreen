//! End to end, in process: real clients (hx-crypto and hx-transport) against the gateway,
//! against a fake privd. Pairing, login, the pepper split, revocation, takeover, device
//! management, the desktop seam.

mod gateway_common;

use std::time::Duration;

use bytes::Bytes;
use gateway_common::*;
use hx_agent::gateway::desktop::DetachReason;
use hx_agent::gateway::desktop::recording::Event;
use hx_crypto::{Error as CryptoError, PinReply};
use hx_ipc::privd::pb::AuditEvent;
use hx_proto::channel::CloseCode;
use hx_proto::pb::{self, control_message::Message as Ctl, device_mgmt::Body as Mgmt};
use hx_proto::version::{Features, PROTOCOL_MINOR};
use hx_transport::TransportPreference::{Quic, WebSocket};

async fn closed_with(conn: &hx_transport::Connection) -> hx_transport::CloseInfo {
    within(conn.closed()).await
}

fn mgmt(request_id: u32, body: Mgmt) -> pb::ControlMessage {
    ctl(Ctl::DeviceMgmt(pb::DeviceMgmt {
        request_id,
        body: Some(body),
    }))
}

async fn list(conn: &hx_transport::Connection, id: u32) -> pb::DeviceList {
    conn.send_control(&mgmt(id, Mgmt::List(pb::ListDevices {})))
        .await
        .unwrap();
    recv_until(conn, |m| match m {
        Ctl::DeviceMgmt(pb::DeviceMgmt {
            request_id,
            body: Some(Mgmt::DeviceList(l)),
        }) if *request_id == id => Some(l.clone()),
        _ => None,
    })
    .await
}

async fn revoke(conn: &hx_transport::Connection, id: u32, target: &[u8]) -> pb::RevokeStatus {
    conn.send_control(&mgmt(
        id,
        Mgmt::Revoke(pb::RevokeDevice {
            device_id: Bytes::copy_from_slice(target),
        }),
    ))
    .await
    .unwrap();
    recv_until(conn, |m| match m {
        Ctl::DeviceMgmt(pb::DeviceMgmt {
            request_id,
            body: Some(Mgmt::RevokeResult(r)),
        }) if *request_id == id => pb::RevokeStatus::try_from(r.status).ok(),
        _ => None,
    })
    .await
}

/// Waits for the next pushed `DeviceEvent`.
async fn next_event(conn: &hx_transport::Connection) -> pb::DeviceEvent {
    recv_until(conn, |m| match m {
        Ctl::DeviceMgmt(pb::DeviceMgmt {
            request_id: 0,
            body: Some(Mgmt::Event(e)),
        }) => Some(e.clone()),
        _ => None,
    })
    .await
}

async fn goodbye(conn: &hx_transport::Connection) -> pb::Goodbye {
    recv_until(conn, |m| match m {
        Ctl::Goodbye(g) => Some(g.clone()),
        _ => None,
    })
    .await
}

// ------------------------------------------------------------------ pairing and login

macro_rules! on_both_transports {
    ($($name:ident),* $(,)?) => {
        mod transports {
            use super::*;
            $(
                mod $name {
                    use super::*;
                    #[tokio::test]
                    async fn quic() { crate::$name(Quic).await }
                    #[tokio::test]
                    async fn websocket() { crate::$name(WebSocket).await }
                }
            )*
        }
    };
}

async fn pair_then_pin_login(pref: hx_transport::TransportPreference) {
    let env = Env::start_with(EnvOptions {
        max_file_bytes: Some(1 << 30),
        ..Default::default()
    })
    .await;
    let laptop = new_key();
    env.pair_with(&laptop, "my laptop", pref).await;
    let rec = env
        .gw
        .authenticator()
        .registry()
        .get(&Env::id_of(&laptop))
        .unwrap()
        .expect("registered");
    assert_eq!(rec.name, "my laptop");
    // Pairing is an audited registry change (decision 1).
    assert!(
        env.privd
            .wait_for(|s| s.events.iter().any(|e| e.0 == AuditEvent::DeviceAdded))
            .await
    );

    // A paired device on a server with no PIN yet is refused like a stranger.
    let err = hx_crypto::connect_session(
        &env.target(pref),
        &laptop,
        env.server_public(),
        &env.session_opts(pref, "my laptop"),
    )
    .await
    .map(|_| ())
    .unwrap_err();
    assert!(
        matches!(&err, CryptoError::Refused { message, .. } if message == "not authorized"),
        "{err}"
    );

    env.set_pin(PIN).await;
    let conn = env.login_with(&laptop, "my laptop", PIN, pref).await;
    assert!(conn.is_authorized());
    let n = conn.negotiated();
    assert_eq!(n.version.minor, PROTOCOL_MINOR);
    assert!(
        conn.enabled_features()
            .contains(Features::defined_up_to(PROTOCOL_MINOR)),
        "every offered feature is in effect: {:?}",
        conn.enabled_features()
    );
    assert_eq!(
        n.max_file_bytes,
        1 << 30,
        "the configured limit is advertised"
    );
    assert_eq!(n.codecs, [hx_proto::VideoCodec::H264]);
    // Only the pepper holder can say yes: one PepperVerify, answered yes.
    assert_eq!(env.privd.with(|s| (s.verify_ok, s.verify_fail)), (1, 0));
    conn.close(CloseCode::NoError, "done").await;
}

async fn an_unknown_or_revoked_device_is_refused_the_same_way(
    pref: hx_transport::TransportPreference,
) {
    let env = Env::start().await;
    env.set_pin(PIN).await;
    let stranger = new_key();
    let refused = |e: CryptoError| match e {
        CryptoError::Refused { reason, message } => (reason, message),
        other => panic!("{other}"),
    };
    let e1 = hx_crypto::connect_session(
        &env.target(pref),
        &stranger,
        env.server_public(),
        &env.session_opts(pref, "x"),
    )
    .await
    .map(|_| ())
    .unwrap_err();
    let (r1, m1) = refused(e1);
    assert_eq!(r1, pb::RefuseReason::Unauthorized);

    let phone = new_key();
    env.pair_with(&phone, "phone", pref).await;
    env.gw
        .devices()
        .revoke_by_operator(Env::id_of(&phone))
        .await
        .unwrap();
    let e2 = hx_crypto::connect_session(
        &env.target(pref),
        &phone,
        env.server_public(),
        &env.session_opts(pref, "phone"),
    )
    .await
    .map(|_| ())
    .unwrap_err();
    let (r2, m2) = refused(e2);
    assert_eq!((r1, &m1), (r2, &m2), "unknown and revoked look the same");
}

async fn wrong_pins_are_counted_backed_off_and_the_fifth_revokes(
    pref: hx_transport::TransportPreference,
) {
    let env = Env::start().await;
    let phone = new_key();
    env.pair_with(&phone, "phone", pref).await;
    env.set_pin(PIN).await;
    let id = Env::id_of(&phone);
    let failed = |env: &Env| {
        env.gw
            .authenticator()
            .registry()
            .get(&id)
            .unwrap()
            .unwrap()
            .failed_pins
    };

    let mut a = env.connect_unauth(&phone, "phone").await;
    let wrong = hx_crypto::Pin::new("111111").unwrap();
    let right = hx_crypto::Pin::new(PIN).unwrap();
    // 1st wrong: counted, 4 left, 1 s wait.
    match within(a.submit(&wrong)).await.unwrap() {
        PinReply::Wrong {
            attempts_left,
            retry_after,
        } => {
            assert_eq!(attempts_left, 4);
            assert_eq!(retry_after, Duration::from_secs(1));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(failed(&env), 1);
    // Too soon: not verified, not counted.
    let verified_before = env.privd.with(|s| s.verify_ok + s.verify_fail);
    assert!(matches!(
        within(a.submit(&right)).await.unwrap(),
        PinReply::Backoff { .. }
    ));
    assert_eq!(failed(&env), 1);
    assert_eq!(
        env.privd.with(|s| s.verify_ok + s.verify_fail),
        verified_before
    );
    // After the wait, the right PIN resets the counter.
    env.clock.advance(Duration::from_secs(2));
    assert_eq!(within(a.submit(&right)).await.unwrap(), PinReply::Accepted);
    assert_eq!(failed(&env), 0);
    a.abandon().await;

    // Five wrong PINs in a row revoke the device, each one counted at the gateway and charged
    // to privd's failure budget.
    let mut b = env.connect_unauth(&phone, "phone").await;
    for n in 1..=4u32 {
        env.clock.advance(Duration::from_secs(40));
        match within(b.submit(&wrong)).await.unwrap() {
            PinReply::Wrong { attempts_left, .. } => assert_eq!(attempts_left, 5 - n),
            other => panic!("{other:?}"),
        }
    }
    env.clock.advance(Duration::from_secs(40));
    // The connection allows five attempt messages in all: the Backoff above used one of the
    // first connection, so open a fresh one for the fifth.
    drop(b);
    let mut c = env.connect_unauth(&phone, "phone").await;
    let err = within(c.submit(&wrong)).await.unwrap_err();
    assert!(matches!(err, CryptoError::Revoked), "{err}");
    let rec = env.gw.authenticator().registry().get(&id).unwrap().unwrap();
    assert!(rec.is_revoked());
    assert_eq!(
        env.privd.with(|s| s.verify_fail),
        6,
        "every wrong PIN reached privd"
    );
    // A revoked device is refused at the next connection.
    let err = hx_crypto::connect_session(
        &env.target(pref),
        &phone,
        env.server_public(),
        &env.session_opts(pref, "phone"),
    )
    .await
    .map(|_| ())
    .unwrap_err();
    assert!(matches!(err, CryptoError::Refused { .. }), "{err}");
    // And the lockout revocation was audited and announced like any other.
    assert!(
        env.privd
            .wait_for(|s| s.events.iter().any(|e| e.0 == AuditEvent::DeviceRevoked))
            .await
    );
}

on_both_transports!(
    pair_then_pin_login,
    an_unknown_or_revoked_device_is_refused_the_same_way,
    wrong_pins_are_counted_backed_off_and_the_fifth_revokes,
);

#[tokio::test]
async fn a_privd_outage_is_never_a_wrong_pin() {
    let env = Env::start().await;
    let phone = new_key();
    env.pair(&phone, "phone").await;
    env.set_pin(PIN).await;
    let id = Env::id_of(&phone);
    let mut a = env.connect_unauth(&phone, "phone").await;
    env.privd.set_down(true);
    match within(a.submit(&hx_crypto::Pin::new(PIN).unwrap()))
        .await
        .unwrap()
    {
        PinReply::Backoff { retry_after } => assert!(retry_after >= Duration::from_secs(1)),
        other => panic!("{other:?}"),
    }
    let rec = env.gw.authenticator().registry().get(&id).unwrap().unwrap();
    assert_eq!(rec.failed_pins, 0, "nothing was counted");
    assert!(!rec.is_revoked());
    env.privd.set_down(false);
    assert_eq!(
        within(a.submit(&hx_crypto::Pin::new(PIN).unwrap()))
            .await
            .unwrap(),
        PinReply::Accepted
    );
}

#[tokio::test]
async fn a_locked_pin_purpose_refuses_logins_without_revoking_anyone() {
    let env = Env::start().await;
    let phone = new_key();
    env.pair(&phone, "phone").await;
    env.set_pin(PIN).await;
    env.privd.with(|s| s.pin_failure_cap = 1);
    let mut a = env.connect_unauth(&phone, "phone").await;
    // The first wrong PIN uses up privd's global budget and locks the purpose.
    assert!(matches!(
        within(a.submit(&hx_crypto::Pin::new("111111").unwrap()))
            .await
            .unwrap(),
        PinReply::Wrong { .. }
    ));
    env.clock.advance(Duration::from_secs(5));
    let err = within(a.submit(&hx_crypto::Pin::new(PIN).unwrap()))
        .await
        .unwrap_err();
    assert!(matches!(err, CryptoError::PinNotAvailable), "{err}");
    let rec = env
        .gw
        .authenticator()
        .registry()
        .get(&Env::id_of(&phone))
        .unwrap()
        .unwrap();
    assert!(!rec.is_revoked());
}

// ------------------------------------------------------------------ revocation

#[tokio::test]
async fn revoking_a_device_closes_its_live_session_and_is_audited() {
    let env = Env::start().await;
    let (a, b) = (new_key(), new_key());
    env.pair(&a, "alice").await;
    env.pair(&b, "bob").await;
    env.set_pin(PIN).await;
    let ca = env.login(&a, "alice", PIN).await;
    let cb = env.login(&b, "bob", PIN).await;
    ca.send_control(&view_config()).await.unwrap();
    assert!(eventually(|| async { env.gw.sessions().has_active_client().await }).await);

    // The operator revokes Alice: her live session is closed with UNAUTHORIZED, her link
    // handle is released, privd's audit log has the event, and Bob is told.
    let sessions = env
        .gw
        .devices()
        .revoke_by_operator(Env::id_of(&a))
        .await
        .unwrap();
    assert_eq!(sessions, Some(1));
    let info = closed_with(&ca).await;
    assert_eq!(info.code, CloseCode::Unauthorized);
    assert!(
        eventually(|| async {
            env.link
                .log()
                .contains(&Event::Detach("alice".into(), DetachReason::Left))
        })
        .await
    );
    assert!(
        env.privd
            .wait_for(|s| s.events.iter().any(|e| e.0 == AuditEvent::DeviceRevoked))
            .await
    );
    let ev = next_event(&cb).await;
    assert_eq!(ev.kind, pb::DeviceEventKind::Revoked as i32);
    assert_eq!(
        ev.device.unwrap().device_id.as_ref(),
        Env::id_of(&a).as_bytes()
    );
    assert!(
        ev.by_device_id.is_empty(),
        "the operator is not a paired device"
    );
    assert!(cb.close_info().is_none(), "Bob is unaffected");
}

#[tokio::test]
async fn shutting_down_tells_live_sessions() {
    let env = Env::start().await;
    let a = new_key();
    env.pair(&a, "alice").await;
    env.set_pin(PIN).await;
    let ca = env.login(&a, "alice", PIN).await;
    let Env { gw, dir, privd, .. } = env;
    gw.shutdown().await;
    assert_eq!(closed_with(&ca).await.code, CloseCode::Shutdown);
    drop((dir, privd));
}

// ------------------------------------------------------------------ takeover

async fn two_devices(
    env: &Env,
) -> (
    std::sync::Arc<hx_crypto::IdentityKey>,
    std::sync::Arc<hx_crypto::IdentityKey>,
) {
    let (a, b) = (new_key(), new_key());
    env.pair(&a, "alice").await;
    env.pair(&b, "bob\u{1b}[31m\u{202e}").await;
    env.set_pin(PIN).await;
    (a, b)
}

#[tokio::test]
async fn takeover_follows_the_documented_order() {
    let env = Env::start().await;
    let (a, b) = two_devices(&env).await;
    let ca = env.login(&a, "alice", PIN).await;
    ca.send_control(&view_config()).await.unwrap();
    assert!(eventually(|| async { env.link.log().len() == 1 }).await);

    let cb = env.login(&b, "bob", PIN).await;
    cb.send_control(&view_config()).await.unwrap();

    // The displaced client is told, with the newcomer's sanitized name and its device id,
    // then closed with code 9.
    let g = goodbye(&ca).await;
    assert_eq!(g.code, CloseCode::TakenOver.code());
    assert_eq!(g.peer_device_name, "bob[31m", "controls and bidi removed");
    assert_eq!(g.peer_device_id.as_ref(), Env::id_of(&b).as_bytes());
    let info = closed_with(&ca).await;
    assert_eq!(info.code, CloseCode::TakenOver);
    assert!(
        !info.reason.contains("bob"),
        "the close reason never carries the name"
    );

    // ipc.md 18: (1) release_input, (2) cancel in-flight, (3) notice, (4) attach.
    assert!(eventually(|| async { env.link.log().len() == 5 }).await);
    assert_eq!(
        env.link.log(),
        [
            Event::Attach("alice".into()),
            Event::ReleaseInput("alice".into()),
            Event::CancelInFlight("alice".into()),
            Event::Detach("alice".into(), DetachReason::Displaced),
            Event::Attach("bob[31m".into()),
        ]
    );
    // privd's audit log has it, and the newcomer is not displaced.
    assert!(
        env.privd
            .wait_for(|s| s.events.iter().any(|e| e.0 == AuditEvent::Takeover
                && e.1.as_deref() == Some(Env::id_of(&b).as_bytes().as_slice())))
            .await
    );
    assert!(cb.close_info().is_none());
}

#[tokio::test]
async fn a_protocol_1_0_client_gets_the_busy_fallback() {
    let env = Env::start().await;
    let (a, b) = two_devices(&env).await;
    // Alice speaks 1.0: she cannot be sent the new close code.
    let mut raw = RawClient::connect(env.gw.quic_addr().unwrap(), &a, env.server_public()).await;
    let ack = raw.hello_v10().await;
    assert_eq!(ack.version.unwrap().minor, PROTOCOL_MINOR);
    assert_eq!(raw.submit_pin(PIN).await, hx_crypto::wire::AuthStatus::Ok);
    raw.send_ctl(&view_config()).await;
    assert!(eventually(|| async { env.link.log().len() == 1 }).await);

    let cb = env.login(&b, "bob", PIN).await;
    cb.send_control(&view_config()).await.unwrap();

    let m = raw.recv_ctl().await.expect("goodbye");
    let Some(Ctl::Goodbye(g)) = m.message else {
        panic!("{m:?}")
    };
    assert_eq!(g.code, CloseCode::Busy.code());
    assert_eq!(g.message, "another device took over this desktop");
    assert!(g.peer_device_name.is_empty() && g.peer_device_id.is_empty());
    // QUIC application close code 5 (BUSY), not 9.
    match within(raw.conn.closed()).await {
        quinn::ConnectionError::ApplicationClosed(c) => {
            assert_eq!(c.error_code.into_inner(), u64::from(CloseCode::Busy.code()));
        }
        other => panic!("{other:?}"),
    }
    // The takeover itself still happened.
    assert!(eventually(|| async { env.link.log().len() == 5 }).await);
}

#[tokio::test]
async fn deny_policy_answers_the_newcomer_busy_and_keeps_the_active_client() {
    let env = Env::start_with(EnvOptions {
        takeover_deny: true,
        ..Default::default()
    })
    .await;
    let (a, b) = two_devices(&env).await;
    let ca = env.login(&a, "alice", PIN).await;
    ca.send_control(&view_config()).await.unwrap();
    assert!(eventually(|| async { env.link.log().len() == 1 }).await);
    let cb = env.login(&b, "bob", PIN).await;
    cb.send_control(&view_config()).await.unwrap();
    let g = goodbye(&cb).await;
    assert_eq!(g.code, CloseCode::Busy.code());
    assert_eq!(closed_with(&cb).await.code, CloseCode::Busy);
    assert_eq!(
        env.link.log(),
        [Event::Attach("alice".into())],
        "Alice was left alone"
    );
    assert!(ca.close_info().is_none());
}

#[tokio::test]
async fn takeovers_are_limited_to_three_per_ten_minutes() {
    let env = Env::start().await;
    let (a, b) = two_devices(&env).await;
    // Alice claims; then Bob, Alice, Bob take over (three takeovers); the fourth is refused.
    let mut conns = Vec::new();
    for (i, (key, name)) in [
        (&a, "alice"),
        (&b, "bob[31m"),
        (&a, "alice"),
        (&b, "bob[31m"),
    ]
    .into_iter()
    .enumerate()
    {
        let c = env.login(key, name, PIN).await;
        c.send_control(&view_config()).await.unwrap();
        assert!(
            eventually(|| async {
                env.link
                    .log()
                    .iter()
                    .filter(|e| matches!(e, Event::Attach(_)))
                    .count()
                    == i + 1
            })
            .await,
            "claim {i}"
        );
        conns.push(c);
    }
    // Bob replacing his own session while the old connection is alive is not exempt: the same
    // limit applies (a copied key plus PIN cannot displace the owner at will).
    let bob_again = env.login(&b, "bob[31m", PIN).await;
    bob_again.send_control(&view_config()).await.unwrap();
    let g = goodbye(&bob_again).await;
    assert_eq!(g.code, CloseCode::Busy.code());
    assert!(g.message.contains("too many takeovers"), "{}", g.message);
    // A different device is refused until the window passes.
    let alice = env.login(&a, "alice", PIN).await;
    alice.send_control(&view_config()).await.unwrap();
    let g = goodbye(&alice).await;
    assert_eq!(g.code, CloseCode::Busy.code());
    assert!(g.message.contains("too many takeovers"), "{}", g.message);
    assert_eq!(
        env.link
            .log()
            .iter()
            .filter(|e| matches!(e, Event::Attach(_)))
            .count(),
        4,
        "the refused takeovers attached nothing"
    );
    drop(conns);
}

#[tokio::test]
async fn a_management_only_session_claims_nothing_and_idles_out() {
    let env = Env::start_with(EnvOptions {
        manage_idle_s: 2,
        ..Default::default()
    })
    .await;
    let (a, b) = two_devices(&env).await;
    let ca = env.login(&a, "alice", PIN).await;
    ca.send_control(&view_config()).await.unwrap();
    assert!(eventually(|| async { env.link.log().len() == 1 }).await);
    // Bob authenticates and manages devices without viewing: Alice is not displaced.
    let cb = env.login(&b, "bob", PIN).await;
    assert_eq!(list(&cb, 1).await.devices.len(), 2);
    assert_eq!(env.link.log(), [Event::Attach("alice".into())]);
    assert!(ca.close_info().is_none());
    // A session that never asks to view is closed after the idle time.
    assert_eq!(closed_with(&cb).await.code, CloseCode::NoError);
    assert!(
        ca.close_info().is_none(),
        "the viewing session has no idle limit"
    );
}

// ------------------------------------------------------------------ the desktop seam

#[tokio::test]
async fn an_unavailable_desktop_is_reported_to_the_client() {
    let env = Env::start_with(EnvOptions {
        link_unavailable: true,
        ..Default::default()
    })
    .await;
    let a = new_key();
    env.pair(&a, "alice").await;
    env.set_pin(PIN).await;
    let ca = env.login(&a, "alice", PIN).await;
    ca.send_control(&view_config()).await.unwrap();
    let g = goodbye(&ca).await;
    assert_eq!(g.code, CloseCode::Busy.code());
    assert_eq!(g.message, "desktop unavailable");
    assert_eq!(closed_with(&ca).await.code, CloseCode::Busy);
}

#[tokio::test]
async fn a_stopped_desktop_is_started_and_its_link_provisioned_through_privd() {
    let env = Env::start().await;
    env.privd
        .with(|s| s.desktop_state = hx_ipc::privd::pb::DesktopState::Stopped as i32);
    let a = new_key();
    env.pair(&a, "alice").await;
    env.set_pin(PIN).await;
    let ca = env.login(&a, "alice", PIN).await;
    ca.send_control(&view_config()).await.unwrap();
    assert!(eventually(|| async { env.link.log().len() == 1 }).await);
    env.privd.with(|s| {
        assert_eq!(s.start_calls, 1);
        assert_eq!(s.provision_calls, 1);
    });
    let cmds = env.privd.commands();
    assert!(cmds.contains(&"GetDesktop".to_string()));
    assert!(cmds.contains(&"StartDesktop".to_string()));
    assert!(cmds.contains(&"ProvisionSessionLink".to_string()));
}

#[tokio::test]
async fn a_missing_desktop_is_unavailable_and_nothing_is_started() {
    let env = Env::start().await;
    env.privd.with(|s| s.desktop_exists = false);
    let a = new_key();
    env.pair(&a, "alice").await;
    env.set_pin(PIN).await;
    let ca = env.login(&a, "alice", PIN).await;
    ca.send_control(&view_config()).await.unwrap();
    assert_eq!(goodbye(&ca).await.message, "desktop unavailable");
    assert_eq!(env.privd.with(|s| s.start_calls), 0);
    assert!(env.link.log().is_empty());
}

#[tokio::test]
async fn the_stub_link_makes_every_view_request_unavailable_but_login_works() {
    // The production stub (UnavailableLink) behind the real gateway.
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let privd = FakePrivd::start(dir.path());
    let mut config = hx_agent::gateway::config::GatewayConfig::with_listen(
        "127.0.0.1:0".parse().unwrap(),
        state,
    );
    config.privd_socket = privd.path.clone();
    let key = new_key();
    let opts = hx_agent::gateway::server::StartOptions::new(
        config,
        key.clone(),
        std::sync::Arc::new(hx_agent::gateway::desktop::UnavailableLink),
    );
    let gw = hx_agent::gateway::server::Gateway::start(opts)
        .await
        .unwrap();
    let device = new_key();
    let token = gw.authenticator().pairing().issue_token().unwrap();
    let target = hx_transport::Target {
        addr: gw.quic_addr().unwrap(),
        server_name: rustls::pki_types::ServerName::try_from("hx.invalid").unwrap(),
    };
    within(hx_crypto::pair_device(
        &target,
        &device,
        &hx_crypto::PairingCredential::parse(&token.to_text()).unwrap(),
        &Default::default(),
    ))
    .await
    .unwrap()
    .finish()
    .await;
    let record = hx_agent::gateway::verifier::enrol(
        gw.privd(),
        hx_ipc::privd::pb::LockoutPurpose::Pin,
        PIN.as_bytes(),
        CHEAP,
    )
    .await
    .unwrap();
    gw.verifiers().set_pin(None, record).unwrap();
    let conn = within(hx_crypto::connect_with_pin(
        &target,
        &device,
        key.public(),
        &hx_crypto::Pin::new(PIN).unwrap(),
        &hx_crypto::SessionOptions {
            capabilities: hx_proto::version::capabilities(
                &[hx_proto::VideoCodec::H264],
                Features::defined_up_to(PROTOCOL_MINOR),
            ),
            ..Default::default()
        },
    ))
    .await
    .unwrap();
    conn.send_control(&view_config()).await.unwrap();
    assert_eq!(goodbye(&conn).await.message, "desktop unavailable");
}

// ------------------------------------------------------------------ device management

#[tokio::test]
async fn list_and_revoke_over_the_device_management_messages() {
    let env = Env::start().await;
    let (a, b, c) = (new_key(), new_key(), new_key());
    env.pair(&a, "alice").await;
    env.pair(&b, "bob").await;
    env.pair(&c, "carol").await;
    env.set_pin(PIN).await;
    let ca = env.login(&a, "alice", PIN).await;
    let cb = env.login(&b, "bob", PIN).await;
    let cc = env.login(&c, "carol", PIN).await;

    // Listing: three active devices, "current" marks the asker.
    let l = list(&ca, 1).await;
    assert_eq!(l.devices.len(), 3);
    assert!(!l.truncated);
    assert!(
        l.devices
            .iter()
            .all(|d| d.status == pb::DeviceStatus::Active as i32)
    );
    let me: Vec<_> = l.devices.iter().filter(|d| d.current).collect();
    assert_eq!(me.len(), 1);
    assert_eq!(me[0].device_id.as_ref(), Env::id_of(&a).as_bytes());
    assert_eq!(me[0].name, "alice");

    // Alice revokes Bob. Bob's session is closed; every live session is told, with Alice as
    // the actor.
    assert_eq!(
        revoke(&ca, 2, Env::id_of(&b).as_bytes()).await,
        pb::RevokeStatus::Ok
    );
    assert_eq!(closed_with(&cb).await.code, CloseCode::Unauthorized);
    for conn in [&ca, &cc] {
        let ev = next_event(conn).await;
        assert_eq!(ev.kind, pb::DeviceEventKind::Revoked as i32);
        assert_eq!(ev.by_device_id.as_ref(), Env::id_of(&a).as_bytes());
        let d = ev.device.unwrap();
        assert_eq!(d.name, "bob");
        assert_eq!(d.status, pb::DeviceStatus::Revoked as i32);
        assert_eq!(d.revoke_reason, pb::DeviceRevokeReason::User as i32);
    }
    // The audit log has it.
    assert!(
        env.privd
            .wait_for(|s| s.events.iter().any(|e| e.0 == AuditEvent::DeviceRevoked))
            .await
    );
    // The list shows Bob revoked, last, with a reason and a time.
    let l = list(&ca, 3).await;
    assert_eq!(l.devices.len(), 3);
    let last = l.devices.last().unwrap();
    assert_eq!(last.name, "bob");
    assert_eq!(last.status, pb::DeviceStatus::Revoked as i32);
    assert!(last.revoked_unix > 0);

    // Idempotent, and honest about unknown ids.
    assert_eq!(
        revoke(&ca, 4, Env::id_of(&b).as_bytes()).await,
        pb::RevokeStatus::AlreadyRevoked
    );
    assert_eq!(
        revoke(&ca, 5, &[0xEE; 16]).await,
        pb::RevokeStatus::NotFound
    );

    // A new device pairing is announced to the live sessions.
    let d = new_key();
    env.pair(&d, "dave").await;
    let ev = next_event(&cc).await;
    assert_eq!(ev.kind, pb::DeviceEventKind::Added as i32);
    assert_eq!(ev.device.unwrap().name, "dave");

    // Self-revoke is allowed while another active device remains: the result comes first, then
    // the connection closes.
    assert_eq!(
        revoke(&cc, 6, Env::id_of(&c).as_bytes()).await,
        pb::RevokeStatus::Ok
    );
    assert_eq!(closed_with(&cc).await.code, CloseCode::Unauthorized);
    // Revoke Dave; Alice is now the last active device and cannot revoke herself.
    assert_eq!(
        revoke(&ca, 7, Env::id_of(&d).as_bytes()).await,
        pb::RevokeStatus::Ok
    );
    assert_eq!(
        revoke(&ca, 8, Env::id_of(&a).as_bytes()).await,
        pb::RevokeStatus::LastActiveDevice
    );
    assert!(
        !env.gw
            .authenticator()
            .registry()
            .get(&Env::id_of(&a))
            .unwrap()
            .unwrap()
            .is_revoked(),
        "nothing changed"
    );
}

#[tokio::test]
async fn revoke_requests_are_rate_limited_per_connection() {
    let env = Env::start().await;
    let a = new_key();
    env.pair(&a, "alice").await;
    env.set_pin(PIN).await;
    let ca = env.login(&a, "alice", PIN).await;
    for i in 1..=10u32 {
        assert_eq!(
            revoke(&ca, i, &[i as u8; 16]).await,
            pb::RevokeStatus::NotFound
        );
    }
    assert_eq!(
        revoke(&ca, 11, &[11; 16]).await,
        pb::RevokeStatus::RateLimited
    );
}

#[tokio::test]
async fn device_management_needs_a_negotiated_feature_and_valid_direction() {
    let env = Env::start().await;
    let (a, b) = (new_key(), new_key());
    env.pair(&a, "alice").await;
    env.pair(&b, "bob").await;
    env.set_pin(PIN).await;

    // A 1.0 client never gets the feature, so DeviceMgmt from it is a protocol error.
    let mut raw = RawClient::connect(env.gw.quic_addr().unwrap(), &a, env.server_public()).await;
    raw.hello_v10().await;
    assert_eq!(raw.submit_pin(PIN).await, hx_crypto::wire::AuthStatus::Ok);
    raw.send_ctl(&mgmt(1, Mgmt::List(pb::ListDevices {}))).await;
    match within(raw.conn.closed()).await {
        quinn::ConnectionError::ApplicationClosed(c) => {
            assert_eq!(
                c.error_code.into_inner(),
                u64::from(CloseCode::ProtocolError.code())
            );
        }
        other => panic!("{other:?}"),
    }

    // A 1.2 client sending a body that only the server may send.
    let cb = env.login(&b, "bob", PIN).await;
    cb.send_control(&mgmt(
        1,
        Mgmt::DeviceList(pb::DeviceList {
            devices: vec![],
            truncated: false,
        }),
    ))
    .await
    .unwrap();
    assert_eq!(closed_with(&cb).await.code, CloseCode::ProtocolError);
}

#[tokio::test]
async fn messages_only_the_server_may_send_are_protocol_errors_from_a_client() {
    let env = Env::start().await;
    let a = new_key();
    env.pair(&a, "alice").await;
    env.set_pin(PIN).await;
    let stats = pb::ServerStats {
        interval_ms: 1000,
        ..Default::default()
    };
    let ca = env.login(&a, "alice", PIN).await;
    ca.send_control(&ctl(Ctl::ServerStats(stats)))
        .await
        .unwrap();
    assert_eq!(closed_with(&ca).await.code, CloseCode::ProtocolError);

    // A ViewConfig that asks for a codec nobody negotiated.
    let ca = env.login(&a, "alice", PIN).await;
    ca.send_control(&ctl(Ctl::ViewConfig(pb::ViewConfig {
        codec: pb::VideoCodec::Av1 as i32,
        ..Default::default()
    })))
    .await
    .unwrap();
    assert_eq!(closed_with(&ca).await.code, CloseCode::ProtocolError);
    assert!(env.link.log().is_empty(), "nothing reached the link");
}

#[tokio::test]
async fn names_with_control_characters_never_reach_a_client_unclean() {
    let env = Env::start().await;
    let (a, b) = two_devices(&env).await;
    let ca = env.login(&a, "alice", PIN).await;
    // The registry holds "bob[31m" (sanitized at pairing); a list must validate on the client.
    let l = list(&ca, 1).await;
    for d in &l.devices {
        assert!(!d.name.chars().any(char::is_control), "{:?}", d.name);
        assert!(!d.name.contains('\u{202e}'));
    }
    drop(b);
}

// ------------------------------------------------------------------ review findings

/// F2: a revoke request that was queued behind its sender's own revocation must not run, or
/// two devices racing could revoke each other and leave nobody.
#[tokio::test]
async fn a_revoked_devices_queued_revoke_cannot_leave_the_server_without_devices() {
    let env = Env::start().await;
    let (a, b) = (new_key(), new_key());
    env.pair(&a, "alice").await;
    env.pair(&b, "bob").await;
    env.set_pin(PIN).await;
    let cb = env.login(&b, "bob", PIN).await;
    // The operator revokes Bob first; then Bob's already-queued RevokeDevice(Alice) is served.
    env.gw
        .devices()
        .revoke_by_operator(Env::id_of(&b))
        .await
        .unwrap();
    let status = env
        .gw
        .devices()
        .revoke_by_device(Env::id_of(&b), Env::id_of(&a))
        .await;
    assert_eq!(
        status,
        pb::RevokeStatus::Failed,
        "a revoked requester is refused"
    );
    assert!(
        env.gw.devices().is_active(&Env::id_of(&a)),
        "Alice is still active"
    );
    assert_eq!(closed_with(&cb).await.code, CloseCode::Unauthorized);

    // Also over the wire: Dave pipelines the request while being revoked; whichever order the
    // gateway sees them in, a device stays active and Dave ends up closed as unauthorized.
    let (c, d) = (new_key(), new_key());
    env.pair(&c, "carol").await;
    env.pair(&d, "dave").await;
    let cd = env.login(&d, "dave", PIN).await;
    cd.send_control(&mgmt(
        1,
        Mgmt::Revoke(pb::RevokeDevice {
            device_id: Bytes::copy_from_slice(Env::id_of(&c).as_bytes()),
        }),
    ))
    .await
    .unwrap();
    env.gw
        .devices()
        .revoke_by_operator(Env::id_of(&d))
        .await
        .unwrap();
    assert_eq!(closed_with(&cd).await.code, CloseCode::Unauthorized);
    assert!(
        env.gw.devices().is_active(&Env::id_of(&a)) || env.gw.devices().is_active(&Env::id_of(&c)),
        "at least one device stays active"
    );
}

/// F2: a device-initiated revocation never leaves zero active devices, whoever the target is.
#[tokio::test]
async fn a_device_cannot_revoke_down_to_zero_active_devices() {
    let env = Env::start().await;
    let (a, b) = (new_key(), new_key());
    env.pair(&a, "alice").await;
    env.pair(&b, "bob").await;
    env.set_pin(PIN).await;
    // Bob revokes Alice: fine, Bob stays. Bob cannot then revoke himself.
    let s = env
        .gw
        .devices()
        .revoke_by_device(Env::id_of(&b), Env::id_of(&a))
        .await;
    assert_eq!(s, pb::RevokeStatus::Ok);
    let s = env
        .gw
        .devices()
        .revoke_by_device(Env::id_of(&b), Env::id_of(&b))
        .await;
    assert_eq!(s, pb::RevokeStatus::LastActiveDevice);
}

/// F3: a device revoked while its claim is waiting for the desktop to start is closed at once
/// (not when the claim finishes) and is never attached.
#[tokio::test]
async fn a_revocation_during_a_slow_claim_closes_the_session_at_once_and_attaches_nothing() {
    let env = Env::start().await;
    env.privd.with(|s| {
        s.desktop_state = hx_ipc::privd::pb::DesktopState::Stopped as i32;
        s.start_delay_ms = 3000;
    });
    let a = new_key();
    env.pair(&a, "alice").await;
    env.set_pin(PIN).await;
    let ca = env.login(&a, "alice", PIN).await;
    ca.send_control(&view_config()).await.unwrap();
    // The claim is now waiting in StartDesktop (3 s). Revoke the device.
    assert!(
        env.privd
            .wait_for(|s| s.commands.iter().any(|c| c == "StartDesktop"))
            .await
    );
    let started = std::time::Instant::now();
    env.gw
        .devices()
        .revoke_by_operator(Env::id_of(&a))
        .await
        .unwrap();
    assert_eq!(closed_with(&ca).await.code, CloseCode::Unauthorized);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "closed in {:?}",
        started.elapsed()
    );
    // Let the slow StartDesktop finish: the claim must find the device revoked.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        env.link.log().is_empty(),
        "nothing was attached: {:?}",
        env.link.log()
    );
    assert!(!env.gw.sessions().has_active_client().await);
}

/// F5: under `deny`, the same key cannot displace its own live session.
#[tokio::test]
async fn a_copied_key_cannot_displace_the_live_owner_even_under_deny() {
    let env = Env::start_with(EnvOptions {
        takeover_deny: true,
        ..Default::default()
    })
    .await;
    let a = new_key();
    env.pair(&a, "alice").await;
    env.set_pin(PIN).await;
    let owner = env.login(&a, "alice", PIN).await;
    owner.send_control(&view_config()).await.unwrap();
    assert!(eventually(|| async { env.link.log().len() == 1 }).await);
    let copy = env.login(&a, "alice", PIN).await;
    copy.send_control(&view_config()).await.unwrap();
    let g = goodbye(&copy).await;
    assert_eq!(g.code, CloseCode::Busy.code());
    assert_eq!(env.link.log(), [Event::Attach("alice".into())]);
    assert!(owner.close_info().is_none(), "the owner was left alone");
}

/// F5: a device whose old connection is dead (it answers no ping) can still come back, even
/// under `deny`: that is the stale-session case the exemption exists for.
#[tokio::test]
async fn a_device_replaces_its_own_unresponsive_session_even_under_deny() {
    let env = Env::start_with(EnvOptions {
        takeover_deny: true,
        ..Default::default()
    })
    .await;
    let a = new_key();
    env.pair(&a, "alice").await;
    env.set_pin(PIN).await;
    // A connection that never reads its control stream cannot answer the gateway's ping.
    let mut stale = RawClient::connect(env.gw.quic_addr().unwrap(), &a, env.server_public()).await;
    stale.hello_v10().await;
    assert_eq!(stale.submit_pin(PIN).await, hx_crypto::wire::AuthStatus::Ok);
    stale.send_ctl(&view_config()).await;
    assert!(eventually(|| async { env.link.log().len() == 1 }).await);
    let back = env.login(&a, "alice", PIN).await;
    back.send_control(&view_config()).await.unwrap();
    assert!(
        eventually(|| async {
            env.link
                .log()
                .iter()
                .filter(|e| matches!(e, Event::Attach(_)))
                .count()
                == 2
        })
        .await,
        "{:?}",
        env.link.log()
    );
    assert!(back.close_info().is_none());
}

/// F1 (interim): while privd reports the PIN purpose locked, a device is made to wait. Its
/// reconnects are answered "too soon" without being counted, so it is never driven to
/// revocation by attempts that were never checked.
#[tokio::test]
async fn a_locked_pin_purpose_makes_devices_wait_and_never_revokes_them() {
    let env = Env::start().await;
    let phone = new_key();
    env.pair(&phone, "phone").await;
    env.set_pin(PIN).await;
    let id = Env::id_of(&phone);
    let failed = |env: &Env| {
        env.gw
            .authenticator()
            .registry()
            .get(&id)
            .unwrap()
            .unwrap()
            .failed_pins
    };
    env.privd.with(|s| s.pin_failure_cap = 1);
    let mut a = env.connect_unauth(&phone, "phone").await;
    assert!(matches!(
        within(a.submit(&hx_crypto::Pin::new("111111").unwrap()))
            .await
            .unwrap(),
        PinReply::Wrong { .. }
    ));
    env.clock.advance(Duration::from_secs(5));
    // The purpose is locked now: this attempt is counted, cannot be checked, and starts a wait.
    let err = within(a.submit(&hx_crypto::Pin::new(PIN).unwrap()))
        .await
        .unwrap_err();
    assert!(matches!(err, CryptoError::PinNotAvailable), "{err}");
    let counted = failed(&env);
    // Seven reconnects with the right PIN inside the wait: all "too soon", none counted.
    for _ in 0..7 {
        let mut b = env.connect_unauth(&phone, "phone").await;
        let r = within(b.submit(&hx_crypto::Pin::new(PIN).unwrap()))
            .await
            .unwrap();
        assert!(matches!(r, PinReply::Backoff { .. }), "{r:?}");
        b.abandon().await;
    }
    assert_eq!(failed(&env), counted, "waiting attempts are not counted");
    assert!(
        !env.gw
            .authenticator()
            .registry()
            .get(&id)
            .unwrap()
            .unwrap()
            .is_revoked()
    );

    // An Admin resets the purpose in privd and the device's lockout; one login clears it.
    env.privd.with(|s| {
        s.pin_locked = false;
        s.pin_failure_cap = 0;
    });
    let mut adm = AdminClient::connect(&env.admin_path).await.unwrap();
    adm.call(
        hx_ipc::admin::pb::request::Command::ReinstateDevice(
            hx_ipc::admin::pb::ReinstateDeviceRequest {
                device_id: Bytes::copy_from_slice(id.as_bytes()),
            },
        ),
        None,
    )
    .await
    .unwrap();
    let _ = env.login(&phone, "phone", PIN).await;
    assert_eq!(failed(&env), 0);
}

/// N6: revocations are recorded directly, not through a broadcast that can lag: a burst larger
/// than the broadcast capacity (64) still reaches privd's audit log in full.
#[tokio::test]
async fn a_burst_of_revocations_is_audited_in_full() {
    let env = Env::start().await;
    let mut keys = Vec::new();
    for i in 0..66 {
        let k = new_key();
        env.pair(&k, &format!("device {i}")).await;
        keys.push(k);
    }
    for k in &keys {
        env.gw
            .devices()
            .revoke_by_operator(Env::id_of(k))
            .await
            .unwrap();
    }
    assert!(
        env.privd
            .wait_for(|s| s
                .events
                .iter()
                .filter(|e| e.0 == AuditEvent::DeviceRevoked)
                .count()
                == 66)
            .await,
        "every revocation was audited"
    );
}

/// F2 (lockout path): a revocation caused by the PIN lockout takes the same lock as every other
/// one, and is audited and announced like them.
#[tokio::test]
async fn a_lockout_revocation_is_serialized_with_the_others_and_recorded() {
    let env = Env::start().await;
    let (a, b) = (new_key(), new_key());
    env.pair(&a, "alice").await;
    env.pair(&b, "bob").await;
    let gate = env.gw.devices().revoke_gate();
    let held = gate.lock().await;
    let devices = env.gw.devices().clone();
    let id = Env::id_of(&b);
    let lockout = tokio::spawn(async move { devices.revoke_lockout(id).await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !lockout.is_finished(),
        "the lockout waits for the revocation lock"
    );
    assert!(env.gw.devices().is_active(&Env::id_of(&b)));
    drop(held);
    assert!(within(lockout).await.unwrap().unwrap());
    assert!(!env.gw.devices().is_active(&Env::id_of(&b)));
    assert!(
        env.privd
            .wait_for(|s| s.events.iter().any(|e| e.0 == AuditEvent::DeviceRevoked))
            .await
    );
}
