//! The admin socket (docs/ipc.md section 9): root only, the command set, secret frames,
//! sanitized replies.

mod gateway_common;

use std::time::Duration;

use bytes::Bytes;
use gateway_common::*;
use hx_agent::gateway::admin::AdminPolicy;
use hx_agent::gateway::verifier;
use hx_ipc::admin::pb::{self, request::Command as C, response::Result as R};
use hx_ipc::privd::pb::{AuditEvent, ErrorCode, LockoutPurpose};
use hx_proto::channel::CloseCode;

async fn admin(env: &Env) -> AdminClient {
    AdminClient::connect(&env.admin_path)
        .await
        .expect("admin connect")
}

fn id_bytes(k: &std::sync::Arc<hx_crypto::IdentityKey>) -> Bytes {
    Bytes::copy_from_slice(Env::id_of(k).as_bytes())
}

fn error_code(r: R) -> ErrorCode {
    match r {
        R::Error(e) => ErrorCode::try_from(e.code).unwrap(),
        other => panic!("expected an error, got {other:?}"),
    }
}

#[tokio::test]
async fn a_non_root_peer_is_refused_without_a_reply() {
    if my_uid() == 0 {
        eprintln!("running as root: the refusal cannot be shown");
        return;
    }
    // The production policy: uid 0 only.
    let env = Env::start_with(EnvOptions {
        admin_policy: AdminPolicy::RootOnly,
        ..Default::default()
    })
    .await;
    let Err(err) = AdminClient::connect(&env.admin_path).await else {
        panic!("a non-root peer was served");
    };
    assert!(
        err == "closed" || err.contains("reset") || err.contains("Broken pipe"),
        "the peer is dropped silently: {err}"
    );
    // Nothing was executed on its behalf and the gateway still serves its owner.
    let phone = new_key();
    env.pair(&phone, "phone").await;
}

#[tokio::test]
async fn status_reports_the_runtime_state() {
    let env = Env::start().await;
    let a = new_key();
    env.pair(&a, "alice").await;
    env.set_pin(PIN).await;
    let mut c = admin(&env).await;
    let R::Status(s) = c.call(C::Status(pb::StatusRequest {}), None).await.unwrap() else {
        panic!("not a status")
    };
    assert_eq!(s.gatewayd_version, env!("CARGO_PKG_VERSION"));
    assert!(s.listening);
    assert_eq!(s.connected_clients, 0);
    assert_eq!(s.session_link, pb::LinkState::Up as i32);
    assert!(!s.setup_window.unwrap().open);
    let v1 = s.registry_version;
    let _conn = env.login(&a, "alice", PIN).await;
    let R::Status(s) = c.call(C::Status(pb::StatusRequest {}), None).await.unwrap() else {
        panic!()
    };
    assert_eq!(s.connected_clients, 1);
    let b = new_key();
    env.pair(&b, "bob").await;
    let R::Status(s2) = c.call(C::Status(pb::StatusRequest {}), None).await.unwrap() else {
        panic!()
    };
    assert!(
        s2.registry_version > v1,
        "a registry change moves the version"
    );
}

#[tokio::test]
async fn device_list_revoke_and_reinstate() {
    let env = Env::start().await;
    let (a, b, c) = (new_key(), new_key(), new_key());
    env.pair(&a, "alice").await;
    env.pair(&b, "bob").await;
    env.pair(&c, "carol").await;
    env.set_pin(PIN).await;
    let mut adm = admin(&env).await;

    // A wrong PIN puts Carol in backoff: "locked".
    let mut wc = env.connect_unauth(&c, "carol").await;
    wc.submit(&hx_crypto::Pin::new("111111").unwrap())
        .await
        .unwrap();
    let live_a = env.login(&a, "alice", PIN).await;

    let R::ListDevices(l) = adm
        .call(C::ListDevices(pb::ListDevicesRequest {}), None)
        .await
        .unwrap()
    else {
        panic!()
    };
    let state_of = |name: &str| {
        pb::DeviceState::try_from(l.devices.iter().find(|d| d.name == name).unwrap().state).unwrap()
    };
    assert_eq!(l.devices.len(), 3);
    assert_eq!(state_of("alice"), pb::DeviceState::Active);
    assert_eq!(state_of("carol"), pb::DeviceState::Locked);

    // Revoke Alice: her live session closes, the count says so, and it is audited.
    let R::RevokeDevice(r) = adm
        .call(
            C::RevokeDevice(pb::RevokeDeviceRequest {
                device_id: id_bytes(&a),
            }),
            None,
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(r.sessions_closed, 1);
    assert_eq!(within(live_a.closed()).await.code, CloseCode::Unauthorized);
    assert!(
        env.privd
            .wait_for(|s| s.events.iter().any(|e| e.0 == AuditEvent::DeviceRevoked))
            .await
    );
    // Again: converges. Unknown: NOT_FOUND. A device id that is not 16 bytes never decodes.
    let R::RevokeDevice(r) = adm
        .call(
            C::RevokeDevice(pb::RevokeDeviceRequest {
                device_id: id_bytes(&a),
            }),
            None,
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(r.sessions_closed, 0);
    let unknown = adm
        .call(
            C::RevokeDevice(pb::RevokeDeviceRequest {
                device_id: Bytes::from(vec![0xAB; 16]),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(error_code(unknown), ErrorCode::NotFound);

    // A revoked device is refused; reinstating lifts it (the PIN counter is reset too).
    assert!(
        hx_crypto::connect_session(
            &env.target(hx_transport::TransportPreference::Quic),
            &a,
            env.server_public(),
            &env.session_opts(hx_transport::TransportPreference::Quic, "alice"),
        )
        .await
        .is_err()
    );
    let ok = adm
        .call(
            C::ReinstateDevice(pb::ReinstateDeviceRequest {
                device_id: id_bytes(&a),
            }),
            None,
        )
        .await
        .unwrap();
    assert!(matches!(ok, R::ReinstateDevice(_)));
    assert!(
        env.privd
            .wait_for(|s| s.events.iter().any(|e| e.0 == AuditEvent::DeviceReinstated))
            .await
    );
    let _again = env.login(&a, "alice", PIN).await;

    // Reinstating a locked device clears its wait: the next attempt is verified, not "too soon".
    let ok = adm
        .call(
            C::ReinstateDevice(pb::ReinstateDeviceRequest {
                device_id: id_bytes(&c),
            }),
            None,
        )
        .await
        .unwrap();
    assert!(matches!(ok, R::ReinstateDevice(_)));
    assert_eq!(
        within(wc.submit(&hx_crypto::Pin::new(PIN).unwrap()))
            .await
            .unwrap(),
        hx_crypto::PinReply::Accepted
    );
    let missing = adm
        .call(
            C::ReinstateDevice(pb::ReinstateDeviceRequest {
                device_id: Bytes::from(vec![1; 16]),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(error_code(missing), ErrorCode::NotFound);
}

#[tokio::test]
async fn pin_and_password_verifiers_are_set_through_the_socket_and_audited() {
    let env = Env::start().await;
    let (a, b) = (new_key(), new_key());
    env.pair(&a, "alice").await;
    env.pair(&b, "bob").await;
    env.set_pin(PIN).await;
    let mut adm = admin(&env).await;
    let enrol = |pin: &'static str, params| {
        let privd = env.gw.privd().clone();
        async move {
            verifier::enrol(&privd, LockoutPurpose::Pin, pin.as_bytes(), params)
                .await
                .unwrap()
                .to_bytes()
        }
    };

    // A per-device PIN: Alice uses hers, Bob still the shared one.
    let alice_pin = enrol("135790", CHEAP).await;
    let r = adm
        .call(
            C::SetPinVerifier(pb::SetPinVerifierRequest {
                target: Some(pb::set_pin_verifier_request::Target::DeviceId(id_bytes(&a))),
                verifier: Bytes::from(alice_pin),
            }),
            None,
        )
        .await
        .unwrap();
    assert!(matches!(r, R::SetPinVerifier(_)));
    let _ = env.login(&a, "alice", "135790").await;
    let _ = env.login(&b, "bob", PIN).await;
    assert!(
        hx_crypto::connect_with_pin(
            &env.target(hx_transport::TransportPreference::Quic),
            &a,
            env.server_public(),
            &hx_crypto::Pin::new(PIN).unwrap(),
            &env.session_opts(hx_transport::TransportPreference::Quic, "alice"),
        )
        .await
        .is_err(),
        "Alice's old PIN no longer works"
    );

    // `all` replaces every device's PIN.
    let new_all = enrol("246810", CHEAP).await;
    adm.call(
        C::SetPinVerifier(pb::SetPinVerifierRequest {
            target: Some(pb::set_pin_verifier_request::Target::All(true)),
            verifier: Bytes::from(new_all),
        }),
        None,
    )
    .await
    .unwrap();
    env.clock.advance(Duration::from_secs(60));
    let _ = env.login(&b, "bob", "246810").await;

    // Refused: a record cheaper than the configured floor, garbage, and an unknown device.
    let cheap = enrol(
        "123456",
        hx_crypto::PinParams {
            memory_kib: 16,
            iterations: 1,
            parallelism: 1,
        },
    )
    .await;
    for (target, v) in [
        (pb::set_pin_verifier_request::Target::All(true), cheap),
        (
            pb::set_pin_verifier_request::Target::All(true),
            b"not a verifier".to_vec(),
        ),
        (
            pb::set_pin_verifier_request::Target::DeviceId(Bytes::from(vec![5; 16])),
            enrol("123456", CHEAP).await,
        ),
    ] {
        let r = adm
            .call(
                C::SetPinVerifier(pb::SetPinVerifierRequest {
                    target: Some(target),
                    verifier: Bytes::from(v),
                }),
                None,
            )
            .await
            .unwrap();
        assert!(matches!(
            error_code(r),
            ErrorCode::InvalidArgument | ErrorCode::NotFound
        ),);
    }

    // The Linux-password verifier is stored (not used by a login).
    let pw = verifier::enrol(
        env.gw.privd(),
        LockoutPurpose::Password,
        b"correct horse battery",
        CHEAP,
    )
    .await
    .unwrap();
    let r = adm
        .call(
            C::SetPasswordVerifier(pb::SetPasswordVerifierRequest {
                verifier: Bytes::from(pw.to_bytes()),
            }),
            None,
        )
        .await
        .unwrap();
    assert!(matches!(r, R::SetPasswordVerifier(_)));
    assert_eq!(env.gw.verifiers().password(), Some(pw));
    assert!(
        env.privd
            .wait_for(|s| {
                let has = |e| s.events.iter().any(|x| x.0 == e);
                has(AuditEvent::PinChanged) && has(AuditEvent::PasswordVerifierChanged)
            })
            .await
    );
}

#[tokio::test]
async fn pairing_codes_and_installed_tokens_work_with_their_lifetimes() {
    let env = Env::start().await;
    let mut adm = admin(&env).await;

    // CreatePairingCode: the printed code pairs a device.
    let R::CreatePairingCode(r) = adm
        .call(
            C::CreatePairingCode(pb::CreatePairingCodeRequest { expires_in_s: 300 }),
            None,
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(r.code.len(), 9, "XXXX-XXXX");
    assert!(r.expires_at_unix_s > 0);
    let phone = new_key();
    let target = env.target(hx_transport::TransportPreference::Quic);
    within(hx_crypto::pair_device(
        &target,
        &phone,
        &hx_crypto::PairingCredential::parse(&r.code).unwrap(),
        &Default::default(),
    ))
    .await
    .expect("paired with the code")
    .finish()
    .await;
    assert!(
        env.gw
            .authenticator()
            .registry()
            .get(&Env::id_of(&phone))
            .unwrap()
            .is_some()
    );
    assert!(
        env.privd
            .wait_for(|s| s.events.iter().any(|e| e.0 == AuditEvent::PairingOpened))
            .await
    );

    // CreatePairingToken: the token is a secret frame, never a protobuf field. It is read,
    // parsed, installed with the requested (capped) lifetime and wiped; the first device pairs
    // with it exactly once.
    let token = hx_crypto::PairingToken::generate().unwrap().to_text();
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let r = adm
        .call(
            C::CreatePairingToken(pb::CreatePairingTokenRequest { expires_in_s: 120 }),
            Some(token.as_bytes()),
        )
        .await
        .unwrap();
    let R::CreatePairingToken(t) = r else {
        panic!("expected a token result, got {r:?}")
    };
    assert!(
        (before + 120..=before + 125).contains(&t.expires_at_unix_s),
        "the requested lifetime is honoured: {}",
        t.expires_at_unix_s
    );
    let tablet = new_key();
    within(hx_crypto::pair_device(
        &target,
        &tablet,
        &hx_crypto::PairingCredential::parse(&token).unwrap(),
        &Default::default(),
    ))
    .await
    .expect("paired with the installed token")
    .finish()
    .await;
    let again = hx_crypto::pair_device(
        &target,
        &new_key(),
        &hx_crypto::PairingCredential::parse(&token).unwrap(),
        &Default::default(),
    )
    .await;
    assert!(again.is_err(), "a token is single use");
    let r = adm
        .call(
            C::CreatePairingToken(pb::CreatePairingTokenRequest { expires_in_s: 300 }),
            Some(b"hxt1-nonsense"),
        )
        .await
        .unwrap();
    assert_eq!(error_code(r), ErrorCode::InvalidArgument);
    // The connection is still healthy after both.
    assert!(matches!(
        adm.call(C::Status(pb::StatusRequest {}), None)
            .await
            .unwrap(),
        R::Status(_)
    ));
}

#[tokio::test]
async fn a_token_command_without_its_secret_frame_is_a_violation() {
    let env = Env::start().await;
    let mut adm = admin(&env).await;
    // The slot count must match the command. hx-ipc's encoder refuses to build such a frame,
    // so the bytes are written by hand: the gateway rejects it and closes the connection.
    let req = pb::Frame {
        frame: Some(pb::frame::Frame::Request(pb::Request {
            request_id: 99,
            deadline_ms: 0,
            secret_slots: vec![],
            command: Some(C::CreatePairingToken(pb::CreatePairingTokenRequest {
                expires_in_s: 300,
            })),
        })),
    };
    let bytes =
        hx_ipc::frame::encode_frame(1, &prost::Message::encode_to_vec(&req), 65_536).unwrap();
    adm.send_raw(&bytes).await.unwrap();
    let Err(err) = adm.read().await else {
        panic!("the connection stayed open");
    };
    assert!(
        err.contains("closed") || err.contains("reset") || err.contains("pipe"),
        "{err}"
    );
    // The gateway is unharmed.
    let mut again = admin(&env).await;
    assert!(matches!(
        again
            .call(C::Status(pb::StatusRequest {}), None)
            .await
            .unwrap(),
        R::Status(_)
    ));
}

#[tokio::test]
async fn the_setup_window_is_mirrored_and_capped_at_24_hours() {
    let env = Env::start().await;
    let mut adm = admin(&env).await;
    let window = |a: pb::SetupWindowAction, s: u32| {
        C::SetupWindow(pb::SetupWindowRequest {
            action: a as i32,
            expires_in_s: s,
        })
    };
    // Extending a closed window is a failed precondition.
    let r = adm
        .call(window(pb::SetupWindowAction::Extend, 600), None)
        .await
        .unwrap();
    assert_eq!(error_code(r), ErrorCode::FailedPrecondition);
    let R::SetupWindow(w) = adm
        .call(window(pb::SetupWindowAction::Open, 7200), None)
        .await
        .unwrap()
    else {
        panic!()
    };
    let opened = w.state.unwrap();
    assert!(opened.open);
    let R::Status(s) = adm
        .call(C::Status(pb::StatusRequest {}), None)
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(s.setup_window.unwrap(), opened);
    // Extending past 24 hours in total is clamped.
    adm.call(window(pb::SetupWindowAction::Extend, 86_400), None)
        .await
        .unwrap();
    let R::SetupWindow(w) = adm
        .call(window(pb::SetupWindowAction::Extend, 86_400), None)
        .await
        .unwrap()
    else {
        panic!()
    };
    let st = w.state.unwrap();
    assert!(
        st.expires_at_unix_s <= opened.expires_at_unix_s - 7200 + 86_400 + 5,
        "{st:?}"
    );
    let R::SetupWindow(w) = adm
        .call(window(pb::SetupWindowAction::Close, 0), None)
        .await
        .unwrap()
    else {
        panic!()
    };
    assert!(!w.state.unwrap().open);
}

#[tokio::test]
async fn close_sessions_closes_every_live_client() {
    let env = Env::start().await;
    let (a, b) = (new_key(), new_key());
    env.pair(&a, "alice").await;
    env.pair(&b, "bob").await;
    env.set_pin(PIN).await;
    let (ca, cb) = (
        env.login(&a, "alice", PIN).await,
        env.login(&b, "bob", PIN).await,
    );
    let mut adm = admin(&env).await;
    let R::CloseSessions(r) = adm
        .call(C::CloseSessions(pb::CloseSessionsRequest {}), None)
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(r.sessions_closed, 2);
    assert_eq!(within(ca.closed()).await.code, CloseCode::Shutdown);
    assert_eq!(within(cb.closed()).await.code, CloseCode::Shutdown);
}

#[tokio::test]
async fn a_request_id_cannot_be_reused_on_a_connection() {
    let env = Env::start().await;
    let mut adm = admin(&env).await;
    adm.call(C::Status(pb::StatusRequest {}), None)
        .await
        .unwrap();
    adm.next_id = 1; // the same id again
    let r = adm
        .call(C::Status(pb::StatusRequest {}), None)
        .await
        .unwrap();
    assert_eq!(error_code(r), ErrorCode::InvalidArgument);
}
