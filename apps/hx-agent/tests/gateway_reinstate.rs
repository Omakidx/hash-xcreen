//! Reinstating a device after a PIN lockout with the account password (protocol 1.3, 11.7):
//! the gateway's `ReinstateGate` (Argon2id here, privd's `PepperVerify(PASSWORD)`), the audit
//! event and the `DeviceEvent`, and the lockout bookkeeping. Real gateway, real privd.

mod gateway_common;

use std::sync::Arc;
use std::time::Duration;

use gateway_common::setup::*;
use gateway_common::{PIN, new_key, recv_until, within};
use hx_crypto::reinstate_client::{ReinstateOptions, ReinstateOutcome, reinstate};
use hx_crypto::setup::Password;
use hx_crypto::{IdentityKey, Pin};
use hx_ipc::admin::pb as apb;
use hx_proto::pb::{self, control_message::Message as Ctl};
use hx_proto::version::ProtocolVersion;

const V13: ProtocolVersion = ProtocolVersion { major: 1, minor: 3 };

fn opts() -> ReinstateOptions {
    ReinstateOptions {
        confirmed_server_version: Some(V13),
        ..Default::default()
    }
}

async fn attempt(e: &SetupEnv, device: &Arc<IdentityKey>, password: &str) -> ReinstateOutcome {
    within(reinstate(
        &e.target(hx_transport::TransportPreference::Quic),
        device,
        e.server_public(),
        &Password::new(password).unwrap(),
        &opts(),
    ))
    .await
    .expect("reinstate")
}

/// Five wrong PINs in a row (the clock moves past each backoff): the device is revoked by the
/// lockout.
async fn lock_out(e: &SetupEnv, device: &Arc<IdentityKey>) {
    let mut a = within(hx_crypto::connect_session(
        &e.target(hx_transport::TransportPreference::Quic),
        device,
        e.server_public(),
        &hx_crypto::SessionOptions::default(),
    ))
    .await
    .expect("connect");
    let wrong = Pin::new("111111").unwrap();
    for _ in 0..5 {
        e.clock.advance(Duration::from_secs(40));
        if within(a.submit(&wrong)).await.is_err() {
            break;
        }
    }
    let rec = e
        .gw()
        .authenticator()
        .registry()
        .get(&device.public().device_id())
        .unwrap()
        .unwrap();
    assert!(rec.is_revoked(), "the fifth wrong PIN revoked the device");
}

async fn env() -> (SetupEnv, Arc<IdentityKey>, Arc<IdentityKey>) {
    let e = SetupEnv::start().await;
    e.make_ready().await;
    let phone = new_key();
    let tablet = new_key();
    e.pair_plain(&phone, "phone").await;
    e.pair_plain(&tablet, "tablet").await;
    e.set_verifiers().await;
    (e, phone, tablet)
}

fn count(e: &SetupEnv, needle: &str) -> usize {
    e.h.audit
        .lines()
        .iter()
        .filter(|l| l.contains(needle))
        .count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_locked_out_device_reinstates_with_the_password_then_logs_in_with_its_pin() {
    capture_logs();
    let (e, phone, tablet) = env().await;
    // The tablet stays logged in to see the notices.
    let watcher = e.login(&tablet, PIN).await.expect("tablet login");
    lock_out(&e, &phone).await;
    assert!(
        e.login(&phone, PIN).await.is_err(),
        "a revoked device cannot log in"
    );
    let revoked_events = count(&e, "DEVICE_REVOKED");
    assert!(revoked_events >= 1);

    // A wrong password first: counted, nothing changes.
    match attempt(&e, &phone, "not the password").await {
        ReinstateOutcome::WrongPassword { attempts_left } => assert!(attempts_left <= 2),
        other => panic!("{other:?}"),
    }
    assert!(e.login(&phone, PIN).await.is_err());

    assert_eq!(
        attempt(&e, &phone, PASSWORD).await,
        ReinstateOutcome::Reinstated
    );
    // No session was authorized by it: the device logs in with its existing PIN.
    let conn = e
        .login(&phone, PIN)
        .await
        .expect("PIN login after reinstating");
    assert!(conn.is_authorized());

    // Audited as DEVICE_REINSTATED with the cause, never the password.
    assert_eq!(count(&e, "DEVICE_REINSTATED"), 1);
    let line =
        e.h.audit
            .lines()
            .into_iter()
            .find(|l| l.contains("DEVICE_REINSTATED"))
            .unwrap();
    assert!(line.contains("password"), "{line}");
    assert!(e.h.audit.lines().iter().all(|l| !l.contains(PASSWORD)));
    // The live session of the other device got `DeviceEvent REINSTATED` for the phone.
    let id = phone.public().device_id();
    let kind = recv_until(&watcher, |c| match c {
        Ctl::DeviceMgmt(d) => match &d.body {
            Some(pb::device_mgmt::Body::Event(ev))
                if ev.kind == pb::DeviceEventKind::Reinstated as i32
                    && ev
                        .device
                        .as_ref()
                        .is_some_and(|i| i.device_id.as_ref() == id.as_bytes()) =>
            {
                Some(ev.kind)
            }
            _ => None,
        },
        _ => None,
    })
    .await;
    assert_eq!(kind, pb::DeviceEventKind::Reinstated as i32);

    // The lockout bookkeeping was reset: locking the device out again is recorded again.
    drop(conn);
    lock_out(&e, &phone).await;
    let mut recorded = false;
    for _ in 0..200 {
        if count(&e, "DEVICE_REVOKED") > revoked_events {
            recorded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        recorded,
        "a second lockout of the same device is audited again"
    );
    assert!(!captured_logs().contains(PASSWORD));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_revoked_by_the_operator_or_another_device_stays_revoked() {
    let (e, phone, tablet) = env().await;
    // The operator revokes the phone.
    let mut a = e.admin().await;
    a.call(
        apb::request::Command::RevokeDevice(apb::RevokeDeviceRequest {
            device_id: phone.public().device_id().as_bytes().to_vec().into(),
        }),
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        attempt(&e, &phone, PASSWORD).await,
        ReinstateOutcome::Refused
    );
    assert!(e.login(&phone, PIN).await.is_err());
    // An unknown key is refused the same way.
    assert_eq!(
        attempt(&e, &new_key(), PASSWORD).await,
        ReinstateOutcome::Refused
    );
    // An active device that is not locked out is refused too.
    assert_eq!(
        attempt(&e, &tablet, PASSWORD).await,
        ReinstateOutcome::Refused
    );
    assert_eq!(count(&e, "DEVICE_REINSTATED"), 0);
    // Only the operator can bring it back.
    a.call(
        apb::request::Command::ReinstateDevice(apb::ReinstateDeviceRequest {
            device_id: phone.public().device_id().as_bytes().to_vec().into(),
        }),
        None,
    )
    .await
    .unwrap();
    assert!(e.login(&phone, PIN).await.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_a_password_verifier_the_server_cannot_check_one() {
    let e = SetupEnv::start().await;
    e.make_ready().await;
    let phone = new_key();
    e.pair_plain(&phone, "phone").await;
    // Only the PIN exists.
    let record = hx_agent::gateway::verifier::enrol(
        e.gw().privd(),
        hx_ipc::privd::pb::LockoutPurpose::Pin,
        PIN.as_bytes(),
        gateway_common::CHEAP,
    )
    .await
    .unwrap();
    e.gw().verifiers().set_pin(None, record).unwrap();
    lock_out(&e, &phone).await;
    assert!(matches!(
        attempt(&e, &phone, PASSWORD).await,
        ReinstateOutcome::NotAvailable { .. }
    ));
    assert_eq!(count(&e, "DEVICE_REINSTATED"), 0);
}

/// Security review F1: after an operator reinstates a locked-out device (not the password
/// path), a second lockout of the same device is audited, announced to the other sessions and
/// closes the device's sessions again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_lockout_after_an_operator_reinstate_is_audited_and_announced() {
    let (e, phone, tablet) = env().await;
    let watcher = e.login(&tablet, PIN).await.expect("tablet login");
    let id = phone.public().device_id();
    let is_revoked_event = |c: &Ctl| match c {
        Ctl::DeviceMgmt(d) => match &d.body {
            Some(pb::device_mgmt::Body::Event(ev))
                if ev.kind == pb::DeviceEventKind::Revoked as i32
                    && ev
                        .device
                        .as_ref()
                        .is_some_and(|i| i.device_id.as_ref() == id.as_bytes()) =>
            {
                Some(())
            }
            _ => None,
        },
        _ => None,
    };

    lock_out(&e, &phone).await;
    recv_until(&watcher, is_revoked_event).await;
    let mut first = 0;
    for _ in 0..200 {
        first = count(&e, "DEVICE_REVOKED");
        if first >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(first, 1, "the first lockout is audited");

    // The operator lifts it (the admin socket's ReinstateDevice calls this).
    e.gw().devices().reinstate(id).await.unwrap().unwrap();
    assert!(e.gw().devices().is_active(&id));
    // The phone signs in again, then is locked out a second time.
    let session = e.login(&phone, PIN).await.expect("phone login");
    drop(session);
    lock_out(&e, &phone).await;
    recv_until(&watcher, is_revoked_event).await;
    let mut second = first;
    for _ in 0..200 {
        second = count(&e, "DEVICE_REVOKED");
        if second > first {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(second, 2, "the second lockout is audited too");
    assert!(e.login(&phone, PIN).await.is_err());
}
