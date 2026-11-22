//! Server management from the app (protocol 1.3, `ServerMgmt`): a real `Gateway` in front of a
//! real privd daemon on `FakeIncus`, with the real client (`hx_crypto::server_admin`).

mod gateway_common;

use std::sync::Arc;
use std::time::Duration;

use gateway_common::setup::*;
use gateway_common::{PIN, new_key, within};
use hx_crypto::server_admin::ServerAdmin;
use hx_crypto::setup::Password;
use hx_crypto::{IdentityKey, Pin};
use hx_proto::channel::CloseCode;
use hx_proto::pb::{self, ServerStatus as S, control_message::Message as Ctl};

const NEW_PIN: &str = "135790";
const NEW_PASSWORD: &str = "Another-Horse-Battery-7";

async fn env() -> (SetupEnv, Arc<IdentityKey>, Arc<IdentityKey>) {
    let e = SetupEnv::start().await;
    e.make_ready().await;
    e.h.incus
        .add_desktop("hx-main", "ubuntu-24.04-xfce-basic", "alice", true);
    e.h.daemon.register_desktop("main").unwrap();
    let phone = new_key();
    let tablet = new_key();
    e.pair_plain(&phone, "phone").await;
    e.pair_plain(&tablet, "tablet").await;
    e.set_verifiers().await;
    (e, phone, tablet)
}

async fn mgmt(e: &SetupEnv, device: &Arc<IdentityKey>, pin: &str) -> ServerAdmin {
    ServerAdmin::new(e.login(device, pin).await.expect("login")).expect("server management")
}

fn status(r: &pb::ServerResult) -> S {
    S::try_from(r.status).unwrap()
}

fn failed_pins(e: &SetupEnv, d: &Arc<IdentityKey>) -> u32 {
    e.gw()
        .authenticator()
        .registry()
        .get(&d.public().device_id())
        .unwrap()
        .unwrap()
        .failed_pins
}

fn audit(e: &SetupEnv, needle: &str) -> usize {
    e.h.audit
        .lines()
        .iter()
        .filter(|l| l.contains(needle))
        .count()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn pwcheck(e: &SetupEnv, exit: i32) {
    e.h.incus.with(|s| {
        s.exec_rules.insert(
            0,
            hx_agent::privd::testing::ExecRule {
                needle: "hx-pwcheck".into(),
                exit,
                stdout: String::new(),
                delay: Some(Duration::ZERO),
            },
        );
    });
}

fn no_secrets_in_logs() {
    let logs = captured_logs();
    for secret in [PIN, NEW_PIN, PASSWORD, NEW_PASSWORD] {
        assert!(!logs.contains(secret), "a secret reached a log line");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_overview_reports_the_server_the_desktop_and_the_host() {
    let (e, phone, _) = env().await;
    let mut a = mgmt(&e, &phone, PIN).await;
    let o = within(a.overview()).await.unwrap();
    assert_eq!(o.agent_version, env!("CARGO_PKG_VERSION"));
    let d = o.desktop.expect("a desktop");
    assert_eq!(d.state, pb::ServerDesktopState::Running as i32);
    assert_eq!(d.username, "alice");
    assert_eq!(d.distro, pb::SetupDistro::Ubuntu2404 as i32);
    assert_eq!(d.preset, pb::SetupPreset::Basic as i32);
    assert!(o.host.as_ref().is_some_and(|h| h.cpu_count > 0));
    assert!(o.update.is_none(), "no check yet");
    assert!(o.server_time_unix.abs_diff(e.unix_now()) < 5);
    assert!(o.privd_version.len() <= 64);
    // Nothing to report as the attention list of a fresh server.
    assert!(o.host_attention.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_overview_says_none_when_there_is_no_desktop() {
    let e = SetupEnv::start().await;
    e.make_ready().await;
    let phone = new_key();
    e.pair_plain(&phone, "phone").await;
    e.set_verifiers().await;
    let mut a = mgmt(&e, &phone, PIN).await;
    let o = within(a.overview()).await.unwrap();
    assert_eq!(
        o.desktop.unwrap().state,
        pb::ServerDesktopState::None as i32
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn changing_the_pin_checks_the_current_one_stores_the_new_one_and_audits() {
    capture_logs();
    let (e, phone, tablet) = env().await;
    let mut a = mgmt(&e, &phone, PIN).await;
    let r = within(a.change_pin(&Pin::new(PIN).unwrap(), &Pin::new(NEW_PIN).unwrap()))
        .await
        .unwrap();
    assert_eq!(status(&r), S::Ok, "{r:?}");
    drop(a);
    // The new PIN is the PIN of every device; the old one no longer logs in.
    assert!(e.login(&phone, NEW_PIN).await.is_ok());
    assert!(e.login(&tablet, NEW_PIN).await.is_ok());
    assert!(e.login(&tablet, PIN).await.is_err());
    let id = hex(phone.public().device_id().as_bytes());
    let line =
        e.h.audit
            .lines()
            .into_iter()
            .rev()
            .find(|l| l.contains("PIN_CHANGED"))
            .unwrap();
    assert!(line.contains(&id), "{line}");
    assert!(
        e.h.audit
            .lines()
            .iter()
            .all(|l| !l.contains(PIN) && !l.contains(NEW_PIN))
    );
    no_secrets_in_logs();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_current_pin_counts_toward_the_lockout_that_a_login_uses() {
    let (e, phone, _) = env().await;
    let mut a = mgmt(&e, &phone, PIN).await;
    let wrong = Pin::new("111111").unwrap();
    let new = Pin::new(NEW_PIN).unwrap();
    // 1st wrong: counted on the device's counter, 4 left, a wait of 1 s.
    let r = within(a.change_pin(&wrong, &new)).await.unwrap();
    assert_eq!(status(&r), S::WrongPin);
    assert_eq!(r.attempts_left, 4);
    assert_eq!(r.retry_after_s, 1);
    assert_eq!(failed_pins(&e, &phone), 1);
    // Too soon: not checked, not counted.
    let r = within(a.change_pin(&Pin::new(PIN).unwrap(), &new))
        .await
        .unwrap();
    assert_eq!(status(&r), S::Backoff);
    assert_eq!(failed_pins(&e, &phone), 1);
    // The counter is the login's: another wrong one after the wait is the 2nd, and a good PIN
    // login resets it.
    e.clock.advance(Duration::from_secs(2));
    let r = within(a.change_pin(&wrong, &new)).await.unwrap();
    assert_eq!((status(&r), r.attempts_left), (S::WrongPin, 3));
    assert_eq!(failed_pins(&e, &phone), 2);
    let _ = e.login(&phone, PIN).await.unwrap();
    assert_eq!(
        failed_pins(&e, &phone),
        0,
        "a login reset the shared counter"
    );
    // Nothing was changed by any of this: the old PIN still works.
    e.clock.advance(Duration::from_secs(5));
    assert_eq!(audit(&e, "PIN_CHANGED"), 0, "nothing was changed");
    assert!(e.login(&phone, PIN).await.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_fifth_wrong_current_pin_revokes_the_device_and_ends_its_session() {
    let (e, phone, tablet) = env().await;
    let mut a = mgmt(&e, &phone, PIN).await;
    let wrong = Pin::new("111111").unwrap();
    let new = Pin::new(NEW_PIN).unwrap();
    for n in 1..=4u32 {
        e.clock.advance(Duration::from_secs(40));
        let r = within(a.change_pin(&wrong, &new)).await.unwrap();
        assert_eq!((status(&r), r.attempts_left), (S::WrongPin, 5 - n));
    }
    e.clock.advance(Duration::from_secs(40));
    let r = within(a.change_pin(&wrong, &new)).await.unwrap();
    assert_eq!((status(&r), r.attempts_left), (S::WrongPin, 0));
    // The answer came first; then the device is revoked by the lockout (as at login) and its
    // session ends.
    let id = phone.public().device_id();
    let mut revoked = false;
    for _ in 0..200 {
        let rec = e.gw().authenticator().registry().get(&id).unwrap().unwrap();
        if rec.is_revoked() {
            revoked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(revoked, "the lockout revoked the device");
    assert!(e.login(&phone, PIN).await.is_err());
    assert!(
        e.login(&tablet, PIN).await.is_ok(),
        "other devices are untouched"
    );
    let mut recorded = false;
    for _ in 0..200 {
        if audit(&e, "DEVICE_REVOKED") >= 1 {
            recorded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(recorded, "the lockout revocation is audited");
    // And the session was closed: the next request cannot be served.
    assert!(within(a.overview()).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn changing_the_password_checks_the_current_one_in_privd_and_refreshes_the_verifier() {
    capture_logs();
    let (e, phone, _) = env().await;
    let before = e.gw().verifiers().password().unwrap().to_bytes();
    pwcheck(&e, 0);
    let mut a = mgmt(&e, &phone, PIN).await;
    let r = within(a.change_password(
        &Password::new(PASSWORD).unwrap(),
        &Password::new(NEW_PASSWORD).unwrap(),
    ))
    .await
    .unwrap();
    assert_eq!(status(&r), S::Ok, "{r:?}");
    assert!(r.message.is_empty(), "no warning: {r:?}");
    assert!(
        e.h.incus
            .with(|s| s.execs.iter().any(|x| x.contains("chpasswd")))
    );
    assert_ne!(e.gw().verifiers().password().unwrap().to_bytes(), before);
    assert_eq!(audit(&e, "PASSWORD_CHANGED"), 1);
    let id = hex(phone.public().device_id().as_bytes());
    assert!(
        e.h.audit
            .lines()
            .iter()
            .any(|l| l.contains("PASSWORD_CHANGED") && l.contains(&id))
    );
    for needle in [PASSWORD, NEW_PASSWORD] {
        assert!(
            e.h.incus
                .with(|s| s.execs.iter().all(|x| !x.contains(needle)))
        );
        assert!(e.h.audit.lines().iter().all(|l| !l.contains(needle)));
    }
    no_secrets_in_logs();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_current_password_changes_nothing_and_waits() {
    let (e, phone, _) = env().await;
    let before = e.gw().verifiers().password().unwrap().to_bytes();
    pwcheck(&e, 1);
    let mut a = mgmt(&e, &phone, PIN).await;
    let (cur, new) = (
        Password::new("not the password").unwrap(),
        Password::new(NEW_PASSWORD).unwrap(),
    );
    let r = within(a.change_password(&cur, &new)).await.unwrap();
    assert_eq!(status(&r), S::WrongPassword, "{r:?}");
    assert!(!r.message.contains("not the password"));
    assert!(
        e.h.incus
            .with(|s| !s.execs.iter().any(|x| x.contains("chpasswd")))
    );
    assert_eq!(e.gw().verifiers().password().unwrap().to_bytes(), before);
    assert_eq!(audit(&e, "PASSWORD_CHANGED"), 0);
    // Straight away again: held back without asking privd.
    let r = within(a.change_password(&cur, &new)).await.unwrap();
    assert_eq!(status(&r), S::Backoff);
    // privd's PASSWORD budget locks after 5 failures (5 an hour), whatever the device does.
    for _ in 0..6 {
        e.clock.advance(Duration::from_secs(5));
        let r = within(a.change_password(&cur, &new)).await.unwrap();
        if status(&r) == S::Locked {
            assert!(r.retry_after_s >= 1);
            return;
        }
        assert_eq!(status(&r), S::WrongPassword, "{r:?}");
    }
    panic!("privd never locked the password purpose");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_docker_limits_are_mapped_and_audited() {
    let (e, phone, _) = env().await;
    let mut a = mgmt(&e, &phone, PIN).await;

    // Docker on is Admin-only after setup: no privd call, and the command to run.
    let before = e.h.audit.lines().len();
    let r = within(a.set_docker(true)).await.unwrap();
    assert_eq!(status(&r), S::AdminOnly);
    assert_eq!(r.message, "sudo hx-agent docker enable");
    assert_eq!(
        e.h.audit.lines().len(),
        before,
        "nothing was asked of privd"
    );

    // Limits: zero is refused by the gateway, an impossible value by privd.
    let r = within(a.set_limits(pb::SetupLimits {
        cpu: 0,
        memory_mib: 2048,
        disk_gib: 20,
    }))
    .await
    .unwrap();
    assert_eq!(status(&r), S::InvalidArgument);
    let r = within(a.set_limits(pb::SetupLimits {
        cpu: 1000,
        memory_mib: 2048,
        disk_gib: 20,
    }))
    .await
    .unwrap();
    assert_eq!(status(&r), S::InvalidArgument, "{r:?}");
    let r = within(a.set_limits(pb::SetupLimits {
        cpu: 1,
        memory_mib: 2048,
        disk_gib: 20,
    }))
    .await
    .unwrap();
    assert!(
        matches!(status(&r), S::Ok | S::InvalidArgument | S::Failed),
        "{r:?}"
    );

    // Restart goes to privd and is audited with the device.
    e.h.clock.advance_secs(2);
    let r = within(a.restart_desktop(false)).await.unwrap();
    assert_eq!(status(&r), S::Ok, "{r:?}");
    let id = hex(phone.public().device_id().as_bytes());
    assert!(
        e.h.audit
            .lines()
            .iter()
            .any(|l| l.contains("DESKTOP_RESTARTED") && l.contains(&id))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn updates_are_checked_and_applied_under_privds_rules() {
    let (e, phone, _) = env().await;
    let mut a = mgmt(&e, &phone, PIN).await;
    // A version that is not a release version never reaches privd.
    let r = within(a.apply_update("../../etc")).await.unwrap();
    assert_eq!(status(&r), S::InvalidArgument);
    // privd refuses a version it has not fetched and verified; the answer is a status.
    let r = within(a.apply_update("9.9.9")).await.unwrap();
    assert!(
        matches!(
            status(&r),
            S::UpdateRefused | S::Unavailable | S::Failed | S::InvalidArgument
        ),
        "{r:?}"
    );
    assert_eq!(
        audit(&e, "UPDATE_APPLIED"),
        0,
        "a refused update is not audited as applied"
    );
    let r = within(a.check_update()).await.unwrap();
    // The harness has no release host: a status, never a hang or an error.
    assert_ne!(status(&r), S::AdminOnly, "{r:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requests_are_rate_limited_per_device() {
    let (e, phone, tablet) = env().await;
    let mut a = mgmt(&e, &phone, PIN).await;
    for n in 1..=10 {
        let r = within(a.set_docker(true)).await.unwrap();
        assert_eq!(status(&r), S::AdminOnly, "request {n}");
    }
    let r = within(a.set_docker(true)).await.unwrap();
    assert_eq!(status(&r), S::RateLimited);
    assert!(r.retry_after_s >= 1 && r.retry_after_s <= 60);
    // The limit is per device: the tablet is not affected.
    let mut b = mgmt(&e, &tablet, PIN).await;
    assert_eq!(
        status(&within(b.set_docker(true)).await.unwrap()),
        S::AdminOnly
    );
    // A minute later the phone may ask again.
    e.clock.advance(Duration::from_secs(61));
    assert_eq!(
        status(&within(a.set_docker(true)).await.unwrap()),
        S::AdminOnly
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_an_authorized_session_with_the_feature_can_manage_the_server() {
    use hx_proto::version::{Features, PROTOCOL_MINOR, capabilities};
    let e = SetupEnv::start().await;
    e.open_window(7200).await;
    let version = e.pair_app().await;
    let mut s = e.key_only(version).await;
    s.set_pin(&pin()).await.unwrap();
    drop(s);
    // A session that did not offer the feature: the variant is a protocol error.
    let mut raw =
        gateway_common::RawClient::connect(e.gw().quic_addr().unwrap(), &e.app, e.server_public())
            .await;
    let hello = pb::ControlMessage::new(Ctl::Hello(pb::Hello {
        version: Some(pb::Version {
            major: 1,
            minor: PROTOCOL_MINOR,
        }),
        capabilities: Some(capabilities(
            &[hx_proto::VideoCodec::H264],
            Features::defined_up_to(PROTOCOL_MINOR).without(Features::SERVER_MANAGEMENT),
        )),
        intent: pb::Intent::Session as i32,
        software: "raw".into(),
        device_name: "raw".into(),
    }));
    raw.send_ctl(&hello).await;
    let ack = match raw.recv_ctl().await.and_then(|m| m.message) {
        Some(Ctl::HelloAck(a)) => a,
        other => panic!("{other:?}"),
    };
    // The server offers it, and the client did not take it.
    assert_ne!(
        ack.capabilities
            .map_or(0, |c| c.features & Features::SERVER_MANAGEMENT.0),
        0
    );
    assert_eq!(raw.submit_pin(PIN).await, hx_crypto::wire::AuthStatus::Ok);
    raw.send_ctl(&pb::ControlMessage::new(Ctl::ServerMgmt(pb::ServerMgmt {
        request_id: 1,
        body: Some(pb::server_mgmt::Body::GetOverview(pb::ServerGetOverview {})),
    })))
    .await;
    match within(raw.conn.closed()).await {
        quinn::ConnectionError::ApplicationClosed(c) => {
            assert_eq!(
                u64::from(c.error_code),
                u64::from(CloseCode::ProtocolError.code())
            );
        }
        other => panic!("{other:?}"),
    }
}
