//! The gateway's privd client against a fake privd (docs/ipc.md Part 1): request ids,
//! deadlines, cancel, secret frames, reconnect, role check, descriptor refusal, error mapping.

mod gateway_common;

use std::time::Duration;

use gateway_common::FakePrivd;
use hx_agent::gateway::privd_client::{PrivdClient, PrivdClientOptions, PrivdError};
use hx_ipc::privd::pb::{self, AuditEvent, LockoutPurpose};

fn client(fake: &FakePrivd) -> PrivdClient {
    PrivdClient::new(
        &fake.path,
        PrivdClientOptions {
            margin: Duration::from_millis(150),
            ..Default::default()
        },
    )
}

fn setup() -> (tempfile::TempDir, FakePrivd) {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakePrivd::start(dir.path());
    (dir, fake)
}

#[tokio::test]
async fn verify_answers_only_yes_or_no_and_enrol_is_the_only_mac() {
    let (_d, fake) = setup();
    let c = client(&fake);
    let input = [7u8; 32];
    let enrolled = c.pepper_enrol(LockoutPurpose::Pin, &input).await.unwrap();
    assert_eq!(enrolled.version, 1);
    assert!(
        c.pepper_verify(LockoutPurpose::Pin, &enrolled.mac, &input)
            .await
            .unwrap()
    );
    assert!(
        !c.pepper_verify(LockoutPurpose::Pin, &enrolled.mac, &[8u8; 32])
            .await
            .unwrap()
    );
    // The same MAC under the other purpose's pepper does not verify: the purposes are keyed.
    assert!(
        !c.pepper_verify(LockoutPurpose::Password, &enrolled.mac, &input)
            .await
            .unwrap()
    );
    assert_eq!(
        fake.commands(),
        [
            "PepperEnrol",
            "PepperVerify",
            "PepperVerify",
            "PepperVerify"
        ]
    );
    fake.with(|s| {
        assert_eq!((s.verify_ok, s.verify_fail), (1, 2));
        assert!(s.secret_problem.is_none());
    });
}

#[tokio::test]
async fn secrets_follow_their_request_and_request_ids_are_unique() {
    let (_d, fake) = setup();
    let c = client(&fake);
    for _ in 0..6 {
        c.pepper_verify(LockoutPurpose::Pin, &[0u8; 32], &[1u8; 32])
            .await
            .unwrap();
    }
    fake.with(|s| {
        assert!(s.secret_problem.is_none(), "{:?}", s.secret_problem);
        let mut ids: Vec<_> = s.request_ids.iter().map(|(_, id)| *id).collect();
        assert!(ids.iter().all(|i| *i != 0), "ids are non-zero");
        let n = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), n, "ids are unique");
    });
}

#[tokio::test]
async fn a_restarted_privd_is_reconnected_transparently() {
    let (_d, fake) = setup();
    let c = client(&fake);
    c.pepper_verify(LockoutPurpose::Pin, &[0u8; 32], &[1u8; 32])
        .await
        .unwrap();
    assert_eq!(fake.with(|s| s.connections), 1);
    fake.restart();
    // The idle connection is dead; the next call must still succeed on a new one.
    tokio::time::sleep(Duration::from_millis(100)).await;
    c.pepper_verify(LockoutPurpose::Pin, &[0u8; 32], &[1u8; 32])
        .await
        .unwrap();
    assert_eq!(fake.with(|s| s.connections), 2);
}

#[tokio::test]
async fn privd_down_is_unavailable_and_retryable_then_recovers() {
    let (_d, fake) = setup();
    let c = client(&fake);
    c.ensure_connected().await.unwrap();
    fake.set_down(true);
    let err = c
        .pepper_verify(LockoutPurpose::Pin, &[0u8; 32], &[1u8; 32])
        .await
        .unwrap_err();
    assert!(matches!(err, PrivdError::Unavailable(_)), "{err}");
    assert!(err.is_retryable() && !err.is_locked());
    assert!(c.ensure_connected().await.is_err());
    fake.set_down(false);
    c.ensure_connected().await.unwrap();
    c.pepper_verify(LockoutPurpose::Pin, &[0u8; 32], &[1u8; 32])
        .await
        .unwrap();
}

#[tokio::test]
async fn a_locked_purpose_is_reported_and_is_not_retryable() {
    let (_d, fake) = setup();
    fake.with(|s| s.pin_failure_cap = 2);
    let c = client(&fake);
    for _ in 0..2 {
        assert!(
            !c.pepper_verify(LockoutPurpose::Pin, &[0u8; 32], &[1u8; 32])
                .await
                .unwrap()
        );
    }
    let err = c
        .pepper_verify(LockoutPurpose::Pin, &[0u8; 32], &[1u8; 32])
        .await
        .unwrap_err();
    assert!(err.is_locked(), "{err}");
    assert!(!err.is_retryable());
}

#[tokio::test]
async fn a_slow_call_times_out_and_privd_is_told_to_cancel() {
    let (_d, fake) = setup();
    fake.with(|s| s.verify_delay_ms = 1500);
    let c = client(&fake);
    let started = std::time::Instant::now();
    let err = c
        .call(
            hx_ipc::privd::pb::request::Command::PepperVerify(pb::PepperVerifyRequest {
                purpose: LockoutPurpose::Pin as i32,
                expected_verifier: bytes::Bytes::from(vec![0u8; 32]),
            }),
            &[hx_agent::gateway::privd_client::OutSecret {
                kind: pb::SecretKind::MacInput,
                bytes: &[1u8; 32],
            }],
            Some(Duration::from_millis(200)),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, PrivdError::Timeout), "{err}");
    assert!(started.elapsed() < Duration::from_millis(1200));
    assert!(err.is_retryable());
    // The timed-out connection was dropped (its request is in an unknown state): the next call
    // runs on a new one and works.
    fake.with(|s| s.verify_delay_ms = 0);
    c.pepper_verify(LockoutPurpose::Pin, &[0u8; 32], &[1u8; 32])
        .await
        .unwrap();
    assert_eq!(fake.with(|s| s.connections), 2);
}

#[tokio::test]
async fn a_connection_served_as_admin_is_refused() {
    let (_d, fake) = setup();
    fake.with(|s| s.role = pb::Role::Admin as i32);
    let c = client(&fake);
    let err = c.ensure_connected().await.unwrap_err();
    assert!(matches!(err, PrivdError::Incompatible(_)), "{err}");
    assert!(!err.is_retryable());
}

#[tokio::test]
async fn a_descriptor_sent_by_privd_is_a_violation_never_installed() {
    let (_d, fake) = setup();
    let c = client(&fake);
    c.ensure_connected().await.unwrap();
    fake.with(|s| s.send_fd_with_next_response = true);
    let err = c
        .pepper_verify(LockoutPurpose::Pin, &[0u8; 32], &[1u8; 32])
        .await
        .unwrap_err();
    assert!(matches!(err, PrivdError::Protocol(_)), "{err}");
    assert!(!err.is_retryable());
    // The poisoned connection was dropped; the next call opens a new one.
    c.pepper_verify(LockoutPurpose::Pin, &[0u8; 32], &[1u8; 32])
        .await
        .unwrap();
}

#[tokio::test]
async fn concurrent_calls_share_a_small_pool() {
    let (_d, fake) = setup();
    let c = client(&fake);
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let c = c.clone();
        tasks.push(tokio::spawn(async move {
            c.pepper_verify(LockoutPurpose::Pin, &[0u8; 32], &[1u8; 32])
                .await
                .unwrap();
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    let conns = fake.with(|s| s.connections);
    assert!((1..=2).contains(&conns), "{conns} connections");
}

#[tokio::test]
async fn desktop_commands_and_remote_errors_map_cleanly() {
    let (_d, fake) = setup();
    let c = client(&fake);
    let d = c.get_desktop("main").await.unwrap().unwrap();
    assert_eq!(d.state, pb::DesktopState::Running as i32);
    fake.with(|s| s.desktop_exists = false);
    assert!(c.get_desktop("main").await.unwrap().is_none());
    fake.with(|s| {
        s.desktop_exists = true;
        s.desktop_state = pb::DesktopState::Stopped as i32;
    });
    assert!(c.start_desktop("main").await.unwrap().running);
    assert_eq!(
        c.provision_session_link("main").await.unwrap(),
        "/run/hx/link/main.sock"
    );
    assert_eq!(c.get_host_info().await.unwrap().privd_version, "fake");
    // A command the fake does not implement is a remote UNIMPLEMENTED, and the connection stays
    // usable.
    let err = c
        .call(
            hx_ipc::privd::pb::request::Command::BackupRun(pb::BackupRunRequest {}),
            &[],
            None,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(&err, PrivdError::Remote(e) if e.code == pb::ErrorCode::Unimplemented),
        "{err}"
    );
    c.get_host_info().await.unwrap();
}

#[tokio::test]
async fn audit_labels_are_sanitized_and_bounded() {
    let (_d, fake) = setup();
    let c = client(&fake);
    let evil = format!("phone\u{1b}[31m\u{202e}{}", "x".repeat(200));
    c.record_event(AuditEvent::DeviceRevoked, Some([9u8; 16]), &evil)
        .await
        .unwrap();
    let events = fake.events();
    assert_eq!(events.len(), 1);
    let (ev, id, label) = &events[0];
    assert_eq!(*ev, AuditEvent::DeviceRevoked);
    assert_eq!(id.as_deref(), Some(&[9u8; 16][..]));
    assert!(label.len() <= 64, "{}", label.len());
    assert!(!label.contains('\u{1b}') && !label.contains('\u{202e}'));
}

/// N2: a call whose request was fully sent is never repeated when the connection then breaks:
/// privd may have acted, and a repeated PepperVerify would be charged twice.
#[tokio::test]
async fn a_request_that_was_fully_sent_is_not_retried_when_the_connection_breaks() {
    let (_d, fake) = setup();
    let c = client(&fake);
    c.pepper_verify(LockoutPurpose::Pin, &[0u8; 32], &[1u8; 32])
        .await
        .unwrap();
    fake.with(|s| s.close_after_request = true);
    let err = c
        .pepper_verify(LockoutPurpose::Pin, &[0u8; 32], &[1u8; 32])
        .await
        .unwrap_err();
    assert!(err.is_retryable(), "{err}");
    let verifies = fake
        .commands()
        .iter()
        .filter(|c| *c == "PepperVerify")
        .count();
    assert_eq!(verifies, 2, "the broken call was sent once, not retried");
}
