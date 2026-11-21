//! Regression tests for the findings of the security review of the CLI (one section per
//! finding, named by its number).

mod cli_common;

use std::sync::Arc;

use cli_common::*;
use hx_agent::cli::Config;
use hx_ipc::admin::pb as apb;
use hx_ipc::privd::pb::{self, request::Command, response::Result as R};

fn privd_ok(set_password: Option<&'static str>) -> PrivdHandler {
    Arc::new(move |req, _s| {
        Box::pin(async move {
            match req.command.expect("a command") {
                Command::SetUserPassword(_) => match set_password {
                    Some(m) => privd_error(pb::ErrorCode::Unavailable, m).into(),
                    None => R::SetUserPassword(Default::default()).into(),
                },
                Command::PepperEnrol(_) => R::PepperEnrol(pb::PepperEnrolResult {
                    mac: vec![7u8; 32].into(),
                    version: 1,
                })
                .into(),
                Command::ResetLockout(_) => R::ResetLockout(Default::default()).into(),
                Command::BeginSetup(_) => R::BeginSetup(pb::BeginSetupResult {
                    expires_at_unix_s: 1_900_000_000,
                })
                .into(),
                _ => privd_error(pb::ErrorCode::Unimplemented, "no").into(),
            }
        })
    })
}

fn admin_handler(fail_verifier: bool) -> AdminHandler {
    Arc::new(move |req, _s| {
        Box::pin(async move {
            use apb::request::Command as C;
            use apb::response::Result as A;
            match req.command.expect("a command") {
                C::SetPasswordVerifier(_) if fail_verifier => {
                    admin_error(pb::ErrorCode::Internal, "storing the verifier failed")
                }
                C::SetPasswordVerifier(_) => A::SetPasswordVerifier(Default::default()),
                C::ListDevices(_) => A::ListDevices(apb::ListDevicesResult {
                    devices: vec![apb::Device {
                        device_id: vec![0xaa; 16].into(),
                        name: "laptop".into(),
                        state: apb::DeviceState::Revoked as i32,
                        ..Default::default()
                    }],
                }),
                C::ReinstateDevice(_) => A::ReinstateDevice(Default::default()),
                C::SetupWindow(_) => A::SetupWindow(apb::SetupWindowResult {
                    state: Some(apb::SetupWindowState {
                        open: true,
                        expires_at_unix_s: 1,
                    }),
                }),
                _ => admin_error(pb::ErrorCode::Unimplemented, "no"),
            }
        })
    })
}

struct Stack {
    _dir: tempfile::TempDir,
    cfg: Config,
    p: ScriptedPrivd,
    a: ScriptedAdmin,
}

async fn stack(set_password: Option<&'static str>, fail_verifier: bool) -> Stack {
    let dir = private_tempdir();
    let p = ScriptedPrivd::start(
        dir.path(),
        "p.sock",
        PrivdOptions::default(),
        privd_ok(set_password),
    )
    .await;
    let a = ScriptedAdmin::start(dir.path(), "a.sock", "0.1.0", admin_handler(fail_verifier)).await;
    let mut cfg = unreachable_config(dir.path());
    cfg.privd_socket = p.path.clone();
    cfg.admin_socket = a.path.clone();
    Stack {
        _dir: dir,
        cfg,
        p,
        a,
    }
}

// ----------------------------------------------------------------------------------------- L1

const PW: &[u8] = b"A-perfectly-fine-pass-1";

#[tokio::test]
async fn l1_password_is_not_changed_when_gatewayd_is_unreachable() {
    let mut s = stack(None, false).await;
    s.cfg.admin_socket = s.cfg.admin_socket.with_file_name("missing.sock");
    let r = cli(&s.cfg, &["desktop", "password"], &[PW, PW], &[]).await;
    assert_eq!(r.code, 3, "{r:?}");
    assert!(
        !s.p.commands().contains(&"SetUserPassword"),
        "privd must never see the password change: {:?}",
        s.p.commands()
    );
}

#[tokio::test]
async fn l1_a_failed_verifier_refresh_says_the_old_password_is_still_accepted() {
    let s = stack(None, true).await;
    let r = cli(&s.cfg, &["desktop", "password"], &[PW, PW], &[]).await;
    assert_eq!(r.code, 1, "{r:?}");
    assert!(r.stderr.contains("OLD password"), "{}", r.stderr);
    assert!(r.stderr.contains("still accepts"), "{}", r.stderr);
    assert!(
        !r.stderr.contains("re-pairing by password will fail"),
        "{}",
        r.stderr
    );
    // The order: the verifier was prepared first, the change second, the refresh last.
    assert_eq!(s.p.commands(), ["PepperEnrol", "SetUserPassword"]);
    assert_eq!(s.a.commands(), ["SetPasswordVerifier"]);
}

#[tokio::test]
async fn l1_a_lost_connection_after_the_request_says_the_password_may_have_changed() {
    let s = stack(Some(DROP), false).await;
    // DROP is carried as an Unavailable error message by the handler; the stand-in closes.
    let r = cli(&s.cfg, &["desktop", "password"], &[PW, PW], &[]).await;
    assert_eq!(r.code, 3, "{r:?}");
    assert!(
        r.stderr.contains("MAY ALREADY HAVE CHANGED"),
        "{}",
        r.stderr
    );
    assert!(
        s.a.commands().is_empty(),
        "no verifier is set on an unknown outcome"
    );
}

// ----------------------------------------------------------------------------------------- L2

#[tokio::test]
async fn l2_reinstating_a_revoked_device_needs_a_confirmation() {
    let s = stack(None, false).await;
    let full = "a".repeat(32);
    // No terminal and no --yes: declined, and nothing is sent.
    let r = cli(&s.cfg, &["devices", "reinstate", "aaaa"], &[], &[]).await;
    assert_eq!(r.code, 8, "{r:?}");
    assert!(
        !s.a.commands().contains(&"ReinstateDevice"),
        "{:?}",
        s.a.commands()
    );
    // A wrong answer is a no too; the warning shows the full id and the name.
    let r = cli(&s.cfg, &["devices", "reinstate", "aaaa"], &[], &["y"]).await;
    assert_eq!(r.code, 8, "{r:?}");
    assert!(
        r.stderr.contains(&full) && r.stderr.contains("laptop"),
        "{}",
        r.stderr
    );
    assert!(!s.a.commands().contains(&"ReinstateDevice"));
    // Typed yes, and --yes, both go through.
    let r = cli(&s.cfg, &["devices", "reinstate", "aaaa"], &[], &["yes"]).await;
    assert_eq!(r.code, 0, "{r:?}");
    let r = cli(&s.cfg, &["devices", "reinstate", "aaaa", "--yes"], &[], &[]).await;
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.asked.is_empty());
    assert_eq!(
        s.a.commands()
            .iter()
            .filter(|c| **c == "ReinstateDevice")
            .count(),
        2
    );
    // --yes belongs to reinstate only.
    assert_eq!(
        cli(&s.cfg, &["devices", "revoke", "aaaa", "--yes"], &[], &[])
            .await
            .code,
        2
    );
}

// ----------------------------------------------------------------------------------------- L3

#[tokio::test]
async fn l3_the_journal_line_is_labelled_by_the_trusted_unit_not_the_identifier() {
    let dir = private_tempdir();
    let mut cfg = unreachable_config(dir.path());
    let data = dir.path().join("journal.json");
    // A line from the gateway unit whose sender-controlled identifier claims to be privd.
    std::fs::write(
        &data,
        journal_entry("hx-gatewayd.service", 42, "hx-privd", "pretending") + "\n",
    )
    .unwrap();
    cfg.journalctl = write_script(
        dir.path(),
        "journalctl",
        &format!("cat '{}'\n", data.display()),
    );
    let r = cli(&cfg, &["logs", "--journal"], &[], &[]).await;
    assert_eq!(r.code, 0, "{r:?}");
    assert!(
        r.stdout.contains("hx-gatewayd.service [42] pretending"),
        "{}",
        r.stdout
    );
    assert!(
        !r.stdout
            .lines()
            .any(|l| l.contains("pretending") && l.contains("hx-privd")),
        "the identifier is never shown: {}",
        r.stdout
    );
    let j = cli(&cfg, &["logs", "--journal", "--json"], &[], &[])
        .await
        .json();
    let l = j["data"]["journal"][0].as_str().unwrap();
    assert!(
        l.contains("hx-gatewayd.service") && !l.contains("hx-privd"),
        "{l}"
    );
}
