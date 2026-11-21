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

// ----------------------------------------------------------------------------------------- L4

#[tokio::test]
async fn l4_a_fifo_at_the_audit_path_is_refused_promptly() {
    let dir = private_tempdir();
    let cfg = unreachable_config(dir.path());
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &cfg.audit_log,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_bits_truncate(0o600),
        0,
    )
    .unwrap();
    let started = std::time::Instant::now();
    let r = cli(&cfg, &["logs", "--audit"], &[], &[]).await;
    assert_eq!(r.code, 1, "{r:?}");
    assert!(r.stderr.contains("regular file"), "{}", r.stderr);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "the open must not hang"
    );
    let r = cli(&cfg, &["logs", "--audit", "--follow"], &[], &[]).await;
    assert_eq!(r.code, 1, "{r:?}");
}

#[tokio::test]
async fn l4_a_symlinked_audit_directory_is_refused() {
    let dir = private_tempdir();
    let real = dir.path().join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::set_permissions(&real, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    write_audit(&real.join("audit.log"), "forged-line\n");
    let link = dir.path().join("hx");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let mut cfg = unreachable_config(dir.path());
    cfg.audit_log = link.join("audit.log");
    let r = cli(&cfg, &["logs", "--audit"], &[], &[]).await;
    assert_eq!(r.code, 1, "{r:?}");
    assert!(
        r.stderr.contains("refusing to read the audit log"),
        "{}",
        r.stderr
    );
    assert!(!r.stdout.contains("forged-line"));
}

// ----------------------------------------------------------------------------------------- L5

/// A writer whose reader has gone away.
struct ClosedPipe;
impl std::io::Write for ClosedPipe {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Runs the CLI with a closed stdout and returns how long it took, or None if it hung.
async fn run_with_closed_stdout(cfg: Config, args: &[&str]) -> Option<(u8, std::time::Duration)> {
    let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    let job = tokio::task::spawn_blocking(move || {
        let started = std::time::Instant::now();
        let mut out = ClosedPipe;
        let mut err = Vec::new();
        let mut prompt = Scripted::new(&[], &[]);
        let mut env = hx_agent::cli::Env {
            config: cfg,
            euid: 0,
            out: &mut out,
            err: &mut err,
            prompt: &mut prompt,
            stop: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            now: hx_agent::cli::system_now,
            json: false,
        };
        let code = hx_agent::cli::run(&args, &mut env);
        (code, started.elapsed())
    });
    tokio::time::timeout(std::time::Duration::from_secs(10), job)
        .await
        .ok()
        .map(|j| j.unwrap())
}

#[tokio::test]
async fn l5_following_stops_on_a_closed_pipe_and_ends_journalctl() {
    let dir = private_tempdir();
    let mut cfg = unreachable_config(dir.path());
    let pidfile = dir.path().join("pid");
    let entry = journal_entry("hx-privd.service", 1, "x", "spam");
    // An endless journal: it only stops when it is killed.
    cfg.journalctl = write_script(
        dir.path(),
        "journalctl",
        &format!(
            "echo $$ > '{}'\nwhile true; do echo '{}'; done\n",
            pidfile.display(),
            entry
        ),
    );
    let (code, took) = run_with_closed_stdout(cfg, &["logs", "--follow", "--journal"])
        .await
        .expect("the CLI must return when its output is closed");
    assert_eq!(code, 0);
    assert!(took < std::time::Duration::from_secs(5), "{took:?}");
    // journalctl was killed, not left running.
    let pid: i32 = std::fs::read_to_string(&pidfile)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let end = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while std::path::Path::new(&format!("/proc/{pid}")).exists()
        && !std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .map(|s| s.contains(") Z"))
            .unwrap_or(true)
    {
        assert!(
            std::time::Instant::now() < end,
            "journalctl (pid {pid}) is still running"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[tokio::test]
async fn l5_plain_output_is_streamed_and_stops_on_a_closed_pipe() {
    let dir = private_tempdir();
    let mut cfg = unreachable_config(dir.path());
    let entry = journal_entry("hx-privd.service", 1, "x", "spam");
    cfg.journalctl = write_script(
        dir.path(),
        "journalctl",
        &format!("while true; do echo '{entry}'; done\n"),
    );
    let (code, took) = run_with_closed_stdout(cfg, &["logs", "--journal", "-n", "10000"])
        .await
        .expect("the CLI must return when its output is closed");
    assert_eq!(code, 0);
    assert!(took < std::time::Duration::from_secs(5), "{took:?}");
}

#[tokio::test]
async fn l5_json_output_is_bounded_by_lines() {
    let dir = private_tempdir();
    let mut cfg = unreachable_config(dir.path());
    let entry = journal_entry("hx-privd.service", 1, "x", "line");
    cfg.journalctl = write_script(
        dir.path(),
        "journalctl",
        &format!("while true; do echo '{entry}'; done\n"),
    );
    let r = cli(
        &cfg,
        &["logs", "--journal", "--json", "-n", "10000"],
        &[],
        &[],
    )
    .await;
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.json()["data"]["journal"].as_array().unwrap().len() <= 20_000);
}

// ----------------------------------------------------------------------------------------- N5

#[tokio::test]
async fn n5_a_rotation_does_not_lose_what_was_appended_to_the_old_file() {
    let dir = private_tempdir();
    let mut cfg = unreachable_config(dir.path());
    // journalctl exists only to keep --follow alive for a while, then ends it.
    cfg.journalctl = write_script(dir.path(), "journalctl", "sleep 2\n");
    write_audit(&cfg.audit_log, "before-1\n");
    let audit = cfg.audit_log.clone();
    let rotator = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        use std::io::Write;
        // Appended to the old file, then (at once) rotated away and replaced.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&audit)
            .unwrap();
        f.write_all(b"old-tail-2\nunterminated-3").unwrap();
        drop(f);
        let rotated = audit.with_extension("log.1");
        std::fs::rename(&audit, &rotated).unwrap();
        write_audit(&audit, "new-1\nnew-2\n");
    });
    let r = cli(&cfg, &["logs", "--follow", "-n", "5"], &[], &[]).await;
    rotator.await.unwrap();
    assert_eq!(r.code, 0, "{r:?}");
    let lines: Vec<&str> = r.stdout.lines().collect();
    let pos = |needle: &str| {
        lines
            .iter()
            .position(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("{needle:?} missing from {}", r.stdout))
    };
    assert!(pos("before-1") < pos("old-tail-2"));
    assert!(pos("old-tail-2") < pos("unterminated-3"));
    assert!(pos("unterminated-3") < pos("new-1"));
    assert!(pos("new-1") < pos("new-2"));
}

// ----------------------------------------------------------------------------------------- L6

#[tokio::test]
async fn l6_usage_errors_never_echo_what_was_typed() {
    let dir = private_tempdir();
    let cfg = unreachable_config(dir.path());
    let secret = "hxt1-SECRETSECRETSECRETSECRETSECRETSECRETSECRETSECRET";
    for args in [
        vec!["pairing", "token", secret],
        vec!["pairing", "code", secret],
        vec!["desktop", "password", secret],
        vec!["pin", "set", secret],
        vec!["pin", "reset-lockout", secret],
        vec!["status", secret],
        vec!["devices", "list", secret],
        vec!["pairing", "token", "--ttl", secret],
        vec!["pairing", secret],
        vec![secret],
        vec!["pairing", "token", "--generate", &format!("--{secret}")],
        vec!["pairing", "token", &format!("-{secret}")],
        vec!["setup", "extend", secret],
        vec!["setup", "begin", "--for", secret],
    ] {
        for json in [false, true] {
            let mut a = args.clone();
            if json {
                a.push("--json");
            }
            let r = cli(&cfg, &a, &[], &[]).await;
            assert_eq!(r.code, 2, "{a:?}: {r:?}");
            assert!(
                !r.stderr.contains("SECRET") && !r.stdout.contains("SECRET"),
                "{a:?}: {r:?}"
            );
        }
    }
}
