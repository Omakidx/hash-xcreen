//! Hostile peers: text with terminal escapes, bidi controls and forged lines in every reply the
//! CLI prints, a daemon that serves the wrong role, descriptors sent along with a reply, broken
//! framing and silence. The real servers sanitize their own text, so these use stand-ins that
//! do not.

mod cli_common;

use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::net::UnixListener;
use std::sync::Arc;

use cli_common::*;
use hx_ipc::admin::{self as ipc_admin, pb as apb};
use hx_ipc::privd::pb::{self, request::Command, response::Result as R};
use hx_ipc::privd::{self, Side};
use serde_json::Value;

/// Escape sequences that clear the screen and retitle the window, a right-to-left override, a
/// zero-width space and a forged output line.
const EVIL: &str = "evil\x1b[2J\x1b]0;pwned\x07\u{202E}rtl\u{200B}zw\nFORGED: all clear\r";

/// The same with a tag character and a line separator.
const EVIL2: &str = "x\u{2028}y\u{E0041}z\x1b[31mred\u{FEFF}";

fn walk_strings(v: &Value, f: &mut dyn FnMut(&str)) {
    match v {
        Value::String(s) => f(s),
        Value::Array(a) => a.iter().for_each(|x| walk_strings(x, f)),
        Value::Object(m) => m.iter().for_each(|(k, x)| {
            f(k);
            walk_strings(x, f);
        }),
        _ => {}
    }
}

/// Everything the CLI wrote is safe, as text and as JSON, and no forged line exists.
fn assert_clean(r: &Run) {
    assert_terminal_safe(&r.stdout);
    assert_terminal_safe(&r.stderr);
    for l in r.stdout.lines().chain(r.stderr.lines()) {
        assert!(!l.starts_with("FORGED"), "a forged line got through: {l:?}");
    }
    if let Ok(v) = serde_json::from_str::<Value>(r.stdout.trim()) {
        walk_strings(&v, &mut |s| assert_terminal_safe(s));
    }
}

fn hostile_privd_handler() -> PrivdHandler {
    Arc::new(|req, _s| {
        Box::pin(async move {
            let result = match req.command {
                Some(Command::GetHostInfo(_)) => R::GetHostInfo(pb::GetHostInfoResult {
                    privd_version: EVIL.into(),
                    phase: pb::Phase::Ready as i32,
                    os_id: EVIL.into(),
                    os_version: EVIL2.into(),
                    arch: EVIL.into(),
                    cpu_count: 4,
                    pool: Some(pb::PoolInfo {
                        exists: true,
                        driver: EVIL.into(),
                        total_gib: 100,
                        free_gib: 50,
                    }),
                    incus_version: Some(EVIL.into()),
                    ..Default::default()
                }),
                Some(Command::ListDesktops(_)) => R::ListDesktops(pb::ListDesktopsResult {
                    desktops: vec![pb::Desktop {
                        desktop_id: EVIL.into(),
                        state: pb::DesktopState::Running as i32,
                        username: EVIL.into(),
                        distro: pb::Distro::Debian12 as i32,
                        preset: pb::Preset::Basic as i32,
                        ip: EVIL2.into(),
                        session: Some(pb::SessionInfo {
                            installed_version: EVIL.into(),
                            link_provisioned: true,
                        }),
                        ..Default::default()
                    }],
                }),
                _ => privd_error(pb::ErrorCode::Internal, EVIL),
            };
            result.into()
        })
    })
}

fn hostile_admin_handler() -> AdminHandler {
    Arc::new(|req, _s| {
        Box::pin(async move {
            use apb::request::Command as C;
            match req.command {
                Some(C::Status(_)) => apb::response::Result::Status(apb::StatusResult {
                    gatewayd_version: EVIL.into(),
                    listening: true,
                    session_link: apb::LinkState::Up as i32,
                    ..Default::default()
                }),
                Some(C::ListDevices(_)) => {
                    apb::response::Result::ListDevices(apb::ListDevicesResult {
                        devices: vec![
                            apb::Device {
                                device_id: vec![0xaa; 16].into(),
                                name: EVIL.into(),
                                state: apb::DeviceState::Active as i32,
                                ..Default::default()
                            },
                            apb::Device {
                                device_id: vec![
                                    0xaa, 0xaa, 0xbb, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                                ]
                                .into(),
                                name: EVIL2.into(),
                                state: apb::DeviceState::Locked as i32,
                                ..Default::default()
                            },
                        ],
                    })
                }
                Some(C::CreatePairingCode(_)) => {
                    apb::response::Result::CreatePairingCode(apb::CreatePairingCodeResult {
                        code: "AB\x1b[31mCD-EFGH\u{202E}".into(),
                        expires_at_unix_s: 1_900_000_000,
                    })
                }
                _ => admin_error(pb::ErrorCode::Internal, EVIL),
            }
        })
    })
}

async fn hostile_stack() -> (
    tempfile::TempDir,
    hx_agent::cli::Config,
    ScriptedPrivd,
    ScriptedAdmin,
) {
    let dir = private_tempdir();
    let p = ScriptedPrivd::start(
        dir.path(),
        "privd.sock",
        PrivdOptions {
            version: "9.9\x1b[2J".into(),
            ..Default::default()
        },
        hostile_privd_handler(),
    )
    .await;
    let a = ScriptedAdmin::start(
        dir.path(),
        "admin.sock",
        "7.7\x1b[2J\u{202E}",
        hostile_admin_handler(),
    )
    .await;
    let mut cfg = unreachable_config(dir.path());
    cfg.privd_socket = p.path.clone();
    cfg.admin_socket = a.path.clone();
    (dir, cfg, p, a)
}

#[tokio::test]
async fn hostile_status_text_is_scrubbed_in_both_output_forms() {
    let (_d, cfg, _p, _a) = hostile_stack().await;
    let r = cli(&cfg, &["status"], &[], &[]).await;
    assert_eq!(r.code, 0, "{r:?}");
    assert_clean(&r);
    // The harmless parts survive; only the controls are gone.
    assert!(
        r.stdout.contains("evil[2J]0;pwnedrtlzwFORGED: all clear"),
        "{}",
        r.stdout
    );
    let j = cli(&cfg, &["status", "--json"], &[], &[]).await;
    assert_eq!(j.code, 0, "{j:?}");
    assert_clean(&j);
    let v = j.json();
    assert!(
        v["data"]["privd"]["host"]["os_id"]
            .as_str()
            .unwrap()
            .starts_with("evil[2J]0;pwnedrtlzwFORGED"),
    );
}

#[tokio::test]
async fn hostile_device_names_are_scrubbed_and_cannot_forge_lines() {
    let (_d, cfg, _p, _a) = hostile_stack().await;
    let r = cli(&cfg, &["devices", "list"], &[], &[]).await;
    assert_eq!(r.code, 0, "{r:?}");
    assert_clean(&r);
    assert_eq!(
        r.stdout.lines().count(),
        3,
        "a header and two devices, no forged extra line:\n{}",
        r.stdout
    );
    let j = cli(&cfg, &["devices", "list", "--json"], &[], &[]).await;
    assert_clean(&j);
    // The ambiguity message lists names too.
    let r = cli(&cfg, &["devices", "revoke", "aaaa"], &[], &[]).await;
    assert_eq!(r.code, 5, "{r:?}");
    assert_clean(&r);
    assert!(r.stderr.contains("ambiguous"));
    // A name never selects a device: it is not an id.
    let r = cli(&cfg, &["devices", "revoke", "evil"], &[], &[]).await;
    assert_eq!(r.code, 2, "{r:?}");
}

#[tokio::test]
async fn hostile_error_messages_are_scrubbed_and_mapped_to_exit_codes() {
    let (_d, cfg, _p, _a) = hostile_stack().await;
    // privd answers every command but two with INTERNAL carrying hostile text.
    let r = cli(&cfg, &["snapshots", "list"], &[], &[]).await;
    assert_eq!(r.code, 1, "{r:?}");
    assert_clean(&r);
    assert!(r.stderr.contains("INTERNAL"), "{}", r.stderr);
    let j = cli(&cfg, &["snapshots", "list", "--json"], &[], &[]).await;
    assert_clean(&j);
    assert_eq!(j.json()["error"]["code"], "INTERNAL");
    let r = cli(&cfg, &["pairing", "token", "--generate"], &[], &[]).await;
    assert_clean(&r);
    let r = cli(&cfg, &["devices", "reinstate", "aaaaaaaa"], &[], &[]).await;
    assert_clean(&r);
}

#[tokio::test]
async fn a_hostile_pairing_code_is_cleaned_before_it_is_printed() {
    let (_d, cfg, _p, _a) = hostile_stack().await;
    let r = cli(&cfg, &["pairing", "code"], &[], &[]).await;
    assert_eq!(r.code, 0, "{r:?}");
    assert_clean(&r);
    assert!(
        r.stdout.contains("pairing code: AB[31mCD-EFGH"),
        "{}",
        r.stdout
    );
}

#[tokio::test]
async fn hostile_docker_progress_and_container_output_are_scrubbed() {
    let dir = private_tempdir();
    let handler: PrivdHandler = Arc::new(|req, _s| {
        Box::pin(async move {
            match req.command {
                Some(Command::EnableDocker(_)) => PrivdReply {
                    progress: vec![pb::Progress {
                        request_id: 0,
                        stage: pb::ProgressStage::Docker as i32,
                        index: 1,
                        total: 3,
                        step: EVIL.into(),
                        percent: 40,
                        ok: false,
                    }],
                    result: R::EnableDocker(pb::EnableDockerResult {
                        outcome: Some(pb::DockerOutcome {
                            outcome: Some(pb::docker_outcome::Outcome::SelfTestFailed(
                                pb::DockerSelfTestFailed {
                                    isolation_restored: true,
                                    hint: EVIL.into(),
                                    output_tail: format!("{EVIL}{EVIL2}"),
                                    fallbacks: vec![pb::DockerFallback::ZabblyIncus as i32],
                                },
                            )),
                        }),
                    }),
                },
                Some(Command::CheckUpdate(_)) => {
                    PrivdReply::from(R::CheckUpdate(pb::CheckUpdateResult {
                        current: EVIL.into(),
                        available: Some(EVIL2.into()),
                        channel: pb::UpdateChannel::Stable as i32,
                        verified: true,
                        rolled_back: Some(pb::RolledBack {
                            version: EVIL.into(),
                            reason: EVIL.into(),
                        }),
                    }))
                }
                Some(Command::ListSnapshots(_)) => {
                    PrivdReply::from(R::ListSnapshots(pb::ListSnapshotsResult {
                        snapshots: vec![pb::Snapshot {
                            name: EVIL.into(),
                            kind: pb::SnapshotKind::Manual as i32,
                            created_unix_s: 1,
                            size_bytes: 5,
                        }],
                    }))
                }
                _ => privd_error(pb::ErrorCode::Unimplemented, EVIL).into(),
            }
        })
    });
    let p = ScriptedPrivd::start(dir.path(), "privd.sock", PrivdOptions::default(), handler).await;
    let mut cfg = unreachable_config(dir.path());
    cfg.privd_socket = p.path.clone();
    let r = cli(&cfg, &["docker", "enable", "--yes"], &[], &[]).await;
    assert_eq!(r.code, 1, "{r:?}");
    assert_clean(&r);
    assert!(
        r.stderr.contains("[docker] 1/3 40%"),
        "progress goes to stderr: {}",
        r.stderr
    );
    assert!(r.stdout.contains("untrusted"), "{}", r.stdout);
    let j = cli(&cfg, &["docker", "enable", "--yes", "--json"], &[], &[]).await;
    assert_eq!(j.code, 1);
    assert_clean(&j);
    assert!(
        j.stderr.is_empty(),
        "no progress noise in --json mode: {:?}",
        j.stderr
    );
    assert_eq!(j.json()["data"]["outcome"], "SELF_TEST_FAILED");
    for args in [vec!["update", "check"], vec!["snapshots", "list"]] {
        let r = cli(&cfg, &args, &[], &[]).await;
        assert_eq!(r.code, 0, "{args:?}: {r:?}");
        assert_clean(&r);
    }
    let r = cli(&cfg, &["update", "rollback", "--yes"], &[], &[]).await;
    assert_eq!(r.code, 6, "UNIMPLEMENTED maps to 6: {r:?}");
    assert_clean(&r);
}

#[tokio::test]
async fn hostile_log_lines_are_scrubbed_bounded_and_cannot_forge_lines() {
    let dir = private_tempdir();
    let mut cfg = unreachable_config(dir.path());
    let journal = dir.path().join("journal.bin");
    // ESC sequences, a bidi override, invalid UTF-8 (as journald encodes it, an array of
    // bytes), a multi-line message, a 1 MiB entry, plain garbage and a forged identifier.
    let mut bytes = Vec::new();
    let line = |m: &str| journal_entry("hx-privd.service", 7, "hx-privd", m) + "\n";
    bytes.extend_from_slice(line("ok \x1b[2J\x1b]0;pwned\x07 line").as_bytes());
    bytes.extend_from_slice(line("bidi \u{202E}evil").as_bytes());
    bytes.extend_from_slice(line("two\nFORGED: lines\r\nhere").as_bytes());
    bytes.extend_from_slice(
        b"{\"_SYSTEMD_UNIT\":\"hx-privd.service\",\"MESSAGE\":[98,97,100,32,255,254,32,101,110,100]}\n",
    );
    bytes.extend_from_slice(b"\x1b[31mnot json at all\n");
    bytes.extend_from_slice(line(&"x".repeat(1 << 20)).as_bytes());
    bytes.extend_from_slice(line("last").as_bytes());
    std::fs::write(&journal, &bytes).unwrap();
    cfg.journalctl = write_script(
        dir.path(),
        "journalctl",
        &format!("cat '{}'\n", journal.display()),
    );
    write_audit(
        &cfg.audit_log,
        "ts=1 note=\"a\x1b[31mb\u{202E}c\"\nsecond \x1b]0;t\x07\n",
    );
    let r = cli(&cfg, &["logs", "-n", "50"], &[], &[]).await;
    assert_eq!(r.code, 0, "{r:?}");
    assert_clean(&r);
    assert!(r.stdout.contains("ok [2J]0;pwned line"), "{}", r.stdout);
    assert!(r.stdout.contains("two FORGED: lines  here"), "{}", r.stdout);
    assert!(
        r.stdout.contains("bad  end") || r.stdout.contains("bad"),
        "{}",
        r.stdout
    );
    assert!(
        r.stdout.contains("(unreadable journal entry)"),
        "{}",
        r.stdout
    );
    assert!(
        r.stdout.contains("hx-privd.service [7] last"),
        "{}",
        r.stdout
    );
    assert!(
        r.stdout.lines().all(|l| l.len() <= 4096 + 1),
        "lines are bounded"
    );
    let j = cli(&cfg, &["logs", "--json"], &[], &[]).await;
    assert_clean(&j);
    let f = cli(&cfg, &["logs", "--follow", "--journal"], &[], &[]).await;
    assert_clean(&f);
    assert!(
        f.stdout
            .contains("hx-privd.service [7] ok [2J]0;pwned line"),
        "{}",
        f.stdout
    );
}

#[tokio::test]
async fn a_daemon_that_does_not_serve_the_admin_role_is_refused_before_any_command() {
    let dir = private_tempdir();
    let p = ScriptedPrivd::start(
        dir.path(),
        "privd.sock",
        PrivdOptions {
            role: pb::Role::Gateway,
            ..Default::default()
        },
        Arc::new(|_r, _s| Box::pin(async { privd_error(pb::ErrorCode::Internal, "x").into() })),
    )
    .await;
    let mut cfg = unreachable_config(dir.path());
    cfg.privd_socket = p.path.clone();
    let r = cli(&cfg, &["desktop", "stop"], &[], &[]).await;
    assert_eq!(r.code, 1, "{r:?}");
    assert!(r.stderr.contains("admin role"), "{}", r.stderr);
    assert!(p.commands().is_empty(), "no command was sent");
}

#[tokio::test]
async fn a_daemon_of_another_protocol_major_is_refused() {
    // A hand-rolled HelloAck with major 2.
    let dir = private_tempdir();
    let path = dir.path().join("privd.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let t = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut buf = [0u8; 256];
        let _ = s.read(&mut buf);
        let ack = pb::Frame {
            frame: Some(pb::frame::Frame::HelloAck(pb::HelloAck {
                major: 2,
                minor: 0,
                privd_version: "2.0.0".into(),
                phase: pb::Phase::Ready as i32,
                role: pb::Role::Admin as i32,
            })),
        };
        s.write_all(&privd::encode_message(&ack, Side::Client).unwrap())
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));
    });
    let mut cfg = unreachable_config(dir.path());
    cfg.privd_socket = path;
    let r = cli(&cfg, &["desktop", "stop"], &[], &[]).await;
    assert_eq!(r.code, 1, "{r:?}");
    assert!(r.stderr.contains("protocol major 2"), "{}", r.stderr);
    t.join().unwrap();
}

fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

#[tokio::test]
async fn a_descriptor_sent_with_a_reply_is_a_violation_and_installs_nothing() {
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};
    let dir = private_tempdir();
    let path = dir.path().join("admin.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let t = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut buf = [0u8; 256];
        let _ = s.read(&mut buf); // Hello
        let ack = apb::Frame {
            frame: Some(apb::frame::Frame::HelloAck(apb::HelloAck {
                major: 1,
                minor: 0,
                gatewayd_version: "1.0.0".into(),
            })),
        };
        let bytes = ipc_admin::encode_message(&ack, Side::Client).unwrap();
        let null = std::fs::File::open("/dev/null").unwrap();
        let fds = [null.as_fd()];
        let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut cmsg = SendAncillaryBuffer::new(&mut space);
        assert!(cmsg.push(SendAncillaryMessage::ScmRights(&fds)));
        sendmsg(
            &s,
            &[std::io::IoSlice::new(&bytes)],
            &mut cmsg,
            SendFlags::empty(),
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
    });
    let mut cfg = unreachable_config(dir.path());
    cfg.admin_socket = path;
    let before = open_fds();
    let r = cli(&cfg, &["devices", "list"], &[], &[]).await;
    assert_eq!(r.code, 1, "{r:?}");
    assert!(r.stderr.contains("broke the protocol"), "{}", r.stderr);
    t.join().unwrap();
    assert!(
        open_fds() <= before,
        "the kernel installed no descriptor in this process"
    );
}

#[tokio::test]
async fn broken_framing_and_silence_end_the_call_instead_of_hanging() {
    let dir = private_tempdir();
    // 1. A frame length above every limit.
    let path = dir.path().join("privd.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let t = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut buf = [0u8; 256];
        let _ = s.read(&mut buf);
        s.write_all(&[0xff, 0xff, 0xff, 0xff, 1]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));
    });
    let mut cfg = unreachable_config(dir.path());
    cfg.privd_socket = path;
    let started = std::time::Instant::now();
    let r = cli(&cfg, &["snapshots", "list"], &[], &[]).await;
    assert_eq!(r.code, 1, "{r:?}");
    assert!(r.stderr.contains("broke the protocol"), "{}", r.stderr);
    assert!(started.elapsed() < std::time::Duration::from_secs(4));
    t.join().unwrap();
    // 2. A peer that accepts and never speaks: the Hello wait (5 s) ends it as UNAVAILABLE.
    let path2 = dir.path().join("mute.sock");
    let listener = UnixListener::bind(&path2).unwrap();
    let t = std::thread::spawn(move || {
        let (s, _) = listener.accept().unwrap();
        std::thread::sleep(std::time::Duration::from_secs(7));
        drop(s);
    });
    cfg.privd_socket = path2;
    let started = std::time::Instant::now();
    let r = cli(&cfg, &["snapshots", "list"], &[], &[]).await;
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.stderr.contains("timed out"), "{}", r.stderr);
    assert!(started.elapsed() < std::time::Duration::from_secs(7));
    t.join().unwrap();
}

#[tokio::test]
async fn a_missing_socket_is_unavailable_with_a_useful_message() {
    let dir = private_tempdir();
    let cfg = unreachable_config(dir.path());
    let r = cli(&cfg, &["desktop", "stop"], &[], &[]).await;
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.stderr.contains("hx-privd is not running"), "{}", r.stderr);
    let r = cli(&cfg, &["devices", "list", "--json"], &[], &[]).await;
    assert_eq!(r.code, 3);
    assert_eq!(r.json()["error"]["code"], "UNAVAILABLE");
}
