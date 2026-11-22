//! The `hx-gatewayd` binary under its seccomp allowlist and process hardening.
//!
//! * A normal run, with the filter in force, must not be killed: start the real binary, check
//!   in `/proc` that the filter and `no_new_privs` are active and that the process is not
//!   dumpable, then pair, set a PIN, log in over QUIC and WebSocket, list and revoke devices,
//!   write the registry, and shut down gracefully.
//! * The filter must actually bite: a forbidden syscall kills a process that installed it, and
//!   `mode = log` lets it through.
//! * Secrets must not reach the binary's log, even at debug level.

mod gateway_common;

use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use gateway_common::*;
use hx_agent::gateway::privd_client::{PrivdClient, PrivdClientOptions};
use hx_agent::gateway::verifier;
use hx_ipc::admin::pb::{self, request::Command as C, response::Result as R};
use hx_ipc::privd::pb::LockoutPurpose;
use hx_proto::channel::CloseCode;
use hx_proto::pb::{control_message::Message as Ctl, device_mgmt::Body as Mgmt};
use hx_transport::{Target, TransportPreference};
use rustls::pki_types::ServerName;

/// 16 MiB, one pass.
const BIG: hx_crypto::PinParams = hx_crypto::PinParams {
    memory_kib: 16 * 1024,
    iterations: 1,
    parallelism: 1,
};

struct Running {
    child: Child,
    quic: std::net::SocketAddr,
    websocket: std::net::SocketAddr,
    admin: std::path::PathBuf,
    log: std::path::PathBuf,
    _dir: tempfile::TempDir,
    server_key: std::sync::Arc<hx_crypto::IdentityKey>,
    privd: FakePrivd,
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn write_private(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400)).unwrap();
}

async fn start_binary(debug_log: bool) -> Running {
    start_binary_mode(debug_log, None).await
}

async fn start_binary_with(mode: &str) -> Running {
    start_binary_mode(false, Some(mode)).await
}

async fn start_binary_mode(debug_log: bool, mode: Option<&str>) -> Running {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let privd = FakePrivd::start(dir.path());
    let server_key = new_key();
    let identity = dir.path().join("identity");
    write_private(&identity, &*server_key.seed());
    let admin = dir.path().join("admin.sock");
    let config = dir.path().join("gatewayd.toml");
    std::fs::write(
        &config,
        format!(
            "listen = \"127.0.0.1:0\"\n\
             state_dir = \"{}\"\n\
             privd_socket = \"{}\"\n\
             admin_socket = \"{}\"\n\
             identity_credential = \"{}\"\n\
             seccomp = \"{}\"\n\
             argon2_min_memory_kib = 1024\n\
             mlock = false\n",
            state.display(),
            privd.path.display(),
            admin.display(),
            identity.display(),
            mode.map(str::to_owned)
                .or_else(|| std::env::var("HX_TEST_SECCOMP").ok())
                .unwrap_or_else(|| "enforce".into())
        ),
    )
    .unwrap();
    let log = dir.path().join("gatewayd.log");
    // Development aid: HX_TEST_STRACE=<file> runs the binary under `strace -f` to list the
    // syscalls a real run needs (compare with `harden::allowed_names`).
    let mut cmd = match std::env::var("HX_TEST_STRACE") {
        Ok(out) => {
            let mut c = Command::new("strace");
            c.args(["-f", "-qq", "-o", &out, env!("CARGO_BIN_EXE_hx-gatewayd")]);
            c
        }
        Err(_) => Command::new(env!("CARGO_BIN_EXE_hx-gatewayd")),
    };
    cmd.arg("--config")
        .arg(&config)
        .arg("--admin-allow-uid")
        .arg(my_uid().to_string())
        .stdout(Stdio::piped())
        .stderr(std::fs::File::create(&log).unwrap())
        .env_remove("CREDENTIALS_DIRECTORY")
        .env_remove("LISTEN_FDS")
        .env_remove("NOTIFY_SOCKET");
    if debug_log {
        cmd.env("HX_LOG", "debug");
    }
    let mut child = cmd.spawn().expect("spawn hx-gatewayd");
    let stdout = child.stdout.take().unwrap();
    let line = tokio::task::spawn_blocking(move || {
        let mut line = String::new();
        BufReader::new(stdout).read_line(&mut line).map(|_| line)
    });
    let line = match tokio::time::timeout(Duration::from_secs(30), line).await {
        Ok(Ok(Ok(l))) if !l.is_empty() => l,
        other => {
            let _ = child.kill();
            panic!(
                "the gateway did not start ({other:?}); log:\n{}",
                std::fs::read_to_string(&log).unwrap_or_default()
            );
        }
    };
    // "hx-gatewayd listening quic=127.0.0.1:P websocket=127.0.0.1:P"
    let addr = |key: &str| -> std::net::SocketAddr {
        line.split_whitespace()
            .find_map(|w| w.strip_prefix(key))
            .unwrap()
            .parse()
            .unwrap()
    };
    Running {
        quic: addr("quic="),
        websocket: addr("websocket="),
        child,
        admin,
        log,
        _dir: dir,
        server_key,
        privd,
    }
}

fn proc_status(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap()
}

fn target(addr: std::net::SocketAddr) -> Target {
    Target {
        addr,
        server_name: ServerName::try_from("hx.invalid").unwrap(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_binary_runs_a_full_session_under_its_seccomp_allowlist() {
    let mut g = start_binary(false).await;
    let pid = g.child.id();

    if std::env::var("HX_TEST_STRACE").is_err() {
        // The filter, no_new_privs and non-dumpability are in force.
        let status = proc_status(pid);
        assert!(status.contains("Seccomp:\t2"), "{status}");
        assert!(status.contains("Seccomp_filters:\t2"), "{status}");
        assert!(status.contains("NoNewPrivs:\t1"), "{status}");
        // A non-dumpable process's /proc entries belong to root, not to us.
        let owner = std::os::unix::fs::MetadataExt::uid(
            &std::fs::metadata(format!("/proc/{pid}/status")).unwrap(),
        );
        assert_eq!(owner, 0, "PR_SET_DUMPABLE=0");
        let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).unwrap();
        let core = limits
            .lines()
            .find(|l| l.starts_with("Max core file size"))
            .unwrap();
        assert!(core.split_whitespace().rev().nth(1) == Some("0"), "{core}");
    }

    // The admin socket answers (root-only policy replaced by the debug-only uid flag).
    let mut adm = AdminClient::connect(&g.admin).await.expect("admin");
    let R::Status(s) = adm
        .call(C::Status(pb::StatusRequest {}), None)
        .await
        .unwrap()
    else {
        panic!()
    };
    assert!(s.listening);
    // The setup store's atomic write (temporary file, fsync, rename, directory fsync) is inside
    // the allowlist: opening the window writes it, and the process survives.
    let R::SetupWindow(w) = adm
        .call(
            C::SetupWindow(pb::SetupWindowRequest {
                action: pb::SetupWindowAction::Open as i32,
                expires_in_s: 600,
            }),
            None,
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    assert!(w.state.unwrap().open);
    let store = g._dir.path().join("state").join("setup");
    assert!(store.exists(), "the setup store was written under seccomp");
    assert_eq!(
        std::fs::metadata(&store).unwrap().permissions().mode() & 0o777,
        0o600
    );
    // Pair with the code the socket prints, over QUIC.
    let R::CreatePairingCode(code) = adm
        .call(
            C::CreatePairingCode(pb::CreatePairingCodeRequest { expires_in_s: 300 }),
            None,
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    let laptop = new_key();
    within(hx_crypto::pair_device(
        &target(g.quic),
        &laptop,
        &hx_crypto::PairingCredential::parse(&code.code).unwrap(),
        &hx_crypto::PairClientOptions {
            device_name: "laptop".into(),
            ..Default::default()
        },
    ))
    .await
    .expect("pairing under the filter")
    .finish()
    .await;
    // Set a PIN with a real Argon2id allocation (16 MiB: the same mmap and madvise paths as the
    // production 64 MiB, fast enough for an unoptimized test build), the MAC from the fake privd.
    let privd = PrivdClient::new(&g.privd.path, PrivdClientOptions::default());
    let record = verifier::enrol(&privd, LockoutPurpose::Pin, PIN.as_bytes(), BIG)
        .await
        .unwrap();
    let r = adm
        .call(
            C::SetPinVerifier(pb::SetPinVerifierRequest {
                target: Some(pb::set_pin_verifier_request::Target::All(true)),
                verifier: bytes::Bytes::from(record.to_bytes()),
            }),
            None,
        )
        .await
        .unwrap();
    assert!(matches!(r, R::SetPinVerifier(_)), "{r:?}");

    // A wrong PIN, then the right one, over QUIC; then a login over WebSocket.
    let opts = |pref| hx_crypto::SessionOptions {
        preference: pref,
        device_name: "laptop".into(),
        capabilities: hx_proto::version::capabilities(
            &[hx_proto::VideoCodec::H264],
            hx_proto::version::Features::defined_up_to(hx_proto::version::PROTOCOL_MINOR),
        ),
        ..Default::default()
    };
    let mut a = within(hx_crypto::connect_session(
        &target(g.quic),
        &laptop,
        g.server_key.public(),
        &opts(TransportPreference::Quic),
    ))
    .await
    .unwrap();
    let wait = match within(a.submit(&hx_crypto::Pin::new("111111").unwrap()))
        .await
        .unwrap()
    {
        hx_crypto::PinReply::Wrong { retry_after, .. } => retry_after,
        other => panic!("expected a wrong-PIN reply, got {other:?}"),
    };
    // Wait out the server's backoff. Under load the server may start its clock slightly after
    // the reply was sent, so a `Backoff` answer is retried after the wait it names.
    tokio::time::sleep(wait + Duration::from_millis(100)).await;
    let mut accepted = false;
    for _ in 0..5 {
        match within(a.submit(&hx_crypto::Pin::new(PIN).unwrap()))
            .await
            .unwrap()
        {
            hx_crypto::PinReply::Accepted => {
                accepted = true;
                break;
            }
            hx_crypto::PinReply::Backoff { retry_after, .. } => {
                tokio::time::sleep(retry_after + Duration::from_millis(100)).await;
            }
            other => panic!("expected the right PIN to be accepted, got {other:?}"),
        }
    }
    assert!(accepted, "the right PIN was never accepted");
    let conn = a.into_connection().unwrap();
    // Device management over the new messages.
    conn.send_control(&ctl(Ctl::DeviceMgmt(hx_proto::pb::DeviceMgmt {
        request_id: 1,
        body: Some(Mgmt::List(hx_proto::pb::ListDevices {})),
    })))
    .await
    .unwrap();
    let n = recv_until(&conn, |m| match m {
        Ctl::DeviceMgmt(hx_proto::pb::DeviceMgmt {
            body: Some(Mgmt::DeviceList(l)),
            ..
        }) => Some(l.devices.len()),
        _ => None,
    })
    .await;
    assert_eq!(n, 1);
    // The desktop link is the stub: a request to view is answered "desktop unavailable".
    conn.send_control(&view_config()).await.unwrap();
    let message = recv_until(&conn, |m| match m {
        Ctl::Goodbye(g) => Some(g.message.clone()),
        _ => None,
    })
    .await;
    assert_eq!(message, "desktop unavailable");
    drop(conn);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let ws = within(hx_crypto::connect_with_pin(
        &target(g.websocket),
        &laptop,
        g.server_key.public(),
        &hx_crypto::Pin::new(PIN).unwrap(),
        &opts(TransportPreference::WebSocket),
    ))
    .await
    .expect("WebSocket login under the filter");

    // A registry write (revocation: temporary file, fsync, rename) under the filter, closing
    // the live session.
    let id = Env::id_of(&laptop);
    let r = adm
        .call(
            C::RevokeDevice(pb::RevokeDeviceRequest {
                device_id: bytes::Bytes::copy_from_slice(id.as_bytes()),
            }),
            None,
        )
        .await
        .unwrap();
    assert!(matches!(r, R::RevokeDevice(_)), "{r:?}");
    assert_eq!(within(ws.closed()).await.code, CloseCode::Unauthorized);
    // The privd side saw the audit events.
    assert!(
        g.privd
            .wait_for(|s| s.commands.iter().any(|c| c == "RecordEvent"))
            .await
    );

    // Still alive after all of that, and a graceful stop is not a crash.
    assert!(g.child.try_wait().unwrap().is_none(), "the gateway died");
    let kill = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .unwrap();
    assert!(kill.success());
    let exit = tokio::task::spawn_blocking(move || {
        let status = g.child.wait().unwrap();
        (status, std::fs::read_to_string(&g.log).unwrap_or_default())
    })
    .await
    .unwrap();
    assert!(
        exit.0.success(),
        "exit {:?} (signal {:?}); log:\n{}",
        exit.0,
        exit.0.signal(),
        exit.1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn secrets_never_reach_the_binarys_log_even_at_debug_level() {
    let mut g = start_binary(true).await;
    let mut adm = AdminClient::connect(&g.admin).await.expect("admin");
    let R::CreatePairingCode(code) = adm
        .call(
            C::CreatePairingCode(pb::CreatePairingCodeRequest { expires_in_s: 300 }),
            None,
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    let phone = new_key();
    within(hx_crypto::pair_device(
        &target(g.quic),
        &phone,
        &hx_crypto::PairingCredential::parse(&code.code).unwrap(),
        &hx_crypto::PairClientOptions {
            device_name: "ph\u{1b}[31mone\u{202e}".into(),
            software: "evil\u{1b}[2Jsoftware".into(),
            ..Default::default()
        },
    ))
    .await
    .unwrap()
    .finish()
    .await;
    let privd = PrivdClient::new(&g.privd.path, PrivdClientOptions::default());
    let record = verifier::enrol(&privd, LockoutPurpose::Pin, PIN.as_bytes(), BIG)
        .await
        .unwrap();
    let record_text = String::from_utf8(record.to_bytes()).unwrap();
    let mac_hex = record_text.rsplit('$').next().unwrap().to_string();
    adm.call(
        C::SetPinVerifier(pb::SetPinVerifierRequest {
            target: Some(pb::set_pin_verifier_request::Target::All(true)),
            verifier: bytes::Bytes::from(record.to_bytes()),
        }),
        None,
    )
    .await
    .unwrap();
    // A secret token frame, a wrong PIN, a right PIN.
    let token = hx_crypto::PairingToken::generate().unwrap().to_text();
    let _ = adm
        .call(
            C::CreatePairingToken(pb::CreatePairingTokenRequest { expires_in_s: 300 }),
            Some(token.as_bytes()),
        )
        .await
        .unwrap();
    let mut a = within(hx_crypto::connect_session(
        &target(g.quic),
        &phone,
        g.server_key.public(),
        &hx_crypto::SessionOptions::default(),
    ))
    .await
    .unwrap();
    let _ = within(a.submit(&hx_crypto::Pin::new("975310").unwrap()))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let _ = within(a.submit(&hx_crypto::Pin::new(PIN).unwrap()))
        .await
        .unwrap();
    drop(a);
    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(g.child.id().to_string())
        .status();
    let log = tokio::task::spawn_blocking(move || {
        let _ = g.child.wait();
        std::fs::read_to_string(&g.log).unwrap_or_default()
    })
    .await
    .unwrap();
    assert!(!log.is_empty(), "debug logging was on");
    let code_digits: String = code
        .code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    for (what, secret) in [
        ("PIN", PIN),
        ("wrong PIN", "975310"),
        ("pairing code", code.code.as_str()),
        ("pairing code digits", code_digits.as_str()),
        ("token", token.as_str()),
        ("verifier record", record_text.as_str()),
        ("verifier mac", mac_hex.as_str()),
    ] {
        assert!(!log.contains(secret), "{what} is in the log:\n{log}");
    }
    // Peer-supplied text is cleaned before it is logged.
    assert!(
        !log.contains('\u{1b}') && !log.contains('\u{202e}'),
        "raw control characters:\n{log}"
    );
    assert!(
        log.contains("pairing") || log.contains("paired") || log.contains("session"),
        "{log}"
    );
}

// ------------------------------------------------------------------ the filter bites

/// Child mode of the tests below: install the filter, then make one call (`HX_SECCOMP_CALL`).
/// Does nothing unless the parent set the environment.
#[test]
fn seccomp_child_process() {
    let Ok(mode) = std::env::var("HX_SECCOMP_CHILD") else {
        return;
    };
    let dir = std::env::var("HX_SECCOMP_DIR").unwrap();
    let call = std::env::var("HX_SECCOMP_CALL").unwrap_or_else(|_| "mkdir".into());
    let mode = if mode == "log" {
        hx_agent::gateway::config::SeccompMode::Log
    } else {
        hx_agent::gateway::config::SeccompMode::Enforce
    };
    hx_agent::gateway::harden::install_seccomp(mode).expect("install");
    match call.as_str() {
        "mkdir" => std::fs::create_dir(&dir).expect("mkdir"),
        // A new user namespace through clone: no thread flags, a CLONE_NEW* flag.
        "clone_newuser" => {
            let r = unsafe {
                libc::syscall(
                    libc::SYS_clone,
                    (libc::CLONE_NEWUSER | libc::SIGCHLD) as libc::c_long,
                    0,
                    0,
                    0,
                    0,
                )
            };
            println!("clone returned {r}");
        }
        // A fork-style clone.
        "fork" => {
            let r = unsafe {
                libc::syscall(libc::SYS_clone, libc::SIGCHLD as libc::c_long, 0, 0, 0, 0)
            };
            println!("fork returned {r}");
        }
        // clone3 must answer ENOSYS (its flags cannot be filtered).
        "clone3" => {
            let r =
                unsafe { libc::syscall(libc::SYS_clone3, 0 as libc::c_long, 0 as libc::c_long) };
            let errno = std::io::Error::last_os_error().raw_os_error();
            println!("clone3 {r} errno {errno:?} ENOSYS {}", libc::ENOSYS);
        }
        // Setting the dumpable flag back on.
        "prctl_dumpable" => {
            let r = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) };
            println!("prctl returned {r}");
        }
        // A raw socket.
        "socket_raw" => {
            let r = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, 1) };
            println!("socket returned {r}");
        }
        // Ordinary things must still work: a thread, a named thread.
        "thread" => {
            let t = std::thread::Builder::new()
                .name("hx-test".into())
                .spawn(|| 7)
                .expect("spawn");
            assert_eq!(t.join().expect("join"), 7);
        }
        other => panic!("unknown call {other}"),
    }
    println!("SURVIVED");
}

fn run_child_call(mode: &str, call: &str, dir: &Path) -> std::process::Output {
    Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "seccomp_child_process",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("HX_SECCOMP_CHILD", mode)
        .env("HX_SECCOMP_CALL", call)
        .env("HX_SECCOMP_DIR", dir)
        .output()
        .unwrap()
}

fn run_child(mode: &str, dir: &Path) -> std::process::Output {
    run_child_call(mode, "mkdir", dir)
}

/// F6: calls the allowlist must not give a process, each killed by SIGSYS.
#[test]
fn namespace_clone_fork_dumpable_and_raw_sockets_kill_the_process() {
    let tmp = tempfile::tempdir().unwrap();
    for call in ["clone_newuser", "fork", "prctl_dumpable", "socket_raw"] {
        let out = run_child_call("enforce", call, tmp.path());
        assert_eq!(out.status.signal(), Some(libc::SIGSYS), "{call}: {out:?}");
        assert!(
            !String::from_utf8_lossy(&out.stdout).contains("SURVIVED"),
            "{call} survived"
        );
    }
}

/// F6: `clone3` answers ENOSYS (not a kill), so the runtime's fallback to `clone` works.
#[test]
fn clone3_answers_enosys_and_threads_still_work() {
    let tmp = tempfile::tempdir().unwrap();
    let out = run_child_call("enforce", "clone3", tmp.path());
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // libtest prints its own text on the same line as the first line of output.
    let line = stdout
        .lines()
        .find(|l| l.contains("clone3 "))
        .expect("clone3 line");
    assert!(line.contains("-1 errno Some(38)"), "ENOSYS is 38: {line}");
    let out = run_child_call("enforce", "thread", tmp.path());
    assert!(
        out.status.success(),
        "threads and thread names work: {out:?}"
    );
}

#[test]
fn a_syscall_outside_the_allowlist_kills_the_process() {
    let tmp = tempfile::tempdir().unwrap();
    let forbidden = tmp.path().join("made-by-a-filtered-process");
    let out = run_child("enforce", &forbidden);
    assert_eq!(out.status.signal(), Some(libc::SIGSYS), "{out:?}");
    assert!(!forbidden.exists());
}

#[test]
fn log_mode_lets_the_same_call_through() {
    let tmp = tempfile::tempdir().unwrap();
    let made = tmp.path().join("made-in-log-mode");
    let out = run_child("log", &made);
    assert!(out.status.success(), "{out:?}");
    assert!(made.exists());
    assert!(String::from_utf8_lossy(&out.stdout).contains("SURVIVED"));
}

/// N1: `seccomp = "log"` is loud at start, and the unit denies the address ranges the gateway
/// never talks to and caps memory.
#[tokio::test(flavor = "multi_thread")]
async fn log_mode_warns_loudly_at_start() {
    let mut g = start_binary_with("log").await;
    let pid = g.child.id();
    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status();
    let log = tokio::task::spawn_blocking(move || {
        let _ = g.child.wait();
        std::fs::read_to_string(&g.log).unwrap_or_default()
    })
    .await
    .unwrap();
    assert!(log.contains("seccomp is in LOG mode"), "{log}");
    assert!(log.contains("NOT blocked"), "{log}");
}

#[test]
fn the_unit_restricts_addresses_and_memory() {
    let unit = include_str!("../systemd/hx-gatewayd.service");
    let has = |l: &str| unit.lines().any(|x| x.trim() == l);
    assert!(has("IPAddressDeny=localhost link-local multicast"));
    assert!(has("MemoryMax=2G"));
    assert!(has("MemoryHigh=1536M"));
    assert!(has("CapabilityBoundingSet="));
    assert!(has("RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX"));
}
