//! The real `hx-backup-worker` binary in its `drive` role, started the way systemd starts it: a
//! listening socket inherited as descriptor 3 with `LISTEN_FDS=1` and `LISTEN_PID` (the test
//! shell sets it to its own pid and `exec`s the binary, which keeps the pid). The test hooks point
//! it at the fake Google and a test CA; nothing reaches a real network.

mod drive_common;

use std::os::fd::AsRawFd;
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use drive_common::*;
use hx_backup_worker::role::{EXIT_LISTEN, EXIT_OK};

/// The binary under test: the one Cargo built, or `HX_WORKER_BIN` (CI runs this file against the
/// static musl build).
fn bin() -> String {
    std::env::var("HX_WORKER_BIN")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_hx-backup-worker").to_owned())
}

fn my_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

struct Helper {
    child: Child,
    sock: PathBuf,
}

fn env_for(cmd: &mut Command, rig: &Rig, idle_ms: u64, peer_uid: u32) {
    let client = rig.dir.path().join("drive-client.json");
    let ca = rig.dir.path().join("ca.pem");
    std::fs::write(&client, client_json()).unwrap();
    std::fs::write(&ca, &rig.fake.cert_pem).unwrap();
    cmd.env("HX_BACKUP_ROLE", "drive")
        .env("HX_WORKER_DRIVE_CLIENT", client)
        .env("HX_WORKER_DRIVE_CA", ca)
        .env("HX_WORKER_DRIVE_API_ADDR", rig.fake.addr.to_string())
        .env("HX_WORKER_DRIVE_PEER_UID", peer_uid.to_string())
        .env("HX_WORKER_DRIVE_IDLE_MS", idle_ms.to_string())
        .env("CREDENTIALS_DIRECTORY", rig.dir.path())
        .stdin(Stdio::null())
        .stderr(Stdio::inherit());
}

/// Starts the binary with a pre-bound listener as descriptor 3.
fn start(rig: &Rig, idle_ms: u64, peer_uid: u32) -> Helper {
    let sock = rig.dir.path().join("activated.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    // a high duplicate, so that the child's dup2 onto 3 is never a no-op that keeps CLOEXEC
    let high = rustix::io::fcntl_dupfd_cloexec(&listener, 10).unwrap();
    let raw = high.as_raw_fd();
    let mut cmd = Command::new("sh");
    cmd.args(["-c", "LISTEN_PID=$$ LISTEN_FDS=1 exec \"$0\"", &bin()]);
    env_for(&mut cmd, rig, idle_ms, peer_uid);
    // SAFETY: the closure only calls `dup2`, which is async-signal-safe.
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(raw, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd.spawn().unwrap();
    drop(high);
    drop(listener); // the child holds its own copy; connections queue in the kernel
    Helper { child, sock }
}

fn wait_exit(child: &mut Child, within: Duration) -> Option<i32> {
    let end = Instant::now() + within;
    while Instant::now() < end {
        if let Some(st) = child.try_wait().unwrap() {
            return st.code();
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

#[test]
fn the_activated_binary_serves_a_session_and_exits_zero_when_idle() {
    let rig = Rig::new();
    let mut h = start(&rig, 1500, my_uid());
    let stream = std::os::unix::net::UnixStream::connect(&h.sock).unwrap();
    let mut env = PrivdEnd::new(stream);
    env.hello();
    assert!(env.software.as_deref().unwrap().starts_with("hx-backup-worker-"));
    env.open("repo", true, SERVER_A, false).ok();
    env.create().ok();
    let config = data(300, 1);
    env.write(T::Config, &[0; 32], &config).ok();
    env.write(T::Pack, &id(0x40), &data(100_000, 2)).ok();
    assert_eq!(env.list(T::Config), Reply::List(vec![(vec![0; 32], 300)]));
    assert_eq!(env.read_full(T::Config, &[0; 32]), Reply::Read(config));
    assert_eq!(env.read_partial(T::Pack, &id(0x40), 10, 20), Reply::Read(data(100_000, 2)[10..30].to_vec()));
    env.remove(T::Pack, &id(0x40)).ok();
    env.quota().ok();
    // it spoke TLS to the fake with the token and nothing else
    rig.fake.with(|m| {
        assert!(m.tokens_issued >= 1);
        assert_eq!(m.bad_refresh_tokens, 0);
        assert_eq!(m.unauthorized, 0);
        assert_eq!(m.count("trash"), 0);
    });
    env.bye();
    drop(env);
    let closed = Instant::now();
    // idle for 1.5 s after the close, then exit 0
    let code = wait_exit(&mut h.child, Duration::from_secs(15));
    assert_eq!(code, Some(EXIT_OK));
    assert!(closed.elapsed() >= Duration::from_millis(1200), "{:?}", closed.elapsed());
}

#[test]
fn a_peer_with_another_uid_is_refused_by_the_binary() {
    let rig = Rig::new();
    let mut h = start(&rig, 800, my_uid() + 1);
    let mut s = std::os::unix::net::UnixStream::connect(&h.sock).unwrap();
    use std::io::{Read, Write};
    let _ = s.write_all(&[0u8; 4]);
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut b = [0u8; 16];
    assert!(matches!(s.read(&mut b), Ok(0) | Err(_)));
    assert_eq!(wait_exit(&mut h.child, Duration::from_secs(10)), Some(EXIT_OK));
    assert_eq!(rig.fake.with(|m| m.log.len()), 0);
}

#[test]
fn without_a_usable_activation_the_binary_exits_71() {
    let rig = Rig::new();
    // no LISTEN_FDS at all
    let mut cmd = Command::new(bin());
    env_for(&mut cmd, &rig, 500, my_uid());
    cmd.env_remove("LISTEN_FDS").env_remove("LISTEN_PID");
    assert_eq!(cmd.status().unwrap().code(), Some(EXIT_LISTEN));
    // LISTEN_PID names another process
    let mut cmd = Command::new(bin());
    env_for(&mut cmd, &rig, 500, my_uid());
    cmd.env("LISTEN_FDS", "1").env("LISTEN_PID", "1");
    assert_eq!(cmd.status().unwrap().code(), Some(EXIT_LISTEN));
    // descriptor 3 is not a listening unix socket (here: a pipe through the shell's own fd 3)
    let mut cmd = Command::new("sh");
    cmd.args(["-c", "LISTEN_PID=$$ LISTEN_FDS=1 exec \"$0\" 3</dev/null", &bin()]);
    env_for(&mut cmd, &rig, 500, my_uid());
    assert_eq!(cmd.status().unwrap().code(), Some(EXIT_LISTEN));
}

#[test]
fn the_binary_without_its_token_still_answers_hello_and_then_auth_revoked() {
    let rig = Rig::new();
    std::fs::remove_file(rig.dir.path().join("drive-token")).unwrap();
    let mut h = start(&rig, 600, my_uid());
    let mut env = PrivdEnd::new(std::os::unix::net::UnixStream::connect(&h.sock).unwrap());
    env.hello();
    assert_eq!(env.open("repo", true, SERVER_A, false).class(), Some(EC::AuthRevoked));
    env.bye();
    drop(env);
    assert_eq!(wait_exit(&mut h.child, Duration::from_secs(10)), Some(EXIT_OK));
    assert_eq!(rig.fake.with(|m| m.log.len()), 0, "no request to Google without a token");
}
