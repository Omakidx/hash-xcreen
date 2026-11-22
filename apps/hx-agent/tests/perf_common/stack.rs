//! The server side of the end-to-end run, and the orchestration of one profile.
//!
//! The orchestrator runs inside the server namespace (see [`super::net`]) and starts
//!
//! ```text
//! Xvfb + desk (the "terminal", in this process)
//!   <- X11 -- hx-session  (the real binary, link socket handed over as fd 3, like systemd does)
//!   <- unix socket (the Incus proxy device's stand-in) -- hx-gatewayd (the real binary, seccomp
//!   enforce, listening on 10.77.0.1) <- QUIC over the netem veth -- client (own process in the
//!   client namespace)
//! hx-gatewayd -- privd socket --> a fake privd (the pepper and the desktop state; no Incus)
//! ```
//!
//! What is not in it: Incus and a real desktop (the Incus run, `e2e_real_incus`, covers those),
//! and the installer (the installer tests cover it). What is real: both binaries as separate
//! processes, so the CPU of each is its own, the wire protocol, the pairing and the PIN login,
//! the capture, conversion and x264 encode of the session, the relay and the decode.
#![allow(dead_code)]

use std::io::{BufRead, BufReader};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hx_agent::gateway::privd_client::PrivdClient;
use hx_agent::gateway::verifier;
use hx_crypto::PinParams;
use hx_ipc::admin::pb as apb;
use hx_ipc::privd::pb::LockoutPurpose;

use super::client::Params;
use super::desk::{Desk, Geometry};
use super::net::{Net, Profile};
use super::result::{ClientReport, RunResult};
use crate::e2e_common::{Gatewayd, proc_ticks, random_pin};
use crate::gateway_common::{AdminClient, FakePrivd, new_key};

#[path = "../../../../crates/hx-capture/tests/common/mod.rs"]
mod xcommon;
use xcommon::Xvfb;

const BIG: PinParams = PinParams {
    memory_kib: 16 * 1024,
    iterations: 1,
    parallelism: 1,
};

#[derive(Clone, Debug)]
pub struct Opts {
    pub width: u32,
    pub height: u32,
    pub keys: u32,
    pub typing_hz: f64,
    pub scroll_ticks: u32,
    pub scroll_hz: f64,
    pub idle_s: u64,
    pub strict: bool,
}

impl Opts {
    /// 720p, a minute of typing and scrolling compressed to about 20 s of measured activity.
    pub fn from_env(width: u32, height: u32) -> Opts {
        let env = |k: &str, d: f64| {
            std::env::var(k)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(d)
        };
        Opts {
            width,
            height,
            keys: env("HX_PERF_KEYS", 60.0) as u32,
            typing_hz: env("HX_PERF_TYPING_HZ", 12.0),
            scroll_ticks: env("HX_PERF_SCROLL_TICKS", 80.0) as u32,
            scroll_hz: env("HX_PERF_SCROLL_HZ", 20.0),
            idle_s: env("HX_PERF_IDLE_S", 10.0) as u64,
            strict: std::env::var("HX_PERF_STRICT").as_deref() == Ok("1"),
        }
    }
}

struct Session(Child);

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Starts hx-session the way `hx-session.socket` does: the listening socket is fd 3,
/// `LISTEN_PID` is the new process, `LISTEN_FDS` is 1.
fn spawn_session(bin: &Path, sock: &Path, display: &str, received: &Path, log: &Path) -> Session {
    let listener = std::os::unix::net::UnixListener::bind(sock).expect("bind the link socket");
    std::fs::set_permissions(sock, std::fs::Permissions::from_mode(0o600)).unwrap();
    let fd = listener.as_raw_fd();
    // `sh` sets LISTEN_PID to its own pid and execs the daemon, which keeps the pid: the
    // variable then names the process that reads it, as under systemd.
    let mut cmd = Command::new("sh");
    cmd.args(["-c", "LISTEN_PID=$$ exec \"$0\""])
        .arg(bin)
        .env("DISPLAY", display)
        .env("HX_SESSION_RECEIVED_DIR", received)
        .env("LISTEN_FDS", "1")
        .env_remove("XAUTHORITY")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(log).unwrap());
    // SAFETY: only async-signal-safe calls (dup2, fcntl) between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            if fd != 3 && libc::dup2(fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // dup2 clears close-on-exec on the new descriptor; if fd was 3 already, clear it.
            if fd == 3 {
                let flags = libc::fcntl(3, libc::F_GETFD);
                libc::fcntl(3, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
            }
            Ok(())
        });
    }
    let child = cmd.spawn().expect("spawn hx-session");
    drop(listener);
    Session(child)
}

/// Starts the real `hx-gatewayd`, listening on `ip`, and waits for its "listening" line. Like
/// `e2e_common::start_gatewayd` but on the veth address, with the link socket the session owns.
async fn start_gatewayd(
    dir: &Path,
    privd_socket: &Path,
    link_socket: &Path,
    seed: &[u8],
    ip: &str,
) -> Gatewayd {
    let state = dir.join("gw-state");
    let identity = dir.join("gw-identity");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(&identity, seed).unwrap();
    std::fs::set_permissions(&identity, std::fs::Permissions::from_mode(0o400)).unwrap();
    let admin = dir.join("gw-admin.sock");
    let config = dir.join("gatewayd.toml");
    std::fs::write(
        &config,
        format!(
            "listen = \"{ip}:0\"\n\
             server_name = \"hx1h\"\n\
             state_dir = \"{}\"\n\
             privd_socket = \"{}\"\n\
             admin_socket = \"{}\"\n\
             identity_credential = \"{}\"\n\
             seccomp = \"enforce\"\n\
             argon2_min_memory_kib = 1024\n\
             mlock = false\n",
            state.display(),
            privd_socket.display(),
            admin.display(),
            identity.display(),
        ),
    )
    .unwrap();
    let log = dir.join("gatewayd.log");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_hx-gatewayd"));
    cmd.arg("--config")
        .arg(&config)
        .arg("--admin-allow-uid")
        .arg(rustix::process::getuid().as_raw().to_string())
        .arg("--link-socket")
        .arg(link_socket)
        .stdout(Stdio::piped())
        .stderr(std::fs::File::create(&log).unwrap())
        .env_remove("CREDENTIALS_DIRECTORY")
        .env_remove("LISTEN_FDS")
        .env_remove("NOTIFY_SOCKET")
        .env(
            "HX_LOG",
            std::env::var("HX_NETEM_GW_LOG").unwrap_or_else(|_| "info".into()),
        );
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
    let addr = |key: &str| -> std::net::SocketAddr {
        line.split_whitespace()
            .find_map(|w| w.strip_prefix(key))
            .unwrap()
            .parse()
            .unwrap()
    };
    Gatewayd {
        quic: addr("quic="),
        websocket: addr("websocket="),
        child,
        admin,
        log,
    }
}

/// `hx-session`: `HX_NETEM_SESSION_BIN`, else next to the gateway binary (built by the
/// controller before the namespaces are entered).
pub fn session_binary() -> PathBuf {
    if let Some(p) = std::env::var_os("HX_NETEM_SESSION_BIN") {
        return PathBuf::from(p);
    }
    Path::new(env!("CARGO_BIN_EXE_hx-gatewayd")).with_file_name("hx-session")
}

type PhaseLog = Arc<Mutex<Vec<(String, String, Instant, u64, u64)>>>;

fn cores(t0: (Instant, u64), t1: (Instant, u64)) -> f64 {
    (t1.1.saturating_sub(t0.1)) as f64 / 100.0 / t1.0.duration_since(t0.0).as_secs_f64().max(1e-9)
}

/// Runs one profile end to end. Everything the netem control or the flow finds wrong ends up in
/// the result (`evaluate`), not in a panic, so a failed profile still reports its numbers.
#[allow(clippy::too_many_lines)]
pub async fn run_profile(p: &Profile, o: &Opts) -> RunResult {
    let net = Net::create().unwrap_or_else(|e| {
        panic!(
            "cannot build the network namespaces ({e}); the run needs `unshare -rn`, `ip`, `tc`, `nsenter` and `ping` and unprivileged user namespaces"
        )
    });
    let mut result = RunResult {
        profile: p.name.into(),
        rtt_ms: p.rtt_ms,
        resolution: format!("{}x{}", o.width, o.height),
        release_build: !cfg!(debug_assertions),
        cpus: std::thread::available_parallelism().map_or(1, |n| n.get() as u32),
        ..RunResult::default()
    };
    result.loadavg_1m = std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse().ok())
        .unwrap_or(0.0);
    result.noisy = result.loadavg_1m > f64::from(result.cpus) / 2.0;

    // ----- 1. the impairment, measured before anything depends on it ---------------------
    result.control = net.control(p).expect("the netem control");
    for n in &result.control.notes {
        eprintln!("NETEM [{}] {n}", p.name);
    }
    if result.control.notes.iter().any(|n| n.starts_with("FAIL")) {
        eprintln!("NETEM [{}] control failed, not running the flow", p.name);
        return result;
    }

    // ----- 2. the server stack -------------------------------------------------------------
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let xvfb = Xvfb::start(o.width, o.height).expect("Xvfb (HX_REQUIRE_XVFB)");
    let g = Geometry {
        width: o.width,
        height: o.height,
    };
    let dump = dir.path().join("desk.mask");
    let _desk = Desk::start(&xvfb.display, g, dump.clone());
    let received = dir.path().join("received");
    std::fs::create_dir_all(&received).unwrap();
    let link = dir.path().join("l.sock");
    let session = spawn_session(
        &session_binary(),
        &link,
        &xvfb.display,
        &received,
        &dir.path().join("session.log"),
    );
    let privd = FakePrivd::start(dir.path());
    let server_key = new_key();
    let mut gw = start_gatewayd(
        dir.path(),
        &privd.path,
        &link,
        &*server_key.seed(),
        super::net::SERVER_IP,
    )
    .await;
    eprintln!(
        "STACK [{}] hx-gatewayd pid {} on {}, hx-session pid {}, desk on {}",
        p.name,
        gw.pid(),
        gw.quic,
        session.0.id(),
        xvfb.display
    );

    // ----- 3. PIN and pairing code through the admin socket -----------------------------------
    let pin = random_pin();
    let privd_client = PrivdClient::new(&privd.path, Default::default());
    let record = verifier::enrol(&privd_client, LockoutPurpose::Pin, pin.as_bytes(), BIG)
        .await
        .expect("PepperEnrol");
    let mut admin = AdminClient::connect(&gw.admin).await.expect("admin");
    let r = admin
        .call(
            apb::request::Command::SetPinVerifier(apb::SetPinVerifierRequest {
                target: Some(apb::set_pin_verifier_request::Target::All(true)),
                verifier: bytes::Bytes::from(record.to_bytes()),
            }),
            None,
        )
        .await
        .expect("set pin");
    assert!(
        matches!(r, apb::response::Result::SetPinVerifier(_)),
        "{r:?}"
    );
    let apb::response::Result::CreatePairingCode(code) = admin
        .call(
            apb::request::Command::CreatePairingCode(apb::CreatePairingCodeRequest {
                expires_in_s: 600,
            }),
            None,
        )
        .await
        .expect("pairing code")
    else {
        panic!("not a pairing code")
    };

    // ----- 4. the client, in its own namespace ---------------------------------------------
    let patience = u64::from(p.rtt_ms) / 10 + if p.loss_pct > 0.0 { 10 } else { 0 };
    let params = Params {
        quic: gw.quic,
        code: code.code,
        pin,
        dump,
        width: o.width,
        height: o.height,
        keys: o.keys,
        typing_hz: o.typing_hz,
        scroll_ticks: o.scroll_ticks,
        scroll_hz: o.scroll_hz,
        idle_s: o.idle_s,
        patience_s: patience,
    };
    let params_path = dir.path().join("client.json");
    std::fs::write(&params_path, serde_json::to_vec(&params).unwrap()).unwrap();
    std::fs::set_permissions(&params_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut client = net
        .client_command(&std::env::current_exe().unwrap())
        .args([
            "--exact",
            "netem_role_client",
            "--ignored",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env("HX_NETEM_ROLE", "client")
        .env("HX_NETEM_PARAMS", &params_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn the client");
    let stdout = client.stdout.take().unwrap();
    let (gw_pid, sess_pid) = (gw.pid(), session.0.id());
    let log: PhaseLog = Arc::new(Mutex::new(Vec::new()));
    let (log2, report) = (log.clone(), Arc::new(Mutex::new(None::<String>)));
    let report2 = report.clone();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if let Some(rest) = line.find("HXPHASE ").map(|i| &line[i + 8..]) {
                let mut w = rest.split_whitespace();
                let (name, what) = (
                    w.next().unwrap_or("").to_string(),
                    w.next().unwrap_or("").to_string(),
                );
                log2.lock().unwrap().push((
                    name,
                    what,
                    Instant::now(),
                    proc_ticks(sess_pid).unwrap_or(0),
                    proc_ticks(gw_pid).unwrap_or(0),
                ));
            } else if let Some(j) = line.find("HXCLIENT ").map(|i| &line[i + 9..]) {
                *report2.lock().unwrap() = Some(j.to_string());
            }
        }
    });
    // A watchdog: a hung run must not hang CI.
    let deadline = Instant::now() + Duration::from_secs(300 + 6 * patience);
    let status = loop {
        match client.try_wait().unwrap() {
            Some(s) => break Some(s),
            None if Instant::now() > deadline => {
                let _ = client.kill();
                let _ = client.wait();
                break None;
            }
            None => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    };
    let _ = reader.join();
    let mut rep: ClientReport = match report.lock().unwrap().take() {
        Some(j) => serde_json::from_str(&j).expect("the client's report"),
        None => ClientReport {
            errors: vec![format!("the client produced no report (exit {status:?})")],
            ..ClientReport::default()
        },
    };
    if status.is_none() {
        rep.errors.push("the client ran into the watchdog".into());
    }
    // The netem counters after the whole flow: the drops netem made while the stack ran.
    net.read_drops(&mut result.control);

    // CPU over each phase window, from the ticks the reader took at its boundaries.
    {
        let l = log.lock().unwrap();
        let window = |name: &str| {
            let s = l.iter().find(|e| e.0 == name && e.1 == "start")?;
            let e = l.iter().find(|e| e.0 == name && e.1 == "end")?;
            Some((cores((s.2, s.3), (e.2, e.3)), cores((s.2, s.4), (e.2, e.4))))
        };
        for (name, ph) in [
            ("typing", &mut rep.typing),
            ("scroll", &mut rep.scroll),
            ("idle", &mut rep.idle),
        ] {
            match window(name) {
                Some((s, g)) => {
                    ph.session_cores = s;
                    ph.gateway_cores = g;
                }
                None => rep.errors.push(format!("no CPU window for {name}")),
            }
        }
    }
    if !rep.errors.is_empty() || std::env::var_os("HX_NETEM_LOGS").is_some() {
        // The logs hold no secret (the gateway never logs one); show their tails for diagnosis.
        for name in ["gatewayd.log", "session.log"] {
            let text = std::fs::read_to_string(dir.path().join(name)).unwrap_or_default();
            let tail: Vec<&str> = text.lines().rev().take(80).collect();
            eprintln!("LOG [{}] {name} (last lines):", p.name);
            for l in tail.iter().rev() {
                eprintln!("    | {l}");
            }
        }
    }
    // The session and the gateway must still be alive after the flow.
    if !matches!(gw.child.try_wait(), Ok(None)) {
        rep.errors.push("hx-gatewayd died during the run".into());
    }
    result.client = rep;
    result
}
