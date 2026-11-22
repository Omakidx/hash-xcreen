//! Socket activation of the real `hx-gatewayd` binary, the way systemd does it.
//!
//! `hx-gatewayd.service` has `Sockets=hx-gatewayd-admin.socket hx-gatewayd-public.socket`:
//! systemd passes the admin socket (name `admin`) and the public TCP and UDP sockets (both
//! named `public`) with `LISTEN_PID`, `LISTEN_FDS` and `LISTEN_FDNAMES`. These tests hand the
//! binary descriptors 3.. in a chosen order, with the variables set by a small `sh` wrapper
//! (`LISTEN_PID` must be the PID of the process that is exec'd, so the wrapper `exec`s), and
//! check:
//!
//! * the gateway serves QUIC and WebSocket on the handed-over sockets, on an unprivileged
//!   port, with its seccomp filter and `no_new_privs` in force, whatever the order;
//! * the admin socket is found by name, whatever its position;
//! * a public port that differs from `listen` is refused with a clear error;
//! * missing, extra, duplicated, unnamed, foreign or unsuitable descriptors are refused;
//! * the unit files say what the activation relies on.

mod gateway_common;

use std::io::{BufRead, BufReader};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use gateway_common::*;
use hx_ipc::admin::pb::{self, request::Command as C, response::Result as R};
use hx_transport::{Target, TransportPreference};
use rustls::pki_types::ServerName;

/// A descriptor to hand over: its `LISTEN_FDNAMES` name and the socket.
struct Handed {
    name: &'static str,
    fd: OwnedFd,
}

fn handed(name: &'static str, fd: impl Into<OwnedFd>) -> Handed {
    Handed {
        name,
        fd: fd.into(),
    }
}

/// A TCP listener and a UDP socket on one port. IPv6 dual-stack (`[::]`, as the unit's
/// `BindIPv6Only=both`) where the host has IPv6, else IPv4 loopback.
fn public_pair() -> (std::net::TcpListener, std::net::UdpSocket, u16) {
    let host = if std::net::TcpListener::bind("[::1]:0").is_ok() {
        "[::]"
    } else {
        "127.0.0.1"
    };
    for _ in 0..64 {
        let tcp = std::net::TcpListener::bind(format!("{host}:0")).expect("tcp");
        let port = tcp.local_addr().unwrap().port();
        if let Ok(udp) = std::net::UdpSocket::bind(format!("{host}:{port}")) {
            return (tcp, udp, port);
        }
    }
    panic!("no port free for both TCP and UDP");
}

struct Spawned {
    child: Child,
    dir: tempfile::TempDir,
    log: PathBuf,
    admin_path: PathBuf,
    server_key: std::sync::Arc<hx_crypto::IdentityKey>,
    _privd: FakePrivd,
}

impl Drop for Spawned {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Plan {
    /// `listen` in the configuration.
    listen: String,
    fds: Vec<Handed>,
    /// `LISTEN_FDNAMES`, when it is not simply the names of `fds`.
    names: Option<String>,
    /// `LISTEN_PID`, when it is not the process's own.
    pid: Option<String>,
    admin_path: PathBuf,
}

fn spawn(plan: Plan, dir: tempfile::TempDir, privd: FakePrivd) -> Spawned {
    let state = dir.path().join("state");
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let server_key = new_key();
    let identity = dir.path().join("identity");
    std::fs::write(&identity, *server_key.seed()).unwrap();
    std::fs::set_permissions(&identity, std::fs::Permissions::from_mode(0o400)).unwrap();
    let config = dir.path().join("gatewayd.toml");
    // `admin_socket` points at a path nobody listens on: only the descriptor named `admin`
    // can serve the admin connection.
    std::fs::write(
        &config,
        format!(
            "listen = \"{}\"\n\
             state_dir = \"{}\"\n\
             privd_socket = \"{}\"\n\
             admin_socket = \"{}\"\n\
             identity_credential = \"{}\"\n\
             argon2_min_memory_kib = 1024\n\
             mlock = false\n",
            plan.listen,
            state.display(),
            privd.path.display(),
            dir.path().join("never-bound.sock").display(),
            identity.display(),
        ),
    )
    .unwrap();
    let log = dir.path().join("gatewayd.log");
    let names = plan.names.clone().unwrap_or_else(|| {
        plan.fds
            .iter()
            .map(|h| h.name)
            .collect::<Vec<_>>()
            .join(":")
    });
    // Move every descriptor out of the 3.. range first, so that placing one at 3+i can never
    // overwrite another that is still to be placed.
    let high: Vec<OwnedFd> = plan
        .fds
        .iter()
        .map(|h| rustix::io::fcntl_dupfd_cloexec(&h.fd, 200).expect("dup"))
        .collect();
    let raw: Vec<i32> = high.iter().map(AsRawFd::as_raw_fd).collect();
    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        // LISTEN_PID is the PID of the process that is exec'd: this shell's PID.
        .arg("export LISTEN_PID=${HX_TEST_PID:-$$}; exec \"$@\"")
        .arg("sh")
        .arg(env!("CARGO_BIN_EXE_hx-gatewayd"))
        .arg("--config")
        .arg(&config)
        .arg("--admin-allow-uid")
        .arg(my_uid().to_string())
        .stdout(Stdio::piped())
        .stderr(std::fs::File::create(&log).unwrap())
        .env_remove("CREDENTIALS_DIRECTORY")
        .env_remove("LISTEN_FDS_FIRST_FD")
        .env_remove("NOTIFY_SOCKET")
        .env("LISTEN_FDS", plan.fds.len().to_string())
        .env("LISTEN_FDNAMES", names);
    if let Some(pid) = &plan.pid {
        cmd.env("HX_TEST_PID", pid);
    }
    // SAFETY: the closure runs between fork and exec and only calls `dup2`, which is
    // async-signal-safe; it allocates nothing and touches no lock. `raw` is moved in and holds
    // descriptors that stay open in the parent until after `spawn` returns.
    unsafe {
        cmd.pre_exec(move || {
            for (i, &src) in raw.iter().enumerate() {
                if libc::dup2(src, 3 + i as i32) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let child = cmd.spawn().expect("spawn hx-gatewayd");
    drop(high);
    drop(plan.fds);
    Spawned {
        child,
        dir,
        log,
        admin_path: plan.admin_path,
        server_key,
        _privd: privd,
    }
}

impl Spawned {
    /// The first stdout line (`hx-gatewayd listening quic=.. websocket=..`).
    async fn started(&mut self) -> std::net::SocketAddr {
        let stdout = self.child.stdout.take().unwrap();
        let line = tokio::task::spawn_blocking(move || {
            let mut line = String::new();
            BufReader::new(stdout).read_line(&mut line).map(|_| line)
        });
        let line = match tokio::time::timeout(Duration::from_secs(30), line).await {
            Ok(Ok(Ok(l))) if !l.is_empty() => l,
            other => panic!(
                "the gateway did not start ({other:?}); log:\n{}",
                self.log_text()
            ),
        };
        let addr = |key: &str| -> std::net::SocketAddr {
            line.split_whitespace()
                .find_map(|w| w.strip_prefix(key))
                .unwrap_or_else(|| panic!("no {key} in {line:?}"))
                .parse()
                .unwrap()
        };
        let (q, w) = (addr("quic="), addr("websocket="));
        assert_eq!(q.port(), w.port());
        q
    }

    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Waits for the process to end and returns its status and log.
    fn failed(&mut self) -> (std::process::ExitStatus, String) {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return (status, self.log_text());
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the gateway kept running; log:\n{}",
                self.log_text()
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

fn start_plan(
    listen: impl FnOnce(u16) -> String,
    build: impl FnOnce(
        std::net::TcpListener,
        std::net::UdpSocket,
        std::os::unix::net::UnixListener,
    ) -> Vec<Handed>,
    names: Option<&str>,
    pid: Option<&str>,
) -> Spawned {
    let dir = tempfile::tempdir().unwrap();
    let privd = FakePrivd::start(dir.path());
    let (tcp, udp, port) = public_pair();
    let admin_path = dir.path().join("admin.sock");
    let admin = std::os::unix::net::UnixListener::bind(&admin_path).unwrap();
    let plan = Plan {
        listen: listen(port),
        fds: build(tcp, udp, admin),
        names: names.map(str::to_owned),
        pid: pid.map(str::to_owned),
        admin_path,
    };
    spawn(plan, dir, privd)
}

fn target(addr: std::net::SocketAddr) -> Target {
    Target {
        addr,
        server_name: ServerName::try_from("hx.invalid").unwrap(),
    }
}

/// Serves on the handed-over sockets: pairs over QUIC and over WebSocket, using the admin
/// socket that arrived as a descriptor.
async fn assert_serves(g: &mut Spawned) {
    let quic = g.started().await;
    // The sockets may be dual-stack `[::]`: connect over IPv4 loopback either way.
    let v4 = std::net::SocketAddr::from(([127, 0, 0, 1], quic.port()));
    let pid = g.child.id();
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    assert!(status.contains("Seccomp:\t2"), "{status}");
    assert!(status.contains("NoNewPrivs:\t1"), "{status}");

    let mut adm = AdminClient::connect(&g.admin_path).await.expect("admin");
    for (pref, name) in [
        (TransportPreference::Quic, "over quic"),
        (TransportPreference::WebSocket, "over websocket"),
    ] {
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
        let paired = within(hx_crypto::pair_device(
            &target(v4),
            &new_key(),
            &hx_crypto::PairingCredential::parse(&code.code).unwrap(),
            &hx_crypto::PairClientOptions {
                preference: pref,
                device_name: name.into(),
                ..Default::default()
            },
        ))
        .await
        .unwrap_or_else(|e| panic!("pairing {name}: {e}\nlog:\n{}", g.log_text()));
        assert_eq!(paired.server_key, g.server_key.public());
        paired.finish().await;
    }
    let _ = &g.dir;
}

#[tokio::test(flavor = "multi_thread")]
async fn serves_quic_and_websocket_on_handed_over_sockets() {
    // The order a real systemd uses is unspecified: admin first, public (tcp, udp) after.
    let mut g = start_plan(
        |port| format!("127.0.0.1:{port}"),
        |tcp, udp, admin| {
            vec![
                handed("admin", admin),
                handed("public", tcp),
                handed("public", udp),
            ]
        },
        None,
        None,
    );
    assert_serves(&mut g).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_admin_descriptor_is_found_by_name_whatever_the_order() {
    // UDP first, admin in the middle, TCP last: nothing is taken by index.
    let mut g = start_plan(
        |port| format!("[::]:{port}"),
        |tcp, udp, admin| {
            vec![
                handed("public", udp),
                handed("admin", admin),
                handed("public", tcp),
            ]
        },
        None,
        None,
    );
    assert_serves(&mut g).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_admin_socket_alone_still_activates_and_the_gateway_binds_listen() {
    // Admin only (an older unit set): the public port is bound by the gateway as before.
    let dir = tempfile::tempdir().unwrap();
    let privd = FakePrivd::start(dir.path());
    let admin_path = dir.path().join("admin.sock");
    let admin = std::os::unix::net::UnixListener::bind(&admin_path).unwrap();
    let plan = Plan {
        listen: "127.0.0.1:0".into(),
        fds: vec![handed("admin", admin)],
        names: None,
        pid: None,
        admin_path,
    };
    let mut g = spawn(plan, dir, privd);
    let addr = g.started().await;
    assert_ne!(addr.port(), 0);
    let mut adm = AdminClient::connect(&g.admin_path).await.expect("admin");
    let R::Status(s) = adm
        .call(C::Status(pb::StatusRequest {}), None)
        .await
        .unwrap()
    else {
        panic!()
    };
    assert!(s.listening);
}

#[test]
fn a_public_port_that_differs_from_listen_is_refused() {
    let mut g = start_plan(
        |port| format!("[::]:{}", if port == 4433 { 4434 } else { 4433 }),
        |tcp, udp, admin| {
            vec![
                handed("admin", admin),
                handed("public", tcp),
                handed("public", udp),
            ]
        },
        None,
        None,
    );
    let (status, log) = g.failed();
    assert!(!status.success());
    assert!(
        log.contains("listen on port") && log.contains("gatewayd.toml"),
        "{log}"
    );
}

#[test]
fn the_tcp_and_udp_sockets_must_share_a_port() {
    let dir = tempfile::tempdir().unwrap();
    let privd = FakePrivd::start(dir.path());
    let (tcp, _udp, port) = public_pair();
    let other_udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    assert_ne!(other_udp.local_addr().unwrap().port(), port);
    let admin_path = dir.path().join("admin.sock");
    let admin = std::os::unix::net::UnixListener::bind(&admin_path).unwrap();
    let plan = Plan {
        listen: format!("[::]:{port}"),
        fds: vec![
            handed("admin", admin),
            handed("public", tcp),
            handed("public", other_udp),
        ],
        names: None,
        pid: None,
        admin_path,
    };
    let mut g = spawn(plan, dir, privd);
    let (status, log) = g.failed();
    assert!(!status.success());
    assert!(log.contains("the TCP socket is on port"), "{log}");
}

fn refused(
    build: impl FnOnce(
        std::net::TcpListener,
        std::net::UdpSocket,
        std::os::unix::net::UnixListener,
    ) -> Vec<Handed>,
    names: Option<&str>,
    pid: Option<&str>,
    needle: &str,
) {
    let mut g = start_plan(|port| format!("[::]:{port}"), build, names, pid);
    let (status, log) = g.failed();
    assert!(
        !status.success(),
        "started although it must refuse: {needle}"
    );
    assert!(log.contains(needle), "wanted {needle:?} in:\n{log}");
}

#[test]
fn missing_extra_duplicate_and_unnamed_descriptors_are_refused() {
    // One public socket only (TCP without UDP).
    refused(
        |tcp, _udp, admin| vec![handed("admin", admin), handed("public", tcp)],
        None,
        None,
        "exactly one TCP and one UDP",
    );
    // Two TCP listeners and no UDP socket.
    refused(
        |tcp, _udp, admin| {
            let second = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            vec![
                handed("admin", admin),
                handed("public", tcp),
                handed("public", second),
            ]
        },
        None,
        None,
        "exactly one TCP and one UDP",
    );
    // A third public descriptor.
    refused(
        |tcp, udp, admin| {
            let extra = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            vec![
                handed("admin", admin),
                handed("public", tcp),
                handed("public", udp),
                handed("public", extra),
            ]
        },
        None,
        None,
        "exactly one TCP and one UDP",
    );
    // A descriptor of a name the gateway does not use.
    refused(
        |tcp, udp, admin| {
            vec![
                handed("admin", admin),
                handed("public", tcp),
                handed("public", udp),
                handed(
                    "surprise",
                    std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
                ),
            ]
        },
        None,
        None,
        "unexpected descriptor name",
    );
    // Two admin sockets.
    refused(
        |tcp, udp, admin| {
            let second = std::os::unix::net::UnixListener::bind(
                std::env::temp_dir().join(format!("hx-act-{}.sock", std::process::id())),
            )
            .unwrap();
            let _ = std::fs::remove_file(
                std::env::temp_dir().join(format!("hx-act-{}.sock", std::process::id())),
            );
            vec![
                handed("admin", admin),
                handed("admin", second),
                handed("public", tcp),
                handed("public", udp),
            ]
        },
        None,
        None,
        "appears more than once",
    );
    // systemd's default name (the unit's) instead of FileDescriptorName=.
    refused(
        |tcp, udp, admin| {
            vec![
                handed("admin", admin),
                handed("public", tcp),
                handed("public", udp),
            ]
        },
        Some("hx-gatewayd-admin.socket:hx-gatewayd-public.socket:hx-gatewayd-public.socket"),
        None,
        "unexpected descriptor name",
    );
    // Fewer names than descriptors, and no names at all.
    refused(
        |tcp, udp, admin| {
            vec![
                handed("admin", admin),
                handed("public", tcp),
                handed("public", udp),
            ]
        },
        Some("admin:public"),
        None,
        "does not name every descriptor",
    );
}

#[test]
fn a_foreign_or_unsuitable_descriptor_is_refused() {
    // The admin name on a TCP socket.
    refused(
        |tcp, udp, _admin| {
            vec![
                handed("admin", std::net::TcpListener::bind("127.0.0.1:0").unwrap()),
                handed("public", tcp),
                handed("public", udp),
            ]
        },
        None,
        None,
        "\"admin\" descriptor is not a suitable",
    );
    // A UDP socket and a unix socket named public.
    refused(
        |tcp, udp, admin| {
            drop(tcp);
            vec![handed("public", udp), handed("public", admin)]
        },
        None,
        None,
        "\"public\" descriptor is not a suitable",
    );
    // A TCP socket that was bound but never put into listening mode.
    refused(
        |tcp, udp, admin| {
            // Free the port the pair was created on, then bind a socket that never listens.
            drop(tcp);
            let s = rustix::net::socket(
                rustix::net::AddressFamily::INET,
                rustix::net::SocketType::STREAM,
                None,
            )
            .unwrap();
            let port = udp.local_addr().unwrap().port();
            rustix::net::bind(
                &s,
                &std::net::SocketAddrV4::new([127, 0, 0, 1].into(), port),
            )
            .unwrap();
            vec![
                handed("admin", admin),
                handed("public", s),
                handed("public", udp),
            ]
        },
        None,
        None,
        "\"public\" descriptor is not a suitable",
    );
}

#[test]
fn listen_pid_of_another_process_is_refused() {
    refused(
        |tcp, udp, admin| {
            vec![
                handed("admin", admin),
                handed("public", tcp),
                handed("public", udp),
            ]
        },
        None,
        Some("1"),
        "LISTEN_PID is not this process",
    );
}

// ------------------------------------------------------------------ the unit files

fn unit(text: &str) -> impl Fn(&str) -> bool + '_ {
    move |l| text.lines().any(|x| x.trim() == l)
}

#[test]
fn the_public_socket_unit_is_what_the_activation_relies_on() {
    let sock = include_str!("../systemd/hx-gatewayd-public.socket");
    let has = unit(sock);
    assert!(has("ListenStream=[::]:443"));
    assert!(has("ListenDatagram=[::]:443"));
    assert!(has("BindIPv6Only=both"));
    assert!(has("FileDescriptorName=public"));
    assert!(has("Service=hx-gatewayd.service"));
    assert!(has("Accept=no"));
    assert!(has("WantedBy=sockets.target"));
    // The comment tells the installer where the port drop-in goes.
    assert!(sock.contains("hx-gatewayd-public.socket.d/50-port.conf"));
    // Both are listed once: the installer's drop-in resets and replaces them.
    assert_eq!(sock.matches("\nListenStream=").count(), 1);
    assert_eq!(sock.matches("\nListenDatagram=").count(), 1);
}

#[test]
fn the_service_takes_both_sockets_and_stays_unprivileged() {
    let svc = include_str!("../systemd/hx-gatewayd.service");
    let has = unit(svc);
    assert!(has(
        "Sockets=hx-gatewayd-admin.socket hx-gatewayd-public.socket"
    ));
    assert!(has(
        "Requires=hx-gatewayd-admin.socket hx-gatewayd-public.socket"
    ));
    assert!(has(
        "After=hx-gatewayd-admin.socket hx-gatewayd-public.socket"
    ));
    // 443 comes from systemd, not from a capability, a redirect or a sysctl.
    assert!(has("CapabilityBoundingSet="));
    assert!(has("AmbientCapabilities="));
    assert!(has("NoNewPrivileges=yes"));
    assert!(!svc.contains("CAP_NET_BIND_SERVICE"));
    for l in svc.lines().filter(|l| !l.trim_start().starts_with('#')) {
        assert!(!l.contains("ip_unprivileged_port_start"), "{l}");
    }
    assert!(
        !svc.contains("installer maps port 443"),
        "stale comment about a redirect"
    );
    // The admin socket keeps its name.
    let admin = include_str!("../systemd/hx-gatewayd-admin.socket");
    assert!(unit(admin)("FileDescriptorName=admin"));
}

/// N4: activation removes `LISTEN_*` from the environment, which is only sound while the
/// process is single-threaded, so `main` adopts the sockets before it builds the runtime.
#[test]
fn the_binary_adopts_the_sockets_before_it_builds_the_runtime() {
    let bin = include_str!("../src/bin/hx-gatewayd.rs");
    let adopt = bin
        .find("activation::from_process(")
        .expect("adopts the sockets");
    let runtime = bin
        .find("tokio::runtime::Builder")
        .expect("builds a runtime");
    assert!(
        adopt < runtime,
        "from_process must run before the runtime exists"
    );
    let run = bin.find("async fn run(").unwrap();
    let main = bin.find("fn main()").unwrap();
    assert!(
        !bin[run..main].contains("activation::from_process("),
        "no activation inside the async part"
    );
}
