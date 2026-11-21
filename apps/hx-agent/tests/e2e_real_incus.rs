//! The first full end-to-end run of hash-xcreen on a **real** Incus: `#[ignore]`d and gated on
//! `HX_E2E_REAL=1`.
//!
//! ```text
//! HX_E2E_REAL=1 sg incus-admin -c 'cargo nextest run -p hx-agent --run-ignored only \
//!     --test e2e_real_incus --no-capture'
//! ```
//!
//! ```text
//! client (hx-crypto + hx-transport) --QUIC / WebSocket--> hx-gatewayd (the real binary, seccomp
//!   enforce) --link socket = Incus proxy device--> hx-session (the real binary, started by
//!   systemd socket activation in the container) --> Xorg + XFCE of a real desktop
//! hx-gatewayd --privd socket--> hx-privd (in-process, real Incus) --> Incus
//! ```
//!
//! What is real: Incus, the `ubuntu-24.04-xfce-basic` recipe built by privd's `CreateDesktop`,
//! the container's systemd units, the proxy device, `hx-session` (the host-built release binary,
//! pushed into the container), the `hx-gatewayd` binary, the client libraries, FFmpeg on both ends.
//!
//! What runs differently from a production host (each is a deviation of the test, not a change of
//! the product; see `docs/spikes/1c-e2e-real-incus.md`):
//!
//! * **Users.** privd runs in-process as your own user with the gateway uid injected through the
//!   `test-support` feature (your uid), `hx-gatewayd` as your user with `--admin-allow-uid`
//!   (`gateway-test-hooks`). The admin role of privd is reached through `Ctx` as in
//!   `privd_real_incus.rs`.
//! * **Firewall.** `SetupHost` runs for real against Incus (pool, bridge, ACL, profiles), but the
//!   host tools go through a stand-in runner: `nft` and `sysctl` report success without running,
//!   `iptables` reports no `DOCKER-USER`. No ruleset is loaded and no host firewall rule changes.
//! * **Packages.** The host runs Docker, which drops forwarded traffic of an Incus bridge. As in the
//!   other real tests an apt proxy is bound only to the test bridge's gateway address and the test
//!   bridge's ACL is detached while packages are installed (`environment.*` instance config added
//!   by a transport shim). The cached image of the distro is used instead of a download.
//! * **The link directory.** `/run/hx/link` needs root; the shim rewrites the proxy device's host
//!   path to a directory the test owns, and the gateway binary is given that socket with the
//!   test-only `--link-socket` flag.
//! * **hx-session.** There is no package yet: the release binary is pushed to
//!   `/usr/lib/hx-session/hx-session`, plus the two FFmpeg runtime packages it links.
//!   `xdotool`, `xclip` and `xinput` are installed for the checks.
//!
//! Everything it creates is named `hx3e-*` and removed again, also before the run. Useful
//! environment variables: `HX_E2E_OUT` (directory for the decoded picture, default
//! `/tmp/hx3e-out`), `HX_E2E_SESSION_BIN` (path of a built `hx-session`), `HX_E2E_REUSE=1` and
//! `HX_E2E_KEEP=1` (development: keep the desktop between runs; the cleanup is then yours).

mod e2e_common;
mod gateway_common;
mod relay_common;

use std::net::SocketAddr;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use e2e_common::*;
use gateway_common::AdminClient;
use hx_agent::gateway::privd_client::PrivdClient;
use hx_agent::gateway::verifier;
use hx_agent::privd::activation::bind_path;
use hx_agent::privd::audit::MemoryAudit;
use hx_agent::privd::clock::SystemClock;
use hx_agent::privd::config::PrivdConfig;
use hx_agent::privd::daemon::{Ctx, Daemon, Deps};
use hx_agent::privd::identity::GatewayIdentity;
use hx_agent::privd::probe::SystemProbe;
use hx_agent::privd::server::{ServeOptions, serve};
use hx_agent::privd::testing::{RawClient, request};
use hx_crypto::{IdentityKey, PairClientOptions, PairingCredential, Pin, PinParams, PublicKey};
use hx_ipc::admin::pb as apb;
use hx_ipc::privd::pb::{self, Role, request::Command, response::Result as R};
use hx_proto::channel::CloseCode;
use hx_proto::pb::{
    ButtonEvent, InputEvent, KeyEvent, MouseButton, control_message::Message as Ctl,
    input_event::Event as In,
};
use hx_provision::Catalog;
use hx_provision::host::Naming;
use hx_provision::incus::{Client, UnixTransport};
use hx_provision::orchestrate::destroy_instance;
use hx_provision::teardown::teardown_host;
use hx_transport::{Connection, Target, TransferKind, TransportPreference};
use relay_common::Client as Stream;
use rustls::pki_types::ServerName;
use sha2::{Digest, Sha256};

macro_rules! evidence {
    ($label:expr, $($arg:tt)*) => {
        eprintln!("EVIDENCE [{}] {}", $label, format!($($arg)*).trim_end().replace('\n', "\n    | "))
    };
}

const BIG: PinParams = PinParams {
    memory_kib: 16 * 1024,
    iterations: 1,
    parallelism: 1,
};

fn naming() -> Naming {
    Naming::with_prefix(PREFIX).unwrap()
}

fn key(sc: u32, pressed: bool) -> InputEvent {
    InputEvent {
        event: Some(In::Key(KeyEvent {
            scancode: sc,
            pressed,
        })),
    }
}

fn click(b: MouseButton, pressed: bool, x: i32, y: i32) -> InputEvent {
    InputEvent {
        event: Some(In::Button(ButtonEvent {
            button: b as i32,
            pressed,
            x,
            y,
        })),
    }
}

fn sha(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

// ----- the stack the client sees --------------------------------------------------------------------------------

struct Stack {
    quic: SocketAddr,
    ws: SocketAddr,
    server: PublicKey,
    admin: PathBuf,
    pin: String,
}

impl Stack {
    fn target(&self, pref: TransportPreference) -> Target {
        Target {
            addr: if pref == TransportPreference::WebSocket {
                self.ws
            } else {
                self.quic
            },
            server_name: ServerName::try_from("hx.invalid").unwrap(),
        }
    }

    async fn admin(&self) -> AdminClient {
        AdminClient::connect(&self.admin).await.expect("admin")
    }

    /// A fresh pairing code from the admin socket.
    async fn code(&self) -> String {
        let apb::response::Result::CreatePairingCode(c) = self
            .admin()
            .await
            .call(
                apb::request::Command::CreatePairingCode(apb::CreatePairingCodeRequest {
                    expires_in_s: 300,
                }),
                None,
            )
            .await
            .expect("code")
        else {
            panic!("not a pairing code")
        };
        c.code
    }

    async fn pair(&self, device: &Arc<IdentityKey>, name: &str, pref: TransportPreference) {
        let cred = PairingCredential::parse(&self.code().await).expect("parse");
        let paired = tokio::time::timeout(
            Duration::from_secs(30),
            hx_crypto::pair_device(
                &self.target(pref),
                device,
                &cred,
                &PairClientOptions {
                    preference: pref,
                    device_name: name.into(),
                    ..Default::default()
                },
            ),
        )
        .await
        .expect("pairing in time")
        .expect("pairing");
        assert_eq!(paired.server_key, self.server, "the pinned server key");
        paired.finish().await;
    }

    fn opts(&self, pref: TransportPreference, name: &str) -> hx_crypto::SessionOptions {
        use hx_proto::VideoCodec;
        use hx_proto::version::{Features, PROTOCOL_MINOR, capabilities};
        hx_crypto::SessionOptions {
            preference: pref,
            device_name: name.into(),
            capabilities: capabilities(
                &[VideoCodec::H264],
                Features::defined_up_to(PROTOCOL_MINOR),
            ),
            ..Default::default()
        }
    }

    async fn login(
        &self,
        device: &Arc<IdentityKey>,
        name: &str,
        pref: TransportPreference,
    ) -> Connection {
        tokio::time::timeout(
            Duration::from_secs(30),
            hx_crypto::connect_with_pin(
                &self.target(pref),
                device,
                self.server,
                &Pin::new(&self.pin).unwrap(),
                &self.opts(pref, name),
            ),
        )
        .await
        .expect("login in time")
        .expect("login")
    }
}

fn new_key() -> Arc<IdentityKey> {
    Arc::new(IdentityKey::generate().expect("key"))
}

// ----- measurement helpers ------------------------------------------------------------------------------------------

struct Window {
    frames: u64,
    key_frames: u64,
    bytes: u64,
    secs: f64,
    decoded: u64,
}

impl Window {
    fn fps(&self) -> f64 {
        self.frames as f64 / self.secs
    }
    fn mbps(&self) -> f64 {
        self.bytes as f64 * 8.0 / self.secs / 1e6
    }
}

/// Counts what arrives in `secs`; feeds every frame to `dec` when given.
async fn measure(
    c: &mut Stream,
    secs: u64,
    mut dec: Option<(&mut Decoder, &mut Option<Decoded>)>,
) -> Window {
    while c.frames.try_recv().is_ok() {}
    let start = Instant::now();
    let end = tokio::time::Instant::now() + Duration::from_secs(secs);
    let mut w = Window {
        frames: 0,
        key_frames: 0,
        bytes: 0,
        secs: 0.0,
        decoded: 0,
    };
    while let Ok(Some(f)) = tokio::time::timeout_at(end, c.frames.recv()).await {
        w.frames += 1;
        w.key_frames += u64::from(f.header.is_key());
        w.bytes += f.payload.len() as u64;
        if let Some((d, last)) = dec.as_mut()
            && let Some(p) = d.decode(&f.payload)
        {
            w.decoded += 1;
            **last = Some(p);
        }
        // `timeout_at` lets a ready future win, so a backlog would never end the window.
        if start.elapsed() >= Duration::from_secs(secs) {
            break;
        }
    }
    w.secs = start.elapsed().as_secs_f64();
    w
}

/// (kind, detail) of the key presses `xinput test-xi2` logged, in order.
fn xi_keys(log: &str) -> Vec<(String, u32)> {
    let mut out = Vec::new();
    let mut kind: Option<String> = None;
    for l in log.lines() {
        if let Some(rest) = l.strip_prefix("EVENT type ") {
            kind = rest
                .split_once('(')
                .map(|(_, k)| k.trim_end_matches(')').to_string());
        } else if let Some(d) = l.trim().strip_prefix("detail:")
            && let Some(k) = kind.take()
            && (k == "KeyPress" || k == "KeyRelease")
            && let Ok(n) = d.trim().parse()
        {
            out.push((k, n));
        }
    }
    out
}

async fn pointer() -> Option<(i32, i32)> {
    let o = exec_user("xdotool getmouselocation").await;
    let t = o.stdout;
    let x = t
        .split("x:")
        .nth(1)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    let y = t
        .split("y:")
        .nth(1)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    Some((x, y))
}

async fn wait_pointer(want: (i32, i32)) -> (i32, i32) {
    let end = Instant::now() + Duration::from_secs(15);
    let mut last = (-1, -1);
    while Instant::now() < end {
        last = pointer().await.unwrap_or(last);
        if last == want {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    last
}

async fn xclip_get() -> Option<String> {
    let o = exec_user("xclip -selection clipboard -o -t UTF8_STRING 2>/dev/null").await;
    (o.code == 0).then_some(o.stdout)
}

async fn screen_size() -> String {
    user_ok("xdpyinfo | awk '/dimensions:/{print $2}'")
        .await
        .trim()
        .to_string()
}

// ----- the test ----------------------------------------------------------------------------------------------------------

async fn cleanup(c: &Client<UnixTransport>) {
    if let Err(e) = hx_provision::teardown::destroy_desktop(c, INSTANCE).await {
        eprintln!("cleanup: destroy_desktop: {e}; forcing");
        let _ = destroy_instance(c, INSTANCE).await;
    }
    match teardown_host(c, &naming()).await {
        Ok(r) => eprintln!("cleanup: {r:?}"),
        Err(e) => eprintln!("cleanup: teardown_host: {e}"),
    }
}

fn dev_mode() -> bool {
    std::env::var("HX_E2E_REUSE").as_deref() == Ok("1")
        || std::env::var("HX_E2E_KEEP").as_deref() == Ok("1")
}

fn work_dir() -> PathBuf {
    if dev_mode() {
        PathBuf::from("/tmp/hx3e-dev")
    } else {
        PathBuf::from(format!("/tmp/hx3e-{}", std::process::id()))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "needs a real Incus (sg incus-admin) and HX_E2E_REAL=1; builds a desktop (many minutes)"]
async fn the_whole_stack_streams_a_real_desktop() {
    if std::env::var("HX_E2E_REAL").as_deref() != Ok("1") {
        eprintln!("HX_E2E_REAL is not 1: skipping");
        return;
    }
    let c = Client::unix(socket());
    let keep = std::env::var("HX_E2E_KEEP").as_deref() == Ok("1");
    if std::env::var("HX_E2E_REUSE").as_deref() != Ok("1") {
        cleanup(&c).await;
    }
    let body = tokio::spawn(run_real(c.clone()));
    let result = body.await;
    if keep {
        eprintln!(
            "HX_E2E_KEEP=1: leaving the hx3e-* objects and {} in place",
            work_dir().display()
        );
    } else {
        cleanup(&c).await;
        let _ = std::fs::remove_dir_all(work_dir());
        let n = naming();
        assert!(c.get_instance(INSTANCE).await.unwrap().is_none());
        assert!(c.get_storage_pool(&n.pool).await.unwrap().is_none());
        assert!(c.get_network(&n.bridge).await.unwrap().is_none());
        assert!(!c.acl_exists(&n.acl).await.unwrap());
        assert!(!c.profile_exists(&n.desktop_profile).await.unwrap());
        assert!(!c.profile_exists(&n.compat_profile).await.unwrap());
        evidence!("cleanup", "no hx3e- object remains");
    }
    print_rows();
    if let Err(e) = result {
        std::panic::resume_unwind(e.into_panic());
    }
}

/// Revokes `device` through the admin socket while `s` streams: the connection must close with
/// `Unauthorized`, no frame may follow, and the device must not get back in.
async fn revoke_mid_stream(
    stack: &Stack,
    device: &Arc<IdentityKey>,
    name: &str,
    pref: TransportPreference,
    mut s: Stream,
) {
    let id = device.public().device_id();
    let r = stack
        .admin()
        .await
        .call(
            apb::request::Command::RevokeDevice(apb::RevokeDeviceRequest {
                device_id: bytes::Bytes::copy_from_slice(id.as_bytes()),
            }),
            None,
        )
        .await
        .unwrap();
    let apb::response::Result::RevokeDevice(rv) = r else {
        panic!("{r:?}")
    };
    let closed = tokio::time::timeout(Duration::from_secs(10), s.conn.closed())
        .await
        .expect("the revoked connection closes");
    evidence!(
        "revoke",
        "{name} over {pref:?}: closed with {:?} reason {:?} by_peer={}",
        closed.code,
        closed.reason,
        closed.by_peer
    );
    assert_eq!(
        closed.code,
        CloseCode::Unauthorized,
        "{name} over {pref:?}: reason {:?}",
        closed.reason
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    while s.frames.try_recv().is_ok() {}
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(s.frames.try_recv().is_err(), "no frame after the cut");
    let again = tokio::time::timeout(
        Duration::from_secs(20),
        hx_crypto::connect_with_pin(
            &stack.target(pref),
            device,
            stack.server,
            &Pin::new(&stack.pin).unwrap(),
            &stack.opts(pref, name),
        ),
    )
    .await
    .expect("answered");
    assert!(again.is_err(), "a revoked device cannot come back");
    pass(
        &format!("revoke ({pref:?})"),
        format!(
            "{name} revoked mid-stream: closed {:?}, {} session(s) closed, no more frames, re-login refused",
            closed.code, rv.sessions_closed
        ),
    );
}

fn session_binary() -> PathBuf {
    if let Some(p) = std::env::var_os("HX_E2E_SESSION_BIN") {
        return p.into();
    }
    let target = std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"),
        PathBuf::from,
    );
    let bin = target.join("release/hx-session");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let st = std::process::Command::new(cargo)
        .args(["build", "-p", "hx-session", "--release"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .expect("cargo build -p hx-session --release");
    assert!(st.success(), "building hx-session failed");
    assert!(bin.exists(), "{} was not built", bin.display());
    bin
}

#[allow(clippy::too_many_lines)]
async fn run_real(c: Client<UnixTransport>) {
    let n = naming();
    let out_dir =
        PathBuf::from(std::env::var("HX_E2E_OUT").unwrap_or_else(|_| "/tmp/hx3e-out".to_string()));
    std::fs::create_dir_all(&out_dir).unwrap();

    // ===== 1. privd: real Incus, a temporary socket ==========================================================
    let tmp = work_dir();
    let link_dir = tmp.join("l");
    std::fs::create_dir_all(&link_dir).unwrap();
    let me = rustix::process::getuid().as_raw();
    let mut cfg = PrivdConfig::for_tests(
        &tmp,
        GatewayIdentity {
            uid: me,
            gid: rustix::process::getgid().as_raw(),
        },
    );
    std::fs::write(&cfg.group_file, format!("hx-gatewayd:x:{me}:\n")).unwrap();
    std::fs::write(
        &cfg.passwd_file,
        format!("hx-gatewayd:x:{me}:{me}::/:/bin/false\n"),
    )
    .unwrap();
    cfg.naming = n.clone();
    cfg.instance_prefix = PREFIX.into();
    let proxy_slot = Arc::new(std::sync::Mutex::new(None));
    let image = local_image().await;
    evidence!("image", "cached image used: {image:?}");
    let shim = Shim {
        inner: UnixTransport::new(socket()),
        proxy: proxy_slot.clone(),
        image: Arc::new(image),
        link_dir: Arc::new(link_dir.to_string_lossy().into_owned()),
    };
    let runner = Arc::new(HostRunner::default());
    let audit = Arc::new(MemoryAudit::default());
    let deps = Deps {
        runner: runner.clone(),
        probe: Arc::new(RealProbe(SystemProbe::new(&cfg.incus_dir))),
        clock: Arc::new(SystemClock),
        audit: audit.clone(),
    };
    let daemon =
        Daemon::new_with_catalog(cfg.clone(), Client::new(shim), deps, Catalog::embedded())
            .unwrap();
    let _ = std::fs::remove_file(&cfg.socket_path);
    let listener = bind_path(&cfg.socket_path).unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let d = daemon.clone();
    tokio::spawn(async move {
        let _ = serve(
            d,
            listener,
            ServeOptions {
                background_tasks: false,
            },
            async {
                let _ = stop_rx.await;
            },
        )
        .await;
    });
    let admin_privd = async |command: Command| {
        daemon
            .handle(request(1, command), Ctx::new(Role::Admin))
            .await
    };
    expect_ok(admin_privd(Command::BeginSetup(Default::default())).await);
    let socket_path = cfg.socket_path.clone();
    let mut gw = Gw(Some(
        tokio::task::spawn_blocking(move || {
            let c = RawClient::connect(&socket_path);
            c.stream
                .set_read_timeout(Some(Duration::from_secs(3600)))
                .unwrap();
            c
        })
        .await
        .unwrap(),
    ));
    let ack = gw.with(|c| c.hello()).await;
    assert_eq!(ack.role(), Role::Gateway);
    pass(
        "privd",
        format!(
            "in-process on {}, role {:?}, setup window open",
            cfg.socket_path.display(),
            ack.role()
        ),
    );

    // ===== 2. SetupHost (no nft), CreateDesktop ===================================================================
    let step = Instant::now();
    let R::SetupHost(host) = expect_ok(
        gw.call(
            Command::SetupHost(pb::SetupHostRequest {
                pool_size_gib: 30,
                ..Default::default()
            }),
            &[],
        )
        .await,
    ) else {
        panic!("SetupHost")
    };
    let gateway_ip: std::net::IpAddr = host.gateway_ip.parse().expect("bridge gateway address");
    let (port, _proxy) = start_proxy(gateway_ip).await;
    *proxy_slot.lock().unwrap() = Some(format!("http://{gateway_ip}:{port}"));
    c.patch_network_config(
        &n.bridge,
        &[("security.acls".to_string(), String::new())].into(),
    )
    .await
    .unwrap();
    evidence!(
        "SetupHost",
        "{:.1}s pool={:?} network={:?} acl={:?} profiles={:?}/{:?} gateway_ip={} docker_user={:?}; host tools asked for (stand-in runner, not run): {:?}",
        step.elapsed().as_secs_f64(),
        host.pool(),
        host.network(),
        host.acl(),
        host.desktop_profile(),
        host.compat_profile(),
        host.gateway_ip,
        host.docker_user_rules(),
        runner
            .log
            .lock()
            .unwrap()
            .iter()
            .filter(|l| !l.starts_with("ip "))
            .cloned()
            .collect::<Vec<_>>()
    );
    pass(
        "SetupHost",
        format!(
            "real pool/bridge/ACL/profiles in {:.1}s; no nft ruleset loaded; apt proxy on {gateway_ip}:{port}",
            step.elapsed().as_secs_f64()
        ),
    );

    let password = format!("Hx3e-{}", random_hex(8));
    let existing = c.get_instance(INSTANCE).await.unwrap().is_some();
    if existing && std::env::var("HX_E2E_REUSE").as_deref() == Ok("1") {
        evidence!(
            "CreateDesktop",
            "HX_E2E_REUSE=1: the desktop exists, not created again"
        );
    } else {
        let started = Instant::now();
        let secrets = password.clone();
        let (resp, progress) = gw
            .with(move |c| {
                let id = c.fresh_id();
                c.send_request(
                    id,
                    Command::CreateDesktop(pb::CreateDesktopRequest {
                        desktop_id: "main".into(),
                        distro: pb::Distro::Ubuntu2404 as i32,
                        desktop: pb::DesktopKind::Xfce as i32,
                        preset: pb::Preset::Basic as i32,
                        username: USER.into(),
                        limits: Some(pb::Limits {
                            cpu: 4,
                            memory_mib: 4096,
                            disk_gib: 16,
                        }),
                        ..Default::default()
                    }),
                    &[(pb::SecretKind::UserPassword, secrets.as_bytes())],
                    0,
                );
                let mut progress = 0usize;
                loop {
                    match c.recv().frame {
                        Some(pb::frame::Frame::Progress(_)) => progress += 1,
                        Some(pb::frame::Frame::Response(r)) if r.request_id == id => {
                            return (r, progress);
                        }
                        other => panic!("{other:?}"),
                    }
                }
            })
            .await;
        let R::CreateDesktop(create) = expect_ok(resp) else {
            panic!("CreateDesktop")
        };
        evidence!(
            "CreateDesktop",
            "{:.0}s path={:?} progress_frames={} timings={:?} warnings={:?}",
            started.elapsed().as_secs_f64(),
            create.path_taken(),
            progress,
            create
                .timings
                .iter()
                .map(|t| (t.stage, t.elapsed_ms))
                .collect::<Vec<_>>(),
            create.warnings
        );
        assert_eq!(create.path_taken(), pb::PathTaken::Build);
        pass(
            "CreateDesktop",
            format!(
                "ubuntu-24.04-xfce-basic built in {:.0}s through privd, user {USER}",
                started.elapsed().as_secs_f64()
            ),
        );
    }
    let inst = c.get_instance(INSTANCE).await.unwrap().expect("instance");
    assert_eq!(inst.config["user.hx.state"], "ready");
    assert_eq!(inst.config["security.privileged"], "false");
    assert_eq!(inst.config["security.idmap.isolated"], "true");

    // ===== 3. hx-session into the container; the socket unit ========================================================
    let bin = session_binary();
    let prepared = exec_root("test -e /etc/hx3e-prepared").await.code == 0;
    if !prepared {
        let apt = exec_root(
            "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && \
             apt-get install -y -qq --no-install-recommends libavcodec60 libavutil58 xdotool xclip xinput x11-utils >/tmp/apt.log 2>&1; echo $?",
        )
        .await;
        assert!(
            apt.stdout.trim().ends_with('0'),
            "apt: {} {}",
            apt.stdout,
            apt.stderr
        );
        root_ok("touch /etc/hx3e-prepared").await;
    }
    // A kept desktop (HX_E2E_REUSE) may be running the old binary, which cannot be overwritten.
    root_ok("systemctl stop hx-session.service hx-session.socket; true").await;
    // Which dynamic libraries does the pushed binary resolve inside the container?
    let push = incus(&[
        "file",
        "push",
        "--create-dirs",
        "--uid",
        "0",
        "--gid",
        "0",
        "--mode",
        "0755",
        bin.to_str().unwrap(),
        &format!("{INSTANCE}/usr/lib/hx-session/hx-session"),
    ])
    .await;
    assert_eq!(push.code, 0, "{}", push.stderr);
    // `--create-dirs` makes the directory 0750; the package would make it 0755, and the service
    // runs as the desktop user.
    root_ok("chmod 0755 /usr/lib/hx-session").await;
    let ldd = root_ok("ldd /usr/lib/hx-session/hx-session | grep -c 'not found' || true").await;
    assert_eq!(ldd.trim(), "0", "unresolved libraries in the container");
    let glibc = root_ok("ldd --version | head -1").await;
    evidence!(
        "hx-session binary",
        "{} bytes pushed to /usr/lib/hx-session/hx-session; unresolved libraries: {}; container {}",
        std::fs::metadata(&bin).unwrap().len(),
        ldd.trim(),
        glibc.trim()
    );
    // The package is not there to install, so `InstallSession` has nothing to do; its last step
    // is privd's own `RestartSession` sequence (`reset-failed`, then restart the socket and the
    // service), which starts the units that the build only enabled. Run it through the wire.
    expect_ok(
        gw.call(
            Command::RestartSession(pb::RestartSessionRequest {
                desktop_id: "main".into(),
            }),
            &[],
        )
        .await,
    );
    let sock_state = root_ok(
        "systemctl is-active hx-session.socket; systemctl is-enabled hx-session.socket; \
         systemctl is-active hx-xorg.service || true",
    )
    .await;
    evidence!(
        "units",
        "after RestartSession: {}",
        sock_state.replace('\n', " ")
    );
    assert!(sock_state.starts_with("active\nenabled"), "{sock_state}");
    // Wait for the real XFCE session: panel and window manager of the desktop user.
    let desk = poll(120, || async {
        let o = exec_root(
            "pgrep -u 1000 -x xfce4-panel >/dev/null && pgrep -u 1000 -x xfwm4 >/dev/null && echo up",
        )
        .await;
        o.stdout.contains("up").then_some(())
    })
    .await;
    let procs = root_ok("ps -u 1000 -o comm= | sort -u | tr '\\n' ' '").await;
    evidence!("XFCE", "desktop processes of uid 1000: {procs}");
    assert!(desk.is_some(), "the XFCE session came up: {procs}");
    pass(
        "hx-session",
        "host-built release binary resolves all libraries in the container (libavcodec60, libavutil58 installed with apt); RestartSession brought up hx-session.socket, Xorg and XFCE",
    );

    for u in ["hx3e-term", "hx3e-xi", "hx3e-clip", "hx3e-uri"] {
        bg_stop(u).await; // left over from a kept desktop
    }

    // ===== 4. ProvisionSessionLink ====================================================================================
    let R::ProvisionSessionLink(link) = expect_ok(
        gw.call(
            Command::ProvisionSessionLink(pb::ProvisionSessionLinkRequest {
                desktop_id: "main".into(),
            }),
            &[],
        )
        .await,
    ) else {
        panic!("ProvisionSessionLink")
    };
    let host_sock = link_dir.join("main.sock");
    let meta = std::fs::symlink_metadata(&host_sock).expect("Incus made the host socket");
    let dev = c.get_instance(INSTANCE).await.unwrap().unwrap().devices["hx-link"].clone();
    evidence!(
        "ProvisionSessionLink",
        "socket_path={} host socket is_socket={} uid={} mode={:o}; device={dev:?}",
        link.socket_path,
        meta.file_type().is_socket(),
        meta.uid(),
        meta.mode() & 0o7777
    );
    assert!(meta.file_type().is_socket());
    assert_eq!((meta.uid(), meta.mode() & 0o7777), (me, 0o600));
    pass(
        "ProvisionSessionLink",
        format!(
            "proxy device hx-link: host socket owned by the gateway uid, mode 600; connect side as uid {UID}"
        ),
    );

    // RestartSession started the service; stop it (the socket unit stays) so that the first
    // connection of the gateway really is a socket activation.
    let svc = root_ok(
        "systemctl stop hx-session.service; systemctl is-active hx-session.socket; \
         systemctl is-active hx-session.service || true",
    )
    .await;
    assert_eq!(svc.replace('\n', " ").trim(), "active inactive", "{svc}");

    // ===== 5. the real hx-gatewayd =====================================================================================
    let server_key = new_key();
    let mut gwd = start_gatewayd(GatewaydSpec {
        dir: &tmp,
        privd_socket: &cfg.socket_path,
        link_socket: &host_sock,
        identity_seed: &*server_key.seed(),
        seccomp: "enforce",
    })
    .await;
    let status = std::fs::read_to_string(format!("/proc/{}/status", gwd.pid())).unwrap();
    assert!(
        status.contains("Seccomp:\t2"),
        "seccomp filter in force: {status}"
    );
    assert!(status.contains("NoNewPrivs:\t1"));
    evidence!(
        "hx-gatewayd",
        "pid {} quic={} websocket={} seccomp enforce (Seccomp:2, NoNewPrivs:1)",
        gwd.pid(),
        gwd.quic,
        gwd.websocket
    );
    let pin = random_pin();
    let stack = Stack {
        quic: gwd.quic,
        ws: gwd.websocket,
        server: server_key.public(),
        admin: gwd.admin.clone(),
        pin: pin.clone(),
    };
    // The PIN verifier: the pepper MAC comes from the real privd.
    let privd_client = PrivdClient::new(&cfg.socket_path, Default::default());
    let record = verifier::enrol(&privd_client, pb::LockoutPurpose::Pin, pin.as_bytes(), BIG)
        .await
        .expect("PepperEnrol through the real privd");
    let r = stack
        .admin()
        .await
        .call(
            apb::request::Command::SetPinVerifier(apb::SetPinVerifierRequest {
                target: Some(apb::set_pin_verifier_request::Target::All(true)),
                verifier: bytes::Bytes::from(record.to_bytes()),
            }),
            None,
        )
        .await
        .unwrap();
    assert!(
        matches!(r, apb::response::Result::SetPinVerifier(_)),
        "{r:?}"
    );
    pass(
        "hx-gatewayd",
        "real binary under seccomp enforce; PIN verifier set through the admin socket (pepper from the real privd)",
    );

    // ===== 6. client 1 over QUIC: pair, wrong PIN, PIN ========================================================
    let laptop = new_key();
    let t = Instant::now();
    stack
        .pair(&laptop, "laptop", TransportPreference::Quic)
        .await;
    pass(
        "pair (QUIC)",
        format!("{:.0} ms", t.elapsed().as_secs_f64() * 1e3),
    );

    let t_login = Instant::now();
    let mut awaiting = tokio::time::timeout(
        Duration::from_secs(30),
        hx_crypto::connect_session(
            &stack.target(TransportPreference::Quic),
            &laptop,
            stack.server,
            &stack.opts(TransportPreference::Quic, "laptop"),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let wait = match awaiting
        .submit(&Pin::new(if pin == "135790" { "246813" } else { "135790" }).unwrap())
        .await
        .unwrap()
    {
        hx_crypto::PinReply::Wrong { retry_after, .. } => retry_after,
        other => panic!("a wrong PIN must be refused, got {other:?}"),
    };
    tokio::time::sleep(wait + Duration::from_millis(150)).await;
    let mut accepted = false;
    for _ in 0..6 {
        match awaiting.submit(&Pin::new(&pin).unwrap()).await.unwrap() {
            hx_crypto::PinReply::Accepted => {
                accepted = true;
                break;
            }
            hx_crypto::PinReply::Backoff { retry_after, .. } => {
                tokio::time::sleep(retry_after + Duration::from_millis(150)).await;
            }
            other => panic!("the right PIN was not accepted: {other:?}"),
        }
    }
    assert!(accepted);
    let conn = awaiting.into_connection().unwrap();
    pass(
        "PIN login (QUIC)",
        format!(
            "wrong PIN refused (backoff {} ms), right PIN accepted; {:.1}s including the backoff",
            wait.as_millis(),
            t_login.elapsed().as_secs_f64()
        ),
    );

    // ===== 7. the stream ==============================================================================================
    let mut a = Stream::new(conn);
    let gw_ticks0 = proc_ticks(gwd.pid()).unwrap();
    let t_view = Instant::now();
    a.view(|v| v.max_fps = 60).await;
    let info = a
        .wait_ctl(60, |m| match m {
            Ctl::StreamInfo(i) => Some(*i),
            _ => None,
        })
        .await
        .expect("StreamInfo (the first dial starts hx-session through socket activation)");
    let t_info = t_view.elapsed();
    let first = a.first_idr(60).await;
    let t_first = t_view.elapsed();
    let screen = screen_size().await;
    evidence!(
        "stream",
        "StreamInfo {}x{} {:?} {} fps after {:.2}s; first IDR ({} bytes, frame {}) after {:.2}s (cold: hx-session started by the first connection); X screen is {screen}",
        info.width,
        info.height,
        info.codec(),
        info.fps,
        t_info.as_secs_f64(),
        first.payload.len(),
        first.header.frame_number,
        t_first.as_secs_f64()
    );
    assert_eq!(
        format!("{}x{}", info.width, info.height),
        screen,
        "the stream has the size of the desktop"
    );
    assert_eq!(info.codec, hx_proto::VideoCodec::H264 as i32);
    let mut dec = Decoder::new();
    let pic0 = dec.decode(&first.payload).expect("the IDR decodes");
    let stats0 = pic0.stats();
    assert_eq!((pic0.width, pic0.height), (info.width, info.height));
    evidence!(
        "decode",
        "IDR decodes to {}x{}: luma mean {:.1}, stddev {:.1}, {} distinct luma values",
        pic0.width,
        pic0.height,
        stats0.mean,
        stats0.stddev,
        stats0.distinct_luma
    );
    assert!(
        stats0.stddev > 8.0 && stats0.distinct_luma > 16,
        "the decoded picture is not uniform"
    );
    if let Some(p) = save_picture(&pic0, &out_dir, "idr") {
        evidence!("decode", "picture saved to {}", p.display());
    }
    pass(
        "first frame",
        format!(
            "{}x{} H.264; StreamInfo after {:.2}s, IDR after {:.2}s (cold start); decoded, stddev {:.1}",
            info.width,
            info.height,
            t_info.as_secs_f64(),
            t_first.as_secs_f64(),
            stats0.stddev
        ),
    );

    // Idle desktop first, then with a scrolling terminal.
    let mut last_pic: Option<Decoded> = None;
    let (cpu_all0, cpu_s0) = container_cpu_usec().await;
    let idle = measure(&mut a, 10, Some((&mut dec, &mut last_pic))).await;
    evidence!(
        "idle desktop",
        "{} frames in {:.1}s = {:.1} fps, {:.2} Mbit/s, {} key frames, {} decoded",
        idle.frames,
        idle.secs,
        idle.fps(),
        idle.mbps(),
        idle.key_frames,
        idle.decoded
    );
    let (cpu_all1, cpu_s1) = container_cpu_usec().await;
    let idle_cpu = (cpu_all1 - cpu_all0, cpu_s1 - cpu_s0);

    bg_user(
        "hx3e-term",
        r#"exec xfce4-terminal --geometry=110x34 -e "bash -c 'while :; do seq 1 500; done'""#,
    )
    .await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let gw_t0 = (Instant::now(), proc_ticks(gwd.pid()).unwrap());
    let (cpu_all0, cpu_s0) = container_cpu_usec().await;
    let busy = measure(&mut a, 10, Some((&mut dec, &mut last_pic))).await;
    let gw_t1 = (Instant::now(), proc_ticks(gwd.pid()).unwrap());
    let (cpu_all1, cpu_s1) = container_cpu_usec().await;
    let gw_pct =
        (gw_t1.1 - gw_t0.1) as f64 / 100.0 / gw_t1.0.duration_since(gw_t0.0).as_secs_f64() * 100.0;
    let busy_cpu = (cpu_all1 - cpu_all0, cpu_s1 - cpu_s0);
    let sess_pct = busy_cpu.1 as f64 / 1e6 / busy.secs * 100.0;
    let all_pct = busy_cpu.0 as f64 / 1e6 / busy.secs * 100.0;
    evidence!(
        "busy desktop",
        "{} frames in {:.1}s = {:.1} fps, {:.2} Mbit/s, {} key frames, {} decoded",
        busy.frames,
        busy.secs,
        busy.fps(),
        busy.mbps(),
        busy.key_frames,
        busy.decoded
    );
    evidence!(
        "cpu",
        "busy: hx-gatewayd {gw_pct:.0}% of one core (host, the whole run so far {:.1} cpu-s), hx-session {sess_pct:.0}%, whole container {all_pct:.0}%; idle: hx-session {:.0}%, container {:.0}%",
        (gw_t1.1 - gw_ticks0) as f64 / 100.0,
        idle_cpu.1 as f64 / 1e6 / idle.secs * 100.0,
        idle_cpu.0 as f64 / 1e6 / idle.secs * 100.0
    );
    assert!(busy.frames >= 30, "P frames flow: {} in 10 s", busy.frames);
    assert!(busy.frames > busy.key_frames * 2, "mostly P frames");
    assert!(
        busy.decoded * 10 >= busy.frames * 9,
        "{} of {} frames decode",
        busy.decoded,
        busy.frames
    );
    if let Some(p) = &last_pic {
        assert!(p.stats().stddev > 8.0);
        if let Some(f) = save_picture(p, &out_dir, "busy-desktop") {
            evidence!(
                "decode",
                "picture of the busy desktop saved to {}",
                f.display()
            );
        }
    }
    pass(
        "frames",
        format!(
            "idle {:.1} fps {:.2} Mbit/s; busy (scrolling terminal) {:.1} fps {:.2} Mbit/s; {}/{} frames decoded",
            idle.fps(),
            idle.mbps(),
            busy.fps(),
            busy.mbps(),
            busy.decoded,
            busy.frames
        ),
    );
    pass(
        "cpu",
        format!(
            "busy: gateway {gw_pct:.0}%, hx-session {sess_pct:.0}%, container {all_pct:.0}% of one core"
        ),
    );
    bg_stop("hx3e-term").await;
    user_ok("pkill -u 1000 -x xfce4-terminal; true").await;

    // ===== 8. input ===================================================================================================
    bg_user("hx3e-xi", "exec stdbuf -oL xinput test-xi2 --root").await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    a.conn.send_input(&key(0x04, true)).await.unwrap(); // HID 'a' = X keycode 38
    a.conn.send_input(&key(0x04, false)).await.unwrap();
    let keys = poll(15, || async {
        let log = user_ok("cat /tmp/hx3e-xi.log").await;
        let k = xi_keys(&log);
        (k.len() >= 2).then_some(k)
    })
    .await
    .expect("the key reached X");
    assert_eq!(
        keys[..2],
        [("KeyPress".to_string(), 38), ("KeyRelease".to_string(), 38)]
    );
    a.conn.send_mouse_move(false, 640, 360).await.unwrap();
    let at = wait_pointer((640, 360)).await;
    assert_eq!(at, (640, 360), "the pointer in the container");
    a.conn
        .send_input(&click(MouseButton::Left, true, 700, 400))
        .await
        .unwrap();
    a.conn
        .send_input(&click(MouseButton::Left, false, 700, 400))
        .await
        .unwrap();
    let at2 = wait_pointer((700, 400)).await;
    evidence!(
        "input",
        "key 'a' arrived as {keys:?}; pointer at {at:?} then {at2:?} (xdotool getmouselocation in the container)"
    );
    assert_eq!(at2, (700, 400));
    pass(
        "input",
        "key (KeyPress/KeyRelease keycode 38 seen by xinput) and mouse move/click (xdotool getmouselocation) reached the real X server",
    );

    // ===== 9. clipboard both ways =======================================================================================
    let text = "grüße from the client \u{1f600} 123";
    a.send_transfer(
        TransferKind::Clipboard,
        "text/plain;charset=utf-8",
        "",
        text.as_bytes(),
    )
    .await
    .expect("clipboard accepted");
    let got = poll(10, || async { xclip_get().await.filter(|s| s == text) }).await;
    assert_eq!(got.as_deref(), Some(text), "client to desktop clipboard");
    let copied = format!("copied in the desktop {}", random_hex(4));
    user_ok(&format!("printf %s '{copied}' > /tmp/clip.txt")).await;
    bg_user(
        "hx3e-clip",
        "exec xclip -quiet -selection clipboard -i /tmp/clip.txt",
    )
    .await;
    let t = a
        .next_transfer(15)
        .await
        .expect("a clipboard transfer from the desktop");
    assert_eq!(t.kind, TransferKind::Clipboard);
    assert_eq!(String::from_utf8_lossy(&t.body), copied);
    pass(
        "clipboard",
        "text both ways: client -> xclip in the container, xclip -> client",
    );

    // ===== 10. files both ways ============================================================================================
    let mut data = vec![0u8; 300_000];
    rustix::rand::getrandom(&mut data, rustix::rand::GetRandomFlags::empty()).unwrap();
    // A name of its own: a kept desktop may hold the file of an earlier run.
    let up_name = format!("e2e-up-{}.bin", random_hex(4));
    a.send_transfer(
        TransferKind::File,
        "application/octet-stream",
        &up_name,
        &data,
    )
    .await
    .expect("file accepted");
    let want = sha(&data);
    let got = poll(15, || async {
        let o = exec_root(&format!(
            "sha256sum /var/lib/hx-session/received/{up_name} 2>/dev/null"
        ))
        .await;
        o.stdout
            .split_whitespace()
            .next()
            .map(str::to_string)
            .filter(|h| *h == want)
    })
    .await;
    assert_eq!(
        got.as_deref(),
        Some(want.as_str()),
        "the file is in /var/lib/hx-session/received"
    );
    let owner = root_ok(&format!(
        "stat -c '%U %a' /var/lib/hx-session/received/{up_name}"
    ))
    .await;
    evidence!(
        "file up",
        "300000 bytes, sha256 {want} in /var/lib/hx-session/received (owner/mode {})",
        owner.trim()
    );
    user_ok("head -c 100000 /dev/urandom > /home/alice/e2e-down.bin; sha256sum /home/alice/e2e-down.bin").await;
    let down_hash = user_ok("sha256sum /home/alice/e2e-down.bin").await;
    let down_hash = down_hash.split_whitespace().next().unwrap().to_string();
    // A file copied in the desktop is offered as a file list; the session pushes it.
    bg_stop("hx3e-clip").await;
    user_ok("printf 'file:///home/alice/e2e-down.bin\\r\\n' > /tmp/uris.txt").await;
    bg_user(
        "hx3e-uri",
        "exec xclip -quiet -selection clipboard -t text/uri-list -i /tmp/uris.txt",
    )
    .await;
    let t = loop {
        let t = a
            .next_transfer(20)
            .await
            .expect("a file transfer from the desktop");
        if t.kind == TransferKind::File {
            break t;
        }
    };
    assert_eq!(t.header.name, "e2e-down.bin");
    assert_eq!(sha(&t.body), down_hash);
    evidence!(
        "file down",
        "{} bytes, name {}, sha256 matches the container's file",
        t.body.len(),
        t.header.name
    );
    pass(
        "files",
        "client -> /var/lib/hx-session/received (sha256 equal); desktop copy (text/uri-list) -> client (sha256 equal)",
    );

    for u in ["hx3e-xi", "hx3e-clip", "hx3e-uri"] {
        bg_stop(u).await;
    }

    // A size that differs from the current one (a kept desktop may already be resized).
    let (rw, rh) = if info.width == 1280 {
        (1600, 900)
    } else {
        (1280, 720)
    };

    // ===== 11. resize ===================================================================================================
    a.view(|v| {
        v.max_fps = 60;
        v.width = rw;
        v.height = rh;
    })
    .await;
    let info2 = a
        .wait_ctl(30, |m| match m {
            Ctl::StreamInfo(i) if (i.width, i.height) == (rw, rh) => Some(*i),
            _ => None,
        })
        .await
        .expect("StreamInfo of the new size");
    let kf = a
        .wait_frame(30, |f| {
            (f.header.is_key()
                && !hx_proto::order::serial_gt(info2.first_frame, f.header.frame_number))
            .then(|| f.payload.clone())
        })
        .await
        .expect("a key frame of the new format");
    let mut dec2 = Decoder::new();
    let pic = dec2.decode(&kf).expect("the resized IDR decodes");
    evidence!(
        "resize",
        "StreamInfo {rw}x{rh}; IDR decodes to {}x{} stddev {:.1}; X screen is now {}",
        pic.width,
        pic.height,
        pic.stats().stddev,
        screen_size().await
    );
    assert_eq!((pic.width, pic.height), (rw, rh));
    assert!(pic.stats().stddev > 8.0);
    pass(
        "resize",
        format!("ViewConfig {rw}x{rh} -> new StreamInfo, key frame decodes at {rw}x{rh}"),
    );

    // ===== 12. takeover by a second device (QUIC) ==========================================================================
    let phone = new_key();
    stack.pair(&phone, "phone", TransportPreference::Quic).await;
    let mut b = Stream::new(
        stack
            .login(&phone, "phone", TransportPreference::Quic)
            .await,
    );
    b.view(|_| {}).await;
    let goodbye = a
        .wait_ctl(30, |m| match m {
            Ctl::Goodbye(g) => Some(g.clone()),
            _ => None,
        })
        .await
        .expect("Goodbye to the first device");
    assert_eq!(goodbye.code, CloseCode::TakenOver.code());
    assert_eq!(goodbye.peer_device_name, "phone");
    let closed = tokio::time::timeout(Duration::from_secs(10), a.conn.closed())
        .await
        .expect("closes");
    assert_eq!(closed.code, CloseCode::TakenOver);
    let info_b = b
        .wait_ctl(30, |m| match m {
            Ctl::StreamInfo(i) => Some(*i),
            _ => None,
        })
        .await
        .expect("StreamInfo for the second device");
    let idr_b = b.first_idr(30).await;
    let pic_b = Decoder::new().decode(&idr_b.payload).expect("decodes");
    assert!(pic_b.stats().stddev > 8.0);
    b.conn.send_mouse_move(false, 321, 123).await.unwrap();
    let at = wait_pointer((321, 123)).await;
    assert_eq!(at, (321, 123), "only the new device's input counts");
    evidence!(
        "takeover",
        "laptop got Goodbye(TAKEN_OVER, peer {:?}); phone StreamInfo {}x{}, IDR frame {}, pointer follows the phone",
        goodbye.peer_device_name,
        info_b.width,
        info_b.height,
        idr_b.header.frame_number
    );
    pass(
        "takeover",
        "second paired device took the desktop: old device told TAKEN_OVER and closed, new device got StreamInfo + IDR + input",
    );
    drop(a);

    // ===== 13. WebSocket: pair, PIN, stream, input; then revoke mid-stream ===================================================
    let tablet = new_key();
    stack
        .pair(&tablet, "tablet", TransportPreference::WebSocket)
        .await;
    let t_ws = Instant::now();
    let mut w = Stream::new(
        stack
            .login(&tablet, "tablet", TransportPreference::WebSocket)
            .await,
    );
    w.view(|_| {}).await;
    let idr_w = w.first_idr(30).await;
    let t_ws_first = t_ws.elapsed();
    let _ = tokio::time::timeout(Duration::from_secs(10), b.conn.closed())
        .await
        .expect("the phone was taken over");
    let pic_w = Decoder::new().decode(&idr_w.payload).expect("decodes");
    assert!(pic_w.stats().stddev > 8.0);
    bg_user(
        "hx3e-term",
        r#"exec xfce4-terminal --geometry=110x34 -e "bash -c 'while :; do seq 1 500; done'""#,
    )
    .await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let ws_win = measure(&mut w, 5, None).await;
    w.conn.send_mouse_move(false, 480, 270).await.unwrap();
    assert_eq!(wait_pointer((480, 270)).await, (480, 270));
    bg_stop("hx3e-term").await;
    user_ok("pkill -u 1000 -x xfce4-terminal; true").await;
    evidence!(
        "websocket",
        "pair + PIN + IDR in {:.2}s over WebSocket; {} frames in {:.1}s = {:.1} fps {:.2} Mbit/s (busy)",
        t_ws_first.as_secs_f64(),
        ws_win.frames,
        ws_win.secs,
        ws_win.fps(),
        ws_win.mbps()
    );
    assert!(ws_win.frames >= 20);
    pass(
        "WebSocket",
        format!(
            "paired, PIN, IDR in {:.2}s, {:.1} fps {:.2} Mbit/s, input reaches X",
            t_ws_first.as_secs_f64(),
            ws_win.fps(),
            ws_win.mbps()
        ),
    );

    // The phone comes back over QUIC (taking the desktop from the tablet) and is revoked while it
    // streams; then the tablet does the same over WebSocket.
    let mut b2 = Stream::new(
        stack
            .login(&phone, "phone", TransportPreference::Quic)
            .await,
    );
    b2.view(|_| {}).await;
    b2.first_idr(30).await;
    let g = w
        .wait_ctl(30, |m| match m {
            Ctl::Goodbye(g) => Some(g.clone()),
            _ => None,
        })
        .await
        .expect("Goodbye to the tablet");
    assert_eq!(g.code, CloseCode::TakenOver.code());
    drop(w);
    revoke_mid_stream(&stack, &phone, "phone", TransportPreference::Quic, b2).await;

    let mut w2 = Stream::new(
        stack
            .login(&tablet, "tablet", TransportPreference::WebSocket)
            .await,
    );
    w2.view(|_| {}).await;
    w2.first_idr(30).await;
    revoke_mid_stream(
        &stack,
        &tablet,
        "tablet",
        TransportPreference::WebSocket,
        w2,
    )
    .await;

    // ===== 14. stop and start the container, reconnect ======================================================================
    let t_stop = Instant::now();
    let R::StopDesktop(p) = expect_ok(
        gw.call(
            Command::StopDesktop(pb::StopDesktopRequest {
                desktop_id: "main".into(),
                force: false,
            }),
            &[],
        )
        .await,
    ) else {
        panic!("StopDesktop")
    };
    assert!(!p.running);
    let stopped_in = t_stop.elapsed();
    let t_start = Instant::now();
    let R::StartDesktop(p) = expect_ok(
        gw.call(
            Command::StartDesktop(pb::StartDesktopRequest {
                desktop_id: "main".into(),
            }),
            &[],
        )
        .await,
    ) else {
        panic!("StartDesktop")
    };
    assert!(p.running);
    let started_in = t_start.elapsed();
    // The device is the laptop (still paired). Retry until the desktop answers: Xorg and the
    // session start with the container, and the link redials with backoff.
    let mut got = None;
    let t_re = Instant::now();
    let mut attempts = 0;
    while t_re.elapsed() < Duration::from_secs(240) {
        attempts += 1;
        let conn = match tokio::time::timeout(
            Duration::from_secs(20),
            hx_crypto::connect_with_pin(
                &stack.target(TransportPreference::Quic),
                &laptop,
                stack.server,
                &Pin::new(&pin).unwrap(),
                &stack.opts(TransportPreference::Quic, "laptop"),
            ),
        )
        .await
        {
            Ok(Ok(c)) => c,
            _ => {
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };
        let mut s = Stream::new(conn);
        s.view(|_| {}).await;
        if tokio::time::timeout(Duration::from_secs(20), s.first_idr(20))
            .await
            .is_ok()
        {
            got = Some(s);
            break;
        }
        drop(s);
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    let mut s = got.expect("a stream again after the container restart");
    let t_back = t_re.elapsed();
    let f = s.next_frame(10).await;
    evidence!(
        "restart",
        "StopDesktop {:.1}s, StartDesktop {:.1}s, first frame again {:.1}s after the start returned ({} login attempt(s)); next frame {}",
        stopped_in.as_secs_f64(),
        started_in.as_secs_f64(),
        t_back.as_secs_f64(),
        attempts,
        f.header.frame_number
    );
    s.conn.send_mouse_move(false, 111, 222).await.unwrap();
    assert_eq!(
        wait_pointer((111, 222)).await,
        (111, 222),
        "input works after the restart"
    );
    pass(
        "stop/start",
        format!(
            "StopDesktop {:.1}s, StartDesktop {:.1}s; reconnect and first frame {:.1}s after start ({} attempts); input works",
            stopped_in.as_secs_f64(),
            started_in.as_secs_f64(),
            t_back.as_secs_f64(),
            attempts
        ),
    );
    drop(s);
    drop(b);

    // ===== 15. what the gateway logged, then shut down ======================================================================
    let log = lines_of(&gwd.log).await;
    let noisy: Vec<&String> = log
        .iter()
        .filter(|l| {
            let u = l.to_ascii_uppercase();
            u.contains(" WARN") || u.contains("ERROR")
        })
        .collect();
    evidence!(
        "gatewayd log",
        "{} lines, {} warnings or errors:\n{}",
        log.len(),
        noisy.len(),
        noisy
            .iter()
            .take(30)
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );
    for l in &log {
        assert!(!l.contains(&pin), "the PIN is in the gateway log");
    }
    assert!(
        std::fs::read_to_string(format!("/proc/{}/status", gwd.pid()))
            .unwrap()
            .contains("Seccomp:\t2"),
        "still under seccomp"
    );
    let exit = gwd.terminate();
    evidence!("hx-gatewayd", "SIGTERM: exit {exit:?}");
    assert!(exit.is_some_and(|s| s.success()), "graceful exit: {exit:?}");
    pass(
        "hx-gatewayd shutdown",
        "SIGTERM: clean exit, still under seccomp, PIN not in the log",
    );

    for l in audit.lines() {
        for secret in [password.as_str(), pin.as_str()] {
            assert!(!l.contains(secret), "a secret in the privd audit log");
        }
    }
    let _ = stop_tx.send(());
}
