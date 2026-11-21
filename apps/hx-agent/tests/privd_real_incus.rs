//! privd against a **real** Incus: `#[ignore]`d and gated on `HX3P_REAL=1`.
//!
//! Run it with
//!
//! ```text
//! HX3P_REAL=1 sg incus-admin -c 'cargo nextest run -p hx-agent --run-ignored only \
//!     --test privd_real_incus --no-capture'
//! ```
//!
//! privd runs in-process as your own user on a temporary socket, with the gateway uid injected
//! through the test-only constructor (your own uid) and the real Incus socket. Through the wire
//! (as `Gateway`) and through `Ctx` (as `Admin`, which needs root on a real socket) it exercises
//! `GetHostInfo`, `CreateDesktop`, `GetDesktop`, `StopDesktop`/`StartDesktop`, `SetLimits`, a
//! snapshot, `SetUserPassword`, `ProvisionSessionLink` and `DestroyDesktop`.
//!
//! Everything it creates is named `hx3p-*` (pool, bridge, ACL, profiles, the instance
//! `hx3p-main`) and removed again, also before the run. It never touches other Incus objects,
//! never loads a firewall ruleset (`SetupHost` is not called: the host objects are made with
//! `hx_provision::ensure_host`), and never changes host firewall rules.
//!
//! Deviations from production, each because the test is not root and the host runs Docker:
//!
//! * **Package downloads.** A host that runs Docker drops forwarded traffic from an Incus bridge,
//!   and this test must not change host firewall rules. As in `hx-provision`'s
//!   `incus_real_session.rs`, a small forward proxy is bound **only to the test bridge's gateway
//!   address** and the test bridge's ACL is detached while packages are installed. privd's
//!   `CreateDesktop` is monolithic, so the proxy reaches the container through `environment.*`
//!   instance configuration that a test-only transport shim adds to the create request.
//! * **Base image.** The same shim points the create request at a locally cached image of the
//!   recipe's distro, if there is one, so the run does not download it.
//! * **The link directory.** `/run/hx/link` needs root. The shim rewrites the proxy device's host
//!   path to a directory the test owns, in the request and back in the response (the same
//!   deviation as docs/spikes/1c-proxy-device.md); privd's code and `hx-provision`'s verification
//!   run unchanged.
//! * **The recipe.** By default a minimal recipe stands in for the XFCE one (same name, same
//!   user, a build step and the real post stage with its apt update), so a run takes minutes.
//!   `HX3P_FULL=1` uses the embedded recipe instead (many minutes, a desktop download).
//! * `hx-session` is not packaged yet, so `InstallSession` has nothing to install and
//!   `CreateDesktop` warns about it; the current-password helper does not exist either.

use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use hx_agent::privd::activation::bind_path;
use hx_agent::privd::audit::MemoryAudit;
use hx_agent::privd::clock::SystemClock;
use hx_agent::privd::config::PrivdConfig;
use hx_agent::privd::daemon::{Ctx, Daemon, Deps};
use hx_agent::privd::identity::GatewayIdentity;
use hx_agent::privd::probe::{HostProbe, SystemProbe};
use hx_agent::privd::runner::SystemRunner;
use hx_agent::privd::server::{ServeOptions, serve};
use hx_agent::privd::testing::{RawClient, error_of, request};
use hx_ipc::privd::pb::{self, ErrorCode, Role, request::Command, response::Result as R};
use hx_provision::host::{HostSpec, Naming, PoolSource, ensure_host};
use hx_provision::incus::{Client, IncusError, Request, Response, Transport, UnixTransport};
use hx_provision::orchestrate::{destroy_instance, exec_captured};
use hx_provision::teardown::teardown_host;
use hx_provision::{Catalog, MemSource};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const PREFIX: &str = "hx3p-";
const INSTANCE: &str = "hx3p-main";
const PASSWORD: &str = "Hx3p-Throwaway-pw-1";
const NEW_PASSWORD: &str = "Hx3p-Another-pw-2";

macro_rules! evidence {
    ($label:expr, $($arg:tt)*) => {
        eprintln!("EVIDENCE [{}] {}", $label, format!($($arg)*).trim_end().replace('\n', "\n    | "))
    };
}

fn socket() -> String {
    std::env::var("HX_INCUS_SOCKET").unwrap_or_else(|_| UnixTransport::DEFAULT_SOCKET.to_string())
}

fn naming() -> Naming {
    Naming::with_prefix(PREFIX).unwrap()
}

// ----- the transport shim (see the module docs) ------------------------------------------------------

#[derive(Clone)]
struct Shim {
    inner: UnixTransport,
    /// `http://gateway:port` of the proxy.
    proxy: Arc<String>,
    /// A locally cached image fingerprint for the recipe's distro.
    image: Arc<Option<String>>,
    /// The host directory standing in for `/run/hx/link`.
    link_dir: Arc<String>,
}

const PROD_LINK_PREFIX: &str = "unix:/run/hx/link/";

impl Transport for Shim {
    async fn send(&self, mut req: Request) -> Result<Response, IncusError> {
        let test_prefix = format!("unix:{}/", self.link_dir);
        // Create: proxy environment and the cached image.
        if req.method == hyper::Method::POST && req.path == "/1.0/instances" {
            let mut v: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            if let Some(cfg) = v["config"].as_object_mut() {
                for k in ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"] {
                    cfg.insert(
                        format!("environment.{k}"),
                        Value::String((*self.proxy).clone()),
                    );
                }
            }
            if let Some(fp) = self.image.as_ref() {
                v["source"] = serde_json::json!({"type": "image", "fingerprint": fp});
            }
            req.body = Bytes::from(serde_json::to_vec(&v).unwrap());
        }
        // The link device: production path -> the test's directory.
        if req.path.starts_with("/1.0/instances/") && !req.body.is_empty() {
            let s = String::from_utf8_lossy(&req.body).replace(PROD_LINK_PREFIX, &test_prefix);
            req.body = Bytes::from(s.into_bytes());
        }
        let mut resp = self.inner.send(req).await?;
        if !resp.body.is_empty() {
            let s = String::from_utf8_lossy(&resp.body).replace(&test_prefix, PROD_LINK_PREFIX);
            resp.body = Bytes::from(s.into_bytes());
        }
        Ok(resp)
    }
}

// ----- a probe that reads the real host, with the pool's numbers from the test pool ---------------------------

struct RealProbe(SystemProbe);

impl HostProbe for RealProbe {
    fn cpu_count(&self) -> u32 {
        self.0.cpu_count()
    }
    fn memory_mib(&self) -> (u64, u64) {
        self.0.memory_mib()
    }
    fn os_release(&self) -> (String, String) {
        self.0.os_release()
    }
    fn pool_space(&self, pool: &str) -> Option<(u64, u64)> {
        // The pool directory is readable by everyone on a stock Incus; if not, use the size the
        // test created the pool with.
        self.0.pool_space(pool).or(Some((24 << 30, 20 << 30)))
    }
    fn incus_dir_free(&self) -> Option<u64> {
        self.0.incus_dir_free()
    }
    fn sysctl_ok(&self) -> bool {
        self.0.sysctl_ok()
    }
}

// ----- the proxy (copied from incus_real_session.rs) -------------------------------------------------------------

async fn start_proxy(bind: IpAddr) -> (u16, tokio::task::JoinHandle<()>) {
    let l = TcpListener::bind(SocketAddr::new(bind, 0)).await.unwrap();
    let port = l.local_addr().unwrap().port();
    let h = tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            tokio::spawn(async move {
                let _ = proxy_conn(s).await;
            });
        }
    });
    (port, h)
}

async fn proxy_conn(mut client: TcpStream) -> std::io::Result<()> {
    let mut head = Vec::new();
    let mut buf = [0u8; 2048];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = client.read(&mut buf).await?;
        if n == 0 || head.len() > 16 * 1024 {
            return Ok(());
        }
        head.extend_from_slice(&buf[..n]);
    }
    let end = head.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let text = String::from_utf8_lossy(&head[..end]).to_string();
    let mut lines = text.split("\r\n");
    let first = lines.next().unwrap_or_default().to_string();
    let parts: Vec<&str> = first.split(' ').collect();
    let refuse = async |mut c: TcpStream| {
        let _ = c
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await;
        Ok::<(), std::io::Error>(())
    };
    if parts.len() < 3 {
        return refuse(client).await;
    }
    let (host, port, request): (String, u16, Option<Vec<u8>>) = if parts[0] == "CONNECT" {
        let Some((h, p)) = parts[1].rsplit_once(':') else {
            return refuse(client).await;
        };
        (h.to_string(), p.parse().unwrap_or(0), None)
    } else {
        let Some(rest) = parts[1].strip_prefix("http://") else {
            return refuse(client).await;
        };
        let (authority, path) = rest
            .split_once('/')
            .map_or((rest, "/".to_string()), |(a, p)| (a, format!("/{p}")));
        let (h, p) = authority
            .rsplit_once(':')
            .map_or((authority, 80u16), |(h, p)| (h, p.parse().unwrap_or(0)));
        let mut req = format!("{} {} HTTP/1.1\r\n", parts[0], path).into_bytes();
        for l in lines.filter(|l| !l.is_empty()) {
            let low = l.to_ascii_lowercase();
            if low.starts_with("proxy-") || low.starts_with("connection:") {
                continue;
            }
            req.extend_from_slice(l.as_bytes());
            req.extend_from_slice(b"\r\n");
        }
        req.extend_from_slice(b"Connection: close\r\n\r\n");
        (h.to_string(), p, Some(req))
    };
    if port != 80 && port != 443 {
        return refuse(client).await;
    }
    let mut up = TcpStream::connect((host.as_str(), port)).await?;
    match request {
        None => {
            client
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await?;
            client.write_all(&head[end..]).await?;
        }
        Some(req) => up.write_all(&req).await?,
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut up).await;
    Ok(())
}

// ----- helpers -------------------------------------------------------------------------------------------------------

async fn local_image() -> Option<String> {
    use hyper::Method;
    let t = UnixTransport::new(socket());
    let r = t
        .send(Request {
            method: Method::GET,
            path: "/1.0/images?recursion=1".into(),
            headers: vec![],
            body: Bytes::new(),
            content_type: None,
            max_response: None,
            timeout: Duration::from_secs(60),
        })
        .await
        .ok()?;
    let v: Value = serde_json::from_slice(&r.body).ok()?;
    v["metadata"].as_array()?.iter().find_map(|i| {
        let p = &i["properties"];
        let ok = p["os"]
            .as_str()
            .is_some_and(|s| s.eq_ignore_ascii_case("ubuntu"))
            && p["release"]
                .as_str()
                .is_some_and(|r| ["noble", "24.04"].contains(&r))
            && i["type"] == "container"
            && i["architecture"] == "x86_64";
        ok.then(|| i["fingerprint"].as_str().map(str::to_string))?
    })
}

async fn sh(c: &Client<UnixTransport>, script: &str) -> (i32, String) {
    let argv = vec!["bash".to_string(), "-c".to_string(), script.to_string()];
    let r = exec_captured(c, INSTANCE, &argv, &[], None, None, Duration::from_secs(60))
        .await
        .unwrap_or_else(|e| panic!("exec `{script}`: {e}"));
    (r.exit_code, r.stdout)
}

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

fn error_text(r: &pb::Response) -> String {
    error_of(r).map_or_else(String::new, |e| format!("{:?}: {}", e.code(), e.message))
}

fn expect_ok(r: pb::Response) -> R {
    match r.result {
        Some(R::Error(e)) => panic!(
            "{:?} {:?} (stage {:?}): {}",
            e.code(),
            e.detail(),
            e.stage,
            e.message
        ),
        Some(v) => v,
        None => panic!("empty response"),
    }
}

/// The minimal recipe: same name and user as the shipped one, a build step, and the real post
/// stage (wait for the network, set the password, security updates).
fn minimal_catalog() -> Catalog {
    Catalog::from_source(MemSource::new().with(
        "ubuntu-24.04-xfce-basic.toml",
        r#"
[recipe]
name = "ubuntu-24.04-xfce-basic"
base_image = "images:ubuntu/24.04"

[vars]
distro = "ubuntu"
codename = "noble"
distro_version = "24.04"
desktop = "xfce"
preset = "basic"

[user]
name = "desk"
uid = 1000
shell = "/bin/bash"
groups = ["sudo"]
linger = false

[[step]]
name = "marker"
run = "echo hx3p > /etc/hx3p-built"
"#,
    ))
}

async fn admin(d: &Arc<Daemon<Shim>>, command: Command) -> pb::Response {
    d.handle(request(1, command), Ctx::new(Role::Admin)).await
}

// ----- the test ----------------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a real Incus (sg incus-admin) and HX3P_REAL=1"]
async fn privd_drives_a_real_incus() {
    if std::env::var("HX3P_REAL").as_deref() != Ok("1") {
        eprintln!("HX3P_REAL is not 1: skipping");
        return;
    }
    let c = Client::unix(socket());
    cleanup(&c).await;
    let body = tokio::spawn(run_real(c.clone()));
    let result = body.await;
    cleanup(&c).await;
    let _ = std::fs::remove_dir_all(format!("/tmp/hx3p-{}", std::process::id()));
    // Nothing of ours may remain.
    let n = naming();
    assert!(c.get_instance(INSTANCE).await.unwrap().is_none());
    assert!(c.get_storage_pool(&n.pool).await.unwrap().is_none());
    assert!(c.get_network(&n.bridge).await.unwrap().is_none());
    assert!(!c.acl_exists(&n.acl).await.unwrap());
    assert!(!c.profile_exists(&n.desktop_profile).await.unwrap());
    assert!(!c.profile_exists(&n.compat_profile).await.unwrap());
    evidence!("cleanup", "no hx3p- object remains");
    if let Err(e) = result {
        std::panic::resume_unwind(e.into_panic());
    }
}

#[allow(clippy::too_many_lines)]
async fn run_real(c: Client<UnixTransport>) {
    let n = naming();
    let full = std::env::var("HX3P_FULL").as_deref() == Ok("1");

    // --- host objects: made by hx-provision, not by SetupHost (which would load an nft ruleset) ---
    let host = ensure_host(
        &c,
        &HostSpec {
            naming: n.clone(),
            pool: PoolSource::LoopFile { size_gib: 24 },
            ipv4: "auto".into(),
            host_addresses: vec![],
            allow_private_networks: false,
        },
    )
    .await
    .unwrap();
    let gateway = host.gateway.expect("bridge gateway");
    let (port, _proxy) = start_proxy(gateway).await;
    c.patch_network_config(
        &n.bridge,
        &[("security.acls".to_string(), String::new())].into(),
    )
    .await
    .unwrap();
    evidence!(
        "proxy",
        "listening on {gateway}:{port} (bridge gateway only); the test bridge's ACL is detached"
    );

    // --- privd, in-process, on a temporary socket ----------------------------------------------------
    let tmp = std::path::PathBuf::from(format!("/tmp/hx3p-{}", std::process::id()));
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
    cfg.naming = n.clone();
    cfg.instance_prefix = PREFIX.into();
    let image = local_image().await;
    evidence!("image", "cached image used: {image:?}");
    let shim = Shim {
        inner: UnixTransport::new(socket()),
        proxy: Arc::new(format!("http://{gateway}:{port}")),
        image: Arc::new(image),
        link_dir: Arc::new(link_dir.to_string_lossy().into_owned()),
    };
    let audit = Arc::new(MemoryAudit::default());
    let deps = Deps {
        runner: Arc::new(SystemRunner),
        probe: Arc::new(RealProbe(SystemProbe::new(&cfg.incus_dir))),
        clock: Arc::new(SystemClock),
        audit: audit.clone(),
    };
    let catalog = if full {
        Catalog::embedded()
    } else {
        minimal_catalog()
    };
    let daemon = Daemon::new_with_catalog(cfg.clone(), Client::new(shim), deps, catalog).unwrap();
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
    // The setup window is opened by Admin (the installer's job).
    expect_ok(admin(&daemon, Command::BeginSetup(Default::default())).await);

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
    evidence!("hello", "role={:?} phase={:?}", ack.role(), ack.phase());
    assert_eq!(ack.role(), Role::Gateway);

    // --- GetHostInfo -------------------------------------------------------------------------------------
    let R::GetHostInfo(info) =
        expect_ok(gw.call(Command::GetHostInfo(Default::default()), &[]).await)
    else {
        panic!()
    };
    evidence!(
        "GetHostInfo",
        "incus={:?} os={} {} arch={} cpus={} mem_total_mib={} pool(exists={} driver={} total_gib={} free_gib={}) docker_on_host={} firewall_loaded={} sysctl_ok={} desktop_exists={}",
        info.incus_version,
        info.os_id,
        info.os_version,
        info.arch,
        info.cpu_count,
        info.memory_total_mib,
        info.pool.as_ref().unwrap().exists,
        info.pool.as_ref().unwrap().driver,
        info.pool.as_ref().unwrap().total_gib,
        info.pool.as_ref().unwrap().free_gib,
        info.docker_on_host,
        info.host_firewall_loaded,
        info.sysctl_ok,
        info.desktop_exists
    );
    assert_eq!(
        info.incus_version.as_deref(),
        Some("6.0.0").or(info.incus_version.as_deref())
    );
    assert!(info.pool.as_ref().unwrap().exists);
    assert!(!info.desktop_exists);

    // --- CreateDesktop (basic recipe) ----------------------------------------------------------------------
    let started = Instant::now();
    let (resp, progress, stages) = gw
        .with(|c| {
            let id = c.fresh_id();
            c.send_request(
                id,
                Command::CreateDesktop(pb::CreateDesktopRequest {
                    desktop_id: "main".into(),
                    distro: pb::Distro::Ubuntu2404 as i32,
                    desktop: pb::DesktopKind::Xfce as i32,
                    preset: pb::Preset::Basic as i32,
                    username: "alice".into(),
                    limits: Some(pb::Limits {
                        cpu: 2,
                        memory_mib: 2048,
                        disk_gib: 8,
                    }),
                    ..Default::default()
                }),
                &[(pb::SecretKind::UserPassword, PASSWORD.as_bytes())],
                0,
            );
            let mut progress = 0usize;
            let mut stages = std::collections::BTreeSet::new();
            loop {
                match c.recv().frame {
                    Some(pb::frame::Frame::Progress(p)) => {
                        progress += 1;
                        stages.insert(p.stage);
                    }
                    Some(pb::frame::Frame::Response(r)) if r.request_id == id => {
                        return (r, progress, stages);
                    }
                    other => panic!("{other:?}"),
                }
            }
        })
        .await;
    let create = match expect_ok_resp(resp) {
        R::CreateDesktop(r) => r,
        other => panic!("{other:?}"),
    };
    evidence!(
        "CreateDesktop",
        "{:.0}s path={:?} reason={:?} progress_frames={} stages={:?} timings={:?} warnings={:?}",
        started.elapsed().as_secs_f64(),
        create.path_taken(),
        create.reason,
        progress,
        stages,
        create
            .timings
            .iter()
            .map(|t| (t.stage, t.elapsed_ms))
            .collect::<Vec<_>>(),
        create.warnings
    );
    assert_eq!(create.path_taken(), pb::PathTaken::Build);
    assert!(progress > 0);

    let inst = c.get_instance(INSTANCE).await.unwrap().expect("instance");
    evidence!(
        "isolation",
        "privileged={:?} idmap.isolated={:?} guestapi={:?} processes={:?} state={:?} username={:?} recipe={:?} limits.cpu={:?} limits.memory={:?}",
        inst.config.get("security.privileged"),
        inst.config.get("security.idmap.isolated"),
        inst.config.get("security.guestapi"),
        inst.config.get("limits.processes"),
        inst.config.get("user.hx.state"),
        inst.config.get("user.hx.username"),
        inst.config.get("user.hx.recipe"),
        inst.config.get("limits.cpu"),
        inst.config.get("limits.memory")
    );
    assert_eq!(inst.config["security.privileged"], "false");
    assert_eq!(inst.config["security.idmap.isolated"], "true");
    assert_eq!(inst.config["user.hx.state"], "ready");
    assert_eq!(inst.config["user.hx.username"], "alice");
    assert_eq!(inst.config["limits.processes"], "8192");
    let (code, out) = sh(
        &c,
        "getent passwd alice | cut -d: -f1,3; grep '^alice:' /etc/shadow | cut -d: -f2 | cut -c1-3",
    )
    .await;
    evidence!("user", "{}", out.replace('\n', " | "));
    assert_eq!(code, 0);
    assert!(out.contains("alice:1000"), "{out}");
    let hash1 = sh(&c, "grep '^alice:' /etc/shadow | cut -d: -f2").await.1;
    assert!(hash1.trim().starts_with("$"), "the password hash is set");

    // --- GetDesktop -------------------------------------------------------------------------------------------
    let R::GetDesktop(g) = expect_ok(
        gw.call(
            Command::GetDesktop(pb::GetDesktopRequest {
                desktop_id: "main".into(),
            }),
            &[],
        )
        .await,
    ) else {
        panic!()
    };
    let desk = g.desktop.unwrap();
    evidence!(
        "GetDesktop",
        "state={:?} user={} distro={:?} preset={:?} ip={} limits={:?} docker={:?} link={} snapshots={}",
        desk.state(),
        desk.username,
        desk.distro(),
        desk.preset(),
        desk.ip,
        desk.limits,
        desk.docker(),
        desk.session.as_ref().unwrap().link_provisioned,
        desk.snapshot_count
    );
    assert_eq!(desk.state(), pb::DesktopState::Running);
    assert!(!desk.ip.is_empty());
    let l = desk.limits.unwrap();
    assert_eq!((l.cpu, l.memory_mib, l.disk_gib), (2, 2048, 8));

    // --- ProvisionSessionLink -------------------------------------------------------------------------------------
    let R::ProvisionSessionLink(link) = expect_ok(
        gw.call(
            Command::ProvisionSessionLink(pb::ProvisionSessionLinkRequest {
                desktop_id: "main".into(),
            }),
            &[],
        )
        .await,
    ) else {
        panic!()
    };
    let host_sock = link_dir.join("main.sock");
    let meta = std::fs::symlink_metadata(&host_sock).expect("Incus created the host-side socket");
    let dev = c.get_instance(INSTANCE).await.unwrap().unwrap().devices["hx-link"].clone();
    evidence!(
        "ProvisionSessionLink",
        "socket_path={} host socket: is_socket={} uid={} gid={} mode={:o} (gateway uid/gid injected: {me}); device={dev:?}",
        link.socket_path,
        meta.file_type().is_socket(),
        meta.uid(),
        meta.gid(),
        meta.mode() & 0o7777
    );
    assert_eq!(link.socket_path, "/run/hx/link/main.sock");
    assert!(meta.file_type().is_socket());
    assert_eq!((meta.uid(), meta.mode() & 0o7777), (me, 0o600));
    assert_eq!(dev["security.uid"], "1000");
    assert_eq!(dev["security.gid"], "1000");
    // Converges.
    expect_ok(
        gw.call(
            Command::ProvisionSessionLink(pb::ProvisionSessionLinkRequest {
                desktop_id: "main".into(),
            }),
            &[],
        )
        .await,
    );

    // --- Stop / Start -------------------------------------------------------------------------------------------------
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
        panic!()
    };
    assert!(!p.running);
    assert_eq!(c.instance_state(INSTANCE).await.unwrap().status, "Stopped");
    let t = Instant::now();
    let R::StartDesktop(p) = expect_ok(
        gw.call(
            Command::StartDesktop(pb::StartDesktopRequest {
                desktop_id: "main".into(),
            }),
            &[],
        )
        .await,
    ) else {
        panic!()
    };
    evidence!(
        "Stop/Start",
        "stopped, then started in {:.1}s: running={} degraded={}",
        t.elapsed().as_secs_f64(),
        p.running,
        p.degraded
    );
    assert!(p.running);
    assert!(c.instance_state(INSTANCE).await.unwrap().is_running());

    // --- SetLimits ----------------------------------------------------------------------------------------------------------
    let bad = gw
        .call(
            Command::SetLimits(pb::SetLimitsRequest {
                desktop_id: "main".into(),
                limits: Some(pb::Limits {
                    cpu: 4096,
                    memory_mib: 2048,
                    disk_gib: 8,
                }),
            }),
            &[],
        )
        .await;
    assert_eq!(
        error_of(&bad).unwrap().code(),
        ErrorCode::InvalidArgument,
        "{}",
        error_text(&bad)
    );
    let R::SetLimits(s) = expect_ok(
        gw.call(
            Command::SetLimits(pb::SetLimitsRequest {
                desktop_id: "main".into(),
                limits: Some(pb::Limits {
                    cpu: 1,
                    memory_mib: 1536,
                    disk_gib: 10,
                }),
            }),
            &[],
        )
        .await,
    ) else {
        panic!()
    };
    let inst = c.get_instance(INSTANCE).await.unwrap().unwrap();
    evidence!(
        "SetLimits",
        "restart_required={} limits.cpu={:?} limits.memory={:?} root.size={:?} limits.processes={:?}",
        s.restart_required,
        inst.config.get("limits.cpu"),
        inst.config.get("limits.memory"),
        inst.devices.get("root").and_then(|r| r.get("size")),
        inst.config.get("limits.processes")
    );
    assert!(
        s.restart_required,
        "the CPU count changed on a running desktop"
    );
    assert_eq!(inst.config["limits.cpu"], "1");
    assert_eq!(inst.config["limits.memory"], "1536MiB");
    assert_eq!(inst.config["limits.processes"], "8192");
    let R::RestartDesktop(p) = expect_ok(
        gw.call(
            Command::RestartDesktop(pb::RestartDesktopRequest {
                desktop_id: "main".into(),
                force: false,
            }),
            &[],
        )
        .await,
    ) else {
        panic!()
    };
    assert!(p.running);
    let (_, nproc) = sh(&c, "nproc").await;
    evidence!("SetLimits", "after the restart nproc={}", nproc.trim());
    assert_eq!(nproc.trim(), "1");

    // --- a manual snapshot ------------------------------------------------------------------------------------------------------
    let R::CreateSnapshot(snap) = expect_ok(
        gw.call(
            Command::CreateSnapshot(pb::CreateSnapshotRequest {
                desktop_id: "main".into(),
            }),
            &[],
        )
        .await,
    ) else {
        panic!()
    };
    let name = snap.snapshot.unwrap().name;
    let R::ListSnapshots(list) = expect_ok(
        gw.call(
            Command::ListSnapshots(pb::ListSnapshotsRequest {
                desktop_id: "main".into(),
            }),
            &[],
        )
        .await,
    ) else {
        panic!()
    };
    evidence!(
        "Snapshots",
        "created {name}; listed {:?}",
        list.snapshots
            .iter()
            .map(|s| s.name.clone())
            .collect::<Vec<_>>()
    );
    assert!(list.snapshots.iter().any(|s| s.name == name));
    expect_ok(
        gw.call(
            Command::DeleteSnapshot(pb::DeleteSnapshotRequest {
                desktop_id: "main".into(),
                name,
            }),
            &[],
        )
        .await,
    );

    // --- SetUserPassword (inside the setup window, so no current password) ---------------------------------------------------------------
    let R::SetUserPassword(_) = expect_ok(
        gw.call(
            Command::SetUserPassword(pb::SetUserPasswordRequest {
                desktop_id: "main".into(),
            }),
            &[(pb::SecretKind::UserPassword, NEW_PASSWORD.as_bytes())],
        )
        .await,
    ) else {
        panic!()
    };
    let hash2 = sh(&c, "grep '^alice:' /etc/shadow | cut -d: -f2").await.1;
    let (_, leftovers) = sh(
        &c,
        "find /run/hx-provision -name 'stdin-*' 2>/dev/null | wc -l",
    )
    .await;
    evidence!(
        "SetUserPassword",
        "hash changed={} (not printed); stdin files left in /run/hx-provision={}",
        hash1 != hash2,
        leftovers.trim()
    );
    assert_ne!(hash1, hash2);
    assert_eq!(leftovers.trim(), "0", "the stdin file is gone");
    // Outside the window the current password is required; without the helper installed the check
    // fails closed (INTERNAL), it never lets the change through.
    expect_ok(
        admin(
            &daemon,
            Command::FinishSetup(pb::FinishSetupRequest { force: Some(true) }),
        )
        .await,
    );
    let r = gw
        .call(
            Command::SetUserPassword(pb::SetUserPasswordRequest {
                desktop_id: "main".into(),
            }),
            &[
                (pb::SecretKind::UserPassword, b"Should-Not-Be-Set-1"),
                (pb::SecretKind::CurrentPassword, NEW_PASSWORD.as_bytes()),
            ],
        )
        .await;
    evidence!("SetUserPassword(outside window)", "{}", error_text(&r));
    assert!(error_of(&r).is_some());
    let hash3 = sh(&c, "grep '^alice:' /etc/shadow | cut -d: -f2").await.1;
    assert_eq!(hash2, hash3, "a failed check changes nothing");

    // --- GetHostInfo again, then DestroyDesktop (Admin) ----------------------------------------------------------------------------------
    let R::GetHostInfo(info) =
        expect_ok(gw.call(Command::GetHostInfo(Default::default()), &[]).await)
    else {
        panic!()
    };
    assert!(info.desktop_exists);
    let denied = gw
        .call(
            Command::DestroyDesktop(pb::DestroyDesktopRequest {
                desktop_id: "main".into(),
                confirm_destroy: true,
            }),
            &[],
        )
        .await;
    assert_eq!(
        error_of(&denied).unwrap().code(),
        ErrorCode::PermissionDenied
    );
    expect_ok(
        admin(
            &daemon,
            Command::DestroyDesktop(pb::DestroyDesktopRequest {
                desktop_id: "main".into(),
                confirm_destroy: true,
            }),
        )
        .await,
    );
    assert!(c.get_instance(INSTANCE).await.unwrap().is_none());
    let gone = gw
        .call(
            Command::GetDesktop(pb::GetDesktopRequest {
                desktop_id: "main".into(),
            }),
            &[],
        )
        .await;
    assert_eq!(error_of(&gone).unwrap().code(), ErrorCode::NotFound);
    evidence!(
        "DestroyDesktop",
        "Gateway refused (PERMISSION_DENIED); Admin destroyed it; GetDesktop is NOT_FOUND"
    );

    // --- the audit log: no secret in it ----------------------------------------------------------------------------------------------------
    let lines = audit.lines();
    evidence!(
        "audit",
        "{} lines, for example:\n{}",
        lines.len(),
        lines.iter().take(6).cloned().collect::<Vec<_>>().join("\n")
    );
    for l in &lines {
        for secret in [PASSWORD, NEW_PASSWORD, "Should-Not-Be-Set-1"] {
            assert!(!l.contains(secret));
        }
    }
    let _ = stop_tx.send(());
    let _ = std::fs::remove_dir_all(&tmp);
}

fn expect_ok_resp(r: pb::Response) -> R {
    expect_ok(r)
}

/// The blocking raw client, driven from async code without blocking a runtime worker.
struct Gw(Option<RawClient>);

impl Gw {
    async fn with<T: Send + 'static>(
        &mut self,
        f: impl FnOnce(&mut RawClient) -> T + Send + 'static,
    ) -> T {
        let mut c = self.0.take().expect("client");
        let (c, r) = tokio::task::spawn_blocking(move || {
            let r = f(&mut c);
            (c, r)
        })
        .await
        .expect("blocking client task");
        self.0 = Some(c);
        r
    }

    async fn call(
        &mut self,
        command: Command,
        secrets: &[(pb::SecretKind, &[u8])],
    ) -> pb::Response {
        let owned: Vec<(pb::SecretKind, Vec<u8>)> =
            secrets.iter().map(|(k, v)| (*k, v.to_vec())).collect();
        self.with(move |c| {
            let s: Vec<(pb::SecretKind, &[u8])> =
                owned.iter().map(|(k, v)| (*k, v.as_slice())).collect();
            c.call(command, &s)
        })
        .await
    }
}
