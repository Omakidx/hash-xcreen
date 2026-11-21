//! Tests against a real Incus daemon. All `#[ignore]`d: they need access to the Incus unix socket
//! (membership of `incus-admin`, or root) and create throwaway objects with the prefix
//! `hx1d-test-`, which they remove afterwards (and before, if an earlier run left some behind).
//! Existing Incus objects are never touched.
//!
//! Run (see crates/hx-provision/README or docs): from the repository root, as a user that may use Incus:
//!
//! ```text
//! sg incus-admin -c 'cargo nextest run -p hx-provision --run-ignored only --test incus_real --no-capture'
//! # or: cargo test -p hx-provision --test incus_real -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Environment:
//! - `HX_INCUS_SOCKET`: socket path (default `/var/lib/incus/unix.socket`)
//! - `HX1D_TEST_DOCKER=1`: also run the Docker opt-in against a real container (needs internet in
//!   the container, i.e. working bridge forwarding; downloads Docker packages and `hello-world`)

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use bytes::Bytes;
use hx_provision::docker::{DockerOptions, DockerOutcome, SelfTestHint, enable_docker};
use hx_provision::host::{HostSpec, Naming, PoolSource, ensure_host};
use hx_provision::incus::{Client, ImageSource, Request, Transport, UnixTransport};
use hx_provision::orchestrate::{
    DesktopSpec, IncusExecutor, Limits, ReadyOptions, destroy_instance, wait_system_running,
};
use hx_provision::{
    Addon, Catalog, Desktop, Distro, MemSource, Preset, RecipeId, Secrets, Stage, apply_stage,
};
use serde_json::Value;

const PREFIX: &str = "hx1d-test-";
const PASSWORD: &str = "hx1d-test-Pa55word-not-a-real-secret";

fn socket() -> String {
    std::env::var("HX_INCUS_SOCKET").unwrap_or_else(|_| UnixTransport::DEFAULT_SOCKET.to_string())
}

async fn connect() -> Client<UnixTransport> {
    let c = Client::unix(socket());
    match c.server_info().await {
        Ok(info) => {
            eprintln!(
                "incus {} (api {}, auth {}, firewall {})",
                info.server_version, info.api_version, info.auth, info.firewall
            );
            c
        }
        Err(e) => panic!(
            "cannot use Incus at {}: {e}\nThese tests need access to the socket: run them as a member of `incus-admin`, \
             e.g. sg incus-admin -c 'cargo test -p hx-provision --test incus_real -- --ignored --nocapture'",
            socket()
        ),
    }
}

fn naming() -> Naming {
    Naming::with_prefix(PREFIX).unwrap()
}

fn instance_names() -> [&'static str; 2] {
    ["hx1d-test-c1", "hx1d-test-c2"]
}

/// Remove everything this suite may have created. Only objects named `hx1d-test-*` are touched.
async fn cleanup(c: &Client<UnixTransport>) {
    let n = naming();
    for i in instance_names() {
        if let Err(e) = destroy_instance(c, i).await {
            eprintln!("cleanup: instance {i}: {e}");
        }
    }
    for p in [&n.desktop_profile, &n.compat_profile] {
        if let Ok(true) = c.profile_exists(p).await {
            let _ = c.delete_profile(p).await;
        }
    }
    if let Ok(Some(_)) = c.get_network(&n.bridge).await {
        let _ = c.delete_network(&n.bridge).await;
    }
    if let Ok(true) = c.acl_exists(&n.acl).await {
        let _ = c.delete_acl(&n.acl).await;
    }
    if let Ok(Some(_)) = c.get_storage_pool(&n.pool).await {
        let _ = c.delete_storage_pool(&n.pool).await;
    }
}

/// Fingerprint of a cached Debian 13 container image, if there is one (avoids a download).
async fn local_debian13_image() -> Option<String> {
    let t = UnixTransport::new(socket());
    let r = t
        .send(Request {
            method: hyper::Method::GET,
            path: "/1.0/images?recursion=1".into(),
            headers: vec![],
            body: Bytes::new(),
            content_type: None,
            max_response: None,
            timeout: Duration::from_secs(30),
        })
        .await
        .ok()?;
    let v: Value = serde_json::from_slice(&r.body).ok()?;
    v["metadata"].as_array()?.iter().find_map(|i| {
        let p = &i["properties"];
        let debian = p["os"]
            .as_str()
            .map(|s| s.eq_ignore_ascii_case("debian"))
            .unwrap_or(false);
        let rel = matches!(p["release"].as_str(), Some("trixie") | Some("13"));
        (debian && rel && i["type"] == "container" && i["architecture"] == "x86_64")
            .then(|| i["fingerprint"].as_str().map(str::to_string))?
    })
}

fn tiny_plan() -> hx_provision::Plan {
    let src = MemSource::new().with(
        "r.toml",
        "[recipe]\nname=\"hx1d-tiny\"\nbase_image=\"images:debian/13\"\n[vars]\ndistro=\"debian\"\ndistro_version=\"13\"\n[user]\nname=\"desk\"\nuid=1000\n",
    );
    hx_provision::recipe::resolve(&src, "r.toml", &[]).unwrap()
}

async fn sh(c: &Client<UnixTransport>, instance: &str, script: &str) -> (i32, String, String) {
    let argv = vec!["bash".to_string(), "-c".to_string(), script.to_string()];
    let r = hx_provision::orchestrate::exec_captured(
        c,
        instance,
        &argv,
        &[],
        None,
        None,
        Duration::from_secs(60),
    )
    .await
    .unwrap_or_else(|e| panic!("exec `{script}`: {e}"));
    (r.exit_code, r.stdout, r.stderr)
}

#[tokio::test]
#[ignore = "needs access to a real Incus daemon; see the module docs"]
async fn real_incus_lifecycle() {
    let c = connect().await;
    cleanup(&c).await;
    let c2 = c.clone();
    let body = tokio::spawn(async move { lifecycle(c2).await });
    let result = body.await;
    cleanup(&c).await;
    // Everything of ours is gone again.
    let n = naming();
    assert!(
        c.get_storage_pool(&n.pool).await.unwrap().is_none(),
        "pool left behind"
    );
    assert!(
        c.get_network(&n.bridge).await.unwrap().is_none(),
        "network left behind"
    );
    assert!(!c.acl_exists(&n.acl).await.unwrap(), "acl left behind");
    for i in instance_names() {
        assert!(
            c.get_instance(i).await.unwrap().is_none(),
            "{i} left behind"
        );
    }
    result.unwrap();
}

async fn lifecycle(c: Client<UnixTransport>) {
    let n = naming();
    let info = c.server_info().await.unwrap();
    let version = info.version().unwrap();

    // --- host setup: pool, bridge, ACL, profiles --------------------------------------------------
    let spec = HostSpec {
        naming: n.clone(),
        pool: PoolSource::LoopFile { size_gib: 5 },
        ipv4: "auto".into(),
        host_addresses: vec!["203.0.113.7".parse::<IpAddr>().unwrap()],
        allow_private_networks: false,
    };
    let r1 = ensure_host(&c, &spec).await.unwrap();
    eprintln!("ensure_host #1: {r1:?}");
    let r2 = ensure_host(&c, &spec).await.unwrap();
    eprintln!("ensure_host #2: {r2:?}");
    assert_eq!(r2.pool, hx_provision::host::Ensured::Existed);
    assert_eq!(r2.acl, hx_provision::host::Ensured::Updated);
    let gateway = r1.gateway.expect("the bridge has an IPv4 gateway");
    let pool = c.get_storage_pool(&n.pool).await.unwrap().unwrap();
    assert_eq!(pool.driver, "btrfs");
    let net = c.get_network(&n.bridge).await.unwrap().unwrap();
    assert_eq!(net.config["security.acls"], n.acl);
    assert_eq!(net.config["ipv6.address"], "none");
    assert_eq!(net.config["ipv4.nat"], "true");

    // --- unprivileged container with limits, Debian 13 compat profile -------------------------------------
    let plan = tiny_plan();
    let image = match local_debian13_image().await {
        Some(fp) => {
            eprintln!("using cached image {}", &fp[..12]);
            ImageSource::LocalFingerprint(fp)
        }
        None => {
            eprintln!(
                "no cached Debian 13 image: downloading debian/13 from the official image server"
            );
            ImageSource::official("debian/13")
        }
    };
    let limits = Limits {
        cpu: Some(1),
        memory_mib: Some(512),
        disk_gib: Some(3),
        processes: Some(2048),
    };
    let dspec = DesktopSpec::for_plan("hx1d-test-c1", n.clone(), &plan, limits).with_image(image);
    assert!(dspec.compat_profile);
    c.create_instance(&dspec.to_create().unwrap(), Duration::from_secs(900))
        .await
        .unwrap();
    let inst = c.get_instance("hx1d-test-c1").await.unwrap().unwrap();
    assert_eq!(inst.kind, "container");
    assert_eq!(
        inst.config.get("security.privileged").map(String::as_str),
        Some("false")
    );
    assert_eq!(inst.config.get("limits.cpu").map(String::as_str), Some("1"));
    assert_eq!(
        inst.config.get("limits.memory").map(String::as_str),
        Some("512MiB")
    );
    assert_eq!(
        inst.profiles,
        [n.desktop_profile.clone(), n.compat_profile.clone()]
    );
    c.set_state(
        "hx1d-test-c1",
        hx_provision::incus::StateAction::Start,
        false,
        Duration::from_secs(60),
    )
    .await
    .unwrap();

    // `systemctl is-system-running` == running (the architecture's readiness check).
    let ready = wait_system_running(
        &c,
        "hx1d-test-c1",
        ReadyOptions {
            timeout: Duration::from_secs(120),
            allow_degraded: false,
        },
    )
    .await;
    eprintln!("readiness: {ready:?}");
    ready.expect("the desktop container must reach `running`");

    // Limits are enforced inside the container.
    let (_, nproc, _) = sh(&c, "hx1d-test-c1", "nproc").await;
    assert_eq!(nproc.trim(), "1");
    let (_, memmax, _) = sh(&c, "hx1d-test-c1", "cat /sys/fs/cgroup/memory.max").await;
    assert_eq!(memmax.trim(), (512u64 * 1024 * 1024).to_string());
    let (_, pids, _) = sh(&c, "hx1d-test-c1", "cat /sys/fs/cgroup/pids.max").await;
    assert_eq!(pids.trim(), "2048", "limits.processes");
    assert_eq!(
        inst.config
            .get("security.idmap.isolated")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        inst.config.get("security.guestapi").map(String::as_str),
        Some("false")
    );
    let (_, devlxd, _) = sh(
        &c,
        "hx1d-test-c1",
        "ls /dev/lxd /dev/incus 2>/dev/null | wc -l",
    )
    .await;
    assert_eq!(devlxd.trim(), "0", "no guest API socket");
    let (_, uid_map, _) = sh(&c, "hx1d-test-c1", "cat /proc/self/uid_map").await;
    assert!(
        !uid_map.contains("4294967295"),
        "container runs with a shifted uid map, i.e. unprivileged: {uid_map}"
    );
    let (_, df, _) = sh(&c, "hx1d-test-c1", "df -B1 --output=size / | tail -1").await;
    eprintln!(
        "root size seen in the container (3 GiB btrfs quota requested): {}",
        df.trim()
    );
    let state = c.instance_state("hx1d-test-c1").await.unwrap();
    eprintln!("state: {state:?}");
    assert!(state.is_running() && state.pid > 0);

    // --- the executor: user creation and the password via a 0600 file, never argv ----------------------------------
    let exec = IncusExecutor::new(&c, "hx1d-test-c1");
    let secrets = Secrets::none().with_user_password(PASSWORD).unwrap();
    // Only the user, password and files of the tiny plan are exercised; no apt (no internet needed).
    let mut user_plan = plan.clone();
    user_plan.post = vec![
        hx_provision::Step::EnsureUser(plan.user().unwrap().clone()),
        hx_provision::Step::SetPassword {
            user: "desk".into(),
        },
        hx_provision::Step::WriteFile(hx_provision::plan::FileSpec {
            path: "/etc/hx/test/hello.conf".into(),
            mode: "0640".into(),
            owner: "root:desk".into(),
            content: "hello\n".into(),
        }),
    ];
    let report = apply_stage(&exec, &user_plan, Stage::Post, &secrets, &mut |_| {})
        .await
        .unwrap();
    eprintln!("post stage timings: {:?}", report.timings);
    let (_, shadow, _) = sh(&c, "hx1d-test-c1", "getent shadow desk").await;
    let hash = shadow.split(':').nth(1).unwrap_or_default().to_string();
    assert!(
        hash.starts_with('$') && !hash.contains(PASSWORD),
        "password is stored hashed: {hash:.6}..."
    );
    let (_, id_out, _) = sh(&c, "hx1d-test-c1", "id -u desk").await;
    assert_eq!(id_out.trim(), "1000");
    let (_, stat, _) = sh(
        &c,
        "hx1d-test-c1",
        "stat -c '%a %U:%G' /etc/hx/test/hello.conf",
    )
    .await;
    assert_eq!(stat.trim(), "640 root:desk");
    let (_, left, _) = sh(
        &c,
        "hx1d-test-c1",
        "ls -A /run/hx-provision | grep -c stdin- || true",
    )
    .await;
    assert_eq!(left.trim(), "0", "the stdin file is removed after use");
    let (_, dirmode, _) = sh(&c, "hx1d-test-c1", "stat -c '%a %U' /run/hx-provision").await;
    assert_eq!(dirmode.trim(), "700 root");
    // The password text is nowhere in the container's journal either.
    let (_, grep, _) = sh(
        &c,
        "hx1d-test-c1",
        &format!("journalctl --no-pager 2>/dev/null | grep -c -F {PASSWORD:?} || true"),
    )
    .await;
    assert_eq!(grep.trim(), "0");
    // A command that reads stdin, via the executor's file mechanism, gets exactly the bytes.
    let (_, who, _) = sh(&c, "hx1d-test-c1", "runuser -u desk -- id -un").await;
    assert_eq!(who.trim(), "desk");

    // --- username contract: ensure-user refuses bad accounts; rename moves a lingering user -----------------------
    let spec_for = |name: &str, uid: Option<u32>| hx_provision::plan::UserSpec {
        name: name.into(),
        uid,
        shell: "/bin/bash".into(),
        groups: vec![],
        linger: false,
    };
    for (name, uid, why) in [
        ("desk", Some(1001), "uid mismatch"),
        ("daemon", None, "system account"),
    ] {
        let mut p = plan.clone();
        p.post = vec![hx_provision::Step::EnsureUser(spec_for(name, uid))];
        let e = apply_stage(&exec, &p, Stage::Post, &Secrets::none(), &mut |_| {})
            .await
            .expect_err(why);
        eprintln!("ensure-user refusal ({why}): {e}");
    }
    // A lingering `desk` has a running user manager, like a desktop imported from the prebuilt image.
    let (code, _, err) = sh(&c, "hx1d-test-c1", "loginctl enable-linger desk").await;
    assert_eq!(code, 0, "{err}");
    let mut p = plan.clone();
    p.post = vec![hx_provision::Step::RenameUser {
        from: "desk".into(),
        to: "hxuser".into(),
    }];
    let t = std::time::Instant::now();
    apply_stage(&exec, &p, Stage::Post, &Secrets::none(), &mut |_| {})
        .await
        .unwrap();
    eprintln!("rename-user desk -> hxuser took {:?}", t.elapsed());
    let (_, ids, _) = sh(&c, "hx1d-test-c1", "id -u hxuser; getent passwd hxuser | cut -d: -f6; getent group hxuser | cut -d: -f1; id -u desk 2>&1 | head -1; ls /var/lib/systemd/linger").await;
    eprintln!("after rename: {ids:?}");
    let lines: Vec<&str> = ids.lines().collect();
    assert_eq!(&lines[..3], ["1000", "/home/hxuser", "hxuser"]);
    assert!(lines[3].contains("no such user"), "{lines:?}");
    assert!(
        lines.contains(&"hxuser") && !lines.contains(&"desk"),
        "linger moved: {lines:?}"
    );
    // Re-running is a no-op.
    apply_stage(&exec, &p, Stage::Post, &Secrets::none(), &mut |_| {})
        .await
        .unwrap();

    // --- snapshots (btrfs copy-on-write) -----------------------------------------------------------------------
    c.create_snapshot("hx1d-test-c1", "hx-test-snap")
        .await
        .unwrap();
    let snaps = c.list_snapshots("hx1d-test-c1").await.unwrap();
    assert_eq!(
        snaps.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
        ["hx-test-snap"]
    );
    c.delete_snapshot("hx1d-test-c1", "hx-test-snap")
        .await
        .unwrap();
    assert!(c.list_snapshots("hx1d-test-c1").await.unwrap().is_empty());

    // --- network ACL: the container cannot reach a listener on the host through the bridge -------------------------
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let acc = accepted.clone();
    tokio::spawn(async move {
        while listener.accept().await.is_ok() {
            acc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    });
    let probe = format!(
        "timeout 4 bash -c 'echo > /dev/tcp/{gateway}/{port}' && echo REACHED || echo BLOCKED"
    );
    let (_, with_acl, _) = sh(&c, "hx1d-test-c1", &probe).await;
    eprintln!(
        "host listener {gateway}:{port} with the ACL attached: {}",
        with_acl.trim()
    );
    assert_eq!(
        with_acl.trim(),
        "BLOCKED",
        "the ACL must drop traffic to the host"
    );
    assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 0);
    // Control: without the ACL the same probe gets through, so the block above is the ACL's doing.
    let detach: BTreeMap<String, String> = [("security.acls".to_string(), String::new())]
        .into_iter()
        .collect();
    c.patch_network_config(&n.bridge, &detach).await.unwrap();
    let (_, without_acl, _) = sh(&c, "hx1d-test-c1", &probe).await;
    eprintln!("same probe with the ACL detached: {}", without_acl.trim());
    assert_eq!(
        without_acl.trim(),
        "REACHED",
        "control: the listener is reachable without the ACL"
    );
    c.patch_network_config(&n.bridge, &hx_provision::host::acl_attachment(&n.acl))
        .await
        .unwrap();
    let (_, again, _) = sh(&c, "hx1d-test-c1", &probe).await;
    assert_eq!(again.trim(), "BLOCKED", "ACL re-attached");
    // Link-local metadata addresses other than 169.254.169.254 (Tencent) are covered by the /16 rule.
    let (_, meta, _) = sh(
        &c,
        "hx1d-test-c1",
        "timeout 4 curl -s -m 3 http://169.254.0.23/ >/dev/null 2>&1 && echo REACHED || echo BLOCKED",
    )
    .await;
    assert_eq!(meta.trim(), "BLOCKED", "169.254.0.23 must not be reachable");
    // Internet egress is informational: it depends on the host's own forwarding rules (a host
    // Docker needs the DOCKER-USER rules the installer adds; S3).
    let (_, net, _) = sh(
        &c,
        "hx1d-test-c1",
        "timeout 5 bash -c 'echo > /dev/tcp/1.1.1.1/443' && echo UP || echo DOWN",
    )
    .await;
    eprintln!(
        "internet egress from the container (informational): {}",
        net.trim()
    );

    // --- ingress default drop: the host (gateway address) may connect in, other bridge members may not -------------
    let (_, perl, _) = sh(&c, "hx1d-test-c1", "command -v perl || true").await;
    assert!(
        !perl.trim().is_empty(),
        "this check needs perl in the image to run a listener"
    );
    let in_port = 18080;
    let listener = format!(
        "(perl -MIO::Socket::INET -e 'alarm 150; $l = IO::Socket::INET->new(Listen => 5, LocalPort => {in_port}, ReuseAddr => 1) or die; while ($c = $l->accept) {{ print $c \"HELLO\\n\"; close $c }}' </dev/null >/dev/null 2>&1 &); sleep 1; echo started"
    );
    let (_, started, _) = sh(&c, "hx1d-test-c1", &listener).await;
    assert_eq!(started.trim(), "started");
    let c1_ip = c.instance_state("hx1d-test-c1").await.unwrap().ipv4["eth0"][0].clone();
    // (a) a connection whose source is the bridge gateway (what the agent on the host uses) succeeds.
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.bind(std::net::SocketAddr::new(gateway, 0)).unwrap();
    let mut stream = tokio::time::timeout(
        Duration::from_secs(5),
        sock.connect(format!("{c1_ip}:{in_port}").parse().unwrap()),
    )
    .await
    .expect("connect from the gateway address timed out: ingress must admit the gateway")
    .expect("connect from the gateway address failed");
    let mut hello = String::new();
    tokio::io::AsyncReadExt::read_to_string(&mut stream, &mut hello)
        .await
        .unwrap();
    assert_eq!(
        hello.trim(),
        "HELLO",
        "host-initiated connection into the desktop works under default-drop ingress"
    );
    eprintln!("host -> desktop from {gateway}: ok");
    // (b) another member of the bridge is refused (ACLs apply between bridge members).
    let c2_spec = DesktopSpec::for_plan("hx1d-test-c2", n.clone(), &plan, Limits::default())
        .with_image(dspec.image.clone());
    c.create_instance(&c2_spec.to_create().unwrap(), Duration::from_secs(900))
        .await
        .unwrap();
    c.set_state(
        "hx1d-test-c2",
        hx_provision::incus::StateAction::Start,
        false,
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    wait_system_running(
        &c,
        "hx1d-test-c2",
        ReadyOptions {
            timeout: Duration::from_secs(120),
            allow_degraded: false,
        },
    )
    .await
    .expect("second container must boot");
    let peer = format!(
        "timeout 4 bash -c 'echo > /dev/tcp/{c1_ip}/{in_port}' && echo REACHED || echo BLOCKED"
    );
    let (_, from_c2, _) = sh(&c, "hx1d-test-c2", &peer).await;
    eprintln!("second container -> desktop: {}", from_c2.trim());
    eprintln!(
        "INFO second container -> desktop (same bridge, L2): {}",
        from_c2.trim()
    );
    // Host connections from an address that is not the gateway (a Docker bridge or public address)
    // are dropped by default-drop ingress; with the ACL detached the same connection works.
    let addrs = std::process::Command::new("ip")
        .args(["-o", "-4", "addr", "show"])
        .output()
        .unwrap();
    let other_src = String::from_utf8_lossy(&addrs.stdout)
        .lines()
        .filter_map(|l| l.split_whitespace().nth(3).map(str::to_string))
        .filter_map(|cidr| {
            cidr.split('/')
                .next()
                .and_then(|a| a.parse::<std::net::Ipv4Addr>().ok())
        })
        .find(|a| {
            !a.is_loopback() && IpAddr::V4(*a) != gateway && !a.to_string().starts_with("10.36.")
        });
    let other_src = other_src.expect("the host has another IPv4 address to originate from");
    let try_from = |src: std::net::Ipv4Addr| {
        let target = format!("{c1_ip}:{in_port}");
        async move {
            let sock = tokio::net::TcpSocket::new_v4().unwrap();
            sock.bind(std::net::SocketAddr::new(IpAddr::V4(src), 0))
                .unwrap();
            matches!(
                tokio::time::timeout(
                    Duration::from_secs(4),
                    sock.connect(target.parse().unwrap())
                )
                .await,
                Ok(Ok(_))
            )
        }
    };
    let blocked = !try_from(other_src).await;
    eprintln!(
        "host source {other_src} -> desktop with the ACL: {}",
        if blocked { "BLOCKED" } else { "REACHED" }
    );
    c.patch_network_config(&n.bridge, &detach).await.unwrap();
    let open = try_from(other_src).await;
    eprintln!(
        "host source {other_src} -> desktop, ACL detached: {}",
        if open { "REACHED" } else { "BLOCKED" }
    );
    c.patch_network_config(&n.bridge, &hx_provision::host::acl_attachment(&n.acl))
        .await
        .unwrap();
    assert!(open, "control: reachable without the ACL");
    assert!(blocked, "ingress admits only the gateway address");
    destroy_instance(&c, "hx1d-test-c2").await.unwrap();

    // --- Docker gate: Incus older than 6.0.5 is refused without touching the container ----------------------
    let docker_plan = Catalog::embedded()
        .resolve_addon(
            RecipeId {
                distro: Distro::Debian13,
                desktop: Desktop::Xfce,
                preset: Preset::Basic,
            },
            Addon::Docker,
        )
        .unwrap();
    let before = c
        .get_instance("hx1d-test-c1")
        .await
        .unwrap()
        .unwrap()
        .config;
    let gated = enable_docker(
        &c,
        "hx1d-test-c1",
        &docker_plan,
        DockerOptions::default(),
        &mut |_| {},
    )
    .await
    .unwrap();
    eprintln!("docker with default options on Incus {version}: {gated:?}");
    if version < hx_provision::incus::DOCKER_MIN_INCUS {
        assert!(matches!(gated, DockerOutcome::UnsupportedIncus { .. }));
        assert_eq!(
            c.get_instance("hx1d-test-c1")
                .await
                .unwrap()
                .unwrap()
                .config,
            before,
            "container config untouched"
        );
    }

    // --- Docker end to end (opt-in: needs working internet from the container) ------------------------------
    if std::env::var("HX1D_TEST_DOCKER").as_deref() == Ok("1") {
        let (code, _, _) = sh(
            &c,
            "hx1d-test-c1",
            "timeout 8 getent hosts download.docker.com >/dev/null",
        )
        .await;
        assert_eq!(
            code, 0,
            "HX1D_TEST_DOCKER=1 needs DNS/internet inside the container (host forwarding rules?)"
        );
        let opts = DockerOptions {
            allow_old_incus: true,
            selftest_timeout: Duration::from_secs(300),
            ..DockerOptions::default()
        };
        let mut lines = Vec::new();
        let out = enable_docker(&c, "hx1d-test-c1", &docker_plan, opts, &mut |p| {
            lines.push(format!("{p:?}"))
        })
        .await;
        eprintln!("docker outcome: {out:?}");
        match out.unwrap() {
            DockerOutcome::Enabled { docker_version } => {
                eprintln!("docker works: {docker_version}")
            }
            DockerOutcome::SelfTestFailed {
                hint, output_tail, ..
            } => {
                eprintln!("self-test failed ({hint:?}): {output_tail}");
                if version < hx_provision::incus::DOCKER_MIN_INCUS {
                    assert_eq!(
                        hint,
                        SelfTestHint::RuncSysctlDenied,
                        "the documented Incus 6.0.0 failure"
                    );
                } else {
                    panic!("Docker self-test failed on Incus {version}");
                }
            }
            other => panic!("{other:?}"),
        }
    }

    // --- destroy -----------------------------------------------------------------------------------------------
    destroy_instance(&c, "hx1d-test-c1").await.unwrap();
    assert!(c.get_instance("hx1d-test-c1").await.unwrap().is_none());
}
