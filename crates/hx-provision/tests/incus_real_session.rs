//! Build a real recipe into a real unprivileged, isolated-idmap Incus container through
//! hx-provision's own code path and check the in-container session units (ipc.md 6.11, 11, 21
//! item 3), plus the follow-up APIs against a real daemon. `#[ignore]`d, and also gated on
//! `HX3B_REAL=1`, because one run downloads and installs a desktop (many minutes).
//!
//! Everything it creates is named `hx3b-*` (pool, bridge, ACL, profiles, instance) and is removed
//! again, also before the run, in case an earlier one left objects behind. It never touches other
//! Incus objects and never loads the host firewall ruleset.
//!
//! ```text
//! HX3B_REAL=1 sg incus-admin -c 'cargo nextest run -p hx-provision --run-ignored only \
//!     --test incus_real_session --no-capture'
//! ```
//!
//! Environment:
//! - `HX3B_REAL=1`: required, otherwise the test returns at once.
//! - `HX3B_RECIPES`: comma-separated recipe names (default `ubuntu-24.04-xfce-basic`), for example
//!   `ubuntu-24.04-xfce-basic,debian-13-xfce-basic`. The first one also runs the API checks
//!   (limits, password, operations, device, Docker disable, teardown).
//! - `HX3B_HOST_PROXY=0`: do not use the host proxy (below). Default on.
//! - `HX_INCUS_SOCKET`: socket path.
//!
//! **Why a host proxy.** On a host that runs Docker, forwarded traffic from an Incus bridge is
//! dropped by Docker's FORWARD policy unless `DOCKER-USER` accepts it (README, "Tests against a
//! real Incus"), and this test must not change host firewall rules. So the test starts a small
//! forward proxy bound **only to the test bridge's gateway address**, detaches the *test bridge's*
//! ACL while packages are installed (Incus drops before it allows, so one port cannot be opened
//! while the gateway is dropped), re-attaches it afterwards, and points apt and curl in the container at it (before the build
//! stage; nothing else about the build differs from `build_on_server`). The proxy refuses every
//! port except 80 and 443.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use bytes::Bytes;
use hx_provision::host::{HostSpec, Naming, PoolSource, ensure_host};
use hx_provision::incus::{
    Client, ImageSource, LimitsUpdate, LinkOutcome, Request, SessionLink, StateAction, Transport,
    UnixTransport,
};
use hx_provision::orchestrate::{
    DesktopSpec, IncusExecutor, Limits, ReadyOptions, exec_captured, run_post_stage,
    wait_system_running,
};
use hx_provision::password::{PasswordChange, change_user_password};
use hx_provision::session::{PASSWORD_CHECK_HELPER, SESSION_BINARY};
use hx_provision::teardown::{Teardown, destroy_desktop, teardown_host};
use hx_provision::{
    Catalog, Distro, RecipeId, Secrets, Settings, Stage, Username, apply_stage, disable_docker,
};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const PREFIX: &str = "hx3b-";
const INSTANCE: &str = "hx3b-main";
const PASSWORD: &str = "hx3b-Throwaway-pw-1";
const NEW_PASSWORD: &str = "hx3b-Another-pw-2";

fn socket() -> String {
    std::env::var("HX_INCUS_SOCKET").unwrap_or_else(|_| UnixTransport::DEFAULT_SOCKET.to_string())
}

fn naming() -> Naming {
    Naming::with_prefix(PREFIX).unwrap()
}

macro_rules! evidence {
    ($label:expr, $($arg:tt)*) => {
        eprintln!("EVIDENCE [{}] {}", $label, format!($($arg)*).trim_end().replace('\n', "\n    | "))
    };
}

async fn raw(c: &UnixTransport, method: hyper::Method, path: &str, body: Value) -> Value {
    let r = c
        .send(Request {
            method,
            path: path.into(),
            headers: vec![],
            body: Bytes::from(serde_json::to_vec(&body).unwrap()),
            content_type: Some("application/json"),
            max_response: None,
            timeout: Duration::from_secs(60),
        })
        .await
        .unwrap();
    serde_json::from_slice(&r.body).unwrap_or(Value::Null)
}

/// Run `script` as root in the instance and return (exit code, stdout, stderr).
async fn sh(c: &Client<UnixTransport>, script: &str) -> (i32, String, String) {
    sh_in(c, INSTANCE, script).await
}

async fn sh_in(c: &Client<UnixTransport>, inst: &str, script: &str) -> (i32, String, String) {
    let argv = vec!["bash".to_string(), "-c".to_string(), script.to_string()];
    let r = exec_captured(c, inst, &argv, &[], None, None, Duration::from_secs(90))
        .await
        .unwrap_or_else(|e| panic!("exec `{script}`: {e}"));
    (r.exit_code, r.stdout, r.stderr)
}

fn sq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Run `script` as the desktop user `desk` (with its user-manager environment).
async fn sh_user(c: &Client<UnixTransport>, script: &str) -> (i32, String, String) {
    let wrapped = format!(
        "runuser -u desk -- env XDG_RUNTIME_DIR=/run/user/1000 DISPLAY=:0 XAUTHORITY=/run/hx-xorg/Xauthority bash -c {}",
        sq(script)
    );
    sh(c, &wrapped).await
}

async fn wait_for(
    c: &Client<UnixTransport>,
    what: &str,
    secs: u64,
    user: bool,
    script: &str,
) -> String {
    let t = Instant::now();
    loop {
        let (code, out, err) = if user {
            sh_user(c, script).await
        } else {
            sh(c, script).await
        };
        if code == 0 {
            return out;
        }
        if t.elapsed() > Duration::from_secs(secs) {
            let (_, st, _) = sh(
                c,
                "systemctl --failed --no-pager --plain; systemctl status hx-xorg.service --no-pager | tail -5",
            )
            .await;
            panic!(
                "timed out waiting for {what}: `{script}` exit {code}\nstdout: {out}\nstderr: {err}\n{st}"
            );
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Cached local image fingerprint for a distro, to avoid a download.
async fn local_image(distro: Distro) -> Option<String> {
    let (os, rel): (&str, &[&str]) = match distro {
        Distro::Ubuntu2404 => ("ubuntu", &["noble", "24.04"]),
        Distro::Ubuntu2604 => ("ubuntu", &["resolute", "26.04"]),
        Distro::Debian12 => ("debian", &["bookworm", "12"]),
        Distro::Debian13 => ("debian", &["trixie", "13"]),
    };
    let t = UnixTransport::new(socket());
    let v = raw(
        &t,
        hyper::Method::GET,
        "/1.0/images?recursion=1",
        Value::Null,
    )
    .await;
    v["metadata"].as_array()?.iter().find_map(|i| {
        let p = &i["properties"];
        let ok = p["os"].as_str().is_some_and(|s| s.eq_ignore_ascii_case(os))
            && p["release"].as_str().is_some_and(|r| rel.contains(&r))
            && i["type"] == "container"
            && i["architecture"] == "x86_64";
        ok.then(|| i["fingerprint"].as_str().map(str::to_string))?
    })
}

// ---------------------------------------------------------------------------------------------
// A forward proxy bound to the bridge gateway only (see the module docs)
// ---------------------------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------------------------

async fn cleanup(c: &Client<UnixTransport>) {
    if let Err(e) = destroy_desktop(c, INSTANCE).await {
        // Not marked (or an error): fall back to the plain destroy, which is ours by name.
        eprintln!("cleanup: destroy_desktop: {e}; forcing");
        let _ = hx_provision::destroy_instance(c, INSTANCE).await;
    }
    match teardown_host(c, &naming()).await {
        Ok(r) => eprintln!("cleanup: {r:?}"),
        Err(e) => eprintln!("cleanup: teardown_host: {e}"),
    }
}

fn recipe_id(name: &str) -> RecipeId {
    RecipeId::all()
        .into_iter()
        .find(|r| r.file_name() == format!("{name}.toml"))
        .unwrap_or_else(|| panic!("unknown recipe `{name}`"))
}

const STUB_SESSION: &str = r#"#!/bin/sh
# Stand-in for the hx-session daemon: records the environment it runs in, then idles.
out=/var/lib/hx-session/received/stub.out
{
  echo "uid=$(id -u) gid=$(id -g) user=$(id -un)"
  echo "DISPLAY=$DISPLAY"
  echo "XAUTHORITY=$XAUTHORITY"
  echo "XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR"
  echo "LISTEN_FDS=$LISTEN_FDS"
  echo "$(grep -E '^(NoNewPrivs|CapEff|CapBnd|Seccomp):' /proc/$$/status | tr '\n' ' ')"
  if (echo x > /etc/hx-stub-test) 2>/dev/null; then echo "write_etc=ALLOWED"; else echo "write_etc=DENIED"; fi
  if (echo x > /home/desk/hx-stub-test) 2>/dev/null; then echo "write_home=ALLOWED"; else echo "write_home=DENIED"; fi
  if (echo x > /var/lib/hx-session/received/rw-test) 2>/dev/null; then echo "write_received=ALLOWED"; else echo "write_received=DENIED"; fi
  if (exec 3<>/dev/tcp/127.0.0.1/9) 2>/dev/null; then echo "inet=ALLOWED"; else echo "inet=DENIED"; fi
  if xset q >/dev/null 2>&1; then echo "x11=REACHABLE"; else echo "x11=UNREACHABLE"; fi
  if ls /tmp/.X11-unix/X0 >/dev/null 2>&1; then echo "x11_socket_visible=yes"; else echo "x11_socket_visible=no"; fi
} > "$out" 2>&1
sleep 600 &
echo $! > /var/lib/hx-session/received/child.pid
wait
"#;

/// A fixed-argv stand-in for the `hx-pwcheck` helper (the real one ships with hx-session).
const STUB_PWCHECK: &str = r#"#!/bin/sh
[ $# -eq 1 ] || exit 2
hash=$(getent shadow "$1" | cut -d: -f2)
case "$hash" in '$'*) ;; *) exit 3;; esac
exec perl -e '$p = <STDIN>; chomp $p; exit(crypt($p, $ARGV[0]) eq $ARGV[0] ? 0 : 1)' "$hash"
"#;

#[tokio::test]
#[ignore = "builds a desktop in a real Incus container; set HX3B_REAL=1, see the module docs"]
async fn real_session_units_in_an_unprivileged_container() {
    if std::env::var("HX3B_REAL").as_deref() != Ok("1") {
        eprintln!("HX3B_REAL=1 is not set: skipping");
        return;
    }
    let c = Client::unix(socket());
    let info = c.server_info().await.unwrap_or_else(|e| {
        panic!("cannot use Incus: {e}; run as a member of incus-admin (sg incus-admin -c ...)")
    });
    evidence!("incus", "version {}", info.server_version);
    cleanup(&c).await;

    let recipes: Vec<String> = std::env::var("HX3B_RECIPES")
        .unwrap_or_else(|_| "ubuntu-24.04-xfce-basic".into())
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    let c2 = c.clone();
    // Every recipe runs in its own task: one failing recipe does not hide the others.
    let result = tokio::spawn(async move {
        let mut failed = Vec::new();
        for (i, r) in recipes.iter().enumerate() {
            let (c3, r3) = (c2.clone(), r.clone());
            let outcome = tokio::spawn(async move { run_one(&c3, &r3, i == 0).await }).await;
            eprintln!(
                "RESULT {r}: {}",
                if outcome.is_ok() { "PASS" } else { "FAIL" }
            );
            if outcome.is_err() {
                failed.push(r.clone());
            }
            if outcome.is_err() && std::env::var("HX3B_KEEP").as_deref() == Ok("1") {
                break;
            }
            // Next recipe starts from a fresh container (host objects stay).
            let _ = destroy_desktop(&c2, INSTANCE).await;
        }
        assert!(failed.is_empty(), "recipes that failed: {failed:?}");
    })
    .await;
    if std::env::var("HX3B_KEEP").as_deref() == Ok("1") {
        eprintln!("HX3B_KEEP=1: leaving the hx3b-* objects in place; delete them by hand");
        return result.unwrap();
    }
    cleanup(&c).await;

    // Everything of ours is gone again.
    let n = naming();
    assert!(c.get_instance(INSTANCE).await.unwrap().is_none());
    assert!(c.get_storage_pool(&n.pool).await.unwrap().is_none());
    assert!(c.get_network(&n.bridge).await.unwrap().is_none());
    assert!(!c.acl_exists(&n.acl).await.unwrap());
    assert!(!c.profile_exists(&n.desktop_profile).await.unwrap());
    assert!(!c.profile_exists(&n.compat_profile).await.unwrap());
    result.unwrap();
}

async fn run_one(c: &Client<UnixTransport>, recipe: &str, full: bool) {
    let n = naming();
    let id = recipe_id(recipe);
    evidence!("recipe", "{recipe}");

    // --- host objects ----------------------------------------------------------------------------
    let spec = HostSpec {
        naming: n.clone(),
        pool: PoolSource::LoopFile { size_gib: 24 },
        ipv4: "auto".into(),
        host_addresses: vec!["203.0.113.7".parse().unwrap()],
        allow_private_networks: false,
    };
    let host = ensure_host(c, &spec).await.unwrap();
    let gateway = host.gateway.expect("bridge gateway");

    // --- proxy for the container's package downloads (module docs) ------------------------------
    let use_proxy = std::env::var("HX3B_HOST_PROXY").as_deref() != Ok("0");
    let mut proxy = None;
    if use_proxy {
        let (port, handle) = start_proxy(gateway).await;
        proxy = Some((port, handle));
        // Incus evaluates drop rules before allow rules, so the gateway cannot be opened for one
        // port while it is dropped. The test bridge's ACL is therefore detached while packages
        // are installed and attached again afterwards (it is the test's own bridge).
        c.patch_network_config(
            &n.bridge,
            &[("security.acls".to_string(), String::new())].into(),
        )
        .await
        .unwrap();
        evidence!(
            "proxy",
            "listening on {gateway}:{port} (bridge gateway only)"
        );
    }

    // --- plan with settings, container creation (as `launch` does) ---------------------------------
    let settings = Settings::none()
        .with_hostname("hx3b-desk")
        .unwrap()
        .with_timezone_in("Europe/Berlin", std::path::Path::new("/usr/share/zoneinfo"))
        .unwrap()
        .with_locale("de_DE")
        .unwrap()
        .with_keyboard("de+nodeadkeys")
        .unwrap();
    let plan = Catalog::embedded()
        .resolve_with(id, &[], None, &settings)
        .unwrap();
    let image = match local_image(id.distro).await {
        Some(fp) => ImageSource::LocalFingerprint(fp),
        None => hx_provision::orchestrate::image_source(&plan.base_image),
    };
    evidence!("image", "{image:?}");
    let dspec = DesktopSpec::for_plan(
        INSTANCE,
        n.clone(),
        &plan,
        Limits {
            cpu: Some(4),
            memory_mib: Some(4096),
            disk_gib: None,
            processes: None,
        },
    )
    .with_image(image);
    let started = Instant::now();
    c.create_instance(&dspec.to_create().unwrap(), Duration::from_secs(900))
        .await
        .unwrap();
    c.set_state(INSTANCE, StateAction::Start, false, Duration::from_secs(60))
        .await
        .unwrap();
    wait_system_running(c, INSTANCE, ReadyOptions::default())
        .await
        .unwrap();

    let inst = c.get_instance(INSTANCE).await.unwrap().unwrap();
    evidence!(
        "isolation",
        "security.privileged={:?} security.idmap.isolated={:?} user.hx.state={:?}",
        inst.config.get("security.privileged"),
        inst.config.get("security.idmap.isolated"),
        inst.config.get("user.hx.state")
    );
    assert_eq!(inst.config["security.privileged"], "false");
    assert_eq!(inst.config["security.idmap.isolated"], "true");
    assert_eq!(inst.config["user.hx.state"], "creating");
    let (_, um, _) = sh(c, "cat /proc/self/uid_map").await;
    evidence!("uid_map", "{um}");
    assert!(!um.contains("4294967295"), "must be unprivileged: {um}");

    if let Some((port, _)) = &proxy {
        let p = format!("http://{gateway}:{port}");
        c.push_file(
            INSTANCE,
            "/etc/apt/apt.conf.d/99hx3b-proxy",
            format!("Acquire::http::Proxy \"{p}\";\nAcquire::https::Proxy \"{p}\";\n").as_bytes(),
            0o644,
        )
        .await
        .unwrap();
        c.push_file(
            INSTANCE,
            "/root/.curlrc",
            format!("proxy = \"{p}\"\n").as_bytes(),
            0o600,
        )
        .await
        .unwrap();
    }

    // --- build and post stage ---------------------------------------------------------------------
    let exec = IncusExecutor::new(c, INSTANCE);
    let build = apply_stage(&exec, &plan, Stage::Build, &Secrets::none(), &mut |p| {
        if let hx_provision::Progress::Finished {
            step, elapsed, ok, ..
        } = p
        {
            eprintln!(
                "  build  {:>6.0?}  {}  {}",
                elapsed,
                if *ok { "ok " } else { "WARN" },
                &step[..step.len().min(70)]
            );
        }
    })
    .await
    .unwrap_or_else(|e| panic!("build stage failed: {e}"));
    evidence!(
        "build",
        "done; {} warnings, took {:?} since create",
        build.warnings.len(),
        started.elapsed()
    );
    let secrets = Secrets::none().with_user_password(PASSWORD).unwrap();
    let post = run_post_stage(c, INSTANCE, &plan, &secrets, &mut |p| {
        if let hx_provision::Progress::Finished {
            step, elapsed, ok, ..
        } = p
        {
            eprintln!(
                "  post   {:>6.0?}  {}  {}",
                elapsed,
                if *ok { "ok " } else { "WARN" },
                &step[..step.len().min(70)]
            );
        }
    })
    .await
    .unwrap_or_else(|e| panic!("post stage failed: {e}"));
    evidence!("post", "done; warnings: {:?}", post.warnings);
    if proxy.is_some() {
        c.patch_network_config(&n.bridge, &hx_provision::host::acl_attachment(&n.acl))
            .await
            .unwrap();
        let net = c.get_network(&n.bridge).await.unwrap().unwrap();
        assert_eq!(net.config["security.acls"], n.acl, "ACL attached again");
    }

    // --- settings took effect ---------------------------------------------------------------------
    let (_, s, _) = sh(
        c,
        "echo hostname=$(cat /etc/hostname); echo tz=$(cat /etc/timezone) $(readlink /etc/localtime); echo locale=$(grep ^LANG= /etc/default/locale); locale -a | grep -c de_DE; cat /etc/default/keyboard",
    )
    .await;
    evidence!("settings", "{s}");
    assert!(s.contains("hostname=hx3b-desk") && s.contains("tz=Europe/Berlin"));
    assert!(
        s.contains("LANG=de_DE.UTF-8")
            && s.contains("XKBLAYOUT=\"de\"")
            && s.contains("XKBVARIANT=\"nodeadkeys\"")
    );

    // --- install the stand-ins for the hx-session package and boot into the session ------------------
    sh(c, "install -d -m 0755 /usr/lib/hx-session").await;
    c.push_file(INSTANCE, SESSION_BINARY, STUB_SESSION.as_bytes(), 0o755)
        .await
        .unwrap();
    c.push_file(
        INSTANCE,
        PASSWORD_CHECK_HELPER,
        STUB_PWCHECK.as_bytes(),
        0o755,
    )
    .await
    .unwrap();
    c.set_state(
        INSTANCE,
        StateAction::Restart,
        false,
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    let ready = wait_system_running(c, INSTANCE, ReadyOptions::default()).await;
    evidence!("boot", "wait_system_running after restart: {ready:?}");
    ready.expect(
        "the system must reach `running` (no failed unit) after boot with the session units",
    );

    // --- 1. hx-xsession.service brings up the XFCE session ---------------------------------------
    wait_for(
        c,
        "hx-xsession.service active",
        120,
        true,
        "systemctl --user is-active hx-xsession.service",
    )
    .await;
    wait_for(
        c,
        "xfwm4 and xfce4-session running",
        90,
        true,
        "pgrep -x xfce4-session && pgrep -x xfwm4 && pgrep -x xfdesktop",
    )
    .await;
    let (_, x, _) = sh_user(
        c,
        "systemctl --user is-active hx-xsession.service; systemctl --user is-enabled hx-xsession.service; pgrep -a -u desk 'xfce4-session|xfwm4|xfdesktop|xfce4-panel' | cut -c1-60; xprop -root _NET_SUPPORTING_WM_CHECK _NET_WM_NAME 2>&1 | head -2; xdpyinfo | grep -E 'dimensions|vendor string' ",
    )
    .await;
    evidence!("hx-xsession.service", "{x}");
    assert!(x.contains("active") && x.contains("xfce4-session") && x.contains("1920x1080"));
    let (_, old, _) = sh(c, "ls /etc/systemd/user/ | grep -c '^hx-session' || true; systemctl cat hx-session.service | head -3").await;
    evidence!("old-unit-name", "{old}");
    assert!(
        old.lines().next() == Some("0"),
        "no user unit called hx-session.service is left"
    );

    // --- 2. /run/hx-session is root:root 0755, the socket is the desktop user's, 0600 ---------------
    let (_, st, _) = sh(
        c,
        "stat -c '%n %U:%G %a %F' /run/hx-session /run/hx-session/link.sock; id desk; systemctl is-active hx-session.socket; systemctl is-active hx-session.service || true",
    )
    .await;
    evidence!("socket", "{st}");
    assert!(
        st.contains("/run/hx-session root:root 755 directory"),
        "{st}"
    );
    assert!(
        st.contains("/run/hx-session/link.sock desk:desk 600 socket"),
        "{st}"
    );
    assert!(st.contains("uid=1000(desk) gid=1000(desk)"), "{st}");
    let states: Vec<&str> = st.lines().rev().take(2).collect();
    assert_eq!(
        states,
        ["inactive", "active"],
        "socket listening, service idle until connected: {st}"
    );
    // Nobody else can connect; the desktop user cannot replace the path.
    let perl_connect = "perl -MSocket -e 'socket(S,PF_UNIX,SOCK_STREAM,0); connect(S,sockaddr_un(\"/run/hx-session/link.sock\")) or do { print \"connect failed: $!\\n\"; exit 1 }; print \"connected\\n\"; sleep 2'";
    let (code, out, _) = sh(c, &format!("runuser -u nobody -- {perl_connect}")).await;
    evidence!("other-user-connect", "exit {code}: {out}");
    assert_ne!(
        code, 0,
        "another account must not be able to connect: {out}"
    );
    let (_, st2, _) = sh(c, "systemctl is-active hx-session.service || true").await;
    assert_eq!(
        st2.trim(),
        "inactive",
        "a refused connection starts nothing"
    );
    let (_, tamper, _) = sh_user(
        c,
        "for cmd in 'rm -f /run/hx-session/link.sock' 'mv /run/hx-session/link.sock /run/hx-session/x' 'ln -sfn /tmp/evil /run/hx-session/link.sock' 'mv /run/hx-session /run/hx-session.old' 'touch /run/hx-session/new'; do if sh -c \"$cmd\" 2>/dev/null; then echo \"ALLOWED: $cmd\"; else echo \"denied:  $cmd\"; fi; done",
    )
    .await;
    evidence!("tamper-as-desktop-user", "{tamper}");
    assert!(!tamper.contains("ALLOWED"), "{tamper}");

    // --- 3. the first connection starts hx-session.service as the desktop user ---------------------
    let (code, out, err) = sh_user(c, perl_connect).await;
    evidence!(
        "first-connection-as-desktop-user",
        "exit {code}: {out}{err}"
    );
    assert_eq!(code, 0, "{err}");
    wait_for(
        c,
        "hx-session.service active",
        30,
        false,
        "systemctl is-active hx-session.service",
    )
    .await;
    wait_for(
        c,
        "stub output",
        30,
        false,
        "grep -q x11_socket_visible /var/lib/hx-session/received/stub.out",
    )
    .await;
    let (_, stub, _) = sh(c, "cat /var/lib/hx-session/received/stub.out").await;
    evidence!("stub-view-from-inside-hx-session.service", "{stub}");
    for want in [
        "uid=1000 gid=1000 user=desk",
        "DISPLAY=:0",
        "XAUTHORITY=/run/hx-xorg/Xauthority",
        "XDG_RUNTIME_DIR=/run/user/1000",
        "LISTEN_FDS=1",
        "NoNewPrivs:\t1",
        "CapEff:\t0000000000000000",
        "write_etc=DENIED",
        "write_home=DENIED",
        "write_received=ALLOWED",
        "inet=DENIED",
        "x11=REACHABLE",
        "x11_socket_visible=yes",
    ] {
        assert!(stub.contains(want), "missing `{want}` in:\n{stub}");
    }
    let (_, dropins, _) = sh(
        c,
        "systemctl cat hx-session.service --no-pager | grep -E '^# /|NoNewPriv|ProtectSystem|ProtectHome|PrivateNetwork' ; ls /etc/systemd/system/service.d /run/systemd/system/service.d /usr/lib/systemd/system/service.d 2>&1 | head",
    )
    .await;
    evidence!("unit files and drop-ins", "{dropins}");
    // Everything Incus's own drop-in sets, in full: nothing in it may weaken what the unit asks
    // for beyond the keys we know (and re-enable NoNewPrivileges for).
    let (_, lxc, _) = sh(c, "cat /run/systemd/system/service.d/zzz-lxc-service.conf").await;
    evidence!(
        "/run/systemd/system/service.d/zzz-lxc-service.conf",
        "{lxc}"
    );
    let known_off = [
        "ProcSubset=all",
        "ProtectProc=default",
        "ProtectControlGroups=no",
        "ProtectKernelTunables=no",
        "NoNewPrivileges=no",
        "LoadCredential=",
        "PrivateNetwork=no",
        "PrivateTmp=no",
        "ProtectClock=no",
        "PrivateUsers=no",
        "MemoryDenyWriteExecute=no",
        "ProtectHostname=no",
    ];
    for line in lxc
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && *l != "[Service]")
    {
        assert!(
            known_off.contains(&line)
                || line.starts_with("ProtectKernelModules=")
                || line.starts_with("ProtectKernelLogs=")
                || line.starts_with("ProtectHome=")
                || line.starts_with("ProtectSystem=")
                || line.starts_with("LockPersonality=")
                || line.starts_with("RestrictAddressFamilies=")
                || line.starts_with("RestrictNamespaces="),
            "unexpected setting in Incus's service.d drop-in: {line}"
        );
        // It must not loosen anything hx-session.service sets itself.
        for ours in [
            "ProtectSystem=",
            "ProtectHome=",
            "LockPersonality=",
            "RestrictAddressFamilies=",
        ] {
            if let Some(v) = line.strip_prefix(ours) {
                assert!(
                    (ours == "ProtectSystem=" && matches!(v, "strict" | "full" | "yes"))
                        || (ours == "ProtectHome=" && matches!(v, "read-only" | "yes" | "tmpfs"))
                        || (ours == "LockPersonality=" && v == "yes")
                        || (ours == "RestrictAddressFamilies=" && v.contains("AF_UNIX")),
                    "Incus's drop-in loosens {line}"
                );
            }
        }
    }
    let (_, show, _) = sh(
        c,
        "systemctl show hx-session.service -p ActiveState -p SubState -p User -p MainPID -p KillMode -p Restart -p RestartUSec -p NoNewPrivileges -p CapabilityBoundingSet -p RestrictAddressFamilies -p ProtectSystem -p ProtectHome -p ReadWritePaths -p LockPersonality -p SystemCallFilter -p TasksMax -p MemoryMax -p PrivateNetwork -p PrivateTmp -p StartLimitIntervalUSec -p StartLimitBurst -p FragmentPath | cut -c1-150",
    )
    .await;
    evidence!("systemctl show hx-session.service", "{show}");
    for want in [
        "ActiveState=active",
        "User=1000",
        "KillMode=control-group",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "ReadWritePaths=/var/lib/hx-session/received /var/lib/hx-session/clipboard",
        "LockPersonality=yes",
        "PrivateNetwork=no",
        "PrivateTmp=no",
        "TasksMax=512",
        "MemoryMax=2147483648",
    ] {
        assert!(show.contains(want), "missing `{want}` in:\n{show}");
    }
    assert!(show.contains("RestrictAddressFamilies=AF_UNIX"), "{show}");
    let (_, pid_user, _) = sh(
        c,
        "pid=$(systemctl show hx-session.service -p MainPID --value); ps -o user:12=,pid=,cmd= -p $pid | cut -c1-80; grep -E 'NoNewPrivs|CapEff|Seccomp:' /proc/$pid/status | tr '\\n' ' '",
    )
    .await;
    evidence!("process-of-hx-session.service", "{pid_user}");
    assert!(pid_user.starts_with("desk"), "{pid_user}");
    let (_, sec, _) = sh(c, "systemd-analyze security hx-session.service --no-pager 2>&1 | grep -E '^(✓|✗|→|\\*)|Overall|NAME' | cut -c1-110 | head -60").await;
    evidence!("systemd-analyze security hx-session.service", "{sec}");

    // --- KillMode=control-group: stopping the service ends what the daemon started -------------------
    let (_, before, _) = sh(
        c,
        "pid=$(cat /var/lib/hx-session/received/child.pid); kill -0 $pid && echo child-alive",
    )
    .await;
    assert!(before.contains("child-alive"), "{before}");
    let (_, after, _) = sh(
        c,
        "pid=$(cat /var/lib/hx-session/received/child.pid); systemctl stop hx-session.service; sleep 1; kill -0 $pid 2>/dev/null && echo child-survived || echo child-gone",
    )
    .await;
    evidence!("KillMode=control-group", "{after}");
    assert!(after.contains("child-gone"), "{after}");
    // The fixed RestartSession sequence works from any state and the first connection restarts it.
    let (code, _, err) = sh(
        c,
        "systemctl reset-failed hx-session.socket hx-session.service && systemctl restart hx-session.socket hx-session.service && sleep 1 && systemctl is-active hx-session.socket hx-session.service",
    )
    .await;
    assert_eq!(code, 0, "{err}");

    if !full {
        return;
    }

    // --- API checks against the real daemon (first recipe only) -----------------------------------
    api_checks(c).await;
    let _ = proxy;
}

async fn api_checks(c: &Client<UnixTransport>) {
    // (d) limits on the live instance, including the root disk size.
    let applied = c
        .set_limits(
            INSTANCE,
            &LimitsUpdate {
                cpu: Some(2),
                memory_mib: Some(3072),
                disk_gib: Some(12),
            },
        )
        .await
        .unwrap();
    evidence!("set_limits", "{applied:?}");
    assert!(
        applied.restart_required,
        "a CPU count change on a running instance"
    );
    let (_, lim, _) = sh(
        c,
        "echo cpus=$(cat /sys/fs/cgroup/cpuset.cpus.effective); echo memory.max=$(cat /sys/fs/cgroup/memory.max); echo pids.max=$(cat /sys/fs/cgroup/pids.max); fallocate -l 13G /var/tmp/hx3b-quota-test 2>&1; echo fallocate13G_exit=$?; rm -f /var/tmp/hx3b-quota-test",
    )
    .await;
    evidence!("limits seen inside the running container", "{lim}");
    // Memory and the disk quota apply at once; a 13 GiB allocation must hit the 12 GiB quota.
    // The CPU count is still the old one on Incus 6.0.0 (hence `restart_required`): it is
    // checked after the restart below.
    let cpu_count = |lim: &str| -> u32 {
        lim.lines()
            .find_map(|l| l.strip_prefix("cpus="))
            .unwrap()
            .trim()
            .split(',')
            .map(|r| match r.split_once('-') {
                Some((a, b)) => b.parse::<u32>().unwrap() - a.parse::<u32>().unwrap() + 1,
                None => 1,
            })
            .sum()
    };
    evidence!("cpuset before the restart", "{} CPUs", cpu_count(&lim));
    assert!(lim.contains(&format!("memory.max={}", 3072u64 << 20)));
    assert!(
        !lim.contains("fallocate13G_exit=0"),
        "the 12 GiB quota must stop a 13 GiB allocation: {lim}"
    );
    assert!(lim.contains("pids.max=8192"), "limits.processes untouched");
    let inst = c.get_instance(INSTANCE).await.unwrap().unwrap();
    assert_eq!(inst.devices["root"]["size"], "12GiB");
    assert_eq!(inst.devices["root"]["pool"], naming().pool);
    // After a restart the new CPU count is in force and memory and quota survived.
    c.set_state(
        INSTANCE,
        StateAction::Restart,
        false,
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    wait_system_running(c, INSTANCE, ReadyOptions::default())
        .await
        .unwrap();
    let (_, lim2, _) = sh(
        c,
        "echo cpus=$(cat /sys/fs/cgroup/cpuset.cpus.effective); echo memory.max=$(cat /sys/fs/cgroup/memory.max)",
    )
    .await;
    evidence!("limits after the restart", "{lim2}");
    assert_eq!(cpu_count(&lim2), 2);
    assert!(lim2.contains(&format!("memory.max={}", 3072u64 << 20)));
    // Same call again converges.
    c.set_limits(
        INSTANCE,
        &LimitsUpdate {
            disk_gib: Some(12),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    // (b) check the current password and set a new one, against the real shadow file.
    let user = Username::new("desk").unwrap();
    let hash = |c: Client<UnixTransport>| async move {
        sh(&c, "getent shadow desk | cut -d: -f2")
            .await
            .1
            .trim()
            .to_string()
    };
    let h0 = hash(c.clone()).await;
    let wrong = Secrets::none()
        .with_user_password(NEW_PASSWORD)
        .unwrap()
        .with_current_password("not-the-password")
        .unwrap();
    let r = change_user_password(c, INSTANCE, &user, wrong, true)
        .await
        .unwrap();
    evidence!("password change with a wrong current password", "{r:?}");
    assert_eq!(r, PasswordChange::CurrentPasswordWrong);
    assert_eq!(hash(c.clone()).await, h0, "nothing changed");
    let right = Secrets::none()
        .with_user_password(NEW_PASSWORD)
        .unwrap()
        .with_current_password(PASSWORD)
        .unwrap();
    let r = change_user_password(c, INSTANCE, &user, right, true)
        .await
        .unwrap();
    evidence!("password change with the right current password", "{r:?}");
    assert_eq!(r, PasswordChange::Changed);
    let h1 = hash(c.clone()).await;
    assert_ne!(h1, h0);
    let (_, left, _) = sh(c, "ls -A /run/hx-provision | grep -c stdin- || true; journalctl --no-pager 2>/dev/null | grep -c -F -e hx3b-Throwaway -e hx3b-Another || true").await;
    evidence!(
        "secret files left in /run/hx-provision, secret text in journal",
        "{left}"
    );
    assert_eq!(left.lines().collect::<Vec<_>>(), ["0", "0"]);
    // The new password now checks out as the current one (helper missing -> would be unavailable).
    let again = Secrets::none()
        .with_user_password(PASSWORD)
        .unwrap()
        .with_current_password(NEW_PASSWORD)
        .unwrap();
    assert_eq!(
        change_user_password(c, INSTANCE, &user, again, true)
            .await
            .unwrap(),
        PasswordChange::Changed
    );
    sh(
        c,
        "mv /usr/lib/hx-session/hx-pwcheck /usr/lib/hx-session/hx-pwcheck.off",
    )
    .await;
    let unavailable = Secrets::none()
        .with_user_password(NEW_PASSWORD)
        .unwrap()
        .with_current_password(PASSWORD)
        .unwrap();
    let r = change_user_password(c, INSTANCE, &user, unavailable, true)
        .await
        .unwrap();
    evidence!("password change with the helper missing", "{r:?}");
    assert!(
        matches!(r, PasswordChange::CheckUnavailable { .. }),
        "{r:?}"
    );
    sh(
        c,
        "mv /usr/lib/hx-session/hx-pwcheck.off /usr/lib/hx-session/hx-pwcheck",
    )
    .await;

    // (c) a running Incus operation can be cancelled and waited for after its future is dropped.
    let scoped = c.scoped();
    let s2 = scoped.clone();
    let task = tokio::spawn(async move {
        let argv = vec!["sleep".to_string(), "300".to_string()];
        exec_captured(
            &s2,
            INSTANCE,
            &argv,
            &[],
            None,
            None,
            Duration::from_secs(300),
        )
        .await
    });
    let t = Instant::now();
    while scoped.in_flight_operations().is_empty() && t.elapsed() < Duration::from_secs(20) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let ids = scoped.in_flight_operations();
    evidence!("in-flight operations while `sleep 300` runs", "{ids:?}");
    assert_eq!(ids.len(), 1);
    task.abort();
    let _ = task.await;
    assert_eq!(
        scoped.in_flight_operations().len(),
        1,
        "the dropped future left it listed"
    );
    // Found on Incus 6.0.0: a command started through the exec API cannot be cancelled ("This
    // operation can't be cancelled", may_cancel=false), so cancel_in_flight reports it stuck. What
    // ends it is stopping the instance (forced), which is what privd's STUCK_OPERATION handling
    // has to do before it cleans up; the in-container `timeout` bounds it otherwise.
    let cancelled = scoped.cancel_in_flight(Duration::from_secs(3)).await;
    evidence!("cancel_in_flight on an exec operation", "{cancelled:?}");
    assert_eq!(cancelled.as_ref().unwrap_err().len(), 1);
    c.set_state(INSTANCE, StateAction::Stop, true, Duration::from_secs(30))
        .await
        .unwrap();
    let ended = scoped.cancel_in_flight(Duration::from_secs(30)).await;
    evidence!("cancel_in_flight after a forced stop", "{ended:?}");
    assert_eq!(ended, Ok(1));
    assert!(scoped.in_flight_operations().is_empty());
    c.set_state(INSTANCE, StateAction::Start, false, Duration::from_secs(60))
        .await
        .unwrap();
    wait_system_running(c, INSTANCE, ReadyOptions::default())
        .await
        .unwrap();
    let (_, sl, _) = sh(c, "pgrep -x -f 'sleep 300' | wc -l").await;
    evidence!(
        "`sleep 300` processes left after the forced stop",
        "{}",
        sl.trim()
    );
    assert_eq!(sl.trim(), "0");

    // (e) already checked above (settings). (g) Docker disable on the real instance.
    let on: std::collections::BTreeMap<String, String> = [
        "security.nesting",
        "security.syscalls.intercept.mknod",
        "security.syscalls.intercept.setxattr",
    ]
    .into_iter()
    .map(|k| (k.to_string(), "true".to_string()))
    .collect();
    c.patch_instance_config(INSTANCE, &on).await.unwrap();
    let out = disable_docker(c, INSTANCE).await.unwrap();
    let cfg = c.get_instance(INSTANCE).await.unwrap().unwrap().config;
    evidence!(
        "disable_docker",
        "{out:?}; nesting={:?} mknod={:?} setxattr={:?}",
        cfg.get("security.nesting"),
        cfg.get("security.syscalls.intercept.mknod"),
        cfg.get("security.syscalls.intercept.setxattr")
    );
    assert!(out.restarted);
    assert!(on.keys().all(|k| cfg[k] == "false"));
    assert!(!disable_docker(c, INSTANCE).await.unwrap().restarted);
    wait_system_running(c, INSTANCE, ReadyOptions::default())
        .await
        .unwrap();

    // (a) the proxy device on the real daemon: Incus accepts exactly these properties.
    c.set_state(INSTANCE, StateAction::Stop, false, Duration::from_secs(60))
        .await
        .unwrap();
    let link = SessionLink::new("main", (990, 990), (1000, 1000)).unwrap();
    assert_eq!(
        c.add_session_link(INSTANCE, &link).await.unwrap(),
        LinkOutcome::Added
    );
    let dev = c.get_instance(INSTANCE).await.unwrap().unwrap().devices["hx-link"].clone();
    evidence!("device hx-link as stored by Incus", "{dev:?}");
    assert_eq!(dev, link.device());
    assert_eq!(
        c.add_session_link(INSTANCE, &link).await.unwrap(),
        LinkOutcome::Unchanged
    );
    // PATCH vs PUT semantics for a device: what does a PATCH with a partial device leave behind?
    let t = UnixTransport::new(socket());
    let mut stale = link.device();
    stale.insert("proxy_protocol".into(), "true".into());
    stale.insert("uid".into(), "5".into());
    raw(
        &t,
        hyper::Method::PATCH,
        &format!("/1.0/instances/{INSTANCE}"),
        serde_json::json!({"devices": {"hx-link": stale}}),
    )
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let patched = raw(
        &t,
        hyper::Method::PATCH,
        &format!("/1.0/instances/{INSTANCE}"),
        serde_json::json!({"devices": {"hx-link": {"type": "proxy", "bind": "host",
            "listen": "unix:/run/hx/link/main.sock", "connect": "unix:/run/hx-session/link.sock",
            "security.uid": "1000", "security.gid": "1000"}}}),
    )
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let after_patch = c.get_instance(INSTANCE).await.unwrap().unwrap().devices["hx-link"].clone();
    evidence!(
        "a PATCH with a partial hx-link device leaves",
        "{after_patch:?} (response {})",
        patched["status"]
    );
    // Whatever PATCH does, add_session_link must end with exactly the wanted device.
    let outcome = c.add_session_link(INSTANCE, &link).await.unwrap();
    let now = c.get_instance(INSTANCE).await.unwrap().unwrap().devices["hx-link"].clone();
    evidence!("add_session_link after stale keys", "{outcome:?}: {now:?}");
    assert_eq!(now, link.device(), "no stale key survives a replace");
    assert!(!now.contains_key("proxy_protocol"));
    assert!(c.remove_session_link(INSTANCE).await.unwrap());
    assert!(
        !c.get_instance(INSTANCE)
            .await
            .unwrap()
            .unwrap()
            .devices
            .contains_key("hx-link")
    );
    assert!(!c.remove_session_link(INSTANCE).await.unwrap());

    // (h) teardown deletes only marked objects, against real objects.
    // An unmarked profile with our name survives teardown_host; the instance is marked and goes.
    let r = destroy_desktop(c, INSTANCE).await.unwrap();
    evidence!("destroy_desktop", "{r:?}");
    assert!(r.instance_removed);
    assert!(c.get_instance(INSTANCE).await.unwrap().is_none());
    let n = naming();
    c.delete_profile(&n.compat_profile).await.unwrap();
    c.create_profile(&hx_provision::incus::ProfileSpec {
        name: n.compat_profile.clone(),
        description: "somebody else's profile".into(),
        config: Default::default(),
        devices: Default::default(),
    })
    .await
    .unwrap();
    let t = teardown_host(c, &n).await.unwrap();
    evidence!("teardown_host with one unmarked object", "{t:?}");
    assert_eq!(t.desktop_profile, Teardown::Removed);
    assert_eq!(t.compat_profile, Teardown::SkippedUnmarked);
    assert_eq!(
        (t.network, t.acl, t.pool),
        (Teardown::Removed, Teardown::Removed, Teardown::Removed)
    );
    assert!(
        c.profile_exists(&n.compat_profile).await.unwrap(),
        "the unmarked profile survived"
    );
    c.delete_profile(&n.compat_profile).await.unwrap();
    // run_one's caller destroys the (already gone) instance: that is a success.
}
