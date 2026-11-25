//! The prebuilt-image path against a real Incus: what image CI does, run once locally.
//!
//! 1. Build an image with `build_image` (build stage, seal, stop, verify), `incus publish
//!    --compression zstd` and `incus image export`, and check that the exported file's SHA-256 is
//!    the Incus fingerprint.
//! 2. Import it with the streaming upload: a wrong fingerprint is rejected, the right one is
//!    accepted, the alias works, a second import conflicts.
//! 3. Create a desktop from it for user `alice` with `finish_prebuilt` (post stage with the user
//!    rename, restart, `running`), delete the image while the instance exists (btrfs), and restart
//!    the instance to show it does not depend on the image.
//! 4. Build the same desktop with `build_on_server`, collect facts from both desktops and run
//!    `equiv::compare`. The drifts are printed; the test fails on any error-level drift unless
//!    `HX1D_ALLOW_DRIFT=1`.
//!
//! `#[ignore]`d and gated on `HX1D_REAL=1`: it builds two desktops (tens of minutes on a loaded
//! host). Every object is named `hx1d-img-*` (pool, bridge, ACL, profiles, instances, image
//! aliases) and is removed again, also before the run. Nothing else on the daemon is touched and
//! no host firewall rule is changed.
//!
//! ```text
//! HX1D_REAL=1 sg incus-admin -c 'cargo nextest run -p hx-provision --run-ignored only \
//!     --test incus_real_image --no-capture'
//! ```
//!
//! Environment: `HX1D_REAL=1` (required); `HX1D_RECIPE` (default `ubuntu-24.04-xfce-basic`);
//! `HX1D_OUT=<dir>` writes the facts and the drift table there; `HX1D_ALLOW_DRIFT=1`;
//! `HX1D_KEEP=1` leaves the objects in place; `HX_INCUS_SOCKET`.
//!
//! **Network.** As in `incus_real_session.rs`, forwarded traffic from an Incus bridge is dropped
//! on a host that runs Docker, and this test must not change host rules. It therefore bakes an
//! apt and curl proxy (a forward proxy bound to the test bridge's gateway only) into a copy of the
//! cached base image, and builds from that copy. Both desktops start from the same copy.

use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use hx_provision::equiv::{collect_facts, compare, has_errors, render_table};
use hx_provision::host::{HostSpec, Naming, PoolSource, ensure_host};
use hx_provision::incus::{Client, ImageSource, ImageUpload, IncusError, UnixTransport};
use hx_provision::orchestrate::{
    DesktopSpec, Limits, build_image, build_on_server, destroy_instance, finish_prebuilt,
};
use hx_provision::teardown::teardown_host;
use hx_provision::{Catalog, Distro, Progress, RecipeId, Secrets, Settings, Username};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const PREFIX: &str = "hx1d-img-";
const BUILDER: &str = "hx1d-img-build";
const BASE0: &str = "hx1d-img-base0";
const INST_A: &str = "hx1d-img-a";
const INST_B: &str = "hx1d-img-b";
const ALIAS_BASE: &str = "hx1d-img-base";
const ALIAS_PUB: &str = "hx1d-img-pub";
const ALIAS_IMPORTED: &str = "hx-img-hx1d-img-test";
const USER: &str = "alice";
const PASSWORD: &str = "hx1d-Throwaway-pw-1";

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

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn file_sha256(p: &Path) -> String {
    let mut f = std::fs::File::open(p).unwrap();
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    hex(&h.finalize())
}

/// Run the `incus` CLI (the test runs inside `sg incus-admin`); returns stdout.
async fn incus(args: &[&str]) -> Result<String, String> {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    tokio::task::spawn_blocking(move || {
        let out = std::process::Command::new("incus")
            .args(&args)
            .output()
            .map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).into_owned())
        }
    })
    .await
    .unwrap()
}

async fn local_image(c: &Client<UnixTransport>, distro: Distro) -> Option<String> {
    let (os, rel): (&str, &[&str]) = match distro {
        Distro::Ubuntu2404 => ("ubuntu", &["noble", "24.04"]),
        Distro::Ubuntu2604 => ("ubuntu", &["resolute", "26.04"]),
        Distro::Debian12 => ("debian", &["bookworm", "12"]),
        Distro::Debian13 => ("debian", &["trixie", "13"]),
    };
    c.list_images().await.ok()?.into_iter().find_map(|i| {
        let ok = i
            .properties
            .get("os")
            .is_some_and(|s| s.eq_ignore_ascii_case(os))
            && i.properties
                .get("release")
                .is_some_and(|r| rel.contains(&r.as_str()));
        ok.then_some(i.fingerprint)
    })
}

async fn fingerprint_of_alias(c: &Client<UnixTransport>, alias: &str) -> Option<String> {
    c.list_images()
        .await
        .ok()?
        .into_iter()
        .find(|i| i.aliases.iter().any(|a| a == alias))
        .map(|i| i.fingerprint)
}

// ---- forward proxy bound to the bridge gateway (see the module docs) --------------------------

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
    for i in [BUILDER, BASE0, INST_A, INST_B] {
        let _ = destroy_instance(c, i).await;
    }
    // Imported images carry our alias; the CLI-published ones are removed by alias.
    if let Ok(images) = c.list_images().await {
        for img in images {
            if img.aliases.iter().any(|a| a == ALIAS_IMPORTED) {
                let _ = c.delete_image(&img.fingerprint).await;
            }
        }
    }
    for a in [ALIAS_PUB, ALIAS_BASE] {
        let _ = incus(&["image", "delete", a]).await;
    }
    match teardown_host(c, &naming()).await {
        Ok(r) => eprintln!("cleanup: {r:?}"),
        Err(e) => eprintln!("cleanup: teardown_host: {e}"),
    }
}

fn progress(label: &'static str) -> impl FnMut(&Progress) + Send {
    move |p| {
        if let Progress::Finished {
            step, elapsed, ok, ..
        } = p
        {
            eprintln!(
                "  {label:<6} {:>6.0?}  {}  {}",
                elapsed,
                if *ok { "ok " } else { "WARN" },
                &step[..step.len().min(70)]
            );
        }
    }
}

fn recipe_id(name: &str) -> RecipeId {
    RecipeId::all()
        .into_iter()
        .find(|r| r.file_name() == format!("{name}.toml"))
        .unwrap_or_else(|| panic!("unknown recipe `{name}`"))
}

fn limits() -> Limits {
    Limits {
        cpu: Some(4),
        memory_mib: Some(4096),
        disk_gib: None,
        processes: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "builds two desktops in a real Incus; set HX1D_REAL=1, see the module docs"]
async fn real_image_build_import_and_equivalence() {
    if std::env::var("HX1D_REAL").as_deref() != Ok("1") {
        eprintln!("HX1D_REAL=1 is not set: skipping");
        return;
    }
    let c = Client::unix(socket());
    let info = c
        .server_info()
        .await
        .unwrap_or_else(|e| panic!("cannot use Incus: {e}; run inside `sg incus-admin -c`"));
    evidence!("incus", "version {}", info.server_version);
    cleanup(&c).await;
    let c2 = c.clone();
    let result = tokio::spawn(async move { run(&c2).await }).await;
    if std::env::var("HX1D_KEEP").as_deref() == Ok("1") {
        eprintln!("HX1D_KEEP=1: leaving the hx1d-img-* objects in place");
        return result.unwrap();
    }
    cleanup(&c).await;
    let n = naming();
    for i in [BUILDER, BASE0, INST_A, INST_B] {
        assert!(c.get_instance(i).await.unwrap().is_none(), "{i} is gone");
    }
    assert!(c.get_storage_pool(&n.pool).await.unwrap().is_none());
    assert!(
        c.list_images().await.unwrap().iter().all(|i| i
            .aliases
            .iter()
            .all(|a| !a.starts_with("hx1d-img-") && a != ALIAS_IMPORTED)),
        "no image of ours is left"
    );
    result.unwrap();
}

async fn run(c: &Client<UnixTransport>) {
    let recipe = std::env::var("HX1D_RECIPE").unwrap_or_else(|_| "ubuntu-24.04-xfce-basic".into());
    let id = recipe_id(&recipe);
    let n = naming();
    let t0 = Instant::now();
    evidence!("recipe", "{recipe}");

    // --- host objects, proxy, proxied base image ---------------------------------------------
    let host = ensure_host(
        c,
        &HostSpec {
            naming: n.clone(),
            pool: PoolSource::LoopFile { size_gib: 40 },
            ipv4: "auto".into(),
            host_addresses: vec!["203.0.113.7".parse().unwrap()],
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
        "listening on {gateway}:{port} (bridge gateway only)"
    );

    let default_plan = Catalog::embedded().resolve(id, &[]).unwrap();
    let settings = Settings::none()
        .with_timezone_in("Europe/Berlin", Path::new("/usr/share/zoneinfo"))
        .unwrap()
        .with_locale("de_DE")
        .unwrap()
        .with_keyboard("de+nodeadkeys")
        .unwrap();
    let alice = Username::new(USER).unwrap();
    let alice_plan = Catalog::embedded()
        .resolve_with(id, &[], Some(&alice), &settings)
        .unwrap();

    let cached = local_image(c, id.distro)
        .await
        .expect("a cached base image for the distro (run any earlier real test first)");
    let base0 = DesktopSpec::for_plan(BASE0, n.clone(), &default_plan, limits())
        .with_image(ImageSource::LocalFingerprint(cached));
    c.create_instance(&base0.to_create().unwrap(), Duration::from_secs(900))
        .await
        .unwrap();
    let p = format!("http://{gateway}:{port}");
    c.push_file(
        BASE0,
        "/etc/apt/apt.conf.d/99hx1d-proxy",
        format!("Acquire::http::Proxy \"{p}\";\nAcquire::https::Proxy \"{p}\";\n").as_bytes(),
        0o644,
    )
    .await
    .unwrap();
    c.push_dir(BASE0, "/root", 0o700).await.unwrap();
    c.push_file(
        BASE0,
        "/root/.curlrc",
        format!("proxy = \"{p}\"\n").as_bytes(),
        0o600,
    )
    .await
    .unwrap();
    incus(&["publish", BASE0, "--alias", ALIAS_BASE])
        .await
        .unwrap();
    destroy_instance(c, BASE0).await.unwrap();
    let base_fp = fingerprint_of_alias(c, ALIAS_BASE)
        .await
        .expect("base image");
    let base = ImageSource::LocalFingerprint(base_fp.clone());
    evidence!("base", "proxied copy of the cached image: {base_fp}");

    // --- 1. build, seal, publish, export ---------------------------------------------------------
    let started = Instant::now();
    let spec =
        DesktopSpec::for_plan(BUILDER, n.clone(), &default_plan, limits()).with_image(base.clone());
    let build = build_image(c, &default_plan, &spec, &mut progress("image"))
        .await
        .unwrap_or_else(|e| panic!("build_image: {e}"));
    evidence!(
        "build_image",
        "done in {:?} ({} warnings); instance is {:?}",
        started.elapsed(),
        build.warnings.len(),
        c.get_instance(BUILDER).await.unwrap().unwrap().status
    );

    incus(&[
        "publish",
        BUILDER,
        "--alias",
        ALIAS_PUB,
        "--compression",
        "zstd",
    ])
    .await
    .unwrap_or_else(|e| panic!("incus publish: {e}"));
    let pub_fp = fingerprint_of_alias(c, ALIAS_PUB)
        .await
        .expect("published image");
    let out_dir: PathBuf = std::env::var_os("HX1D_OUT")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(format!("hx1d-img-export-{}", std::process::id()));
    std::fs::create_dir_all(&out_dir).unwrap();
    incus(&["image", "export", &pub_fp, out_dir.to_str().unwrap()])
        .await
        .unwrap_or_else(|e| panic!("incus image export: {e}"));
    let exported: Vec<PathBuf> = std::fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    evidence!("export", "files: {exported:?}");
    assert_eq!(exported.len(), 1, "a single unified file");
    let image_file = exported[0].clone();
    let size = std::fs::metadata(&image_file).unwrap().len();
    let sha = file_sha256(&image_file);
    evidence!(
        "export",
        "{} bytes, sha256 {sha}, fingerprint {pub_fp}, name {:?}",
        size,
        image_file.file_name().unwrap()
    );
    assert_eq!(sha, pub_fp, "the file's sha256 is the Incus fingerprint");
    // Remove the published copy so the import below is a real import.
    incus(&["image", "delete", ALIAS_PUB]).await.unwrap();
    assert!(c.get_image(&pub_fp).await.unwrap().is_none());

    // --- 2. import --------------------------------------------------------------------------------
    let open = || std::fs::File::open(&image_file).unwrap();
    let wrong = hex(&Sha256::digest(b"not this image"));
    let before = c.list_images().await.unwrap().len();
    let t = Instant::now();
    let err = c
        .import_image(
            ImageUpload {
                file: open(),
                len: size,
                fingerprint: wrong.clone(),
            },
            Duration::from_secs(900),
        )
        .await
        .expect_err("a wrong fingerprint must be rejected");
    evidence!(
        "fingerprint-mismatch",
        "rejected after {:?}: {err:?}",
        t.elapsed()
    );
    assert!(
        matches!(err, IncusError::Api { .. } | IncusError::Operation(_)),
        "{err:?}"
    );
    assert_eq!(
        c.list_images().await.unwrap().len(),
        before,
        "nothing was stored under either fingerprint"
    );
    assert!(c.get_image(&wrong).await.unwrap().is_none());
    assert!(c.get_image(&pub_fp).await.unwrap().is_none());

    let t = Instant::now();
    let fp = c
        .import_image(
            ImageUpload {
                file: open(),
                len: size,
                fingerprint: pub_fp.clone(),
            },
            Duration::from_secs(900),
        )
        .await
        .unwrap_or_else(|e| panic!("import_image: {e}"));
    evidence!("import", "{size} bytes streamed in {:?}", t.elapsed());
    assert_eq!(fp, pub_fp);
    c.create_image_alias(ALIAS_IMPORTED, &fp).await.unwrap();
    let info = c.get_image(&fp).await.unwrap().unwrap();
    evidence!(
        "image",
        "aliases {:?}, size {}, properties {:?}",
        info.aliases,
        info.size,
        info.properties
    );
    assert_eq!(info.aliases, [ALIAS_IMPORTED]);
    assert_eq!(info.size, size);
    assert_eq!(
        fingerprint_of_alias(c, ALIAS_IMPORTED).await.as_deref(),
        Some(fp.as_str())
    );
    let dup = c
        .import_image(
            ImageUpload {
                file: open(),
                len: size,
                fingerprint: pub_fp.clone(),
            },
            Duration::from_secs(900),
        )
        .await
        .expect_err("importing again conflicts");
    evidence!("duplicate-import", "{dup:?}");
    // The alias works as an instance source (an alias, not a fingerprint).
    // (Exercised by the launch below, which uses the fingerprint; alias launch is checked here.)
    // `delete_image` refuses an image that does not carry an hx-img- alias.
    let foreign = c.delete_image(&base_fp).await;
    evidence!("delete-guard", "{foreign:?}");
    assert!(matches!(foreign, Err(IncusError::InvalidArgument(_))));

    // --- 3. prebuilt path: finish_prebuilt for alice, restart, running ------------------------------
    let secrets = Secrets::none().with_user_password(PASSWORD).unwrap();
    let t = Instant::now();
    let spec_b = DesktopSpec::for_plan(INST_B, n.clone(), &alice_plan, limits())
        .with_image(ImageSource::LocalAlias(ALIAS_IMPORTED.into()));
    finish_prebuilt(c, &alice_plan, &spec_b, &secrets, &mut progress("post-b"))
        .await
        .unwrap_or_else(|e| panic!("finish_prebuilt: {e}"));
    evidence!(
        "prebuilt",
        "create + post stage + restart in {:?}",
        t.elapsed()
    );
    let b = c.get_instance(INST_B).await.unwrap().unwrap();
    assert_eq!(b.status.to_ascii_lowercase(), "running");
    let (code, passwd, _) = sh(c, INST_B, "getent passwd alice desk; echo ---; ls /home").await;
    evidence!("rename", "exit {code}\n{passwd}");
    assert!(passwd.contains("alice:") && !passwd.contains("desk:"));
    let mid_b = c
        .read_file(INST_B, "/etc/machine-id", 256)
        .await
        .unwrap()
        .unwrap();
    evidence!("machine-id", "B has {} bytes after boot", mid_b.len());
    assert!(mid_b.len() >= 32, "a fresh machine id was generated");

    // After the instance exists the image is no longer needed (btrfs).
    assert!(c.delete_image(&fp).await.unwrap(), "image deleted");
    assert!(c.get_image(&fp).await.unwrap().is_none());
    hx_provision::orchestrate::wait_system_running(c, INST_B, Default::default())
        .await
        .unwrap();
    c.set_state(
        INST_B,
        hx_provision::incus::StateAction::Restart,
        false,
        Duration::from_secs(120),
    )
    .await
    .unwrap();
    hx_provision::orchestrate::wait_system_running(c, INST_B, Default::default())
        .await
        .unwrap();
    evidence!(
        "delete-image",
        "deleted with the instance present; the instance restarted and is running"
    );

    // --- 4. build path and the equivalence check -----------------------------------------------------
    let t = Instant::now();
    let spec_a = DesktopSpec::for_plan(INST_A, n.clone(), &alice_plan, limits()).with_image(base);
    build_on_server(c, &alice_plan, &spec_a, &secrets, &mut progress("build-a"))
        .await
        .unwrap_or_else(|e| panic!("build_on_server: {e}"));
    evidence!("build-path", "built on the server in {:?}", t.elapsed());

    let t = Instant::now();
    let fa = collect_facts(c, INST_A, USER).await.unwrap();
    let fb = collect_facts(c, INST_B, USER).await.unwrap();
    evidence!(
        "facts",
        "collected in {:?}: A {} packages / {} etc entries, B {} / {}",
        t.elapsed(),
        fa.packages.len(),
        fa.etc.len(),
        fb.packages.len(),
        fb.etc.len()
    );
    let drifts = compare(&fa, &fb, &default_plan.manifest());
    let table = render_table(&drifts);
    evidence!("equivalence", "{} drifts\n{table}", drifts.len());
    if let Some(dir) = std::env::var_os("HX1D_OUT") {
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("facts-a.json"),
            serde_json::to_vec_pretty(&fa).unwrap(),
        )
        .unwrap();
        std::fs::write(
            dir.join("facts-b.json"),
            serde_json::to_vec_pretty(&fb).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.join("drifts.md"), &table).unwrap();
    }
    // The XDG folders are made by the post stage in the chosen language (de_DE), so no session
    // program falls back to an English ~/Desktop beside ~/Schreibtisch (recipes/README.md).
    let home = format!("/home/{USER}");
    for (name, f) in [("A", &fa), ("B", &fb)] {
        let paths: Vec<&str> = f.trees[&home].iter().map(|x| x.path.as_str()).collect();
        assert!(
            paths.contains(&format!("{home}/Schreibtisch").as_str()),
            "{name}: no ~/Schreibtisch"
        );
        assert!(
            !paths.contains(&format!("{home}/Desktop").as_str()),
            "{name}: an English ~/Desktop beside ~/Schreibtisch"
        );
    }
    evidence!("total", "{:?}", t0.elapsed());
    if std::env::var("HX1D_ALLOW_DRIFT").as_deref() != Ok("1") {
        assert!(
            !has_errors(&drifts),
            "the desktops are not equivalent:\n{table}"
        );
    }
}

async fn sh(c: &Client<UnixTransport>, inst: &str, script: &str) -> (i32, String, String) {
    let argv = vec!["bash".to_string(), "-c".to_string(), script.to_string()];
    let r = hx_provision::orchestrate::exec_captured(
        c,
        inst,
        &argv,
        &[],
        None,
        None,
        Duration::from_secs(90),
    )
    .await
    .unwrap_or_else(|e| panic!("exec `{script}`: {e}"));
    (r.exit_code, r.stdout, r.stderr)
}
