//! The probes of ipc.md 24 ("Why this mechanism is correct"), automated against a real Incus
//! daemon. `#[ignore]`d: it needs access to the Incus unix socket (membership of `incus-admin`, or
//! root), a cached Debian 13 container image, and `rustc` on `PATH` (or `$RUSTC`) to build the
//! static test fixture. It creates throwaway objects only and removes them before and after:
//!
//! - the storage pool `hx2w-test-pool` (a 4 GiB btrfs loop pool; never the `default` pool),
//! - the instance `hx2w-test-src` and its `hx-backup-...` snapshot,
//! - the restore target `hx-restore-hx2wtest` (marked, copied from the source),
//! - the helpers `hx-bkw-7e57ba5e` and `hx-bkw-7e57ba5f` (a helper's name is fixed by the contract,
//!   so the test recognises its own by these two job ids),
//! - the directory `/tmp/hx2w-test-<uid>` with the host side of the repository link.
//!
//! Run, from the repository root, as a user that may use Incus:
//!
//! ```text
//! sg incus-admin -c 'cargo test -p hx-provision --test incus_real_backup -- --ignored --nocapture --test-threads=1'
//! ```
//!
//! Environment: `HX_INCUS_SOCKET` (default `/var/lib/incus/unix.socket`).
//!
//! The fixture (`tests/fixtures/backup_probe.rs`) is a std-only program compiled with
//! `rustc -C target-feature=+crt-static`: the helper's rootfs is empty, so its PID 1 must be a
//! static executable. It plays the worker (reads `/src`, or writes `/dst`, and reports over the
//! repository link) and, pushed into the source container and the restored target, the data
//! generator and checker.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bytes::Bytes;
use hx_provision::host::Naming;
use hx_provision::incus::{
    BackupHelperSpec, Client, ExecSpec, HelperEnd, ImageSource, InstanceCreate, JobId,
    PreconditionFailed, ProfileSpec, RepoLink, Request, RestoreTargetName, RestoreTargetSpec,
    SnapshotMount, StateAction, TargetMount, Transport, UnixTransport, description_is_marked,
};
use hx_provision::orchestrate::{
    ReadyOptions, destroy_instance, exec_captured, wait_system_running,
};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const POOL: &str = "hx2w-test-pool";
/// A desktop's instance name is `hx-<id>`; the id carries the test prefix.
const SRC: &str = "hx-hx2wtest";
const PREFIX: &str = "hx2w-test-";
const TARGET: &str = "hx-restore-hx2wtest";
const JOB_BACKUP: &str = "7e57ba5e000000000000000000000001";
const JOB_RESTORE: &str = "7e57ba5f000000000000000000000002";
const SNAPSHOT: &str = "hx-backup-20261126T170000Z-7e57";
const PROBE_IN_SRC: &str = "/usr/local/bin/hxprobe";

fn socket() -> String {
    std::env::var("HX_INCUS_SOCKET").unwrap_or_else(|_| UnixTransport::DEFAULT_SOCKET.to_string())
}

async fn connect() -> Client<UnixTransport> {
    let c = Client::unix(socket());
    match c.server_info().await {
        Ok(info) => {
            eprintln!(
                "OBS incus {} (api {}, auth {}), kernel {}",
                info.server_version, info.api_version, info.auth, info.kernel_version
            );
            c
        }
        Err(e) => panic!(
            "cannot use Incus at {}: {e}\nThese tests need access to the socket: run them as a member of `incus-admin`, \
             e.g. sg incus-admin -c 'cargo test -p hx-provision --test incus_real_backup -- --ignored --nocapture'",
            socket()
        ),
    }
}

fn job(hex: &str) -> JobId {
    JobId::from_hex(hex).unwrap()
}

fn my_uid() -> u32 {
    std::fs::metadata("/proc/self")
        .map(|m| m.uid())
        .expect("/proc/self")
}

fn link_dir() -> PathBuf {
    std::env::temp_dir().join(format!("hx2w-test-{}", my_uid()))
}

fn naming() -> Naming {
    Naming::with_prefix(PREFIX).unwrap()
}

/// Whether `path` is a real directory (not a symlink) owned by the user running the test.
fn is_my_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .is_ok_and(|m| m.file_type().is_dir() && !m.file_type().is_symlink() && m.uid() == my_uid())
}

/// Remove everything this suite may have created. Each object is checked before it is deleted:
/// the pool and the profile by the hash-xcreen description and the test prefix, the desktop by its
/// `user.hx.state` marker and a root disk on the test pool, the helpers and the target by their
/// kind and job markers (the client calls refuse anything else), the scratch directory by being a
/// real directory of ours.
async fn cleanup(c: &Client<UnixTransport>) {
    for hex in [JOB_BACKUP, JOB_RESTORE] {
        if let Err(e) = c.force_delete_backup_helper(job(hex)).await {
            eprintln!("cleanup: helper of {hex}: {e}");
        }
    }
    if let Err(e) = c
        .delete_restore_target(
            &RestoreTargetName::new(TARGET).unwrap(),
            Some(job(JOB_RESTORE)),
        )
        .await
    {
        eprintln!("cleanup: restore target: {e}");
    }
    match c.get_instance(SRC).await {
        Ok(Some(i))
            if i.config.contains_key("user.hx.state")
                && i.expanded_devices
                    .get("root")
                    .and_then(|r| r.get("pool"))
                    .map(String::as_str)
                    == Some(POOL) =>
        {
            if let Err(e) = destroy_instance(c, SRC).await {
                eprintln!("cleanup: {SRC}: {e}");
            }
        }
        Ok(Some(_)) => eprintln!("cleanup: {SRC} exists but is not ours: left alone"),
        Ok(None) => {}
        Err(e) => eprintln!("cleanup: {SRC}: {e}"),
    }
    let n = naming();
    if let Ok(Some(p)) = c.get_profile(&n.desktop_profile).await
        && description_is_marked(&p.description)
        && n.desktop_profile.starts_with(PREFIX)
        && let Err(e) = c.delete_profile(&n.desktop_profile).await
    {
        eprintln!("cleanup: profile: {e}");
    }
    if let Ok(Some(p)) = c.get_storage_pool(POOL).await
        && description_is_marked(&p.description)
        && POOL.starts_with(PREFIX)
        && let Err(e) = c.delete_storage_pool(POOL).await
    {
        eprintln!("cleanup: pool: {e}");
    }
    let dir = link_dir();
    if is_my_real_dir(&dir) {
        let _ = std::fs::remove_dir_all(&dir);
    } else if dir.symlink_metadata().is_ok() {
        eprintln!(
            "cleanup: {} is not a real directory of ours: left alone",
            dir.display()
        );
    }
}

/// Fingerprint of a cached Debian 13 container image (a download would make the test depend on
/// the internet).
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
            .is_some_and(|s| s.eq_ignore_ascii_case("debian"));
        let rel = matches!(p["release"].as_str(), Some("trixie") | Some("13"));
        (debian && rel && i["type"] == "container" && i["architecture"] == "x86_64")
            .then(|| i["fingerprint"].as_str().map(str::to_string))?
    })
}

/// Compile the fixture into `dir` as a static executable and return its bytes.
fn build_fixture(dir: &Path) -> Vec<u8> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/backup_probe.rs");
    let out = dir.join("backup_probe");
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let r = std::process::Command::new(&rustc)
        .args([
            "--edition",
            "2024",
            "-O",
            "-C",
            "target-feature=+crt-static",
        ])
        .args(["-C", "strip=symbols"])
        .arg(&src)
        .arg("-o")
        .arg(&out)
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "cannot run `{rustc}` to build the fixture ({e}); put rustc on PATH or set RUSTC"
            )
        });
    assert!(
        r.status.success(),
        "building the fixture failed (needs glibc static libs, libc.a):\n{}",
        String::from_utf8_lossy(&r.stderr)
    );
    let bytes = std::fs::read(&out).unwrap();
    eprintln!("OBS fixture built: {} bytes", bytes.len());
    bytes
}

async fn sh(c: &Client<UnixTransport>, instance: &str, argv: &[&str]) -> (i32, String, String) {
    let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    let r = exec_captured(c, instance, &argv, &[], None, None, Duration::from_secs(60))
        .await
        .unwrap_or_else(|e| panic!("exec {argv:?} in {instance}: {e}"));
    (r.exit_code, r.stdout, r.stderr)
}

/// Connect to the host side of the repository link (retrying every 200 ms for 30 s, as privd
/// does), send `go`, optionally half-close, and read until the peer closes.
async fn talk(socket: &Path, half_close: bool) -> (String, Duration) {
    let started = Instant::now();
    let mut stream = loop {
        match UnixStream::connect(socket).await {
            Ok(s) => break s,
            Err(e) if started.elapsed() < Duration::from_secs(30) => {
                let _ = e;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(e) => panic!("cannot connect to {} within 30 s: {e}", socket.display()),
        }
    };
    let connected = started.elapsed();
    stream.write_all(b"go\n").await.unwrap();
    if half_close {
        stream.shutdown().await.unwrap();
    }
    let mut buf = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(60), stream.read_to_end(&mut buf)).await;
    if let Ok(Err(e)) = &read {
        eprintln!("OBS link read ended with: {e}");
    }
    assert!(read.is_ok(), "the helper did not answer within 60 s");
    (String::from_utf8_lossy(&buf).into_owned(), connected)
}

/// The `entry=` and `shadow` lines of a report (the part that can be compared with `dump`).
fn data_lines(text: &str) -> String {
    text.lines()
        .filter(|l| l.starts_with("entry=") || l.starts_with("shadow"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn field<'a>(report: &'a str, line_start: &str, key: &str) -> Option<&'a str> {
    report
        .lines()
        .find(|l| l.starts_with(line_start))?
        .split_whitespace()
        .find_map(|w| w.strip_prefix(key)?.strip_prefix('='))
}

#[tokio::test]
#[ignore = "needs access to a real Incus daemon, a cached Debian 13 image and rustc; see the module docs"]
async fn real_backup_helper_probes() {
    let c = connect().await;
    cleanup(&c).await;
    let c2 = c.clone();
    let result = tokio::spawn(async move { probes(c2).await }).await;
    cleanup(&c).await;
    // Everything of ours is gone again.
    assert!(
        c.get_storage_pool(POOL).await.unwrap().is_none(),
        "pool left behind"
    );
    assert!(
        c.get_instance(SRC).await.unwrap().is_none(),
        "{SRC} left behind"
    );
    assert!(
        c.get_instance(TARGET).await.unwrap().is_none(),
        "{TARGET} left behind"
    );
    let left: Vec<String> = c
        .list_backup_helpers()
        .await
        .unwrap()
        .into_iter()
        .filter(|h| h.job == job(JOB_BACKUP) || h.job == job(JOB_RESTORE))
        .map(|h| h.name.to_string())
        .collect();
    assert!(left.is_empty(), "helpers left behind: {left:?}");
    assert!(
        link_dir().symlink_metadata().is_err(),
        "link directory left behind"
    );
    assert!(
        c.get_profile(&naming().desktop_profile)
            .await
            .unwrap()
            .is_none(),
        "profile left behind"
    );
    eprintln!("OBS cleanup verified: no pool, source, target, helper or link directory left");
    result.unwrap();
}

async fn probes(c: Client<UnixTransport>) {
    let started = Instant::now();
    let work = link_dir();
    // `create_dir`, not `create_dir_all`: an existing path (a symlink planted in /tmp, say) is an
    // error, and what we got must be a real directory of ours.
    std::fs::create_dir(&work).unwrap_or_else(|e| panic!("create {}: {e}", work.display()));
    assert!(
        is_my_real_dir(&work),
        "{} is not a real directory of ours",
        work.display()
    );
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let owner = {
        let m = std::fs::symlink_metadata(&work).unwrap();
        (m.uid(), m.gid())
    };
    let fixture = build_fixture(&work);

    // --- the source container, its data and a snapshot -----------------------------------------
    let image = local_debian13_image()
        .await
        .expect("no cached Debian 13 container image (this test does not download one)");
    c.create_storage_pool(
        POOL,
        "btrfs",
        &[("size".to_string(), "4GiB".to_string())].into(),
    )
    .await
    .unwrap();
    c.create_profile(&ProfileSpec {
        name: naming().desktop_profile,
        description: "hash-xcreen: test desktop profile".into(),
        config: Default::default(),
        devices: Default::default(),
    })
    .await
    .unwrap();
    c.create_instance(
        &InstanceCreate {
            name: SRC.into(),
            image: ImageSource::LocalFingerprint(image),
            profiles: vec![naming().desktop_profile],
            config: [
                ("security.idmap.isolated", "true"),
                ("security.privileged", "false"),
                ("security.guestapi", "false"),
                ("user.hx.state", "ready"),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
            devices: [(
                "root".to_string(),
                [("type", "disk"), ("path", "/"), ("pool", POOL)]
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            )]
            .into(),
        },
        Duration::from_secs(300),
    )
    .await
    .unwrap();
    c.set_state(SRC, StateAction::Start, false, Duration::from_secs(60))
        .await
        .unwrap();
    wait_system_running(
        &c,
        SRC,
        ReadyOptions {
            timeout: Duration::from_secs(120),
            allow_degraded: true,
        },
    )
    .await
    .expect("the source container must boot");
    c.push_file(SRC, PROBE_IN_SRC, &fixture, 0o755)
        .await
        .unwrap();
    let (code, _, err) = sh(&c, SRC, &[PROBE_IN_SRC, "make", "/probe"]).await;
    assert_eq!(code, 0, "make: {err}");
    let (_, expected, _) = sh(&c, SRC, &[PROBE_IN_SRC, "dump", "/probe", "/"]).await;
    eprintln!("OBS source container's own view:\n{expected}");
    assert!(
        expected.contains("entry=a uid=1234 gid=4321")
            && expected.contains("entry=b uid=1000 gid=1000")
            && expected.contains("shadow uid=0")
            && expected.contains("readable=yes"),
        "{expected}"
    );
    c.create_snapshot(SRC, SNAPSHOT).await.unwrap();

    // --- the guard, with every input it read ---------------------------------------------------
    let info = c.server_info().await.unwrap();
    let pool_info = c.get_storage_pool(POOL).await.unwrap().unwrap();
    let desktop = c.get_instance(SRC).await.unwrap().unwrap();
    let snap = c
        .list_snapshots(SRC)
        .await
        .unwrap()
        .into_iter()
        .find(|s| s.name == SNAPSHOT)
        .expect("the snapshot is listed");
    eprintln!(
        "OBS guard inputs: kernel_features.idmapped_mounts={:?} pool.driver={:?} desktop root pool={:?} \
         desktop volatile.last_state.idmap={:?} snapshot volatile.last_state.idmap={:?}",
        info.kernel_features.get("idmapped_mounts"),
        pool_info.driver,
        desktop
            .expanded_devices
            .get("root")
            .and_then(|r| r.get("pool")),
        desktop.config.get("volatile.last_state.idmap"),
        snap.config.get("volatile.last_state.idmap"),
    );
    assert_eq!(
        info.kernel_features
            .get("idmapped_mounts")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(pool_info.driver, "btrfs");
    assert_eq!(
        desktop
            .config
            .get("volatile.last_state.idmap")
            .map(String::as_str),
        Some("[]")
    );
    assert_eq!(
        snap.config
            .get("volatile.last_state.idmap")
            .map(String::as_str),
        Some("[]")
    );
    eprintln!(
        "OBS source container config keys: {:?}",
        desktop.config.keys().collect::<Vec<_>>()
    );
    let mount = SnapshotMount::checked(&info, &pool_info, &desktop, &snap)
        .expect("the checks before a backup pass");
    eprintln!(
        "OBS SnapshotMount::checked passed; source = {}",
        mount.source()
    );
    // The checks are not a formality: the same objects with one input changed are refused.
    let mut shifted = snap.clone();
    shifted.config.insert(
        "volatile.last_state.idmap".into(),
        "[{\"Isuid\":true}]".into(),
    );
    assert!(matches!(
        SnapshotMount::checked(&info, &pool_info, &desktop, &shifted),
        Err(PreconditionFailed::SnapshotIdmap { .. })
    ));
    let mut other = snap.clone();
    other.instance = "hx-other".into();
    assert!(matches!(
        SnapshotMount::checked(&info, &pool_info, &desktop, &other),
        Err(PreconditionFailed::SnapshotOfOther { .. })
    ));

    // --- backup: the helper reads the snapshot through `src` -----------------------------------
    let bjob = job(JOB_BACKUP);
    let spec = BackupHelperSpec::backup(
        mount,
        RepoLink::in_dir(bjob, work.to_str().unwrap(), owner).unwrap(),
    );
    let sock = PathBuf::from(spec.link().socket_path());
    c.create_backup_helper(&spec).await.unwrap();
    let def = c.get_instance(spec.name().as_str()).await.unwrap().unwrap();
    assert!(def.profiles.is_empty(), "no profiles: {:?}", def.profiles);
    let nics: Vec<_> = def
        .expanded_devices
        .iter()
        .filter(|(_, d)| d.get("type").map(String::as_str) == Some("nic"))
        .collect();
    assert!(nics.is_empty(), "no NIC in the definition: {nics:?}");
    assert_eq!(def.config["user.hx.kind"], "backup-worker");
    assert_eq!(def.config["user.hx.job"], JOB_BACKUP);
    c.populate_backup_helper(&spec, &fixture).await.unwrap();
    c.start_backup_helper(bjob).await.unwrap();
    let listed = c.list_backup_helpers().await.unwrap();
    assert!(
        listed
            .iter()
            .any(|h| h.name == spec.name() && h.job == bjob),
        "crash recovery would find the helper: {listed:?}"
    );
    let (report, connected_after) = talk(&sock, false).await;
    eprintln!("OBS backup helper's report (connected after {connected_after:?}):\n{report}");
    assert_eq!(
        data_lines(&report),
        data_lines(&expected),
        "ids, modes, capability, xattr, fifo and /etc/shadow through `src` are the container's own"
    );
    let cap = field(&report, "entry=cap", "cap").unwrap();
    assert_eq!(cap.len(), 40, "a v2 file capability is 20 bytes: {cap}");
    assert!(cap.starts_with("01000002"), "VFS_CAP_REVISION_2: {cap}");
    assert_eq!(field(&report, "entry=ux", "xattr"), Some("hx-probe-value"));
    assert_eq!(field(&report, "entry=fifo", "kind"), Some("fifo"));
    assert_eq!(field(&report, "entry=a", "uid"), Some("1234"));
    assert_eq!(field(&report, "entry=a", "gid"), Some("4321"));
    assert_eq!(field(&report, "entry=b", "uid"), Some("1000"));
    assert!(report.contains("shadow uid=0 gid=42") && report.contains("readable=yes"));
    assert!(
        report.contains("write errno=30"),
        "EROFS (30) on a write through `src`"
    );
    assert!(report.contains("ifaces=lo\n"), "the helper has only `lo`");
    assert!(report.contains("got=go"), "host to worker bytes arrive");
    let uid_map = report.lines().find(|l| l.starts_with("uid_map=")).unwrap();
    eprintln!(
        "OBS helper user namespace: {uid_map} (desktop host base: {:?})",
        desktop.config.get("volatile.idmap.base")
    );
    assert!(
        !uid_map.contains("4294967295"),
        "an unprivileged helper: {uid_map}"
    );
    // `uid_map=<ns start> <host base> <size>`: field 1 is the host base.
    let helper_base = uid_map
        .strip_prefix("uid_map=")
        .and_then(|m| m.split_whitespace().nth(1))
        .map(str::to_string);
    let desktop_base = desktop.config.get("volatile.idmap.base").cloned();
    assert!(
        helper_base
            .as_deref()
            .is_some_and(|b| b.parse::<u64>().is_ok_and(|n| n > 0))
            && helper_base != desktop_base,
        "the helper has a host uid range of its own: helper {helper_base:?}, desktop {desktop_base:?}"
    );
    let end = c
        .finish_backup_helper(bjob, Duration::from_secs(30))
        .await
        .unwrap();
    eprintln!("OBS ephemeral helper deleted by Incus after PID 1 exited: {end:?}");
    assert!(matches!(end, HelperEnd::Exited(t) if t < Duration::from_secs(30)));
    assert!(
        c.get_instance(spec.name().as_str())
            .await
            .unwrap()
            .is_none(),
        "the helper is gone"
    );
    assert!(
        sock.exists(),
        "Incus leaves the host socket behind after the helper is deleted (ipc.md 24): privd removes it"
    );
    eprintln!("OBS host socket left behind after the helper was deleted: true");

    // --- restore: the helper writes through `dst` into a never-started target -------------------
    let rjob = job(JOB_RESTORE);
    let tspec = RestoreTargetSpec::from_desktop(
        &desktop,
        RestoreTargetName::new(TARGET).unwrap(),
        rjob,
        &naming(),
    )
    .unwrap();
    c.create_restore_target(&tspec, Duration::from_secs(120))
        .await
        .unwrap();
    let target = c.get_instance(TARGET).await.unwrap().unwrap();
    assert_eq!(target.status, "Stopped");
    assert_eq!(target.config["boot.autostart"], "false");
    assert_eq!(target.config["security.idmap.isolated"], "true");
    assert_eq!(target.config["user.hx.kind"], "restore-target");
    assert_eq!(target.config["user.hx.job"], JOB_RESTORE);
    assert_eq!(target.config["user.hx.state"], "restoring");
    let (db, tb) = (
        desktop.config.get("volatile.idmap.base"),
        target.config.get("volatile.idmap.base"),
    );
    eprintln!(
        "OBS idmap base: desktop {db:?}, restore target {tb:?} (the target has a range of its own)"
    );
    assert!(
        tb.is_some() && tb != db,
        "two instances never share a host range"
    );
    assert!(
        !target
            .devices
            .values()
            .any(|d| d.get("type").map(String::as_str) == Some("proxy")),
        "no proxy device is copied"
    );
    let listed = c.list_restore_targets().await.unwrap();
    assert!(
        listed
            .iter()
            .any(|t| t.name.as_str() == TARGET && t.job == Some(rjob))
    );
    eprintln!(
        "OBS never-started target: status={:?} last_used_at={:?} volatile.last_state.*={:?} \
         volatile.idmap.current={:?} volatile.last_state.idmap={:?}",
        target.status,
        target.last_used_at,
        target
            .config
            .iter()
            .filter(|(k, _)| k.starts_with("volatile.last_state."))
            .collect::<Vec<_>>(),
        target.config.get("volatile.idmap.current"),
        target.config.get("volatile.last_state.idmap"),
    );
    let tmount = TargetMount::checked(&info, &pool_info, &target)
        .expect("the checks before a restore pass on the never-started target");
    eprintln!(
        "OBS TargetMount::checked passed; source = {}",
        tmount.source()
    );
    // The desktop is not a restore target, even though it is a perfectly good instance.
    assert!(matches!(
        TargetMount::checked(&info, &pool_info, &desktop),
        Err(PreconditionFailed::NotARestoreTarget { .. })
    ));

    let rspec = BackupHelperSpec::restore(
        tmount,
        RepoLink::in_dir(rjob, work.to_str().unwrap(), owner).unwrap(),
    );
    let rsock = PathBuf::from(rspec.link().socket_path());
    c.create_backup_helper(&rspec).await.unwrap();
    c.populate_backup_helper(&rspec, &fixture).await.unwrap();
    c.start_backup_helper(rjob).await.unwrap();
    // The host half-closes after its request, which the contract says to never rely on (ipc.md
    // 24, "No half-close"): record what this Incus does. The restore itself is done before the
    // worker serves the link, so it does not depend on the answer.
    let (rreport, _) = talk(&rsock, true).await;
    eprintln!("OBS restore helper's answer after the host's shutdown(SHUT_WR): {rreport:?}");
    eprintln!(
        "OBS half-close: the reply {}",
        if rreport.contains("got=go") {
            "arrived (no loss on this Incus)"
        } else {
            "was lost (matches ipc.md 24, \"No half-close\")"
        }
    );
    let end = c
        .finish_backup_helper(rjob, Duration::from_secs(60))
        .await
        .unwrap();
    eprintln!("OBS restore helper end: {end:?}");
    assert!(matches!(end, HelperEnd::Exited(_)), "{end:?}");
    // The helper's own report is the proof it finished; the target is the proof it worked.
    c.set_state(TARGET, StateAction::Start, false, Duration::from_secs(60))
        .await
        .unwrap();
    // The target's init is the fixture (idle) and the target has no shell, so the fixture writes
    // its view to a file that is read back through the file API.
    let mut dump = None;
    for _ in 0..50 {
        let spec = ExecSpec {
            command: ["/sbin/init", "dump", "/probe", "/", "/run/dump.txt"]
                .map(String::from)
                .into(),
            env: vec![],
            cwd: None,
            timeout: Duration::from_secs(30),
        };
        if let Ok(r) = c.exec(TARGET, &spec).await
            && r.exit_code == 0
        {
            dump = c
                .read_file(TARGET, "/run/dump.txt", 64 * 1024)
                .await
                .unwrap();
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let dump = String::from_utf8(dump.expect("exec in the restored target")).unwrap();
    eprintln!("OBS restored target's own view after its first start:\n{dump}");
    let entries = |t: &str| {
        t.lines()
            .filter(|l| l.starts_with("entry="))
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert_eq!(
        entries(&dump),
        entries(&expected),
        "ids, modes, capability, xattr and fifo written through `dst` are the container's own after its first start"
    );
    let target = c.get_instance(TARGET).await.unwrap().unwrap();
    eprintln!(
        "OBS target after start: volatile.last_state.idmap={:?} idmap.base={:?}",
        target.config.get("volatile.last_state.idmap"),
        target.config.get("volatile.idmap.base")
    );
    // A target that has started is no longer accepted: stop it and ask again.
    c.set_state(TARGET, StateAction::Stop, true, Duration::from_secs(30))
        .await
        .unwrap();
    let stopped = c.get_instance(TARGET).await.unwrap().unwrap();
    eprintln!(
        "OBS started-then-stopped target: status={:?} last_used_at={:?} volatile.last_state.power={:?} volatile.idmap.current={:?}",
        stopped.status,
        stopped.last_used_at,
        stopped.config.get("volatile.last_state.power"),
        stopped
            .config
            .get("volatile.idmap.current")
            .map(|_| "(present)"),
    );
    let refused = TargetMount::checked(&info, &pool_info, &stopped);
    assert!(
        matches!(refused, Err(PreconditionFailed::TargetStarted { .. })),
        "{refused:?}"
    );
    assert!(
        c.delete_restore_target(tspec.name(), Some(rjob))
            .await
            .unwrap()
    );
    eprintln!("OBS all probes passed in {:?}", started.elapsed());
}
