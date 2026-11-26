//! The Incus side of the backup helper (ipc.md Part 3, 24): exact requests, name and path
//! validation, the checks before each job and the client calls, against a scripted in-memory
//! daemon. The real-Incus counterpart is `incus_real_backup.rs`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use hx_provision::incus::{
    BackupHelperSpec, BackupSnapshotName, Client, DesktopName, HelperEnd, HelperName, IncusError,
    Instance, JobId, JobKind, PoolName, PreconditionFailed, RepoLink, Request, Response,
    RestoreTargetName, RestoreTargetSpec, ServerInfo, Snapshot, SnapshotMount, TargetMount,
    Transport, check_backup_preconditions, check_restore_preconditions,
};
use serde_json::{Value, json};

const JOB: &str = "0a1b2c3d4e5f60718293a4b5c6d7e8f9";
const SNAP: &str = "hx-backup-20261126T101500Z-0a1b";

fn job() -> JobId {
    JobId::from_hex(JOB).unwrap()
}
fn pool() -> PoolName {
    PoolName::new("hx-pool").unwrap()
}
fn snapshot_mount() -> SnapshotMount {
    SnapshotMount::new(
        pool(),
        DesktopName::new("hx-desk1").unwrap(),
        BackupSnapshotName::new(SNAP).unwrap(),
    )
}
fn target_name() -> RestoreTargetName {
    RestoreTargetName::new("hx-restore-0a1b2c3d").unwrap()
}
fn dev<const N: usize>(p: [(&str, &str); N]) -> BTreeMap<String, String> {
    p.into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

// ---------------------------------------------------------------------------------------------
// A scripted daemon
// ---------------------------------------------------------------------------------------------

type Headers = Vec<(String, String)>;
type Logged = (String, String, Headers, Vec<u8>);
type Pushed = (String, Headers, Vec<u8>);

#[derive(Default)]
struct Daemon {
    /// Instances by name: the object `GET` returns.
    instances: BTreeMap<String, Value>,
    /// Every request: method, path, headers, body.
    log: Vec<Logged>,
    /// Ephemeral instances are removed when they are stopped.
    ops: u32,
}

#[derive(Clone, Default)]
struct Mock(Arc<Mutex<Daemon>>);

fn env(kind: &str, op: &str, metadata: Value) -> Bytes {
    Bytes::from(
        json!({"type": kind, "status": "Success", "status_code": 200, "operation": op,
               "error_code": 0, "error": "", "metadata": metadata})
        .to_string(),
    )
}
fn err(code: u16, msg: &str) -> Response {
    Response {
        status: code,
        body: Bytes::from(
            json!({"type":"error","error_code":code,"error":msg,"metadata":null}).to_string(),
        ),
        headers: BTreeMap::new(),
    }
}
fn ok(body: Bytes) -> Response {
    Response {
        status: 200,
        body,
        headers: BTreeMap::new(),
    }
}

impl Mock {
    fn with<R>(&self, f: impl FnOnce(&mut Daemon) -> R) -> R {
        f(&mut self.0.lock().unwrap())
    }

    fn put(&self, name: &str, status: &str, config: Value, extra: Value) {
        let mut v = json!({
            "name": name, "status": status, "type": "container", "config": config,
            "profiles": [], "devices": {}, "expanded_devices": {}, "architecture": "x86_64",
            "description": "", "ephemeral": false,
        });
        if let (Some(o), Some(e)) = (v.as_object_mut(), extra.as_object()) {
            for (k, x) in e {
                o.insert(k.clone(), x.clone());
            }
        }
        self.with(|d| d.instances.insert(name.to_string(), v));
    }

    fn requests(&self, method: &str) -> Vec<(String, Value)> {
        self.with(|d| {
            d.log
                .iter()
                .filter(|(m, ..)| m == method)
                .map(|(_, p, _, b)| (p.clone(), serde_json::from_slice(b).unwrap_or(Value::Null)))
                .collect()
        })
    }

    fn keys(&self) -> Vec<String> {
        self.with(|d| d.log.iter().map(|(m, p, ..)| format!("{m} {p}")).collect())
    }
}

impl Transport for Mock {
    async fn send(&self, r: Request) -> Result<Response, IncusError> {
        let mut d = self.0.lock().unwrap();
        let method = r.method.to_string();
        d.log.push((
            method.clone(),
            r.path.clone(),
            r.headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
            r.body.to_vec(),
        ));
        let (path, _) = r.path.split_once('?').unwrap_or((r.path.as_str(), ""));
        let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        let body: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
        let op = |d: &mut Daemon| {
            d.ops += 1;
            ok(env(
                "async",
                &format!("/1.0/operations/00000000-0000-4000-8000-{:012}", d.ops),
                json!({"id": format!("00000000-0000-4000-8000-{:012}", d.ops)}),
            ))
        };
        Ok(match (method.as_str(), segs.as_slice()) {
            ("GET", ["1.0", "operations", id, "wait"]) => ok(env(
                "sync",
                "",
                json!({"id": id, "status": "Success", "status_code": 200, "err": "",
                       "metadata": null}),
            )),
            ("POST", ["1.0", "instances"]) => {
                let n = body["name"].as_str().unwrap_or_default().to_string();
                let mut v = body.clone();
                v["status"] = json!("Stopped");
                v["expanded_devices"] = body["devices"].clone();
                d.instances.insert(n, v);
                op(&mut d)
            }
            ("GET", ["1.0", "instances"]) => ok(env(
                "sync",
                "",
                Value::Array(d.instances.values().cloned().collect()),
            )),
            ("GET", ["1.0", "instances", n]) => match d.instances.get(*n) {
                Some(v) => ok(env("sync", "", v.clone())),
                None => err(404, "Instance not found"),
            },
            ("PUT", ["1.0", "instances", n, "state"]) => {
                let action = body["action"].as_str().unwrap_or_default().to_string();
                if !d.instances.contains_key(*n) {
                    return Ok(err(404, "Instance not found"));
                }
                let ephemeral = d.instances[*n]["ephemeral"] == json!(true);
                if action == "start" {
                    d.instances.get_mut(*n).unwrap()["status"] = json!("Running");
                } else if action == "stop" {
                    if ephemeral {
                        d.instances.remove(*n);
                    } else {
                        d.instances.get_mut(*n).unwrap()["status"] = json!("Stopped");
                    }
                }
                op(&mut d)
            }
            ("DELETE", ["1.0", "instances", n]) => {
                if d.instances.remove(*n).is_none() {
                    err(404, "Instance not found")
                } else {
                    op(&mut d)
                }
            }
            ("POST", ["1.0", "instances", n, "files"]) => {
                if d.instances.contains_key(*n) {
                    ok(env("sync", "", Value::Null))
                } else {
                    err(404, "Instance not found")
                }
            }
            _ => err(500, &format!("unscripted {method} {path}")),
        })
    }
}

fn client() -> (Client<Mock>, Mock) {
    let m = Mock::default();
    (Client::new(m.clone()), m)
}

// ---------------------------------------------------------------------------------------------
// The instance definition
// ---------------------------------------------------------------------------------------------

fn expected_config() -> Value {
    json!({
        "security.idmap.isolated": "true",
        "security.privileged": "false",
        "security.nesting": "false",
        "security.guestapi": "false",
        "security.syscalls.deny_compat": "true",
        "limits.memory": "1GiB",
        "limits.memory.swap": "false",
        "limits.cpu": "2",
        "limits.cpu.priority": "0",
        "limits.disk.priority": "0",
        "limits.processes": "64",
        "boot.autostart": "false",
        "user.hx.kind": "backup-worker",
        "user.hx.job": JOB,
    })
}

fn root_device() -> Value {
    json!({"type": "disk", "path": "/", "pool": "hx-pool", "size": "256MiB"})
}

fn repo_device() -> Value {
    json!({
        "type": "proxy", "bind": "host",
        "listen": format!("unix:/run/hx/backup/{JOB}.sock"),
        "connect": "unix:/run/hx-worker/repo.sock",
        "uid": "0", "gid": "0", "mode": "0600",
    })
}

#[test]
fn a_backup_helper_is_exactly_the_table_of_ipc_24() {
    let spec = BackupHelperSpec::backup(snapshot_mount(), RepoLink::new(job()));
    assert_eq!(spec.kind(), JobKind::Backup);
    assert_eq!(spec.name().as_str(), "hx-bkw-0a1b2c3d");
    assert_eq!(
        spec.to_json(),
        json!({
            "name": "hx-bkw-0a1b2c3d",
            "type": "container",
            "source": {"type": "none"},
            "profiles": [],
            "ephemeral": true,
            "config": expected_config(),
            "devices": {
                "root": root_device(),
                "src": {
                    "type": "disk",
                    "source": format!(
                        "/var/lib/incus/storage-pools/hx-pool/containers-snapshots/hx-desk1/{SNAP}/rootfs"
                    ),
                    "path": "/src", "readonly": "true", "shift": "true",
                },
                "repo": repo_device(),
            },
        })
    );
}

#[test]
fn a_restore_helper_has_a_writable_dst_and_no_src() {
    let spec = BackupHelperSpec::restore(
        TargetMount::new(pool(), target_name()),
        RepoLink::new(job()),
    );
    let d = spec.devices();
    assert_eq!(
        d.keys().map(String::as_str).collect::<Vec<_>>(),
        ["dst", "repo", "root"]
    );
    assert_eq!(
        d["dst"],
        dev([
            ("type", "disk"),
            (
                "source",
                "/var/lib/incus/storage-pools/hx-pool/containers/hx-restore-0a1b2c3d/rootfs"
            ),
            ("path", "/dst"),
            ("shift", "true"),
        ])
    );
    assert!(!d["dst"].contains_key("readonly"));
    assert_eq!(
        spec.config(),
        serde_json::from_value(expected_config()).unwrap()
    );
    assert_eq!(
        spec.directories().iter().map(|d| d.0).collect::<Vec<_>>(),
        ["/sbin", "/dev", "/proc", "/sys", "/tmp", "/run", "/dst"]
    );
}

#[test]
fn a_repository_only_helper_has_root_and_repo_and_nothing_else() {
    let spec = BackupHelperSpec::repository_only(pool(), RepoLink::new(job()));
    assert_eq!(spec.kind(), JobKind::RepositoryOnly);
    let d = spec.devices();
    assert_eq!(
        d.keys().map(String::as_str).collect::<Vec<_>>(),
        ["repo", "root"]
    );
    assert_eq!(
        spec.directories().iter().map(|d| d.0).collect::<Vec<_>>(),
        ["/sbin", "/dev", "/proc", "/sys", "/tmp", "/run"]
    );
}

#[test]
fn no_helper_has_a_nic_a_profile_or_anything_beyond_the_table() {
    let backup = BackupHelperSpec::backup(snapshot_mount(), RepoLink::new(job()));
    let restore = BackupHelperSpec::restore(
        TargetMount::new(pool(), target_name()),
        RepoLink::new(job()),
    );
    let repo = BackupHelperSpec::repository_only(pool(), RepoLink::new(job()));
    for s in [&backup, &restore, &repo] {
        let j = s.to_json();
        assert_eq!(j["profiles"], json!([]));
        assert_eq!(j["ephemeral"], json!(true));
        assert_eq!(j["source"], json!({"type": "none"}));
        assert_eq!(j["config"], expected_config());
        let mut keys: Vec<&str> = j.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "config",
                "devices",
                "ephemeral",
                "name",
                "profiles",
                "source",
                "type"
            ]
        );
        for (name, d) in s.devices() {
            let t = d["type"].as_str();
            assert!(
                matches!(t, "disk" | "proxy"),
                "{name} is a {t:?}: a helper has no NIC"
            );
            assert!(
                !d.contains_key("network") && !d.contains_key("nictype"),
                "{name}"
            );
        }
        // The proxy never runs as anything but the helper's own root, never over TCP.
        let r = &s.devices()["repo"];
        assert!(!r.contains_key("security.uid") && !r.contains_key("security.gid"));
        assert!(r["listen"].starts_with("unix:") && r["connect"].starts_with("unix:"));
        assert_eq!(r["bind"], "host");
    }
}

#[test]
fn the_helper_name_is_the_first_8_digits_of_the_job_id() {
    assert_eq!(job().helper_name().as_str(), "hx-bkw-0a1b2c3d");
    assert_eq!(job().hex(), JOB);
    let other = JobId::from_bytes([0xab; 16]).unwrap();
    assert_eq!(other.helper_name().as_str(), "hx-bkw-abababab");
    assert_eq!(
        HelperName::new("hx-bkw-abababab").unwrap(),
        other.helper_name()
    );
}

// ---------------------------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------------------------

fn nasty() -> Vec<String> {
    [
        "",
        ".",
        "..",
        "../etc",
        "a/b",
        "/abs",
        "a\0b",
        "UPPER",
        "Upper",
        "-lead",
        "trail-",
        "has space",
        "semi;colon",
        "uni\u{e9}code",
        "a\nb",
        "a:b",
        "a,b",
        "a=b",
    ]
    .into_iter()
    .map(str::to_string)
    .chain(["a".repeat(64)])
    .collect()
}

#[test]
fn pool_and_desktop_names_are_strict_single_segments() {
    for ok in [
        "hx-pool",
        "default",
        "a",
        "0",
        "hx2w-test-pool",
        &"a".repeat(63),
    ] {
        assert!(PoolName::new(ok).is_ok(), "{ok}");
        assert!(DesktopName::new(ok).is_ok(), "{ok}");
    }
    for bad in nasty() {
        assert!(PoolName::new(&bad).is_err(), "pool {bad:?}");
        assert!(DesktopName::new(&bad).is_err(), "desktop {bad:?}");
    }
    // No dot or underscore either: nothing that could be read as a path component or an option.
    for bad in ["a.b", "a_b"] {
        assert!(PoolName::new(bad).is_err() && DesktopName::new(bad).is_err());
    }
}

#[test]
fn snapshot_names_are_the_backup_kind_only() {
    for ok in [
        SNAP,
        "hx-backup-1-dead",
        "hx-backup-20261126T101500Z-0a1b",
        "hx-backup-2026-11-26-ffff",
    ] {
        assert!(BackupSnapshotName::new(ok).is_ok(), "{ok}");
    }
    for bad in [
        "",
        "hx-backup-",
        "hx-backup--0a1b",
        "hx-backup-1-0A1B",
        "hx-backup-1-0a1",
        "hx-backup-1-0a1bc",
        "hx-backup-1-gggg",
        "hx-manual-1-0a1b",
        "hx-preupdate-1-0a1b",
        "backup-1-0a1b",
        "hx-backup-1x-0a1b",
        "hx-backup-../..-0a1b",
        "hx-backup-1/2-0a1b",
        "hx-backup-1-0a1b/rootfs",
        "hx-backup-1\0-0a1b",
        "hx-backup-1-0a1b\n",
        &format!("hx-backup-{}-0a1b", "1".repeat(60)),
    ] {
        assert!(BackupSnapshotName::new(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn restore_target_and_helper_names_have_their_own_prefixes() {
    for ok in [
        "hx-restore-0a1b2c3d",
        "hx-restore-x",
        &format!("hx-restore-{}", "a1".repeat(16)),
    ] {
        assert!(RestoreTargetName::new(ok).is_ok(), "{ok}");
    }
    for bad in [
        "",
        "hx-restore-",
        "hx-restore-UPPER",
        "hx-restore-a-b",
        "hx-restore-a/b",
        "hx-restore-..",
        "hx-restore-a\0",
        "hx-bkw-0a1b2c3d",
        "restore-0a1b",
        "hx-desk1",
        &format!("hx-restore-{}", "a".repeat(33)),
    ] {
        assert!(RestoreTargetName::new(bad).is_err(), "{bad:?}");
    }
    for ok in ["hx-bkw-00000000", "hx-bkw-0a1b2c3d"] {
        assert!(HelperName::new(ok).is_ok());
    }
    for bad in [
        "",
        "hx-bkw-",
        "hx-bkw-0a1b2c3",
        "hx-bkw-0a1b2c3d4",
        "hx-bkw-0A1B2C3D",
        "hx-bkw-0a1b2c3g",
        "hx-bkw-../../..",
        "hx-bkw-0a1b2c3d\0",
        "hx-restore-0a1b2c3d",
        "bkw-0a1b2c3d",
    ] {
        assert!(HelperName::new(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn job_ids_are_32_lowercase_hex_digits_and_not_zero() {
    assert!(JobId::from_hex(JOB).is_ok());
    for bad in [
        "",
        "0",
        &"0".repeat(32),
        &JOB.to_uppercase(),
        &format!("{JOB}0"),
        &JOB[..31],
        "zz1b2c3d4e5f60718293a4b5c6d7e8f9",
        "0a1b2c3d4e5f60718293a4b5c6d7e8f\0",
        "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f",
        "../../../../../../../../../../tmp",
    ] {
        assert!(JobId::from_hex(bad).is_err(), "{bad:?}");
    }
    assert!(JobId::from_bytes([0; 16]).is_err());
    assert!(JobId::from_bytes([1; 16]).is_ok());
}

#[test]
fn the_production_socket_path_is_short_and_fixed() {
    let l = RepoLink::new(job());
    assert_eq!(l.socket_path(), format!("/run/hx/backup/{JOB}.sock"));
    assert!(l.socket_path().len() <= hx_provision::incus::SUN_PATH_MAX);
    assert_eq!(hx_provision::incus::SUN_PATH_MAX, 107);
}

#[test]
fn the_socket_path_must_fit_sun_path() {
    // `/d/<32 hex>.sock` is 3 + 32 + 5 = 40 bytes plus the directory.
    let overhead = 1 + JOB.len() + ".sock".len();
    let dir_of = |n: usize| format!("/{}", "a".repeat(n - 1));
    let fits = dir_of(107 - overhead);
    let l = RepoLink::in_dir(job(), &fits, (1000, 1000)).unwrap();
    assert_eq!(l.socket_path().len(), 107);
    let too_long = dir_of(108 - overhead);
    let e = RepoLink::in_dir(job(), &too_long, (1000, 1000)).unwrap_err();
    assert!(
        matches!(e, IncusError::InvalidArgument(ref m) if m.contains("108") && m.contains("107")),
        "{e}"
    );
}

#[test]
fn a_caller_directory_must_be_a_plain_absolute_path() {
    for bad in [
        "",
        "/",
        "run/hx",
        "./run",
        "/run/../etc",
        "/run/./hx",
        "/run//hx",
        "/run/hx/",
        "/run/h x",
        "/run/hx\0",
        "/run/hx\n",
        "/run/h;x",
        "/run/h\u{e9}x",
    ] {
        assert!(
            RepoLink::in_dir(job(), bad, (0, 0)).is_err(),
            "dir {bad:?} must be refused"
        );
    }
    assert!(RepoLink::in_dir(job(), "/tmp/hx2w-test-1.d_x", (0, 0)).is_ok());
    assert!(RepoLink::in_dir(job(), "/tmp/x", (u32::MAX, 0)).is_err());
    assert!(RepoLink::in_dir(job(), "/tmp/x", (0, u32::MAX)).is_err());
    let l = RepoLink::in_dir(job(), "/tmp/x", (1000, 100)).unwrap();
    let d = l.device();
    assert_eq!((d["uid"].as_str(), d["gid"].as_str()), ("1000", "100"));
    assert_eq!(d["listen"], format!("unix:/tmp/x/{JOB}.sock"));
    assert_eq!(d["mode"], "0600");
}

// ---------------------------------------------------------------------------------------------
// The checks before each job
// ---------------------------------------------------------------------------------------------

fn server(features: &[(&str, &str)]) -> ServerInfo {
    ServerInfo {
        api_version: "1.0".into(),
        auth: "trusted".into(),
        server_version: "6.0.0".into(),
        storage_drivers: vec!["btrfs".into()],
        firewall: "nftables".into(),
        kernel_version: "6.8.0".into(),
        kernel_features: features
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    }
}

fn good_pool() -> hx_provision::incus::StoragePool {
    serde_json::from_value(json!({"name": "hx-pool", "driver": "btrfs"})).unwrap()
}

fn desktop(idmap: Option<&str>, pool: Option<&str>) -> Instance {
    let mut config = json!({"user.hx.state": "ready"});
    if let Some(i) = idmap {
        config["volatile.last_state.idmap"] = json!(i);
    }
    let expanded = match pool {
        Some(p) => json!({"root": {"type": "disk", "path": "/", "pool": p}}),
        None => json!({}),
    };
    serde_json::from_value(json!({
        "name": "hx-desk1", "status": "Running", "type": "container",
        "config": config, "expanded_devices": expanded,
        "devices": {}, "profiles": ["hx-desktop"], "architecture": "x86_64",
    }))
    .unwrap()
}

fn snap(idmap: Option<&str>) -> Snapshot {
    let mut config = json!({});
    if let Some(i) = idmap {
        config["volatile.last_state.idmap"] = json!(i);
    }
    serde_json::from_value(json!({"name": SNAP, "config": config})).unwrap()
}

#[test]
fn the_guard_passes_when_everything_is_as_verified_on_6_0_0() {
    let s = server(&[("idmapped_mounts", "true"), ("seccomp_listener", "true")]);
    check_backup_preconditions(
        &s,
        &good_pool(),
        &desktop(Some("[]"), Some("hx-pool")),
        &snap(Some("[]")),
    )
    .unwrap();
    check_restore_preconditions(&s, &good_pool()).unwrap();
}

#[test]
fn the_guard_names_the_check_that_failed() {
    let good = server(&[("idmapped_mounts", "true")]);
    let d_ok = desktop(Some("[]"), Some("hx-pool"));
    let s_ok = snap(Some("[]"));
    let p = good_pool();

    // idmapped mounts: false, missing, odd.
    for (feat, want) in [
        (vec![("idmapped_mounts", "false")], Some("false")),
        (vec![], None),
        (vec![("idmapped_mounts", "TRUE")], Some("TRUE")),
        (vec![("idmapped_mounts", "")], Some("")),
    ] {
        let s = server(&feat);
        let e = PreconditionFailed::IdmappedMounts(want.map(str::to_string));
        assert_eq!(
            check_backup_preconditions(&s, &p, &d_ok, &s_ok),
            Err(e.clone())
        );
        assert_eq!(check_restore_preconditions(&s, &p), Err(e));
    }

    // pool driver.
    for driver in ["zfs", "dir", "lvm", "ceph", "", "Btrfs"] {
        let mut bad = good_pool();
        bad.driver = driver.into();
        let e = PreconditionFailed::PoolDriver {
            pool: "hx-pool".into(),
            driver: driver.into(),
        };
        assert_eq!(
            check_backup_preconditions(&good, &bad, &d_ok, &s_ok),
            Err(e.clone())
        );
        assert_eq!(check_restore_preconditions(&good, &bad), Err(e));
    }

    // desktop on another pool, or without a root device.
    for actual in [Some("default"), None] {
        let d = desktop(Some("[]"), actual);
        assert_eq!(
            check_backup_preconditions(&good, &p, &d, &s_ok),
            Err(PreconditionFailed::DesktopPool {
                desktop: "hx-desk1".into(),
                pool: "hx-pool".into(),
                actual: actual.map(str::to_string),
            })
        );
    }

    // desktop idmap: shifted storage, never started, odd spelling.
    for v in [
        Some(r#"[{"Isuid":true,"Isgid":false,"Hostid":1065536,"Nsid":0,"Maprange":65536}]"#),
        None,
        Some("[ ]"),
        Some(""),
        Some("null"),
    ] {
        assert_eq!(
            check_backup_preconditions(&good, &p, &desktop(v, Some("hx-pool")), &s_ok),
            Err(PreconditionFailed::DesktopIdmap {
                desktop: "hx-desk1".into(),
                value: v.map(str::to_string),
            }),
            "{v:?}"
        );
    }

    // snapshot idmap.
    for v in [Some(r#"[{"Isuid":true}]"#), None, Some(" []")] {
        assert_eq!(
            check_backup_preconditions(&good, &p, &d_ok, &snap(v)),
            Err(PreconditionFailed::SnapshotIdmap {
                snapshot: SNAP.into(),
                value: v.map(str::to_string),
            }),
            "{v:?}"
        );
    }
}

#[test]
fn the_guard_checks_the_host_before_the_instances() {
    // Everything wrong at once: the first failure in the documented order is reported.
    let s = server(&[]);
    let mut bad_pool = good_pool();
    bad_pool.driver = "zfs".into();
    let e =
        check_backup_preconditions(&s, &bad_pool, &desktop(None, None), &snap(None)).unwrap_err();
    assert!(matches!(e, PreconditionFailed::IdmappedMounts(None)));
    let s = server(&[("idmapped_mounts", "true")]);
    let e =
        check_backup_preconditions(&s, &bad_pool, &desktop(None, None), &snap(None)).unwrap_err();
    assert!(matches!(e, PreconditionFailed::PoolDriver { .. }));
    let e = check_backup_preconditions(&s, &good_pool(), &desktop(None, None), &snap(None))
        .unwrap_err();
    assert!(matches!(e, PreconditionFailed::DesktopPool { .. }));
    let e = check_backup_preconditions(
        &s,
        &good_pool(),
        &desktop(None, Some("hx-pool")),
        &snap(None),
    )
    .unwrap_err();
    assert!(matches!(e, PreconditionFailed::DesktopIdmap { .. }));
    let e = check_backup_preconditions(
        &s,
        &good_pool(),
        &desktop(Some("[]"), Some("hx-pool")),
        &snap(None),
    )
    .unwrap_err();
    assert!(matches!(e, PreconditionFailed::SnapshotIdmap { .. }));
    // The messages name the failing check.
    assert!(e.to_string().contains("snapshot") && e.to_string().contains("last_state.idmap"));
}

#[tokio::test]
async fn server_info_and_snapshots_carry_the_fields_the_guard_reads() {
    struct Canned;
    impl Transport for Canned {
        async fn send(&self, r: Request) -> Result<Response, IncusError> {
            let body = if r.path == "/1.0" {
                env(
                    "sync",
                    "",
                    json!({"api_version": "1.0", "auth": "trusted", "environment": {
                        "server_version": "6.0.0",
                        "kernel_features": {"idmapped_mounts": "true", "netnsid_getifaddrs": "false"}}}),
                )
            } else {
                env(
                    "sync",
                    "",
                    json!([{"name": format!("hx-desk1/{SNAP}"), "created_at": "x", "stateful": false,
                            "config": {"volatile.last_state.idmap": "[]", "user.hx.state": "ready"}}]),
                )
            };
            Ok(ok(body))
        }
    }
    let c2 = Client::new(Canned);
    let info = c2.server_info().await.unwrap();
    assert_eq!(info.kernel_features["idmapped_mounts"], "true");
    assert_eq!(info.kernel_features["netnsid_getifaddrs"], "false");
    let snaps = c2.list_snapshots("hx-desk1").await.unwrap();
    assert_eq!(snaps[0].name, SNAP);
    assert_eq!(snaps[0].config["volatile.last_state.idmap"], "[]");
}

// ---------------------------------------------------------------------------------------------
// The restore target
// ---------------------------------------------------------------------------------------------

fn full_desktop() -> Instance {
    serde_json::from_value(json!({
        "name": "hx-desk1", "status": "Running", "type": "container",
        "profiles": ["hx-desktop", "hx-compat-debian13"],
        "architecture": "x86_64",
        "description": "the desktop",
        "config": {
            "security.privileged": "false",
            "security.idmap.isolated": "true",
            "security.guestapi": "false",
            "boot.autostart": "true",
            "limits.cpu": "4",
            "limits.memory": "8192MiB",
            "limits.processes": "4096",
            "user.hx.state": "ready",
            "volatile.base_image": "abc",
            "volatile.eth0.hwaddr": "10:66:6a:00:00:01",
            "volatile.idmap.base": "1065536",
            "volatile.idmap.current": "[...]",
            "volatile.idmap.next": "[...]",
            "volatile.last_state.idmap": "[]",
            "volatile.uuid": "u",
        },
        "devices": {
            "root": {"type": "disk", "path": "/", "pool": "hx-pool", "size": "40GiB"},
            "hx-link": {"type": "proxy", "bind": "host", "listen": "unix:/run/hx/link/desk1.sock",
                        "connect": "unix:/run/hx-session/link.sock", "uid": "998", "gid": "998",
                        "mode": "0600", "security.uid": "1000", "security.gid": "1000"},
            "other-proxy": {"type": "proxy", "listen": "tcp:0.0.0.0:80", "connect": "tcp:127.0.0.1:80"},
        },
        "expanded_devices": {
            "root": {"type": "disk", "path": "/", "pool": "hx-pool", "size": "40GiB"},
            "eth0": {"type": "nic", "network": "hxbr0", "name": "eth0"},
        },
    }))
    .unwrap()
}

#[test]
fn the_restore_target_is_the_desktop_without_runtime_state_and_the_link() {
    let spec = RestoreTargetSpec::from_desktop(&full_desktop(), target_name(), &pool()).unwrap();
    assert_eq!(
        spec.to_json(),
        json!({
            "name": "hx-restore-0a1b2c3d",
            "type": "container",
            "source": {"type": "none"},
            "profiles": ["hx-desktop", "hx-compat-debian13"],
            "description": "the desktop",
            "architecture": "x86_64",
            "ephemeral": false,
            "config": {
                "security.privileged": "false",
                "security.idmap.isolated": "true",
                "security.guestapi": "false",
                "boot.autostart": "false",
                "limits.cpu": "4",
                "limits.memory": "8192MiB",
                "limits.processes": "4096",
                "user.hx.state": "ready",
            },
            "devices": {
                "root": {"type": "disk", "path": "/", "pool": "hx-pool", "size": "40GiB"},
            },
        })
    );
    assert_eq!(spec.mount(), TargetMount::new(pool(), target_name()));
}

#[test]
fn the_restore_target_refuses_a_desktop_it_cannot_copy_faithfully() {
    let mut other_pool = full_desktop();
    other_pool
        .expanded_devices
        .get_mut("root")
        .unwrap()
        .insert("pool".into(), "default".into());
    let mut no_root = full_desktop();
    no_root.expanded_devices.clear();
    let mut unmarked = full_desktop();
    unmarked.config.remove("user.hx.state");
    let mut vm = full_desktop();
    vm.kind = "virtual-machine".into();
    for (what, d) in [
        ("other pool", other_pool),
        ("no root", no_root),
        ("unmarked", unmarked),
        ("vm", vm),
    ] {
        let e = RestoreTargetSpec::from_desktop(&d, target_name(), &pool()).unwrap_err();
        assert!(matches!(e, IncusError::InvalidArgument(_)), "{what}: {e}");
    }
}

#[tokio::test]
async fn creating_and_deleting_a_restore_target() {
    let (c, m) = client();
    let spec = RestoreTargetSpec::from_desktop(&full_desktop(), target_name(), &pool()).unwrap();
    c.create_restore_target(&spec, Duration::from_secs(5))
        .await
        .unwrap();
    let posts = m.requests("POST");
    assert_eq!(posts.len(), 1);
    assert_eq!(posts[0].0, "/1.0/instances");
    assert_eq!(posts[0].1, spec.to_json());
    assert!(m.requests("PUT").is_empty(), "the target is never started");

    assert!(c.delete_restore_target(&target_name()).await.unwrap());
    assert!(!c.delete_restore_target(&target_name()).await.unwrap());
    // Refused for an instance that is not ours.
    m.put(
        "hx-restore-ffff",
        "Stopped",
        json!({"foo": "bar"}),
        json!({}),
    );
    let e = c
        .delete_restore_target(&RestoreTargetName::new("hx-restore-ffff").unwrap())
        .await
        .unwrap_err();
    assert!(matches!(e, IncusError::InvalidArgument(_)), "{e}");
    assert!(m.with(|d| d.instances.contains_key("hx-restore-ffff")));
}

// ---------------------------------------------------------------------------------------------
// The client calls
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_helper_is_created_populated_started_and_ends_by_itself() {
    let (c, m) = client();
    let spec = BackupHelperSpec::backup(snapshot_mount(), RepoLink::new(job()));
    c.create_backup_helper(&spec).await.unwrap();
    let posts = m.requests("POST");
    assert_eq!(posts[0].0, "/1.0/instances");
    assert_eq!(posts[0].1, spec.to_json());

    c.populate_backup_helper(&spec, b"\x7fELF-worker")
        .await
        .unwrap();
    let files: Vec<Pushed> = m.with(|d| {
        d.log
            .iter()
            .filter(|(me, p, ..)| me == "POST" && p.contains("/files?"))
            .map(|(_, p, h, b)| (p.clone(), h.clone(), b.clone()))
            .collect()
    });
    let paths: Vec<&str> = files.iter().map(|f| f.0.as_str()).collect();
    let base = "/1.0/instances/hx-bkw-0a1b2c3d/files?path=";
    assert_eq!(
        paths,
        [
            "/sbin",
            "/dev",
            "/proc",
            "/sys",
            "/tmp",
            "/run",
            "/src",
            "/sbin/init"
        ]
        .map(|p| format!("{base}{p}"))
    );
    let h = |f: &(String, Vec<(String, String)>, Vec<u8>), k: &str| {
        f.1.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
    };
    let init = files.last().unwrap();
    assert_eq!(h(init, "X-Incus-type").as_deref(), Some("file"));
    assert_eq!(h(init, "X-Incus-mode").as_deref(), Some("0755"));
    assert_eq!(h(init, "X-Incus-uid").as_deref(), Some("0"));
    assert_eq!(h(init, "X-Incus-gid").as_deref(), Some("0"));
    assert_eq!(init.2, b"\x7fELF-worker");
    for d in &files[..7] {
        assert_eq!(h(d, "X-Incus-type").as_deref(), Some("directory"));
    }
    assert_eq!(h(&files[4], "X-Incus-mode").as_deref(), Some("1777"));
    assert_eq!(h(&files[0], "X-Incus-mode").as_deref(), Some("0755"));

    c.start_backup_helper(&spec.name()).await.unwrap();
    let puts = m.requests("PUT");
    assert_eq!(puts[0].0, "/1.0/instances/hx-bkw-0a1b2c3d/state");
    assert_eq!(puts[0].1["action"], "start");
    assert_eq!(puts[0].1["force"], false);

    // The worker exits; Incus deletes the ephemeral instance a moment later.
    let m2 = m.clone();
    let gone = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        m2.with(|d| d.instances.remove("hx-bkw-0a1b2c3d"));
    });
    let end = c
        .finish_backup_helper(&spec.name(), Duration::from_secs(10))
        .await
        .unwrap();
    gone.await.unwrap();
    match end {
        HelperEnd::Exited(t) => assert!(
            t >= Duration::from_millis(250) && t < Duration::from_secs(5),
            "{t:?}"
        ),
        other => panic!("{other:?}"),
    }
    assert!(
        m.requests("DELETE").is_empty() && m.requests("PUT").len() == 1,
        "nothing was forced: {:?}",
        m.keys()
    );
}

#[tokio::test]
async fn a_helper_that_does_not_end_is_stopped_and_deleted_by_force() {
    let (c, m) = client();
    let spec = BackupHelperSpec::repository_only(pool(), RepoLink::new(job()));
    c.create_backup_helper(&spec).await.unwrap();
    c.start_backup_helper(&spec.name()).await.unwrap();
    let end = c
        .finish_backup_helper(&spec.name(), Duration::from_millis(500))
        .await
        .unwrap();
    assert_eq!(end, HelperEnd::ForceDeleted);
    let puts = m.requests("PUT");
    assert_eq!(puts.len(), 2);
    assert_eq!(puts[1].1["action"], "stop");
    assert_eq!(puts[1].1["force"], true);
    assert!(!m.with(|d| d.instances.contains_key("hx-bkw-0a1b2c3d")));
    // Repeating is harmless.
    assert!(!c.force_delete_backup_helper(&spec.name()).await.unwrap());
}

#[tokio::test]
async fn the_helper_calls_refuse_an_instance_that_is_not_a_helper() {
    let (c, m) = client();
    // Named like a helper but not marked as one (somebody else's object).
    m.put(
        "hx-bkw-deadbeef",
        "Running",
        json!({"user.hx.state": "ready"}),
        json!({}),
    );
    let name = HelperName::new("hx-bkw-deadbeef").unwrap();
    for e in [
        c.force_delete_backup_helper(&name).await.unwrap_err(),
        c.start_backup_helper(&name).await.unwrap_err(),
        c.finish_backup_helper(&name, Duration::from_millis(10))
            .await
            .unwrap_err(),
    ] {
        assert!(matches!(e, IncusError::InvalidArgument(_)), "{e}");
    }
    assert!(m.requests("PUT").is_empty() && m.requests("DELETE").is_empty());
    assert!(m.with(|d| d.instances.contains_key("hx-bkw-deadbeef")));
}

#[tokio::test]
async fn populate_refuses_an_empty_worker_a_running_helper_and_a_missing_helper() {
    let (c, m) = client();
    let spec = BackupHelperSpec::backup(snapshot_mount(), RepoLink::new(job()));
    let e = c.populate_backup_helper(&spec, b"x").await.unwrap_err();
    assert!(e.is_not_found(), "{e}");
    c.create_backup_helper(&spec).await.unwrap();
    assert!(matches!(
        c.populate_backup_helper(&spec, b"").await.unwrap_err(),
        IncusError::InvalidArgument(_)
    ));
    c.start_backup_helper(&spec.name()).await.unwrap();
    let e = c.populate_backup_helper(&spec, b"x").await.unwrap_err();
    assert!(
        matches!(e, IncusError::InvalidArgument(ref s) if s.contains("stopped")),
        "{e}"
    );
    assert!(
        !m.keys().iter().any(|k| k.contains("/files")),
        "no file was pushed: {:?}",
        m.keys()
    );
}

#[tokio::test]
async fn listing_finds_only_marked_helpers_with_helper_names() {
    let (c, m) = client();
    let job2 = JobId::from_bytes([0xcd; 16]).unwrap();
    m.put(
        "hx-bkw-0a1b2c3d",
        "Running",
        json!({"user.hx.kind": "backup-worker", "user.hx.job": JOB}),
        json!({}),
    );
    m.put(
        "hx-bkw-cdcdcdcd",
        "Stopped",
        json!({"user.hx.kind": "backup-worker", "user.hx.job": job2.hex()}),
        json!({}),
    );
    // Marked but oddly named, named like a helper but unmarked, a desktop, a bad job id.
    m.put(
        "hx-bkw-zz",
        "Running",
        json!({"user.hx.kind": "backup-worker"}),
        json!({}),
    );
    m.put(
        "hx-bkw-11111111",
        "Running",
        json!({"user.hx.kind": "desktop"}),
        json!({}),
    );
    m.put(
        "hx-desk1",
        "Running",
        json!({"user.hx.state": "ready"}),
        json!({}),
    );
    m.put(
        "hx-bkw-22222222",
        "Stopped",
        json!({"user.hx.kind": "backup-worker", "user.hx.job": "not-a-job"}),
        json!({}),
    );
    let mut found = c.list_backup_helpers().await.unwrap();
    found.sort_by(|a, b| a.name.cmp(&b.name));
    let summary: Vec<(String, Option<String>, String)> = found
        .iter()
        .map(|h| (h.name.to_string(), h.job.map(|j| j.hex()), h.status.clone()))
        .collect();
    assert_eq!(
        summary,
        [
            (
                "hx-bkw-0a1b2c3d".to_string(),
                Some(JOB.to_string()),
                "Running".to_string()
            ),
            ("hx-bkw-22222222".to_string(), None, "Stopped".to_string()),
            (
                "hx-bkw-cdcdcdcd".to_string(),
                Some(job2.hex()),
                "Stopped".to_string()
            ),
        ]
    );
    assert_eq!(m.requests("GET")[0].0, "/1.0/instances?recursion=1");
}

#[tokio::test]
async fn create_surfaces_incus_errors_and_leaves_nothing_in_the_log_but_the_post() {
    struct Refuse;
    impl Transport for Refuse {
        async fn send(&self, _: Request) -> Result<Response, IncusError> {
            Ok(err(400, "Failed to start dnsmasq"))
        }
    }
    let spec = BackupHelperSpec::backup(snapshot_mount(), RepoLink::new(job()));
    let e = Client::new(Refuse)
        .create_backup_helper(&spec)
        .await
        .unwrap_err();
    assert!(matches!(e, IncusError::Api { code: 400, .. }), "{e}");
}
