//! The Incus side of the backup helper (ipc.md Part 3, 24): exact requests, name and path
//! validation, the checks before each job and the client calls, against a scripted in-memory
//! daemon. The real-Incus counterpart is `incus_real_backup.rs`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use hx_provision::host::Naming;
use hx_provision::incus::{
    BackupHelperSpec, BackupSnapshotName, Client, DesktopName, HelperEnd, HelperName, IncusError,
    Instance, JobId, JobKind, PoolName, PreconditionFailed, RepoLink, Request, Response,
    RestoreTargetName, RestoreTargetSpec, ServerInfo, Snapshot, SnapshotMount, StoragePool,
    TargetMount, Transport, check_host_preconditions,
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
    SnapshotMount::unchecked(
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
type Edit = Box<dyn Fn(&mut Instance)>;
type Pushed = (String, Headers, Vec<u8>);

#[derive(Default)]
struct Daemon {
    /// Instances by name: the object `GET` returns.
    instances: BTreeMap<String, Value>,
    /// Every request: method, path, headers, body.
    log: Vec<Logged>,
    /// Ephemeral instances are removed when they are stopped.
    ops: u32,
    /// Misbehaviour of the daemon on creation: a NIC the spec does not have, a profile, a missing
    /// config key.
    inject_nic: bool,
    inject_profile: bool,
    drop_config_key: Option<String>,
    /// A DELETE fails with 500 while the instance vanishes (Incus deleting it at the same time).
    delete_races: bool,
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
                v["expanded_config"] = body["config"].clone();
                if d.inject_nic {
                    v["expanded_devices"]["eth0"] = json!({"type": "nic", "network": "x"});
                }
                if d.inject_profile {
                    v["profiles"] = json!(["default"]);
                }
                if let Some(k) = d.drop_config_key.clone() {
                    v["expanded_config"].as_object_mut().unwrap().remove(&k);
                    v["config"].as_object_mut().unwrap().remove(&k);
                }
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
            ("DELETE", ["1.0", "instances", n]) if d.delete_races => {
                d.instances.remove(*n);
                err(500, "Instance is busy")
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
        TargetMount::unchecked(pool(), target_name()),
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
        TargetMount::unchecked(pool(), target_name()),
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
fn pool_names_are_strict_single_segments() {
    for ok in [
        "hx-pool",
        "default",
        "a",
        "0",
        "hx2w-test-pool",
        &"a".repeat(63),
    ] {
        assert!(PoolName::new(ok).is_ok(), "{ok}");
    }
    for bad in nasty() {
        assert!(PoolName::new(&bad).is_err(), "pool {bad:?}");
    }
    // No dot or underscore either: nothing that could be read as a path component or an option.
    for bad in ["a.b", "a_b"] {
        assert!(PoolName::new(bad).is_err());
    }
}

#[test]
fn desktop_names_are_hx_and_a_desktop_id() {
    for ok in ["hx-a", "hx-desk1", "hx-hx2wtest", "hx-abcdefghijkl"] {
        assert!(DesktopName::new(ok).is_ok(), "{ok}");
    }
    for bad in nasty().iter().map(String::as_str).chain([
        "desk1",
        "hx-",
        "hx-1a",
        "hx-Desk",
        "hx-a-b",
        "hx-a_b",
        "hx-a.b",
        "hx-abcdefghijklm",
        "hx-bkw-0a1b2c3d",
        "hx-restore-0a1b",
        "hx-a\0",
        "HX-a",
        "default",
    ]) {
        assert!(DesktopName::new(bad).is_err(), "desktop {bad:?}");
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
// The checks before each job (SnapshotMount::checked, TargetMount::checked)
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

fn good_server() -> ServerInfo {
    server(&[("idmapped_mounts", "true"), ("seccomp_listener", "true")])
}

fn good_pool() -> StoragePool {
    serde_json::from_value(json!({"name": "hx-pool", "driver": "btrfs"})).unwrap()
}

fn instance(v: Value) -> Instance {
    serde_json::from_value(v).unwrap()
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
    instance(json!({
        "name": "hx-desk1", "status": "Running", "type": "container",
        "config": config, "expanded_devices": expanded,
        "devices": {}, "profiles": ["hx-desktop"], "architecture": "x86_64",
    }))
}

fn good_desktop() -> Instance {
    desktop(Some("[]"), Some("hx-pool"))
}

fn snap_of(instance: &str, name: &str, idmap: Option<&str>) -> Snapshot {
    let mut config = json!({});
    if let Some(i) = idmap {
        config["volatile.last_state.idmap"] = json!(i);
    }
    let mut s: Snapshot = serde_json::from_value(json!({"name": name, "config": config})).unwrap();
    s.instance = instance.to_string();
    s
}

fn snap(idmap: Option<&str>) -> Snapshot {
    snap_of("hx-desk1", SNAP, idmap)
}

fn checked(
    s: &ServerInfo,
    p: &StoragePool,
    d: &Instance,
    sn: &Snapshot,
) -> Result<SnapshotMount, PreconditionFailed> {
    SnapshotMount::checked(s, p, d, sn)
}

#[test]
fn a_checked_snapshot_mount_derives_every_name_from_the_objects() {
    let m = checked(
        &good_server(),
        &good_pool(),
        &good_desktop(),
        &snap(Some("[]")),
    )
    .unwrap();
    assert_eq!(m, snapshot_mount());
    assert_eq!(
        m.source(),
        format!("/var/lib/incus/storage-pools/hx-pool/containers-snapshots/hx-desk1/{SNAP}/rootfs")
    );
}

#[test]
fn the_snapshot_checks_name_the_check_that_failed() {
    let good = good_server();
    let p = good_pool();
    let d_ok = good_desktop();
    let s_ok = snap(Some("[]"));

    // idmapped mounts: false, missing, odd.
    for (feat, want) in [
        (vec![("idmapped_mounts", "false")], Some("false")),
        (vec![], None),
        (vec![("idmapped_mounts", "TRUE")], Some("TRUE")),
        (vec![("idmapped_mounts", "")], Some("")),
    ] {
        let s = server(&feat);
        let e = PreconditionFailed::IdmappedMounts(want.map(str::to_string));
        assert_eq!(checked(&s, &p, &d_ok, &s_ok), Err(e.clone()));
        assert_eq!(check_host_preconditions(&s, &p), Err(e));
    }

    // pool driver.
    for driver in ["zfs", "dir", "lvm", "ceph", "", "Btrfs"] {
        let mut bad = good_pool();
        bad.driver = driver.into();
        let e = PreconditionFailed::PoolDriver {
            pool: "hx-pool".into(),
            driver: driver.into(),
        };
        assert_eq!(checked(&good, &bad, &d_ok, &s_ok), Err(e.clone()));
        assert_eq!(check_host_preconditions(&good, &bad), Err(e));
    }

    // desktop on another pool, or without a root device.
    for actual in [Some("default"), None] {
        assert_eq!(
            checked(&good, &p, &desktop(Some("[]"), actual), &s_ok),
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
            checked(&good, &p, &desktop(v, Some("hx-pool")), &s_ok),
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
            checked(&good, &p, &d_ok, &snap(v)),
            Err(PreconditionFailed::SnapshotIdmap {
                snapshot: SNAP.into(),
                value: v.map(str::to_string),
            }),
            "{v:?}"
        );
    }
}

#[test]
fn a_snapshot_mount_needs_a_real_desktop_and_its_own_backup_snapshot() {
    let (good, p, s_ok) = (good_server(), good_pool(), snap(Some("[]")));
    let not_a_desktop = |d: &Instance| {
        matches!(
            checked(&good, &p, d, &s_ok),
            Err(PreconditionFailed::NotADesktop { .. })
        )
    };
    let with = |f: &dyn Fn(&mut Instance)| {
        let mut d = good_desktop();
        f(&mut d);
        d
    };
    assert!(not_a_desktop(&with(&|d| d.kind = "virtual-machine".into())));
    assert!(not_a_desktop(&with(&|d| {
        d.config.remove("user.hx.state");
    })));
    // A helper or a restore target is never a desktop.
    for kind in ["backup-worker", "restore-target", "desktop"] {
        assert!(not_a_desktop(&with(&|d| {
            d.config.insert("user.hx.kind".into(), kind.into());
        })));
    }
    // Names that are not `hx-<id>` are refused before any path is built.
    for bad in [
        "desk1",
        "hx-",
        "hx-Desk",
        "hx-1desk",
        "hx-a/b",
        "hx-..",
        "hx-a.b",
        "hx-abcdefghijklm",
        "hx-bkw-0a1b2c3d",
        "hx-restore-0a1b",
    ] {
        let d = with(&|d| d.name = bad.into());
        assert!(
            matches!(
                checked(&good, &p, &d, &snap_of(bad, SNAP, Some("[]"))),
                Err(PreconditionFailed::InvalidName { .. })
            ),
            "{bad}"
        );
    }
    // Snapshot: not a backup snapshot, another desktop's, unknown owner.
    for name in [
        "hx-manual-1-0a1b",
        "hx-preupdate-1-0a1b",
        "snap0",
        "hx-backup-../x-0a1b",
    ] {
        assert_eq!(
            checked(
                &good,
                &p,
                &good_desktop(),
                &snap_of("hx-desk1", name, Some("[]"))
            ),
            Err(PreconditionFailed::SnapshotNotBackup {
                snapshot: name.into()
            })
        );
    }
    for owner in ["hx-other", "", "hx-desk12", "hx-desk"] {
        assert_eq!(
            checked(
                &good,
                &p,
                &good_desktop(),
                &snap_of(owner, SNAP, Some("[]"))
            ),
            Err(PreconditionFailed::SnapshotOfOther {
                snapshot: SNAP.into(),
                instance: owner.into(),
                desktop: "hx-desk1".into(),
            })
        );
    }
}

#[test]
fn the_snapshot_checks_run_in_the_documented_order() {
    // Everything wrong at once: the first failure in the documented order is reported.
    let mut bad_pool = good_pool();
    bad_pool.driver = "zfs".into();
    let e = checked(&server(&[]), &bad_pool, &desktop(None, None), &snap(None)).unwrap_err();
    assert!(matches!(e, PreconditionFailed::IdmappedMounts(None)));
    let s = server(&[("idmapped_mounts", "true")]);
    let e = checked(&s, &bad_pool, &desktop(None, None), &snap(None)).unwrap_err();
    assert!(matches!(e, PreconditionFailed::PoolDriver { .. }));
    let e = checked(&s, &good_pool(), &desktop(None, None), &snap(None)).unwrap_err();
    assert!(matches!(e, PreconditionFailed::DesktopPool { .. }));
    let e = checked(
        &s,
        &good_pool(),
        &desktop(None, Some("hx-pool")),
        &snap(None),
    )
    .unwrap_err();
    assert!(matches!(e, PreconditionFailed::DesktopIdmap { .. }));
    let e = checked(&s, &good_pool(), &good_desktop(), &snap(None)).unwrap_err();
    assert!(matches!(e, PreconditionFailed::SnapshotIdmap { .. }));
    assert!(e.to_string().contains("snapshot") && e.to_string().contains("last_state.idmap"));
}

fn good_target() -> Instance {
    instance(json!({
        "name": "hx-restore-0a1b2c3d", "status": "Stopped", "type": "container",
        "last_used_at": "1970-01-01T00:00:00Z",
        "config": {
            "user.hx.kind": "restore-target", "user.hx.job": JOB, "user.hx.state": "restoring",
            "volatile.last_state.idmap": "[]", "volatile.idmap.base": "1131072",
            "volatile.idmap.next": "[...]",
        },
        "expanded_devices": {"root": {"type": "disk", "path": "/", "pool": "hx-pool"}},
        "devices": {}, "profiles": ["hx-desktop"],
    }))
}

#[test]
fn a_checked_target_mount_is_a_never_started_restore_target() {
    let m = TargetMount::checked(&good_server(), &good_pool(), &good_target()).unwrap();
    assert_eq!(m, TargetMount::unchecked(pool(), target_name()));
    assert_eq!(
        m.source(),
        "/var/lib/incus/storage-pools/hx-pool/containers/hx-restore-0a1b2c3d/rootfs"
    );
    // The zero time may also be spelled the Go way or be absent.
    for t in ["0001-01-01T00:00:00Z", "1970-01-01T00:00:00+00:00", ""] {
        let mut x = good_target();
        x.last_used_at = t.into();
        assert!(
            TargetMount::checked(&good_server(), &good_pool(), &x).is_ok(),
            "{t}"
        );
    }
}

#[test]
fn the_target_checks_name_the_check_that_failed() {
    let (s, p) = (good_server(), good_pool());
    let try_with = |f: &dyn Fn(&mut Instance)| {
        let mut t = good_target();
        f(&mut t);
        TargetMount::checked(&s, &p, &t)
    };
    // Host conditions first.
    assert!(matches!(
        TargetMount::checked(&server(&[]), &p, &good_target()),
        Err(PreconditionFailed::IdmappedMounts(None))
    ));
    let mut zfs = good_pool();
    zfs.driver = "zfs".into();
    assert!(matches!(
        TargetMount::checked(&s, &zfs, &good_target()),
        Err(PreconditionFailed::PoolDriver { .. })
    ));
    // A desktop (only user.hx.state=ready), a helper, no kind: not a restore target.
    for kind in [None, Some("backup-worker"), Some("desktop"), Some("")] {
        let e = try_with(&|t| {
            t.config.remove("user.hx.kind");
            if let Some(k) = kind {
                t.config.insert("user.hx.kind".into(), k.into());
            }
            t.config.insert("user.hx.state".into(), "ready".into());
        })
        .unwrap_err();
        assert!(
            matches!(e, PreconditionFailed::NotARestoreTarget { .. }),
            "{kind:?}: {e}"
        );
    }
    for name in [
        "hx-desk1",
        "hx-bkw-0a1b2c3d",
        "hx-restore-",
        "hx-restore-A",
        "hx-restore-a/b",
    ] {
        let e = try_with(&|t| t.name = name.into()).unwrap_err();
        assert!(
            matches!(e, PreconditionFailed::NotARestoreTarget { .. }),
            "{name}"
        );
    }
    assert!(matches!(
        try_with(&|t| t.kind = "virtual-machine".into()),
        Err(PreconditionFailed::NotARestoreTarget { .. })
    ));
    // Not stopped.
    for st in ["Running", "Frozen", "Error", ""] {
        assert!(
            matches!(
                try_with(&|t| t.status = st.into()),
                Err(PreconditionFailed::TargetNotStopped { .. })
            ),
            "{st}"
        );
    }
    // Started before.
    assert!(matches!(
        try_with(&|t| t.last_used_at = "2026-11-26T17:30:00.123Z".into()),
        Err(PreconditionFailed::TargetStarted { .. })
    ));
    for key in ["volatile.last_state.power", "volatile.idmap.current"] {
        let e = try_with(&|t| {
            t.config.insert(key.into(), "STOPPED".into());
        })
        .unwrap_err();
        assert!(
            matches!(&e, PreconditionFailed::TargetStarted { evidence, .. } if evidence.contains(key)),
            "{e}"
        );
    }
    // The idmap value is pinned.
    for v in [
        Some(r#"[{"Isuid":true,"Isgid":false,"Hostid":1131072,"Nsid":0,"Maprange":65536}]"#),
        None,
        Some("[ ]"),
        Some("null"),
    ] {
        let e = try_with(&|t| {
            t.config.remove("volatile.last_state.idmap");
            if let Some(x) = v {
                t.config
                    .insert("volatile.last_state.idmap".into(), x.into());
            }
        })
        .unwrap_err();
        assert_eq!(
            e,
            PreconditionFailed::TargetIdmap {
                target: "hx-restore-0a1b2c3d".into(),
                value: v.map(str::to_string)
            }
        );
    }
    // Pool.
    for actual in [Some("default"), None] {
        let e = try_with(&|t| {
            t.expanded_devices.clear();
            if let Some(a) = actual {
                t.expanded_devices.insert(
                    "root".into(),
                    [("type", "disk"), ("pool", a)]
                        .into_iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect(),
                );
            }
        })
        .unwrap_err();
        assert!(
            matches!(e, PreconditionFailed::TargetPool { .. }),
            "{actual:?}"
        );
    }
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
                    json!([{"name": SNAP, "created_at": "x", "stateful": false,
                            "config": {"volatile.last_state.idmap": "[]", "user.hx.state": "ready"}}]),
                )
            };
            Ok(ok(body))
        }
    }
    let c = Client::new(Canned);
    let info = c.server_info().await.unwrap();
    assert_eq!(info.kernel_features["idmapped_mounts"], "true");
    assert_eq!(info.kernel_features["netnsid_getifaddrs"], "false");
    let snaps = c.list_snapshots("hx-desk1").await.unwrap();
    assert_eq!(snaps[0].name, SNAP);
    assert_eq!(snaps[0].instance, "hx-desk1");
    assert_eq!(snaps[0].config["volatile.last_state.idmap"], "[]");
    // What the daemon reported is exactly what `checked` accepts.
    SnapshotMount::checked(&info, &good_pool(), &good_desktop(), &snaps[0]).unwrap();
}

// ---------------------------------------------------------------------------------------------
// The restore target
// ---------------------------------------------------------------------------------------------

fn naming() -> Naming {
    Naming::with_prefix("hx-").unwrap()
}

fn full_desktop() -> Instance {
    instance(json!({
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
            "security.nesting": "true",
            "user.hx.state": "ready",
            "image.os": "Debian",
            "image.release": "trixie",
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
        },
        "expanded_devices": {
            "root": {"type": "disk", "path": "/", "pool": "hx-pool", "size": "40GiB"},
            "eth0": {"type": "nic", "network": "hxbr0", "name": "eth0"},
        },
    }))
}

fn spec_of(d: &Instance) -> Result<RestoreTargetSpec, IncusError> {
    RestoreTargetSpec::from_desktop(d, target_name(), job(), &naming())
}

#[test]
fn the_restore_target_is_an_allowlisted_copy_marked_as_a_target() {
    let spec = spec_of(&full_desktop()).unwrap();
    assert_eq!(
        spec.to_json(),
        json!({
            "name": "hx-restore-0a1b2c3d",
            "type": "container",
            "source": {"type": "none"},
            "profiles": ["hx-desktop", "hx-compat-debian13"],
            "architecture": "x86_64",
            "ephemeral": false,
            "config": {
                "security.privileged": "false",
                "security.idmap.isolated": "true",
                "security.guestapi": "false",
                "security.nesting": "true",
                "boot.autostart": "false",
                "limits.cpu": "4",
                "limits.memory": "8192MiB",
                "limits.processes": "4096",
                "user.hx.kind": "restore-target",
                "user.hx.job": JOB,
                "user.hx.state": "restoring",
            },
            "devices": {
                "root": {"type": "disk", "path": "/", "pool": "hx-pool", "size": "40GiB"},
            },
        })
    );
    assert_eq!(spec.pool(), &pool());
    assert_eq!(spec.job(), job());
}

#[test]
fn the_restore_target_overrides_the_desktops_identity_and_copies_other_hx_keys() {
    let mut d = full_desktop();
    d.config.insert("user.hx.job".into(), "stale".into());
    d.config
        .insert("user.hx.created".into(), "2026-11-20".into());
    let spec = spec_of(&d).unwrap();
    assert_eq!(spec.config()["user.hx.state"], "restoring");
    assert_eq!(spec.config()["user.hx.job"], JOB);
    assert_eq!(spec.config()["user.hx.kind"], "restore-target");
    assert_eq!(spec.config()["user.hx.created"], "2026-11-20");
    assert!(
        spec.config()
            .keys()
            .all(|k| !k.starts_with("volatile.") && !k.starts_with("image."))
    );
}

#[test]
fn the_restore_target_refuses_everything_outside_the_allowlist() {
    let bad: Vec<(&str, Edit)> = vec![
        (
            "raw.lxc",
            Box::new(|d| {
                d.config.insert("raw.lxc".into(), "lxc.cap.drop=".into());
            }),
        ),
        (
            "raw.idmap",
            Box::new(|d| {
                d.config.insert("raw.idmap".into(), "both 0 0".into());
            }),
        ),
        (
            "security.idmap.base",
            Box::new(|d| {
                d.config.insert("security.idmap.base".into(), "0".into());
            }),
        ),
        (
            "security.idmap.size",
            Box::new(|d| {
                d.config
                    .insert("security.idmap.size".into(), "1000000".into());
            }),
        ),
        (
            "linux.sysctl",
            Box::new(|d| {
                d.config
                    .insert("linux.sysctl.net.ipv4.ip_forward".into(), "1".into());
            }),
        ),
        (
            "linux.kernel_modules",
            Box::new(|d| {
                d.config.insert("linux.kernel_modules".into(), "x".into());
            }),
        ),
        (
            "syscall intercept bpf",
            Box::new(|d| {
                d.config
                    .insert("security.syscalls.intercept.bpf".into(), "true".into());
            }),
        ),
        (
            "privileged true",
            Box::new(|d| {
                d.config.insert("security.privileged".into(), "true".into());
            }),
        ),
        (
            "isolated false",
            Box::new(|d| {
                d.config
                    .insert("security.idmap.isolated".into(), "false".into());
            }),
        ),
        (
            "isolated missing",
            Box::new(|d| {
                d.config.remove("security.idmap.isolated");
            }),
        ),
        (
            "bad memory",
            Box::new(|d| {
                d.config.insert("limits.memory".into(), "8GiB; rm".into());
            }),
        ),
        (
            "zero cpu",
            Box::new(|d| {
                d.config.insert("limits.cpu".into(), "0".into());
            }),
        ),
        (
            "bad bool",
            Box::new(|d| {
                d.config.insert("security.nesting".into(), "yes".into());
            }),
        ),
        (
            "odd hx key",
            Box::new(|d| {
                d.config.insert("user.hx.Bad Key".into(), "x".into());
            }),
        ),
        (
            "control char in hx value",
            Box::new(|d| {
                d.config.insert("user.hx.note".into(), "a\nb".into());
            }),
        ),
        (
            "user key outside hx",
            Box::new(|d| {
                d.config.insert("user.other".into(), "x".into());
            }),
        ),
        (
            "has a kind",
            Box::new(|d| {
                d.config.insert("user.hx.kind".into(), "desktop".into());
            }),
        ),
        (
            "unmarked",
            Box::new(|d| {
                d.config.remove("user.hx.state");
            }),
        ),
        (
            "host-source disk",
            Box::new(|d| {
                d.devices.insert(
                    "evil".into(),
                    [("type", "disk"), ("source", "/etc"), ("path", "/mnt")]
                        .into_iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect(),
                );
            }),
        ),
        (
            "extra nic",
            Box::new(|d| {
                d.devices.insert(
                    "eth1".into(),
                    [
                        ("type", "nic"),
                        ("network", "hxbr0"),
                        ("ipv4.address", "10.0.0.9"),
                    ]
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                );
            }),
        ),
        (
            "other proxy",
            Box::new(|d| {
                d.devices.insert(
                    "web".into(),
                    [
                        ("type", "proxy"),
                        ("listen", "tcp:0.0.0.0:80"),
                        ("connect", "tcp:127.0.0.1:80"),
                    ]
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                );
            }),
        ),
        (
            "root with a source",
            Box::new(|d| {
                d.devices
                    .get_mut("root")
                    .unwrap()
                    .insert("source".into(), "/etc".into());
            }),
        ),
        (
            "root on another pool",
            Box::new(|d| {
                d.devices
                    .get_mut("root")
                    .unwrap()
                    .insert("pool".into(), "default".into());
                d.expanded_devices
                    .get_mut("root")
                    .unwrap()
                    .insert("pool".into(), "default".into());
            }),
        ),
        (
            "root bad size",
            Box::new(|d| {
                d.devices
                    .get_mut("root")
                    .unwrap()
                    .insert("size".into(), "40GiB,x".into());
            }),
        ),
        (
            "hx-link that is a disk",
            Box::new(|d| {
                d.devices
                    .get_mut("hx-link")
                    .unwrap()
                    .insert("type".into(), "disk".into());
            }),
        ),
        (
            "foreign profile",
            Box::new(|d| d.profiles = vec!["default".into()]),
        ),
        (
            "extra profile",
            Box::new(|d| {
                d.profiles = vec![
                    "hx-desktop".into(),
                    "hx-compat-debian13".into(),
                    "default".into(),
                ]
            }),
        ),
        (
            "compat first",
            Box::new(|d| d.profiles = vec!["hx-compat-debian13".into(), "hx-desktop".into()]),
        ),
        ("no profile", Box::new(|d| d.profiles.clear())),
        ("vm", Box::new(|d| d.kind = "virtual-machine".into())),
        ("not a desktop name", Box::new(|d| d.name = "desk1".into())),
        (
            "other pool",
            Box::new(|d| {
                d.expanded_devices
                    .get_mut("root")
                    .unwrap()
                    .insert("pool".into(), "default".into());
            }),
        ),
        (
            "odd architecture",
            Box::new(|d| d.architecture = "x86;64".into()),
        ),
    ];
    for (what, f) in bad {
        let mut d = full_desktop();
        f(&mut d);
        let e = spec_of(&d).unwrap_err();
        assert!(matches!(e, IncusError::InvalidArgument(_)), "{what}: {e}");
    }
    // Sanity: the unmodified desktop is accepted, with or without the instance-level root disk
    // (the pool may come from the profile) and without the link.
    let mut d = full_desktop();
    d.devices.clear();
    assert!(spec_of(&d).unwrap().devices().is_empty());
}

#[test]
fn the_allowlist_covers_every_key_desktop_creation_sets() {
    use hx_provision::orchestrate::{DESKTOP_CONFIG_KEYS, DesktopSpec, Limits};
    let src = hx_provision::MemSource::new().with(
        "r.toml",
        "[recipe]\nname=\"t\"\nbase_image=\"images:debian/13\"\n[vars]\ndistro=\"debian\"\ndistro_version=\"13\"\n[user]\nname=\"desk\"\nuid=1000\n",
    );
    let plan = hx_provision::recipe::resolve(&src, "r.toml", &[]).unwrap();
    let spec = DesktopSpec::for_plan(
        "hx-t",
        naming(),
        &plan,
        Limits {
            cpu: Some(2),
            memory_mib: Some(2048),
            disk_gib: Some(20),
            processes: Some(4096),
        },
    );
    let create = spec.to_create().unwrap();
    for k in create.config.keys() {
        assert!(
            DESKTOP_CONFIG_KEYS.contains(&k.as_str()) || k.starts_with("user.hx."),
            "desktop creation sets `{k}`, which the restore target's allowlist lacks"
        );
    }
    // And such a desktop is accepted as a source once it has been through Incus.
    let mut d = full_desktop();
    d.config = create.config.clone();
    d.config
        .insert("volatile.last_state.idmap".into(), "[]".into());
    d.profiles = create.profiles.clone();
    d.devices = create.devices.clone();
    assert!(spec_of(&d).is_ok());
}

// ---------------------------------------------------------------------------------------------
// The client calls
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn creating_and_deleting_a_restore_target() {
    let (c, m) = client();
    let spec = spec_of(&full_desktop()).unwrap();
    c.create_restore_target(&spec, Duration::from_secs(5))
        .await
        .unwrap();
    let posts = m.requests("POST");
    assert_eq!(posts.len(), 1);
    assert_eq!(posts[0].0, "/1.0/instances");
    assert_eq!(posts[0].1, spec.to_json());
    assert!(m.requests("PUT").is_empty(), "the target is never started");

    let listed = c.list_restore_targets().await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        (&listed[0].name, listed[0].job),
        (&target_name(), Some(job()))
    );

    // Another job's id does not open it.
    let other = JobId::from_bytes([9; 16]).unwrap();
    assert!(matches!(
        c.delete_restore_target(&target_name(), Some(other)).await,
        Err(IncusError::InvalidArgument(_))
    ));
    assert!(m.requests("DELETE").is_empty());
    assert!(
        c.delete_restore_target(&target_name(), Some(job()))
            .await
            .unwrap()
    );
    assert!(!c.delete_restore_target(&target_name(), None).await.unwrap());
}

#[tokio::test]
async fn only_a_restore_target_can_be_deleted_as_one() {
    let (c, m) = client();
    // Named like a target and marked like a desktop (only user.hx.state=ready): not deletable.
    for (n, config) in [
        ("hx-restore-ffff", json!({"user.hx.state": "ready"})),
        ("hx-restore-eeee", json!({"foo": "bar"})),
        ("hx-restore-dddd", json!({"user.hx.kind": "backup-worker"})),
        ("hx-restore-cccc", json!({"user.hx.kind": "desktop"})),
    ] {
        m.put(n, "Stopped", config, json!({}));
        let e = c
            .delete_restore_target(&RestoreTargetName::new(n).unwrap(), None)
            .await
            .unwrap_err();
        assert!(matches!(e, IncusError::InvalidArgument(_)), "{n}: {e}");
        assert!(m.with(|d| d.instances.contains_key(n)));
    }
    assert!(m.requests("DELETE").is_empty() && m.requests("PUT").is_empty());
    assert!(c.list_restore_targets().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_target_that_is_not_what_was_asked_for_is_deleted_and_the_call_fails() {
    let (c, m) = client();
    m.with(|d| d.drop_config_key = Some("security.idmap.isolated".into()));
    let spec = spec_of(&full_desktop()).unwrap();
    let e = c
        .create_restore_target(&spec, Duration::from_secs(5))
        .await
        .unwrap_err();
    assert!(
        matches!(&e, IncusError::Protocol(m) if m.contains("security.idmap.isolated") && m.contains("deleted: true")),
        "{e}"
    );
    assert!(!m.with(|d| d.instances.contains_key("hx-restore-0a1b2c3d")));
    assert_eq!(m.requests("DELETE").len(), 1);
}

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
    let h = |f: &Pushed, k: &str| f.1.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
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

    c.start_backup_helper(job()).await.unwrap();
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
        .finish_backup_helper(job(), Duration::from_secs(10))
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
    c.start_backup_helper(job()).await.unwrap();
    let end = c
        .finish_backup_helper(job(), Duration::from_millis(500))
        .await
        .unwrap();
    assert_eq!(end, HelperEnd::ForceDeleted);
    let puts = m.requests("PUT");
    assert_eq!(puts.len(), 2);
    assert_eq!(puts[1].1["action"], "stop");
    assert_eq!(puts[1].1["force"], true);
    assert!(!m.with(|d| d.instances.contains_key("hx-bkw-0a1b2c3d")));
    // Repeating is harmless.
    assert!(!c.force_delete_backup_helper(job()).await.unwrap());
}

#[tokio::test]
async fn a_helper_that_never_started_is_deleted_directly_without_waiting_for_it_to_vanish() {
    let (c, m) = client();
    let spec = BackupHelperSpec::repository_only(pool(), RepoLink::new(job()));
    c.create_backup_helper(&spec).await.unwrap();
    // Stopped and never started: an ephemeral instance deletes itself only after PID 1 exits.
    let t = std::time::Instant::now();
    assert!(c.force_delete_backup_helper(job()).await.unwrap());
    assert!(
        t.elapsed() < Duration::from_secs(2),
        "no 5 s poll: {:?}",
        t.elapsed()
    );
    assert!(m.requests("PUT").is_empty(), "no stop for a stopped helper");
    assert_eq!(m.requests("DELETE").len(), 1);
    // Only the one GET before and the one after: no polling loop.
    let gets = m
        .keys()
        .iter()
        .filter(|k| k.starts_with("GET /1.0/instances/hx-bkw"))
        .count();
    assert!(gets <= 3, "{:?}", m.keys());
}

#[tokio::test]
async fn the_helper_calls_refuse_an_instance_that_is_not_the_helper_of_the_job() {
    let (c, m) = client();
    let other = JobId::from_bytes([0xde; 16]).unwrap();
    let name = other.helper_name().to_string();
    let spec = BackupHelperSpec::repository_only(pool(), RepoLink::new(other));
    for config in [
        // Named like a helper but marked like a desktop.
        json!({"user.hx.state": "ready"}),
        // Marked as a helper but of another job.
        json!({"user.hx.kind": "backup-worker", "user.hx.job": JOB}),
        // Marked as a helper without a job.
        json!({"user.hx.kind": "backup-worker"}),
        // The right job but another kind.
        json!({"user.hx.kind": "restore-target", "user.hx.job": other.hex()}),
    ] {
        m.put(&name, "Running", config, json!({}));
        for e in [
            c.force_delete_backup_helper(other).await.unwrap_err(),
            c.start_backup_helper(other).await.unwrap_err(),
            c.finish_backup_helper(other, Duration::from_millis(10))
                .await
                .unwrap_err(),
            c.populate_backup_helper(&spec, b"x").await.unwrap_err(),
        ] {
            assert!(matches!(e, IncusError::InvalidArgument(_)), "{e}");
        }
        assert!(m.requests("PUT").is_empty() && m.requests("DELETE").is_empty());
        assert!(m.with(|d| d.instances.contains_key(&name)));
    }
}

#[tokio::test]
async fn a_helper_with_a_nic_or_a_missing_key_is_deleted_and_the_call_fails() {
    for (what, set) in [
        (
            "nic",
            Box::new(|d: &mut Daemon| d.inject_nic = true) as Box<dyn Fn(&mut Daemon)>,
        ),
        (
            "profile",
            Box::new(|d: &mut Daemon| d.inject_profile = true),
        ),
        (
            "config",
            Box::new(|d: &mut Daemon| d.drop_config_key = Some("limits.memory".into())),
        ),
        (
            "config job",
            Box::new(|d: &mut Daemon| d.drop_config_key = Some("user.hx.job".into())),
        ),
    ] {
        let (c, m) = client();
        m.with(|d| set(d));
        let spec = BackupHelperSpec::backup(snapshot_mount(), RepoLink::new(job()));
        let e = c.create_backup_helper(&spec).await.unwrap_err();
        assert!(
            matches!(&e, IncusError::Protocol(msg) if msg.contains("not what was asked for")),
            "{what}: {e}"
        );
        if what != "config job" {
            // Ours by name, marker and job: deleted.
            assert!(
                !m.with(|d| d.instances.contains_key("hx-bkw-0a1b2c3d")),
                "{what}: left behind"
            );
            assert_eq!(m.requests("DELETE").len(), 1, "{what}");
        } else {
            // Without its job key it is not provably ours: it is reported, not deleted.
            assert!(m.requests("DELETE").is_empty());
        }
    }
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
    c.start_backup_helper(job()).await.unwrap();
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
async fn listing_finds_only_consistent_marked_helpers() {
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
    // Marked but oddly named, named like a helper but unmarked, a desktop, a bad job id, a job
    // id that does not belong to the name.
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
    m.put(
        "hx-bkw-33333333",
        "Stopped",
        json!({"user.hx.kind": "backup-worker", "user.hx.job": JOB}),
        json!({}),
    );
    let mut found = c.list_backup_helpers().await.unwrap();
    found.sort_by(|a, b| a.name.cmp(&b.name));
    let summary: Vec<(String, String, String)> = found
        .iter()
        .map(|h| (h.name.to_string(), h.job.hex(), h.status.clone()))
        .collect();
    assert_eq!(
        summary,
        [
            (
                "hx-bkw-0a1b2c3d".to_string(),
                JOB.to_string(),
                "Running".to_string()
            ),
            (
                "hx-bkw-cdcdcdcd".to_string(),
                job2.hex(),
                "Stopped".to_string()
            ),
        ]
    );
    assert_eq!(m.requests("GET")[0].0, "/1.0/instances?recursion=1");
}

#[tokio::test]
async fn an_incus_error_on_creation_is_returned_and_nothing_else_is_sent() {
    use std::sync::atomic::{AtomicU32, Ordering};
    struct Refuse(Arc<AtomicU32>);
    impl Transport for Refuse {
        async fn send(&self, _: Request) -> Result<Response, IncusError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(err(400, "Failed to start dnsmasq"))
        }
    }
    let calls = Arc::new(AtomicU32::new(0));
    let spec = BackupHelperSpec::backup(snapshot_mount(), RepoLink::new(job()));
    let e = Client::new(Refuse(calls.clone()))
        .create_backup_helper(&spec)
        .await
        .unwrap_err();
    assert!(matches!(e, IncusError::Api { code: 400, .. }), "{e}");
    assert_eq!(calls.load(Ordering::SeqCst), 1, "only the POST was sent");
}

#[tokio::test]
async fn a_delete_that_races_incus_own_deletion_is_not_an_error() {
    let (c, m) = client();
    let spec = BackupHelperSpec::repository_only(pool(), RepoLink::new(job()));
    c.create_backup_helper(&spec).await.unwrap();
    m.with(|d| d.delete_races = true);
    // Stopped: deleted directly; the DELETE fails but the helper is gone.
    assert!(c.force_delete_backup_helper(job()).await.unwrap());
    assert!(!m.with(|d| d.instances.contains_key("hx-bkw-0a1b2c3d")));
    // A DELETE that fails while the instance stays is still an error.
    m.with(|d| d.delete_races = false);
    c.create_backup_helper(&spec).await.unwrap();
    struct Stuck(Mock);
    impl Transport for Stuck {
        async fn send(&self, r: Request) -> Result<Response, IncusError> {
            if r.method == hyper::Method::DELETE && r.path.starts_with("/1.0/instances/") {
                return Ok(err(500, "Instance is busy"));
            }
            self.0.send(r).await
        }
    }
    let e = Client::new(Stuck(m.clone()))
        .force_delete_backup_helper(job())
        .await
        .unwrap_err();
    assert!(matches!(e, IncusError::Api { code: 500, .. }), "{e}");
}

#[test]
fn the_allowlist_bounds_come_from_the_crates_limits() {
    use hx_provision::incus::{MAX_CPU, MAX_DISK_GIB, MAX_MEMORY_MIB};
    let try_cfg = |k: &str, v: String| {
        let mut d = full_desktop();
        d.config.insert(k.into(), v);
        spec_of(&d)
    };
    let try_root = |size: String| {
        let mut d = full_desktop();
        d.devices
            .get_mut("root")
            .unwrap()
            .insert("size".into(), size);
        spec_of(&d)
    };
    assert!(try_cfg("limits.memory", format!("{MAX_MEMORY_MIB}MiB")).is_ok());
    assert!(try_cfg("limits.memory", format!("{}MiB", MAX_MEMORY_MIB + 1)).is_err());
    assert!(try_cfg("limits.cpu", MAX_CPU.to_string()).is_ok());
    assert!(try_cfg("limits.cpu", (MAX_CPU + 1).to_string()).is_err());
    assert!(try_cfg("limits.processes", u32::MAX.to_string()).is_ok());
    assert!(try_cfg("limits.processes", (u64::from(u32::MAX) + 1).to_string()).is_err());
    assert!(try_root(format!("{MAX_DISK_GIB}GiB")).is_ok());
    assert!(try_root(format!("{}GiB", MAX_DISK_GIB + 1)).is_err());
    for bad in ["0", "01", "+5", "-1", "5 ", "", "99999999999999999999999"] {
        assert!(try_cfg("limits.cpu", bad.into()).is_err(), "{bad:?}");
        assert!(
            try_cfg("limits.memory", format!("{bad}MiB")).is_err(),
            "{bad:?}"
        );
        assert!(try_root(format!("{bad}GiB")).is_err(), "{bad:?}");
    }
    // The guest API stays off.
    assert!(try_cfg("security.guestapi", "true".into()).is_err());
    assert!(try_cfg("security.guestapi", "false".into()).is_ok());
}
