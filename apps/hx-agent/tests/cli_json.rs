//! `--json` stability: the exact output of each command against stand-in daemons with fixed data.
//! These are the contract of scripts that parse the CLI; a change here is a breaking change and
//! belongs in the usage document (`src/cli/README.md`) as well.

mod cli_common;

use std::sync::Arc;

use cli_common::*;
use hx_ipc::admin::pb as apb;
use hx_ipc::privd::pb::{self, request::Command, response::Result as R};
use serde_json::{Value, json};

fn desktop() -> pb::Desktop {
    pb::Desktop {
        desktop_id: "main".into(),
        state: pb::DesktopState::Running as i32,
        username: "alice".into(),
        distro: pb::Distro::Ubuntu2404 as i32,
        preset: pb::Preset::Basic as i32,
        ip: "10.77.0.2".into(),
        limits: Some(pb::Limits {
            cpu: 2,
            memory_mib: 4096,
            disk_gib: 40,
        }),
        docker: pb::DockerState::Off as i32,
        needs_attention: vec![],
        session: Some(pb::SessionInfo {
            installed_version: "0.1.0".into(),
            link_provisioned: true,
        }),
        snapshot_count: 1,
        created_unix_s: 1_700_000_000,
    }
}

fn snapshot() -> pb::Snapshot {
    pb::Snapshot {
        name: "hx-manual-20261121T101500Z-ab12".into(),
        kind: pb::SnapshotKind::Manual as i32,
        created_unix_s: 1_795_000_000,
        size_bytes: 1_048_576,
    }
}

fn canned_privd() -> PrivdHandler {
    Arc::new(|req, _s| {
        Box::pin(async move {
            let r: R = match req.command.expect("a command") {
                Command::GetHostInfo(_) => R::GetHostInfo(pb::GetHostInfoResult {
                    privd_version: "0.1.0".into(),
                    phase: pb::Phase::Ready as i32,
                    os_id: "ubuntu".into(),
                    os_version: "24.04".into(),
                    arch: "x86_64".into(),
                    cpu_count: 4,
                    memory_total_mib: 16_000,
                    memory_available_mib: 9_000,
                    pool: Some(pb::PoolInfo {
                        exists: true,
                        driver: "dir".into(),
                        total_gib: 100,
                        free_gib: 60,
                    }),
                    incus_version: Some("6.0.0".into()),
                    docker_on_host: false,
                    host_firewall_loaded: true,
                    sysctl_ok: true,
                    needs_attention: vec![pb::NeedsAttention::PinLocked as i32],
                    desktop_exists: true,
                }),
                Command::ListDesktops(_) => R::ListDesktops(pb::ListDesktopsResult {
                    desktops: vec![desktop()],
                }),
                Command::GetDesktop(_) => R::GetDesktop(pb::GetDesktopResult {
                    desktop: Some(desktop()),
                }),
                Command::SetLimits(_) => R::SetLimits(pb::SetLimitsResult {
                    restart_required: true,
                }),
                Command::StartDesktop(_) => R::StartDesktop(pb::PowerResult {
                    running: true,
                    degraded: false,
                }),
                Command::StopDesktop(_) => R::StopDesktop(pb::PowerResult {
                    running: false,
                    degraded: false,
                }),
                Command::RestartDesktop(_) => R::RestartDesktop(pb::PowerResult {
                    running: true,
                    degraded: true,
                }),
                Command::ListSnapshots(_) => R::ListSnapshots(pb::ListSnapshotsResult {
                    snapshots: vec![snapshot()],
                }),
                Command::CreateSnapshot(_) => R::CreateSnapshot(pb::CreateSnapshotResult {
                    snapshot: Some(snapshot()),
                }),
                Command::DeleteSnapshot(_) => R::DeleteSnapshot(Default::default()),
                Command::CheckUpdate(_) => R::CheckUpdate(pb::CheckUpdateResult {
                    current: "0.1.0".into(),
                    available: Some("0.2.0".into()),
                    channel: pb::UpdateChannel::Stable as i32,
                    verified: true,
                    rolled_back: Some(pb::RolledBack {
                        version: "0.1.9".into(),
                        reason: "health check failed".into(),
                    }),
                }),
                Command::ApplyUpdate(_) => {
                    R::ApplyUpdate(pb::ApplyUpdateResult { restarting: true })
                }
                Command::RollbackUpdate(_) => R::RollbackUpdate(Default::default()),
                Command::EnableDocker(_) => R::EnableDocker(pb::EnableDockerResult {
                    outcome: Some(pb::DockerOutcome {
                        outcome: Some(pb::docker_outcome::Outcome::Enabled(pb::DockerEnabled {
                            docker_version: "27.3.1".into(),
                        })),
                    }),
                }),
                Command::DisableDocker(_) => {
                    R::DisableDocker(pb::DisableDockerResult { restarted: true })
                }
                Command::ResetLockout(_) => R::ResetLockout(Default::default()),
                Command::BeginSetup(_) => R::BeginSetup(pb::BeginSetupResult {
                    expires_at_unix_s: 1_900_007_200,
                }),
                Command::ExtendSetup(_) => R::ExtendSetup(pb::ExtendSetupResult {
                    expires_at_unix_s: 1_900_009_000,
                }),
                Command::FinishSetup(_) => R::FinishSetup(Default::default()),
                Command::SetUserPassword(_) => R::SetUserPassword(Default::default()),
                Command::PepperEnrol(_) => R::PepperEnrol(pb::PepperEnrolResult {
                    mac: vec![7u8; 32].into(),
                    version: 1,
                }),
                Command::Uninstall(_) => {
                    return privd_error(pb::ErrorCode::Unimplemented, "reserved").into();
                }
                _ => return privd_error(pb::ErrorCode::Unimplemented, "not canned").into(),
            };
            r.into()
        })
    })
}

fn canned_admin() -> AdminHandler {
    Arc::new(|req, _s| {
        Box::pin(async move {
            use apb::request::Command as C;
            use apb::response::Result as A;
            match req.command.expect("a command") {
                C::Status(_) => A::Status(apb::StatusResult {
                    gatewayd_version: "0.1.0".into(),
                    listening: true,
                    connected_clients: 1,
                    certificate: apb::CertificateState::Valid as i32,
                    certificate_not_after_unix_s: 1_900_000_000,
                    setup_window: Some(apb::SetupWindowState {
                        open: true,
                        expires_at_unix_s: 1_900_007_200,
                    }),
                    session_link: apb::LinkState::Up as i32,
                    registry_version: 5,
                    ..Default::default()
                }),
                C::ListDevices(_) => A::ListDevices(apb::ListDevicesResult {
                    devices: vec![
                        apb::Device {
                            device_id: vec![0xaa; 16].into(),
                            name: "laptop".into(),
                            created_unix_s: 1_700_000_000,
                            last_seen_unix_s: 1_795_000_000,
                            state: apb::DeviceState::Active as i32,
                        },
                        apb::Device {
                            device_id: vec![0xbb; 16].into(),
                            name: "phone".into(),
                            created_unix_s: 1_710_000_000,
                            last_seen_unix_s: 0,
                            state: apb::DeviceState::Locked as i32,
                        },
                    ],
                }),
                C::RevokeDevice(_) => {
                    A::RevokeDevice(apb::RevokeDeviceResult { sessions_closed: 2 })
                }
                C::ReinstateDevice(_) => A::ReinstateDevice(Default::default()),
                C::SetPinVerifier(_) => A::SetPinVerifier(Default::default()),
                C::SetPasswordVerifier(_) => A::SetPasswordVerifier(Default::default()),
                C::CreatePairingToken(_) => A::CreatePairingToken(apb::CreatePairingTokenResult {
                    expires_at_unix_s: 1_900_000_900,
                }),
                C::CreatePairingCode(_) => A::CreatePairingCode(apb::CreatePairingCodeResult {
                    code: "ABCD-2345".into(),
                    expires_at_unix_s: 1_900_000_900,
                }),
                C::SetupWindow(_) => A::SetupWindow(apb::SetupWindowResult {
                    state: Some(apb::SetupWindowState {
                        open: true,
                        expires_at_unix_s: 1_900_007_200,
                    }),
                }),
                C::CloseSessions(_) => A::CloseSessions(Default::default()),
            }
        })
    })
}

async fn stack() -> (tempfile::TempDir, hx_agent::cli::Config) {
    let dir = private_tempdir();
    let p = ScriptedPrivd::start(
        dir.path(),
        "p.sock",
        PrivdOptions::default(),
        canned_privd(),
    )
    .await;
    let a = ScriptedAdmin::start(dir.path(), "a.sock", "0.1.0", canned_admin()).await;
    let mut cfg = unreachable_config(dir.path());
    cfg.privd_socket = p.path.clone();
    cfg.admin_socket = a.path.clone();
    // Leak the stand-ins' handles into the tempdir's lifetime: they live as long as the runtime.
    std::mem::forget(p);
    std::mem::forget(a);
    (dir, cfg)
}

async fn golden(
    cfg: &hx_agent::cli::Config,
    args: &[&str],
    secrets: &[&[u8]],
    lines: &[&str],
    expect_exit: u8,
    expected: Value,
) {
    let mut a: Vec<&str> = args.to_vec();
    a.push("--json");
    let r = cli(cfg, &a, secrets, lines).await;
    assert_eq!(r.code, expect_exit, "{args:?}: {r:?}");
    assert!(
        r.stderr.is_empty() || expect_exit != 0 || args[0] == "pairing",
        "{args:?}: stderr {:?}",
        r.stderr
    );
    assert_eq!(
        r.stdout.lines().count(),
        1,
        "{args:?}: exactly one line of JSON"
    );
    assert_eq!(r.json(), expected, "{args:?}");
}

fn dev(id: &str, name: &str, state: &str, created: u64, seen: u64) -> Value {
    json!({"id": id, "name": name, "state": state, "created_unix_s": created, "last_seen_unix_s": seen})
}

fn snap_json() -> Value {
    json!({"name": "hx-manual-20261121T101500Z-ab12", "kind": "MANUAL", "created_unix_s": 1_795_000_000u64, "size_bytes": 1_048_576})
}

const AA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BB: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[tokio::test]
async fn status_json_is_stable() {
    let (_d, cfg) = stack().await;
    golden(
        &cfg,
        &["status"],
        &[],
        &[],
        0,
        json!({
            "ok": true,
            "command": "status",
            "data": {
                "cli_version": env!("CARGO_PKG_VERSION"),
                "privd": {
                    "reachable": true,
                    "version": "0.1.0",
                    "phase": "READY",
                    "host": {
                        "os_id": "ubuntu", "os_version": "24.04", "arch": "x86_64",
                        "cpu_count": 4, "memory_total_mib": 16000, "memory_available_mib": 9000,
                        "incus_version": "6.0.0", "docker_on_host": false,
                        "host_firewall_loaded": true, "sysctl_ok": true,
                        "pool": {"exists": true, "driver": "dir", "total_gib": 100, "free_gib": 60}
                    },
                    "needs_attention": ["PIN_LOCKED"],
                    "desktops": [{
                        "id": "main", "state": "RUNNING", "username": "alice",
                        "distro": "UBUNTU_24_04", "preset": "BASIC", "ip": "10.77.0.2",
                        "limits": {"cpu": 2, "memory_mib": 4096, "disk_gib": 40},
                        "docker": "OFF", "needs_attention": [],
                        "session": {"installed_version": "0.1.0", "link_provisioned": true},
                        "snapshots": 1, "created_unix_s": 1_700_000_000u64
                    }]
                },
                "gatewayd": {
                    "reachable": true, "version": "0.1.0", "listening": true,
                    "connected_clients": 1, "certificate": "VALID",
                    "certificate_not_after_unix_s": 1_900_000_000u64,
                    "setup_window": {"open": true, "expires_at_unix_s": 1_900_007_200u64},
                    "session_link": "UP", "link_faults_10min": 0, "registry_version": 5
                },
                "devices": {"total": 2, "active": 1, "revoked": 0, "locked": 1},
                "needs_attention": ["PIN_LOCKED"],
                "lockouts": {"pin": true, "password": false, "devices_locked": 1}
            }
        }),
    )
    .await;
}

#[tokio::test]
async fn device_commands_json_is_stable() {
    let (_d, cfg) = stack().await;
    golden(
        &cfg,
        &["devices", "list"],
        &[],
        &[],
        0,
        json!({"ok": true, "command": "devices list", "data": {"devices": [
            dev(AA, "laptop", "ACTIVE", 1_700_000_000, 1_795_000_000),
            dev(BB, "phone", "LOCKED", 1_710_000_000, 0),
        ]}}),
    )
    .await;
    golden(
        &cfg,
        &["devices", "revoke", "aaaa"],
        &[],
        &[],
        0,
        json!({"ok": true, "command": "devices revoke", "data": {
            "device": dev(AA, "laptop", "ACTIVE", 1_700_000_000, 1_795_000_000),
            "revoked": true, "sessions_closed": 2}}),
    )
    .await;
    golden(
        &cfg,
        &["devices", "reinstate", "bbbb"],
        &[],
        &[],
        0,
        json!({"ok": true, "command": "devices reinstate", "data": {
            "device": dev(BB, "phone", "LOCKED", 1_710_000_000, 0), "reinstated": true}}),
    )
    .await;
    // The error envelope.
    golden(
        &cfg,
        &["devices", "revoke", "cccc"],
        &[],
        &[],
        5,
        json!({"ok": false, "command": "devices revoke", "error": {
            "code": "NOT_FOUND",
            "message": "no device id starts with cccc (see: hx-agent devices list)"}}),
    )
    .await;
}

#[tokio::test]
async fn pairing_pin_and_setup_json_is_stable() {
    let (_d, cfg) = stack().await;
    golden(
        &cfg,
        &["pairing", "code"],
        &[],
        &[],
        0,
        json!({"ok": true, "command": "pairing code", "data": {"code": "ABCD-2345", "expires_at_unix_s": 1_900_000_900u64}}),
    )
    .await;
    let token = hx_crypto::PairingToken::generate().unwrap().to_text();
    golden(
        &cfg,
        &["pairing", "token"],
        &[token.as_bytes()],
        &[],
        0,
        json!({"ok": true, "command": "pairing token", "data": {"installed": true, "expires_at_unix_s": 1_900_000_900u64}}),
    )
    .await;
    golden(
        &cfg,
        &["pin", "set"],
        &[b"482913", b"482913"],
        &[],
        0,
        json!({"ok": true, "command": "pin set", "data": {"pin_set": true, "target": "all"}}),
    )
    .await;
    golden(
        &cfg,
        &["pin", "reset-lockout", "--yes"],
        &[],
        &[],
        0,
        json!({"ok": true, "command": "pin reset-lockout", "data": {"reset": true, "purpose": "PIN", "audited": true}}),
    )
    .await;
    golden(
        &cfg,
        &["setup", "begin", "--yes"],
        &[],
        &[],
        0,
        json!({"ok": true, "command": "setup begin", "data": {"open": true, "expires_at_unix_s": 1_900_007_200u64}}),
    )
    .await;
    golden(
        &cfg,
        &["setup", "extend", "30m"],
        &[],
        &[],
        0,
        json!({"ok": true, "command": "setup extend", "data": {"open": true, "expires_at_unix_s": 1_900_009_000u64}}),
    )
    .await;
    golden(
        &cfg,
        &["setup", "finish"],
        &[],
        &[],
        0,
        json!({"ok": true, "command": "setup finish", "data": {"open": false}}),
    )
    .await;
}

#[tokio::test]
async fn desktop_docker_and_snapshot_json_is_stable() {
    let (_d, cfg) = stack().await;
    golden(
        &cfg,
        &["desktop", "stop"],
        &[],
        &[],
        0,
        json!({"ok": true, "command": "desktop stop", "data": {"desktop": "main", "running": false, "degraded": false}}),
    )
    .await;
    golden(
        &cfg,
        &["desktop", "restart"],
        &[],
        &[],
        0,
        json!({"ok": true, "command": "desktop restart", "data": {"desktop": "main", "running": true, "degraded": true}}),
    )
    .await;
    golden(
        &cfg,
        &["desktop", "limits"],
        &[],
        &[],
        0,
        json!({"ok": true, "command": "desktop limits", "data": {"desktop": "main", "limits": {"cpu": 2, "memory_mib": 4096, "disk_gib": 40}}}),
    )
    .await;
    golden(
        &cfg,
        &["desktop", "limits", "--cpu", "4"],
        &[],
        &[],
        0,
        json!({"ok": true, "command": "desktop limits", "data": {"desktop": "main", "limits": {"cpu": 4, "memory_mib": 4096, "disk_gib": 40}, "restart_required": true}}),
    )
    .await;
    golden(
        &cfg,
        &["desktop", "password"],
        &[b"A-long-password-1", b"A-long-password-1"],
        &[],
        0,
        json!({"ok": true, "command": "desktop password", "data": {"desktop": "main", "password_changed": true, "verifier_refreshed": true, "verified_against_desktop": true}}),
    )
    .await;
    golden(
        &cfg,
        &["docker", "enable", "--yes"],
        &[],
        &[],
        0,
        json!({"ok": true, "command": "docker enable", "data": {"desktop": "main", "outcome": "ENABLED", "docker_version": "27.3.1"}}),
    )
    .await;
    golden(
        &cfg,
        &["docker", "disable"],
        &[],
        &[],
        0,
        json!({"ok": true, "command": "docker disable", "data": {"desktop": "main", "docker": "OFF", "restarted": true}}),
    )
    .await;
    golden(
        &cfg,
        &["snapshots", "list"],
        &[],
        &[],
        0,
        json!({"ok": true, "command": "snapshots list", "data": {"desktop": "main", "snapshots": [snap_json()]}}),
    )
    .await;
    golden(
        &cfg,
        &["snapshots", "create"],
        &[],
        &[],
        0,
        json!({"ok": true, "command": "snapshots create", "data": {"desktop": "main", "snapshot": snap_json()}}),
    )
    .await;
    golden(
        &cfg,
        &["snapshots", "delete", "hx-manual-20261121T101500Z-ab12"],
        &[],
        &[],
        0,
        json!({"ok": true, "command": "snapshots delete", "data": {"desktop": "main", "deleted": "hx-manual-20261121T101500Z-ab12"}}),
    )
    .await;
}

#[tokio::test]
async fn update_and_uninstall_json_is_stable() {
    let (_d, cfg) = stack().await;
    golden(
        &cfg,
        &["update", "check"],
        &[],
        &[],
        0,
        json!({"ok": true, "command": "update check", "data": {
            "current": "0.1.0", "available": "0.2.0", "channel": "STABLE", "verified": true,
            "rolled_back": {"version": "0.1.9", "reason": "health check failed"}}}),
    )
    .await;
    golden(
        &cfg,
        &["update", "apply", "--yes"],
        &[],
        &[],
        0,
        json!({"ok": true, "command": "update apply", "data": {"version": "0.2.0", "restarting": true}}),
    )
    .await;
    golden(
        &cfg,
        &["update", "rollback", "--yes"],
        &[],
        &[],
        0,
        json!({"ok": true, "command": "update rollback", "data": {"rolled_back": true}}),
    )
    .await;
    // UNIMPLEMENTED uninstall: the manual steps, exit 6, ok false.
    let r = cli(
        &cfg,
        &["uninstall", "--keep-desktop", "--yes", "--json"],
        &[],
        &[],
    )
    .await;
    assert_eq!(r.code, 6, "{r:?}");
    let v = r.json();
    assert_eq!(v["ok"], false);
    assert_eq!(v["command"], "uninstall");
    assert_eq!(v["data"]["implemented"], false);
    assert_eq!(v["data"]["uninstalled"], false);
    assert_eq!(v["data"]["keep_desktop"], true);
    assert!(v["data"]["manual_steps"].as_array().unwrap().len() >= 5);
    let human = cli(&cfg, &["uninstall", "--destroy-desktop", "--yes"], &[], &[]).await;
    assert_eq!(human.code, 6);
    assert!(
        human.stdout.contains("Nothing was changed"),
        "{}",
        human.stdout
    );
    assert!(human.stdout.contains("incus delete --force hx-main"));
}
