//! `hx-agent status`.
//!
//! Calls: privd `GetHostInfo` and `ListDesktops` (a superset of `GetDesktop` that does not hard
//! code the desktop id), gatewayd `Status` and `ListDevices` (for the device and lockout counts).
//! Each daemon is reported on its own: one being down does not hide the other, and the exit code
//! is 3 when either is unreachable.

use hx_ipc::admin::pb as apb;
use hx_ipc::privd::pb::{self, request::Command, response::Result as R};
use serde_json::{Value, json};

use super::{admin, enum_name, privd};
use crate::cli::error::{CliError, exit};
use crate::cli::text::{peer, time};
use crate::cli::{Env, Outcome};

fn needs_json(list: &[i32]) -> Vec<&'static str> {
    list.iter()
        .map(|n| enum_name!(pb::NeedsAttention, *n, "NEEDS_ATTENTION_"))
        .collect()
}

fn limits_json(l: &Option<pb::Limits>) -> Value {
    let l = l.unwrap_or_default();
    json!({"cpu": l.cpu, "memory_mib": l.memory_mib, "disk_gib": l.disk_gib})
}

fn desktop_json(d: &pb::Desktop) -> Value {
    let session = d.session.clone().unwrap_or_default();
    json!({
        "id": peer(&d.desktop_id, 16),
        "state": enum_name!(pb::DesktopState, d.state, "DESKTOP_STATE_"),
        "username": peer(&d.username, 64),
        "distro": enum_name!(pb::Distro, d.distro, "DISTRO_"),
        "preset": enum_name!(pb::Preset, d.preset, "PRESET_"),
        "ip": peer(&d.ip, 64),
        "limits": limits_json(&d.limits),
        "docker": enum_name!(pb::DockerState, d.docker, "DOCKER_STATE_"),
        "needs_attention": needs_json(&d.needs_attention),
        "session": {
            "installed_version": peer(&session.installed_version, 64),
            "link_provisioned": session.link_provisioned,
        },
        "snapshots": d.snapshot_count,
        "created_unix_s": d.created_unix_s,
    })
}

struct PrivdPart {
    json: Value,
    text: String,
    needs: Vec<&'static str>,
    reachable: bool,
}

fn privd_part(env: &Env<'_>) -> PrivdPart {
    let down = |e: CliError| PrivdPart {
        json: json!({"reachable": false, "error": e.message()}),
        text: format!("hx-privd       not reachable: {}\n", e.message()),
        needs: vec![],
        reachable: false,
    };
    let mut c = match privd(env) {
        Ok(c) => c,
        Err(e) => return down(e),
    };
    let host = match c.simple(Command::GetHostInfo(pb::GetHostInfoRequest {})) {
        Ok(R::GetHostInfo(h)) => h,
        Ok(_) => {
            return down(CliError::failed(
                "hx-privd answered with the wrong result type",
            ));
        }
        Err(e) => return down(e),
    };
    let desktops = match c.simple(Command::ListDesktops(pb::ListDesktopsRequest {})) {
        Ok(R::ListDesktops(l)) => l.desktops,
        Ok(_) => {
            return down(CliError::failed(
                "hx-privd answered with the wrong result type",
            ));
        }
        Err(e) => return down(e),
    };
    let pool = host.pool.unwrap_or_default();
    let phase = enum_name!(pb::Phase, host.phase, "PHASE_");
    let mut needs = needs_json(&host.needs_attention);
    for d in &desktops {
        needs.extend(needs_json(&d.needs_attention));
    }
    needs.sort_unstable();
    needs.dedup();

    let mut t = String::new();
    t.push_str(&format!(
        "hx-privd       {} running, phase {}\n",
        peer(&host.privd_version, 64),
        phase
    ));
    t.push_str(&format!(
        "  host         {} {} {}, {} CPUs, {}/{} MiB memory available\n",
        peer(&host.os_id, 32),
        peer(&host.os_version, 32),
        peer(&host.arch, 16),
        host.cpu_count,
        host.memory_available_mib,
        host.memory_total_mib
    ));
    t.push_str(&format!(
        "  incus        {}\n",
        host.incus_version
            .as_deref()
            .map(|v| peer(v, 64))
            .unwrap_or_else(|| "not reachable".into())
    ));
    t.push_str(&format!(
        "  pool         {}\n",
        if pool.exists {
            format!(
                "{} {}/{} GiB free",
                peer(&pool.driver, 32),
                pool.free_gib,
                pool.total_gib
            )
        } else {
            "none".into()
        }
    ));
    t.push_str(&format!(
        "  firewall     host table {}, sysctl {}, docker on host: {}\n",
        if host.host_firewall_loaded {
            "loaded"
        } else {
            "NOT loaded"
        },
        if host.sysctl_ok { "ok" } else { "NOT ok" },
        if host.docker_on_host { "yes" } else { "no" }
    ));
    if desktops.is_empty() {
        t.push_str("  desktop      none\n");
    }
    for d in &desktops {
        let s = d.session.clone().unwrap_or_default();
        let l = d.limits.unwrap_or_default();
        t.push_str(&format!(
            "  desktop      {} {} (user {}, {} {}), ip {}\n",
            peer(&d.desktop_id, 16),
            enum_name!(pb::DesktopState, d.state, "DESKTOP_STATE_").to_lowercase(),
            peer(&d.username, 64),
            enum_name!(pb::Distro, d.distro, "DISTRO_").to_lowercase(),
            enum_name!(pb::Preset, d.preset, "PRESET_").to_lowercase(),
            peer(&d.ip, 64)
        ));
        t.push_str(&format!(
            "               limits {} CPU, {} MiB memory, {} GiB disk; docker {}; {} snapshots\n",
            l.cpu,
            l.memory_mib,
            l.disk_gib,
            enum_name!(pb::DockerState, d.docker, "DOCKER_STATE_").to_lowercase(),
            d.snapshot_count
        ));
        t.push_str(&format!(
            "               session package {} (link {})\n",
            if s.installed_version.is_empty() {
                "not installed".into()
            } else {
                peer(&s.installed_version, 64)
            },
            if s.link_provisioned {
                "provisioned"
            } else {
                "not provisioned"
            }
        ));
    }
    PrivdPart {
        json: json!({
            "reachable": true,
            "version": peer(&host.privd_version, 64),
            "phase": phase,
            "host": {
                "os_id": peer(&host.os_id, 32),
                "os_version": peer(&host.os_version, 32),
                "arch": peer(&host.arch, 16),
                "cpu_count": host.cpu_count,
                "memory_total_mib": host.memory_total_mib,
                "memory_available_mib": host.memory_available_mib,
                "incus_version": host.incus_version.as_deref().map(|v| peer(v, 64)),
                "docker_on_host": host.docker_on_host,
                "host_firewall_loaded": host.host_firewall_loaded,
                "sysctl_ok": host.sysctl_ok,
                "pool": {
                    "exists": pool.exists,
                    "driver": peer(&pool.driver, 32),
                    "total_gib": pool.total_gib,
                    "free_gib": pool.free_gib,
                },
            },
            "needs_attention": needs_json(&host.needs_attention),
            "desktops": desktops.iter().map(desktop_json).collect::<Vec<_>>(),
        }),
        text: t,
        needs,
        reachable: true,
    }
}

struct GatewayPart {
    json: Value,
    text: String,
    devices: Value,
    locked_devices: Option<u64>,
    reachable: bool,
}

fn gateway_part(env: &Env<'_>) -> GatewayPart {
    let down = |e: CliError| GatewayPart {
        json: json!({"reachable": false, "error": e.message()}),
        text: format!("hx-gatewayd    not reachable: {}\n", e.message()),
        devices: Value::Null,
        locked_devices: None,
        reachable: false,
    };
    let mut c = match admin(env) {
        Ok(c) => c,
        Err(e) => return down(e),
    };
    let s = match c.call(apb::request::Command::Status(apb::StatusRequest {}), None) {
        Ok(apb::response::Result::Status(s)) => s,
        Ok(_) => {
            return down(CliError::failed(
                "hx-gatewayd answered with the wrong result type",
            ));
        }
        Err(e) => return down(e),
    };
    let devs = match c.call(
        apb::request::Command::ListDevices(apb::ListDevicesRequest {}),
        None,
    ) {
        Ok(apb::response::Result::ListDevices(l)) => l.devices,
        Ok(_) => {
            return down(CliError::failed(
                "hx-gatewayd answered with the wrong result type",
            ));
        }
        Err(e) => return down(e),
    };
    let count = |st: apb::DeviceState| devs.iter().filter(|d| d.state == st as i32).count();
    let (active, revoked, locked) = (
        count(apb::DeviceState::Active),
        count(apb::DeviceState::Revoked),
        count(apb::DeviceState::Locked),
    );
    let setup = s.setup_window.unwrap_or_default();
    let cert = enum_name!(apb::CertificateState, s.certificate, "CERTIFICATE_STATE_");
    let link = enum_name!(apb::LinkState, s.session_link, "LINK_STATE_");
    let mut t = String::new();
    t.push_str(&format!(
        "hx-gatewayd    {} {}, {} connected clients\n",
        peer(&s.gatewayd_version, 64),
        if s.listening {
            "listening"
        } else {
            "NOT listening"
        },
        s.connected_clients
    ));
    t.push_str(&format!(
        "  setup window {}\n",
        if setup.open {
            format!("open until {}", time(setup.expires_at_unix_s))
        } else {
            "closed".into()
        }
    ));
    t.push_str(&format!(
        "  session link {} ({} faults in 10 min), certificate {}, registry v{}\n",
        link.to_lowercase(),
        s.link_faults_10min,
        cert.to_lowercase(),
        s.registry_version
    ));
    t.push_str(&format!(
        "  devices      {} total: {active} active, {revoked} revoked, {locked} locked\n",
        devs.len()
    ));
    GatewayPart {
        json: json!({
            "reachable": true,
            "version": peer(&s.gatewayd_version, 64),
            "listening": s.listening,
            "connected_clients": s.connected_clients,
            "certificate": cert,
            "certificate_not_after_unix_s": s.certificate_not_after_unix_s,
            "setup_window": {"open": setup.open, "expires_at_unix_s": setup.expires_at_unix_s},
            "session_link": link,
            "link_faults_10min": s.link_faults_10min,
            "registry_version": s.registry_version,
        }),
        text: t,
        devices: json!({"total": devs.len(), "active": active, "revoked": revoked, "locked": locked}),
        locked_devices: Some(locked as u64),
        reachable: true,
    }
}

pub(super) fn run(env: &mut Env<'_>) -> Result<Outcome, CliError> {
    let p = privd_part(env);
    let g = gateway_part(env);
    let pin_locked = p.needs.contains(&"PIN_LOCKED");
    let password_locked = p.needs.contains(&"PASSWORD_LOCKED");
    let mut text = format!("hx-agent       {}\n", env!("CARGO_PKG_VERSION"));
    text.push_str(&p.text);
    text.push_str(&g.text);
    text.push_str("attention      ");
    if !p.reachable {
        text.push_str("unknown (hx-privd is not reachable)\n");
    } else if p.needs.is_empty() {
        text.push_str("nothing needs attention\n");
    } else {
        text.push_str(&format!("NEEDS ATTENTION: {}\n", p.needs.join(", ")));
    }
    text.push_str(&format!(
        "lockouts       pin {}, password {}, devices locked {}\n",
        if pin_locked {
            "LOCKED (hx-agent pin reset-lockout)"
        } else {
            "ok"
        },
        if password_locked {
            "LOCKED (hx-agent pin reset-lockout --purpose password)"
        } else {
            "ok"
        },
        g.locked_devices
            .map(|n| n.to_string())
            .unwrap_or_else(|| "unknown".into())
    ));
    let data = json!({
        "cli_version": env!("CARGO_PKG_VERSION"),
        "privd": p.json,
        "gatewayd": g.json,
        "devices": g.devices,
        "needs_attention": p.needs,
        "lockouts": {
            "pin": pin_locked,
            "password": password_locked,
            "devices_locked": g.locked_devices,
        },
    });
    let exit = if p.reachable && g.reachable {
        exit::OK
    } else {
        exit::UNAVAILABLE
    };
    Ok(Outcome { text, data, exit })
}
