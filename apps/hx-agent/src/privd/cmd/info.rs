//! `GetHostInfo` and `GetRecipientKey` (ipc.md 6.2).

use std::collections::BTreeSet;

use hx_ipc::privd::pb::{self, response};
use hx_provision::incus::Transport;

use crate::privd::daemon::{Daemon, Reply};
use crate::privd::error::CmdError;
use crate::privd::runner::{Program, Tool};
use std::time::Duration;

const GIB: u64 = 1 << 30;

/// How long the `iptables` and `nft` probes of `GetHostInfo` are reused.
const PROBE_TTL_MS: u64 = 5_000;

/// `(docker_on_host, host_firewall_loaded)`, forking `iptables` and `nft` at most once every 5 s.
async fn host_probe<T: Transport + Clone + 'static>(d: &Daemon<T>) -> (bool, bool) {
    let now = d.clock.unix_ms();
    if let Some((at, a, b)) = *d.host_probe.lock().unwrap_or_else(|e| e.into_inner())
        && now.saturating_sub(at) < PROBE_TTL_MS
    {
        return (a, b);
    }
    let probe_ok = |p: Program| async move { d.runner.run(p).await.is_ok_and(|o| o.success()) };
    let docker = probe_ok(
        Program::new(Tool::Iptables, &["-n", "-L", "DOCKER-USER"])
            .with_timeout(Duration::from_secs(5)),
    )
    .await;
    let firewall = probe_ok(
        Program::new(Tool::Nft, &["list", "table", "inet", "hx"])
            .with_timeout(Duration::from_secs(5)),
    )
    .await;
    *d.host_probe.lock().unwrap_or_else(|e| e.into_inner()) = Some((now, docker, firewall));
    (docker, firewall)
}

/// `GetHostInfo` (class R, both roles). Incus being down leaves `incus_version` unset and still
/// returns every other field.
pub async fn get_host_info<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
) -> Result<Reply, CmdError> {
    let (os_id, os_version) = d.probe.os_release();
    let (mem_total, mem_avail) = d.probe.memory_mib();
    let incus_version = d
        .incus
        .server_info()
        .await
        .ok()
        .map(|i| hx_ipc::text::sanitize_text(&i.server_version, 64));
    let pool = match d.incus.get_storage_pool(&d.cfg.naming.pool).await {
        Ok(Some(p)) => {
            let (total, free) = d.probe.pool_space(&d.cfg.naming.pool).unwrap_or((0, 0));
            pb::PoolInfo {
                exists: true,
                driver: hx_ipc::text::sanitize_text(&p.driver, 32),
                total_gib: total / GIB,
                free_gib: free / GIB,
            }
        }
        _ => pb::PoolInfo::default(),
    };
    let (docker_on_host, host_firewall_loaded) = host_probe(d).await;
    let (needs_attention, desktop_exists) = d.read_state(|s| {
        let mut all: BTreeSet<_> = s.flags.clone();
        for r in s.desktops.values() {
            all.extend(r.flags.iter().copied());
        }
        (
            all.into_iter()
                .map(|f| f.to_pb() as i32)
                .collect::<Vec<_>>(),
            !s.desktops.is_empty(),
        )
    });
    Ok(response::Result::GetHostInfo(pb::GetHostInfoResult {
        privd_version: env!("CARGO_PKG_VERSION").to_string(),
        phase: d.phase().to_pb() as i32,
        os_id,
        os_version,
        arch: std::env::consts::ARCH.to_string(),
        cpu_count: d.probe.cpu_count(),
        memory_total_mib: mem_total,
        memory_available_mib: mem_avail,
        pool: Some(pool),
        incus_version,
        docker_on_host,
        host_firewall_loaded,
        sysctl_ok: d.probe.sysctl_ok(),
        needs_attention,
        desktop_exists,
    }))
}

/// `GetRecipientKey`: the X25519 key that sealed secrets are encrypted to. Sealed secrets are
/// Phase 2 (HPKE), so there is no recipient key yet.
pub async fn get_recipient_key<T: Transport + Clone + 'static>(
    _d: &Daemon<T>,
) -> Result<Reply, CmdError> {
    Err(CmdError::unimplemented(
        "sealed secrets (and so the recipient key) arrive in Phase 2",
    ))
}
