//! `SetLimits` (ipc.md 6.8): every bound is enforced here before Incus is called.

use hx_ipc::privd::pb::{self, ErrorDetail, response};
use hx_provision::incus::{LimitsUpdate, Transport};

use super::common::{host_bounds, parse_gib, validate_limits};
use crate::privd::daemon::{Ctx, Daemon, Reply};
use crate::privd::error::CmdError;

/// `SetLimits` (class A): `cpu` within the host's CPUs, `memory_mib` at least 1 024 and leaving
/// the host `max(1 536 MiB, 25% of RAM)`, `disk_gib` not below the current size and at most the
/// pool's free space; no field zero. Writes `limits.cpu`, `limits.memory` and the root disk size
/// with one call and never touches `limits.processes` or any other key.
///
/// The "never below current usage" bound of the contract uses the **configured** size as its
/// floor: `hx-provision` does not report disk usage yet (see the README follow-ups), so a disk can
/// grow but not shrink. That is stricter than the contract, never looser.
pub async fn set_limits<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &mut Ctx,
    r: pb::SetLimitsRequest,
) -> Result<Reply, CmdError> {
    let l = r
        .limits
        .ok_or_else(|| CmdError::invalid("set_limits.limits"))?;
    let id = r.desktop_id;
    let _g = d.lock_desktop(ctx, &id, false).await?;
    let desktop = d.load_desktop(&id).await?;
    if desktop.meta.state != "ready" {
        return Err(CmdError::precondition(
            ErrorDetail::DesktopNotReady,
            "the desktop is not ready",
        ));
    }
    let current_disk = desktop
        .instance
        .devices
        .get("root")
        .or_else(|| desktop.instance.expanded_devices.get("root"))
        .and_then(|r| r.get("size"))
        .and_then(|s| parse_gib(s))
        .unwrap_or(0);
    let bounds = host_bounds(d)?;
    let cpu = l.cpu;
    validate_limits(cpu, l.memory_mib, l.disk_gib, &bounds, current_disk)?;
    let update = LimitsUpdate {
        cpu: Some(cpu),
        memory_mib: Some(l.memory_mib),
        disk_gib: Some(l.disk_gib),
    };
    let client = d.incus.scoped();
    let applied = d
        .run_cancellable(ctx, &client, Some(&id), async {
            client.set_limits(&desktop.name, &update).await
        })
        .await?;
    Ok(response::Result::SetLimits(pb::SetLimitsResult {
        restart_required: applied.restart_required,
    }))
}
