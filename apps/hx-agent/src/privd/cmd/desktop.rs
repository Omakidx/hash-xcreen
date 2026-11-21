//! `GetDesktop`, `ListDesktops` (class R) and `DestroyDesktop` (class X) (ipc.md 6.6, 6.13).

use hx_ipc::privd::pb::{self, Role, response};
use hx_provision::incus::Transport;
use hx_provision::teardown;

use super::common::desktop_view;
use crate::privd::daemon::{Ctx, Daemon, Reply};
use crate::privd::error::CmdError;

/// Most desktops `ListDesktops` returns.
pub const MAX_LIST: usize = 8;

/// `GetDesktop`: from `Client::get_instance`, `instance_state` and the `user.hx.*` keys.
pub async fn get_desktop<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    r: pb::GetDesktopRequest,
) -> Result<Reply, CmdError> {
    let l = d.load_desktop(&r.desktop_id).await?;
    let desktop = desktop_view(d, &r.desktop_id, &l).await?;
    Ok(response::Result::GetDesktop(pb::GetDesktopResult {
        desktop: Some(desktop),
    }))
}

/// `ListDesktops`: at most 8; a registered desktop whose instance is gone is skipped.
pub async fn list_desktops<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
) -> Result<Reply, CmdError> {
    let ids: Vec<String> = d.read_state(|s| s.desktops.keys().take(MAX_LIST).cloned().collect());
    let mut out = Vec::new();
    for id in ids {
        match d.load_desktop(&id).await {
            Ok(l) => out.push(desktop_view(d, &id, &l).await?),
            Err(e) if e.code == pb::ErrorCode::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(response::Result::ListDesktops(pb::ListDesktopsResult {
        desktops: out,
    }))
}

/// `DestroyDesktop` (Admin): stops and deletes the instance (only if it carries the hash-xcreen
/// marker), its `hx-` snapshots and its link device. Idempotent. Clears `STUCK_OPERATION`: a forced
/// stop and delete is what ends an operation that would not.
pub async fn destroy_desktop<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &Ctx,
    r: pb::DestroyDesktopRequest,
) -> Result<Reply, CmdError> {
    if ctx.role != Role::Admin {
        return Err(CmdError::denied("destroy_desktop: Admin only"));
    }
    if !r.confirm_destroy {
        return Err(CmdError::invalid("destroy_desktop.confirm_destroy"));
    }
    let _g = d.lock_desktop(ctx, &r.desktop_id, true).await?;
    let name = d.instance_name(&r.desktop_id);
    let client = d.incus.scoped();
    let report = d
        .run_cancellable(ctx, &client, Some(&r.desktop_id), async {
            teardown::destroy_desktop(&client, &name).await
        })
        .await?;
    d.unregister_desktop(&r.desktop_id)?;
    d.audit_notice(&format!(
        "desktop destroyed (instance removed: {}, snapshots removed: {})",
        report.instance_removed, report.snapshots_removed
    ));
    Ok(response::Result::DestroyDesktop(
        pb::DestroyDesktopResult {},
    ))
}
