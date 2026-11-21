//! `StartDesktop`, `StopDesktop`, `RestartDesktop` (ipc.md 6.7).

use std::time::Duration;

use hx_ipc::privd::pb::{self, ErrorDetail, Role, response};
use hx_provision::incus::{StateAction, Transport};
use hx_provision::orchestrate::{ReadyError, ReadyOptions, wait_system_running};

use super::docker::restore_isolation;
use crate::privd::daemon::{Ctx, Daemon, Reply};
use crate::privd::error::CmdError;
use crate::privd::state::Flag;

/// Graceful shutdown time before Incus stops waiting (ipc.md 6.7).
const GRACE: Duration = Duration::from_secs(30);

/// How long to wait for `systemctl is-system-running` after a start (ipc.md 6.7).
const READY_WAIT: Duration = Duration::from_secs(60);

async fn wait_ready<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &Ctx,
    client: &hx_provision::incus::Client<T>,
    id: &str,
    name: &str,
) -> Result<pb::PowerResult, CmdError> {
    let r = d
        .run_cancellable(ctx, client, Some(id), async {
            Ok::<_, CmdError>(
                wait_system_running(
                    client,
                    name,
                    ReadyOptions {
                        timeout: READY_WAIT,
                        allow_degraded: false,
                    },
                )
                .await,
            )
        })
        .await?;
    match r {
        Ok(()) => Ok(pb::PowerResult {
            running: true,
            degraded: false,
        }),
        Err(ReadyError::Degraded { .. }) => Ok(pb::PowerResult {
            running: true,
            degraded: true,
        }),
        Err(ReadyError::Timeout { .. }) => Ok(pb::PowerResult {
            running: false,
            degraded: false,
        }),
        Err(ReadyError::Incus(e)) => Err(e.into()),
    }
}

async fn ensure_ready_desktop<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    id: &str,
) -> Result<crate::privd::daemon::LoadedDesktop, CmdError> {
    let l = d.load_desktop(id).await?;
    if l.meta.state != "ready" {
        return Err(CmdError::precondition(
            ErrorDetail::DesktopNotReady,
            "the desktop is not ready",
        ));
    }
    Ok(l)
}

/// `StartDesktop` (class A). Refused for Gateway while `ISOLATION_NOT_RESTORED` holds; Admin's
/// start retries the rollback first (ipc.md 6.7, 7 rule 11).
pub async fn start<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &mut Ctx,
    r: pb::StartDesktopRequest,
) -> Result<Reply, CmdError> {
    let id = r.desktop_id;
    let _g = d.lock_desktop(ctx, &id, false).await?;
    let l = ensure_ready_desktop(d, &id).await?;
    let client = d.incus.scoped();
    if d.flags_for(&id).contains(&Flag::IsolationNotRestored) {
        if ctx.role != Role::Admin {
            return Err(CmdError::precondition(
                ErrorDetail::IsolationNotRestored,
                "Docker's isolation was not restored; an administrator must start this desktop",
            ));
        }
        if !restore_isolation(d, &client, &id, &l.name).await {
            return Err(CmdError::precondition(
                ErrorDetail::IsolationNotRestored,
                "the isolation rollback failed again",
            ));
        }
    }
    let running = d
        .run_cancellable(ctx, &client, Some(&id), async {
            client.instance_state(&l.name).await
        })
        .await?
        .is_running();
    if !running {
        d.run_cancellable(ctx, &client, Some(&id), async {
            client
                .set_state(&l.name, StateAction::Start, false, GRACE)
                .await
        })
        .await?;
    }
    Ok(response::Result::StartDesktop(
        wait_ready(d, ctx, &client, &id, &l.name).await?,
    ))
}

/// `StopDesktop` (class A). `force` skips the grace period; Admin's forced stop also clears
/// `STUCK_OPERATION`.
pub async fn stop<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &mut Ctx,
    r: pb::StopDesktopRequest,
) -> Result<Reply, CmdError> {
    let id = r.desktop_id;
    let allow_stuck = ctx.role == Role::Admin && r.force;
    let _g = d.lock_desktop(ctx, &id, allow_stuck).await?;
    let l = ensure_ready_desktop(d, &id).await?;
    let client = d.incus.scoped();
    let running = d
        .run_cancellable(ctx, &client, Some(&id), async {
            client.instance_state(&l.name).await
        })
        .await?
        .is_running();
    if running {
        d.run_cancellable(ctx, &client, Some(&id), async {
            client
                .set_state(&l.name, StateAction::Stop, r.force, GRACE)
                .await
        })
        .await?;
    }
    if allow_stuck {
        d.set_flag(Some(&id), Flag::StuckOperation, false);
    }
    Ok(response::Result::StopDesktop(pb::PowerResult {
        running: false,
        degraded: false,
    }))
}

/// `RestartDesktop` (class A). The same isolation gate as a start.
pub async fn restart<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &mut Ctx,
    r: pb::RestartDesktopRequest,
) -> Result<Reply, CmdError> {
    let id = r.desktop_id;
    let _g = d.lock_desktop(ctx, &id, false).await?;
    let l = ensure_ready_desktop(d, &id).await?;
    if d.flags_for(&id).contains(&Flag::IsolationNotRestored) && ctx.role != Role::Admin {
        return Err(CmdError::precondition(
            ErrorDetail::IsolationNotRestored,
            "Docker's isolation was not restored; an administrator must restart this desktop",
        ));
    }
    let client = d.incus.scoped();
    d.run_cancellable(ctx, &client, Some(&id), async {
        client
            .set_state(&l.name, StateAction::Restart, r.force, GRACE)
            .await
    })
    .await?;
    Ok(response::Result::RestartDesktop(
        wait_ready(d, ctx, &client, &id, &l.name).await?,
    ))
}
