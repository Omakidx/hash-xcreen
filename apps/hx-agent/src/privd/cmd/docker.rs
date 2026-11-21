//! `EnableDocker`, `DisableDocker` and the fail-closed rollback (ipc.md 6.9).
//!
//! Enabling Docker lowers container isolation (nesting and two syscall intercepts). The rules:
//! the acknowledgement must be true; the add-on is resolved from the recipe privd recorded, never
//! from the request; `allow_old_incus` is never set; the outcome of the self-test is a normal
//! response; and if the isolation could not be restored privd retries the rollback up to three
//! times, then stops the desktop and sets `ISOLATION_NOT_RESTORED`, which blocks Gateway's start
//! until the rollback succeeds.

use hx_ipc::privd::pb::{self, ErrorDetail, ProgressStage, response};
use hx_ipc::text::sanitize_text;
use hx_provision::docker::{
    DockerFallback, DockerMode, DockerOptions, DockerOutcome, SelfTestHint, disable_docker,
    enable_docker,
};
use hx_provision::incus::{Client, StateAction, Transport};
use hx_provision::{Addon, Username};
use std::time::Duration;

use super::common::recipe_from_text;
use crate::privd::daemon::{Ctx, Daemon, Reply};
use crate::privd::error::CmdError;
use crate::privd::state::Flag;

fn pb_fallbacks(f: &[DockerFallback]) -> Vec<i32> {
    f.iter()
        .filter_map(|f| match f {
            DockerFallback::UpgradeIncusFromZabbly => Some(pb::DockerFallback::ZabblyIncus as i32),
            DockerFallback::HostNetworkOnly => Some(pb::DockerFallback::HostNetworkOnly as i32),
            DockerFallback::IncusVm => None,
        })
        .collect()
}

fn hint_text(h: SelfTestHint) -> &'static str {
    match h {
        SelfTestHint::RuncSysctlDenied => "runc could not set a sysctl (Incus older than 6.0.5)",
        SelfTestHint::DaemonNotRunning => "the Docker daemon is not running",
        SelfTestHint::RegistryUnreachable => "Docker Hub could not be reached",
        SelfTestHint::Unknown => "the self-test failed",
    }
}

/// Switches nesting and the intercepts back off, up to three tries. When every try fails the
/// desktop is stopped and `ISOLATION_NOT_RESTORED` is set (fail closed). Returns whether the
/// isolation is restored. Used after a failed self-test, after a cancelled enable, and by Admin's
/// start.
pub async fn restore_isolation<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    client: &Client<T>,
    id: &str,
    name: &str,
) -> bool {
    for attempt in 1..=3 {
        match disable_docker(client, name).await {
            Ok(_) => {
                d.set_flag(Some(id), Flag::IsolationNotRestored, false);
                d.set_autostart(client, name, true).await;
                return true;
            }
            Err(e) => crate::privd::log::error(&format!(
                "isolation rollback attempt {attempt} failed: {e}"
            )),
        }
    }
    // Fail closed: do not leave a desktop running with nesting on.
    let _ = client
        .set_state(name, StateAction::Stop, true, Duration::from_secs(30))
        .await;
    d.set_flag(Some(id), Flag::IsolationNotRestored, true);
    d.audit_notice("needs_attention=ISOLATION_NOT_RESTORED");
    false
}

/// The Docker flow shared by `EnableDocker` and `CreateDesktop`: resolve the add-on, enable,
/// map the outcome, and fail closed. The caller holds the desktop lock.
pub async fn enable_flow<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &Ctx,
    id: &str,
    name: &str,
    recipe_text: &str,
    username: &str,
) -> Result<pb::DockerOutcome, CmdError> {
    let recipe = recipe_from_text(recipe_text)
        .ok_or_else(|| CmdError::internal("the desktop has no valid recipe recorded"))?;
    let user = Username::new(username)
        .map_err(|_| CmdError::internal("the desktop has no valid username recorded"))?;
    let plan = d
        .catalog
        .resolve_addon_for(recipe, Addon::Docker, Some(&user))
        .map_err(|e| CmdError::internal(sanitize_text(&e.to_string(), 200)))?;
    let client = d.incus.scoped();
    let progress = ctx.progress.clone();
    let mut cb = move |p: &hx_provision::Progress| {
        progress.from_provision_as(p, Some(ProgressStage::Docker));
    };
    let opts = DockerOptions {
        mode: DockerMode::Standard,
        ..DockerOptions::default()
    };
    let outcome = match d
        .run_cancellable(ctx, &client, Some(id), async {
            enable_docker(&client, name, &plan, opts, &mut cb).await
        })
        .await
    {
        Ok(o) => o,
        Err(e) => {
            // Cancelled, timed out or failed half way: the add-on may have switched nesting on.
            // `enable_docker` rolls back on its own errors; after a cancel nobody did.
            if matches!(
                e.code,
                pb::ErrorCode::Cancelled | pb::ErrorCode::DeadlineExceeded
            ) {
                restore_isolation(d, &d.incus.scoped(), id, name).await;
            }
            return Err(e.at_stage(ProgressStage::Docker));
        }
    };
    Ok(match outcome {
        DockerOutcome::Enabled { docker_version } => pb::DockerOutcome {
            outcome: Some(pb::docker_outcome::Outcome::Enabled(pb::DockerEnabled {
                docker_version: sanitize_text(&docker_version, 200),
            })),
        },
        DockerOutcome::UnsupportedIncus {
            found,
            required,
            fallbacks,
        } => pb::DockerOutcome {
            outcome: Some(pb::docker_outcome::Outcome::UnsupportedIncus(
                pb::DockerUnsupportedIncus {
                    found: found.to_string(),
                    required: required.to_string(),
                    fallbacks: pb_fallbacks(&fallbacks),
                },
            )),
        },
        DockerOutcome::SelfTestFailed {
            isolation_restored,
            hint,
            output_tail,
            fallbacks,
        } => {
            // The README's rule: when isolation_restored is false, retry the rollback.
            let restored =
                isolation_restored || restore_isolation(d, &d.incus.scoped(), id, name).await;
            pb::DockerOutcome {
                outcome: Some(pb::docker_outcome::Outcome::SelfTestFailed(
                    pb::DockerSelfTestFailed {
                        isolation_restored: restored,
                        hint: hint_text(hint).to_string(),
                        output_tail: sanitize_text(&output_tail, 2048),
                        fallbacks: pb_fallbacks(&fallbacks),
                    },
                )),
            }
        }
    })
}

/// `EnableDocker` (class S: Gateway only while the setup window is open, else Admin).
pub async fn enable<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &mut Ctx,
    r: pb::EnableDockerRequest,
) -> Result<Reply, CmdError> {
    if !r.acknowledged_isolation_warning {
        return Err(CmdError::invalid(
            "enable_docker.acknowledged_isolation_warning",
        ));
    }
    if pb::DockerMode::try_from(r.mode) == Ok(pb::DockerMode::HostNetworkOnly) {
        return Err(CmdError::unimplemented(
            "the host-network-only Docker mode is not implemented",
        ));
    }
    let id = r.desktop_id;
    let _g = d.lock_desktop(ctx, &id, false).await?;
    let l = d.load_desktop(&id).await?;
    if l.meta.state != "ready" {
        return Err(CmdError::precondition(
            ErrorDetail::DesktopNotReady,
            "the desktop is not ready",
        ));
    }
    let client = d.incus.scoped();
    if !client.instance_state(&l.name).await?.is_running() {
        return Err(CmdError::precondition(
            ErrorDetail::DesktopNotReady,
            "the desktop is not running",
        ));
    }
    // Record the acknowledgement before anything changes.
    client
        .patch_instance_config(
            &l.name,
            &[("user.hx.docker_ack".to_string(), d.now().to_string())]
                .into_iter()
                .collect(),
        )
        .await?;
    let outcome = enable_flow(d, ctx, &id, &l.name, &l.meta.recipe, &l.meta.username).await?;
    Ok(response::Result::EnableDocker(pb::EnableDockerResult {
        outcome: Some(outcome),
    }))
}

/// `DisableDocker` (class A, always open to Gateway: it only reduces exposure).
pub async fn disable<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &mut Ctx,
    r: pb::DisableDockerRequest,
) -> Result<Reply, CmdError> {
    let id = r.desktop_id;
    let _g = d.lock_desktop(ctx, &id, false).await?;
    let l = d.load_desktop(&id).await?;
    let client = d.incus.scoped();
    let out = d
        .run_cancellable(ctx, &client, Some(&id), async {
            disable_docker(&client, &l.name).await
        })
        .await?;
    d.set_flag(Some(&id), Flag::IsolationNotRestored, false);
    d.set_autostart(&client, &l.name, true).await;
    Ok(response::Result::DisableDocker(pb::DisableDockerResult {
        restarted: out.restarted,
    }))
}
