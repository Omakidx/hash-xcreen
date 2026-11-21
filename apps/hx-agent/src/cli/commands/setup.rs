//! `setup begin | extend | finish`.
//!
//! The setup window (`docs/ipc.md` 5.1, 6.3) lives in two places: privd is the authority
//! (`BeginSetup`, `ExtendSetup`, `FinishSetup`) and gatewayd keeps a mirror (`SetupWindow`) so
//! that it refuses setup traffic from clients while the window is closed. The CLI calls privd
//! first, then updates the mirror from privd's answer. If the mirror cannot be updated the command
//! fails with a message that says privd already changed, because gatewayd would then still refuse
//! (or still allow) setup traffic until the same command is run again.

use hx_ipc::admin::pb as apb;
use hx_ipc::privd::pb::{self, request::Command, response::Result as R};
use serde_json::json;

use super::{admin, confirm, privd};
use crate::cli::error::CliError;
use crate::cli::gatewayd::unexpected as admin_unexpected;
use crate::cli::privd::unexpected;
use crate::cli::text::time;
use crate::cli::{Env, Outcome};

fn mirror(
    env: &Env<'_>,
    action: apb::SetupWindowAction,
    expires_in_s: u32,
) -> Result<apb::SetupWindowState, CliError> {
    let mut a = admin(env)?;
    match a.call(
        apb::request::Command::SetupWindow(apb::SetupWindowRequest {
            action: action as i32,
            expires_in_s,
        }),
        None,
    )? {
        apb::response::Result::SetupWindow(r) => Ok(r.state.unwrap_or_default()),
        _ => Err(admin_unexpected("SetupWindow")),
    }
}

fn mirror_failed(what: &str, e: CliError) -> CliError {
    CliError::Failed(format!(
        "hx-privd {what}, but hx-gatewayd could not be told ({}); run the same command again so that gatewayd follows",
        e.message()
    ))
}

/// Seconds from now to `expires`, clamped to the range the admin socket accepts for open/extend.
fn remaining(env: &Env<'_>, expires: u64) -> u32 {
    u32::try_from(expires.saturating_sub((env.now)()).clamp(60, 86_400)).unwrap_or(60)
}

/// What an open setup window lets a compromised gateway do (docs/ipc.md 5.1, 6.3 to 6.9, 7).
const WINDOW_WARNING: &str =
    "While the setup window is open, hx-gatewayd (the internet-facing process) may ask privd to:
  - build the host and create the desktop (SetupHost, CreateDesktop),
  - enable Docker in the desktop, which lowers its isolation (EnableDocker),
  - change the desktop user's password WITHOUT knowing the current one (SetUserPassword),
  - mint verifier MACs at a higher rate (PepperEnrol), and close the window.
A gateway that is compromised during that time can do all of it. Open the window only when you
are about to run the setup, keep it short, and close it with: hx-agent setup finish";

pub(super) fn begin(env: &mut Env<'_>, secs: u32, yes: bool) -> Result<Outcome, CliError> {
    confirm(env, WINDOW_WARNING, "yes", yes)?;
    let mut p = privd(env)?;
    let expires = match p.simple(Command::BeginSetup(pb::BeginSetupRequest {
        expires_in_s: secs,
    }))? {
        R::BeginSetup(r) => r.expires_at_unix_s,
        _ => return Err(unexpected("BeginSetup")),
    };
    let state = mirror(env, apb::SetupWindowAction::Open, secs)
        .map_err(|e| mirror_failed("opened the setup window", e))?;
    Ok(Outcome::ok(
        format!(
            "setup window open until {} (privd and gatewayd)\n",
            time(expires)
        ),
        json!({"open": state.open, "expires_at_unix_s": expires}),
    ))
}

pub(super) fn extend(env: &mut Env<'_>, secs: u32) -> Result<Outcome, CliError> {
    let mut p = privd(env)?;
    let expires = match p.simple(Command::ExtendSetup(pb::ExtendSetupRequest {
        extend_by_s: secs,
    }))? {
        R::ExtendSetup(r) => r.expires_at_unix_s,
        _ => return Err(unexpected("ExtendSetup")),
    };
    // gatewayd extends its own window; if it restarted and lost it, open it to privd's expiry.
    let state = match mirror(env, apb::SetupWindowAction::Extend, secs) {
        Ok(s) => Ok(s),
        Err(CliError::Remote(r)) if r.code == pb::ErrorCode::FailedPrecondition => {
            mirror(env, apb::SetupWindowAction::Open, remaining(env, expires))
        }
        Err(e) => Err(e),
    }
    .map_err(|e| mirror_failed("extended the setup window", e))?;
    Ok(Outcome::ok(
        format!(
            "setup window now open until {} (24 hours in total at most)\n",
            time(expires)
        ),
        json!({"open": state.open, "expires_at_unix_s": expires}),
    ))
}

pub(super) fn finish(env: &mut Env<'_>, force: bool) -> Result<Outcome, CliError> {
    let mut p = privd(env)?;
    match p.simple(Command::FinishSetup(pb::FinishSetupRequest {
        force: force.then_some(true),
    }))? {
        R::FinishSetup(_) => {}
        _ => return Err(unexpected("FinishSetup")),
    }
    mirror(env, apb::SetupWindowAction::Close, 0)
        .map_err(|e| mirror_failed("closed the setup window", e))?;
    Ok(Outcome::ok(
        "setup window closed (privd and gatewayd)\n",
        json!({"open": false}),
    ))
}
