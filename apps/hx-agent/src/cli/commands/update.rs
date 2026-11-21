//! `update check | apply | rollback`: a front end for privd's `CheckUpdate`, `ApplyUpdate` and
//! `RollbackUpdate` (`docs/ipc.md` 6.12). The CLI does no update logic: privd fetches, verifies
//! the signature, applies and rolls back. Where privd answers `UNIMPLEMENTED` (a release without
//! the self-update) the CLI says so and exits 6.

use hx_ipc::privd::pb::{self, request::Command, response::Result as R};
use serde_json::json;

use super::{confirm, enum_name, privd, progress_printer};
use crate::cli::error::CliError;
use crate::cli::privd::unexpected;
use crate::cli::text::peer;
use crate::cli::{Env, Outcome};

/// Makes the `UNIMPLEMENTED` answer of an update command explicit.
fn explain(e: CliError) -> CliError {
    match e {
        CliError::Remote(r) if r.code == pb::ErrorCode::Unimplemented => {
            CliError::Unimplemented(format!(
                "self-update is not available in this release of hx-privd ({}); update by installing the new release package",
                r.message
            ))
        }
        other => other,
    }
}

struct Checked {
    current: String,
    available: Option<String>,
    channel: &'static str,
    verified: bool,
    rolled_back: Option<(String, String)>,
}

fn check_inner(p: &mut crate::cli::privd::PrivdConn) -> Result<Checked, CliError> {
    match p
        .simple(Command::CheckUpdate(pb::CheckUpdateRequest {}))
        .map_err(explain)?
    {
        R::CheckUpdate(r) => Ok(Checked {
            current: peer(&r.current, 32),
            available: r.available.as_deref().map(|v| peer(v, 32)),
            channel: enum_name!(pb::UpdateChannel, r.channel, "UPDATE_CHANNEL_"),
            verified: r.verified,
            rolled_back: r
                .rolled_back
                .as_ref()
                .map(|b| (peer(&b.version, 32), peer(&b.reason, 256))),
        }),
        _ => Err(unexpected("CheckUpdate")),
    }
}

pub(super) fn check(env: &mut Env<'_>) -> Result<Outcome, CliError> {
    let mut p = privd(env)?;
    let c = check_inner(&mut p)?;
    let mut t = format!(
        "installed: {}\nchannel:   {}\n",
        c.current,
        c.channel.to_lowercase()
    );
    match &c.available {
        Some(v) => t.push_str(&format!(
            "available: {v} ({})\n",
            if c.verified {
                "signature verified"
            } else {
                "NOT verified"
            }
        )),
        None => t.push_str("available: nothing newer\n"),
    }
    if let Some((v, why)) = &c.rolled_back {
        t.push_str(&format!("last update to {v} was rolled back: {why}\n"));
    }
    Ok(Outcome::ok(
        t,
        json!({
            "current": c.current,
            "available": c.available,
            "channel": c.channel,
            "verified": c.verified,
            "rolled_back": c.rolled_back.as_ref().map(|(v, r)| json!({"version": v, "reason": r})),
        }),
    ))
}

pub(super) fn apply(
    env: &mut Env<'_>,
    version: Option<String>,
    yes: bool,
) -> Result<Outcome, CliError> {
    let mut p = privd(env)?;
    let version = match version {
        Some(v) => v,
        None => check_inner(&mut p)?
            .available
            .ok_or_else(|| CliError::NotFound("no newer release is available".into()))?,
    };
    // The version came from the operator or from privd's own check; re-validated before it is
    // sent, because privd only applies a release it fetched and verified itself.
    if !hx_ipc::privd::is_valid_update_version(&version) {
        return Err(CliError::failed("the version string is not valid"));
    }
    confirm(
        env,
        &format!(
            "This applies release {version}: privd snapshots the desktop, switches the agent binaries, and restarts hx-gatewayd and itself. Connected clients are dropped for a moment. A failed health check rolls back automatically."
        ),
        "yes",
        yes,
    )?;
    let json_mode = env.json;
    let mut progress = progress_printer(json_mode, env.err);
    let restarting = match p
        .call(
            Command::ApplyUpdate(pb::ApplyUpdateRequest {
                version: version.clone(),
            }),
            &[],
            &mut progress,
        )
        .map_err(explain)?
    {
        R::ApplyUpdate(r) => r.restarting,
        _ => return Err(unexpected("ApplyUpdate")),
    };
    Ok(Outcome::ok(
        format!(
            "update to {version} accepted{}; check the result with: hx-agent status\n",
            if restarting {
                " (privd is restarting)"
            } else {
                ""
            }
        ),
        json!({"version": version, "restarting": restarting}),
    ))
}

pub(super) fn rollback(env: &mut Env<'_>, yes: bool) -> Result<Outcome, CliError> {
    confirm(
        env,
        "This switches back to the previous retained release and restarts hx-gatewayd and hx-privd.",
        "yes",
        yes,
    )?;
    let mut p = privd(env)?;
    match p
        .simple(Command::RollbackUpdate(pb::RollbackUpdateRequest {}))
        .map_err(explain)?
    {
        R::RollbackUpdate(_) => {}
        _ => return Err(unexpected("RollbackUpdate")),
    }
    Ok(Outcome::ok(
        "rolled back to the previous release\n",
        json!({"rolled_back": true}),
    ))
}
