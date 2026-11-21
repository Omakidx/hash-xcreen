//! `SetUserPassword` (ipc.md 6.9) and the current-password check.
//!
//! The whole section that handles a password is **shielded** (ipc.md 4 and the `hx-provision`
//! README): `change_user_password` runs as one detached task, so dropping this future could not
//! leave the 0600 stdin file behind, but privd goes further and never drops it. On `Cancel` or a
//! deadline it keeps polling the future until it resolves, holds the `desktop:<id>` lock the whole
//! time, and only then answers `CANCELLED` or `DEADLINE_EXCEEDED`. Every wrong current password is
//! charged to the shared `PASSWORD` failure budget (ipc.md 5.3), and a locked purpose refuses the
//! check.

use hx_ipc::privd::pb::{self, ErrorDetail, Role, response};
use hx_provision::Username;
use hx_provision::exec::Secrets;
use hx_provision::incus::Transport;
use hx_provision::password::{PasswordChange, change_user_password};

use crate::privd::daemon::{Ctx, Daemon, Reply};
use crate::privd::error::CmdError;
use crate::privd::limiter::{Purpose, Refused};
use crate::privd::state::PhaseKind;

/// The secret as `&str`, **borrowed**: no `String` copy that nothing would zeroize.
fn utf8<'a>(secret: &'a hx_ipc::secret::Secret, what: &'static str) -> Result<&'a str, CmdError> {
    std::str::from_utf8(secret.expose()).map_err(|_| CmdError::invalid(what))
}

/// `SetUserPassword` (class A). Slot 0 is the new password; slot 1 the current one, required
/// unless the setup window is open. The username is read from `user.hx.username`; a caller
/// cannot name one.
///
/// Admin may omit the current password: root on the host can run `chpasswd` in the container
/// directly (architecture 8.1), so the check protects only against a compromised gateway. If
/// Admin does supply it, it is checked like the gateway's.
pub async fn set_user_password<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &mut Ctx,
    r: pb::SetUserPasswordRequest,
) -> Result<Reply, CmdError> {
    let id = r.desktop_id;
    let new = ctx
        .take_secret(0)
        .ok_or_else(|| CmdError::invalid("set_user_password: slot 0 (USER_PASSWORD) missing"))?;
    let current = ctx.take_secret(1);
    let in_setup = d.phase() == PhaseKind::SetupOpen;
    let require_current = !in_setup && (ctx.role != Role::Admin || current.is_some());
    if require_current && current.is_none() {
        return Err(CmdError::denied(
            "set_user_password: current password required outside the setup window",
        ));
    }

    let _g = d.lock_desktop(ctx, &id, false).await?;
    let l = d.load_desktop(&id).await?;
    if l.meta.state != "ready" {
        return Err(CmdError::precondition(
            ErrorDetail::DesktopNotReady,
            "the desktop is not ready",
        ));
    }
    let username = Username::new(&l.meta.username)
        .map_err(|_| CmdError::internal("the desktop has no valid username recorded"))?;

    let mut secrets = Secrets::none()
        .with_user_password(utf8(&new, "set_user_password: slot 0")?)
        .map_err(|_| CmdError::invalid("set_user_password: slot 0"))?;
    if let Some(c) = &current {
        // A locked PASSWORD purpose refuses the check; the check also has its own daily cap.
        {
            let mut lim = d.limiter.lock().unwrap_or_else(|e| e.into_inner());
            if lim.is_locked(Purpose::Password) {
                return Err(CmdError::locked("the password purpose is locked"));
            }
            lim.admit_current_check().map_err(|r| match r {
                Refused::Wait(ms) => {
                    CmdError::exhausted("too many current-password checks today", ms)
                }
                Refused::Unsaved => {
                    CmdError::unavailable("the failure budget cannot be saved; try again later")
                }
            })?;
        }
        secrets = secrets
            .with_current_password(utf8(c, "set_user_password: slot 1")?)
            .map_err(|_| CmdError::invalid("set_user_password: slot 1"))?;
    }
    drop((new, current));

    // Shielded: awaited to completion whatever `ctx.cancel` does.
    let outcome =
        change_user_password(&d.incus, &l.name, &username, secrets, require_current).await;
    let result = match outcome {
        Ok(PasswordChange::Changed) => Ok(response::Result::SetUserPassword(
            pb::SetUserPasswordResult {},
        )),
        Ok(PasswordChange::CurrentPasswordWrong) => {
            d.charge_failure(Purpose::Password);
            Err(CmdError::denied("the current password is wrong"))
        }
        Ok(PasswordChange::CheckUnavailable { exit_code }) => {
            crate::privd::log::warn(&format!(
                "the current-password helper could not decide (exit {exit_code})"
            ));
            Err(CmdError::internal(
                "the current password could not be checked",
            ))
        }
        Err(e) => Err(e.into()),
    };
    // Only now may the request end as cancelled; the effect of a completed change stands.
    if let Some(reason) = ctx.cancel.reason() {
        return Err(reason.error());
    }
    result
}
