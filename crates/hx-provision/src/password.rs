//! Checking the current password and setting a new one (ipc.md 6.9).
//!
//! [`change_user_password`] is the standalone entry point for `SetUserPassword`: it is not part of
//! the post stage, but it uses the same secret path as the post stage's `chpasswd` step. A secret
//! exists in the container only in a file with mode 0600 in the 0700 [`WORK_DIR`], redirected into
//! the command's standard input and deleted by the same wrapper; it is never in argv or in the
//! environment. The work directory is swept before and after.
//!
//! # Shielded against cancellation
//!
//! Dropping a future from this crate stops waiting, not working: the container-side command keeps
//! running, and whatever the future would have done afterwards (the sweep) never happens. So the
//! whole sequence runs as **one detached task**: the future these functions return only waits for
//! its result. If the caller drops it (cancel, closed connection, deadline), the task still runs
//! to its end, bounded by its own timeouts, and sweeps. A cancel can therefore never land between
//! writing the secret file and removing it. The caller answers `CANCELLED` after the task is done
//! if it wants to; it cannot interrupt it.
//!
//! The functions need a tokio runtime and a `'static` client (clone it; clones share the
//! transport).
//!
//! # The check
//!
//! The current password is verified by [`PASSWORD_CHECK_HELPER`] (contract in
//! [`crate::session`]), a fixed-argv program that ships with the `hx-session` package. Only its
//! exit status is used. A missing helper (status 127), a timeout, or any status other than 0 and 1
//! makes the check *unavailable* and the password is **not** changed: the check fails closed.

use std::time::Duration;

use crate::exec::{ApplyError, ExecRequest, Executor, Secret, Secrets, StepFailure};
use crate::incus::{Client, Transport};
use crate::lower::lower;
use crate::orchestrate::{IncusExecutor, ProvisionError};
use crate::plan::{Stage, Step};
use crate::session::{PASSWORD_CHECK_HELPER, PWCHECK_MATCH, PWCHECK_MISMATCH};
use crate::user::Username;

/// How long the helper may run.
const CHECK_TIMEOUT: Duration = Duration::from_secs(30);

/// Result of checking the desktop user's current password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurrentPassword {
    /// The helper exited 0.
    Matches,
    /// The helper exited 1: wrong password. Count it against the failure budget.
    Wrong,
    /// The helper could not decide (not installed, no such user, locked account, bad usage, ...).
    /// Not a wrong-password event; the caller should surface it as an internal error.
    Unavailable {
        /// The exit status, for the caller's journal.
        exit_code: i32,
    },
}

/// Result of [`change_user_password`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordChange {
    /// The password was set.
    Changed,
    /// The current password did not match; nothing was changed.
    CurrentPasswordWrong,
    /// The current password could not be checked; nothing was changed.
    CheckUnavailable {
        /// The helper's exit status.
        exit_code: i32,
    },
}

/// Check `secrets`' current password (see [`Secrets::with_current_password`]) against the
/// desktop user's. Shielded: see the module docs.
pub async fn check_user_password<T>(
    client: &Client<T>,
    instance: &str,
    user: &Username,
    secrets: Secrets,
) -> Result<CurrentPassword, ProvisionError>
where
    T: Transport + Clone + 'static,
{
    let (client, instance, user) = (client.clone(), instance.to_string(), user.clone());
    shield(async move {
        run_swept(&client, &instance, async |exec| {
            check(exec, &user, &secrets).await
        })
        .await
    })
    .await
}

/// Set the desktop user's password to `secrets`' user password
/// ([`Secrets::with_user_password`]), after checking the current password when `require_current`
/// is set (then [`Secrets::with_current_password`] is required too: a missing one is an error, not
/// a skipped check). Outside the setup window `hx-privd` always passes `true` (ipc.md 6.9).
///
/// Refuses with [`ProvisionError::NotRunning`] when the desktop is not running. Shielded: see the
/// module docs. Setting the password the user already has is a no-op in effect.
pub async fn change_user_password<T>(
    client: &Client<T>,
    instance: &str,
    user: &Username,
    secrets: Secrets,
    require_current: bool,
) -> Result<PasswordChange, ProvisionError>
where
    T: Transport + Clone + 'static,
{
    let (client, instance, user) = (client.clone(), instance.to_string(), user.clone());
    shield(async move {
        run_swept(&client, &instance, async |exec| {
            if require_current {
                match check(exec, &user, &secrets).await? {
                    CurrentPassword::Matches => {}
                    CurrentPassword::Wrong => return Ok(PasswordChange::CurrentPasswordWrong),
                    CurrentPassword::Unavailable { exit_code } => {
                        return Ok(PasswordChange::CheckUnavailable { exit_code });
                    }
                }
            }
            set(exec, &user, &secrets).await?;
            Ok(PasswordChange::Changed)
        })
        .await
    })
    .await
}

/// Run `fut` as a detached task and wait for it; dropping the returned future does not stop it.
async fn shield<R: Send + 'static>(
    fut: impl Future<Output = Result<R, ProvisionError>> + Send + 'static,
) -> Result<R, ProvisionError> {
    tokio::spawn(fut)
        .await
        .map_err(|e| ProvisionError::Task(e.to_string()))?
}

/// Sweep the work directory, run `body`, sweep again whatever `body` returned.
async fn run_swept<T, R>(
    client: &Client<T>,
    instance: &str,
    body: impl AsyncFnOnce(&IncusExecutor<'_, T>) -> Result<R, ProvisionError>,
) -> Result<R, ProvisionError>
where
    T: Transport,
{
    if !client.instance_state(instance).await?.is_running() {
        return Err(ProvisionError::NotRunning);
    }
    let exec = IncusExecutor::new(client, instance);
    let _ = exec.sweep().await;
    let result = body(&exec).await;
    let _ = exec.sweep().await;
    result
}

async fn check<T: Transport>(
    exec: &IncusExecutor<'_, T>,
    user: &Username,
    secrets: &Secrets,
) -> Result<CurrentPassword, ProvisionError> {
    let current = secrets
        .current_password()
        .ok_or_else(|| ApplyError::MissingSecret {
            stage: Stage::Post,
            step: "check-current-password".into(),
        })?;
    let out = exec
        .exec(&ExecRequest {
            label: "check-current-password".into(),
            argv: vec![PASSWORD_CHECK_HELPER.into(), user.as_str().into()],
            env: Vec::new(),
            cwd: None,
            stdin: Some(Secret::from_slice(current.expose())),
            timeout: CHECK_TIMEOUT,
        })
        .await;
    let out = match out {
        Ok(o) => o,
        // Incus refuses to start a command whose binary does not exist (400 "Command not found",
        // seen on a real daemon): that is "no helper installed", which fails closed like exit 127.
        Err(crate::exec::ExecError::Backend(m)) if m.contains("Command not found") => {
            return Ok(CurrentPassword::Unavailable { exit_code: 127 });
        }
        Err(e) => {
            return Err(ApplyError::Step {
                stage: Stage::Post,
                index: 1,
                step: "check-current-password".into(),
                failure: StepFailure::Exec(e),
            }
            .into());
        }
    };
    // Only the exit status is used; the output is dropped unread.
    Ok(match out.exit_code {
        PWCHECK_MATCH => CurrentPassword::Matches,
        PWCHECK_MISMATCH => CurrentPassword::Wrong,
        exit_code => CurrentPassword::Unavailable { exit_code },
    })
}

async fn set<T: Transport>(
    exec: &IncusExecutor<'_, T>,
    user: &Username,
    secrets: &Secrets,
) -> Result<(), ProvisionError> {
    let step = Step::SetPassword {
        user: user.as_str().to_string(),
    };
    let missing = || ApplyError::MissingSecret {
        stage: Stage::Post,
        step: step.describe(),
    };
    for action in lower(&step, secrets).map_err(|_| missing())? {
        let crate::exec::Action::Exec(req) = action else {
            continue;
        };
        let fail = |failure| ApplyError::Step {
            stage: Stage::Post,
            index: 1,
            step: step.describe(),
            failure,
        };
        let out = exec
            .exec(&req)
            .await
            .map_err(|e| fail(StepFailure::Exec(e)))?;
        if out.exit_code != 0 {
            return Err(fail(StepFailure::ExitCode {
                code: out.exit_code,
                tail: crate::exec::sanitize(&out.stderr, 500),
            })
            .into());
        }
    }
    Ok(())
}
