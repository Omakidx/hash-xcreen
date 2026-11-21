//! Authorization of a request: role, command class, phase and the confused-deputy rules of
//! ipc.md 7 that depend only on the request and the phase.
//!
//! The order is the contract's: the command's **class**, then `hx_ipc::privd::gateway_denied`
//! (class `X`, Admin-only arguments, `DeleteSnapshot` kinds, the `SetUserPassword` current
//! password), then the **phase gates**. Rules that need privd's state (`ISOLATION_NOT_RESTORED`,
//! the setup caps, locks, rate limits) are applied by the command or by [`rate_rule`] after this.

use hx_ipc::privd::pb::{ErrorDetail, Request, Role, request::Command};
use hx_ipc::privd::{CommandClass, command_info, gateway_denied};

use super::error::CmdError;
use super::state::PhaseKind;

/// Decides whether `role` may call this request's command in `phase`.
///
/// `Admin` is allowed everything here (full argument set, any phase); what Admin still cannot do
/// is bypass per-command caps or lock rules, which are applied later. A `Gateway` request is
/// refused with `PERMISSION_DENIED` when the role may never do it (class `X`, an Admin-only
/// argument, `EnableDocker` after setup), and with `FAILED_PRECONDITION` when it is a matter of
/// phase (setup commands outside `SETUP_OPEN`, routine commands while `UNINITIALIZED`).
pub fn authorize(role: Role, req: &Request, phase: PhaseKind) -> Result<(), CmdError> {
    let Some(cmd) = &req.command else {
        return Err(CmdError::invalid("request: no command set"));
    };
    match role {
        Role::Admin => Ok(()),
        Role::Gateway => authorize_gateway(cmd, req, phase),
        Role::Unspecified => Err(CmdError::denied("no role")),
    }
}

fn authorize_gateway(cmd: &Command, req: &Request, phase: PhaseKind) -> Result<(), CmdError> {
    let info = command_info(cmd);
    // 1 and 2: class X, Admin-only arguments and the other request-only Gateway rules.
    if let Some(reason) = gateway_denied(req, phase.to_pb()) {
        return Err(CmdError::denied(reason));
    }
    // 3: phase gates.
    match info.class {
        CommandClass::X => Err(CmdError::denied("command class X is Admin only")),
        CommandClass::R => Ok(()),
        CommandClass::A => match phase {
            PhaseKind::Uninitialized => Err(CmdError::precondition(
                ErrorDetail::SetupWindowClosed,
                "the host is not set up yet",
            )),
            PhaseKind::SetupOpen | PhaseKind::Ready => Ok(()),
        },
        CommandClass::S => match (cmd, phase) {
            (_, PhaseKind::SetupOpen) => Ok(()),
            // Enabling Docker lowers isolation: after setup it is Admin-only (ipc.md 5.1, 7 rule 5),
            // a permission question rather than a phase one.
            (Command::EnableDocker(_), _) => Err(CmdError::denied(
                "enable_docker: Admin only once the setup window is closed",
            )),
            _ => Err(CmdError::precondition(
                ErrorDetail::SetupWindowClosed,
                "the setup window is closed",
            )),
        },
    }
}

/// A rate limit on one command: `max` calls per `window_ms`, optionally per desktop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateRule {
    /// Window length in milliseconds.
    pub window_ms: u64,
    /// Calls allowed in the window.
    pub max: usize,
    /// Whether the bucket is per desktop id (otherwise global for the role and command).
    pub per_desktop: bool,
}

const MIN: u64 = 60_000;
const HOUR: u64 = 3_600_000;
const DAY: u64 = 86_400_000;

/// The command-specific limit of ipc.md 6 and 8, if the command has one. `PepperEnrol` and the
/// failure caps of `PepperVerify` are not here: they are persisted budgets (`limiter`).
pub fn rate_rule(cmd: &Command) -> Option<RateRule> {
    let r = |window_ms, max, per_desktop| {
        Some(RateRule {
            window_ms,
            max,
            per_desktop,
        })
    };
    match cmd {
        Command::CreateDesktop(_) => r(HOUR, 3, false),
        Command::EnableDocker(_) => r(HOUR, 3, false),
        Command::SetUserPassword(_) => r(HOUR, 10, false),
        Command::CreateSnapshot(_) => r(HOUR, 6, false),
        Command::ApplyUpdate(_) => r(DAY, 2, false),
        Command::StartDesktop(_) | Command::StopDesktop(_) | Command::RestartDesktop(_) => {
            r(MIN, 6, true)
        }
        Command::SetLimits(_) => r(HOUR, 6, false),
        Command::DisableDocker(_) => r(HOUR, 6, false),
        Command::ProvisionSessionLink(_) | Command::InstallSession(_) => r(HOUR, 6, false),
        Command::RestartSession(_) => r(HOUR, 6, true),
        Command::CheckUpdate(_) => r(HOUR, 6, false),
        Command::RecordEvent(_) => r(HOUR, 60, false),
        _ => None,
    }
}

/// The default cap on mutating commands: 30 per minute across all of them, for `Gateway` (Admin is
/// exempt from this cap only, ipc.md 8). Reads, the verifier commands (which have their own
/// budgets) and `RecordEvent` are not counted.
pub const MUTATING_PER_MINUTE: usize = 30;

/// Whether `cmd` counts towards [`MUTATING_PER_MINUTE`].
pub fn counts_as_mutating(cmd: &Command) -> bool {
    let info = command_info(cmd);
    info.class != CommandClass::R
        && !matches!(
            cmd,
            Command::PepperVerify(_) | Command::PepperEnrol(_) | Command::RecordEvent(_)
        )
}

/// The desktop id a command targets, if any.
pub fn desktop_of(cmd: &Command) -> Option<&str> {
    Some(match cmd {
        Command::CreateDesktop(r) => &r.desktop_id,
        Command::GetDesktop(r) => &r.desktop_id,
        Command::StartDesktop(r) => &r.desktop_id,
        Command::StopDesktop(r) => &r.desktop_id,
        Command::RestartDesktop(r) => &r.desktop_id,
        Command::SetLimits(r) => &r.desktop_id,
        Command::SetUserPassword(r) => &r.desktop_id,
        Command::EnableDocker(r) => &r.desktop_id,
        Command::DisableDocker(r) => &r.desktop_id,
        Command::CreateSnapshot(r) => &r.desktop_id,
        Command::ListSnapshots(r) => &r.desktop_id,
        Command::DeleteSnapshot(r) => &r.desktop_id,
        Command::ProvisionSessionLink(r) => &r.desktop_id,
        Command::InstallSession(r) => &r.desktop_id,
        Command::RestartSession(r) => &r.desktop_id,
        Command::DestroyDesktop(r) => &r.desktop_id,
        Command::BeginSecretUpload(r) => &r.desktop_id,
        _ => return None,
    })
}
