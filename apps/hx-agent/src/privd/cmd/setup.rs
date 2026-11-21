//! `BeginSetup`, `ExtendSetup`, `FinishSetup` (ipc.md 5.1 and 6.3): the setup window.
//!
//! The window is opened only by Admin (the installer), lasts 2 hours by default, is extended only
//! by Admin (never beyond 24 hours in total), and is closed by `FinishSetup` or by expiry. The
//! phase and window are persisted, so a restart neither opens nor closes anything.

use hx_ipc::privd::pb::{self, ErrorDetail, Role, response};
use hx_provision::incus::Transport;

use crate::privd::daemon::{Ctx, Daemon, Reply};
use crate::privd::error::CmdError;
use crate::privd::state::PhaseKind;

/// Default window length (2 hours).
pub const DEFAULT_WINDOW_S: u64 = 7_200;
/// Longest total life of one window (24 hours).
pub const MAX_WINDOW_S: u64 = 86_400;

/// `BeginSetup` (Admin): `UNINITIALIZED` or `READY` to `SETUP_OPEN`. Calling it again while open
/// starts a fresh window (converges: the state afterwards is "open for the requested time").
pub fn begin<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &Ctx,
    r: pb::BeginSetupRequest,
) -> Result<Reply, CmdError> {
    if ctx.role != Role::Admin {
        return Err(CmdError::denied("begin_setup: Admin only"));
    }
    let secs = if r.expires_in_s == 0 {
        DEFAULT_WINDOW_S
    } else {
        u64::from(r.expires_in_s)
    };
    let now = d.now();
    let expires = d.mutate_state(|s| {
        let return_to = match s.phase.phase {
            PhaseKind::SetupOpen => s.phase.return_to,
            p => p,
        };
        s.phase.phase = PhaseKind::SetupOpen;
        s.phase.return_to = return_to;
        s.phase.window_started = now;
        s.phase.window_expires = now + secs;
        s.phase.window_expires
    })?;
    d.audit_notice(&format!("setup window opened for {secs}s"));
    Ok(response::Result::BeginSetup(pb::BeginSetupResult {
        expires_at_unix_s: expires,
    }))
}

/// `ExtendSetup` (Admin): adds time to the open window; the total never exceeds 24 hours from the
/// moment it opened (the extension is clamped, and the result says where it ends).
pub fn extend<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    r: pb::ExtendSetupRequest,
) -> Result<Reply, CmdError> {
    let by = u64::from(r.extend_by_s);
    if d.phase() != PhaseKind::SetupOpen {
        return Err(CmdError::precondition(
            ErrorDetail::SetupWindowClosed,
            "the setup window is not open",
        ));
    }
    let expires = d.mutate_state(|s| {
        let cap = s.phase.window_started + MAX_WINDOW_S;
        s.phase.window_expires = (s.phase.window_expires + by).min(cap);
        s.phase.window_expires
    })?;
    d.audit_notice("setup window extended");
    Ok(response::Result::ExtendSetup(pb::ExtendSetupResult {
        expires_at_unix_s: expires,
    }))
}

/// `FinishSetup` (class A: Gateway or Admin): `SETUP_OPEN` to `READY`. Needs at least one desktop
/// in state `ready` unless Admin passes `force`. In `READY` it is a no-op (converge).
pub async fn finish<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &Ctx,
    r: pb::FinishSetupRequest,
) -> Result<Reply, CmdError> {
    match d.phase() {
        PhaseKind::Ready => return Ok(response::Result::FinishSetup(pb::FinishSetupResult {})),
        PhaseKind::Uninitialized => {
            return Err(CmdError::precondition(
                ErrorDetail::SetupWindowClosed,
                "the setup window is not open",
            ));
        }
        PhaseKind::SetupOpen => {}
    }
    // `force` is an Admin-only argument: `gateway_denied` already refused a Gateway request that
    // sets it, but the role is checked again here because this is the rule that matters.
    let forced = ctx.role == Role::Admin && r.force == Some(true);
    if !forced && !d.any_desktop_ready().await? {
        return Err(CmdError::precondition(
            ErrorDetail::DesktopNotReady,
            "no desktop is ready yet",
        ));
    }
    d.mutate_state(|s| {
        s.phase.phase = PhaseKind::Ready;
        s.phase.return_to = PhaseKind::Ready;
        s.phase.window_started = 0;
        s.phase.window_expires = 0;
    })?;
    d.audit_notice("setup window closed by FinishSetup");
    Ok(response::Result::FinishSetup(pb::FinishSetupResult {}))
}

impl<T: Transport + Clone + 'static> Daemon<T> {
    /// Whether a registered desktop's instance is in state `ready`.
    pub async fn any_desktop_ready(&self) -> Result<bool, CmdError> {
        let ids: Vec<String> = self.read_state(|s| s.desktops.keys().cloned().collect());
        for id in ids {
            match self.load_desktop(&id).await {
                Ok(l) if l.meta.state == "ready" => return Ok(true),
                Ok(_) => {}
                Err(e) if e.code == pb::ErrorCode::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(false)
    }
}
