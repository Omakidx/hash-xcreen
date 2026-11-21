//! `PepperVerify` and `PepperEnrol` (ipc.md 5.3, 6.15).
//!
//! **No command returns a MAC to a caller that could use it as a guessing oracle**:
//! `PepperVerify` answers yes or no only, and counts failures globally per purpose (PIN 10 per
//! hour and 50 per day, PASSWORD 5 and 20, then locked until Admin's `ResetLockout`);
//! `PepperEnrol` returns the MAC only so that a verifier can be set, limited for Gateway to 5 per
//! day after setup (60 per hour during `SETUP_OPEN`) and never for Admin.
//!
//! Both are shielded against cancellation: they are synchronous sections that run to completion,
//! and a cancel is answered only afterwards.

use hx_ipc::privd::pb::{self, Role, response};
use hx_provision::incus::Transport;

use crate::privd::daemon::{Ctx, Daemon, Reply};
use crate::privd::error::CmdError;
use crate::privd::limiter::{Purpose, Refused};
use crate::privd::pepper;
use crate::privd::state::PhaseKind;

fn unsaved() -> CmdError {
    CmdError::unavailable("the failure budget cannot be saved; try again later")
}

fn purpose_of(p: i32, what: &'static str) -> Result<Purpose, CmdError> {
    Purpose::from_pb(p).ok_or_else(|| CmdError::invalid(what))
}

/// `PepperVerify` (class A, both roles). A locked purpose answers `RESOURCE_EXHAUSTED` (`LOCKED`)
/// to every call; a success never consumes the budget.
pub async fn verify<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &mut Ctx,
    r: pb::PepperVerifyRequest,
) -> Result<Reply, CmdError> {
    let purpose = purpose_of(r.purpose, "pepper_verify.purpose")?;
    let secret = ctx
        .take_secret(0)
        .ok_or_else(|| CmdError::invalid("pepper_verify: slot 0 (MAC_INPUT) missing"))?;
    if secret.len() != pepper::LEN {
        return Err(CmdError::invalid("pepper_verify: slot 0 must be 32 bytes"));
    }
    // Check the lock, compare and count the failure under one lock, so that concurrent callers
    // cannot overshoot the cap.
    let (ok, newly_locked, saved) = {
        let mut lim = d.limiter.lock().unwrap_or_else(|e| e.into_inner());
        if lim.is_locked(purpose) {
            return Err(CmdError::locked("this verifier purpose is locked"));
        }
        // Fail closed: while a past charge could not be written, nothing is verified.
        lim.ensure_saved().map_err(|_| unsaved())?;
        let ok = d
            .pepper
            .verify(purpose, secret.expose(), &r.expected_verifier);
        if ok {
            (ok, false, true)
        } else {
            match lim.record_failure(purpose) {
                Ok(newly) => (ok, newly, true),
                // The charge is kept in memory; the answer is withheld.
                Err(_) => (ok, lim.is_locked(purpose), false),
            }
        }
    };
    drop(secret);
    if newly_locked {
        d.after_lock(purpose);
    }
    if !saved {
        return Err(unsaved());
    }
    d.audit_notice(&format!(
        "pepper_verify purpose={} ok={ok}",
        purpose.label()
    ));
    if let Some(reason) = ctx.cancel.reason() {
        return Err(reason.error());
    }
    Ok(response::Result::PepperVerify(pb::PepperVerifyResult {
        ok,
    }))
}

/// `PepperEnrol` (class A, both roles): returns the MAC (the only command that ever does).
pub async fn enrol<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &mut Ctx,
    r: pb::PepperEnrolRequest,
) -> Result<Reply, CmdError> {
    let purpose = purpose_of(r.purpose, "pepper_enrol.purpose")?;
    let secret = ctx
        .take_secret(0)
        .ok_or_else(|| CmdError::invalid("pepper_enrol: slot 0 (MAC_INPUT) missing"))?;
    if secret.len() != pepper::LEN {
        return Err(CmdError::invalid("pepper_enrol: slot 0 must be 32 bytes"));
    }
    if ctx.role == Role::Gateway {
        let during_setup = d.phase() == PhaseKind::SetupOpen;
        d.limiter
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .admit_enrol(during_setup)
            .map_err(|r| match r {
                Refused::Wait(ms) => CmdError::exhausted("PepperEnrol allowance used up", ms),
                Refused::Unsaved => unsaved(),
            })?;
    }
    let mac = d.pepper.mac(purpose, secret.expose());
    drop(secret);
    d.audit_notice(&format!("pepper_enrol purpose={}", purpose.label()));
    if let Some(reason) = ctx.cancel.reason() {
        return Err(reason.error());
    }
    Ok(response::Result::PepperEnrol(pb::PepperEnrolResult {
        mac: bytes::Bytes::copy_from_slice(&mac),
        version: u32::from(pepper::VERSION),
    }))
}
