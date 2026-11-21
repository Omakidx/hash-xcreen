//! `ResetLockout`, `EnrolOwnerKey` (Admin only) and `RecordEvent` (ipc.md 6.13, 6.15).

use hx_ipc::privd::pb::{self, AuditEvent, Role, response};
use hx_provision::incus::Transport;

use crate::privd::audit;
use crate::privd::daemon::{Ctx, Daemon, Reply};
use crate::privd::error::CmdError;
use crate::privd::limiter::Purpose;
use crate::privd::state::{Flag, write_atomic};

/// `ResetLockout` (Admin): clears the failure counters and the lock of a purpose and the
/// `PIN_LOCKED` / `PASSWORD_LOCKED` flag, and records the event.
pub fn reset_lockout<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &Ctx,
    r: pb::ResetLockoutRequest,
) -> Result<Reply, CmdError> {
    if ctx.role != Role::Admin {
        return Err(CmdError::denied("reset_lockout: Admin only"));
    }
    let purpose =
        Purpose::from_pb(r.purpose).ok_or_else(|| CmdError::invalid("reset_lockout.purpose"))?;
    d.limiter
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .reset(purpose);
    let flag = match purpose {
        Purpose::Pin => Flag::PinLocked,
        Purpose::Password => Flag::PasswordLocked,
    };
    d.set_flag(None, flag, false);
    d.audit_notice(&format!(
        "lockout of the {} purpose reset by Admin",
        purpose.label()
    ));
    Ok(response::Result::ResetLockout(pb::ResetLockoutResult {}))
}

/// `EnrolOwnerKey` (Admin): records the owner public key (Phase 2 shape, accepted but unused
/// now) in `owner-key` (0644). Replacing an enrolled key needs `replace`.
pub fn enrol_owner_key<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    r: pb::EnrolOwnerKeyRequest,
) -> Result<Reply, CmdError> {
    if r.public_key.len() != 32 {
        return Err(CmdError::invalid("enrol_owner_key.public_key"));
    }
    let path = d.store.path("owner-key");
    if path.exists() && !r.replace {
        return Err(CmdError::precondition(
            pb::ErrorDetail::Unspecified,
            "an owner key is already enrolled; pass replace to change it",
        ));
    }
    write_atomic(&path, &r.public_key, 0o644)?;
    d.audit_notice("owner key enrolled");
    Ok(response::Result::EnrolOwnerKey(pb::EnrolOwnerKeyResult {}))
}

/// `RecordEvent` (class A): writes a registry event to the audit log, which gatewayd cannot edit.
/// Best effort and rate limited (60 per hour, by the dispatcher); it grants nothing.
pub fn record_event<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &Ctx,
    r: pb::RecordEventRequest,
) -> Result<Reply, CmdError> {
    let event = AuditEvent::try_from(r.event)
        .ok()
        .filter(|e| *e != AuditEvent::Unspecified)
        .ok_or_else(|| CmdError::invalid("record_event.event"))?;
    d.audit.append(&audit::event_line(
        d.now(),
        ctx.role,
        ctx.peer.uid,
        event,
        r.device_id.as_deref(),
        &r.label,
    ));
    Ok(response::Result::RecordEvent(pb::RecordEventResult {}))
}
