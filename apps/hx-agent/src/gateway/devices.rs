//! Paired devices: listing, revocation, and the change notices (protocol 5.9, `docs/ipc.md`
//! sections 6.15 and 9, decision 1).
//!
//! One service serves both doors: a client's `DeviceMgmt` messages ([`super::session`]) and the
//! root-only admin socket ([`super::admin`]). The rules are therefore written once:
//!
//! * Every revocation goes through `Authenticator::revoke` (persisted, announced, as one unit).
//!   A single announcer task listens to `Authenticator::subscribe_revocations`, so **every**
//!   revocation, whoever caused it (a device, the operator, the PIN lockout), is recorded in
//!   privd's audit log (`RecordEvent DEVICE_REVOKED`, ipc.md 6.15) and pushed to every live
//!   session that negotiated `DEVICE_MANAGEMENT` as a `DeviceEvent`.
//! * Revoking is serialized, so the "never leave the server with no active device" check cannot
//!   be raced by two self-revocations.
//! * Audit events are best effort with a few retries: a compromised gateway can omit or forge
//!   them (ipc.md 6.15); the log is a tripwire, not a guarantee.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use hx_crypto::{Authenticator, DeviceId, DeviceRecord, RevokeReason};
use hx_ipc::privd::pb::AuditEvent;
use hx_proto::channel::MAX_DEVICE_LIST;
use hx_proto::message::sanitize_device_name;
use hx_proto::pb;
use tokio::sync::broadcast;

use super::live::LiveSessions;
use super::privd_client::PrivdClient;

/// A change of the registry, as pushed to clients.
#[derive(Debug, Clone)]
pub struct DeviceNotice {
    /// What happened.
    pub kind: pb::DeviceEventKind,
    /// The device after the change (`current` is never set here).
    pub device: pb::DeviceInfo,
    /// The paired device that caused it, if one did.
    pub by: Option<DeviceId>,
}

/// The device service. Create it once per gateway.
pub struct DeviceService {
    auth: Authenticator,
    privd: PrivdClient,
    live: Arc<LiveSessions>,
    tx: broadcast::Sender<Arc<DeviceNotice>>,
    /// Serializes every revocation, whoever asks (a device, the operator, the PIN lockout):
    /// the "keep one active device" and "requester still active" checks are only sound if
    /// nothing else revokes between the check and the write.
    revoke_lock: Arc<tokio::sync::Mutex<()>>,
    version: AtomicU64,
}

/// Maps a registry record to its wire form. The name is sanitized again here: it was cleaned
/// at pairing, but a registry file is data, not trust.
pub fn device_info(rec: &DeviceRecord, current: bool) -> pb::DeviceInfo {
    let (status, reason, at) = match rec.revoked {
        None => (
            pb::DeviceStatus::Active,
            pb::DeviceRevokeReason::Unspecified,
            0,
        ),
        Some(r) => (
            pb::DeviceStatus::Revoked,
            match r.reason {
                RevokeReason::User => pb::DeviceRevokeReason::User,
                RevokeReason::TooManyPinFailures => pb::DeviceRevokeReason::TooManyPinFailures,
            },
            r.at_unix,
        ),
    };
    pb::DeviceInfo {
        device_id: bytes::Bytes::copy_from_slice(rec.id.as_bytes()),
        name: sanitize_device_name(&rec.name),
        created_unix: rec.created_unix,
        last_seen_unix: rec.last_seen_unix,
        status: status as i32,
        revoke_reason: reason as i32,
        revoked_unix: at,
        current,
    }
}

impl DeviceService {
    /// Creates the service.
    pub fn new(auth: Authenticator, privd: PrivdClient, live: Arc<LiveSessions>) -> Arc<Self> {
        let (tx, _) = broadcast::channel(64);
        Arc::new(Self {
            auth,
            privd,
            live,
            tx,
            revoke_lock: Arc::new(tokio::sync::Mutex::new(())),
            version: AtomicU64::new(1),
        })
    }

    /// The lock every revocation path takes ([`super::login::Login`] takes it for a lockout).
    pub fn revoke_gate(&self) -> Arc<tokio::sync::Mutex<()>> {
        self.revoke_lock.clone()
    }

    /// True if `id` is in the registry and not revoked.
    pub fn is_active(&self, id: &DeviceId) -> bool {
        matches!(self.auth.registry().get(id), Ok(Some(r)) if !r.is_revoked())
    }

    /// Receives the notices pushed to clients.
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<DeviceNotice>> {
        self.tx.subscribe()
    }

    /// A counter that grows with every registry or verifier change (admin `Status`).
    pub fn registry_version(&self) -> u64 {
        self.version.load(Ordering::Relaxed)
    }

    /// Notes a change that is not a device event (a verifier was set).
    pub fn bump_version(&self) {
        self.version.fetch_add(1, Ordering::Relaxed);
    }

    /// Every record, in registry order.
    pub fn records(&self) -> Result<Vec<DeviceRecord>, hx_crypto::Error> {
        self.auth.registry().list()
    }

    /// Records a revocation that was just persisted, **directly** (not through a broadcast
    /// that a slow consumer could lag behind): audit event, closing of the device's live
    /// sessions, and the notice to the clients. `by` is the paired device that asked, or
    /// `None` for the operator and the PIN lockout; it belongs to this very revocation.
    fn record_revoked(&self, id: DeviceId, by: Option<DeviceId>) {
        self.bump_version();
        let Ok(Some(rec)) = self.auth.registry().get(&id) else {
            return;
        };
        if !rec.is_revoked() {
            return;
        }
        self.audit(AuditEvent::DeviceRevoked, id, &rec.name);
        // Close the device's live sessions from here, not only from their own loops: a loop
        // that is busy (claiming the desktop, waiting on privd) would notice much later. A
        // self-revoke is left a moment so that its answer is delivered first.
        let live = self.live.clone();
        let self_revoke = by == Some(id);
        tokio::spawn(async move {
            if self_revoke {
                tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
            }
            live.close_device(
                &id,
                hx_proto::channel::CloseCode::Unauthorized,
                "device revoked",
            )
            .await;
        });
        let _ = self.tx.send(Arc::new(DeviceNotice {
            kind: pb::DeviceEventKind::Revoked,
            device: device_info(&rec, false),
            by,
        }));
    }

    /// Revokes `id` after too many wrong PINs, serialized with every other revocation. True if
    /// it was revoked now. (The PIN login calls this; the lockout is not subject to the
    /// "keep one active device" rule: a device that fails its PIN five times is locked out
    /// even if it was the last one, and the operator reinstates it.)
    pub async fn revoke_lockout(&self, id: DeviceId) -> Result<bool, hx_crypto::Error> {
        let _serial = self.revoke_lock.lock().await;
        let done = self
            .auth
            .revoke(&id, RevokeReason::TooManyPinFailures)
            .await?;
        if done {
            self.record_revoked(id, None);
        }
        Ok(done)
    }

    /// A device paired: record it and tell the live sessions.
    pub fn announce_added(&self, rec: &DeviceRecord) {
        self.bump_version();
        self.audit(AuditEvent::DeviceAdded, rec.id, &rec.name);
        let _ = self.tx.send(Arc::new(DeviceNotice {
            kind: pb::DeviceEventKind::Added,
            device: device_info(rec, false),
            by: None,
        }));
    }

    /// An operator lifted a revocation: record it and tell the live sessions.
    pub fn announce_reinstated(&self, rec: &DeviceRecord) {
        self.bump_version();
        self.audit(AuditEvent::DeviceReinstated, rec.id, &rec.name);
        let _ = self.tx.send(Arc::new(DeviceNotice {
            kind: pb::DeviceEventKind::Reinstated,
            device: device_info(rec, false),
            by: None,
        }));
    }

    /// Writes an audit event about a device to privd, retrying in the background.
    pub fn audit(&self, event: AuditEvent, id: DeviceId, label: &str) {
        self.audit_opt(event, Some(id), label);
    }

    /// Writes an audit event to privd, retrying a few times in the background. `id` is absent
    /// for events that concern the server as a whole (a verifier for every device, a pairing
    /// window).
    pub fn audit_opt(&self, event: AuditEvent, id: Option<DeviceId>, label: &str) {
        let privd = self.privd.clone();
        let label = label.to_owned();
        tokio::spawn(async move {
            for wait in [0u64, 1, 3] {
                if wait > 0 {
                    tokio::time::sleep(Duration::from_secs(wait)).await;
                }
                match privd
                    .record_event(event, id.map(|d| *d.as_bytes()), &label)
                    .await
                {
                    Ok(()) => return,
                    Err(e) if e.is_retryable() => {}
                    Err(e) => {
                        tracing::warn!(error = %e, ?event, "audit event refused by privd");
                        return;
                    }
                }
            }
            tracing::warn!(?event, "audit event not recorded: privd stayed unavailable");
        });
    }

    /// The `DeviceList` for `requester`: active devices first, then revoked ones, newest first
    /// in each group, at most [`MAX_DEVICE_LIST`] entries.
    pub fn device_list(
        &self,
        requester: Option<DeviceId>,
    ) -> Result<pb::DeviceList, hx_crypto::Error> {
        let mut records = self.records()?;
        records.sort_by_key(|r| {
            (
                r.is_revoked(),
                std::cmp::Reverse(r.revoked.map_or(r.created_unix, |v| v.at_unix)),
            )
        });
        let truncated = records.len() > MAX_DEVICE_LIST;
        let devices = records
            .iter()
            .take(MAX_DEVICE_LIST)
            .map(|r| device_info(r, Some(r.id) == requester))
            .collect();
        Ok(pb::DeviceList { devices, truncated })
    }

    /// A paired device revokes `target` (protocol 5.9, "Revoking").
    pub async fn revoke_by_device(
        &self,
        requester: DeviceId,
        target: DeviceId,
    ) -> pb::RevokeStatus {
        use pb::RevokeStatus as S;
        let _serial = self.revoke_lock.lock().await;
        let records = match self.records() {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "registry read failed during a revoke");
                return S::Failed;
            }
        };
        // The requester must still be a paired, non-revoked device *now*: a request queued
        // behind its own revocation (an operator or a lockout got there first) must not run.
        if !records.iter().any(|r| r.id == requester && !r.is_revoked()) {
            return S::Failed;
        }
        let Some(rec) = records.iter().find(|r| r.id == target) else {
            return S::NotFound;
        };
        if rec.is_revoked() {
            return S::AlreadyRevoked;
        }
        // Whoever the target is, a device-initiated revocation never leaves the server
        // without an active device.
        let active = records.iter().filter(|r| !r.is_revoked()).count();
        if active <= 1 {
            return S::LastActiveDevice;
        }
        match self.auth.revoke(&target, RevokeReason::User).await {
            Ok(true) => {
                self.record_revoked(target, Some(requester));
                S::Ok
            }
            Ok(false) => S::AlreadyRevoked,
            Err(e) => {
                tracing::error!(error = %e, "revocation failed");
                S::Failed
            }
        }
    }

    /// The operator revokes `target`. `Ok(None)` if the device is unknown; otherwise how many
    /// live sessions of it were open (they are closed by the announcement).
    pub async fn revoke_by_operator(
        &self,
        target: DeviceId,
    ) -> Result<Option<usize>, hx_crypto::Error> {
        let _serial = self.revoke_lock.lock().await;
        let Some(rec) = self.auth.registry().get(&target)? else {
            return Ok(None);
        };
        if rec.is_revoked() {
            return Ok(Some(0));
        }
        let sessions = self.live.count_for(&target);
        if self.auth.revoke(&target, RevokeReason::User).await? {
            self.record_revoked(target, None);
        }
        Ok(Some(sessions))
    }

    /// The operator lifts a revocation or clears a lock. `Ok(None)` if unknown.
    pub async fn reinstate(
        &self,
        target: DeviceId,
    ) -> Result<Option<DeviceRecord>, hx_crypto::Error> {
        let Some(rec) = self.auth.registry().get(&target)? else {
            return Ok(None);
        };
        if rec.is_revoked() {
            self.auth.reinstate(&target).await?;
            let rec = self.auth.registry().get(&target)?;
            if let Some(r) = &rec {
                self.announce_reinstated(r);
            }
            return Ok(rec);
        }
        Ok(Some(rec))
    }
}
