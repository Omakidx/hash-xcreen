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

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
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
    revoke_lock: tokio::sync::Mutex<()>,
    /// Which paired device asked for a pending revocation (consumed by the announcer).
    actors: Mutex<HashMap<DeviceId, DeviceId>>,
    version: AtomicU64,
}

/// Maps a registry record to its wire form. The name is sanitized again here: it was cleaned
/// at pairing, but a registry file is data, not trust.
pub fn device_info(rec: &DeviceRecord, current: bool) -> pb::DeviceInfo {
    let (status, reason, at) = match rec.revoked {
        None => (pb::DeviceStatus::Active, pb::DeviceRevokeReason::Unspecified, 0),
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
    /// Creates the service and starts its announcer task.
    pub fn new(auth: Authenticator, privd: PrivdClient, live: Arc<LiveSessions>) -> Arc<Self> {
        let (tx, _) = broadcast::channel(64);
        let svc = Arc::new(Self {
            auth: auth.clone(),
            privd,
            live,
            tx,
            revoke_lock: tokio::sync::Mutex::new(()),
            actors: Mutex::new(HashMap::new()),
            version: AtomicU64::new(1),
        });
        let weak = Arc::downgrade(&svc);
        let mut rx = auth.subscribe_revocations();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(id) => {
                        let Some(svc) = Weak::upgrade(&weak) else { break };
                        svc.announce_revoked(id);
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        // A lag means missed notices; clients re-list to resynchronize.
                        tracing::warn!(missed = n, "revocation announcements were missed");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        svc
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

    fn announce_revoked(&self, id: DeviceId) {
        self.bump_version();
        let by = self
            .actors
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&id);
        let Ok(Some(rec)) = self.auth.registry().get(&id) else {
            return; // removed, not revoked: there is no event for that
        };
        if !rec.is_revoked() {
            return;
        }
        self.audit(AuditEvent::DeviceRevoked, id, &rec.name);
        let _ = self.tx.send(Arc::new(DeviceNotice {
            kind: pb::DeviceEventKind::Revoked,
            device: device_info(&rec, false),
            by,
        }));
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
                    .await {
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
    pub fn device_list(&self, requester: Option<DeviceId>) -> Result<pb::DeviceList, hx_crypto::Error> {
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
    pub async fn revoke_by_device(&self, requester: DeviceId, target: DeviceId) -> pb::RevokeStatus {
        use pb::RevokeStatus as S;
        let _serial = self.revoke_lock.lock().await;
        let records = match self.records() {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "registry read failed during a revoke");
                return S::Failed;
            }
        };
        let Some(rec) = records.iter().find(|r| r.id == target) else {
            return S::NotFound;
        };
        if rec.is_revoked() {
            return S::AlreadyRevoked;
        }
        let active = records.iter().filter(|r| !r.is_revoked()).count();
        if target == requester && active <= 1 {
            return S::LastActiveDevice;
        }
        self.actors
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(target, requester);
        match self.auth.revoke(&target, RevokeReason::User).await {
            Ok(true) => S::Ok,
            Ok(false) => S::AlreadyRevoked,
            Err(e) => {
                tracing::error!(error = %e, "revocation failed");
                self.actors
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&target);
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
        self.auth.revoke(&target, RevokeReason::User).await?;
        Ok(Some(sessions))
    }

    /// The operator lifts a revocation or clears a lock. `Ok(None)` if unknown.
    pub async fn reinstate(&self, target: DeviceId) -> Result<Option<DeviceRecord>, hx_crypto::Error> {
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
