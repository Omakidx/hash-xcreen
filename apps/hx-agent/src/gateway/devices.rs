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

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hx_crypto::{Authenticator, Clock, DeviceId, DeviceRecord, RevokeReason};
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
    clock: Arc<dyn Clock>,
    /// Lockout revocations already recorded (see `sweep_lockouts`).
    recorded_lockouts: Mutex<HashSet<DeviceId>>,
    /// When each device asked to revoke (the rate limit holds per device, across connections).
    revoke_times: Mutex<HashMap<DeviceId, VecDeque<std::time::Instant>>>,
    /// Revocations of *other* devices that a device made recently, for the cooling-off rule.
    recent: Mutex<HashMap<DeviceId, Vec<(DeviceId, std::time::Instant)>>>,
    version: AtomicU64,
}

/// Revoke requests one device may make per [`REVOKE_WINDOW`], over all its connections
/// (protocol 5.9).
pub const REVOKES_PER_WINDOW: usize = 10;
/// The window of [`REVOKES_PER_WINDOW`].
pub const REVOKE_WINDOW: Duration = Duration::from_secs(60);
/// The cooling-off period (protocol 5.9): if a device is revoked less than this long after it
/// revoked other devices, those revocations are undone. A thief with a stolen device and its
/// PIN can revoke the owner's other devices, but the owner's counter-revocation wins.
pub const COOLING_OFF: Duration = Duration::from_secs(60);

/// A validated device-initiated revocation that holds the revocation lock.
pub struct RevokeTicket<'a> {
    svc: &'a DeviceService,
    _guard: tokio::sync::OwnedMutexGuard<()>,
    requester: DeviceId,
    target: DeviceId,
}

impl RevokeTicket<'_> {
    /// Performs the revocation (and records it, and applies the cooling-off rule).
    pub async fn commit(self) -> pb::RevokeStatus {
        use pb::RevokeStatus as S;
        let (svc, requester, target) = (self.svc, self.requester, self.target);
        match svc.auth.revoke(&target, RevokeReason::User).await {
            Ok(true) => {
                if target != requester {
                    svc.recent
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .entry(requester)
                        .or_default()
                        .push((target, svc.clock.now()));
                }
                svc.record_revoked(target, Some(requester)).await;
                S::Ok
            }
            Ok(false) => S::AlreadyRevoked,
            Err(e) => {
                tracing::error!(error = %e, "revocation failed");
                S::Failed
            }
        }
    }
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
    pub fn new(
        auth: Authenticator,
        privd: PrivdClient,
        live: Arc<LiveSessions>,
        clock: Arc<dyn Clock>,
    ) -> Arc<Self> {
        let (tx, _) = broadcast::channel(64);
        // Lockouts that happened before this start were recorded then.
        let already: HashSet<DeviceId> = auth
            .registry()
            .list()
            .unwrap_or_default()
            .into_iter()
            .filter(|r| {
                r.revoked
                    .is_some_and(|v| v.reason == RevokeReason::TooManyPinFailures)
            })
            .map(|r| r.id)
            .collect();
        let svc = Arc::new(Self {
            auth: auth.clone(),
            privd,
            live,
            tx,
            revoke_lock: Arc::new(tokio::sync::Mutex::new(())),
            clock,
            recorded_lockouts: Mutex::new(already),
            revoke_times: Mutex::new(HashMap::new()),
            recent: Mutex::new(HashMap::new()),
            version: AtomicU64::new(1),
        });
        // Every revocation wakes the lockout scan; a lag only means "scan again".
        let weak = std::sync::Arc::downgrade(&svc);
        let mut rx = auth.subscribe_revocations();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {
                        let Some(svc) = weak.upgrade() else { break };
                        svc.sweep_lockouts().await;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        svc
    }

    /// The lock the operator and device revocation paths take (a lockout revocation is made by
    /// the authenticator itself and cannot take it).
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
    async fn record_revoked(&self, id: DeviceId, by: Option<DeviceId>) {
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
        // Cooling-off: a device revoked by someone else soon after it revoked others loses
        // those revocations (a self-revoke is a sign-out, not a counter-measure).
        if by != Some(id) {
            self.undo_revocations_by(id).await;
        }
    }

    /// Undoes the recent revocations that `culprit` made (it was itself just revoked): the
    /// devices come back as active, are audited and announced as reinstated.
    async fn undo_revocations_by(&self, culprit: DeviceId) {
        let now = self.clock.now();
        let victims: Vec<DeviceId> = {
            let mut recent = self.recent.lock().unwrap_or_else(|p| p.into_inner());
            recent
                .remove(&culprit)
                .unwrap_or_default()
                .into_iter()
                .filter(|(_, at)| now.saturating_duration_since(*at) < COOLING_OFF)
                .map(|(t, _)| t)
                .collect()
        };
        for target in victims {
            // Only a revocation that a device made is undone, never an operator's or a lockout.
            let user_revoked = matches!(
                self.auth.registry().get(&target),
                Ok(Some(r)) if r.revoked.is_some_and(|v| v.reason == RevokeReason::User)
            );
            if !user_revoked || target == culprit {
                continue;
            }
            match self.auth.reinstate(&target).await {
                Ok(true) => {
                    tracing::warn!(
                        culprit = %super::util::short_id(&culprit),
                        target = %super::util::short_id(&target),
                        "cooling-off: a revocation made by a since-revoked device was undone"
                    );
                    if let Ok(Some(rec)) = self.auth.registry().get(&target) {
                        self.announce_reinstated(&rec);
                    }
                }
                Ok(false) => {}
                Err(e) => tracing::error!(error = %e, "undoing a revocation failed"),
            }
        }
    }

    /// Counts one revoke request of `requester` against the per-device limit. False if over.
    fn allow_revoke_request(&self, requester: DeviceId) -> bool {
        let now = self.clock.now();
        let mut m = self.revoke_times.lock().unwrap_or_else(|p| p.into_inner());
        let q = m.entry(requester).or_default();
        while q
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= REVOKE_WINDOW)
        {
            q.pop_front();
        }
        if q.len() >= REVOKES_PER_WINDOW {
            return false;
        }
        q.push_back(now);
        true
    }

    /// Records the revocations the authenticator makes by itself (the PIN lockout, the 5th
    /// wrong PIN): audit, session closing, notice. They are found by scanning the registry for
    /// devices revoked with reason `TooManyPinFailures` that were not recorded yet, so a
    /// lagging broadcast cannot lose one (the broadcast only wakes the scan).
    async fn sweep_lockouts(&self) {
        let Ok(records) = self.records() else {
            return;
        };
        for r in records {
            let locked_out = r
                .revoked
                .is_some_and(|v| v.reason == RevokeReason::TooManyPinFailures);
            if !locked_out {
                continue;
            }
            let fresh = self
                .recorded_lockouts
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(r.id);
            if fresh {
                self.record_revoked(r.id, None).await;
            }
        }
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
        match self.begin_revoke(requester, target).await {
            Ok(ticket) => ticket.commit().await,
            Err(status) => status,
        }
    }

    /// The checks of a device-initiated revocation, with the revocation lock held. `Err` is the
    /// answer to give; `Ok` is a [`RevokeTicket`] to [`commit`](RevokeTicket::commit). The two
    /// steps exist so that a session can tell the asker "OK" **before** the commit when it asks
    /// to revoke its own device: the authenticator closes a revoked device's connections at
    /// once, which would otherwise swallow the answer.
    pub async fn begin_revoke(
        &self,
        requester: DeviceId,
        target: DeviceId,
    ) -> Result<RevokeTicket<'_>, pb::RevokeStatus> {
        use pb::RevokeStatus as S;
        if !self.allow_revoke_request(requester) {
            return Err(S::RateLimited);
        }
        let guard = self.revoke_lock.clone().lock_owned().await;
        let records = match self.records() {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "registry read failed during a revoke");
                return Err(S::Failed);
            }
        };
        // The requester must still be a paired, non-revoked device *now*: a request queued
        // behind its own revocation (an operator or a lockout got there first) must not run.
        if !records.iter().any(|r| r.id == requester && !r.is_revoked()) {
            return Err(S::Failed);
        }
        let Some(rec) = records.iter().find(|r| r.id == target) else {
            return Err(S::NotFound);
        };
        if rec.is_revoked() {
            return Err(S::AlreadyRevoked);
        }
        // Whoever the target is, a device-initiated revocation never leaves the server
        // without an active device.
        let active = records.iter().filter(|r| !r.is_revoked()).count();
        if active <= 1 {
            return Err(S::LastActiveDevice);
        }
        Ok(RevokeTicket {
            svc: self,
            _guard: guard,
            requester,
            target,
        })
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
            self.record_revoked(target, None).await;
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
