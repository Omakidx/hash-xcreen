//! Authorized client sessions: the control loop of one connection, the one-active-client rule
//! and the takeover sequence (`docs/ipc.md` section 18, protocol 5.7 and 5.9).
//!
//! # What a session does
//!
//! After login the connection is authorized and this module owns its control channel:
//!
//! * `ViewConfig` (validated against what was negotiated) is the **request to view the
//!   desktop**. The first one *claims* the desktop (below); later ones go to the link.
//!   Authenticating alone claims nothing, so a connection that only manages devices (the
//!   "Revoke that device" path after a takeover) displaces nobody (protocol 5.9).
//! * `RequestKeyframe` and `ClientStats` go to the link once claimed.
//! * `DeviceMgmt` is served by [`super::devices::DeviceService`] if `DEVICE_MANAGEMENT` was
//!   negotiated, otherwise it is a protocol error; `DeviceEvent`s are pushed to the client.
//! * A message only the server may send (`ServerStats`, `StreamInfo`, ...), a handshake message
//!   after the handshake, and `pairing` or `auth` after authorization are protocol errors.
//! * The session ends when the client says `Goodbye`, the connection closes, the device is
//!   revoked (the revocation announcement, a registry re-check every 5 s as a backstop), or no
//!   `ViewConfig` arrives within `manage_idle`.
//!
//! # Claiming the desktop and the takeover sequence
//!
//! [`SessionManager::claim`] runs with the per-desktop lock held:
//!
//! 0. the desktop is made ready through privd ([`super::desktop::DesktopSupervisor`]); if that
//!    fails the client is told "desktop unavailable" (`Goodbye{BUSY}`);
//! 1. if another client is active: the policy and the rate limit decide (`deny`, or more than 3
//!    takeovers in 10 minutes, answer the newcomer `BUSY`; the same device replacing its own
//!    stale session is exempt from both);
//! 2. **(1)** `release_input()` on the old client (stop forwarding its input, `release_all`),
//!    **(2)** `cancel_in_flight()` (cancel its frames, abort its transfers), then the old
//!    client's link handle is detached (`Displaced`);
//! 3. **(3)** the old client is told: `Goodbye{TAKEN_OVER, message, peer_device_name (sanitized),
//!    peer_device_id}` on its control channel, delivery is awaited (a `Ping` round trip on the
//!    same ordered stream, at most 1 s), then its connection is closed with code 9 (a client that
//!    negotiated minor 0 gets `Goodbye{BUSY}` and close `BUSY` with a fixed text instead);
//!    `RecordEvent TAKEOVER` goes to privd's audit log;
//! 4. **(4)** `DesktopLink::attach` for the newcomer (epoch increment and `start`, in the link).
//!
//! Steps (1), (2) and (4) run in the link, behind [`super::desktop`]'s seam.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hx_crypto::{Authenticator, Clock, DeviceId, DeviceRecord};
use hx_ipc::privd::pb::AuditEvent;
use hx_proto::channel::CloseCode;
use hx_proto::message::{MgmtDirection, sanitize_device_name};
use hx_proto::pb::{self, control_message::Message as Ctl};
use hx_proto::version::Features;
use hx_transport::Connection;
use tokio::sync::{Mutex, broadcast};

use super::desktop::{
    AttachRequest, DesktopLink, DesktopSupervisor, DetachReason, GuardedClient, LinkClient,
    LinkError,
};
use super::devices::{DeviceNotice, DeviceService};
use super::live::LiveSessions;
use super::privd_client::PrivdClient;
use super::takeover::{Refusal, TakeoverLimiter, TakeoverPolicy};
use super::util::{device_id, log_text, short_id};

/// Revoke requests a connection may make per window (protocol 5.9).
pub const REVOKES_PER_WINDOW: usize = 10;
/// The window of [`REVOKES_PER_WINDOW`].
pub const REVOKE_WINDOW: Duration = Duration::from_secs(60);
/// How long delivery of a `Goodbye` is awaited (protocol 5.7).
pub const GOODBYE_FLUSH: Duration = Duration::from_secs(1);
/// How long a device's own old connection has to answer before it counts as dead.
const SELF_REPLACE_PING: Duration = Duration::from_secs(1);
/// Bound on each takeover step that calls into the link.
const LINK_STEP_TIMEOUT: Duration = Duration::from_secs(2);
/// Bound on writing one message to a client's control channel from the session loop.
const SEND_TIMEOUT: Duration = Duration::from_secs(5);
/// Fixed text of the takeover close reason: never carries a name.
const TAKEN_OVER_REASON: &str = "taken over";
const TAKEN_OVER_MESSAGE: &str = "another device took over this desktop";

/// Settings of the session layer.
#[derive(Debug, Clone)]
pub struct SessionSettings {
    /// The desktop served (v1: one).
    pub desktop_id: String,
    /// The takeover policy.
    pub takeover: TakeoverPolicy,
    /// A session that never asks to view is closed after this long.
    pub manage_idle: Duration,
    /// How often a session re-reads the registry as a backstop for unannounced revocations.
    pub watch_interval: Duration,
}

struct Active {
    token: u64,
    conn: Connection,
    device_id: DeviceId,
    device_name: String,
    client: Arc<dyn LinkClient>,
}

enum Claim {
    Claimed(Arc<dyn LinkClient>, u64),
    Busy(&'static str),
    Unavailable,
    /// The device was revoked (or the connection closed) while the claim was running.
    Revoked,
}

/// How long making the desktop ready may take before the client is told "unavailable": the
/// supervisor's lock must not be held for minutes by a slow `StartDesktop`.
const READY_TIMEOUT: Duration = Duration::from_secs(10);

/// What a message handler asks the loop to do next.
enum Flow {
    Continue,
    /// End the session; `Some` closes with that code and reason.
    End(Option<(CloseCode, &'static str)>),
}

/// Owns the one-active-client rule and runs sessions.
pub struct SessionManager {
    settings: SessionSettings,
    link: Arc<dyn DesktopLink>,
    supervisor: DesktopSupervisor,
    limiter: TakeoverLimiter,
    active: Mutex<Option<Active>>,
    live: Arc<LiveSessions>,
    devices: Arc<DeviceService>,
    privd: PrivdClient,
    auth: Authenticator,
    next_token: AtomicU64,
}

impl SessionManager {
    /// Builds the manager.
    pub fn new(
        settings: SessionSettings,
        link: Arc<dyn DesktopLink>,
        privd: PrivdClient,
        devices: Arc<DeviceService>,
        live: Arc<LiveSessions>,
        auth: Authenticator,
        clock: Arc<dyn Clock>,
    ) -> Arc<Self> {
        Arc::new(Self {
            supervisor: DesktopSupervisor::new(privd.clone(), settings.desktop_id.clone()),
            limiter: TakeoverLimiter::new(settings.takeover, clock),
            settings,
            link,
            active: Mutex::new(None),
            live,
            devices,
            privd,
            auth,
            next_token: AtomicU64::new(1),
        })
    }

    /// The link, for the admin `Status`.
    pub fn link(&self) -> &Arc<dyn DesktopLink> {
        &self.link
    }

    /// Runs one authorized session to its end. Returns when the connection is closed.
    pub async fn serve(
        self: &Arc<Self>,
        conn: Connection,
        device: DeviceRecord,
        revocations: broadcast::Receiver<DeviceId>,
    ) {
        let Ok(live_guard) = self.live.register(device.id, conn.clone()) else {
            tracing::warn!(device = %short_id(&device.id), "too many live sessions; refusing");
            goodbye(
                &conn,
                CloseCode::Busy,
                "too many sessions",
                "too many sessions",
            )
            .await;
            return;
        };
        let mut s = Session {
            mgr: self.clone(),
            features: conn.enabled_features(),
            conn,
            device,
            client: None,
            token: 0,
            revokes: VecDeque::new(),
        };
        s.run(revocations).await;
        s.cleanup().await;
        drop(live_guard);
    }

    /// Claims the desktop for `device` (see the module documentation).
    async fn claim(&self, conn: &Connection, device: &DeviceRecord, view: pb::ViewConfig) -> Claim {
        match tokio::time::timeout(READY_TIMEOUT, self.supervisor.ensure_ready()).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::warn!(reason = %log_text(&e.0, 200), "the desktop is not ready");
                return Claim::Unavailable;
            }
            Err(_) => {
                tracing::warn!("making the desktop ready took too long");
                return Claim::Unavailable;
            }
        }
        let mut active = self.active.lock().await;
        // The device may have been revoked while the desktop was starting: look again, under
        // the lock, right before anything is displaced or attached.
        if conn.close_info().is_some() || !self.devices.is_active(&device.id) {
            return Claim::Revoked;
        }
        // A stale entry (its connection already closed) is not an active client.
        if active
            .as_ref()
            .is_some_and(|a| a.conn.close_info().is_some())
            && let Some(stale) = active.take()
        {
            stale.client.detach(DetachReason::Left).await;
        }
        let new_name = sanitize_device_name(&device.name);
        if let Some(old) = active.take() {
            let same_device = old.device_id == device.id;
            // A device replacing its own session is exempt from the policy and the limit only
            // if the old connection is dead: it does not answer a ping within a second (a
            // client that lost its network). A copied key plus PIN against a live owner
            // connection gets no exemption, so it cannot displace the owner at will.
            let exempt = same_device && old.conn.ping(SELF_REPLACE_PING).await.is_err();
            if !exempt && let Err(refusal) = self.limiter.permit() {
                *active = Some(old);
                return Claim::Busy(match refusal {
                    Refusal::Denied => "another device is using this desktop",
                    Refusal::RateLimited => "too many takeovers, try again later",
                });
            }
            tracing::info!(
                old = %short_id(&old.device_id),
                new = %short_id(&device.id),
                same_device,
                exempt,
                "taking over the desktop"
            );
            // (1) and (2), then the old relay is torn down.
            bounded(old.client.release_input()).await;
            bounded(old.client.cancel_in_flight()).await;
            old.client.detach(DetachReason::Displaced).await;
            // (3) tell the old client, then close it.
            notify_displaced(&old.conn, &new_name, &device.id).await;
            if !exempt {
                let privd = self.privd.clone();
                let (id, label) = (*device.id.as_bytes(), new_name.clone());
                tokio::spawn(async move {
                    if let Err(e) = privd
                        .record_event(AuditEvent::Takeover, Some(id), &label)
                        .await
                    {
                        tracing::warn!(error = %e, "TAKEOVER was not recorded in the audit log");
                    }
                });
            }
        }
        // (4) the newcomer.
        let request = AttachRequest {
            connection: conn.clone(),
            device_id: device.id,
            device_name: new_name.clone(),
            negotiated: conn.negotiated().clone(),
            view,
        };
        match self.link.attach(request).await {
            Ok(client) => {
                // Whatever the link does with a handle after it is detached, the gateway's
                // wrapper ignores it.
                let client: Arc<dyn LinkClient> = GuardedClient::new(client);
                let token = self.next_token.fetch_add(1, Ordering::Relaxed);
                *active = Some(Active {
                    token,
                    conn: conn.clone(),
                    device_id: device.id,
                    device_name: new_name,
                    client: client.clone(),
                });
                Claim::Claimed(client, token)
            }
            Err(LinkError::Unavailable) => Claim::Unavailable,
            Err(e) => {
                tracing::error!(error = %e, "attaching the client to the desktop failed");
                Claim::Unavailable
            }
        }
    }

    /// Releases the desktop if `token` still holds it (the client left or was revoked).
    async fn release(&self, token: u64) {
        let mut active = self.active.lock().await;
        if active.as_ref().is_some_and(|a| a.token == token)
            && let Some(a) = active.take()
        {
            tracing::debug!(device = %short_id(&a.device_id), name = %log_text(&a.device_name, 64), "client left the desktop");
            a.client.detach(DetachReason::Left).await;
        }
    }

    /// True if some client holds the desktop (tests and `Status`).
    pub async fn has_active_client(&self) -> bool {
        self.active.lock().await.is_some()
    }
}

async fn bounded(f: impl std::future::Future<Output = ()>) {
    if tokio::time::timeout(LINK_STEP_TIMEOUT, f).await.is_err() {
        tracing::warn!("a link step during takeover timed out");
    }
}

/// Sends `Goodbye`, waits (at most [`GOODBYE_FLUSH`]) until the peer's transport has read it,
/// then closes. A `Ping` round trip proves delivery: the control stream is ordered, so the
/// peer cannot answer the ping before it has read the `Goodbye` that precedes it.
async fn goodbye(conn: &Connection, code: CloseCode, message: &str, reason: &str) {
    let m = pb::ControlMessage::new(Ctl::Goodbye(pb::Goodbye {
        code: code.code(),
        message: message.to_owned(),
        ..Default::default()
    }));
    if tokio::time::timeout(SEND_TIMEOUT, conn.send_control(&m))
        .await
        .is_ok()
    {
        let _ = conn.ping(GOODBYE_FLUSH).await;
    }
    conn.close(code, reason).await;
}

/// Takeover step (3): tell the displaced client and close its connection.
async fn notify_displaced(old: &Connection, new_name: &str, new_id: &DeviceId) {
    let minor_ok = old.negotiated().version.minor >= 1;
    let (code, goodbye_msg) = if minor_ok {
        (
            CloseCode::TakenOver,
            pb::Goodbye {
                code: CloseCode::TakenOver.code(),
                message: TAKEN_OVER_MESSAGE.into(),
                peer_device_name: new_name.to_owned(),
                peer_device_id: bytes::Bytes::copy_from_slice(new_id.as_bytes()),
            },
        )
    } else {
        // A 1.0 peer would read the new code as INTERNAL_ERROR (protocol 5.7, item 5).
        (
            CloseCode::Busy,
            pb::Goodbye {
                code: CloseCode::Busy.code(),
                message: TAKEN_OVER_MESSAGE.into(),
                ..Default::default()
            },
        )
    };
    let m = pb::ControlMessage::new(Ctl::Goodbye(goodbye_msg));
    if tokio::time::timeout(SEND_TIMEOUT, old.send_control(&m))
        .await
        .is_ok()
    {
        let _ = old.ping(GOODBYE_FLUSH).await;
    }
    let old = old.clone();
    tokio::spawn(async move { old.close(code, TAKEN_OVER_REASON).await });
}

struct Session {
    mgr: Arc<SessionManager>,
    conn: Connection,
    device: DeviceRecord,
    features: Features,
    client: Option<Arc<dyn LinkClient>>,
    token: u64,
    revokes: VecDeque<Instant>,
}

impl Session {
    async fn run(&mut self, mut revocations: broadcast::Receiver<DeviceId>) {
        let mut notices = self.mgr.devices.subscribe();
        let mut tick = tokio::time::interval(self.mgr.settings.watch_interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await; // the first tick is immediate
        let idle = tokio::time::sleep(self.mgr.settings.manage_idle);
        tokio::pin!(idle);
        let id = self.device.id;
        loop {
            let flow = tokio::select! {
                // Closing and revocation are looked at before the next message: a request
                // queued behind its sender's revocation must never be served.
                biased;
                _ = self.conn.closed() => return,
                r = revocations.recv() => match r {
                    Ok(rid) if rid == id => Flow::End(Some((CloseCode::Unauthorized, "device revoked"))),
                    Ok(_) => Flow::Continue,
                    Err(broadcast::error::RecvError::Lagged(_)) => self.registry_check().await,
                    Err(broadcast::error::RecvError::Closed) => return,
                },
                msg = self.conn.recv_control() => match msg {
                    Ok(m) => self.handle(m).await,
                    Err(_) => return,
                },
                n = notices.recv() => match n {
                    Ok(notice) => self.push_notice(&notice).await,
                    Err(broadcast::error::RecvError::Lagged(_)) => Flow::Continue,
                    Err(broadcast::error::RecvError::Closed) => return,
                },
                _ = tick.tick() => self.registry_check().await,
                () = &mut idle, if self.client.is_none() => {
                    tracing::debug!(device = %short_id(&id), "management-only session idle; closing");
                    Flow::End(Some((CloseCode::NoError, "idle")))
                }
            };
            match flow {
                Flow::Continue => {}
                Flow::End(close) => {
                    if let Some((code, reason)) = close {
                        // A QUIC close discards what the peer has not read yet: let it read
                        // what was just sent (a self-revoke's answer) unless it misbehaved.
                        if code != CloseCode::ProtocolError {
                            let _ = self.conn.ping(GOODBYE_FLUSH).await;
                        }
                        self.conn.close(code, reason).await;
                    }
                    return;
                }
            }
        }
    }

    async fn cleanup(&mut self) {
        if self.client.is_some() {
            self.mgr.release(self.token).await;
        }
    }

    async fn registry_check(&self) -> Flow {
        match self.mgr.devices.records() {
            Ok(list) => match list.iter().find(|r| r.id == self.device.id) {
                Some(r) if !r.is_revoked() => Flow::Continue,
                _ => Flow::End(Some((CloseCode::Unauthorized, "device revoked"))),
            },
            Err(e) => {
                tracing::error!(error = %e, "registry re-check failed");
                Flow::Continue
            }
        }
    }

    async fn send(&self, m: pb::ControlMessage) -> Result<(), Flow> {
        match tokio::time::timeout(SEND_TIMEOUT, self.conn.send_control(&m)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(Flow::End(None)),
            // A client that does not read its control channel: the write may be half done, so
            // the connection cannot be used any more.
            Err(_) => Err(Flow::End(Some((CloseCode::Busy, "not reading")))),
        }
    }

    async fn push_notice(&self, n: &DeviceNotice) -> Flow {
        if !self.features.contains(Features::DEVICE_MANAGEMENT) {
            return Flow::Continue;
        }
        let m = pb::ControlMessage::new(Ctl::DeviceMgmt(pb::DeviceMgmt {
            request_id: 0,
            body: Some(pb::device_mgmt::Body::Event(pb::DeviceEvent {
                kind: n.kind as i32,
                device: Some(n.device.clone()),
                by_device_id: n
                    .by
                    .map(|d| bytes::Bytes::copy_from_slice(d.as_bytes()))
                    .unwrap_or_default(),
            })),
        }));
        match self.send(m).await {
            Ok(()) => Flow::Continue,
            Err(f) => f,
        }
    }

    async fn handle(&mut self, m: pb::ControlMessage) -> Flow {
        let violation = |why: &'static str| Flow::End(Some((CloseCode::ProtocolError, why)));
        match m.message {
            Some(Ctl::ViewConfig(v)) => self.view_config(v).await,
            Some(Ctl::RequestKeyframe(k)) => {
                if let Some(c) = &self.client {
                    c.request_keyframe(k.last_decoded_frame).await;
                }
                Flow::Continue
            }
            Some(Ctl::Stats(s)) => {
                if let Some(c) = &self.client {
                    c.client_stats(s).await;
                }
                Flow::Continue
            }
            Some(Ctl::Goodbye(_)) => Flow::End(Some((CloseCode::NoError, "goodbye"))),
            Some(Ctl::DeviceMgmt(d)) => self.device_mgmt(d).await,
            // Only the server sends these (protocol 5.8, 5.2, 10): a client that does is broken.
            Some(Ctl::ServerStats(_)) => violation("ServerStats from a client"),
            Some(Ctl::StreamInfo(_)) => violation("StreamInfo from a client"),
            Some(Ctl::Hello(_) | Ctl::HelloAck(_) | Ctl::Refuse(_)) => {
                violation("handshake message after the handshake")
            }
            Some(Ctl::Pairing(_) | Ctl::Auth(_)) => {
                violation("pairing or auth after authorization")
            }
            // Ping and Pong never surface; a message with no variant never validates.
            Some(Ctl::Ping(_) | Ctl::Pong(_)) | None => Flow::Continue,
        }
    }

    async fn view_config(&mut self, v: pb::ViewConfig) -> Flow {
        let violation = |why: &'static str| Flow::End(Some((CloseCode::ProtocolError, why)));
        let n = self.conn.negotiated();
        // Protocol 4.3: a codec outside the negotiated intersection is a protocol error.
        let codec = pb::VideoCodec::try_from(v.codec).unwrap_or(pb::VideoCodec::Unspecified);
        if codec != pb::VideoCodec::Unspecified && !n.codecs.contains(&codec) {
            return violation("ViewConfig codec was not negotiated");
        }
        // Protocol 5.2: these flags require the matching negotiated feature.
        if (v.audio_enabled && !self.features.contains(Features::AUDIO))
            || (v.clipboard_enabled && !self.features.contains(Features::CLIPBOARD))
            || (v.stats_enabled && !self.features.contains(Features::SERVER_STATS))
        {
            return violation("ViewConfig asks for a feature that was not negotiated");
        }
        if let Some(c) = &self.client {
            c.view_config(v).await;
            return Flow::Continue;
        }
        match self.mgr.claim(&self.conn, &self.device, v).await {
            Claim::Claimed(client, token) => {
                self.client = Some(client);
                self.token = token;
                Flow::Continue
            }
            Claim::Busy(why) => {
                goodbye(&self.conn, CloseCode::Busy, why, "busy").await;
                Flow::End(None)
            }
            Claim::Revoked => Flow::End(Some((CloseCode::Unauthorized, "device revoked"))),
            Claim::Unavailable => {
                goodbye(
                    &self.conn,
                    CloseCode::Busy,
                    "desktop unavailable",
                    "desktop unavailable",
                )
                .await;
                Flow::End(None)
            }
        }
    }

    async fn device_mgmt(&mut self, m: pb::DeviceMgmt) -> Flow {
        use pb::device_mgmt::Body as B;
        let violation = |why: &'static str| Flow::End(Some((CloseCode::ProtocolError, why)));
        if !self.features.contains(Features::DEVICE_MANAGEMENT) {
            return violation("device management was not negotiated");
        }
        if m.direction() != Some(MgmtDirection::ClientToServer) {
            return violation("a server-only DeviceMgmt body from a client");
        }
        let mut requester_gone = false;
        let reply = match m.body {
            Some(B::List(_)) => match self.mgr.devices.device_list(Some(self.device.id)) {
                Ok(list) => B::DeviceList(list),
                Err(e) => {
                    tracing::error!(error = %e, "listing devices failed");
                    return Flow::End(Some((CloseCode::InternalError, "registry failure")));
                }
            },
            Some(B::Revoke(r)) => {
                let now = Instant::now();
                while self
                    .revokes
                    .front()
                    .is_some_and(|t| now.duration_since(*t) >= REVOKE_WINDOW)
                {
                    self.revokes.pop_front();
                }
                let status = if self.revokes.len() >= REVOKES_PER_WINDOW {
                    pb::RevokeStatus::RateLimited
                } else {
                    self.revokes.push_back(now);
                    match device_id(&r.device_id) {
                        Some(target) => {
                            self.mgr
                                .devices
                                .revoke_by_device(self.device.id, target)
                                .await
                        }
                        None => pb::RevokeStatus::NotFound,
                    }
                };
                // FAILED because the asker itself was revoked meanwhile: answer, then close.
                requester_gone = status == pb::RevokeStatus::Failed
                    && !self.mgr.devices.is_active(&self.device.id);
                B::RevokeResult(pb::RevokeResult {
                    status: status as i32,
                })
            }
            _ => return violation("unexpected DeviceMgmt body"),
        };
        let out = pb::ControlMessage::new(Ctl::DeviceMgmt(pb::DeviceMgmt {
            request_id: m.request_id,
            body: Some(reply),
        }));
        match self.send(out).await {
            Ok(()) if requester_gone => {
                Flow::End(Some((CloseCode::Unauthorized, "device revoked")))
            }
            Ok(()) => Flow::Continue,
            Err(f) => f,
        }
    }
}
