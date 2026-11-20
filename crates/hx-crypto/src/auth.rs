//! The server-side authenticator: decides, for every [`PendingSession`], between pairing and
//! a PIN-protected session, and authorizes the connection only after the peer proved itself
//! (protocol §11.2 to §11.5).

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};

use hx_proto::{
    channel::CloseCode,
    pb::{self, Intent, RefuseReason},
    version::{Features, capabilities},
};
use hx_transport::{Connection, PendingSession, ServerHello};
use tokio::sync::broadcast;

use crate::{
    clock::{Clock, SystemClock},
    error::{Error, Result},
    keys::{DeviceId, IdentityKey, PublicKey},
    pairing::{PairedDevice, PairingLimits, PairingWindow, serve_pairing},
    pin::{MAX_PIN_FAILURES, PinHash, backoff_after},
    registry::{DeviceRecord, DeviceRegistry, RevokeReason},
    secrets::Pin,
    text::sanitize_label,
    tls,
    wire::{AuthMessage, AuthResult, AuthStatus, auth_message::Body},
};

/// Tunables of the [`Authenticator`].
#[derive(Clone, Debug)]
pub struct AuthenticatorConfig {
    /// Label sent to clients during pairing (at most 64 bytes).
    pub server_name: String,
    /// Software string for `HelloAck` (at most 128 bytes).
    pub software: String,
    /// Capabilities offered to authenticated sessions (pairing connections get none).
    pub capabilities: pb::Capabilities,
    /// Features enabled when a session is authorized (intersected with the negotiated ones).
    pub session_features: Features,
    /// Bound on the pairing exchange after `HelloAck`.
    pub pair_timeout: Duration,
    /// Bound on the PIN exchange after `HelloAck`.
    pub pin_timeout: Duration,
    /// Wrong PINs that revoke a device (protocol: 5).
    pub max_pin_failures: u32,
    /// PIN attempt messages accepted on one connection.
    pub max_pin_messages: u32,
    /// Pairing window limits.
    pub pairing: PairingLimits,
}

impl Default for AuthenticatorConfig {
    fn default() -> Self {
        Self {
            server_name: "hash-xcreen server".into(),
            software: concat!("hx-crypto ", env!("CARGO_PKG_VERSION")).into(),
            capabilities: capabilities(&[], Features::NONE),
            session_features: Features::defined_up_to(0),
            pair_timeout: Duration::from_secs(20),
            pin_timeout: Duration::from_secs(25),
            max_pin_failures: MAX_PIN_FAILURES,
            max_pin_messages: 5,
            pairing: PairingLimits::default(),
        }
    }
}

/// What [`Authenticator::authenticate`] did with a session.
#[derive(Debug)]
pub enum Outcome {
    /// Pairing succeeded. The connection is open and still restricted (pairing connections
    /// carry control messages only); the application may exchange its setup messages on it
    /// and must then close it with `NO_ERROR`. The device reconnects with `INTENT_SESSION`.
    Paired {
        /// The pairing connection.
        connection: Connection,
        /// The registry entry of the new device.
        device: DeviceRecord,
    },
    /// The PIN was right and the connection was authorized.
    Authorized {
        /// The authorized connection. It is closed automatically if the device is revoked.
        connection: Connection,
        /// The device.
        device: DeviceRecord,
    },
    /// The session was refused before `HelloAck` (the client was told); nothing is left open.
    Refused(RefuseReason),
}

struct Inner {
    identity: Arc<IdentityKey>,
    registry: Arc<dyn DeviceRegistry>,
    clock: Arc<dyn Clock>,
    window: PairingWindow,
    pin: RwLock<Option<Arc<PinHash>>>,
    config: AuthenticatorConfig,
    revocations: broadcast::Sender<DeviceId>,
    /// Earliest time each device may try its PIN again (memory only).
    not_before: Mutex<HashMap<DeviceId, Instant>>,
    /// One PIN verification at a time per device, so parallel connections cannot multiply
    /// guesses past the failure limit.
    device_locks: Mutex<HashMap<DeviceId, Arc<tokio::sync::Mutex<()>>>>,
}

/// Decides, for each incoming session, whether to pair it, check its PIN, or refuse it.
/// Cheap to clone (shared state).
#[derive(Clone)]
pub struct Authenticator {
    inner: Arc<Inner>,
}

impl Authenticator {
    /// Build an authenticator with the real clock.
    pub fn new(
        identity: Arc<IdentityKey>,
        registry: Arc<dyn DeviceRegistry>,
        config: AuthenticatorConfig,
    ) -> Self {
        Self::with_clock(identity, registry, config, Arc::new(SystemClock))
    }

    /// Build with an explicit clock (tests move time without sleeping).
    pub fn with_clock(
        identity: Arc<IdentityKey>,
        registry: Arc<dyn DeviceRegistry>,
        config: AuthenticatorConfig,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let (revocations, _) = broadcast::channel(64);
        Self {
            inner: Arc::new(Inner {
                identity,
                registry,
                window: PairingWindow::new(clock.clone(), config.pairing.clone()),
                clock,
                pin: RwLock::new(None),
                config,
                revocations,
                not_before: Mutex::new(HashMap::new()),
                device_locks: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// The pairing window: issue tokens and codes, close it.
    pub fn pairing(&self) -> &PairingWindow {
        &self.inner.window
    }

    /// The registry (for listing devices and, after the caller verified the password,
    /// `reinstate`).
    pub fn registry(&self) -> &Arc<dyn DeviceRegistry> {
        &self.inner.registry
    }

    /// This server's public identity key (what clients pin).
    pub fn server_key(&self) -> PublicKey {
        self.inner.identity.public()
    }

    /// Set or replace the PIN verifier. Until one is set, sessions are refused.
    pub fn set_pin(&self, hash: PinHash) {
        if let Ok(mut p) = self.inner.pin.write() {
            *p = Some(Arc::new(hash));
        }
    }

    fn pin_hash(&self) -> Option<Arc<PinHash>> {
        self.inner.pin.read().ok().and_then(|p| p.clone())
    }

    /// Revoke a device now: persist it, close its live sessions, and announce it on
    /// [`subscribe_revocations`](Self::subscribe_revocations). Returns false if the device is
    /// unknown or already revoked.
    pub async fn revoke(&self, id: &DeviceId, reason: RevokeReason) -> Result<bool> {
        let (id2, now) = (*id, self.inner.clock.unix_secs());
        let revoked = self.reg(move |r| r.revoke(&id2, reason, now)).await?;
        if revoked {
            // No receiver is fine: nothing is live.
            let _ = self.inner.revocations.send(*id);
        }
        Ok(revoked)
    }

    /// Every revocation (by an operator or by the PIN lockout) is announced here, for
    /// components that keep per-device state (for example the session supervisor). Live
    /// connections authorized by this authenticator are closed by it directly.
    pub fn subscribe_revocations(&self) -> broadcast::Receiver<DeviceId> {
        self.inner.revocations.subscribe()
    }

    /// Run a registry call on a blocking thread (it may fsync).
    async fn reg<R: Send + 'static>(
        &self,
        f: impl FnOnce(&dyn DeviceRegistry) -> Result<R> + Send + 'static,
    ) -> Result<R> {
        let r = self.inner.registry.clone();
        tokio::task::spawn_blocking(move || f(&*r))
            .await
            .map_err(|_| Error::Protocol("registry task failed"))?
    }

    /// Handle one pending session end to end. Call it from its own task for every session
    /// the transport yields, so a slow peer never blocks the accept loop.
    ///
    /// The peer's key is looked up in the **current** registry. The connection is authorized
    /// only after the PIN was verified, and just before the client is told so. Failures close
    /// the connection and are returned as errors (logged here without secrets).
    pub async fn authenticate(&self, pending: PendingSession) -> Result<Outcome> {
        // Subscribe before the first registry read, so a revocation during the exchange is
        // never missed.
        let rx = self.inner.revocations.subscribe();
        let hello = pending.hello();
        let device_label = sanitize_label(&hello.device_name, 64, "unnamed");
        let remote = pending.remote_addr();
        let intent = Intent::try_from(hello.intent).unwrap_or(Intent::Unspecified);

        let key = match tls::peer_key(pending.peer_certificates()) {
            Ok(k) => k,
            Err(_) => {
                return self
                    .refuse(pending, RefuseReason::Unauthorized, "not authorized")
                    .await;
            }
        };
        let known = {
            let k = key;
            self.reg(move |r| r.find_by_key(&k)).await
        };
        let known = match known {
            Ok(k) => k,
            Err(e) => {
                tracing::error!(error = %e, "registry lookup failed; refusing");
                let _ = self
                    .refuse(pending, RefuseReason::Unauthorized, "not authorized")
                    .await;
                return Err(e);
            }
        };
        tracing::debug!(%remote, device = %device_label, key = %key.fingerprint().short(), ?intent, "pending session");

        match intent {
            Intent::Pair => self.pair(pending, key, known).await,
            Intent::Session => self.session(pending, known, rx).await,
            Intent::Unspecified => {
                self.refuse(pending, RefuseReason::Unauthorized, "not authorized")
                    .await
            }
        }
    }

    async fn refuse(
        &self,
        pending: PendingSession,
        reason: RefuseReason,
        text: &str,
    ) -> Result<Outcome> {
        pending.refuse(reason, text).await?;
        Ok(Outcome::Refused(reason))
    }

    // -------------------------------------------------------------- pairing

    async fn pair(
        &self,
        pending: PendingSession,
        key: PublicKey,
        known: Option<DeviceRecord>,
    ) -> Result<Outcome> {
        if known.as_ref().is_some_and(DeviceRecord::is_revoked) {
            return self
                .refuse(
                    pending,
                    RefuseReason::Unauthorized,
                    "this device was revoked",
                )
                .await;
        }
        if !self.inner.window.is_open() {
            return self
                .refuse(pending, RefuseReason::PairingClosed, "pairing is closed")
                .await;
        }
        let conn = pending
            .accept(ServerHello {
                capabilities: capabilities(&[], Features::NONE),
                software: self.inner.config.software.clone(),
            })
            .await?;
        let result = tokio::time::timeout(
            self.inner.config.pair_timeout,
            serve_pairing(
                &conn,
                &self.inner.window,
                &self.inner.registry,
                &self.inner.clock,
                &self.inner.identity.public(),
                &self.inner.config.server_name,
                &key,
                self.inner.config.pair_timeout,
            ),
        )
        .await;
        match result {
            Ok(Ok(PairedDevice { record })) => {
                tracing::info!(device = %record.id, key = %key.fingerprint().short(), "device paired");
                Ok(Outcome::Paired {
                    connection: conn,
                    device: record,
                })
            }
            Ok(Err(e)) => {
                tracing::warn!(key = %key.fingerprint().short(), "pairing failed");
                close_after(&conn, CloseCode::Unauthorized, "pairing failed").await;
                Err(e)
            }
            Err(_) => {
                close_after(&conn, CloseCode::Unauthorized, "pairing timed out").await;
                Err(Error::Timeout("pairing"))
            }
        }
    }

    // -------------------------------------------------------------- session and PIN

    async fn session(
        &self,
        pending: PendingSession,
        known: Option<DeviceRecord>,
        rx: broadcast::Receiver<DeviceId>,
    ) -> Result<Outcome> {
        let Some(device) = known else {
            return self
                .refuse(pending, RefuseReason::Unauthorized, "not authorized")
                .await;
        };
        if device.is_revoked() {
            return self
                .refuse(
                    pending,
                    RefuseReason::Unauthorized,
                    "this device was revoked",
                )
                .await;
        }
        if self.pin_hash().is_none() {
            return self
                .refuse(
                    pending,
                    RefuseReason::Unauthorized,
                    "server is not set up yet",
                )
                .await;
        }
        let conn = pending
            .accept(ServerHello {
                capabilities: self.inner.config.capabilities.clone(),
                software: self.inner.config.software.clone(),
            })
            .await?;
        let result = tokio::time::timeout(
            self.inner.config.pin_timeout,
            self.pin_exchange(&conn, &device),
        )
        .await;
        let verdict = match result {
            Ok(v) => v,
            Err(_) => Err(Error::Timeout("PIN exchange")),
        };
        if let Err(e) = verdict {
            close_after(&conn, CloseCode::Unauthorized, "authentication failed").await;
            return Err(e);
        }

        // The PIN is right. Check the registry once more, now: a revocation (by an operator or
        // another connection) may have happened while we were hashing.
        let id = device.id;
        let fresh = self.reg(move |r| r.get(&id)).await;
        let device = match fresh {
            Ok(Some(d)) if !d.is_revoked() => d,
            Ok(_) => {
                close_after(&conn, CloseCode::Unauthorized, "device revoked").await;
                return Err(Error::Revoked);
            }
            Err(e) => {
                conn.close(CloseCode::InternalError, "registry failure")
                    .await;
                return Err(e);
            }
        };
        // Authorize first, then tell the client (protocol §13).
        if let Err(e) = conn.authorize(self.inner.config.session_features) {
            conn.close(CloseCode::InternalError, "authorize failed")
                .await;
            return Err(e.into());
        }
        self.watch(conn.clone(), device.id, rx);
        let ok = AuthMessage::new(Body::Result(AuthResult {
            status: AuthStatus::Ok as i32,
            attempts_left: self.inner.config.max_pin_failures,
            retry_after_ms: 0,
        }))
        .into_control();
        let sent = match ok {
            Ok(m) => conn.send_control(&m).await.map_err(Error::from),
            Err(e) => Err(e),
        };
        if let Err(e) = sent {
            conn.close(CloseCode::InternalError, "could not confirm")
                .await;
            return Err(e);
        }
        tracing::info!(device = %device.id, "session authorized");
        Ok(Outcome::Authorized {
            connection: conn,
            device,
        })
    }

    fn device_lock(&self, id: &DeviceId) -> Arc<tokio::sync::Mutex<()>> {
        let mut m = self
            .inner
            .device_locks
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        m.entry(*id).or_default().clone()
    }

    async fn send_result(
        &self,
        conn: &Connection,
        status: AuthStatus,
        attempts_left: u32,
        retry_after: Duration,
    ) -> Result<()> {
        let m = AuthMessage::new(Body::Result(AuthResult {
            status: status as i32,
            attempts_left,
            retry_after_ms: u32::try_from(retry_after.as_millis()).unwrap_or(u32::MAX),
        }))
        .into_control()?;
        conn.send_control(&m).await?;
        Ok(())
    }

    /// Read PIN attempts until one is right, the device is revoked, or the connection runs out
    /// of attempts. `Ok(())` means the PIN was verified (nothing is sent yet).
    async fn pin_exchange(&self, conn: &Connection, device: &DeviceRecord) -> Result<()> {
        let cfg = &self.inner.config;
        for _ in 0..cfg.max_pin_messages {
            let m = conn.recv_control().await?;
            let Some(Body::Pin(attempt)) = AuthMessage::from_control(&m)?.body else {
                return Err(Error::Protocol("expected a PIN attempt"));
            };

            // From here to the verdict nothing else may try this device's PIN.
            let lock = self.device_lock(&device.id);
            let _guard = lock.lock().await;
            let id = device.id;
            let current = self
                .reg(move |r| r.get(&id))
                .await?
                .ok_or(Error::UnknownDevice)?;
            if current.is_revoked() {
                let _ = self
                    .send_result(conn, AuthStatus::Revoked, 0, Duration::ZERO)
                    .await;
                return Err(Error::Revoked);
            }
            let now = self.inner.clock.now();
            let wait = self
                .inner
                .not_before
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(&device.id)
                .map(|t| t.saturating_duration_since(now))
                .unwrap_or(Duration::ZERO);
            let left = cfg.max_pin_failures.saturating_sub(current.failed_pins);
            if !wait.is_zero() {
                self.send_result(conn, AuthStatus::Backoff, left, wait)
                    .await?;
                continue;
            }

            let Some(hash) = self.pin_hash() else {
                self.send_result(conn, AuthStatus::NotAvailable, left, Duration::ZERO)
                    .await?;
                return Err(Error::PinNotAvailable);
            };
            let right = match Pin::from_bytes(&attempt.pin) {
                Ok(pin) => tokio::task::spawn_blocking(move || hash.verify(pin.as_bytes()))
                    .await
                    .map_err(|_| Error::Protocol("PIN task failed"))?,
                Err(_) => false,
            };
            drop(attempt);
            let now_unix = self.inner.clock.unix_secs();
            if right {
                let id = device.id;
                self.reg(move |r| r.record_pin_success(&id, now_unix))
                    .await?;
                self.inner
                    .not_before
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&device.id);
                return Ok(());
            }

            // Wrong: count it durably before answering.
            let (id, max) = (device.id, cfg.max_pin_failures);
            let f = self
                .reg(move |r| r.record_pin_failure(&id, max, now_unix))
                .await?;
            if f.revoked {
                tracing::warn!(device = %device.id, "device revoked after too many wrong PINs");
                let _ = self.inner.revocations.send(device.id);
                let _ = self
                    .send_result(conn, AuthStatus::Revoked, 0, Duration::ZERO)
                    .await;
                return Err(Error::Revoked);
            }
            let retry = backoff_after(f.failed_pins);
            self.inner
                .not_before
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(device.id, self.inner.clock.now() + retry);
            self.send_result(
                conn,
                AuthStatus::WrongPin,
                max.saturating_sub(f.failed_pins),
                retry,
            )
            .await?;
        }
        Err(Error::Protocol("too many PIN attempts on one connection"))
    }

    /// Close `conn` when its device is revoked.
    fn watch(&self, conn: Connection, id: DeviceId, mut rx: broadcast::Receiver<DeviceId>) {
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = conn.closed() => break,
                    r = rx.recv() => {
                        let hit = match r {
                            Ok(rid) => rid == id,
                            // Missed announcements: ask the registry instead.
                            Err(broadcast::error::RecvError::Lagged(_)) => this
                                .reg(move |reg| reg.get(&id))
                                .await
                                .map(|d| d.is_none_or(|d| d.is_revoked()))
                                .unwrap_or(true),
                            Err(broadcast::error::RecvError::Closed) => break,
                        };
                        if hit {
                            conn.close(CloseCode::Unauthorized, "device revoked").await;
                            break;
                        }
                    }
                }
            }
        });
    }
}

/// How long to let the peer read our last message (a failure verdict) before closing. A QUIC
/// close discards stream data the peer has not read yet, so closing at once would turn "wrong
/// PIN, revoked" into an unexplained connection loss.
const CLOSE_GRACE: Duration = Duration::from_millis(500);

async fn close_after(conn: &Connection, code: CloseCode, reason: &str) {
    let _ = tokio::time::timeout(CLOSE_GRACE, conn.closed()).await;
    conn.close(code, reason).await;
}
