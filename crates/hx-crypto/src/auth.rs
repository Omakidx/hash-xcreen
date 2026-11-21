//! The server-side authenticator: decides, for every [`PendingSession`], between pairing and
//! a PIN-protected session, and authorizes the connection only after the peer proved itself
//! (protocol §11.2 to §11.5).
//!
//! # Where the PIN is checked: [`PinVerifier`]
//!
//! By default the PIN is checked against a local [`PinHash`] ([`Authenticator::set_pin`]).
//! A deployment whose verifier has a secret step it cannot compute itself (the gateway: the
//! last step is `HMAC(pepper, Argon2id(pin))`, computed by `hx-privd`) installs a
//! [`PinVerifier`] instead with [`Authenticator::set_pin_verifier`]. The authenticator keeps
//! owning every security rule of §11.4 (counting before checking, the per-device lock, the
//! backoff, the 5th failure revokes); the verifier only answers with a [`PinVerdict`].
//!
//! ```no_run
//! use std::{sync::Arc, time::Duration};
//! use hx_crypto::{
//!     DeviceId, PairingToken,
//!     auth::{Authenticator, BoxFuture, PinVerdict, PinVerifier},
//! };
//! use zeroize::Zeroizing;
//!
//! /// What the gateway implements: Argon2id locally, then ask privd for the yes/no.
//! struct PrivdPin; // holds the privd client and the stored per-device verifiers
//!
//! impl PinVerifier for PrivdPin {
//!     fn has_pin(&self, _device: &DeviceId) -> bool {
//!         true // a verifier is stored for this device
//!     }
//!     fn verify<'a>(
//!         &'a self,
//!         _device: &'a DeviceId,
//!         _pin: Zeroizing<Vec<u8>>,
//!     ) -> BoxFuture<'a, PinVerdict> {
//!         Box::pin(async move {
//!             // 1. Argon2id(pin) on a blocking thread.
//!             // 2. `PepperVerify` to privd, bounded by a timeout.
//!             //    yes -> Right, no -> Wrong, privd down or timed out -> Unavailable,
//!             //    PIN purpose locked -> Locked { retry_after: privd's wait }.
//!             PinVerdict::Unavailable
//!         })
//!     }
//! }
//!
//! # fn demo(auth: &Authenticator, token_from_installer: &str) -> hx_crypto::Result<()> {
//! auth.set_pin_verifier(Arc::new(PrivdPin));
//! // `CreatePairingToken`: install the token the installer created (capped at the window's
//! // token ttl), so the first device can pair with it exactly once.
//! let token = PairingToken::parse(token_from_installer)?;
//! auth.pairing().install_token(&token, Duration::from_secs(15 * 60))?;
//! # Ok(()) }
//! ```

use std::{
    collections::HashMap,
    future::Future,
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
use zeroize::Zeroizing;

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
    /// How often a live session re-checks the registry as a backstop for revocations that
    /// were not announced (default 5 s; an in-memory lookup).
    pub watch_interval: Duration,
    /// A PIN attempt is not started (and not counted) if less than this remains of
    /// `pin_timeout`, so a hash is not begun that the deadline would cut off (default 1 s).
    pub min_hash_budget: Duration,
    /// How long a client is told to wait (`BACKOFF`) when the [`PinVerifier`] could not
    /// answer ([`PinVerdict::Unavailable`]); the device is also held that long server-side
    /// (default 2 s).
    pub unavailable_retry: Duration,
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
            watch_interval: Duration::from_secs(5),
            min_hash_budget: Duration::from_secs(1),
            unavailable_retry: Duration::from_secs(2),
        }
    }
}

/// A boxed, sendable future (what [`PinVerifier::verify`] returns), so the trait stays
/// object safe without extra dependencies.
pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What a [`PinVerifier`] found out about one PIN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinVerdict {
    /// The PIN is right.
    Right,
    /// The PIN is wrong: counted, backed off, and the 5th consecutive one revokes the device.
    Wrong,
    /// The verifier could not decide (a remote check failed or timed out). Not the device's
    /// fault: the attempt is refunded, the device is never revoked for it, and the client is
    /// told to retry (`BACKOFF`).
    Unavailable,
    /// The verifier refuses to check PINs at all (for example `hx-privd` locked the PIN
    /// purpose after its global failure cap). Not a wrong PIN: the attempt is refunded, the
    /// client gets `NOT_AVAILABLE` (with the wait in `retry_after_ms`) and the connection
    /// ends. The device is held for the wait before its guard is released: attempts that
    /// arrive earlier get `BACKOFF`, are not verified and are not counted.
    Locked {
        /// How long to hold the device (for example privd's `retry_after`). `None` or zero
        /// means [`DEFAULT_LOCKED_WAIT`]; anything above [`MAX_LOCKED_WAIT`] is capped.
        retry_after: Option<Duration>,
    },
}

/// The wait applied after [`PinVerdict::Locked`] when the verifier names none.
pub const DEFAULT_LOCKED_WAIT: Duration = Duration::from_secs(60);

/// The longest wait a verifier can impose with [`PinVerdict::Locked`].
pub const MAX_LOCKED_WAIT: Duration = Duration::from_secs(24 * 60 * 60);

fn locked_wait(retry_after: Option<Duration>) -> Duration {
    retry_after
        .filter(|d| !d.is_zero())
        .unwrap_or(DEFAULT_LOCKED_WAIT)
        .min(MAX_LOCKED_WAIT)
}

/// Decides whether a PIN is right. The authenticator calls it **inside** the per-device guard
/// and after the attempt was counted, so an implementation needs no rate limiting of its own
/// against one device, but it must:
///
/// * bound every external call with a timeout and answer [`PinVerdict::Unavailable`] when it
///   fires: a verifier that never returns would hold that device's guard forever;
/// * answer [`PinVerdict::Wrong`] only for a definite "no": a failure to ask is `Unavailable`,
///   because a `Wrong` counts toward revocation and an `Unavailable` is refunded;
/// * never log or keep the PIN.
///
/// The PIN's format (6 to 16 digits) is checked by the authenticator first; a malformed PIN
/// never reaches the verifier.
pub trait PinVerifier: Send + Sync + 'static {
    /// True if a PIN can be checked for `device` at all. When false the client gets
    /// `NOT_AVAILABLE` (and, before `HelloAck`, the same uniform refusal as for an unknown or revoked device).
    fn has_pin(&self, _device: &DeviceId) -> bool {
        true
    }

    /// Check `pin` for `device`.
    fn verify<'a>(
        &'a self,
        device: &'a DeviceId,
        pin: Zeroizing<Vec<u8>>,
    ) -> BoxFuture<'a, PinVerdict>;
}

/// The local check: constant-time Argon2id comparison on a blocking thread.
impl PinVerifier for PinHash {
    fn verify<'a>(
        &'a self,
        _device: &'a DeviceId,
        pin: Zeroizing<Vec<u8>>,
    ) -> BoxFuture<'a, PinVerdict> {
        let hash = self.clone();
        Box::pin(async move {
            match tokio::task::spawn_blocking(move || hash.verify(&pin)).await {
                Ok(true) => PinVerdict::Right,
                // A panicked hash task is not a "right" and fails closed.
                Ok(false) | Err(_) => PinVerdict::Wrong,
            }
        })
    }
}

/// What one counted attempt came to.
enum Judged {
    Right,
    Wrong {
        failed: u32,
        revoked: bool,
    },
    /// Refunded; `failed` is the counter afterwards.
    Unavailable {
        failed: u32,
    },
    /// Refunded and the device held for `wait`.
    Locked {
        wait: Duration,
    },
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

/// Read-only view of the registry. Changes go through [`Authenticator`] (`revoke`, `remove`,
/// `reinstate`), which also close live sessions and announce them.
#[derive(Clone)]
pub struct RegistryView(Arc<dyn DeviceRegistry>);

impl RegistryView {
    /// Look a device up by id.
    pub fn get(&self, id: &DeviceId) -> Result<Option<DeviceRecord>> {
        self.0.get(id)
    }

    /// Look a device up by key.
    pub fn find_by_key(&self, key: &PublicKey) -> Result<Option<DeviceRecord>> {
        self.0.find_by_key(key)
    }

    /// All devices.
    pub fn list(&self) -> Result<Vec<DeviceRecord>> {
        self.0.list()
    }
}

struct Inner {
    identity: Arc<IdentityKey>,
    registry: Arc<dyn DeviceRegistry>,
    clock: Arc<dyn Clock>,
    window: PairingWindow,
    pin: RwLock<Option<Arc<dyn PinVerifier>>>,
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

    /// A read-only view of the registry (device list). Mutations go through
    /// [`revoke`](Self::revoke), [`remove`](Self::remove) and [`reinstate`](Self::reinstate).
    pub fn registry(&self) -> RegistryView {
        RegistryView(self.inner.registry.clone())
    }

    /// This server's public identity key (what clients pin).
    pub fn server_key(&self) -> PublicKey {
        self.inner.identity.public()
    }

    /// Set or replace the PIN verifier with a local hash. Until one is set, sessions are
    /// refused.
    pub fn set_pin(&self, hash: PinHash) {
        self.set_pin_verifier(Arc::new(hash));
    }

    /// Set or replace the PIN check with a custom [`PinVerifier`] (for example one that asks
    /// `hx-privd` for the peppered yes/no). Takes effect for the next attempt. Until a
    /// verifier is set, sessions are refused.
    pub fn set_pin_verifier(&self, verifier: Arc<dyn PinVerifier>) {
        if let Ok(mut p) = self.inner.pin.write() {
            *p = Some(verifier);
        }
    }

    fn pin_verifier(&self) -> Option<Arc<dyn PinVerifier>> {
        self.inner.pin.read().ok().and_then(|p| p.clone())
    }

    /// Revoke a device now: persist it, close its live sessions, and announce it on
    /// [`subscribe_revocations`](Self::subscribe_revocations). Returns false if the device is
    /// unknown or already revoked. The write and the announcement run as one unit that
    /// finishes even if the caller's future is dropped.
    pub async fn revoke(&self, id: &DeviceId, reason: RevokeReason) -> Result<bool> {
        let id = *id;
        self.commit(move |r, tx, now| {
            let revoked = r.revoke(&id, reason, now)?;
            if revoked {
                // No receiver is fine: nothing is live.
                let _ = tx.send(id);
            }
            Ok(revoked)
        })
        .await
    }

    /// Forget a device: persist, close its live sessions (announced like a revocation) and
    /// drop its PIN backoff state. Returns false if it was unknown.
    pub async fn remove(&self, id: &DeviceId) -> Result<bool> {
        let id = *id;
        let removed = self
            .commit(move |r, tx, _| {
                let removed = r.remove(&id)?;
                if removed {
                    let _ = tx.send(id);
                }
                Ok(removed)
            })
            .await?;
        self.inner
            .not_before
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&id);
        Ok(removed)
    }

    /// Lift a revocation. **The caller must have verified the Linux password first**
    /// (architecture §8.3). The device then has to pair again. Returns false if the device
    /// is unknown or not revoked.
    pub async fn reinstate(&self, id: &DeviceId) -> Result<bool> {
        let id = *id;
        let done = self.commit(move |r, _, _| r.reinstate(&id)).await?;
        self.inner
            .not_before
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&id);
        Ok(done)
    }

    /// An operator's lockout reset: zero the device's failure counter (without stamping
    /// `last_seen`) and drop its backoff wait. It waits for any PIN check running for the
    /// device, so it cannot interleave with an attempt. A revocation is not lifted (use
    /// [`reinstate`](Self::reinstate)). Returns false if the device is unknown.
    pub async fn reset_lockout(&self, id: &DeviceId) -> Result<bool> {
        let id = *id;
        let _guard = self.device_lock(&id).lock_owned().await;
        let done = match self.reg(move |r| r.reset_pin_failures(&id)).await {
            Ok(()) => true,
            Err(Error::UnknownDevice) => false,
            Err(e) => return Err(e),
        };
        self.set_not_before(&id, None);
        Ok(done)
    }

    /// How long the device must still wait before its PIN is tried again: the backoff after a
    /// wrong PIN, the hold after [`PinVerdict::Unavailable`] or [`PinVerdict::Locked`].
    /// Zero when no wait is running. Memory only, never blocks (a map lookup), so an admin
    /// listing can call it for every device.
    pub fn backoff_remaining(&self, id: &DeviceId) -> Duration {
        let now = self.inner.clock.now();
        self.inner
            .not_before
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(id)
            .map_or(Duration::ZERO, |t| t.saturating_duration_since(now))
    }

    /// True while [`backoff_remaining`](Self::backoff_remaining) is not zero.
    pub fn is_backing_off(&self, id: &DeviceId) -> bool {
        !self.backoff_remaining(id).is_zero()
    }

    /// Run a registry change and its announcement as one blocking unit: once started it
    /// completes even if the awaiting future is cancelled, so a persisted revocation is
    /// never left unannounced.
    async fn commit<R: Send + 'static>(
        &self,
        f: impl FnOnce(&dyn DeviceRegistry, &broadcast::Sender<DeviceId>, u64) -> Result<R>
        + Send
        + 'static,
    ) -> Result<R> {
        let (r, tx, now) = (
            self.inner.registry.clone(),
            self.inner.revocations.clone(),
            self.inner.clock.unix_secs(),
        );
        tokio::task::spawn_blocking(move || f(&*r, &tx, now))
            .await
            .map_err(|_| Error::Protocol("registry task failed"))?
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
                    .refuse(pending, RefuseReason::Unauthorized, NOT_AUTHORIZED)
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
                    .refuse(pending, RefuseReason::Unauthorized, NOT_AUTHORIZED)
                    .await;
                return Err(e);
            }
        };
        tracing::debug!(%remote, device = %device_label, key = %key.fingerprint().short(), ?intent, "pending session");

        match intent {
            Intent::Pair => self.pair(pending, key, known).await,
            Intent::Session => self.session(pending, known, rx).await,
            Intent::Unspecified => {
                self.refuse(pending, RefuseReason::Unauthorized, NOT_AUTHORIZED)
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
                .refuse(pending, RefuseReason::Unauthorized, NOT_AUTHORIZED)
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
                tracing::warn!(remote = %conn.remote_addr(), key = %key.fingerprint().short(), error = %e, "pairing failed");
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
                .refuse(pending, RefuseReason::Unauthorized, NOT_AUTHORIZED)
                .await;
        };
        if device.is_revoked() {
            return self
                .refuse(pending, RefuseReason::Unauthorized, NOT_AUTHORIZED)
                .await;
        }
        if self.pin_verifier().is_none_or(|v| !v.has_pin(&device.id)) {
            return self
                .refuse(pending, RefuseReason::Unauthorized, NOT_AUTHORIZED)
                .await;
        }
        let conn = pending
            .accept(ServerHello {
                capabilities: self.inner.config.capabilities.clone(),
                software: self.inner.config.software.clone(),
            })
            .await?;
        let deadline = std::time::Instant::now() + self.inner.config.pin_timeout;
        let result = tokio::time::timeout(
            self.inner.config.pin_timeout,
            self.pin_exchange(&conn, &device, deadline),
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

    /// Set (or clear) the earliest time the device may try its PIN again. Called while the
    /// per-device guard is held.
    fn set_not_before(&self, id: &DeviceId, wait: Option<Duration>) {
        let mut m = self
            .inner
            .not_before
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        match wait {
            Some(w) => {
                m.insert(*id, self.inner.clock.now() + w);
            }
            None => {
                m.remove(id);
            }
        }
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
    async fn pin_exchange(
        &self,
        conn: &Connection,
        device: &DeviceRecord,
        deadline: std::time::Instant,
    ) -> Result<()> {
        let cfg = &self.inner.config;
        for _ in 0..cfg.max_pin_messages {
            let m = conn.recv_control().await?;
            let Some(Body::Pin(mut attempt)) = AuthMessage::from_control(&m)?.body else {
                return Err(Error::Protocol("expected a PIN attempt"));
            };
            // Move the PIN out of the message into a zeroizing buffer.
            let pin = Zeroizing::new(std::mem::take(&mut attempt.pin));
            drop(attempt);

            // From here to the verdict nothing else may try this device's PIN. The guard is
            // owned so that the counting unit below keeps it even if this future is dropped.
            let guard = self.device_lock(&device.id).lock_owned().await;
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
            let wait = self.backoff_remaining(&device.id);
            let left = cfg.max_pin_failures.saturating_sub(current.failed_pins);
            if !wait.is_zero() {
                self.send_result(conn, AuthStatus::Backoff, left, wait)
                    .await?;
                continue;
            }
            let verifier = match self.pin_verifier() {
                Some(v) if v.has_pin(&device.id) => v,
                _ => {
                    self.send_result(conn, AuthStatus::NotAvailable, left, Duration::ZERO)
                        .await?;
                    return Err(Error::PinNotAvailable);
                }
            };
            // Do not begin a hash the deadline would cut off.
            if deadline.saturating_duration_since(std::time::Instant::now()) < cfg.min_hash_budget {
                return Err(Error::Timeout("PIN exchange"));
            }

            match self.check_pin(device.id, verifier, pin, guard).await? {
                Judged::Right => return Ok(()),
                Judged::Locked { wait } => {
                    tracing::error!(device = %device.id, ?wait, "the PIN verifier is locked; PIN logins are refused");
                    let _ = self
                        .send_result(conn, AuthStatus::NotAvailable, left, wait)
                        .await;
                    return Err(Error::PinNotAvailable);
                }
                Judged::Unavailable { failed } => {
                    tracing::warn!(device = %device.id, "the PIN verifier could not answer; the client is asked to retry");
                    self.send_result(
                        conn,
                        AuthStatus::Backoff,
                        cfg.max_pin_failures.saturating_sub(failed),
                        cfg.unavailable_retry,
                    )
                    .await?;
                }
                Judged::Wrong { failed, revoked } => {
                    tracing::warn!(remote = %conn.remote_addr(), device = %device.id, failed, "wrong PIN");
                    if revoked {
                        tracing::warn!(device = %device.id, "device revoked after too many wrong PINs");
                        let _ = self
                            .send_result(conn, AuthStatus::Revoked, 0, Duration::ZERO)
                            .await;
                        return Err(Error::Revoked);
                    }
                    self.send_result(
                        conn,
                        AuthStatus::WrongPin,
                        cfg.max_pin_failures.saturating_sub(failed),
                        backoff_after(failed),
                    )
                    .await?;
                }
            }
        }
        Err(Error::Protocol("too many PIN attempts on one connection"))
    }

    /// Count the attempt, verify, then record the outcome, as one detached unit that owns the
    /// per-device guard: if the caller is cancelled (deadline, disconnect) the attempt is
    /// still counted and a wrong PIN still counts toward revocation. The attempt is counted
    /// **before** the verifier is asked and is cleared only by a correct PIN, or refunded
    /// (exactly once) when the verifier could not judge it.
    ///
    /// The guard is held for the whole verifier round trip, so a slow verifier (a remote
    /// check) delays other attempts on this device instead of letting them run in parallel.
    async fn check_pin(
        &self,
        id: DeviceId,
        verifier: Arc<dyn PinVerifier>,
        pin: Zeroizing<Vec<u8>>,
        guard: tokio::sync::OwnedMutexGuard<()>,
    ) -> Result<Judged> {
        let this = self.clone();
        let max = self.inner.config.max_pin_failures;
        tokio::spawn(async move {
            let _guard = guard;
            let counted = this.reg(move |r| r.begin_pin_attempt(&id)).await?;
            // An earlier attempt at the limit was cut off before its verdict: it counted.
            // A malformed PIN is a failure without a check.
            let verdict = if counted > max || Pin::from_bytes(&pin).is_err() {
                PinVerdict::Wrong
            } else {
                verifier.verify(&id, pin).await
            };
            let now_unix = this.inner.clock.unix_secs();
            match verdict {
                PinVerdict::Right => {
                    this.reg(move |r| r.record_pin_success(&id, now_unix))
                        .await?;
                    this.set_not_before(&id, None);
                    return Ok(Judged::Right);
                }
                PinVerdict::Unavailable | PinVerdict::Locked { .. } => {
                    // Not judged, so not a failure: give the attempt back. If that write
                    // fails the attempt stays counted, which errs on the safe side.
                    let failed = match this.reg(move |r| r.refund_pin_attempt(&id)).await {
                        Ok(left) => left,
                        Err(e) => {
                            tracing::error!(error = %e, "could not refund a PIN attempt");
                            counted
                        }
                    };
                    if let PinVerdict::Locked { retry_after } = verdict {
                        // Same unit, still under the device guard: the next connection to
                        // take the lock sees the wait.
                        let wait = locked_wait(retry_after);
                        this.set_not_before(&id, Some(wait));
                        return Ok(Judged::Locked { wait });
                    }
                    // Hold the device for the wait the client is told, before the guard is
                    // released, so retries do not hammer the verifier.
                    this.set_not_before(&id, Some(this.inner.config.unavailable_retry));
                    return Ok(Judged::Unavailable { failed });
                }
                PinVerdict::Wrong => {}
            }
            let revoked = this
                .commit(move |r, tx, now| {
                    let revoked = r.revoke_if_failed(&id, max, now)?;
                    if revoked {
                        let _ = tx.send(id);
                    }
                    Ok(revoked)
                })
                .await?;
            // The wait starts here, before the guard is released: another connection that
            // takes the lock next must see it.
            this.set_not_before(&id, Some(backoff_after(counted)));
            Ok(Judged::Wrong {
                failed: counted,
                revoked,
            })
        })
        .await
        .map_err(|_| Error::Protocol("PIN task failed"))?
    }

    /// Close `conn` when its device is revoked or removed: on the announcement, and, as a
    /// backstop for changes nobody announced, by re-reading the registry every
    /// `watch_interval`.
    fn watch(&self, conn: Connection, id: DeviceId, mut rx: broadcast::Receiver<DeviceId>) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(this.inner.config.watch_interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await; // the first tick is immediate
            loop {
                let check_registry = tokio::select! {
                    _ = conn.closed() => break,
                    r = rx.recv() => match r {
                        Ok(rid) => {
                            if rid == id {
                                conn.close(CloseCode::Unauthorized, "device revoked").await;
                                break;
                            }
                            false
                        }
                        // Missed announcements: ask the registry instead.
                        Err(broadcast::error::RecvError::Lagged(_)) => true,
                        Err(broadcast::error::RecvError::Closed) => break,
                    },
                    _ = tick.tick() => true,
                };
                if check_registry {
                    match this.reg(move |reg| reg.get(&id)).await {
                        Ok(d) if d.as_ref().is_none_or(DeviceRecord::is_revoked) => {
                            conn.close(CloseCode::Unauthorized, "device revoked").await;
                            break;
                        }
                        Ok(_) => {}
                        Err(e) => tracing::error!(error = %e, "registry re-check failed"),
                    }
                }
            }
        });
    }
}

/// The one refusal text for an unknown device, a revoked device and a device with no PIN
/// (protocol §11.6), so a refusal never tells which case applies.
const NOT_AUTHORIZED: &str = "not authorized";

/// How long to let the peer read our last message (a failure verdict) before closing. A QUIC
/// close discards stream data the peer has not read yet, so closing at once would turn "wrong
/// PIN, revoked" into an unexplained connection loss.
const CLOSE_GRACE: Duration = Duration::from_millis(500);

async fn close_after(conn: &Connection, code: CloseCode, reason: &str) {
    let _ = tokio::time::timeout(CLOSE_GRACE, conn.closed()).await;
    conn.close(code, reason).await;
}
