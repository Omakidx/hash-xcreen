//! The session login: pinned key, then the PIN (protocol 11.2 and 11.4), with the pepper kept in
//! privd (`docs/ipc.md` section 5.3).
//!
//! # Why the gateway runs this exchange itself
//!
//! `hx_crypto::Authenticator` runs the PIN exchange, but it compares an Argon2id output with a
//! locally stored `PinHash`: there is no hook for a remote check, so it cannot use a peppered
//! verifier whose last step only privd can compute. The gateway therefore runs the *session*
//! half itself and keeps everything else of hx-crypto: the registry (failure counter, revocation),
//! `Authenticator::revoke` (persist, announce, close), the wire messages and the pairing
//! exchange (still `Authenticator::authenticate`, for `INTENT_PAIR` only). The rules below are
//! the ones of protocol 11.4, copied from `hx_crypto::auth` with exactly one difference, the
//! verdict comes from `PepperVerify`:
//!
//! 1. An attempt is **counted before it is checked** (`begin_pin_attempt`), the count, the hash
//!    and the outcome run as one detached unit that owns the per-device lock, so an attempt cut
//!    off by the connection or the deadline still counts.
//! 2. After the n-th consecutive failure the device waits `min(2^(n-1), 30)` s; an attempt that
//!    arrives earlier is answered `BACKOFF`, not verified, not counted. The wait is in memory.
//! 3. The 5th consecutive failure revokes the device (`REVOKED`, close `UNAUTHORIZED`).
//! 4. At most 5 attempt messages per connection; a malformed PIN counts as a failure without a
//!    hash.
//! 5. The registry is checked again immediately before `authorize()`.
//!
//! # privd outages are not wrong PINs
//!
//! privd may restart during an update (`UNAVAILABLE`, ipc.md 5.3). Before an attempt is counted
//! the gateway checks that privd answers; if it does not, the attempt is answered `BACKOFF`
//! (the client waits and retries; nothing was verified or counted). If privd fails *after* the
//! attempt was counted (a window of milliseconds), the counter stays counted (the registry has no
//! decrement; the round report proposes one) but the device is **never revoked** on a privd
//! failure: only a `no` from `PepperVerify` is a wrong PIN. A locked PIN purpose (`LOCKED`) is
//! answered `NOT_AVAILABLE` and the connection is closed.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hx_crypto::pin::{MAX_PIN_FAILURES, backoff_after};
use hx_crypto::wire::{AuthMessage, AuthResult, AuthStatus, auth_message::Body};
use hx_crypto::{Clock, DeviceId, DeviceRecord, DeviceRegistry, Pin};
use hx_ipc::privd::pb::LockoutPurpose;
use hx_proto::channel::CloseCode;
use hx_transport::Connection;
use zeroize::Zeroizing;

use super::privd_client::{PrivdClient, PrivdError};
use super::verifier::{VerifierRecord, VerifierStore};

/// Tunables of the PIN exchange.
#[derive(Debug, Clone)]
pub struct LoginConfig {
    /// Bound on the whole exchange after `HelloAck`.
    pub pin_timeout: Duration,
    /// Wrong PINs that revoke a device (protocol: 5).
    pub max_pin_failures: u32,
    /// PIN attempt messages accepted on one connection.
    pub max_pin_messages: u32,
    /// An attempt is not started if less than this remains of `pin_timeout`.
    pub min_hash_budget: Duration,
    /// How long a client is told to wait when privd is unavailable.
    pub privd_retry: Duration,
}

impl Default for LoginConfig {
    fn default() -> Self {
        Self {
            pin_timeout: Duration::from_secs(25),
            max_pin_failures: MAX_PIN_FAILURES,
            max_pin_messages: 5,
            min_hash_budget: Duration::from_secs(1),
            privd_retry: Duration::from_secs(2),
        }
    }
}

/// Why a PIN exchange ended without success.
#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    /// The device is (or just became) revoked.
    #[error("device revoked")]
    Revoked,
    /// The exchange ran out of time.
    #[error("PIN exchange timed out")]
    Timeout,
    /// The peer broke the protocol (a wrong message, too many attempts).
    #[error("protocol violation: {0}")]
    Protocol(&'static str),
    /// The server has no PIN for this device.
    #[error("no PIN verifier is set")]
    NoVerifier,
    /// privd locked the PIN purpose (global failure cap, ipc.md 5.3).
    #[error("the PIN purpose is locked in privd")]
    Locked,
    /// The transport failed.
    #[error("transport: {0}")]
    Transport(#[from] hx_transport::Error),
    /// A registry or message error from hx-crypto.
    #[error("{0}")]
    Crypto(#[from] hx_crypto::Error),
}

/// How long a device waits after privd reported the PIN purpose locked (when privd names no
/// time of its own).
const LOCKED_WAIT: Duration = Duration::from_secs(60);

enum Verdict {
    Right,
    Wrong {
        failed: u32,
        revoked: bool,
    },
    /// privd failed after the attempt was counted: neither right nor wrong.
    Unavailable {
        counted: u32,
    },
    Locked,
}

struct Shared {
    registry: Arc<dyn DeviceRegistry>,
    verifiers: Arc<VerifierStore>,
    privd: PrivdClient,
    clock: Arc<dyn Clock>,
    config: LoginConfig,
    /// Earliest time each device may try its PIN again (memory only).
    not_before: Mutex<HashMap<DeviceId, Instant>>,
    /// One verification at a time per device, so parallel connections cannot multiply guesses.
    device_locks: Mutex<HashMap<DeviceId, Arc<tokio::sync::Mutex<()>>>>,
    /// The device service: a lockout revocation goes through it, so that it is serialized with
    /// every other revocation and recorded like one.
    devices: Arc<super::devices::DeviceService>,
}

/// The PIN login of the gateway. Cheap to clone.
#[derive(Clone)]
pub struct Login(Arc<Shared>);

impl Login {
    /// A login over `registry` (the same one the authenticator was built on), `verifiers` and `privd`.
    pub fn new(
        registry: Arc<dyn DeviceRegistry>,
        verifiers: Arc<VerifierStore>,
        privd: PrivdClient,
        clock: Arc<dyn Clock>,
        config: LoginConfig,
        devices: Arc<super::devices::DeviceService>,
    ) -> Self {
        Self(Arc::new(Shared {
            registry,
            verifiers,
            privd,
            clock,
            config,
            not_before: Mutex::new(HashMap::new()),
            device_locks: Mutex::new(HashMap::new()),
            devices,
        }))
    }

    /// The exchange timeout.
    pub fn pin_timeout(&self) -> Duration {
        self.0.config.pin_timeout
    }

    /// True while `id` must wait before its next attempt (the "locked" state shown to admins).
    pub fn is_backing_off(&self, id: &DeviceId) -> bool {
        let now = self.0.clock.now();
        self.0
            .not_before
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(id)
            .is_some_and(|t| *t > now)
    }

    /// Forgets the wait of `id` and drops its lock entry (admin reinstate / lockout reset).
    pub fn clear_backoff(&self, id: &DeviceId) {
        self.0
            .not_before
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(id);
    }

    /// Resets a device's failure counter and wait (the operator's lockout reset). The registry
    /// has no "reset counter" call, so this uses `record_pin_success`, which also stamps the
    /// last-seen time (a proposed hx-crypto addition would avoid that side effect).
    pub async fn reset_lockout(&self, id: &DeviceId) -> Result<(), hx_crypto::Error> {
        let id = *id;
        let now = self.0.clock.unix_secs();
        let guard = self.device_lock(&id).lock_owned().await;
        let done = self
            .reg(move |r| match r.get(&id)? {
                Some(rec) if !rec.is_revoked() && rec.failed_pins > 0 => {
                    r.record_pin_success(&id, now)
                }
                _ => Ok(()),
            })
            .await;
        self.clear_backoff(&id);
        drop(guard);
        done
    }

    fn set_not_before(&self, id: &DeviceId, wait: Option<Duration>) {
        let mut m = self.0.not_before.lock().unwrap_or_else(|p| p.into_inner());
        match wait {
            Some(w) => {
                m.insert(*id, self.0.clock.now() + w);
            }
            None => {
                m.remove(id);
            }
        }
    }

    fn device_lock(&self, id: &DeviceId) -> Arc<tokio::sync::Mutex<()>> {
        let mut m = self
            .0
            .device_locks
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        m.entry(*id).or_default().clone()
    }

    async fn reg<R: Send + 'static>(
        &self,
        f: impl FnOnce(&dyn DeviceRegistry) -> hx_crypto::Result<R> + Send + 'static,
    ) -> hx_crypto::Result<R> {
        let r = self.0.registry.clone();
        tokio::task::spawn_blocking(move || f(&*r))
            .await
            .map_err(|_| hx_crypto::Error::Protocol("registry task failed"))?
    }

    async fn send_result(
        &self,
        conn: &Connection,
        status: AuthStatus,
        attempts_left: u32,
        retry_after: Duration,
    ) -> Result<(), LoginError> {
        let m = AuthMessage::new(Body::Result(AuthResult {
            status: status as i32,
            attempts_left,
            retry_after_ms: u32::try_from(retry_after.as_millis()).unwrap_or(u32::MAX),
        }))
        .into_control()?;
        conn.send_control(&m).await?;
        Ok(())
    }

    /// Reads PIN attempts until one is right, the device is revoked, or the connection runs
    /// out of attempts. `Ok(())` means the PIN was verified and **nothing was sent yet**: the
    /// caller re-checks the registry, authorizes the connection and then sends the success
    /// ([`Self::complete`]).
    pub async fn pin_exchange(
        &self,
        conn: &Connection,
        device: &DeviceRecord,
    ) -> Result<(), LoginError> {
        let deadline = Instant::now() + self.0.config.pin_timeout;
        tokio::time::timeout(
            self.0.config.pin_timeout,
            self.pin_exchange_inner(conn, device, deadline),
        )
        .await
        .map_err(|_| LoginError::Timeout)?
    }

    async fn pin_exchange_inner(
        &self,
        conn: &Connection,
        device: &DeviceRecord,
        deadline: Instant,
    ) -> Result<(), LoginError> {
        let cfg = &self.0.config;
        for _ in 0..cfg.max_pin_messages {
            let m = conn.recv_control().await?;
            let Some(Body::Pin(mut attempt)) = AuthMessage::from_control(&m)?.body else {
                return Err(LoginError::Protocol("expected a PIN attempt"));
            };
            // Move the PIN out of the message into a zeroizing buffer; the message wipes
            // what is left of it when it drops.
            let pin = Zeroizing::new(std::mem::take(&mut attempt.pin));
            drop(attempt);

            // From here to the verdict nothing else may try this device's PIN. The guard is
            // owned so that the counting unit below keeps it even if this future is dropped.
            let guard = self.device_lock(&device.id).lock_owned().await;
            let id = device.id;
            let current = self
                .reg(move |r| r.get(&id))
                .await?
                .ok_or(hx_crypto::Error::UnknownDevice)?;
            if current.is_revoked() {
                let _ = self
                    .send_result(conn, AuthStatus::Revoked, 0, Duration::ZERO)
                    .await;
                return Err(LoginError::Revoked);
            }
            let left = cfg.max_pin_failures.saturating_sub(current.failed_pins);
            let wait = self
                .0
                .not_before
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(&device.id)
                .map(|t| t.saturating_duration_since(self.0.clock.now()))
                .unwrap_or(Duration::ZERO);
            if !wait.is_zero() {
                self.send_result(conn, AuthStatus::Backoff, left, wait)
                    .await?;
                continue;
            }
            let Some(verifier) = self.0.verifiers.pin_for(&device.id) else {
                self.send_result(conn, AuthStatus::NotAvailable, left, Duration::ZERO)
                    .await?;
                return Err(LoginError::NoVerifier);
            };
            // Do not begin a hash the deadline would cut off.
            if deadline.saturating_duration_since(Instant::now()) < cfg.min_hash_budget {
                return Err(LoginError::Timeout);
            }
            // privd must answer before the attempt is counted: an outage is never charged to
            // the device (ipc.md 5.3).
            if self.0.privd.ensure_connected().await.is_err() {
                tracing::warn!("privd is not reachable; asking the client to retry");
                self.send_result(conn, AuthStatus::Backoff, left, cfg.privd_retry)
                    .await?;
                continue;
            }

            match self.check_pin(device.id, verifier, pin, guard).await? {
                Verdict::Right => return Ok(()),
                Verdict::Locked => {
                    tracing::error!("privd reports the PIN purpose locked; PIN logins are refused");
                    let _ = self
                        .send_result(conn, AuthStatus::NotAvailable, left, Duration::ZERO)
                        .await;
                    return Err(LoginError::Locked);
                }
                Verdict::Unavailable { counted } => {
                    tracing::warn!("privd failed during a PIN check; the client is asked to retry");
                    let left = cfg.max_pin_failures.saturating_sub(counted);
                    self.send_result(conn, AuthStatus::Backoff, left, cfg.privd_retry)
                        .await?;
                }
                Verdict::Wrong { failed, revoked } => {
                    tracing::warn!(remote = %conn.remote_addr(), device = %device.id, failed, "wrong PIN");
                    if revoked {
                        tracing::warn!(device = %device.id, "device revoked after too many wrong PINs");
                        let _ = self
                            .send_result(conn, AuthStatus::Revoked, 0, Duration::ZERO)
                            .await;
                        return Err(LoginError::Revoked);
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
        Err(LoginError::Protocol(
            "too many PIN attempts on one connection",
        ))
    }

    /// Count, hash, verify with privd, record: one detached unit that owns the per-device
    /// guard. Cancelling the caller (deadline, disconnect) does not stop it, so a cut-off
    /// attempt still counts and a wrong one still counts toward revocation.
    async fn check_pin(
        &self,
        id: DeviceId,
        verifier: VerifierRecord,
        pin: Zeroizing<Vec<u8>>,
        guard: tokio::sync::OwnedMutexGuard<()>,
    ) -> Result<Verdict, LoginError> {
        let this = self.clone();
        let max = self.0.config.max_pin_failures;
        tokio::spawn(async move {
            let _guard = guard;
            let counted = this.reg(move |r| r.begin_pin_attempt(&id)).await?;
            // An earlier attempt at the limit was cut off before its verdict: it counted.
            let right = if counted > max {
                Some(false)
            } else {
                match Pin::from_bytes(&pin) {
                    // A malformed PIN is a failure without a hash.
                    Err(_) => Some(false),
                    Ok(p) => {
                        let input =
                            tokio::task::spawn_blocking(move || verifier_input(&verifier, &p))
                                .await
                                .map_err(|_| hx_crypto::Error::Protocol("PIN task failed"))?;
                        match input {
                            Err(()) => None,
                            Ok((expected, output)) => {
                                match this
                                    .0
                                    .privd
                                    .pepper_verify(LockoutPurpose::Pin, &expected, &*output)
                                    .await
                                {
                                    Ok(b) => Some(b),
                                    Err(e) if e.is_locked() => {
                                        // Nobody can be verified until an Admin resets the
                                        // purpose: make every device wait, so that reconnecting
                                        // does not keep counting attempts that are never checked
                                        // (F1, interim: the registry refund call is pending).
                                        let wait = match &e {
                                            PrivdError::Remote(r) if !r.retry_after.is_zero() => {
                                                r.retry_after
                                            }
                                            _ => LOCKED_WAIT,
                                        };
                                        this.set_not_before(&id, Some(wait));
                                        return Ok(Verdict::Locked);
                                    }
                                    Err(e) => {
                                        log_privd_failure(&e);
                                        None
                                    }
                                }
                            }
                        }
                    }
                }
            };
            let now_unix = this.0.clock.unix_secs();
            match right {
                None => {
                    // privd failed after the attempt was counted: the same wait as the retry
                    // hint given to the client, enforced here too.
                    this.set_not_before(&id, Some(this.0.config.privd_retry));
                    Ok(Verdict::Unavailable { counted })
                }
                Some(true) => {
                    this.reg(move |r| r.record_pin_success(&id, now_unix))
                        .await?;
                    this.set_not_before(&id, None);
                    Ok(Verdict::Right)
                }
                Some(false) => {
                    // The same rule as `revoke_if_failed`, through the authenticator so that the
                    // revocation is persisted, announced and its live sessions closed.
                    let revoked = if counted >= max {
                        this.0.devices.revoke_lockout(id).await?
                    } else {
                        false
                    };
                    // The wait starts here, before the guard is released: another connection
                    // that takes the lock next must see it.
                    this.set_not_before(&id, Some(backoff_after(counted)));
                    Ok(Verdict::Wrong {
                        failed: counted,
                        revoked,
                    })
                }
            }
        })
        .await
        .map_err(|_| hx_crypto::Error::Protocol("PIN task failed"))?
    }

    /// After the PIN was verified: re-read the registry (a revocation may have happened while
    /// hashing), authorize the connection with `features`, then tell the client. The order is
    /// protocol 13: a client that sees success can use every channel at once.
    pub async fn complete(
        &self,
        conn: &Connection,
        device: &DeviceRecord,
        features: hx_proto::version::Features,
    ) -> Result<DeviceRecord, LoginError> {
        let id = device.id;
        let fresh = match self.reg(move |r| r.get(&id)).await {
            Ok(Some(d)) if !d.is_revoked() => d,
            Ok(_) => return Err(LoginError::Revoked),
            Err(e) => return Err(e.into()),
        };
        conn.authorize(features)?;
        self.send_result(
            conn,
            AuthStatus::Ok,
            self.0.config.max_pin_failures,
            Duration::ZERO,
        )
        .await?;
        Ok(fresh)
    }

    /// Closes `conn` after a failed login, leaving the client a moment to read the verdict (a
    /// QUIC close discards stream data the peer has not read yet).
    pub async fn close_failed(conn: &Connection, reason: &str) {
        let _ = tokio::time::timeout(Duration::from_millis(500), conn.closed()).await;
        conn.close(CloseCode::Unauthorized, reason).await;
    }
}

fn verifier_input(
    verifier: &VerifierRecord,
    pin: &Pin,
) -> Result<([u8; 32], Zeroizing<[u8; 32]>), ()> {
    let output = verifier.derive(pin.as_bytes()).map_err(|_| ())?;
    Ok((*verifier.expected_mac(), output))
}

fn log_privd_failure(e: &PrivdError) {
    // The error carries no request content, so this never names a secret.
    tracing::warn!(error = %e, "PepperVerify failed");
}
