//! Server management from the app (protocol 1.3, `docs/protocol.md` 5.11, `docs/ipc.md` 5.6):
//! the overview, changing the PIN and the account password, restarting the desktop, turning
//! Docker off, resource limits and the agent update, for a PIN-authenticated session of an
//! active device.
//!
//! * **Nothing widens in privd's contract.** Every command used is class `A` or `R` and
//!   already allowed to the gateway role. Turning Docker **on** after setup is Admin-only
//!   (`EnableDocker` is class `S`), so it is answered `ADMIN_ONLY` without calling privd.
//! * **The current PIN is checked like a login**: the attempt is counted on the device's own
//!   failure counter (the registry's, the one a PIN login uses) *before* it is checked, a wrong
//!   one backs off, the 5th consecutive wrong one revokes the device through
//!   `Authenticator::revoke` (so the sessions close and the audit follows the login's path),
//!   and a verifier that cannot answer is refunded, never a wrong PIN.
//! * **Secrets** are copied into `Zeroizing` memory at once and the message is dropped. The
//!   new password and the current password go to privd through the dedicated lane's owned-secret
//!   path (wiped as soon as the frames are written). Nothing here logs a secret, and no status
//!   text carries a value that was sent.
//! * Every mutation is audited with the requesting device (`RecordEvent`), never a secret.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hx_crypto::auth::{PinVerdict, PinVerifier};
use hx_crypto::pin::{MAX_PIN_FAILURES, backoff_after};
use hx_crypto::{
    Authenticator, Clock, DeviceId, DeviceRegistry, PinParams, RevokeReason, RevokedBy,
};
use hx_ipc::privd::pb::{self as privd_pb, AuditEvent, ErrorCode, ErrorDetail};
use hx_ipc::text::sanitize_text;
use hx_proto::message::{password_problem, pin_problem};
use hx_proto::pb::{self, server_mgmt::Body};
use zeroize::Zeroizing;

use super::devices::DeviceService;
use super::privd_client::{PrivdClient, PrivdError, PrivdLane};
use super::verifier::{self, PrivdPinVerifier, VerifierError, VerifierStore};

/// Overview requests one device may make per minute (over all its connections).
pub const OVERVIEW_PER_MINUTE: usize = 30;
/// Every other request one device may make per minute.
pub const OTHER_PER_MINUTE: usize = 10;
/// Bound on the privd calls of the overview.
const OVERVIEW_TIMEOUT: Duration = Duration::from_secs(5);
/// Bound on the password change (the lane may be busy with a setup job).
const PASSWORD_TIMEOUT: Duration = Duration::from_secs(90);
/// The command an operator runs to turn Docker on after setup.
pub const DOCKER_ENABLE_COMMAND: &str = "sudo hx-agent docker enable";

/// Tunables; [`ServerMgmtSettings::new`] has the production values.
#[derive(Debug, Clone)]
pub struct ServerMgmtSettings {
    /// The desktop that is managed (`main`).
    pub desktop_id: String,
    /// Argon2id cost of the verifiers made here (the same as setup's).
    pub params: PinParams,
}

impl ServerMgmtSettings {
    /// Production settings for `desktop_id`.
    pub fn new(desktop_id: impl Into<String>) -> Self {
        Self {
            desktop_id: desktop_id.into(),
            params: PinParams::DEFAULT,
        }
    }
}

#[derive(Default)]
struct Limits {
    overview: VecDeque<Instant>,
    other: VecDeque<Instant>,
}

#[derive(Default)]
struct Mem {
    rate: HashMap<DeviceId, Limits>,
    /// Wait after a wrong current PIN / password, per device (not counted again while it runs).
    pin_not_before: HashMap<DeviceId, Instant>,
    password_not_before: HashMap<DeviceId, Instant>,
    update: Option<pb::ServerUpdateInfo>,
}

/// What [`ServerMgmtService::handle`] answers.
pub struct Answer {
    /// The response body.
    pub body: Body,
    /// The request was the device's 5th wrong PIN: send `body` first, then call
    /// [`ServerMgmtService::lockout`] (revoking closes the device's connections at once and
    /// would swallow the answer).
    pub lockout: bool,
}

/// The service. Create it once per gateway.
pub struct ServerMgmtService {
    privd: PrivdClient,
    lane: PrivdLane,
    verifiers: Arc<VerifierStore>,
    pin_verifier: Arc<PrivdPinVerifier>,
    registry: Arc<dyn DeviceRegistry>,
    auth: Authenticator,
    devices: Arc<DeviceService>,
    clock: Arc<dyn Clock>,
    settings: ServerMgmtSettings,
    started: Instant,
    mem: Mutex<Mem>,
    /// Serializes the secret-checking requests (PIN and password), so the counting and the
    /// check of one device cannot interleave.
    secret_lock: tokio::sync::Mutex<()>,
}

fn result(status: pb::ServerStatus) -> pb::ServerResult {
    pb::ServerResult {
        status: status as i32,
        ..Default::default()
    }
}

fn with_message(status: pb::ServerStatus, message: &str) -> pb::ServerResult {
    pb::ServerResult {
        message: sanitize_text(message, 256),
        ..result(status)
    }
}

fn retry(status: pb::ServerStatus, wait: Duration) -> pb::ServerResult {
    pb::ServerResult {
        retry_after_s: u32::try_from(wait.as_secs().max(1)).unwrap_or(u32::MAX),
        ..result(status)
    }
}

/// True for `^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(-(alpha|beta|rc)\.[0-9]{1,4})?$` (ipc.md 6.12).
pub fn version_syntax_ok(v: &str) -> bool {
    let num = |s: &str| (1..=4).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit());
    let (core, pre) = match v.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (v, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 || !parts.iter().all(|p| num(p)) {
        return false;
    }
    match pre {
        None => true,
        Some(p) => match p.split_once('.') {
            Some((tag, n)) => matches!(tag, "alpha" | "beta" | "rc") && num(n),
            None => false,
        },
    }
}

/// privd's error as the app's status (docs/ipc.md 5.6). `what` says which command, because
/// `PERMISSION_DENIED` means "wrong current password" for `SetUserPassword` and "refused" for
/// `ApplyUpdate`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum What {
    General,
    Password,
    Update,
}

fn map_privd(e: &PrivdError, what: What) -> pb::ServerResult {
    use pb::ServerStatus as S;
    match e {
        PrivdError::Remote(r) => {
            let wait = r.retry_after.max(Duration::from_secs(1));
            match (r.code, r.detail) {
                (ErrorCode::InvalidArgument, _) => {
                    with_message(S::InvalidArgument, "refused by the server")
                }
                (ErrorCode::PermissionDenied, _) if what == What::Password => {
                    with_message(S::WrongPassword, "the current password is wrong")
                }
                (ErrorCode::PermissionDenied, _) if what == What::Update => {
                    with_message(S::UpdateRefused, "that release cannot be applied now")
                }
                (ErrorCode::PermissionDenied, _) => {
                    with_message(S::AdminOnly, "an administrator must do this")
                }
                (ErrorCode::ResourceExhausted, ErrorDetail::Locked) => retry(S::Locked, wait),
                (ErrorCode::ResourceExhausted, _) => retry(S::RateLimited, wait),
                (ErrorCode::FailedPrecondition, ErrorDetail::DesktopNotReady) => {
                    result(S::DesktopNotReady)
                }
                (ErrorCode::FailedPrecondition, ErrorDetail::SetupWindowClosed) => {
                    retry(S::Unavailable, wait)
                }
                (ErrorCode::FailedPrecondition, _) if what == What::Update => {
                    with_message(S::UpdateRefused, "that release cannot be applied now")
                }
                (ErrorCode::Unavailable, _) | (ErrorCode::DeadlineExceeded, _) => {
                    retry(S::Unavailable, wait)
                }
                (ErrorCode::Unimplemented, _) => result(S::Unsupported),
                _ => result(S::Failed),
            }
        }
        PrivdError::Unavailable(_) | PrivdError::Timeout => {
            retry(S::Unavailable, Duration::from_secs(2))
        }
        _ => result(S::Failed),
    }
}

fn map_verifier(e: &VerifierError) -> pb::ServerResult {
    use pb::ServerStatus as S;
    match e {
        VerifierError::Privd(p) => map_privd(p, What::General),
        VerifierError::InvalidSecret => {
            with_message(S::InvalidArgument, "the new secret is not acceptable")
        }
        _ => result(S::Failed),
    }
}

fn desktop_state(d: &privd_pb::Desktop) -> pb::ServerDesktopState {
    use privd_pb::DesktopState as D;
    match D::try_from(d.state).unwrap_or(D::Unspecified) {
        D::Creating => pb::ServerDesktopState::Creating,
        D::Ready => pb::ServerDesktopState::Ready,
        D::Failed => pb::ServerDesktopState::Failed,
        D::Stopped => pb::ServerDesktopState::Stopped,
        D::Running => pb::ServerDesktopState::Running,
        D::Starting => pb::ServerDesktopState::Starting,
        D::Unspecified => pb::ServerDesktopState::Unknown,
    }
}

fn attention(list: &[i32]) -> Vec<i32> {
    // privd's `NeedsAttention` and the wire's `ServerAttention` share their numbering.
    list.iter()
        .filter(|a| (1..=7).contains(*a))
        .take(hx_proto::channel::MAX_SERVER_ATTENTION)
        .copied()
        .collect()
}

fn update_info(r: &privd_pb::CheckUpdateResult, checked_unix: u64) -> pb::ServerUpdateInfo {
    let channel = match privd_pb::UpdateChannel::try_from(r.channel) {
        Ok(privd_pb::UpdateChannel::Stable) => pb::ServerUpdateChannel::Stable,
        Ok(privd_pb::UpdateChannel::Beta) => pb::ServerUpdateChannel::Beta,
        _ => pb::ServerUpdateChannel::Unspecified,
    };
    let rb = r.rolled_back.clone().unwrap_or_default();
    pb::ServerUpdateInfo {
        current: sanitize_text(&r.current, 32),
        available: sanitize_text(r.available.as_deref().unwrap_or(""), 32),
        channel: channel as i32,
        verified: r.verified,
        rolled_back_version: sanitize_text(&rb.version, 32),
        rolled_back_reason: sanitize_text(&rb.reason, 256),
        checked_unix,
    }
}

impl ServerMgmtService {
    /// Builds the service.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        privd: PrivdClient,
        verifiers: Arc<VerifierStore>,
        pin_verifier: Arc<PrivdPinVerifier>,
        registry: Arc<dyn DeviceRegistry>,
        auth: Authenticator,
        devices: Arc<DeviceService>,
        clock: Arc<dyn Clock>,
        settings: ServerMgmtSettings,
    ) -> Arc<Self> {
        let started = clock.now();
        Arc::new(Self {
            lane: privd.dedicated(),
            privd,
            verifiers,
            pin_verifier,
            registry,
            auth,
            devices,
            clock,
            settings,
            started,
            mem: Mutex::new(Mem::default()),
            secret_lock: tokio::sync::Mutex::new(()),
        })
    }

    fn mem(&self) -> std::sync::MutexGuard<'_, Mem> {
        self.mem.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Counts one request of `device` against its per-minute limit. `Err` carries the wait.
    fn allow(&self, device: DeviceId, overview: bool) -> Result<(), Duration> {
        let now = self.clock.now();
        let mut m = self.mem();
        let l = m.rate.entry(device).or_default();
        let (q, max) = if overview {
            (&mut l.overview, OVERVIEW_PER_MINUTE)
        } else {
            (&mut l.other, OTHER_PER_MINUTE)
        };
        while q
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= Duration::from_secs(60))
        {
            q.pop_front();
        }
        if q.len() >= max {
            let wait = q
                .front()
                .map(|t| Duration::from_secs(60).saturating_sub(now.saturating_duration_since(*t)))
                .unwrap_or(Duration::from_secs(60));
            return Err(wait);
        }
        q.push_back(now);
        Ok(())
    }

    /// Revokes `device` after its 5th wrong PIN, the consequence a wrong PIN at login has.
    pub async fn lockout(&self, device: DeviceId) {
        if let Err(e) = self
            .auth
            .revoke(
                &device,
                RevokeReason::TooManyPinFailures,
                RevokedBy::Lockout,
            )
            .await
        {
            tracing::error!(error = %e, "revoking after the lockout failed");
        }
    }

    /// Handles one request of `device`. `session_active` says whether some client holds the
    /// desktop (the session asks its manager).
    pub async fn handle(&self, device: DeviceId, body: Body, session_active: bool) -> Answer {
        let overview = matches!(body, Body::GetOverview(_));
        if let Err(wait) = self.allow(device, overview) {
            return Answer {
                body: Body::Result(retry(pb::ServerStatus::RateLimited, wait)),
                lockout: false,
            };
        }
        if let Body::ChangePin(p) = body {
            // Copied into zeroizing memory; the message (and its prost buffers) is dropped.
            let current = Zeroizing::new(p.current.to_vec());
            let new = Zeroizing::new(p.new.to_vec());
            drop(p);
            let (r, lockout) = self.change_pin(device, current, new).await;
            return Answer {
                body: Body::Result(r),
                lockout,
            };
        }
        Answer {
            body: self.handle_other(device, body, session_active).await,
            lockout: false,
        }
    }

    async fn handle_other(&self, device: DeviceId, body: Body, session_active: bool) -> Body {
        match body {
            Body::GetOverview(_) => Body::Overview(self.overview(session_active).await),
            Body::ChangePin(_) => Body::Result(result(pb::ServerStatus::Failed)),
            Body::ChangePassword(p) => {
                let current = Zeroizing::new(p.current.to_vec());
                let new = Zeroizing::new(p.new.to_vec());
                drop(p);
                Body::Result(self.change_password(device, current, new).await)
            }
            Body::RestartDesktop(r) => Body::Result(self.restart(device, r.force).await),
            Body::SetDocker(d) => Body::Result(self.set_docker(device, d.enable).await),
            Body::SetLimits(l) => Body::Result(self.set_limits(device, l.limits).await),
            Body::CheckUpdate(_) => Body::Result(self.check_update().await),
            Body::ApplyUpdate(a) => Body::Result(self.apply_update(device, &a.version).await),
            // Server-only bodies never get here (the session refuses them by direction).
            Body::Overview(_) | Body::Result(_) => Body::Result(result(pb::ServerStatus::Failed)),
        }
    }

    // ------------------------------------------------------------------ overview

    async fn overview(&self, session_active: bool) -> pb::ServerOverview {
        let id = &self.settings.desktop_id;
        let (host, desk) = tokio::join!(
            tokio::time::timeout(OVERVIEW_TIMEOUT, self.privd.get_host_info()),
            tokio::time::timeout(OVERVIEW_TIMEOUT, self.privd.get_desktop(id)),
        );
        let (host, host_attention, privd_version) = match host {
            Ok(Ok(h)) => {
                let pool = h.pool.clone().unwrap_or_default();
                let facts = pb::SetupHostFacts {
                    cpu_count: h.cpu_count,
                    memory_total_mib: h.memory_total_mib,
                    pool_total_gib: pool.total_gib,
                    pool_free_gib: pool.free_gib,
                    docker_supported: h.incus_version.as_deref().is_some_and(|v| {
                        crate::install::stages::incus::at_least(
                            v,
                            crate::install::stages::incus::DOCKER_MIN_VERSION,
                        )
                    }),
                    os: sanitize_text(format!("{} {}", h.os_id, h.os_version).trim(), 64),
                    arch: sanitize_text(&h.arch, 16),
                };
                (Some(facts), attention(&h.needs_attention), h.privd_version)
            }
            _ => (None, Vec::new(), String::new()),
        };
        let desktop = match desk {
            Ok(Ok(Some(d))) => Some(pb::ServerDesktop {
                state: desktop_state(&d) as i32,
                username: sanitize_text(&d.username, 32),
                distro: d.distro,
                preset: d.preset,
                limits: d.limits.map(|l| pb::SetupLimits {
                    cpu: l.cpu,
                    memory_mib: l.memory_mib,
                    disk_gib: l.disk_gib,
                }),
                docker: match privd_pb::DockerState::try_from(d.docker) {
                    Ok(privd_pb::DockerState::Off) => pb::ServerDockerState::Off,
                    Ok(privd_pb::DockerState::On) => pb::ServerDockerState::On,
                    Ok(privd_pb::DockerState::Degraded) => pb::ServerDockerState::Degraded,
                    _ => pb::ServerDockerState::Unspecified,
                } as i32,
                needs_attention: attention(&d.needs_attention),
                created_unix: d.created_unix_s,
            }),
            Ok(Ok(None)) => Some(pb::ServerDesktop {
                state: pb::ServerDesktopState::None as i32,
                ..Default::default()
            }),
            _ => Some(pb::ServerDesktop {
                state: pb::ServerDesktopState::Unknown as i32,
                ..Default::default()
            }),
        };
        pb::ServerOverview {
            agent_version: sanitize_text(env!("CARGO_PKG_VERSION"), 64),
            privd_version: sanitize_text(&privd_version, 64),
            server_time_unix: self.clock.unix_secs(),
            agent_uptime_s: self
                .clock
                .now()
                .saturating_duration_since(self.started)
                .as_secs(),
            update: self.mem().update.clone(),
            desktop,
            host,
            host_attention,
            session_active,
        }
    }

    // ------------------------------------------------------------------ secrets

    /// Waits left after a wrong secret of `device`, if any.
    fn backoff_left(&self, device: &DeviceId, pin: bool) -> Option<Duration> {
        let now = self.clock.now();
        let mut m = self.mem();
        let map = if pin {
            &mut m.pin_not_before
        } else {
            &mut m.password_not_before
        };
        match map.get(device) {
            Some(t) if *t > now => Some(*t - now),
            Some(_) => {
                map.remove(device);
                None
            }
            None => None,
        }
    }

    fn set_backoff(&self, device: DeviceId, pin: bool, wait: Duration) {
        let until = self.clock.now() + wait;
        let mut m = self.mem();
        if pin {
            m.pin_not_before.insert(device, until);
        } else {
            m.password_not_before.insert(device, until);
        }
    }

    async fn blocking_registry<R: Send + 'static>(
        &self,
        f: impl FnOnce(&dyn DeviceRegistry) -> hx_crypto::Result<R> + Send + 'static,
    ) -> hx_crypto::Result<R> {
        let r = self.registry.clone();
        tokio::task::spawn_blocking(move || f(&*r))
            .await
            .map_err(|_| hx_crypto::Error::Protocol("registry task failed"))?
    }

    async fn change_pin(
        &self,
        device: DeviceId,
        current: Zeroizing<Vec<u8>>,
        new: Zeroizing<Vec<u8>>,
    ) -> (pb::ServerResult, bool) {
        let mut lockout = false;
        let r = self
            .change_pin_inner(device, current, new, &mut lockout)
            .await;
        (r, lockout)
    }

    async fn change_pin_inner(
        &self,
        device: DeviceId,
        current: Zeroizing<Vec<u8>>,
        new: Zeroizing<Vec<u8>>,
        lockout: &mut bool,
    ) -> pb::ServerResult {
        use pb::ServerStatus as S;
        if pin_problem(&current).is_some() || pin_problem(&new).is_some() {
            return with_message(S::InvalidArgument, "a PIN must be 6 to 16 digits");
        }
        let _one = self.secret_lock.lock().await;
        if let Some(wait) = self.backoff_left(&device, true) {
            return retry(S::Backoff, wait);
        }
        if self.verifiers.pin_for(&device).is_none() {
            return result(S::Failed);
        }
        // Counted before it is checked, on the counter a login uses.
        let failures = match self
            .blocking_registry(move |r| r.begin_pin_attempt(&device))
            .await
        {
            Ok(n) => n,
            Err(e) => {
                tracing::error!(error = %e, "counting a PIN attempt failed");
                return result(S::Failed);
            }
        };
        match self.pin_verifier.verify(&device, current).await {
            PinVerdict::Right => {
                let now = self.clock.unix_secs();
                if let Err(e) = self
                    .blocking_registry(move |r| r.record_pin_success(&device, now))
                    .await
                {
                    tracing::error!(error = %e, "resetting the PIN counter failed");
                }
            }
            PinVerdict::Wrong => {
                if failures >= MAX_PIN_FAILURES {
                    // The same consequence as the 5th wrong PIN at login, applied by the
                    // caller after the answer is on its way.
                    *lockout = true;
                    return pb::ServerResult {
                        attempts_left: 0,
                        ..with_message(S::WrongPin, "too many wrong PINs: this device was revoked")
                    };
                }
                let wait = backoff_after(failures);
                self.set_backoff(device, true, wait);
                return pb::ServerResult {
                    attempts_left: MAX_PIN_FAILURES - failures,
                    retry_after_s: u32::try_from(wait.as_secs()).unwrap_or(u32::MAX),
                    ..result(S::WrongPin)
                };
            }
            PinVerdict::Unavailable => {
                let _ = self
                    .blocking_registry(move |r| r.refund_pin_attempt(&device))
                    .await;
                return retry(S::Unavailable, Duration::from_secs(2));
            }
            PinVerdict::Locked { retry_after } => {
                let _ = self
                    .blocking_registry(move |r| r.refund_pin_attempt(&device))
                    .await;
                return retry(S::Locked, retry_after.unwrap_or(Duration::from_secs(60)));
            }
        }
        // The current PIN was right: enrol the new one (Argon2id here, `PepperEnrol(PIN)`).
        let record = match verifier::enrol(
            &self.privd,
            privd_pb::LockoutPurpose::Pin,
            &new,
            self.settings.params,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => return map_verifier(&e),
        };
        drop(new);
        if let Err(e) = self.verifiers.set_pin(None, record) {
            tracing::error!(error = %e, "storing the new PIN failed");
            return result(S::Failed);
        }
        self.devices.bump_version();
        self.devices.audit(AuditEvent::PinChanged, device, "app");
        result(S::Ok)
    }

    async fn change_password(
        &self,
        device: DeviceId,
        current: Zeroizing<Vec<u8>>,
        new: Zeroizing<Vec<u8>>,
    ) -> pb::ServerResult {
        use pb::ServerStatus as S;
        if password_problem(&current).is_some() || password_problem(&new).is_some() {
            return with_message(S::InvalidArgument, "a password must be 1 to 511 bytes");
        }
        let _one = self.secret_lock.lock().await;
        if let Some(wait) = self.backoff_left(&device, false) {
            return retry(S::Backoff, wait);
        }
        // privd checks `CURRENT_PASSWORD` against the desktop user's hash (charged to its
        // PASSWORD budget) and sets the new one, **before** anything is enrolled: a typo in the
        // current password must not use up `PepperEnrol`'s allowance of 5 a day. Both secrets are
        // owned by the call and wiped as soon as their frames are written; the new one is
        // copied once for the verifier.
        let for_verifier = Zeroizing::new(new.to_vec());
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let call = self.lane.call_streaming(
            privd_pb::request::Command::SetUserPassword(privd_pb::SetUserPasswordRequest {
                desktop_id: self.settings.desktop_id.clone(),
            }),
            vec![
                (privd_pb::SecretKind::UserPassword, new),
                (privd_pb::SecretKind::CurrentPassword, current),
            ],
            None,
            tx,
        );
        match tokio::time::timeout(PASSWORD_TIMEOUT, call.wait()).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                let r = map_privd(&e, What::Password);
                if r.status == S::WrongPassword as i32 {
                    // privd charged the failure to its own budget; this wait keeps one device
                    // from hammering it.
                    self.set_backoff(device, false, Duration::from_secs(2));
                }
                return r;
            }
            Err(_) => return retry(S::Unavailable, Duration::from_secs(2)),
        }
        self.devices
            .audit(AuditEvent::PasswordChanged, device, "app");
        // The password is changed. Refresh the verifier (Argon2id here, `PepperEnrol(PASSWORD)`);
        // if that cannot be done now the change still stands: the answer is OK with a warning,
        // because a stale verifier only affects reinstating a locked-out device by password.
        let stale = with_message(
            S::Ok,
            "The password was changed, but the server could not refresh its recovery check yet: run `sudo hx-agent desktop password --verifier-only`.",
        );
        let record = match verifier::enrol(
            &self.privd,
            privd_pb::LockoutPurpose::Password,
            &for_verifier,
            self.settings.params,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "refreshing the password verifier failed");
                return stale;
            }
        };
        drop(for_verifier);
        if let Err(e) = self.verifiers.set_password(record) {
            tracing::error!(error = %e, "storing the new password verifier failed");
            return stale;
        }
        self.devices.bump_version();
        self.devices
            .audit(AuditEvent::PasswordVerifierChanged, device, "app");
        result(S::Ok)
    }

    // ------------------------------------------------------------------ desktop and agent

    async fn restart(&self, device: DeviceId, force: bool) -> pb::ServerResult {
        match self
            .privd
            .restart_desktop(&self.settings.desktop_id, force)
            .await
        {
            Ok(_) => {
                self.devices
                    .audit(AuditEvent::DesktopRestarted, device, "app");
                result(pb::ServerStatus::Ok)
            }
            Err(e) => map_privd(&e, What::General),
        }
    }

    async fn set_docker(&self, device: DeviceId, enable: bool) -> pb::ServerResult {
        if enable {
            // `EnableDocker` is class S: Admin only once setup is over (docs/ipc.md 5.1).
            return with_message(pb::ServerStatus::AdminOnly, DOCKER_ENABLE_COMMAND);
        }
        match self.privd.disable_docker(&self.settings.desktop_id).await {
            Ok(_) => {
                self.devices
                    .audit(AuditEvent::DockerDisabled, device, "app");
                result(pb::ServerStatus::Ok)
            }
            Err(e) => map_privd(&e, What::General),
        }
    }

    async fn set_limits(
        &self,
        device: DeviceId,
        limits: Option<pb::SetupLimits>,
    ) -> pb::ServerResult {
        use pb::ServerStatus as S;
        let Some(l) = limits.filter(|l| l.cpu > 0 && l.memory_mib > 0 && l.disk_gib > 0) else {
            return with_message(S::InvalidArgument, "every limit must be set");
        };
        match self
            .privd
            .set_limits(
                &self.settings.desktop_id,
                privd_pb::Limits {
                    cpu: l.cpu,
                    memory_mib: l.memory_mib,
                    disk_gib: l.disk_gib,
                },
            )
            .await
        {
            Ok(r) => {
                self.devices.audit(AuditEvent::LimitsChanged, device, "app");
                pb::ServerResult {
                    restart_required: r.restart_required,
                    ..result(S::Ok)
                }
            }
            Err(e) => map_privd(&e, What::General),
        }
    }

    async fn check_update(&self) -> pb::ServerResult {
        match self.privd.check_update().await {
            Ok(r) => {
                let info = update_info(&r, self.clock.unix_secs());
                self.mem().update = Some(info.clone());
                pb::ServerResult {
                    update: Some(info),
                    ..result(pb::ServerStatus::Ok)
                }
            }
            Err(e) => map_privd(&e, What::Update),
        }
    }

    async fn apply_update(&self, device: DeviceId, version: &str) -> pb::ServerResult {
        use pb::ServerStatus as S;
        if !version_syntax_ok(version) {
            return with_message(S::InvalidArgument, "not a release version");
        }
        match self.privd.apply_update(version).await {
            Ok(_) => {
                self.devices
                    .audit(AuditEvent::UpdateApplied, device, version);
                // The cached status is stale now.
                self.mem().update = None;
                pb::ServerResult {
                    version: sanitize_text(version, 32),
                    ..result(S::Ok)
                }
            }
            Err(e) => map_privd(&e, What::Update),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_syntax_follows_the_update_rule() {
        for ok in [
            "0.1.0",
            "1.2.3",
            "9999.9999.9999",
            "1.0.0-rc.1",
            "1.0.0-alpha.12",
            "2.0.0-beta.0",
        ] {
            assert!(version_syntax_ok(ok), "{ok}");
        }
        for bad in [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "01234.1.1",
            "1.2.x",
            "v1.2.3",
            "1.2.3-",
            "1.2.3-rc",
            "1.2.3-gamma.1",
            "1.2.3-rc.12345",
            "1.2.3 ",
            "../1.2.3",
            "1.2.3/..",
            "1.2.3-rc.1-x",
        ] {
            assert!(!version_syntax_ok(bad), "{bad:?}");
        }
    }

    #[test]
    fn privd_errors_map_as_documented() {
        use pb::ServerStatus as S;
        let remote = |code, detail| {
            PrivdError::Remote(crate::gateway::privd_client::RemoteError {
                code,
                detail,
                message: "m".into(),
                retryable: false,
                retry_after: Duration::ZERO,
                stage: None,
            })
        };
        let st = |e: &PrivdError, w| map_privd(e, w).status;
        let denied = remote(ErrorCode::PermissionDenied, ErrorDetail::Unspecified);
        assert_eq!(st(&denied, What::Password), S::WrongPassword as i32);
        assert_eq!(st(&denied, What::Update), S::UpdateRefused as i32);
        assert_eq!(st(&denied, What::General), S::AdminOnly as i32);
        let locked = remote(ErrorCode::ResourceExhausted, ErrorDetail::Locked);
        assert_eq!(st(&locked, What::Password), S::Locked as i32);
        let limited = map_privd(
            &remote(ErrorCode::ResourceExhausted, ErrorDetail::Unspecified),
            What::General,
        );
        assert_eq!(limited.status, S::RateLimited as i32);
        assert!(limited.retry_after_s >= 1);
        assert_eq!(
            st(
                &remote(ErrorCode::FailedPrecondition, ErrorDetail::DesktopNotReady),
                What::General
            ),
            S::DesktopNotReady as i32
        );
        assert_eq!(
            st(&PrivdError::Timeout, What::General),
            S::Unavailable as i32
        );
        assert_eq!(
            st(
                &remote(ErrorCode::Unimplemented, ErrorDetail::Unspecified),
                What::General
            ),
            S::Unsupported as i32
        );
        assert_eq!(
            st(
                &remote(ErrorCode::Internal, ErrorDetail::Unspecified),
                What::General
            ),
            S::Failed as i32
        );
        // privd's text is never forwarded for the statuses that could echo it.
        assert!(
            !map_privd(
                &remote(ErrorCode::InvalidArgument, ErrorDetail::Unspecified),
                What::General
            )
            .message
            .contains('m')
        );
    }
}
