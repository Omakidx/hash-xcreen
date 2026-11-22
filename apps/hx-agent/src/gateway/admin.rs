//! The admin socket (`docs/ipc.md` section 9): the CLI's and the installer's door into the
//! gateway's registry and runtime state.
//!
//! * **Root only.** On accept the peer's `SO_PEERCRED` uid is checked with
//!   [`hx_ipc::peer::admin_socket_allows`] (uid 0); any other peer is closed without a reply.
//!   The socket is also created 0600, and systemd normally creates it (socket activation,
//!   `LISTEN_FDS`), root-owned, in `/run/hx`.
//! * Same framing, `Hello`, error model, limits and `recvmsg` rule as the privd socket:
//!   frames are read through [`super::ipc_io::read_frame`], a violation closes the connection,
//!   one request is in flight per connection, a secret frame follows its request.
//! * **Outside the pre-authentication limits** of the public listener: a separate accept loop,
//!   so it is a valid update health probe (`Status`, ipc.md 6.12).
//! * Every reply is sanitized text or numbers; device names are cleaned again before they leave.
//!
//! The pairing token of decision 14 arrives as a kind-2 secret frame (never an environment
//! variable or file): `CreatePairingToken` reads it, validates it, installs it with
//! `PairingWindow::install_token` and wipes it. `CreatePairingCode` issues a short code
//! instead, the interactive install's alternative.

use std::collections::HashSet;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use hx_crypto::{Authenticator, PairingToken};
use hx_ipc::ReadError;
use hx_ipc::admin::{self, Incoming, pb};
use hx_ipc::frame::Decoder;
use hx_ipc::peer::{self, peer_credentials};
use hx_ipc::privd::{self, PrivdPolicy, Side, pb as privd_pb};
use hx_ipc::text::sanitize_text;
use hx_proto::channel::CloseCode;
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, watch};

use super::devices::{DeviceService, device_info};
use super::ipc_io::read_frame;
use super::live::LiveSessions;
use super::session::SessionManager;
use super::setup::SetupCoordinator;
use super::util::{device_id, now_unix};
use super::verifier::{VerifierRecord, VerifierStore};
use hx_ipc::privd::pb::AuditEvent;

/// Who may use the admin socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminPolicy {
    /// uid 0 only (`hx_ipc::peer::admin_socket_allows`): the only policy the binary uses.
    RootOnly,
    /// One uid, for tests that cannot run as root. Not reachable from a configuration file.
    #[doc(hidden)]
    OnlyUid(u32),
}

impl AdminPolicy {
    fn allows(self, uid: u32) -> bool {
        match self {
            Self::RootOnly => peer::admin_socket_allows(uid),
            Self::OnlyUid(u) => uid == u,
        }
    }
}

/// Connections served at once (the socket is root's, so this only bounds accidents).
const MAX_CONNECTIONS: usize = 4;
/// Devices listed at most (the reply must fit one 64 KiB frame).
const MAX_LISTED: usize = 256;
/// Request ids remembered per connection before it is closed (a repeat is refused).
const MAX_IDS: usize = 4096;

/// What the admin commands act on.
pub struct AdminState {
    /// Device operations.
    pub devices: Arc<DeviceService>,
    /// The verifiers.
    pub verifiers: Arc<VerifierStore>,
    /// The authenticator (pairing window).
    pub auth: Authenticator,
    /// The session manager (link state).
    pub sessions: Arc<SessionManager>,
    /// Live sessions.
    pub live: Arc<LiveSessions>,
    /// Lowest Argon2id memory accepted in a verifier.
    pub min_argon_memory_kib: u32,
    /// Lifetime of pairing credentials, in seconds (the window's configured TTL).
    pub pairing_ttl_s: u64,
    /// The server listens (for `Status`).
    pub listening: bool,
    /// The setup coordinator: the window mirror (persisted), the binding and the job.
    pub setup: SetupCoordinator,
}

impl AdminState {
    /// Builds the state.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        devices: Arc<DeviceService>,
        verifiers: Arc<VerifierStore>,
        auth: Authenticator,
        sessions: Arc<SessionManager>,
        live: Arc<LiveSessions>,
        min_argon_memory_kib: u32,
        pairing_ttl_s: u64,
        setup: SetupCoordinator,
    ) -> Arc<Self> {
        Arc::new(Self {
            devices,
            verifiers,
            auth,
            sessions,
            live,
            min_argon_memory_kib,
            pairing_ttl_s,
            listening: true,
            setup,
        })
    }
}

/// Creates the admin socket at `path` (used when systemd does not hand one over): mode 0600,
/// a stale socket file of ours is replaced.
pub fn bind(path: &Path) -> std::io::Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => {
            return Err(std::io::Error::other(
                "the admin socket path exists and is not a socket",
            ));
        }
        Err(_) => {}
    }
    let listener = std::os::unix::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    UnixListener::from_std(listener)
}

trait IsSocket {
    fn is_socket(&self) -> bool;
}
impl IsSocket for std::fs::FileType {
    fn is_socket(&self) -> bool {
        std::os::unix::fs::FileTypeExt::is_socket(self)
    }
}

/// Accepts admin connections until `shutdown` changes.
pub async fn serve(
    listener: UnixListener,
    policy: AdminPolicy,
    state: Arc<AdminState>,
    mut shutdown: watch::Receiver<bool>,
) {
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let stream = tokio::select! {
            _ = shutdown.changed() => return,
            r = listener.accept() => match r {
                Ok((s, _)) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "admin accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let cred = match peer_credentials(&stream) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if !policy.allows(cred.uid) {
            // No reply: the peer learns nothing (ipc.md section 3 applies the same rule).
            tracing::warn!(uid = cred.uid, "admin socket: refused a non-root peer");
            continue;
        }
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            tracing::warn!("admin socket: too many connections");
            continue;
        };
        let state = state.clone();
        let mut sd = shutdown.clone();
        tokio::spawn(async move {
            let _permit = permit;
            tokio::select! {
                _ = sd.changed() => {}
                r = connection(stream, state) => {
                    if let Err(why) = r {
                        tracing::warn!(reason = %why, "admin connection closed");
                    }
                }
            }
        });
    }
}

fn error(code: privd_pb::ErrorCode, message: &str) -> privd_pb::Error {
    privd_pb::Error {
        code: code as i32,
        detail: 0,
        message: sanitize_text(message, privd::MAX_ERROR_MESSAGE_LEN),
        retryable: false,
        retry_after_ms: 0,
        stage: None,
    }
}

async fn write(stream: &mut UnixStream, frame: &pb::Frame) -> Result<(), String> {
    let bytes = admin::encode_message(frame, Side::Client).map_err(|e| e.to_string())?;
    tokio::time::timeout(privd::RESPONSE_WRITE_TIMEOUT, stream.write_all(&bytes))
        .await
        .map_err(|_| "the peer does not read".to_string())?
        .map_err(|e| e.kind().to_string())
}

async fn next(
    stream: &UnixStream,
    decoder: &mut Decoder<PrivdPolicy>,
    wait: Duration,
) -> Result<Option<Incoming>, String> {
    let raw = match tokio::time::timeout(wait, read_frame(stream, decoder)).await {
        Err(_) => return Err("timed out".into()),
        Ok(Ok(Some(raw))) => raw,
        Ok(Ok(None)) => return Ok(None),
        Ok(Err(ReadError::Io(e))) => return Err(format!("io: {}", e.kind())),
        Ok(Err(violation)) => return Err(format!("violation: {violation}")),
    };
    admin::decode(raw, Side::Server)
        .map(Some)
        .map_err(|e| format!("violation: {e}"))
}

async fn connection(mut stream: UnixStream, state: Arc<AdminState>) -> Result<(), String> {
    let mut decoder = Decoder::new(PrivdPolicy::new(Side::Server));
    // Hello within 5 s.
    match next(&stream, &mut decoder, privd::HELLO_TIMEOUT).await? {
        Some(Incoming::Message(pb::Frame {
            frame: Some(pb::frame::Frame::Hello(h)),
        })) => {
            if h.major != privd::VERSION_MAJOR {
                return Err("incompatible major version".into());
            }
        }
        _ => return Err("expected Hello".into()),
    }
    write(
        &mut stream,
        &pb::Frame {
            frame: Some(pb::frame::Frame::HelloAck(pb::HelloAck {
                major: privd::VERSION_MAJOR,
                minor: privd::VERSION_MINOR,
                gatewayd_version: env!("CARGO_PKG_VERSION").into(),
            })),
        },
    )
    .await?;

    let mut seen: HashSet<u64> = HashSet::new();
    loop {
        let Some(frame) = next(&stream, &mut decoder, privd::IDLE_TIMEOUT).await? else {
            return Ok(());
        };
        let req = match frame {
            Incoming::Message(pb::Frame { frame: Some(f) }) => match f {
                pb::frame::Frame::Request(r) => r,
                pb::frame::Frame::Ping(p) => {
                    write(
                        &mut stream,
                        &pb::Frame {
                            frame: Some(pb::frame::Frame::Pong(privd_pb::Pong { nonce: p.nonce })),
                        },
                    )
                    .await?;
                    continue;
                }
                // Nothing runs concurrently with the next request, so there is nothing to cancel.
                pb::frame::Frame::Cancel(_) | pb::frame::Frame::Pong(_) => continue,
                _ => return Err("unexpected frame".into()),
            },
            _ => return Err("unexpected frame".into()),
        };
        if seen.len() >= MAX_IDS {
            return Err("too many requests on one connection".into());
        }
        let id = req.request_id;
        let fresh = seen.insert(id);
        // The secret frames follow the request at once (ipc.md 5.2).
        let mut secrets = Vec::new();
        for slot in &req.secret_slots {
            match next(&stream, &mut decoder, privd::BODY_TIMEOUT).await? {
                Some(Incoming::Secret(sf))
                    if sf.request_id == id && u32::from(sf.slot) == slot.slot =>
                {
                    admin::check_secret_against_slot(slot, &sf.secret)
                        .map_err(|e| format!("violation: {e}"))?;
                    secrets.push(sf.secret);
                }
                _ => return Err("missing or wrong secret frame".into()),
            }
        }
        let result = if fresh {
            match &req.command {
                Some(cmd) => {
                    tracing::debug!(command = admin::command_name(cmd), "admin request");
                    handle(&state, cmd, secrets).await
                }
                None => Err(error(privd_pb::ErrorCode::InvalidArgument, "no command")),
            }
        } else {
            Err(error(
                privd_pb::ErrorCode::InvalidArgument,
                "request_id was used before",
            ))
        };
        let result = match result {
            Ok(r) => r,
            Err(e) => pb::response::Result::Error(e),
        };
        let mut frame = pb::Frame {
            frame: Some(pb::frame::Frame::Response(pb::Response {
                request_id: id,
                result: Some(result),
            })),
        };
        let sent = write(&mut stream, &frame).await;
        // The reply's text of a pairing code is a protobuf `String`: wipe it once written.
        if let pb::Frame {
            frame:
                Some(pb::frame::Frame::Response(pb::Response {
                    result: Some(r), ..
                })),
        } = &mut frame
        {
            scrub(r);
        }
        sent?;
    }
}

/// Best-effort wiping of the secret text a reply carries (the pairing code of
/// `CreatePairingCode`). The protobuf type is a plain `String`, so a copy is made when the
/// frame is encoded; this wipes the one that we own.
fn scrub(r: &mut pb::response::Result) {
    use zeroize::Zeroize;
    if let pb::response::Result::CreatePairingCode(c) = r {
        c.code.zeroize();
    }
}

type Reply = Result<pb::response::Result, privd_pb::Error>;

fn internal(what: &str, e: impl std::fmt::Display) -> privd_pb::Error {
    tracing::error!(error = %e, "{what}");
    error(privd_pb::ErrorCode::Internal, what)
}

async fn handle(
    st: &Arc<AdminState>,
    cmd: &pb::request::Command,
    mut secrets: Vec<hx_ipc::secret::Secret>,
) -> Reply {
    use pb::request::Command as C;
    use pb::response::Result as R;
    let now = now_unix();
    match cmd {
        C::Status(_) => {
            let (open, expires) = st.setup.window_state();
            let setup = pb::SetupWindowState {
                open,
                expires_at_unix_s: expires,
            };
            let sub = st.setup.status();
            Ok(R::Status(pb::StatusResult {
                gatewayd_version: env!("CARGO_PKG_VERSION").into(),
                listening: st.listening,
                connected_clients: u32::try_from(st.live.count()).unwrap_or(u32::MAX),
                certificate: pb::CertificateState::None as i32,
                certificate_not_after_unix_s: 0,
                setup_window: Some(setup),
                session_link: st.sessions.link().state() as i32,
                link_faults_10min: 0,
                registry_version: st.devices.registry_version(),
                setup_device_bound: sub.device.is_some(),
                setup_device_id: sub
                    .device
                    .map(|d| bytes::Bytes::copy_from_slice(d.as_bytes()))
                    .unwrap_or_default(),
                setup_token_pending: sub.token_pending,
                setup_job: match sub.job {
                    hx_proto::pb::SetupJobState::Running => pb::SetupJobState::Running,
                    hx_proto::pb::SetupJobState::Succeeded => pb::SetupJobState::Succeeded,
                    hx_proto::pb::SetupJobState::Failed => pb::SetupJobState::Failed,
                    hx_proto::pb::SetupJobState::Cancelled => pb::SetupJobState::Cancelled,
                    _ => pb::SetupJobState::Idle,
                } as i32,
                setup_job_id: sub.job_id,
            }))
        }
        C::ListDevices(_) => {
            let records = st
                .devices
                .records()
                .map_err(|e| internal("registry read failed", e))?;
            let devices = records
                .iter()
                .take(MAX_LISTED)
                .map(|r| {
                    let info = device_info(r, false);
                    let state = if r.is_revoked() {
                        pb::DeviceState::Revoked
                    } else if st.auth.is_backing_off(&r.id) {
                        // "Locked": the authenticator holds this device's PIN back right now
                        // (a wrong-PIN backoff, an unavailable verifier or a locked purpose).
                        pb::DeviceState::Locked
                    } else {
                        pb::DeviceState::Active
                    };
                    pb::Device {
                        device_id: info.device_id,
                        name: info.name,
                        created_unix_s: info.created_unix,
                        last_seen_unix_s: info.last_seen_unix,
                        state: state as i32,
                    }
                })
                .collect();
            Ok(R::ListDevices(pb::ListDevicesResult { devices }))
        }
        C::RevokeDevice(r) => {
            let id = device_id(&r.device_id).ok_or_else(|| {
                error(
                    privd_pb::ErrorCode::InvalidArgument,
                    "device_id must be 16 bytes",
                )
            })?;
            match st.devices.revoke_by_operator(id).await {
                Ok(Some(n)) => Ok(R::RevokeDevice(pb::RevokeDeviceResult {
                    sessions_closed: u32::try_from(n).unwrap_or(u32::MAX),
                })),
                Ok(None) => Err(error(privd_pb::ErrorCode::NotFound, "unknown device")),
                Err(e) => Err(internal("revocation failed", e)),
            }
        }
        C::ReinstateDevice(r) => {
            let id = device_id(&r.device_id).ok_or_else(|| {
                error(
                    privd_pb::ErrorCode::InvalidArgument,
                    "device_id must be 16 bytes",
                )
            })?;
            match st.devices.reinstate(id).await {
                Ok(Some(_)) => {
                    // A locked (not revoked) device has its failure counter and wait reset too.
                    st.auth
                        .reset_lockout(&id)
                        .await
                        .map_err(|e| internal("lockout reset failed", e))?;
                    Ok(R::ReinstateDevice(pb::ReinstateDeviceResult {}))
                }
                Ok(None) => Err(error(privd_pb::ErrorCode::NotFound, "unknown device")),
                Err(e) => Err(internal("reinstate failed", e)),
            }
        }
        C::SetPinVerifier(r) => {
            let record = parse_verifier(&r.verifier, st.min_argon_memory_kib)?;
            use pb::set_pin_verifier_request::Target;
            let target = match &r.target {
                Some(Target::DeviceId(b)) => {
                    let id = device_id(b).ok_or_else(|| {
                        error(
                            privd_pb::ErrorCode::InvalidArgument,
                            "device_id must be 16 bytes",
                        )
                    })?;
                    let known = st
                        .devices
                        .records()
                        .map_err(|e| internal("registry read failed", e))?
                        .iter()
                        .any(|d| d.id == id);
                    if !known {
                        return Err(error(privd_pb::ErrorCode::NotFound, "unknown device"));
                    }
                    Some(id)
                }
                _ => None,
            };
            st.verifiers
                .set_pin(target, record)
                .map_err(|e| internal("storing the verifier failed", e))?;
            st.devices.bump_version();
            st.devices
                .audit_opt(AuditEvent::PinChanged, target, "admin");
            Ok(R::SetPinVerifier(pb::SetPinVerifierResult {}))
        }
        C::SetPasswordVerifier(r) => {
            let record = parse_verifier(&r.verifier, st.min_argon_memory_kib)?;
            st.verifiers
                .set_password(record)
                .map_err(|e| internal("storing the verifier failed", e))?;
            st.devices.bump_version();
            st.devices
                .audit_opt(AuditEvent::PasswordVerifierChanged, None, "admin");
            Ok(R::SetPasswordVerifier(pb::SetPasswordVerifierResult {}))
        }
        C::CreatePairingToken(r) => {
            // The token is secret slot 0: read, parsed, installed, wiped on drop.
            let secret = secrets.pop().ok_or_else(|| {
                error(
                    privd_pb::ErrorCode::InvalidArgument,
                    "the token secret is missing",
                )
            })?;
            let text = std::str::from_utf8(secret.expose()).map_err(|_| {
                error(
                    privd_pb::ErrorCode::InvalidArgument,
                    "the token is not text",
                )
            })?;
            let token = PairingToken::parse(text)
                .map_err(|_| error(privd_pb::ErrorCode::InvalidArgument, "not a pairing token"))?;
            let ttl = pairing_ttl(st, r.expires_in_s);
            st.auth
                .pairing()
                .install_token(&token, ttl)
                .map_err(|e| internal("installing the token failed", e))?;
            // While the setup window is open this is the installer's token: its public id
            // is how the device that pairs with it becomes the setup device (ipc.md 5.5).
            st.setup.on_token_installed(token.id());
            st.devices
                .audit_opt(AuditEvent::PairingOpened, None, "token");
            Ok(R::CreatePairingToken(pb::CreatePairingTokenResult {
                expires_at_unix_s: now + ttl.as_secs(),
            }))
        }
        C::CreatePairingCode(r) => {
            let ttl = pairing_ttl(st, r.expires_in_s);
            let code = st
                .auth
                .pairing()
                .issue_code_with_ttl(ttl)
                .map_err(|e| internal("issuing a code failed", e))?;
            st.devices
                .audit_opt(AuditEvent::PairingOpened, None, "code");
            Ok(R::CreatePairingCode(pb::CreatePairingCodeResult {
                code: code.to_text().to_string(),
                expires_at_unix_s: now + ttl.as_secs(),
            }))
        }
        C::SetupWindow(r) => {
            match pb::SetupWindowAction::try_from(r.action)
                .unwrap_or(pb::SetupWindowAction::Unspecified)
            {
                pb::SetupWindowAction::Open => st.setup.on_window_open(u64::from(r.expires_in_s)),
                pb::SetupWindowAction::Extend => {
                    if !st.setup.on_window_extend(u64::from(r.expires_in_s)) {
                        return Err(error(
                            privd_pb::ErrorCode::FailedPrecondition,
                            "the setup window is not open",
                        ));
                    }
                }
                pb::SetupWindowAction::Close => st.setup.on_window_close(),
                pb::SetupWindowAction::Unspecified => {
                    return Err(error(
                        privd_pb::ErrorCode::InvalidArgument,
                        "setup_window.action",
                    ));
                }
            }
            let (open, expires) = st.setup.window_state();
            Ok(R::SetupWindow(pb::SetupWindowResult {
                state: Some(pb::SetupWindowState {
                    open,
                    expires_at_unix_s: expires,
                }),
            }))
        }
        C::CloseSessions(_) => {
            let n = st
                .live
                .close_all(CloseCode::Shutdown, "closed by the operator")
                .await;
            Ok(R::CloseSessions(pb::CloseSessionsResult {
                sessions_closed: u32::try_from(n).unwrap_or(u32::MAX),
            }))
        }
    }
}

/// The lifetime of a pairing credential: what the caller asked for, capped at the configured
/// lifetime (the window caps it again).
fn pairing_ttl(st: &AdminState, requested_s: u32) -> Duration {
    Duration::from_secs(u64::from(requested_s).min(st.pairing_ttl_s))
}

fn parse_verifier(bytes: &[u8], min_memory_kib: u32) -> Result<VerifierRecord, privd_pb::Error> {
    let record = VerifierRecord::parse(bytes)
        .map_err(|_| error(privd_pb::ErrorCode::InvalidArgument, "malformed verifier"))?;
    record.check_cost(min_memory_kib).map_err(|_| {
        error(
            privd_pb::ErrorCode::InvalidArgument,
            "verifier cost parameters are below the minimum",
        )
    })?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pairing_code_reply_is_wiped_after_it_is_written() {
        let mut r = pb::response::Result::CreatePairingCode(pb::CreatePairingCodeResult {
            code: "ABCD-EFGH".into(),
            expires_at_unix_s: 1,
        });
        scrub(&mut r);
        let pb::response::Result::CreatePairingCode(c) = r else {
            panic!()
        };
        assert!(c.code.is_empty(), "the code text is gone");
    }
}
