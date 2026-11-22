//! The gateway's client of `hx-privd` (`docs/ipc.md` Part 1, sections 3 to 8, role `Gateway`).
//!
//! * One unix stream socket per connection, `Hello` first, one request in flight per
//!   connection (a small pool gives the gateway concurrency, privd allows 4 `Gateway`
//!   connections).
//! * Request ids are unique, non-zero and global to the client; every call has a deadline that
//!   can only shorten the command's maximum (`hx_ipc::privd::command_info`), and a local timeout
//!   a little beyond it. When a call times out or the caller drops the future, the connection is
//!   closed (privd treats that as a cancel; the shielded sections of section 4 still finish).
//! * Secrets travel as kind-2 frames written **right after** the request, never inside a
//!   protobuf message, from `Zeroizing` buffers. They are never logged: [`PrivdError`] carries
//!   no request content.
//! * Frames are read only through [`crate::gateway::ipc_io::read_frame`] (`recvmsg`, descriptors
//!   refused).
//! * privd restarts: a connection that privd closed is noticed before reuse (readable while
//!   idle) or on the first write (retried once on a fresh connection, nothing was processed),
//!   and a lost connection mid-call is [`PrivdError::Unavailable`], which callers treat as
//!   "retry", never as a wrong PIN (section 5.3).
//!
//! Only the commands the gateway role may use are wrapped; [`PrivdClient::call`] is the generic
//! entry point and privd's role check is the authority.

use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use hx_ipc::ReadError;
use hx_ipc::frame::Decoder;
use hx_ipc::privd::{self, Incoming, PrivdPolicy, Side, pb, pb::request::Command};
use hx_ipc::text::sanitize_text;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::sync::{Notify, Semaphore, mpsc};
use tokio::time::Instant;
use zeroize::Zeroizing;

use super::ipc_io::read_frame;

/// Tunables of [`PrivdClient`].
#[derive(Debug, Clone)]
pub struct PrivdClientOptions {
    /// Connections kept open at most (privd allows 4 for the `Gateway` role).
    pub max_connections: usize,
    /// Bound on `connect(2)`.
    pub connect_timeout: Duration,
    /// Slack added to a command's deadline before the client gives up locally (privd enforces
    /// the deadline itself and answers `DEADLINE_EXCEEDED`).
    pub margin: Duration,
    /// `Hello.software` (at most 64 bytes).
    pub software: String,
}

impl Default for PrivdClientOptions {
    fn default() -> Self {
        Self {
            max_connections: 2,
            connect_timeout: Duration::from_secs(2),
            margin: Duration::from_secs(2),
            software: concat!("hx-gatewayd ", env!("CARGO_PKG_VERSION")).into(),
        }
    }
}

/// An error answer from privd (`docs/ipc.md` section 4, error model).
#[derive(Debug, Clone)]
pub struct RemoteError {
    /// The error code.
    pub code: pb::ErrorCode,
    /// The command-specific refinement, if any.
    pub detail: pb::ErrorDetail,
    /// privd's message, sanitized again here (untrusted text, for logs only).
    pub message: String,
    /// privd says a retry may succeed.
    pub retryable: bool,
    /// Suggested wait before the retry.
    pub retry_after: Duration,
    /// The failing stage (`ProgressStage` number), set by long commands such as `CreateDesktop`.
    pub stage: Option<i32>,
}

/// Why a privd call failed.
#[derive(Debug, thiserror::Error)]
pub enum PrivdError {
    /// privd cannot be reached, or the connection was lost (privd restarting). Retryable; the
    /// effect of the command, if it was sent, is unknown.
    #[error("privd is unavailable: {0}")]
    Unavailable(String),
    /// The call did not finish in time.
    #[error("privd call timed out")]
    Timeout,
    /// privd answered with an error.
    #[error("privd refused: {:?} {:?}: {}", .0.code, .0.detail, .0.message)]
    Remote(RemoteError),
    /// privd broke the contract (bad frame, wrong id, wrong result variant). The connection is
    /// closed.
    #[error("privd protocol violation: {0}")]
    Protocol(String),
    /// privd speaks another major version, or served this connection as another role.
    #[error("incompatible privd: {0}")]
    Incompatible(String),
    /// The request itself is invalid (rejected before sending; a gateway bug).
    #[error("invalid request: {0}")]
    InvalidRequest(String),
}

impl PrivdError {
    /// True if the same call may succeed later: privd down or restarting, a timeout, or an
    /// error privd marked retryable.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Unavailable(_) | Self::Timeout => true,
            Self::Remote(e) => e.retryable || e.code == pb::ErrorCode::Unavailable,
            _ => false,
        }
    }

    /// True if privd answered `RESOURCE_EXHAUSTED` with detail `LOCKED`: the verification
    /// purpose is locked until an Admin resets it (`docs/ipc.md` section 5.3).
    pub fn is_locked(&self) -> bool {
        matches!(self, Self::Remote(e)
            if e.code == pb::ErrorCode::ResourceExhausted && e.detail == pb::ErrorDetail::Locked)
    }

    /// True for `NOT_FOUND`.
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::Remote(e) if e.code == pb::ErrorCode::NotFound)
    }
}

/// One secret to send in a kind-2 frame after the request. `bytes` is borrowed so that the
/// caller keeps it in its own zeroizing buffer.
pub struct OutSecret<'a> {
    /// Declared kind of the slot.
    pub kind: pb::SecretKind,
    /// The raw secret.
    pub bytes: &'a [u8],
}

/// Result of `PepperEnrol`: the MAC to store in a verifier. Not a secret by itself (it is
/// useless without the Argon2id input) but handled with care all the same.
pub struct PepperMac {
    /// `HMAC-SHA256(pepper_purpose, input)`.
    pub mac: [u8; 32],
    /// Pepper version, for forward compatibility.
    pub version: u8,
}

/// Prefix of the error for a failed write of the request frame itself.
const REQUEST_WRITE: &str = "request write";

/// Bound on the liveness ping of [`PrivdClient::ensure_connected`].
const PING_TIMEOUT: Duration = Duration::from_secs(1);

struct Conn {
    stream: UnixStream,
    decoder: Decoder<PrivdPolicy>,
}

impl Conn {
    async fn open(path: &PathBuf, opts: &PrivdClientOptions) -> Result<Self, PrivdError> {
        let stream = tokio::time::timeout(opts.connect_timeout, UnixStream::connect(path))
            .await
            .map_err(|_| PrivdError::Unavailable("connect timed out".into()))?
            .map_err(|e| PrivdError::Unavailable(format!("connect: {}", e.kind())))?;
        let mut conn = Self {
            stream,
            decoder: Decoder::new(PrivdPolicy::new(Side::Client)),
        };
        let hello = pb::Frame {
            frame: Some(pb::frame::Frame::Hello(pb::Hello {
                major: privd::VERSION_MAJOR,
                minor: privd::VERSION_MINOR,
                software: sanitize_text(&opts.software, privd::MAX_SOFTWARE_LEN),
            })),
        };
        let bytes = privd::encode_message(&hello, Side::Server)
            .map_err(|e| PrivdError::InvalidRequest(e.to_string()))?;
        conn.write(&bytes)
            .await
            .map_err(|e| PrivdError::Unavailable(format!("hello: {}", e.kind())))?;
        let until = Instant::now() + privd::HELLO_TIMEOUT;
        match tokio::time::timeout_at(until, conn.recv())
            .await
            .map_err(|_| PrivdError::Unavailable("hello timed out".into()))??
        {
            Incoming::Message(pb::Frame {
                frame: Some(pb::frame::Frame::HelloAck(ack)),
            }) => {
                if ack.major != privd::VERSION_MAJOR {
                    return Err(PrivdError::Incompatible(format!(
                        "privd speaks major {}",
                        ack.major
                    )));
                }
                // The role follows from the uid privd saw. A gateway served as Admin runs as
                // root, which breaks the privilege separation (docs/ipc.md section 1.1).
                if ack.role != pb::Role::Gateway as i32 {
                    return Err(PrivdError::Incompatible(
                        "privd did not serve this connection as the gateway role".into(),
                    ));
                }
                Ok(conn)
            }
            _ => Err(PrivdError::Protocol("expected HelloAck".into())),
        }
    }

    async fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.stream.write_all(bytes).await
    }

    async fn recv(&mut self) -> Result<Incoming, PrivdError> {
        let raw = match read_frame(&self.stream, &mut self.decoder).await {
            Ok(Some(raw)) => raw,
            Ok(None) => {
                return Err(PrivdError::Unavailable(
                    "privd closed the connection".into(),
                ));
            }
            Err(ReadError::Io(e)) => {
                return Err(PrivdError::Unavailable(format!("read: {}", e.kind())));
            }
            Err(violation) => return Err(PrivdError::Protocol(violation.to_string())),
        };
        privd::decode(raw, Side::Client).map_err(|e| PrivdError::Protocol(e.to_string()))
    }

    /// True if an idle connection is not reusable: privd closed it, or sent something nobody
    /// asked for. The probe is a one-byte non-blocking `recvmsg` (never a plain `recv`, so a
    /// descriptor cannot be installed); `WouldBlock` means quiet and healthy. Tokio only runs
    /// the probe once it has seen readiness, so a close it has not noticed yet is caught by
    /// the retry on the first write instead.
    fn is_stale(&self) -> bool {
        let mut byte = [0u8; 1];
        match self.stream.try_io(tokio::io::Interest::READABLE, || {
            hx_ipc::recv_no_cmsg(&self.stream, &mut byte)
        }) {
            Err(e) => e.kind() != io::ErrorKind::WouldBlock,
            Ok(_) => true,
        }
    }

    /// Sends the request and its secret frames, then waits for the matching `Response`.
    async fn run(
        &mut self,
        request_id: u64,
        deadline_ms: u32,
        command: &Command,
        secrets: &[OutSecret<'_>],
    ) -> Result<pb::response::Result, PrivdError> {
        let slots = secrets
            .iter()
            .enumerate()
            .map(|(i, s)| pb::SecretSlot {
                slot: i as u32,
                kind: s.kind as i32,
                sealed: false,
                length: s.bytes.len() as u32,
                upload_nonce: Bytes::new(),
                signer_key_id: 0,
            })
            .collect();
        let frame = pb::Frame {
            frame: Some(pb::frame::Frame::Request(pb::Request {
                request_id,
                deadline_ms,
                secret_slots: slots,
                command: Some(command.clone()),
            })),
        };
        let bytes = privd::encode_message(&frame, Side::Server)
            .map_err(|e| PrivdError::InvalidRequest(e.to_string()))?;
        // Only a failure here, before privd can have seen the whole request, is safe to retry.
        self.write(&bytes)
            .await
            .map_err(|e| PrivdError::Unavailable(format!("{REQUEST_WRITE}: {}", e.kind())))?;
        for (i, s) in secrets.iter().enumerate() {
            // Zeroizing buffer: the frame copy of the secret is wiped when this drops.
            let framed = privd::encode_secret(request_id, i as u8, s.bytes)
                .map_err(|e| PrivdError::InvalidRequest(e.to_string()))?;
            self.write(&framed)
                .await
                .map_err(|e| PrivdError::Unavailable(format!("send: {}", e.kind())))?;
        }
        loop {
            match self.recv().await? {
                Incoming::Message(pb::Frame {
                    frame: Some(pb::frame::Frame::Response(r)),
                }) => {
                    if r.request_id != request_id {
                        return Err(PrivdError::Protocol("response for another request".into()));
                    }
                    return match r.result {
                        Some(pb::response::Result::Error(e)) => Err(remote(e)),
                        Some(ok) => Ok(ok),
                        None => Err(PrivdError::Protocol("response without a result".into())),
                    };
                }
                Incoming::Message(pb::Frame {
                    frame: Some(pb::frame::Frame::Progress(_)),
                }) => {}
                Incoming::Message(pb::Frame {
                    frame: Some(pb::frame::Frame::Ping(p)),
                }) => {
                    let pong = pb::Frame {
                        frame: Some(pb::frame::Frame::Pong(pb::Pong { nonce: p.nonce })),
                    };
                    let bytes = privd::encode_message(&pong, Side::Server)
                        .map_err(|e| PrivdError::InvalidRequest(e.to_string()))?;
                    self.write(&bytes)
                        .await
                        .map_err(|e| PrivdError::Unavailable(format!("send: {}", e.kind())))?;
                }
                Incoming::Message(pb::Frame {
                    frame: Some(pb::frame::Frame::Pong(_)),
                }) => {}
                _ => return Err(PrivdError::Protocol("unexpected frame".into())),
            }
        }
    }

    /// Like [`Conn::run`] for the dedicated lane: the secrets are **owned** and each is wiped
    /// right after its frame has been written (docs/ipc.md 5.2 rule 4), `Progress` frames are
    /// forwarded, and `cancel` makes the call send a privd `Cancel` frame and then keep waiting
    /// for privd's answer (`CANCELLED`).
    async fn run_streaming(
        &mut self,
        request_id: u64,
        deadline_ms: u32,
        command: &Command,
        secrets: Vec<(pb::SecretKind, Zeroizing<Vec<u8>>)>,
        progress: &mpsc::Sender<pb::Progress>,
        cancel: &Notify,
    ) -> Result<pb::response::Result, PrivdError> {
        let slots = secrets
            .iter()
            .enumerate()
            .map(|(i, (kind, bytes))| pb::SecretSlot {
                slot: i as u32,
                kind: *kind as i32,
                sealed: false,
                length: bytes.len() as u32,
                upload_nonce: Bytes::new(),
                signer_key_id: 0,
            })
            .collect();
        let frame = pb::Frame {
            frame: Some(pb::frame::Frame::Request(pb::Request {
                request_id,
                deadline_ms,
                secret_slots: slots,
                command: Some(command.clone()),
            })),
        };
        let bytes = privd::encode_message(&frame, Side::Server)
            .map_err(|e| PrivdError::InvalidRequest(e.to_string()))?;
        self.write(&bytes)
            .await
            .map_err(|e| PrivdError::Unavailable(format!("{REQUEST_WRITE}: {}", e.kind())))?;
        for (i, (_, bytes)) in secrets.into_iter().enumerate() {
            // The framed copy is `Zeroizing`; `bytes` is wiped at the end of this iteration,
            // as soon as the frame is on the socket.
            let framed = privd::encode_secret(request_id, i as u8, &bytes)
                .map_err(|e| PrivdError::InvalidRequest(e.to_string()))?;
            self.write(&framed)
                .await
                .map_err(|e| PrivdError::Unavailable(format!("send: {}", e.kind())))?;
        }
        let mut cancelled = false;
        loop {
            let incoming = tokio::select! {
                () = cancel.notified(), if !cancelled => {
                    cancelled = true;
                    let f = pb::Frame {
                        frame: Some(pb::frame::Frame::Cancel(pb::Cancel { request_id })),
                    };
                    let b = privd::encode_message(&f, Side::Server)
                        .map_err(|e| PrivdError::InvalidRequest(e.to_string()))?;
                    self.write(&b)
                        .await
                        .map_err(|e| PrivdError::Unavailable(format!("send: {}", e.kind())))?;
                    continue;
                }
                r = self.recv() => r?,
            };
            match incoming {
                Incoming::Message(pb::Frame {
                    frame: Some(pb::frame::Frame::Response(r)),
                }) => {
                    if r.request_id != request_id {
                        return Err(PrivdError::Protocol("response for another request".into()));
                    }
                    return match r.result {
                        Some(pb::response::Result::Error(e)) => Err(remote(e)),
                        Some(ok) => Ok(ok),
                        None => Err(PrivdError::Protocol("response without a result".into())),
                    };
                }
                Incoming::Message(pb::Frame {
                    frame: Some(pb::frame::Frame::Progress(p)),
                }) => {
                    if p.request_id == request_id {
                        // A slow consumer loses intermediate steps, never blocks the call.
                        let _ = progress.try_send(p);
                    }
                }
                Incoming::Message(pb::Frame {
                    frame: Some(pb::frame::Frame::Ping(p)),
                }) => {
                    let pong = pb::Frame {
                        frame: Some(pb::frame::Frame::Pong(pb::Pong { nonce: p.nonce })),
                    };
                    let bytes = privd::encode_message(&pong, Side::Server)
                        .map_err(|e| PrivdError::InvalidRequest(e.to_string()))?;
                    self.write(&bytes)
                        .await
                        .map_err(|e| PrivdError::Unavailable(format!("send: {}", e.kind())))?;
                }
                Incoming::Message(pb::Frame {
                    frame: Some(pb::frame::Frame::Pong(_)),
                }) => {}
                _ => return Err(PrivdError::Protocol("unexpected frame".into())),
            }
        }
    }

    /// A connection-level `Ping`: proves privd is alive and reading on this connection.
    async fn ping(&mut self, nonce: u64) -> Result<(), PrivdError> {
        let frame = pb::Frame {
            frame: Some(pb::frame::Frame::Ping(pb::Ping { nonce })),
        };
        let bytes = privd::encode_message(&frame, Side::Server)
            .map_err(|e| PrivdError::InvalidRequest(e.to_string()))?;
        self.write(&bytes)
            .await
            .map_err(|e| PrivdError::Unavailable(format!("write: {}", e.kind())))?;
        loop {
            match self.recv().await? {
                Incoming::Message(pb::Frame {
                    frame: Some(pb::frame::Frame::Pong(p)),
                }) if p.nonce == nonce => return Ok(()),
                Incoming::Message(pb::Frame {
                    frame: Some(pb::frame::Frame::Progress(_)),
                }) => {}
                _ => return Err(PrivdError::Protocol("unexpected frame".into())),
            }
        }
    }

    /// Best effort `Cancel` for a request we stop waiting for. The connection is dropped right
    /// after by the caller.
    async fn cancel(&mut self, request_id: u64) {
        let frame = pb::Frame {
            frame: Some(pb::frame::Frame::Cancel(pb::Cancel { request_id })),
        };
        if let Ok(bytes) = privd::encode_message(&frame, Side::Server) {
            let _ = tokio::time::timeout(Duration::from_millis(200), self.write(&bytes)).await;
        }
    }
}

fn remote(e: pb::Error) -> PrivdError {
    PrivdError::Remote(RemoteError {
        code: pb::ErrorCode::try_from(e.code).unwrap_or(pb::ErrorCode::Internal),
        detail: pb::ErrorDetail::try_from(e.detail).unwrap_or(pb::ErrorDetail::Unspecified),
        message: sanitize_text(&e.message, privd::MAX_ERROR_MESSAGE_LEN),
        retryable: e.retryable,
        retry_after: Duration::from_millis(u64::from(e.retry_after_ms)),
        stage: e.stage,
    })
}

struct Inner {
    path: PathBuf,
    opts: PrivdClientOptions,
    next_id: AtomicU64,
    idle: Mutex<Vec<Conn>>,
    permits: Semaphore,
}

/// Async client of the `hx-privd` socket. Cheap to clone.
#[derive(Clone)]
pub struct PrivdClient(Arc<Inner>);

impl std::fmt::Debug for PrivdClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivdClient")
            .field("path", &self.0.path)
            .finish_non_exhaustive()
    }
}

impl PrivdClient {
    /// A client for the socket at `path`. Connects lazily, so privd may start later.
    pub fn new(path: impl Into<PathBuf>, opts: PrivdClientOptions) -> Self {
        let n = opts.max_connections.clamp(1, 4);
        Self(Arc::new(Inner {
            path: path.into(),
            opts,
            next_id: AtomicU64::new(1),
            idle: Mutex::new(Vec::new()),
            permits: Semaphore::new(n),
        }))
    }

    fn take_idle(&self) -> Option<Conn> {
        self.0.idle.lock().unwrap_or_else(|p| p.into_inner()).pop()
    }

    fn put_idle(&self, conn: Conn) {
        self.0
            .idle
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(conn);
    }

    /// Checks that privd can be reached **right now**: a live idle connection answers a
    /// connection-level `Ping`, otherwise a new connection is opened (`Hello` and role check).
    /// Used before a PIN attempt is counted, so that an outage is never charged to a device.
    pub async fn ensure_connected(&self) -> Result<(), PrivdError> {
        let _permit = self
            .0
            .permits
            .acquire()
            .await
            .map_err(|_| PrivdError::Unavailable("client closed".into()))?;
        let nonce = self.0.next_id.fetch_add(1, Ordering::Relaxed);
        while let Some(mut conn) = self.take_idle() {
            if conn.is_stale() {
                continue;
            }
            if let Ok(Ok(())) = tokio::time::timeout(PING_TIMEOUT, conn.ping(nonce)).await {
                self.put_idle(conn);
                return Ok(());
            }
        }
        let conn = Conn::open(&self.0.path, &self.0.opts).await?;
        self.put_idle(conn);
        Ok(())
    }

    /// Sends `command` (with `secrets` in kind-2 frames) and waits for its result.
    ///
    /// `deadline` may only shorten the command's maximum deadline (`docs/ipc.md` section 8).
    /// Dropping the returned future closes the connection (a cancel for privd).
    pub async fn call(
        &self,
        command: Command,
        secrets: &[OutSecret<'_>],
        deadline: Option<Duration>,
    ) -> Result<pb::response::Result, PrivdError> {
        let info = privd::command_info(&command);
        let requested_ms = deadline
            .map(|d| u32::try_from(d.as_millis()).unwrap_or(u32::MAX))
            .unwrap_or(0);
        let deadline_ms = info.effective_deadline_ms(requested_ms);
        let until =
            Instant::now() + Duration::from_millis(u64::from(deadline_ms)) + self.0.opts.margin;
        let _permit = tokio::time::timeout_at(until, self.0.permits.acquire())
            .await
            .map_err(|_| PrivdError::Timeout)?
            .map_err(|_| PrivdError::Unavailable("client closed".into()))?;
        let request_id = self.0.next_id.fetch_add(1, Ordering::Relaxed);

        // Prefer a live idle connection; drop the ones privd closed meanwhile.
        let mut reused = None;
        while let Some(conn) = self.take_idle() {
            if conn.is_stale() {
                continue;
            }
            reused = Some(conn);
            break;
        }
        let was_reused = reused.is_some();
        let mut conn = match reused {
            Some(c) => c,
            None => connect_until(&self.0, until).await?,
        };

        let mut outcome =
            tokio::time::timeout_at(until, conn.run(request_id, deadline_ms, &command, secrets))
                .await;
        // A reused connection that failed on its first write was closed by privd (a restart):
        // nothing was processed, so one retry on a fresh connection is safe.
        if was_reused && write_failed(&outcome) {
            conn = connect_until(&self.0, until).await?;
            outcome = tokio::time::timeout_at(
                until,
                conn.run(request_id, deadline_ms, &command, secrets),
            )
            .await;
        }
        match outcome {
            Ok(Ok(result)) => {
                self.put_idle(conn);
                Ok(result)
            }
            Ok(Err(e @ PrivdError::Remote(_))) => {
                // A well-formed error answer leaves the connection usable.
                self.put_idle(conn);
                Err(e)
            }
            Ok(Err(e)) => Err(e),
            Err(_elapsed) => {
                conn.cancel(request_id).await;
                Err(PrivdError::Timeout)
            }
        }
    }

    // ----------------------------------------------------------- typed commands

    /// `PepperVerify` (docs/ipc.md section 6.15): does `HMAC(pepper_purpose, input)` equal
    /// `expected`? Only yes or no comes back. `input` is the Argon2id output (32 bytes).
    ///
    /// `Err` with [`PrivdError::is_locked`] means the purpose is locked; any retryable error
    /// means "ask again later", never "wrong".
    pub async fn pepper_verify(
        &self,
        purpose: pb::LockoutPurpose,
        expected: &[u8; 32],
        input: &[u8],
    ) -> Result<bool, PrivdError> {
        let command = Command::PepperVerify(pb::PepperVerifyRequest {
            purpose: purpose as i32,
            expected_verifier: Bytes::copy_from_slice(expected),
        });
        let secret = OutSecret {
            kind: pb::SecretKind::MacInput,
            bytes: input,
        };
        match self.call(command, &[secret], None).await? {
            pb::response::Result::PepperVerify(r) => Ok(r.ok),
            _ => Err(PrivdError::Protocol("unexpected result variant".into())),
        }
    }

    /// `PepperEnrol` (section 6.15): the MAC to store in a new verifier. Limited by privd to a
    /// few calls a day for the gateway after setup.
    pub async fn pepper_enrol(
        &self,
        purpose: pb::LockoutPurpose,
        input: &[u8],
    ) -> Result<PepperMac, PrivdError> {
        let command = Command::PepperEnrol(pb::PepperEnrolRequest {
            purpose: purpose as i32,
        });
        let secret = OutSecret {
            kind: pb::SecretKind::MacInput,
            bytes: input,
        };
        match self.call(command, &[secret], None).await? {
            pb::response::Result::PepperEnrol(r) => {
                let mac: [u8; 32] = r
                    .mac
                    .as_ref()
                    .try_into()
                    .map_err(|_| PrivdError::Protocol("mac is not 32 bytes".into()))?;
                Ok(PepperMac {
                    mac,
                    version: u8::try_from(r.version).unwrap_or(u8::MAX),
                })
            }
            _ => Err(PrivdError::Protocol("unexpected result variant".into())),
        }
    }

    /// `RecordEvent` (section 6.15): an entry in privd's audit log. `label` is sanitized and
    /// cut to 64 bytes here as well.
    pub async fn record_event(
        &self,
        event: pb::AuditEvent,
        device_id: Option<[u8; 16]>,
        label: &str,
    ) -> Result<(), PrivdError> {
        let command = Command::RecordEvent(pb::RecordEventRequest {
            event: event as i32,
            device_id: device_id.map(|d| Bytes::copy_from_slice(&d)),
            label: sanitize_text(label, 64),
        });
        match self.call(command, &[], None).await? {
            pb::response::Result::RecordEvent(_) => Ok(()),
            _ => Err(PrivdError::Protocol("unexpected result variant".into())),
        }
    }

    /// `GetHostInfo` (section 6.2).
    pub async fn get_host_info(&self) -> Result<pb::GetHostInfoResult, PrivdError> {
        let command = Command::GetHostInfo(pb::GetHostInfoRequest {});
        match self.call(command, &[], None).await? {
            pb::response::Result::GetHostInfo(r) => Ok(r),
            _ => Err(PrivdError::Protocol("unexpected result variant".into())),
        }
    }

    /// `GetDesktop` (section 6.6). `Ok(None)` if the desktop does not exist.
    pub async fn get_desktop(&self, desktop_id: &str) -> Result<Option<pb::Desktop>, PrivdError> {
        let command = Command::GetDesktop(pb::GetDesktopRequest {
            desktop_id: desktop_id.to_owned(),
        });
        match self.call(command, &[], None).await {
            Ok(pb::response::Result::GetDesktop(r)) => Ok(r.desktop),
            Ok(_) => Err(PrivdError::Protocol("unexpected result variant".into())),
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `StartDesktop` (section 6.7). Converges: starting a running desktop succeeds.
    pub async fn start_desktop(&self, desktop_id: &str) -> Result<pb::PowerResult, PrivdError> {
        let command = Command::StartDesktop(pb::StartDesktopRequest {
            desktop_id: desktop_id.to_owned(),
        });
        match self.call(command, &[], None).await? {
            pb::response::Result::StartDesktop(r) => Ok(r),
            _ => Err(PrivdError::Protocol("unexpected result variant".into())),
        }
    }

    /// `SetUserPassword` (section 6.9) without `CURRENT_PASSWORD`, which privd allows only
    /// while the setup window is open. The caller keeps `password` in its own zeroizing buffer.
    pub async fn set_user_password(
        &self,
        desktop_id: &str,
        password: &[u8],
    ) -> Result<(), PrivdError> {
        let command = Command::SetUserPassword(pb::SetUserPasswordRequest {
            desktop_id: desktop_id.to_owned(),
        });
        let secret = OutSecret {
            kind: pb::SecretKind::UserPassword,
            bytes: password,
        };
        match self.call(command, &[secret], None).await? {
            pb::response::Result::SetUserPassword(_) => Ok(()),
            _ => Err(PrivdError::Protocol("unexpected result variant".into())),
        }
    }

    /// `FinishSetup` (section 6.3) without `force`: closes the setup window.
    pub async fn finish_setup(&self) -> Result<(), PrivdError> {
        let command = Command::FinishSetup(pb::FinishSetupRequest { force: None });
        match self.call(command, &[], None).await? {
            pb::response::Result::FinishSetup(_) => Ok(()),
            _ => Err(PrivdError::Protocol("unexpected result variant".into())),
        }
    }

    /// `ProvisionSessionLink` (section 6.11): ensures the proxy device exists and returns the
    /// host path of the link socket.
    pub async fn provision_session_link(&self, desktop_id: &str) -> Result<String, PrivdError> {
        let command = Command::ProvisionSessionLink(pb::ProvisionSessionLinkRequest {
            desktop_id: desktop_id.to_owned(),
        });
        match self.call(command, &[], None).await? {
            pb::response::Result::ProvisionSessionLink(r) => Ok(r.socket_path),
            _ => Err(PrivdError::Protocol("unexpected result variant".into())),
        }
    }

    /// `RestartSession` (section 6.11): restarts `hx-session` after repeated link faults
    /// (section 19.2). privd rate limits it.
    pub async fn restart_session(&self, desktop_id: &str) -> Result<(), PrivdError> {
        let command = Command::RestartSession(pb::RestartSessionRequest {
            desktop_id: desktop_id.to_owned(),
        });
        match self.call(command, &[], None).await? {
            pb::response::Result::RestartSession(_) => Ok(()),
            _ => Err(PrivdError::Protocol("unexpected result variant".into())),
        }
    }

    /// `InstallSession` (section 6.11): pushes the `hx-session` package of the agent release into
    /// the desktop (an outdated or incompatible session, section 19.2). privd rate limits it.
    pub async fn install_session(&self, desktop_id: &str) -> Result<(), PrivdError> {
        let command = Command::InstallSession(pb::InstallSessionRequest {
            desktop_id: desktop_id.to_owned(),
        });
        match self.call(command, &[], None).await? {
            pb::response::Result::InstallSession(_) => Ok(()),
            _ => Err(PrivdError::Protocol("unexpected result variant".into())),
        }
    }
}

// ------------------------------------------------------------------ the dedicated lane

/// One privd call on the dedicated lane, running in its own task so that a caller that is
/// busy elsewhere (the setup job, forwarding progress) is never what holds the connection.
/// Dropping it closes the connection, which privd treats as a cancel.
pub struct LaneCall {
    /// The request id, for [`PrivdLane::cancel`].
    pub request_id: u64,
    lane: Arc<LaneInner>,
    task: Option<tokio::task::JoinHandle<Result<pb::response::Result, PrivdError>>>,
}

impl LaneCall {
    /// Waits for privd's answer.
    pub async fn wait(mut self) -> Result<pb::response::Result, PrivdError> {
        let task = self.task.take().expect("waited once");
        task.await
            .unwrap_or_else(|_| Err(PrivdError::Unavailable("the call was aborted".into())))
    }
}

impl Drop for LaneCall {
    fn drop(&mut self) {
        if let Some(t) = &self.task {
            t.abort();
            self.lane
                .cancels
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&self.request_id);
        }
    }
}

struct LaneInner {
    client: PrivdClient,
    /// One call at a time on the lane.
    gate: Arc<Semaphore>,
    cancels: Mutex<std::collections::HashMap<u64, Arc<Notify>>>,
}

/// A privd connection outside the pool (`docs/ipc.md` 5.5): the setup job's `CreateDesktop`
/// runs here so that the pool stays free for logins, and so that progress frames can be
/// forwarded. Pool (2) plus the lane (1) stay within privd's 4 connections for the gateway.
/// Cheap to clone; calls are serialized.
#[derive(Clone)]
pub struct PrivdLane(Arc<LaneInner>);

impl PrivdClient {
    /// The dedicated lane of this client.
    pub fn dedicated(&self) -> PrivdLane {
        PrivdLane(Arc::new(LaneInner {
            client: self.clone(),
            gate: Arc::new(Semaphore::new(1)),
            cancels: Mutex::new(std::collections::HashMap::new()),
        }))
    }
}

impl PrivdLane {
    /// Starts `command` on its own fresh connection. `secrets` are owned and each is wiped as
    /// soon as its frame is written. `Progress` frames go to `progress` (a full channel drops
    /// the frame). `deadline` may only shorten the command's maximum.
    pub fn call_streaming(
        &self,
        command: Command,
        secrets: Vec<(pb::SecretKind, Zeroizing<Vec<u8>>)>,
        deadline: Option<Duration>,
        progress: mpsc::Sender<pb::Progress>,
    ) -> LaneCall {
        let inner = self.0.clone();
        let request_id = inner.client.0.next_id.fetch_add(1, Ordering::Relaxed);
        let cancel = Arc::new(Notify::new());
        // Registered before the task starts, so a cancel that races the start is not lost: the
        // stored permit is consumed as soon as the request has been written.
        inner
            .cancels
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(request_id, cancel.clone());
        let info = privd::command_info(&command);
        let requested_ms = deadline
            .map(|d| u32::try_from(d.as_millis()).unwrap_or(u32::MAX))
            .unwrap_or(0);
        let deadline_ms = info.effective_deadline_ms(requested_ms);
        let task = tokio::spawn(async move {
            let _slot = inner
                .gate
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| PrivdError::Unavailable("lane closed".into()))?;
            let opts = &inner.client.0.opts;
            let until =
                Instant::now() + Duration::from_millis(u64::from(deadline_ms)) + opts.margin;
            let result = async {
                let mut conn = connect_until(&inner.client.0, until).await?;
                tokio::time::timeout_at(
                    until,
                    conn.run_streaming(
                        request_id,
                        deadline_ms,
                        &command,
                        secrets,
                        &progress,
                        &cancel,
                    ),
                )
                .await
                .map_err(|_| PrivdError::Timeout)?
            }
            .await;
            inner
                .cancels
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&request_id);
            result
        });
        LaneCall {
            request_id,
            lane: self.0.clone(),
            task: Some(task),
        }
    }

    /// Asks privd to cancel `request_id` (a `Cancel` frame on the call's own connection). The
    /// call's [`LaneCall::wait`] then resolves with privd's `CANCELLED` answer once privd has
    /// destroyed what it had built. A request that is not in flight is ignored.
    pub fn cancel(&self, request_id: u64) {
        let cancels = self.0.cancels.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(n) = cancels.get(&request_id) {
            n.notify_one();
        }
    }
}

async fn connect_until(inner: &Inner, until: Instant) -> Result<Conn, PrivdError> {
    tokio::time::timeout_at(until, Conn::open(&inner.path, &inner.opts))
        .await
        .map_err(|_| PrivdError::Timeout)?
}

/// True if the failure was a write error (as opposed to the connection ending while waiting
/// for the answer, after which the effect of the command is unknown and nothing is retried).
fn write_failed(
    outcome: &Result<Result<pb::response::Result, PrivdError>, tokio::time::error::Elapsed>,
) -> bool {
    matches!(outcome, Ok(Err(PrivdError::Unavailable(m))) if m.starts_with(REQUEST_WRITE))
}
