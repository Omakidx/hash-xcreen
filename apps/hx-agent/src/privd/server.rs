//! The socket server: accept, peer authentication, framing, the request/secret/cancel protocol of
//! ipc.md 3 and 4.
//!
//! Every frame is read with `hx_ipc::Decoder::read_from` over a `NoCmsgReader` (so a control
//! message or `MSG_CTRUNC` closes the connection and the kernel installs no descriptor), directly
//! from the non-blocking socket through `try_io`; the decoder keeps a partly received frame
//! between wake-ups, so a slow peer costs nothing but its connection slot.
//!
//! Per connection: `Hello` within 5 s; the body of a frame within 5 s of its header; idle 10
//! minutes; one request in flight (a second `Request` is `RESOURCE_EXHAUSTED`); `Ping` answered at
//! once at most 10 times a second; secrets as kind-2 frames straight after their `Request`, within
//! 5 s, each matching the pending `request_id` and a declared, unfilled slot; a `Response` the
//! peer will not read within 10 s closes the connection (the command's effect stands).

use std::collections::HashSet;
use std::future::Future;
use std::io;
use std::os::unix::net::UnixListener as StdListener;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hx_ipc::peer::{PeerCred, peer_credentials, role_for_uid};
use hx_ipc::privd::pb::{self, ErrorCode, Role, frame::Frame as F};
use hx_ipc::privd::{
    self, BODY_TIMEOUT, HELLO_TIMEOUT, IDLE_TIMEOUT, Incoming, PrivdPolicy, RESPONSE_WRITE_TIMEOUT,
    Side, VERSION_MAJOR, VERSION_MINOR, check_secret_against_slot, command_info,
};
use hx_ipc::secret::Secret;
use hx_ipc::{Decoder, NoCmsgReader, ReadError};
use hx_provision::incus::Transport;
use tokio::io::Interest;
use tokio::net::{UnixListener, UnixStream};

use super::cancel::{CancelReason, CancelToken};
use super::daemon::{Ctx, Daemon, error_response};
use super::error::CmdError;
use super::log;
use super::progress::{MIN_INTERVAL_MS, ProgressSender};

/// What a successful read produced.
#[allow(clippy::large_enum_variant)] // one value per received frame; boxing only adds an allocation
enum Item {
    /// A decoded and validated frame.
    Frame(Incoming),
    /// A `Request` that decoded but broke a validation rule of the contract (a field rule, a wrong
    /// secret kind, no command): answered with `INVALID_ARGUMENT` instead of closing, as ipc.md 4
    /// says. `secrets` is how many secret frames it announced.
    Invalid {
        request_id: u64,
        secrets: usize,
        what: String,
    },
}

/// Largest body for which a rejected request is decoded again to find its `request_id`. The
/// normal path runs `hx_ipc`'s pre-scan before decoding (a body of empty repeated elements decodes
/// to far more memory than its size); this second decode skips that scan, so it is limited to
/// bodies small enough that the worst case is negligible.
const RECOVER_MAX_BODY: usize = 4096;

/// How a read ended badly.
#[derive(Debug)]
enum ConnError {
    /// The peer broke the protocol (framing, direction, ancillary data, secrets): close.
    Violation(String),
    /// A frame body did not arrive within 5 s of its header.
    BodyTimeout,
    /// Nothing arrived for the idle period.
    Idle,
    /// The transport failed or the peer went away.
    Io,
}

struct FrameReader {
    decoder: Decoder<PrivdPolicy>,
    body_deadline: Option<Instant>,
}

impl FrameReader {
    fn new() -> Self {
        Self {
            decoder: Decoder::new(PrivdPolicy::new(Side::Server)),
            body_deadline: None,
        }
    }

    /// The next decoded frame; `Ok(None)` is a clean end of stream. `idle` bounds the wait for the
    /// first byte of a frame; the rest of a frame is bounded by [`BODY_TIMEOUT`] from its header.
    async fn next(
        &mut self,
        stream: &UnixStream,
        idle: Duration,
    ) -> Result<Option<Item>, ConnError> {
        loop {
            let (wait, in_body) = if self.decoder.at_boundary() {
                self.body_deadline = None;
                (idle, false)
            } else {
                let dl = *self
                    .body_deadline
                    .get_or_insert_with(|| Instant::now() + BODY_TIMEOUT);
                (dl.saturating_duration_since(Instant::now()), true)
            };
            match tokio::time::timeout(wait, stream.readable()).await {
                Err(_) if in_body => return Err(ConnError::BodyTimeout),
                Err(_) => return Err(ConnError::Idle),
                Ok(Err(_)) => return Err(ConnError::Io),
                Ok(Ok(())) => {}
            }
            let mut outcome = None;
            let io = stream.try_io(Interest::READABLE, || {
                match self.decoder.read_from(&mut NoCmsgReader(stream)) {
                    Err(ReadError::Io(e)) if e.kind() == io::ErrorKind::WouldBlock => Err(e),
                    other => {
                        outcome = Some(other);
                        Ok(())
                    }
                }
            });
            match io {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(_) => return Err(ConnError::Io),
                Ok(()) => {}
            }
            match outcome {
                Some(Ok(Some(raw))) => {
                    self.body_deadline = None;
                    let keep = (raw.kind == privd::KIND_MESSAGE
                        && raw.body.len() <= RECOVER_MAX_BODY)
                        .then(|| raw.body.to_vec());
                    return match privd::decode(raw, Side::Server) {
                        Ok(i) => Ok(Some(Item::Frame(i))),
                        Err(hx_ipc::FrameError::Invalid(what)) => match recover_request(keep) {
                            Some((request_id, secrets)) => Ok(Some(Item::Invalid {
                                request_id,
                                secrets,
                                what: what.to_string(),
                            })),
                            None => Err(ConnError::Violation(what.to_string())),
                        },
                        Err(e) => Err(ConnError::Violation(e.to_string())),
                    };
                }
                Some(Ok(None)) => return Ok(None),
                Some(Err(e)) if e.is_violation() => {
                    return Err(ConnError::Violation(e.to_string()));
                }
                _ => return Err(ConnError::Io),
            }
        }
    }
}

/// The `request_id` and the number of announced secret slots of a body that failed validation, if
/// it is a `Request` with a non-zero id.
fn recover_request(body: Option<Vec<u8>>) -> Option<(u64, usize)> {
    use prost::Message;
    let frame = pb::Frame::decode(body?.as_slice()).ok()?;
    match frame.frame? {
        F::Request(r) if r.request_id != 0 => Some((r.request_id, r.secret_slots.len())),
        _ => None,
    }
}

/// Writes all of `bytes` within `timeout`.
async fn write_all(stream: &UnixStream, bytes: &[u8], timeout: Duration) -> Result<(), ()> {
    let deadline = Instant::now() + timeout;
    let mut off = 0;
    while off < bytes.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(());
        }
        match tokio::time::timeout(left, stream.writable()).await {
            Ok(Ok(())) => {}
            _ => return Err(()),
        }
        match stream.try_write(&bytes[off..]) {
            Ok(0) => return Err(()),
            Ok(n) => off += n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => return Err(()),
        }
    }
    Ok(())
}

async fn send(stream: &UnixStream, frame: F) -> Result<(), ()> {
    let bytes = privd::encode_message(&pb::Frame { frame: Some(frame) }, Side::Client)
        .map_err(|e| log::error(&format!("cannot encode a frame: {e}")))?;
    write_all(stream, &bytes, RESPONSE_WRITE_TIMEOUT).await
}

async fn send_error(stream: &UnixStream, request_id: u64, e: &CmdError) -> Result<(), ()> {
    send(stream, F::Response(error_response(request_id, e))).await
}

/// Server options.
#[derive(Debug, Clone, Copy)]
pub struct ServeOptions {
    /// Run the daily self-checks and the host-address watcher. Tests turn this off.
    pub background_tasks: bool,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            background_tasks: true,
        }
    }
}

/// Serves `listener` until `shutdown` completes. Each connection gets its own task.
pub async fn serve<T, S>(
    daemon: Arc<Daemon<T>>,
    listener: StdListener,
    opts: ServeOptions,
    shutdown: S,
) -> io::Result<()>
where
    T: Transport + Clone + 'static,
    S: Future<Output = ()>,
{
    listener.set_nonblocking(true)?;
    let listener = UnixListener::from_std(listener)?;
    if opts.background_tasks {
        // ipc.md 6.4: privd re-runs steps 1 to 3 of SetupHost at start.
        match daemon.refresh_host().await {
            Ok(true) => log::info("host ruleset re-applied at start"),
            Ok(false) => {}
            Err(e) => log::error(&format!("host refresh at start failed: {e}")),
        }
        tokio::spawn(background(daemon.clone()));
        // Isolation first: a desktop left with nesting on (or flagged) by a crash or a reboot is
        // stopped now, not when someone next asks for it.
        let d = daemon.clone();
        tokio::spawn(async move { d.enforce_isolation_all().await });
    }
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    tokio::spawn(serve_connection(daemon.clone(), stream));
                }
                Err(e) => {
                    log::warn(&format!("accept failed: {e}"));
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            },
            () = &mut shutdown => return Ok(()),
        }
    }
}

/// The daily self-checks, and the address watcher with a 30 s debounce (ipc.md 3 and 6.4).
async fn background<T: Transport + Clone + 'static>(d: Arc<Daemon<T>>) {
    let d2 = d.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
            let _ = d2.run_self_checks();
        }
    });
    let sorted = |v: Result<Vec<std::net::IpAddr>, CmdError>| {
        v.ok().map(|mut v| {
            v.sort();
            v
        })
    };
    let mut last = sorted(d.host_addresses(&[]).await);
    let mut pending: Option<Vec<std::net::IpAddr>> = None;
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        let now = sorted(d.host_addresses(&[]).await);
        if now == last || now.is_none() {
            pending = None;
            continue;
        }
        if pending == now {
            match d.refresh_host().await {
                Ok(_) => last = now,
                Err(e) => log::error(&format!("host refresh failed: {e}")),
            }
            pending = None;
        } else {
            pending = now;
        }
    }
}

async fn serve_connection<T: Transport + Clone + 'static>(d: Arc<Daemon<T>>, stream: UnixStream) {
    let Ok(peer) = peer_credentials(&stream) else {
        return;
    };
    let Some(role) = role_for_uid(peer.uid, d.cfg.gateway.uid) else {
        // Not root and not the gateway: closed without a reply (ipc.md 3).
        log::warn(&format!("refused a connection from uid {}", peer.uid));
        d.audit_notice(&format!("refused a connection from uid {}", peer.uid));
        return;
    };
    if role == Role::Gateway
        && let Err(why) = d.check_gateway_peer(&stream, peer.gid)
    {
        log::error(&format!("refused a Gateway connection: {why}"));
        d.audit_notice(&format!("refused a Gateway connection: {why}"));
        d.set_flag(None, super::state::Flag::HostAccountPolicy, true);
        return;
    }
    let Some(_slot) = d.admit_connection(role) else {
        log::warn("too many connections for this role; closing");
        return;
    };
    let mut conn = Conn {
        d,
        stream,
        reader: FrameReader::new(),
        role,
        peer,
        seen: HashSet::new(),
        pings: (Instant::now(), 0),
    };
    if let Err(why) = conn.run().await {
        log::warn(&format!("connection closed: {why}"));
    }
}

struct Conn<T: Transport + Clone + 'static> {
    d: Arc<Daemon<T>>,
    stream: UnixStream,
    reader: FrameReader,
    role: Role,
    peer: PeerCred,
    seen: HashSet<u64>,
    pings: (Instant, u32),
}

/// Most distinct request ids remembered per connection (a longer-lived connection is closed).
const MAX_SEEN: usize = 1 << 16;
/// `Ping` frames answered per second.
const PINGS_PER_SECOND: u32 = 10;

impl<T: Transport + Clone + 'static> Conn<T> {
    async fn run(&mut self) -> Result<(), String> {
        // Hello within 5 s.
        let hello = match self.reader.next(&self.stream, HELLO_TIMEOUT).await {
            Ok(Some(Item::Frame(Incoming::Message(pb::Frame {
                frame: Some(F::Hello(h)),
            })))) => h,
            Ok(Some(_)) => return Err("the first frame is not Hello".into()),
            Ok(None) => return Ok(()),
            Err(e) => return Err(format!("no valid Hello: {e:?}")),
        };
        if hello.major != VERSION_MAJOR {
            let e = CmdError::precondition(
                pb::ErrorDetail::Unspecified,
                "protocol major version mismatch",
            );
            let _ = send_error(&self.stream, 0, &e).await;
            return Err("version mismatch".into());
        }
        let ack = pb::HelloAck {
            major: VERSION_MAJOR,
            minor: VERSION_MINOR,
            privd_version: env!("CARGO_PKG_VERSION").to_string(),
            phase: self.d.phase().to_pb() as i32,
            role: self.role as i32,
        };
        send(&self.stream, F::HelloAck(ack))
            .await
            .map_err(|()| "cannot send HelloAck".to_string())?;

        loop {
            let incoming = match self.reader.next(&self.stream, IDLE_TIMEOUT).await {
                Ok(Some(Item::Frame(i))) => i,
                Ok(Some(Item::Invalid {
                    request_id,
                    secrets,
                    what,
                })) => {
                    self.reject(request_id, secrets, &what).await?;
                    continue;
                }
                Ok(None) => return Ok(()),
                Err(ConnError::Idle) => return Ok(()),
                Err(ConnError::Violation(why)) => {
                    return Err(format!("protocol violation: {why}"));
                }
                Err(e) => return Err(format!("{e:?}")),
            };
            match incoming {
                Incoming::Message(pb::Frame {
                    frame: Some(F::Ping(p)),
                }) => {
                    self.pong(p.nonce).await?;
                }
                Incoming::Message(pb::Frame {
                    frame: Some(F::Pong(_) | F::Cancel(_)),
                }) => {}
                Incoming::Message(pb::Frame {
                    frame: Some(F::Request(req)),
                }) => self.request(req).await?,
                Incoming::Message(_) => return Err("unexpected frame".into()),
                Incoming::Secret(_) => return Err("a secret frame without a request".into()),
            }
        }
    }

    async fn pong(&mut self, nonce: u64) -> Result<(), String> {
        let (since, n) = &mut self.pings;
        if since.elapsed() >= Duration::from_secs(1) {
            *since = Instant::now();
            *n = 0;
        }
        *n += 1;
        if *n > PINGS_PER_SECOND {
            return Ok(()); // over the rate: not answered
        }
        send(&self.stream, F::Pong(pb::Pong { nonce }))
            .await
            .map_err(|()| "cannot send Pong".into())
    }

    /// Answers a request that failed validation with `INVALID_ARGUMENT` and swallows the secret
    /// frames it announced (zeroized on drop), so the stream stays in sync. More than the
    /// contract's maximum of announced slots, or anything but secret frames, closes the connection.
    async fn reject(&mut self, request_id: u64, secrets: usize, what: &str) -> Result<(), String> {
        let admitted = self.d.admit_reject(self.role);
        let e = if admitted {
            CmdError::invalid(format!("invalid request: {what}"))
        } else {
            CmdError::exhausted("too many invalid requests per second", 1000)
        };
        send_error(&self.stream, request_id, &e)
            .await
            .map_err(|()| "cannot send an error".to_string())?;
        if admitted {
            self.d
                .audit_notice(&format!("a request failed validation: {what}"));
        }
        if secrets > privd::MAX_SECRET_SLOTS {
            return Err("too many secret slots announced".into());
        }
        let deadline = Instant::now() + BODY_TIMEOUT;
        for _ in 0..secrets {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.reader.next(&self.stream, left).await {
                Ok(Some(Item::Frame(Incoming::Secret(_)))) => {}
                _ => return Err("the secret frames of a rejected request did not follow".into()),
            }
        }
        Ok(())
    }

    /// One request: its secret frames, then the command while watching for `Cancel`.
    async fn request(&mut self, req: pb::Request) -> Result<(), String> {
        let id = req.request_id;
        let slots = req.secret_slots.clone();
        if self.seen.len() >= MAX_SEEN {
            return Err("too many requests on one connection".into());
        }
        if !self.seen.insert(id) {
            let _ = send_error(
                &self.stream,
                id,
                &CmdError::invalid("request_id was used before on this connection"),
            )
            .await;
            // Its secret frames, if any, would be unsolicited: do not stay in sync with them.
            return if slots.is_empty() {
                Ok(())
            } else {
                Err("duplicate request id with secrets".into())
            };
        }
        let secrets = match self.read_secrets(id, &slots).await {
            Ok(s) => s,
            Err(why) => {
                let _ = send_error(&self.stream, id, &CmdError::invalid(why)).await;
                // The framing of what follows cannot be trusted any more.
                return Err(format!("secret frames rejected: {why}"));
            }
        };

        let Some(cmd) = req.command.as_ref() else {
            return Err("request without a command".into());
        };
        let deadline = Duration::from_millis(u64::from(
            command_info(cmd).effective_deadline_ms(req.deadline_ms),
        ));
        let cancel = CancelToken::new();
        let (progress, queue) = ProgressSender::new(id);
        let ctx = Ctx {
            role: self.role,
            peer: self.peer,
            request_id: id,
            secrets,
            cancel: cancel.clone(),
            progress,
        };
        let d = self.d.clone();
        let fut = d.handle(req, ctx);
        tokio::pin!(fut);
        let sleep = tokio::time::sleep(deadline);
        tokio::pin!(sleep);
        let mut deadline_fired = false;
        let mut closed = false;
        let mut tick = tokio::time::interval(Duration::from_millis(MIN_INTERVAL_MS));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let response = loop {
            tokio::select! {
                resp = &mut fut => break resp,
                () = &mut sleep, if !deadline_fired => {
                    deadline_fired = true;
                    cancel.cancel(CancelReason::Deadline);
                }
                _ = tick.tick(), if !closed => {
                    if let Some(p) = queue.pop()
                        && send(&self.stream, F::Progress(p)).await.is_err()
                    {
                        closed = true;
                        cancel.cancel(CancelReason::Closed);
                    }
                }
                frame = self.reader.next(&self.stream, IDLE_TIMEOUT), if !closed => {
                    match frame {
                        Ok(Some(Item::Invalid { request_id, secrets, what })) => {
                            // A second, invalid request while one runs: answer it, stay in sync.
                            if self.reject(request_id, secrets, &what).await.is_err() {
                                closed = true;
                                cancel.cancel(CancelReason::Closed);
                            }
                        }
                        Ok(Some(Item::Frame(Incoming::Message(pb::Frame { frame: Some(f) })))) => match f {
                            F::Cancel(c) if c.request_id == id => cancel.cancel(CancelReason::Cancelled),
                            F::Cancel(_) | F::Pong(_) => {}
                            F::Ping(p) => {
                                if self.pong(p.nonce).await.is_err() {
                                    closed = true;
                                    cancel.cancel(CancelReason::Closed);
                                }
                            }
                            F::Request(second) => {
                                // One request in flight per connection.
                                let sid = second.request_id;
                                let ok = second.secret_slots.is_empty();
                                let e = CmdError::exhausted("one request at a time per connection", 0);
                                let _ = send_error(&self.stream, sid, &e).await;
                                if !ok {
                                    closed = true;
                                    cancel.cancel(CancelReason::Closed);
                                }
                            }
                            _ => {
                                closed = true;
                                cancel.cancel(CancelReason::Closed);
                            }
                        },
                        // Idle while a long command runs is normal.
                        Err(ConnError::Idle) => {}
                        _ => {
                            closed = true;
                            cancel.cancel(CancelReason::Closed);
                        }
                    }
                }
            }
        };
        if closed {
            return Err("connection lost while a request was running".into());
        }
        send(&self.stream, F::Response(response))
            .await
            .map_err(|()| "the peer did not read the Response in time".to_string())
    }

    /// Reads the kind-2 frames of `slots`, each matching `request_id`, a declared and unfilled
    /// slot and its length and character rules, all within 5 s of the request.
    async fn read_secrets(
        &mut self,
        request_id: u64,
        slots: &[pb::SecretSlot],
    ) -> Result<Vec<Option<Secret>>, &'static str> {
        let mut secrets: Vec<Option<Secret>> = (0..slots.len()).map(|_| None).collect();
        if slots.is_empty() {
            return Ok(secrets);
        }
        let deadline = Instant::now() + BODY_TIMEOUT;
        for _ in 0..slots.len() {
            let left = deadline.saturating_duration_since(Instant::now());
            let frame = match self.reader.next(&self.stream, left).await {
                Ok(Some(Item::Frame(Incoming::Secret(f)))) => f,
                Ok(Some(_)) => return Err("a secret frame was expected"),
                Err(ConnError::Idle) => return Err("the secret frame is late"),
                _ => return Err("the secret frame did not arrive"),
            };
            if frame.request_id != request_id {
                return Err("the secret frame belongs to another request");
            }
            let slot = usize::from(frame.slot);
            let (Some(decl), Some(cell)) = (slots.get(slot), secrets.get_mut(slot)) else {
                return Err("the secret frame names an undeclared slot");
            };
            if cell.is_some() {
                return Err("the secret slot was filled twice");
            }
            if check_secret_against_slot(decl, &frame.secret).is_err() {
                return Err("the secret does not match its slot");
            }
            *cell = Some(frame.secret);
        }
        Ok(secrets)
    }
}

/// Whether a code is one that tells the caller to try again later (used by clients and tests).
pub fn is_retryable(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::ResourceExhausted | ErrorCode::Unavailable | ErrorCode::DeadlineExceeded
    )
}
