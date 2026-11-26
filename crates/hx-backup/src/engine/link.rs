//! The worker's end of the repository link (`docs/ipc.md` Part 3) and a `rustic_core` backend on
//! top of it.
//!
//! [`Link`] owns the one connection to `hx-privd`. [`Link::accept`] runs the handshake on the
//! calling thread (`Hello`, `HelloAck`, `Job` and its secret frames); [`Link::start`] then spawns
//! two threads:
//!
//! * the **reader** decodes every frame, tells the shared [`LinkState`] about it, hands responses
//!   and data frames to the request that waits for them, answers `Ping`, raises the cancel token on
//!   `Cancel`, and ends the session on a violation, a lost connection or 60 s of silence;
//! * the **writer** takes finished frames from a queue and writes them. Nobody else writes to the
//!   socket, so the reader never blocks on a write (a reader stuck behind a one-megabyte upload
//!   would stop reading while `hx-privd` is stuck writing to it: a deadlock).
//!
//! [`LinkBackend`] implements `ReadBackend` and `WriteBackend` for any number of calling threads
//! (rustic uses a pool): a call takes one of the 8 request slots (4 for writes), blocking while
//! none is free, so the limits of ipc.md §25 are never violated. There is **no per-request timeout**
//! (§32): privd guarantees an answer.
//!
//! # Errors
//!
//! A `RepoError` of privd becomes a `RusticError` of kind `Backend` whose source is a
//! [`BackendFault`]; the first class other than `NOT_FOUND` is remembered
//! ([`Link::first_repo_error`]) so that the job runner can report `WorkerError::REPO`. After
//! `Cancel` every call fails at once with [`BackendFault::Cancelled`] and sends nothing, which is
//! what stops a rustic call that cannot be interrupted from inside.
//!
//! # Lock order
//!
//! `state` before `pending`; the outbox lock is never held with either. Nothing blocks while holding
//! `state` except the condition variable that waits on it.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;
use hx_ipc::ReadError;
use hx_ipc::frame::Decoder;
use hx_ipc::recv::NoCmsgReader;
use hx_ipc::repo::{
    self, DataFrame, Endpoint, Incoming, LinkState, MAX_DATA_PAYLOAD, RepoFramePolicy,
    WORKER_SILENCE_TIMEOUT, pb,
};
use hx_ipc::secret::Secret;
use rustic_core::{
    BytesList, ErrorKind, FileType, Id, ReadBackend, RusticError, RusticResult, WriteBackend,
};

use super::CancelToken;

/// Frames a request thread may have in flight with the writer: bounds the memory of queued uploads
/// (two data frames) while keeping the socket busy.
const MAX_QUEUED_DATA_BYTES: usize = 2 * MAX_DATA_PAYLOAD;
/// Events a request may have waiting for its thread before the reader waits (back-pressure).
const EVENT_DEPTH: usize = 4;
/// A thread that waits for a slot or for the end of the requests wakes at least this often, so that a
/// failure that raced its wait is seen.
const WAIT_SLICE: Duration = Duration::from_millis(100);
/// How long a failed `JobResult` waits for the discarded downloads to end before `Bye`
/// (ipc.md §32).
pub const DISCARD_WAIT: Duration = Duration::from_secs(10);

/// Why the link ended. The worker has no `JobResult` for any of these (ipc.md §24).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LinkFailure {
    /// privd (or this end) broke a rule of the link; the text names the rule, never peer data.
    #[error("protocol violation: {0}")]
    Violation(&'static str),
    /// The connection ended or failed.
    #[error("the repository link was lost")]
    Lost,
    /// Nothing arrived from privd for the silence timeout.
    #[error("privd was silent for too long")]
    Silent,
}

/// What a backend call failed with, as the `source` of the `RusticError`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BackendFault {
    /// privd answered with this error class.
    #[error("repository error {0:?}")]
    Repo(pb::ErrorClass),
    /// The object does not exist (`RepoError` class `NOT_FOUND`).
    #[error("not found")]
    NotFound,
    /// The job was cancelled; the call sent nothing.
    #[error("cancelled")]
    Cancelled,
    /// The link failed.
    #[error("{0}")]
    Link(LinkFailure),
    /// The request itself is refused by the codec (a size over the cap of its type, for example).
    #[error("request refused by the link codec: {0}")]
    Refused(&'static str),
    /// The answer does not fit the request. Cannot happen when `LinkState` accepted it.
    #[error("unexpected answer")]
    Unexpected,
}

fn fault(f: BackendFault) -> Box<RusticError> {
    RusticError::with_source(ErrorKind::Backend, "The repository link failed.", f)
}

impl BackendFault {
    /// The `RusticError` a backend call returns for this fault.
    #[must_use]
    pub fn into_rustic(self) -> Box<RusticError> {
        fault(self)
    }
}

/// Timing of a link; the defaults are the contract's.
#[derive(Debug, Clone, Copy)]
pub struct LinkOptions {
    /// The worker exits after this long without anything from privd (ipc.md §32: 60 s).
    pub silence_timeout: Duration,
}

impl Default for LinkOptions {
    fn default() -> Self {
        Self {
            silence_timeout: WORKER_SILENCE_TIMEOUT,
        }
    }
}

/// What the handshake delivered.
#[derive(Debug)]
pub struct JobStart {
    /// The validated `Job`.
    pub job: pb::Job,
    /// The secrets by slot, as declared by the job (slot 0, then slot 1 when present). Zeroized on
    /// drop.
    pub secrets: Vec<(u8, Secret)>,
    /// `Cancel` already arrived during the handshake.
    pub cancelled: bool,
}

// ----- the writer's queue -----

enum Out {
    Frame(Vec<u8>),
    Data {
        header: [u8; repo::DATA_FRAME_HEADER_LEN],
        payload: Bytes,
    },
}

#[derive(Default)]
struct OutQueue {
    items: VecDeque<Out>,
    data_bytes: usize,
    writing: bool,
    closed: bool,
}

#[derive(Default)]
struct Outbox {
    q: Mutex<OutQueue>,
    cv: Condvar,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Outbox {
    /// A small frame: never waits (the reader's `Pong` must not block).
    fn push_control(&self, frame: Vec<u8>) -> bool {
        let mut q = lock(&self.q);
        if q.closed {
            return false;
        }
        q.items.push_back(Out::Frame(frame));
        self.cv.notify_all();
        true
    }

    /// A data frame: waits while two frames are already queued.
    fn push_data(&self, header: [u8; repo::DATA_FRAME_HEADER_LEN], payload: Bytes) -> bool {
        let mut q = lock(&self.q);
        while q.data_bytes >= MAX_QUEUED_DATA_BYTES && !q.closed {
            q = self.cv.wait(q).unwrap_or_else(PoisonError::into_inner);
        }
        if q.closed {
            return false;
        }
        q.data_bytes += payload.len();
        q.items.push_back(Out::Data { header, payload });
        self.cv.notify_all();
        true
    }

    fn next(&self) -> Option<Out> {
        let mut q = lock(&self.q);
        loop {
            if q.closed {
                return None;
            }
            if let Some(item) = q.items.pop_front() {
                if let Out::Data { payload, .. } = &item {
                    q.data_bytes -= payload.len();
                }
                q.writing = true;
                self.cv.notify_all();
                return Some(item);
            }
            q = self.cv.wait(q).unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn written(&self) {
        lock(&self.q).writing = false;
        self.cv.notify_all();
    }

    /// Waits until everything queued has been written. False if the link failed first.
    fn flush(&self) -> bool {
        let mut q = lock(&self.q);
        while (!q.items.is_empty() || q.writing) && !q.closed {
            q = self.cv.wait(q).unwrap_or_else(PoisonError::into_inner);
        }
        !q.closed
    }

    fn close(&self) {
        lock(&self.q).closed = true;
        self.cv.notify_all();
    }
}

// ----- requests in flight -----

enum Event {
    Response(pb::RepoResponse),
    Data(DataFrame),
}

struct Pending {
    tx: SyncSender<Event>,
    /// `ReadBegin` was answered: the request is a download whose data may still arrive.
    download_begun: bool,
}

struct Inner {
    state: Mutex<LinkState>,
    /// Signalled when a request finished, on cancel, on failure.
    slots: Condvar,
    pending: Mutex<HashMap<u64, Pending>>,
    outbox: Outbox,
    next_req: AtomicU64,
    cancel: CancelToken,
    cancelled: AtomicBool,
    failure: OnceLock<LinkFailure>,
    first_repo_error: OnceLock<pb::ErrorClass>,
    snapshot_write_started: AtomicBool,
    /// `Bye` was sent: the end of the session is orderly, nothing is a failure any more.
    closed: AtomicBool,
}

impl Inner {
    fn failed(&self) -> Option<LinkFailure> {
        self.failure.get().copied()
    }

    fn fail(&self, why: LinkFailure) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        let _ = self.failure.set(why);
        self.cancel.cancel();
        // Dropping the senders wakes every thread that waits for an answer.
        lock(&self.pending).clear();
        self.outbox.close();
        // `fail` can be called with `state` held (a violation found while sending), so it must
        // not take that lock. A waiter that missed this notification wakes on its own within
        // `WAIT_SLICE` and sees the flag.
        self.slots.notify_all();
    }

    fn violation(&self, what: &'static str) -> LinkFailure {
        self.fail(LinkFailure::Violation(what));
        self.failed().unwrap_or(LinkFailure::Violation(what))
    }

    fn check_usable(&self) -> Result<(), BackendFault> {
        if let Some(f) = self.failed() {
            return Err(BackendFault::Link(f));
        }
        if self.cancelled.load(Ordering::SeqCst) {
            return Err(BackendFault::Cancelled);
        }
        Ok(())
    }

    /// Takes a request slot (waiting for one), registers the request and queues its frame.
    fn begin(
        &self,
        op: pb::repo_request::Op,
        is_write: bool,
    ) -> Result<(u64, Receiver<Event>), BackendFault> {
        let mut st = lock(&self.state);
        loop {
            self.check_usable()?;
            if st.can_request(is_write) {
                break;
            }
            if st.is_closed() || st.result_seen() {
                return Err(BackendFault::Link(LinkFailure::Violation(
                    "request after the end of the job",
                )));
            }
            st = self
                .slots
                .wait_timeout(st, WAIT_SLICE)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        let req_id = self.next_req.fetch_add(1, Ordering::SeqCst);
        let frame = pb::RepoFrame {
            frame: Some(pb::repo_frame::Frame::Request(pb::RepoRequest {
                req_id,
                op: Some(op),
            })),
        };
        // Refused here, before the state sees it: a refused request must not poison the link.
        let wire = repo::encode_message(&frame, Endpoint::PrivdWorkerLink)
            .map_err(|e| BackendFault::Refused(refusal(&e)))?;
        st.sent_message(&frame)
            .map_err(|e| BackendFault::Link(self.violation(e.0)))?;
        let (tx, rx) = mpsc::sync_channel(EVENT_DEPTH);
        {
            // `fail` sets the failure before it clears `pending` under this lock, so a request
            // registered after the clear sees the failure here and never waits for an answer
            // that cannot come.
            let mut pending = lock(&self.pending);
            if let Some(f) = self.failed() {
                return Err(BackendFault::Link(f));
            }
            pending.insert(
                req_id,
                Pending {
                    tx,
                    download_begun: false,
                },
            );
        }
        drop(st);
        if !self.outbox.push_control(wire) {
            return Err(BackendFault::Link(
                self.failed().unwrap_or(LinkFailure::Lost),
            ));
        }
        Ok((req_id, rx))
    }

    /// One data frame of an upload.
    fn send_data(&self, req_id: u64, end: bool, payload: Bytes) -> Result<(), BackendFault> {
        let header = repo::encode_data_header(req_id, end, payload.len())
            .map_err(|e| BackendFault::Refused(refusal(&e)))?;
        let disp = lock(&self.state)
            .sent_data(req_id, end, payload.len())
            .map_err(|e| BackendFault::Link(self.violation(e.0)))?;
        if disp.done == Some(req_id) {
            // The `END` that closes an aborted upload finishes the request: free its slot.
            self.finished(req_id);
        }
        if self.outbox.push_data(header, payload) {
            Ok(())
        } else {
            Err(BackendFault::Link(
                self.failed().unwrap_or(LinkFailure::Lost),
            ))
        }
    }

    fn recv(&self, rx: &Receiver<Event>) -> Result<Event, BackendFault> {
        rx.recv()
            .map_err(|_| BackendFault::Link(self.failed().unwrap_or(LinkFailure::Lost)))
    }

    /// Waits for the next frame of a download that has begun. A `Cancel` abandons it: the reader
    /// goes on taking the rest of the stream off the link (ipc.md §26, §32) and nobody waits for it.
    fn recv_stream(&self, rx: &Receiver<Event>) -> Result<Event, BackendFault> {
        loop {
            match rx.recv_timeout(WAIT_SLICE) {
                Ok(e) => return Ok(e),
                Err(RecvTimeoutError::Timeout) => {
                    if self.cancelled.load(Ordering::SeqCst) {
                        return Err(BackendFault::Cancelled);
                    }
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(BackendFault::Link(
                        self.failed().unwrap_or(LinkFailure::Lost),
                    ));
                }
            }
        }
    }

    /// Turns a privd error answer into the fault of the call and remembers its class.
    fn repo_fault(&self, e: &pb::RepoError) -> BackendFault {
        let class = pb::ErrorClass::try_from(e.class).unwrap_or(pb::ErrorClass::Internal);
        if class == pb::ErrorClass::NotFound {
            return BackendFault::NotFound;
        }
        let _ = self.first_repo_error.set(class);
        BackendFault::Repo(class)
    }

    fn answer(&self, rx: &Receiver<Event>) -> Result<pb::repo_response::Result, BackendFault> {
        match self.recv(rx)? {
            Event::Response(r) => match r.result {
                Some(pb::repo_response::Result::Error(e)) => Err(self.repo_fault(&e)),
                Some(other) => Ok(other),
                None => Err(BackendFault::Unexpected),
            },
            Event::Data(_) => Err(BackendFault::Unexpected),
        }
    }

    fn plain(&self, op: pb::repo_request::Op) -> Result<(), BackendFault> {
        let (_, rx) = self.begin(op, false)?;
        match self.answer(&rx)? {
            pb::repo_response::Result::Done(_) => Ok(()),
            _ => Err(BackendFault::Unexpected),
        }
    }

    /// A download: `ReadBegin`, then data frames up to `END`.
    fn download(
        &self,
        op: pb::repo_request::Op,
        exact: Option<u32>,
    ) -> Result<Bytes, BackendFault> {
        let (_, rx) = self.begin(op, false)?;
        let size = match self.answer(&rx)? {
            pb::repo_response::Result::ReadBegin(b) => b.size,
            _ => return Err(BackendFault::Unexpected),
        };
        // A pack read that comes back short is a damaged repository, not data.
        let short = exact.is_some_and(|want| size != want);
        let mut buf = Vec::with_capacity(size as usize);
        loop {
            match self.recv_stream(&rx)? {
                Event::Data(d) => {
                    buf.extend_from_slice(&d.payload);
                    if d.end {
                        break;
                    }
                }
                Event::Response(_) => return Err(BackendFault::Unexpected),
            }
        }
        if short {
            return Err(BackendFault::Refused("short read"));
        }
        Ok(Bytes::from(buf))
    }

    fn list(&self, ty: pb::ObjectType) -> Result<Vec<(Id, u32)>, BackendFault> {
        let (_, rx) = self.begin(
            pb::repo_request::Op::List(pb::List {
                object_type: ty as i32,
            }),
            false,
        )?;
        let mut out = Vec::new();
        loop {
            match self.answer(&rx)? {
                pb::repo_response::Result::ListPage(p) => {
                    for e in &p.entries {
                        let id = id_from(&e.id).ok_or(BackendFault::Unexpected)?;
                        out.push((id, e.size));
                    }
                    if p.last {
                        return Ok(out);
                    }
                }
                _ => return Err(BackendFault::Unexpected),
            }
        }
    }

    fn upload(
        &self,
        ty: pb::ObjectType,
        id: Bytes,
        content: &BytesList,
    ) -> Result<(), BackendFault> {
        let size = u32::try_from(content.size())
            .map_err(|_| BackendFault::Refused("object larger than 4 GiB"))?;
        let (req_id, rx) = self.begin(
            pb::repo_request::Op::Write(pb::Write {
                object_type: ty as i32,
                id,
                size,
            }),
            true,
        )?;
        if ty == pb::ObjectType::Snapshot {
            self.snapshot_write_started.store(true, Ordering::SeqCst);
        }
        let mut chunks: Vec<Bytes> = Vec::new();
        for part in content.slice() {
            let mut rest = part.clone();
            while !rest.is_empty() {
                let n = rest.len().min(MAX_DATA_PAYLOAD);
                chunks.push(rest.split_to(n));
            }
        }
        let mut end_sent = false;
        let mut early: Option<pb::RepoResponse> = None;
        if chunks.is_empty() {
            self.send_data(req_id, true, Bytes::new())?;
            end_sent = true;
        } else {
            let last = chunks.len() - 1;
            for (i, chunk) in chunks.into_iter().enumerate() {
                // privd may answer `Error` while the stream is still running: stop sending.
                match rx.try_recv() {
                    Ok(Event::Response(r)) => {
                        early = Some(r);
                        break;
                    }
                    Ok(Event::Data(_)) => return Err(BackendFault::Unexpected),
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => {
                        return Err(BackendFault::Link(
                            self.failed().unwrap_or(LinkFailure::Lost),
                        ));
                    }
                }
                self.send_data(req_id, i == last, chunk)?;
                end_sent = i == last;
            }
        }
        if let Some(r) = early {
            // The aborted upload is closed with an (empty) `END` of ours, unless it was sent.
            if !end_sent {
                self.send_data(req_id, true, Bytes::new())?;
            }
            return match r.result {
                Some(pb::repo_response::Result::Error(e)) => Err(self.repo_fault(&e)),
                _ => Err(BackendFault::Unexpected),
            };
        }
        match self.answer(&rx)? {
            pb::repo_response::Result::Done(_) => Ok(()),
            _ => Err(BackendFault::Unexpected),
        }
    }

    // ----- the reader -----

    fn reader_loop(self: &Arc<Self>, mut decoder: Decoder<RepoFramePolicy>, stream: UnixStream) {
        let mut input = NoCmsgReader(&stream);
        loop {
            let raw = match decoder.read_from(&mut input) {
                Ok(Some(raw)) => raw,
                Ok(None) => return self.fail(LinkFailure::Lost),
                Err(ReadError::Io(e))
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return self.fail(LinkFailure::Silent);
                }
                Err(ReadError::Io(_)) => return self.fail(LinkFailure::Lost),
                Err(e) => {
                    tracing::warn!(error = %e, "framing error on the repository link");
                    return self.fail(LinkFailure::Violation("framing"));
                }
            };
            let incoming = match repo::decode(raw, Endpoint::Worker) {
                Ok(i) => i,
                Err(e) => {
                    tracing::warn!(error = %e, "invalid frame on the repository link");
                    return self.fail(LinkFailure::Violation("invalid frame"));
                }
            };
            // The guard must not live into the error arm: `fail` takes the same lock.
            let verdict = lock(&self.state).received(&incoming);
            let disp = match verdict {
                Ok(d) => d,
                Err(e) => return self.fail(LinkFailure::Violation(e.0)),
            };
            match incoming {
                Incoming::Message(frame) => {
                    if !self.dispatch_message(frame, disp.done) {
                        return;
                    }
                }
                Incoming::Data(d) => {
                    if !disp.discard {
                        self.deliver(d.stream_id, Event::Data(d.clone()));
                    }
                    if disp.done == Some(d.stream_id) {
                        self.finished(d.stream_id);
                    }
                }
                // Cannot happen after the handshake: `LinkState` refuses a late secret.
                Incoming::Secret(_) => return self.fail(LinkFailure::Violation("late secret")),
            }
        }
    }

    /// False when the reader must stop.
    fn dispatch_message(&self, frame: pb::RepoFrame, done: Option<u64>) -> bool {
        use pb::repo_frame::Frame as F;
        match frame.frame {
            Some(F::Response(r)) => {
                let id = r.req_id;
                if matches!(r.result, Some(pb::repo_response::Result::ReadBegin(_)))
                    && let Some(p) = lock(&self.pending).get_mut(&id)
                {
                    p.download_begun = true;
                }
                self.deliver(id, Event::Response(r));
                if done == Some(id) {
                    self.finished(id);
                }
                true
            }
            Some(F::Ping(p)) => {
                if self.closed.load(Ordering::SeqCst) {
                    // `Bye` is queued or sent: a `Pong` would be refused, and nothing needs it.
                    return true;
                }
                let pong = pb::RepoFrame {
                    frame: Some(F::Pong(pb::Pong { nonce: p.nonce })),
                };
                let sent = lock(&self.state).sent_message(&pong).is_ok();
                if !sent {
                    self.fail(LinkFailure::Violation("pong"));
                    return false;
                }
                match repo::encode_message(&pong, Endpoint::PrivdWorkerLink) {
                    Ok(wire) => {
                        self.outbox.push_control(wire);
                        true
                    }
                    Err(_) => {
                        self.fail(LinkFailure::Violation("pong"));
                        false
                    }
                }
            }
            Some(F::Cancel(_)) => {
                self.cancelled.store(true, Ordering::SeqCst);
                self.cancel.cancel();
                drop(lock(&self.state));
                self.slots.notify_all();
                true
            }
            Some(F::Bye(_)) => {
                // privd ended the session before the job did.
                self.fail(LinkFailure::Lost);
                false
            }
            // `Pong` needs no action; the state machine refused everything else.
            _ => true,
        }
    }

    /// Hands an event to the request's thread. The sender is cloned out of the map first: the reader
    /// must not wait for a slow thread while holding the lock.
    fn deliver(&self, req_id: u64, event: Event) {
        let tx = lock(&self.pending).get(&req_id).map(|p| p.tx.clone());
        if let Some(tx) = tx {
            // A thread that is gone (rustic gave up) simply does not read it.
            let _ = tx.send(event);
        }
    }

    fn finished(&self, req_id: u64) {
        lock(&self.pending).remove(&req_id);
        drop(lock(&self.state));
        self.slots.notify_all();
    }

    fn writer_loop(&self, mut stream: UnixStream) {
        while let Some(item) = self.outbox.next() {
            let r = match &item {
                Out::Frame(b) => stream.write_all(b),
                Out::Data { header, payload } => stream
                    .write_all(header)
                    .and_then(|()| stream.write_all(payload)),
            };
            self.outbox.written();
            if r.is_err() {
                self.outbox.close();
                self.fail(LinkFailure::Lost);
                return;
            }
        }
    }
}

fn refusal(e: &hx_ipc::FrameError) -> &'static str {
    match e {
        hx_ipc::FrameError::Invalid(what) => what,
        hx_ipc::FrameError::TooLong { .. } => "frame too long",
        _ => "invalid frame",
    }
}

fn id_bytes(id: &Id) -> [u8; repo::ID_LEN] {
    let hex = id.to_hex();
    let mut out = [0u8; repo::ID_LEN];
    for (i, pair) in hex
        .as_str()
        .as_bytes()
        .chunks(2)
        .enumerate()
        .take(out.len())
    {
        let digit = |c: u8| match c {
            b'0'..=b'9' => c - b'0',
            _ => c.to_ascii_lowercase() - b'a' + 10,
        };
        out[i] = digit(pair[0]) << 4 | digit(pair[1]);
    }
    out
}

/// The id as it goes on the wire. `CONFIG` has no id in the contract (all zero); rustic names it by
/// the hash of its content when it writes it and by the id of a listing when it reads it, and its own
/// backends ignore the name of the config file.
fn wire_id(t: FileType, id: &Id) -> Bytes {
    if t == FileType::Config {
        Bytes::from_static(&[0u8; repo::ID_LEN])
    } else {
        Bytes::copy_from_slice(&id_bytes(id))
    }
}

fn id_from(bytes: &[u8]) -> Option<Id> {
    <[u8; repo::ID_LEN]>::try_from(bytes).ok().map(Id::new)
}

fn object_type(t: FileType) -> pb::ObjectType {
    match t {
        FileType::Config => pb::ObjectType::Config,
        FileType::Key => pb::ObjectType::Key,
        FileType::Snapshot => pb::ObjectType::Snapshot,
        FileType::Index => pb::ObjectType::Index,
        FileType::Pack => pb::ObjectType::Pack,
    }
}

// ----- the public link -----

struct ReaderParts {
    decoder: Decoder<RepoFramePolicy>,
    read: UnixStream,
    write: UnixStream,
}

/// The worker's end of one repository link. See the module documentation.
pub struct Link {
    inner: Arc<Inner>,
    parts: Mutex<Option<ReaderParts>>,
}

impl Link {
    /// Runs the handshake on `stream` (`Hello`, `HelloAck`, `Job`, the declared secrets) on the
    /// calling thread, which must be the only thread of the process that matters: nothing else may
    /// read or write the stream. `software` is `HelloAck.software` (1 to 64 bytes of
    /// `[A-Za-z0-9._+-]`).
    ///
    /// # Errors
    /// [`LinkFailure`]: nothing was sent that could be taken for a job result.
    pub fn accept(
        stream: UnixStream,
        software: &str,
        options: LinkOptions,
    ) -> Result<(Self, JobStart), LinkFailure> {
        stream
            .set_read_timeout(Some(options.silence_timeout))
            .map_err(|_| LinkFailure::Lost)?;
        let mut read = stream;
        let mut write = read.try_clone().map_err(|_| LinkFailure::Lost)?;
        let mut decoder = Decoder::new(RepoFramePolicy::new(Endpoint::Worker));
        let mut state = LinkState::new(Endpoint::Worker);
        let mut job = None;
        let mut secrets: Vec<(u8, Secret)> = Vec::new();
        let mut cancelled = false;
        let mut send = |state: &mut LinkState, frame: pb::RepoFrame| -> Result<(), LinkFailure> {
            let wire = repo::encode_message(&frame, Endpoint::PrivdWorkerLink)
                .map_err(|_| LinkFailure::Violation("our own frame is invalid"))?;
            state
                .sent_message(&frame)
                .map_err(|e| LinkFailure::Violation(e.0))?;
            write.write_all(&wire).map_err(|_| LinkFailure::Lost)
        };
        loop {
            let incoming = read_incoming(&mut decoder, &mut read)?;
            state
                .received(&incoming)
                .map_err(|e| LinkFailure::Violation(e.0))?;
            match incoming {
                Incoming::Message(f) => {
                    use pb::repo_frame::Frame as F;
                    match f.frame {
                        Some(F::Hello(_)) => send(
                            &mut state,
                            pb::RepoFrame {
                                frame: Some(F::HelloAck(pb::HelloAck {
                                    major: repo::VERSION_MAJOR,
                                    minor: repo::VERSION_MINOR,
                                    software: software.to_owned(),
                                })),
                            },
                        )?,
                        Some(F::Ping(p)) => send(
                            &mut state,
                            pb::RepoFrame {
                                frame: Some(F::Pong(pb::Pong { nonce: p.nonce })),
                            },
                        )?,
                        Some(F::Job(j)) => job = Some(j),
                        Some(F::Cancel(_)) => cancelled = true,
                        Some(F::Bye(_)) => return Err(LinkFailure::Lost),
                        _ => {}
                    }
                }
                Incoming::Secret(sf) => secrets.push((sf.slot, sf.secret)),
                Incoming::Data(_) => return Err(LinkFailure::Violation("data before the job")),
            }
            if state.job_ready() {
                break;
            }
        }
        let job = job.ok_or(LinkFailure::Violation("no job"))?;
        let inner = Arc::new(Inner {
            state: Mutex::new(state),
            slots: Condvar::new(),
            pending: Mutex::new(HashMap::new()),
            outbox: Outbox::default(),
            next_req: AtomicU64::new(1),
            cancel: CancelToken::new(),
            cancelled: AtomicBool::new(cancelled),
            failure: OnceLock::new(),
            first_repo_error: OnceLock::new(),
            snapshot_write_started: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        });
        if cancelled {
            inner.cancel.cancel();
        }
        let link = Link {
            inner,
            parts: Mutex::new(Some(ReaderParts {
                decoder,
                read,
                write,
            })),
        };
        Ok((
            link,
            JobStart {
                job,
                secrets,
                cancelled,
            },
        ))
    }

    /// Starts the reader and the writer thread. Call it once, after the sandbox is in place.
    ///
    /// # Panics
    /// If called twice.
    pub fn start(&self) -> io::Result<()> {
        let parts = lock(&self.parts)
            .take()
            .expect("Link::start is called once");
        let reader = Arc::clone(&self.inner);
        thread::Builder::new()
            .name("hx-link-read".into())
            .spawn(move || reader.reader_loop(parts.decoder, parts.read))?;
        let writer = Arc::clone(&self.inner);
        thread::Builder::new()
            .name("hx-link-write".into())
            .spawn(move || writer.writer_loop(parts.write))?;
        Ok(())
    }

    /// A backend for the engine. Clones share the link.
    #[must_use]
    pub fn backend(&self) -> LinkBackend {
        LinkBackend {
            inner: Arc::clone(&self.inner),
        }
    }

    /// The token that `Cancel` (and a failed link) raises. Give it to the engine.
    #[must_use]
    pub fn cancel_token(&self) -> CancelToken {
        self.inner.cancel.clone()
    }

    /// `Cancel` has arrived: the backend sends nothing new.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::SeqCst)
    }

    /// Why the link ended, if it did.
    #[must_use]
    pub fn failure(&self) -> Option<LinkFailure> {
        self.inner.failed()
    }

    /// The first `RepoError` class other than `NOT_FOUND` that privd answered, for
    /// `WorkerError::REPO`.
    #[must_use]
    pub fn first_repo_error(&self) -> Option<pb::ErrorClass> {
        self.inner.first_repo_error.get().copied()
    }

    /// A `Write` of a `SNAPSHOT` object has been requested (the `WRITE_SNAPSHOT` phase).
    #[must_use]
    pub fn snapshot_write_started(&self) -> bool {
        self.inner.snapshot_write_started.load(Ordering::SeqCst)
    }

    /// Sends one `Progress`. The caller paces them (at most 2 a second). An error means the link is
    /// finished; nothing is sent then.
    ///
    /// # Errors
    /// [`LinkFailure`].
    pub fn send_progress(&self, progress: pb::Progress) -> Result<(), LinkFailure> {
        if let Some(f) = self.inner.failed() {
            return Err(f);
        }
        let frame = pb::RepoFrame {
            frame: Some(pb::repo_frame::Frame::Progress(progress)),
        };
        let wire = repo::encode_message(&frame, Endpoint::PrivdWorkerLink)
            .map_err(|_| LinkFailure::Violation("progress"))?;
        lock(&self.inner.state)
            .sent_message(&frame)
            .map_err(|e| self.inner.violation(e.0))?;
        if self.inner.outbox.push_control(wire) {
            Ok(())
        } else {
            Err(self.inner.failed().unwrap_or(LinkFailure::Lost))
        }
    }

    /// Whether `result` would be accepted for this job: the frame rules, the shape rules of the
    /// job kind and the frame size. Does not touch the link.
    ///
    /// # Errors
    /// The rule that fails.
    pub fn validate_result(&self, result: &pb::JobResult) -> Result<(), &'static str> {
        let kind = lock(&self.inner.state)
            .job_kind()
            .unwrap_or(pb::JobKind::Unspecified);
        let frame = pb::RepoFrame {
            frame: Some(pb::repo_frame::Frame::Result(result.clone())),
        };
        repo::encode_message(&frame, Endpoint::PrivdWorkerLink).map_err(|e| refusal(&e))?;
        repo::check_result_shape(kind, result).map_err(|e| refusal(&e))
    }

    /// Ends the job: waits until the requests that block the result are answered (all of them for a
    /// successful result; all but downloads already begun for a failed one), sends the one
    /// `JobResult`, and then `Bye` once nothing is outstanding (waiting at most [`DISCARD_WAIT`] for
    /// discarded downloads). Returns when both frames are written.
    ///
    /// # Errors
    /// [`LinkFailure`] if the link failed first.
    pub fn finish(&self, result: pb::JobResult) -> Result<(), LinkFailure> {
        let inner = &self.inner;
        let ok = result.ok;
        let mut st = lock(&inner.state);
        loop {
            if let Some(f) = inner.failed() {
                return Err(f);
            }
            let outstanding = st.outstanding();
            let blocking = if ok {
                outstanding
            } else {
                outstanding.saturating_sub(
                    lock(&inner.pending)
                        .values()
                        .filter(|p| p.download_begun)
                        .count(),
                )
            };
            if blocking == 0 {
                break;
            }
            st = inner
                .slots
                .wait_timeout(st, WAIT_SLICE)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        let frame = pb::RepoFrame {
            frame: Some(pb::repo_frame::Frame::Result(result)),
        };
        let wire = repo::encode_message(&frame, Endpoint::PrivdWorkerLink)
            .map_err(|e| LinkFailure::Violation(refusal(&e)))?;
        st.sent_message(&frame)
            .map_err(|e| LinkFailure::Violation(e.0))?;
        drop(st);
        if !inner.outbox.push_control(wire) {
            return Err(inner.failed().unwrap_or(LinkFailure::Lost));
        }
        // Bye needs nothing outstanding: wait for the discarded downloads, but not forever.
        let deadline = Instant::now() + DISCARD_WAIT;
        let mut st = lock(&inner.state);
        while st.outstanding() > 0 {
            if let Some(f) = inner.failed() {
                // The result is already queued; whether it left is the flush's answer below.
                let _ = f;
                break;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            st = inner
                .slots
                .wait_timeout(st, left.min(WAIT_SLICE))
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        let bye = pb::RepoFrame {
            frame: Some(pb::repo_frame::Frame::Bye(pb::Bye {})),
        };
        // From here on the end of the connection is expected (privd closes it after `Bye`) and a
        // `Pong` would be refused: set before the `Bye` is accounted, not after.
        inner.closed.store(true, Ordering::SeqCst);
        if st.outstanding() == 0
            && inner.failed().is_none()
            && let Ok(wire) = repo::encode_message(&bye, Endpoint::PrivdWorkerLink)
            && st.sent_message(&bye).is_ok()
        {
            inner.outbox.push_control(wire);
        }
        drop(st);
        let flushed = inner.outbox.flush();
        // Nothing more will be written: let the writer thread end.
        inner.outbox.close();
        if flushed {
            Ok(())
        } else {
            Err(inner.failed().unwrap_or(LinkFailure::Lost))
        }
    }
}

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Link").finish_non_exhaustive()
    }
}

fn read_incoming(
    decoder: &mut Decoder<RepoFramePolicy>,
    stream: &mut UnixStream,
) -> Result<Incoming, LinkFailure> {
    let raw = match decoder.read_from(&mut NoCmsgReader(&*stream)) {
        Ok(Some(raw)) => raw,
        Ok(None) => return Err(LinkFailure::Lost),
        Err(ReadError::Io(e))
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            return Err(LinkFailure::Silent);
        }
        Err(ReadError::Io(_)) => return Err(LinkFailure::Lost),
        Err(e) => {
            tracing::warn!(error = %e, "framing error on the repository link");
            return Err(LinkFailure::Violation("framing"));
        }
    };
    repo::decode(raw, Endpoint::Worker).map_err(|e| {
        tracing::warn!(error = %e, "invalid frame on the repository link");
        LinkFailure::Violation("invalid frame")
    })
}

// ----- the rustic backend -----

/// A `rustic_core` backend that speaks the repository link. Cheap to clone; all clones share one
/// connection. See the module documentation.
#[derive(Clone)]
pub struct LinkBackend {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for LinkBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkBackend").finish_non_exhaustive()
    }
}

impl ReadBackend for LinkBackend {
    fn location(&self) -> String {
        "hx repository link".to_owned()
    }

    fn list_with_size(&self, tpe: FileType) -> RusticResult<Vec<(Id, u32)>> {
        self.inner.list(object_type(tpe)).map_err(fault)
    }

    fn read_full(&self, tpe: FileType, id: &Id) -> RusticResult<Bytes> {
        self.inner
            .download(
                pb::repo_request::Op::ReadFull(pb::ReadFull {
                    object_type: object_type(tpe) as i32,
                    id: wire_id(tpe, id),
                }),
                None,
            )
            .map_err(fault)
    }

    fn read_partial(
        &self,
        tpe: FileType,
        id: &Id,
        _cacheable: bool,
        offset: u32,
        length: u32,
    ) -> RusticResult<Bytes> {
        self.inner
            .download(
                pb::repo_request::Op::ReadPartial(pb::ReadPartial {
                    object_type: object_type(tpe) as i32,
                    id: wire_id(tpe, id),
                    offset,
                    length,
                }),
                Some(length),
            )
            .map_err(fault)
    }

    fn warmup_path(&self, tpe: FileType, id: &Id) -> String {
        format!("{}/{}", tpe.dirname(), id.to_hex().as_str())
    }
}

impl WriteBackend for LinkBackend {
    fn create(&self) -> RusticResult<()> {
        self.inner
            .plain(pb::repo_request::Op::Create(pb::Create {}))
            .map_err(fault)
    }

    fn write_bytes(
        &self,
        tpe: FileType,
        id: &Id,
        _cacheable: bool,
        content: BytesList,
    ) -> RusticResult<()> {
        self.inner
            .upload(object_type(tpe), wire_id(tpe, id), &content)
            .map_err(fault)
    }

    fn remove(&self, tpe: FileType, id: &Id, _cacheable: bool) -> RusticResult<()> {
        self.inner
            .plain(pb::repo_request::Op::Remove(pb::Remove {
                object_type: object_type(tpe) as i32,
                id: wire_id(tpe, id),
            }))
            .map_err(fault)
    }
}
