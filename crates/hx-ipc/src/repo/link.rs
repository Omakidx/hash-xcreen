//! The stateful rules of one repository link (`docs/ipc.md` sections 25 to 27 and 29), as a
//! sans-I/O state machine.
//!
//! One [`LinkState`] serves **one end of one link**, named by the [`Endpoint`] it runs at. It is
//! told about every frame that passes in either direction, the peer's ([`LinkState::received`])
//! and its own ([`LinkState::sent_message`], [`LinkState::sent_secret`],
//! [`LinkState::sent_data`]), because the end of a request is an answer that the responder sends
//! and the requester receives. Telling it about its own frames also catches a local bug (a ninth
//! request, a stream that overruns its size) where it happens instead of as a closed link.
//!
//! It decides **protocol validity only**: never Drive semantics, never policy (that is
//! [`super::policy`]) and never time (this crate never sleeps). Any error is a violation: the
//! caller closes the link and, in privd, fails the job with `WORKER_PROTOCOL`; the state is then
//! poisoned.
//!
//! # Rules enforced
//!
//! * **Handshake.** The first frame is `Hello` from privd with the supported major; `HelloAck`
//!   from the peer with the same major answers it; nothing else passes before that and nothing
//!   after `Bye`.
//! * **Job (worker link).** One `Job` from privd with the `Hello`'s job id, then exactly the
//!   declared secret frames in order and of the declared lengths; the worker sends nothing but
//!   `Ping` and `Pong` until the last secret has been delivered.
//! * **Requests.** `req_id` non-zero and unique among the live requests (a request is live from
//!   its `RepoRequest` to its last answer); at most 8 live, at most 4 of them writes; on the
//!   Drive link the first request is `OpenRepo` and no other is.
//! * **Streams.** A `Write` opens an upload stream of exactly `size` bytes that ends with an
//!   `END` frame, and its `Done` may come only after `END`; a `ReadBegin{size}` opens a download
//!   stream with the same rules. A frame without `END` has at least one byte. A frame for an
//!   unknown, finished, wrong-direction or overrun stream, and an `END` before `size`, are
//!   violations. An `Error` answering a `Write` aborts the upload: the sender's frames that are
//!   already in flight are accepted and discarded up to `size` (or its `END`).
//! * **Listing.** Pages answer a `List` until `last`; a page before the last has an entry; ids
//!   are all zero for `CONFIG` and non-zero otherwise; sizes respect the per-type cap; at most
//!   1 000 000 entries in all.
//! * **Reads.** `ReadBegin` is at most the per-type cap, and for a `ReadPartial` at most the
//!   requested length.
//! * **End.** Exactly one `JobResult` (its shape must match the job kind), no `Progress` or
//!   request after it, and the worker's `Bye` only after it.
//!
//! `req_id` is unique among live requests, which is all the state machine depends on; a sender
//! numbers its requests upwards and never reuses a number.

use bytes::Bytes;
use thiserror::Error;

use super::limits::{
    MAX_LIST_ENTRIES, MAX_OUTSTANDING_REQUESTS, MAX_OUTSTANDING_WRITES, VERSION_MAJOR,
    max_object_size,
};
use super::validate::check_result_shape;
use super::{DataFrame, Endpoint, Incoming, pb};
use crate::error::FrameError;
use crate::secret::SecretFrame;

/// A protocol violation on the link. The text names the rule, never carries peer data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("repository link violation: {0}")]
pub struct LinkError(pub &'static str);

impl From<FrameError> for LinkError {
    fn from(e: FrameError) -> Self {
        match e {
            FrameError::Invalid(what) => LinkError(what),
            _ => LinkError("invalid frame"),
        }
    }
}

type R = Result<(), LinkError>;

fn violation(what: &'static str) -> R {
    Err(LinkError(what))
}

fn need(cond: bool, what: &'static str) -> R {
    if cond { Ok(()) } else { violation(what) }
}

/// The two ends of a link, by role in the conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Party {
    Privd,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    AwaitHello,
    AwaitAck,
    Open,
    Closed,
}

/// What a live request is waiting for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    List { ty: pb::ObjectType, total: u32 },
    ReadFull { ty: pb::ObjectType },
    ReadPartial { ty: pb::ObjectType, length: u32 },
    Write,
    Plain,
    Quota,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stream {
    /// No stream: before `ReadBegin`, or an operation without data.
    Idle,
    /// An upload that still expects this many bytes.
    Upload(u32),
    /// The `END` of an upload arrived; the answer is due.
    UploadDone,
    /// A download that still expects this many bytes.
    Download(u32),
    /// An upload that was answered with `Error`: its in-flight frames are discarded.
    Aborted(u32),
}

#[derive(Debug, Clone, Copy)]
struct Live {
    req_id: u64,
    op: Op,
    stream: Stream,
}

#[derive(Debug, Clone)]
struct JobState {
    kind: pb::JobKind,
    /// Declared slots `(slot, length)`, in order.
    slots: Vec<(u32, u32)>,
    delivered: usize,
}

/// The state of one end of one repository link. See the module documentation.
#[derive(Debug, Clone)]
pub struct LinkState {
    endpoint: Endpoint,
    phase: Phase,
    job_id: Option<Bytes>,
    job: Option<JobState>,
    result_seen: bool,
    live: Vec<Live>,
    requests_started: bool,
    poisoned: bool,
}

impl LinkState {
    /// A link that has seen nothing, at `endpoint`.
    pub fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            phase: Phase::AwaitHello,
            job_id: None,
            job: None,
            result_seen: false,
            live: Vec::with_capacity(MAX_OUTSTANDING_REQUESTS),
            requests_started: false,
            poisoned: false,
        }
    }

    /// The endpoint this state serves.
    pub fn endpoint(&self) -> Endpoint {
        self.endpoint
    }

    /// True once `Bye` has passed in either direction.
    pub fn is_closed(&self) -> bool {
        self.phase == Phase::Closed
    }

    /// True once the handshake completed and the link is not closed.
    pub fn is_open(&self) -> bool {
        self.phase == Phase::Open
    }

    /// Live (outstanding) requests, including aborted uploads that still owe an `END`.
    pub fn outstanding(&self) -> usize {
        self.live.len()
    }

    /// Of those, the writes.
    pub fn outstanding_writes(&self) -> usize {
        self.live.iter().filter(|l| l.op == Op::Write).count()
    }

    /// The kind of the job, once `Job` has passed (worker link).
    pub fn job_kind(&self) -> Option<pb::JobKind> {
        self.job.as_ref().map(|j| j.kind)
    }

    /// True once the job and all its secrets have been delivered (always false on the Drive
    /// link, which has no job).
    pub fn job_ready(&self) -> bool {
        self.job
            .as_ref()
            .is_some_and(|j| j.delivered == j.slots.len())
    }

    /// True once the worker's `JobResult` has passed.
    pub fn result_seen(&self) -> bool {
        self.result_seen
    }

    // ----- frames of the peer -----

    /// A decoded frame of the peer.
    pub fn received(&mut self, incoming: &Incoming) -> R {
        match incoming {
            Incoming::Message(f) => self.received_message(f),
            Incoming::Secret(s) => self.received_secret(s),
            Incoming::Data(d) => self.received_data(d),
        }
    }

    /// A kind-1 frame of the peer.
    pub fn received_message(&mut self, frame: &pb::RepoFrame) -> R {
        let from = self.peer();
        self.guarded(|s| s.message(from, frame))
    }

    /// A kind-2 frame of the peer (only privd sends them, so only the worker end receives).
    pub fn received_secret(&mut self, frame: &SecretFrame) -> R {
        let from = self.peer();
        self.guarded(|s| s.secret(from, frame.request_id, frame.slot, frame.secret.len()))
    }

    /// A kind-3 frame of the peer.
    pub fn received_data(&mut self, frame: &DataFrame) -> R {
        let from = self.peer();
        self.guarded(|s| s.data(from, frame.stream_id, frame.end, frame.payload.len()))
    }

    // ----- frames of our own -----

    /// A kind-1 frame this end is about to send.
    pub fn sent_message(&mut self, frame: &pb::RepoFrame) -> R {
        let from = self.own();
        self.guarded(|s| s.message(from, frame))
    }

    /// A kind-2 frame this end is about to send (privd, on the worker link).
    pub fn sent_secret(&mut self, request_id: u64, slot: u8, len: usize) -> R {
        let from = self.own();
        self.guarded(|s| s.secret(from, request_id, slot, len))
    }

    /// A kind-3 frame this end is about to send, with its payload length.
    pub fn sent_data(&mut self, stream_id: u64, end: bool, payload_len: usize) -> R {
        let from = self.own();
        self.guarded(|s| s.data(from, stream_id, end, payload_len))
    }

    // ----- internals -----

    fn own(&self) -> Party {
        match self.endpoint {
            Endpoint::Worker | Endpoint::DriveHelper => Party::Other,
            Endpoint::PrivdWorkerLink | Endpoint::PrivdDriveLink => Party::Privd,
        }
    }

    fn peer(&self) -> Party {
        match self.own() {
            Party::Privd => Party::Other,
            Party::Other => Party::Privd,
        }
    }

    fn on_worker_link(&self) -> bool {
        matches!(self.endpoint, Endpoint::Worker | Endpoint::PrivdWorkerLink)
    }

    /// The party that sends requests: the worker on the worker link, privd on the Drive link.
    fn requester(&self) -> Party {
        if self.on_worker_link() {
            Party::Other
        } else {
            Party::Privd
        }
    }

    fn responder(&self) -> Party {
        match self.requester() {
            Party::Privd => Party::Other,
            Party::Other => Party::Privd,
        }
    }

    fn guarded(&mut self, f: impl FnOnce(&mut Self) -> R) -> R {
        if self.poisoned {
            return violation("link already failed");
        }
        let r = f(self);
        if r.is_err() {
            self.poisoned = true;
        }
        r
    }

    /// May the requester send requests yet?
    fn can_request(&self) -> bool {
        if self.on_worker_link() {
            self.job_ready()
        } else {
            true
        }
    }

    fn message(&mut self, from: Party, frame: &pb::RepoFrame) -> R {
        use pb::repo_frame::Frame as F;
        let Some(variant) = &frame.frame else {
            return violation("frame: no variant set");
        };
        need(self.phase != Phase::Closed, "frame after Bye")?;
        match variant {
            F::Hello(h) => {
                need(from == Party::Privd, "Hello from the peer of privd")?;
                need(self.phase == Phase::AwaitHello, "Hello out of order")?;
                need(h.major == VERSION_MAJOR, "Hello: unsupported major version")?;
                self.job_id = Some(h.job_id.clone());
                self.phase = Phase::AwaitAck;
                return Ok(());
            }
            F::HelloAck(a) => {
                need(from == Party::Other, "HelloAck from privd")?;
                need(self.phase == Phase::AwaitAck, "HelloAck out of order")?;
                need(
                    a.major == VERSION_MAJOR,
                    "HelloAck: unsupported major version",
                )?;
                self.phase = Phase::Open;
                return Ok(());
            }
            _ => need(self.phase == Phase::Open, "frame before the handshake")?,
        }
        match variant {
            F::Hello(_) | F::HelloAck(_) => Ok(()),
            F::Job(j) => self.job_frame(from, j),
            F::Request(r) => self.request(from, r),
            F::Response(r) => self.response(from, r),
            F::Progress(_) => {
                need(self.on_worker_link(), "Progress on the Drive link")?;
                need(from == Party::Other, "Progress from privd")?;
                need(self.job_ready(), "Progress before the job is ready")?;
                need(!self.result_seen, "Progress after JobResult")
            }
            F::Result(r) => {
                need(self.on_worker_link(), "JobResult on the Drive link")?;
                need(from == Party::Other, "JobResult from privd")?;
                need(self.job_ready(), "JobResult before the job is ready")?;
                need(!self.result_seen, "second JobResult")?;
                let kind = self.job_kind().unwrap_or(pb::JobKind::Unspecified);
                check_result_shape(kind, r)?;
                self.result_seen = true;
                Ok(())
            }
            F::Cancel(_) => {
                need(self.on_worker_link(), "Cancel on the Drive link")?;
                need(from == Party::Privd, "Cancel from the worker")?;
                need(self.job.is_some(), "Cancel before the job")
            }
            F::CancelRequest(_) => {
                need(!self.on_worker_link(), "CancelRequest on the worker link")?;
                need(from == Party::Privd, "CancelRequest from the Drive helper")
            }
            F::Event(_) => {
                need(!self.on_worker_link(), "Event on the worker link")?;
                need(from == Party::Other, "Event from privd")
            }
            F::Ping(_) | F::Pong(_) => Ok(()),
            F::Bye(_) => {
                if self.on_worker_link() && from == Party::Other {
                    need(self.result_seen, "Bye before JobResult")?;
                }
                self.phase = Phase::Closed;
                Ok(())
            }
        }
    }

    fn job_frame(&mut self, from: Party, j: &pb::Job) -> R {
        need(self.on_worker_link(), "Job on the Drive link")?;
        need(from == Party::Privd, "Job from the worker")?;
        need(self.job.is_none(), "second Job")?;
        need(
            self.job_id.as_ref() == Some(&j.job_id),
            "Job: job id differs from Hello",
        )?;
        let kind = pb::JobKind::try_from(j.kind).map_err(|_| LinkError("Job: kind"))?;
        self.job = Some(JobState {
            kind,
            slots: j.secret_slots.iter().map(|s| (s.slot, s.length)).collect(),
            delivered: 0,
        });
        Ok(())
    }

    fn secret(&mut self, from: Party, request_id: u64, slot: u8, len: usize) -> R {
        need(self.phase == Phase::Open, "secret before the handshake")?;
        need(self.on_worker_link(), "secret on the Drive link")?;
        need(from == Party::Privd, "secret from the worker")?;
        need(request_id == 0, "secret: request_id")?;
        let Some(job) = &mut self.job else {
            return violation("secret before the Job");
        };
        let Some(&(want_slot, want_len)) = job.slots.get(job.delivered) else {
            return violation("secret: more than declared");
        };
        need(u32::from(slot) == want_slot, "secret: slot out of order")?;
        need(
            len == want_len as usize,
            "secret: length differs from the declaration",
        )?;
        job.delivered += 1;
        Ok(())
    }

    fn request(&mut self, from: Party, r: &pb::RepoRequest) -> R {
        use pb::repo_request::Op as O;
        need(from == self.requester(), "request from the responder")?;
        need(self.can_request(), "request before the job is ready")?;
        need(!self.result_seen, "request after JobResult")?;
        need(r.req_id != 0, "request: req_id is zero")?;
        need(
            !self.live.iter().any(|l| l.req_id == r.req_id),
            "request: req_id already in use",
        )?;
        need(
            self.live.len() < MAX_OUTSTANDING_REQUESTS,
            "too many outstanding requests",
        )?;
        let Some(op) = &r.op else {
            return violation("request: no operation");
        };
        if self.on_worker_link() {
            need(
                !matches!(op, O::OpenRepo(_) | O::Quota(_) | O::SetUploadRate(_)),
                "privd-only operation on the worker link",
            )?;
        } else {
            let first = matches!(op, O::OpenRepo(_));
            if self.requests_started {
                need(!first, "second OpenRepo")?;
            } else {
                need(first, "the first request must be OpenRepo")?;
            }
        }
        self.requests_started = true;
        let ty = |v: i32| pb::ObjectType::try_from(v).map_err(|_| LinkError("request: type"));
        let (op, stream) = match op {
            O::List(l) => (
                Op::List {
                    ty: ty(l.object_type)?,
                    total: 0,
                },
                Stream::Idle,
            ),
            O::ReadFull(x) => (
                Op::ReadFull {
                    ty: ty(x.object_type)?,
                },
                Stream::Idle,
            ),
            O::ReadPartial(x) => (
                Op::ReadPartial {
                    ty: ty(x.object_type)?,
                    length: x.length,
                },
                Stream::Idle,
            ),
            O::Write(w) => {
                need(
                    self.outstanding_writes() < MAX_OUTSTANDING_WRITES,
                    "too many outstanding writes",
                )?;
                (Op::Write, Stream::Upload(w.size))
            }
            O::Quota(_) => (Op::Quota, Stream::Idle),
            O::Remove(_) | O::Create(_) | O::OpenRepo(_) | O::SetUploadRate(_) => {
                (Op::Plain, Stream::Idle)
            }
        };
        self.live.push(Live {
            req_id: r.req_id,
            op,
            stream,
        });
        Ok(())
    }

    fn response(&mut self, from: Party, r: &pb::RepoResponse) -> R {
        use pb::repo_response::Result as Res;
        need(from == self.responder(), "response from the requester")?;
        let Some(idx) = self.live.iter().position(|l| l.req_id == r.req_id) else {
            return violation("response for an unknown request");
        };
        let Some(result) = &r.result else {
            return violation("response: no result");
        };
        let live = &mut self.live[idx];
        need(
            !matches!(live.stream, Stream::Aborted(_) | Stream::Download(_)),
            "response for a request that was already answered",
        )?;
        let done = match (&mut live.op, result) {
            (Op::List { ty, total }, Res::ListPage(p)) => {
                need(
                    !p.entries.is_empty() || p.last,
                    "an empty page before the last",
                )?;
                let cap = max_object_size(*ty).ok_or(LinkError("list: type"))?;
                let config = *ty == pb::ObjectType::Config;
                for e in &p.entries {
                    let zero = e.id.iter().all(|b| *b == 0);
                    need(zero == config, "list entry: id does not fit the type")?;
                    need(e.size <= cap, "list entry: size over the cap of its type")?;
                }
                let n = u32::try_from(p.entries.len()).unwrap_or(u32::MAX);
                *total = total.saturating_add(n);
                need(*total <= MAX_LIST_ENTRIES, "listing over 1 000 000 entries")?;
                p.last
            }
            (Op::ReadFull { ty }, Res::ReadBegin(b)) => {
                need(live.stream == Stream::Idle, "second ReadBegin")?;
                let cap = max_object_size(*ty).ok_or(LinkError("read: type"))?;
                need(b.size <= cap, "ReadBegin over the cap of its type")?;
                live.stream = Stream::Download(b.size);
                false
            }
            (Op::ReadPartial { ty, length }, Res::ReadBegin(b)) => {
                need(live.stream == Stream::Idle, "second ReadBegin")?;
                let cap = max_object_size(*ty).ok_or(LinkError("read: type"))?;
                need(
                    b.size <= cap.min(*length),
                    "ReadBegin over the requested length",
                )?;
                live.stream = Stream::Download(b.size);
                false
            }
            (Op::Write, Res::Done(_)) => {
                need(
                    live.stream == Stream::UploadDone,
                    "Done before the END of the upload",
                )?;
                true
            }
            (Op::Plain, Res::Done(_)) | (Op::Quota, Res::QuotaResult(_)) => true,
            (_, Res::Error(_)) => match live.stream {
                Stream::Upload(left) => {
                    live.stream = Stream::Aborted(left);
                    false
                }
                _ => true,
            },
            _ => return violation("response does not match the request"),
        };
        if done {
            self.live.swap_remove(idx);
        }
        Ok(())
    }

    fn data(&mut self, from: Party, stream_id: u64, end: bool, len: usize) -> R {
        need(self.phase == Phase::Open, "data before the handshake")?;
        need(stream_id != 0, "data: stream id is zero")?;
        let Some(idx) = self.live.iter().position(|l| l.req_id == stream_id) else {
            return violation("data for an unknown stream");
        };
        let requester = self.requester();
        let live = &mut self.live[idx];
        let len = u32::try_from(len).map_err(|_| LinkError("data: payload length"))?;
        need(len > 0 || end, "an empty data frame without END")?;
        match live.stream {
            Stream::Upload(left) => {
                need(from == requester, "upload data from the responder")?;
                need(len <= left, "stream exceeds its announced size")?;
                if end {
                    need(len == left, "END before the announced size")?;
                    live.stream = Stream::UploadDone;
                } else {
                    live.stream = Stream::Upload(left - len);
                }
                Ok(())
            }
            Stream::Download(left) => {
                need(from != requester, "download data from the requester")?;
                need(len <= left, "stream exceeds its announced size")?;
                if end {
                    need(len == left, "END before the announced size")?;
                    self.live.swap_remove(idx);
                } else {
                    live.stream = Stream::Download(left - len);
                }
                Ok(())
            }
            Stream::Aborted(left) => {
                need(from == requester, "upload data from the responder")?;
                need(len <= left, "stream exceeds its announced size")?;
                if end {
                    self.live.swap_remove(idx);
                } else {
                    live.stream = Stream::Aborted(left - len);
                }
                Ok(())
            }
            Stream::Idle | Stream::UploadDone => {
                violation("data for a finished or unopened stream")
            }
        }
    }
}
