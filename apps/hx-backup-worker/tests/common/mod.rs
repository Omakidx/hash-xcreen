//! A fake `hx-privd` for the worker's tests: it speaks the repository link over a socket pair with
//! `hx_ipc::repo` and `LinkState` (as `Endpoint::PrivdWorkerLink`), applies `policy::check_op` and the
//! SHA-256 check of every write as privd will, and serves the repository from memory.
#![allow(dead_code)] // each test binary uses a different subset

use std::collections::{BTreeMap, HashMap};
use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use hx_backup::engine::{LinkOptions, Ownership};
use hx_backup_worker::job::JobOptions;
use hx_backup_worker::session::{Sandbox, WorkerConfig, serve};
use hx_ipc::frame::Decoder;
use hx_ipc::recv::NoCmsgReader;
use hx_ipc::repo::pb::{self, ObjectType as T, repo_frame::Frame as F, repo_request::Op};
use hx_ipc::repo::policy::{Verdict, check_op};
use hx_ipc::repo::{
    self, Endpoint, Incoming, LinkState, RepoFramePolicy, encode_data_header, encode_message,
};
use sha2::{Digest, Sha256};

/// The repository the fake serves: objects by (type, id).
#[derive(Default)]
pub struct Store {
    pub objects: BTreeMap<(i32, Vec<u8>), Vec<u8>>,
    pub created: bool,
}

pub type SharedStore = Arc<Mutex<Store>>;

pub fn new_store() -> SharedStore {
    Arc::new(Mutex::new(Store::default()))
}

impl Store {
    pub fn count(&self, ty: T) -> usize {
        self.objects.keys().filter(|(t, _)| *t == ty as i32).count()
    }

    pub fn ids(&self, ty: T) -> Vec<Vec<u8>> {
        self.objects
            .keys()
            .filter(|(t, _)| *t == ty as i32)
            .map(|(_, id)| id.clone())
            .collect()
    }
}

/// When the fake sends `Cancel`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CancelOn {
    /// When the first `Write` of a `PACK` is requested.
    FirstPackWrite,
    /// After it has started the first download of a `PACK` (sent `ReadBegin` and one data frame,
    /// no `END`), and then it holds the rest back until the worker's `JobResult` arrives.
    FirstPackDownload,
}

/// A rule of the link that the fake breaks on purpose.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Violation {
    /// `Done` for a `req_id` that was never requested, answering the first request.
    DoneForUnknownRequest,
}

#[derive(Clone, Default)]
pub struct Behavior {
    pub list_page: Option<usize>,
    pub read_chunk: Option<usize>,
    pub cancel_on: Option<CancelOn>,
    /// Answer the first `PACK` write with this error after its first data frame.
    pub abort_pack_upload: Option<pb::ErrorClass>,
    pub violate: Option<Violation>,
    pub ping_every: Option<Duration>,
    /// Answer every `List` of this type with this error.
    pub fail_list: Option<(T, pb::ErrorClass)>,
    /// Never answer anything after the job and its secrets (the worker must give up).
    pub go_silent: bool,
    /// Sleep this long before answering each request (a slow Drive).
    pub answer_delay: Option<Duration>,
    /// Answer the first `PACK` write with this error only after its `END` has arrived (the `Error`
    /// and the `END` crossed on the wire).
    pub error_after_end: Option<pb::ErrorClass>,
    /// Send `Cancel` between the `Job` and its secrets.
    pub cancel_before_secrets: bool,
    /// Never deliver the rest of a held download (the worker's `Bye` wait must time out).
    pub never_release_held: bool,
    /// Hold read-like requests until six are waiting (or the link goes idle), so that many are
    /// outstanding at once.
    pub defer_reads: bool,
}

/// What the fake saw.
#[derive(Default, Debug)]
pub struct Outcome {
    pub result: Option<pb::JobResult>,
    pub result_at: Option<Instant>,
    pub cancel_sent_at: Option<Instant>,
    pub progress: Vec<(Instant, pb::Progress)>,
    pub frames: Vec<pb::RepoFrame>,
    pub ops: Vec<String>,
    pub denied: Vec<String>,
    /// Rules that privd's own `LinkState` or decoder found broken by the worker.
    pub worker_violations: Vec<String>,
    pub software: Option<String>,
    pub bye: bool,
    pub pongs: Vec<u64>,
    pub packs_written: usize,
    /// Most requests, and most writes, outstanding at once as privd's state saw them.
    pub max_outstanding: usize,
    pub max_writes: usize,
    /// How many requests had been seen when `Cancel` was sent.
    pub ops_at_cancel: Option<usize>,
}

struct Upload {
    ty: i32,
    id: Vec<u8>,
    buf: Vec<u8>,
    abort_after_first: Option<pb::ErrorClass>,
    first_seen: bool,
}

struct Held {
    req_id: u64,
    rest: Vec<(bool, Vec<u8>)>,
}

pub struct Fake {
    stream: UnixStream,
    decoder: Decoder<RepoFramePolicy>,
    state: LinkState,
    job: pb::Job,
    secrets: Vec<Vec<u8>>,
    store: SharedStore,
    b: Behavior,
    out: Outcome,
    uploads: HashMap<u64, Upload>,
    held: Vec<Held>,
    deferred: Vec<pb::RepoRequest>,
    cancel_sent: bool,
    violated: bool,
    abort_used: bool,
    last_ping: Instant,
    nonce: u64,
}

fn frame(f: F) -> pb::RepoFrame {
    pb::RepoFrame { frame: Some(f) }
}

fn variant_name(f: &pb::RepoFrame) -> &'static str {
    match &f.frame {
        Some(F::Hello(_)) => "Hello",
        Some(F::HelloAck(_)) => "HelloAck",
        Some(F::Job(_)) => "Job",
        Some(F::Request(_)) => "Request",
        Some(F::Response(_)) => "Response",
        Some(F::Progress(_)) => "Progress",
        Some(F::Result(_)) => "Result",
        Some(F::Cancel(_)) => "Cancel",
        Some(F::Ping(_)) => "Ping",
        Some(F::Pong(_)) => "Pong",
        Some(F::Bye(_)) => "Bye",
        Some(F::CancelRequest(_)) => "CancelRequest",
        Some(F::Event(_)) => "Event",
        None => "none",
    }
}

#[allow(clippy::large_enum_variant)]
enum Read {
    Frame(Incoming),
    Idle,
    Eof,
}

impl Fake {
    pub fn new(
        stream: UnixStream,
        job: pb::Job,
        secrets: Vec<Vec<u8>>,
        store: SharedStore,
        b: Behavior,
    ) -> Self {
        stream
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        Self {
            stream,
            decoder: Decoder::new(RepoFramePolicy::new(Endpoint::PrivdWorkerLink)),
            state: LinkState::new(Endpoint::PrivdWorkerLink),
            job,
            secrets,
            store,
            b,
            out: Outcome::default(),
            uploads: HashMap::new(),
            held: Vec::new(),
            deferred: Vec::new(),
            cancel_sent: false,
            violated: false,
            abort_used: false,
            last_ping: Instant::now(),
            nonce: 0,
        }
    }

    fn send(&mut self, f: pb::RepoFrame) {
        self.state
            .sent_message(&f)
            .unwrap_or_else(|e| panic!("the fake's own frame {}: {e}", variant_name(&f)));
        let wire = encode_message(&f, Endpoint::Worker).expect("the fake's frame encodes");
        let _ = self.stream.write_all(&wire);
    }

    fn send_data(&mut self, id: u64, end: bool, payload: &[u8]) {
        self.state.sent_data(id, end, payload.len()).unwrap();
        let h = encode_data_header(id, end, payload.len()).unwrap();
        let _ = self.stream.write_all(&h);
        let _ = self.stream.write_all(payload);
    }

    fn respond(&mut self, req_id: u64, r: pb::repo_response::Result) {
        self.send(frame(F::Response(pb::RepoResponse {
            req_id,
            result: Some(r),
        })));
    }

    fn error(&mut self, req_id: u64, class: pb::ErrorClass) {
        self.respond(
            req_id,
            pb::repo_response::Result::Error(pb::RepoError {
                class: class as i32,
                retry_after_ms: 0,
            }),
        );
    }

    fn read(&mut self) -> Read {
        match self.decoder.read_from(&mut NoCmsgReader(&self.stream)) {
            Ok(Some(raw)) => match repo::decode(raw, Endpoint::PrivdWorkerLink) {
                Ok(i) => Read::Frame(i),
                Err(e) => {
                    self.out.worker_violations.push(format!("decode: {e}"));
                    Read::Eof
                }
            },
            Ok(None) => Read::Eof,
            Err(hx_ipc::ReadError::Io(e))
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                Read::Idle
            }
            Err(hx_ipc::ReadError::Io(_)) => Read::Eof,
            Err(e) => {
                self.out.worker_violations.push(format!("framing: {e}"));
                Read::Eof
            }
        }
    }

    /// Runs the session: `Hello`, the handshake, the job and its secrets, then serves until `Bye`.
    pub fn run(mut self) -> Outcome {
        self.send(frame(F::Hello(pb::Hello {
            major: repo::VERSION_MAJOR,
            minor: repo::VERSION_MINOR,
            job_id: self.job.job_id.clone(),
        })));
        // HelloAck
        loop {
            match self.read() {
                Read::Frame(i) => {
                    if let Err(e) = self.state.received(&i) {
                        self.out.worker_violations.push(e.to_string());
                        return self.out;
                    }
                    if let Incoming::Message(f) = i {
                        if let Some(F::HelloAck(a)) = &f.frame {
                            self.out.software = Some(a.software.clone());
                        }
                        self.out.frames.push(f);
                        break;
                    }
                }
                Read::Idle => {}
                Read::Eof => return self.out,
            }
        }
        let job = self.job.clone();
        self.send(frame(F::Job(job)));
        if self.b.cancel_before_secrets {
            self.send_cancel();
        }
        let secrets = self.secrets.clone();
        for (slot, s) in secrets.iter().enumerate() {
            self.state.sent_secret(0, slot as u8, s.len()).unwrap();
            let wire = repo::encode_secret(0, slot as u8, s).unwrap();
            let _ = self.stream.write_all(&wire);
        }
        loop {
            self.tick();
            match self.read() {
                Read::Frame(i) => {
                    if self.b.go_silent {
                        continue;
                    }
                    let disp = match self.state.received(&i) {
                        Ok(d) => d,
                        Err(e) => {
                            self.out.worker_violations.push(e.to_string());
                            return self.out;
                        }
                    };
                    match i {
                        Incoming::Message(f) => {
                            self.out.frames.push(f.clone());
                            if self.message(f) {
                                return self.out;
                            }
                        }
                        Incoming::Data(d) => {
                            if !disp.discard {
                                self.data(d.stream_id, d.end, &d.payload);
                            }
                        }
                        Incoming::Secret(_) => unreachable!("workers send no secrets"),
                    }
                }
                Read::Idle => {
                    self.flush_deferred();
                    // a worker that skips `Bye` leaves its end open (in-process); stop waiting
                    if let Some(t) = self.out.result_at
                        && t.elapsed() > Duration::from_secs(13)
                    {
                        return self.out;
                    }
                }
                Read::Eof => return self.out,
            }
        }
    }

    fn tick(&mut self) {
        if self.b.go_silent {
            return;
        }
        if let Some(every) = self.b.ping_every
            && self.last_ping.elapsed() >= every
        {
            self.last_ping = Instant::now();
            self.nonce += 1;
            let n = self.nonce;
            self.send(frame(F::Ping(pb::Ping { nonce: n })));
        }
    }

    /// True when the session is over.
    fn message(&mut self, f: pb::RepoFrame) -> bool {
        match f.frame {
            Some(F::Progress(p)) => self.out.progress.push((Instant::now(), p)),
            Some(F::Result(r)) => {
                self.out.result = Some(r);
                self.out.result_at = Some(Instant::now());
                // the held downloads finish now
                let held = if self.b.never_release_held {
                    Vec::new()
                } else {
                    std::mem::take(&mut self.held)
                };
                for h in held {
                    for (end, chunk) in h.rest {
                        self.send_data(h.req_id, end, &chunk);
                    }
                }
            }
            Some(F::Bye(_)) => {
                self.out.bye = true;
                return true;
            }
            Some(F::Pong(p)) => self.out.pongs.push(p.nonce),
            Some(F::Request(r)) => self.request(r),
            _ => {}
        }
        false
    }

    fn request(&mut self, r: pb::RepoRequest) {
        let op = r.op.clone().unwrap();
        self.out.ops.push(op_name(&op));
        self.out.max_outstanding = self.out.max_outstanding.max(self.state.outstanding());
        self.out.max_writes = self.out.max_writes.max(self.state.outstanding_writes());
        if self.b.defer_reads
            && matches!(
                op,
                Op::ReadFull(_) | Op::ReadPartial(_) | Op::List(_) | Op::Remove(_)
            )
        {
            self.deferred.push(r);
            if self.deferred.len() >= 6 {
                self.flush_deferred();
            }
            return;
        }
        self.handle(r);
    }

    fn flush_deferred(&mut self) {
        for r in std::mem::take(&mut self.deferred) {
            self.handle(r);
        }
    }

    fn handle(&mut self, r: pb::RepoRequest) {
        let op = r.op.clone().unwrap();
        if let Some(d) = self.b.answer_delay {
            std::thread::sleep(d);
        }
        if self.b.violate == Some(Violation::DoneForUnknownRequest) && !self.violated {
            self.violated = true;
            // bypass the state machine: this is the violation
            let f = frame(F::Response(pb::RepoResponse {
                req_id: 9_999_999,
                result: Some(pb::repo_response::Result::Done(pb::Done {})),
            }));
            let wire = encode_message(&f, Endpoint::Worker).unwrap();
            let _ = self.stream.write_all(&wire);
            return;
        }
        // policy, as privd applies it
        let spec = self.job.spec.clone();
        let kind = pb::JobKind::try_from(self.job.kind).unwrap();
        let verdict = match check_op(kind, spec.as_ref(), &op) {
            Verdict::AllowIfAbsent => {
                if self.store.lock().unwrap().count(T::Config) == 0 {
                    Verdict::Allow
                } else {
                    Verdict::Deny
                }
            }
            v => v,
        };
        if verdict == Verdict::Deny {
            self.out.denied.push(op_name(&op));
            self.error(r.req_id, pb::ErrorClass::PolicyDenied);
            return;
        }
        let rid = r.req_id;
        match op {
            Op::List(l) => {
                if let Some((t, class)) = self.b.fail_list
                    && t as i32 == l.object_type
                {
                    self.error(rid, class);
                    return;
                }
                let entries: Vec<pb::ListEntry> = {
                    let st = self.store.lock().unwrap();
                    st.objects
                        .iter()
                        .filter(|((t, _), _)| *t == l.object_type)
                        .map(|((_, id), v)| pb::ListEntry {
                            id: Bytes::from(id.clone()),
                            size: v.len() as u32,
                        })
                        .collect()
                };
                let page = self.b.list_page.unwrap_or(repo::MAX_LIST_PAGE_ENTRIES);
                if entries.is_empty() {
                    self.respond(
                        rid,
                        pb::repo_response::Result::ListPage(pb::ListPage {
                            entries: vec![],
                            last: true,
                        }),
                    );
                }
                let chunks: Vec<&[pb::ListEntry]> = entries.chunks(page).collect();
                for (i, c) in chunks.iter().enumerate() {
                    self.respond(
                        rid,
                        pb::repo_response::Result::ListPage(pb::ListPage {
                            entries: c.to_vec(),
                            last: i + 1 == chunks.len(),
                        }),
                    );
                }
            }
            Op::ReadFull(x) => self.download(rid, x.object_type, &x.id, 0, None),
            Op::ReadPartial(x) => self.download(
                rid,
                x.object_type,
                &x.id,
                x.offset as usize,
                Some(x.length as usize),
            ),
            Op::Write(w) => {
                if w.object_type == T::Pack as i32 {
                    self.out.packs_written += 1;
                    if self.b.cancel_on == Some(CancelOn::FirstPackWrite) {
                        self.send_cancel();
                    }
                }
                let abort = (w.object_type == T::Pack as i32 && !self.abort_used)
                    .then_some(self.b.abort_pack_upload)
                    .flatten();
                if abort.is_some() {
                    self.abort_used = true;
                }
                self.uploads.insert(
                    rid,
                    Upload {
                        ty: w.object_type,
                        id: w.id.to_vec(),
                        buf: Vec::new(),
                        abort_after_first: abort,
                        first_seen: false,
                    },
                );
            }
            Op::Remove(x) => {
                let gone = self
                    .store
                    .lock()
                    .unwrap()
                    .objects
                    .remove(&(x.object_type, x.id.to_vec()))
                    .is_some();
                if gone {
                    self.respond(rid, pb::repo_response::Result::Done(pb::Done {}));
                } else {
                    self.error(rid, pb::ErrorClass::NotFound);
                }
            }
            Op::Create(_) => {
                self.store.lock().unwrap().created = true;
                self.respond(rid, pb::repo_response::Result::Done(pb::Done {}));
            }
            Op::OpenRepo(_) | Op::Quota(_) | Op::SetUploadRate(_) => unreachable!("denied above"),
        }
    }

    fn send_cancel(&mut self) {
        if !self.cancel_sent {
            self.cancel_sent = true;
            self.out.cancel_sent_at = Some(Instant::now());
            self.out.ops_at_cancel = Some(self.out.ops.len());
            self.send(frame(F::Cancel(pb::Cancel {})));
        }
    }

    fn download(&mut self, rid: u64, ty: i32, id: &[u8], offset: usize, len: Option<usize>) {
        let obj = self
            .store
            .lock()
            .unwrap()
            .objects
            .get(&(ty, id.to_vec()))
            .cloned();
        let Some(obj) = obj else {
            self.error(rid, pb::ErrorClass::NotFound);
            return;
        };
        let end = len.map_or(obj.len(), |l| (offset + l).min(obj.len()));
        let body = &obj[offset.min(obj.len())..end];
        self.respond(
            rid,
            pb::repo_response::Result::ReadBegin(pb::ReadBegin {
                size: body.len() as u32,
            }),
        );
        let chunk = self.b.read_chunk.unwrap_or(256 * 1024);
        let mut frames: Vec<(bool, Vec<u8>)> =
            body.chunks(chunk).map(|c| (false, c.to_vec())).collect();
        match frames.last_mut() {
            Some(l) => l.0 = true,
            None => frames.push((true, Vec::new())),
        }
        let hold = ty == T::Pack as i32
            && self.b.cancel_on == Some(CancelOn::FirstPackDownload)
            && !self.cancel_sent
            && frames.len() > 1;
        if hold {
            let (_, first) = frames.remove(0);
            self.send_data(rid, false, &first);
            self.send_cancel();
            self.held.push(Held {
                req_id: rid,
                rest: frames,
            });
        } else {
            for (end, c) in frames {
                self.send_data(rid, end, &c);
            }
        }
    }

    fn data(&mut self, stream_id: u64, end: bool, payload: &[u8]) {
        let Some(u) = self.uploads.get_mut(&stream_id) else {
            self.out
                .worker_violations
                .push("data for an unknown upload".into());
            return;
        };
        u.buf.extend_from_slice(payload);
        let abort = (!u.first_seen).then_some(u.abort_after_first).flatten();
        u.first_seen = true;
        if let Some(class) = abort {
            // privd's Error mid-stream: the worker must stop and close the stream with END
            if !end {
                self.error(stream_id, class);
                self.uploads.remove(&stream_id);
                return;
            }
        }
        if !end {
            return;
        }
        let u = self.uploads.remove(&stream_id).unwrap();
        if u.ty == T::Pack as i32
            && let Some(class) = self.b.error_after_end.take()
        {
            self.error(stream_id, class);
            return;
        }
        let ok = u.ty == T::Config as i32 || Sha256::digest(&u.buf).as_slice() == u.id.as_slice();
        if !ok {
            self.error(stream_id, pb::ErrorClass::Integrity);
            return;
        }
        self.store
            .lock()
            .unwrap()
            .objects
            .insert((u.ty, u.id), u.buf);
        self.respond(stream_id, pb::repo_response::Result::Done(pb::Done {}));
    }
}

fn op_name(op: &Op) -> String {
    match op {
        Op::List(l) => format!("List({})", l.object_type),
        Op::ReadFull(r) => format!("ReadFull({})", r.object_type),
        Op::ReadPartial(r) => format!("ReadPartial({})", r.object_type),
        Op::Write(w) => format!("Write({})", w.object_type),
        Op::Remove(r) => format!("Remove({})", r.object_type),
        Op::Create(_) => "Create".into(),
        Op::OpenRepo(_) => "OpenRepo".into(),
        Op::Quota(_) => "Quota".into(),
        Op::SetUploadRate(_) => "SetUploadRate".into(),
    }
}

// ----- jobs -----

pub const PASSWORD: &[u8] = b"correct horse battery staple 1f2e3d";
pub const RECOVERY: &[u8] = b"recovery key 9a8b7c6d5e4f3a2b1c0d";

fn job(kind: pb::JobKind, spec: pb::job::Spec, slots: &[(u32, pb::SecretKind, usize)]) -> pb::Job {
    pb::Job {
        job_id: Bytes::from(vec![0x5a; 16]),
        kind: kind as i32,
        secret_slots: slots
            .iter()
            .map(|(slot, kind, len)| pb::SecretSlot {
                slot: *slot,
                kind: *kind as i32,
                length: *len as u32,
            })
            .collect(),
        spec: Some(spec),
    }
}

const PW: pb::SecretKind = pb::SecretKind::RepoPassword;
const NEW: pb::SecretKind = pb::SecretKind::NewKeyPassword;

pub struct JobSpec {
    pub job: pb::Job,
    pub secrets: Vec<Vec<u8>>,
}

pub fn init_job() -> JobSpec {
    JobSpec {
        job: job(
            pb::JobKind::Init,
            pb::job::Spec::Init(pb::InitSpec {
                compression: repo::INIT_COMPRESSION,
                datapack_size_limit: repo::INIT_DATAPACK_SIZE_LIMIT,
                treepack_size_limit: repo::INIT_TREEPACK_SIZE_LIMIT,
            }),
            &[(0, PW, PASSWORD.len()), (1, NEW, RECOVERY.len())],
        ),
        secrets: vec![PASSWORD.to_vec(), RECOVERY.to_vec()],
    }
}

pub fn backup_job(excludes: &[&str], tags: &[&str]) -> JobSpec {
    JobSpec {
        job: job(
            pb::JobKind::Backup,
            pb::job::Spec::Backup(pb::BackupSpec {
                manifest: Some(pb::ManifestInput {
                    agent_version: "0.1.0-test".into(),
                    distro: Some(pb::Distro {
                        id: "ubuntu".into(),
                        version_id: "24.04".into(),
                        pretty_name: "Ubuntu 24.04 LTS".into(),
                    }),
                    desktop: "xfce4".into(),
                    preset: "dev".into(),
                    container_config: vec![pb::ConfigEntry {
                        key: "limits.cpu".into(),
                        value: "4".into(),
                    }],
                    format_version: 1,
                }),
                excludes: excludes.iter().map(|s| (*s).to_owned()).collect(),
                docker_mode: pb::DockerMode::Complete as i32,
                tags: tags.iter().map(|s| (*s).to_owned()).collect(),
                docker_enabled: true,
            }),
            &[(0, PW, PASSWORD.len())],
        ),
        secrets: vec![PASSWORD.to_vec()],
    }
}

pub fn with_docker(mut j: JobSpec, enabled: bool) -> JobSpec {
    if let Some(pb::job::Spec::Backup(b)) = &mut j.job.spec {
        b.docker_enabled = enabled;
    }
    j
}

pub fn simple_job(kind: pb::JobKind, spec: pb::job::Spec) -> JobSpec {
    JobSpec {
        job: job(kind, spec, &[(0, PW, PASSWORD.len())]),
        secrets: vec![PASSWORD.to_vec()],
    }
}

pub fn snapshots_job() -> JobSpec {
    simple_job(
        pb::JobKind::Snapshots,
        pb::job::Spec::Snapshots(pb::SnapshotsSpec {}),
    )
}

pub fn restore_plan_job(id: &[u8]) -> JobSpec {
    simple_job(
        pb::JobKind::RestorePlan,
        pb::job::Spec::RestorePlan(pb::RestorePlanSpec {
            snapshot_id: Bytes::from(id.to_vec()),
        }),
    )
}

pub fn restore_job(id: &[u8]) -> JobSpec {
    simple_job(
        pb::JobKind::Restore,
        pb::job::Spec::Restore(pb::RestoreSpec {
            snapshot_id: Bytes::from(id.to_vec()),
            verify_existing: false,
        }),
    )
}

pub fn check_job(percent: u32) -> JobSpec {
    simple_job(
        pb::JobKind::Check,
        pb::job::Spec::Check(pb::CheckSpec {
            read_data_percent: percent,
        }),
    )
}

pub fn forget_job(ids: &[Vec<u8>]) -> JobSpec {
    simple_job(
        pb::JobKind::ForgetPrune,
        pb::job::Spec::ForgetPrune(pb::ForgetPruneSpec {
            forget: ids.iter().map(|i| Bytes::from(i.clone())).collect(),
            instant: true,
        }),
    )
}

/// A `KEYS` job: `open_with` is slot 0, `new_key` is slot 1 when `add`.
pub fn keys_job(open_with: &[u8], add: Option<&[u8]>, remove: &[Vec<u8>]) -> JobSpec {
    let mut slots = vec![(0, PW, open_with.len())];
    let mut secrets = vec![open_with.to_vec()];
    if let Some(n) = add {
        slots.push((1, NEW, n.len()));
        secrets.push(n.to_vec());
    }
    JobSpec {
        job: job(
            pb::JobKind::Keys,
            pb::job::Spec::Keys(pb::KeysSpec {
                add: add.is_some(),
                remove_key_ids: remove.iter().map(|i| Bytes::from(i.clone())).collect(),
            }),
            &slots,
        ),
        secrets,
    }
}

pub fn with_password(mut j: JobSpec, pw: &[u8]) -> JobSpec {
    j.secrets[0] = pw.to_vec();
    j.job.secret_slots[0].length = pw.len() as u32;
    j
}

// ----- running a session -----

pub struct Dirs {
    pub src: std::path::PathBuf,
    pub dst: std::path::PathBuf,
}

pub fn config(dirs: &Dirs) -> WorkerConfig {
    WorkerConfig {
        run_dir: "/nonexistent".into(),
        accept_timeout: Duration::from_secs(5),
        link: LinkOptions {
            silence_timeout: Duration::from_secs(30),
        },
        job: JobOptions {
            src: dirs.src.clone(),
            dst: dirs.dst.clone(),
            ownership: Ownership::Skip,
        },
        sandbox: Sandbox::Off,
    }
}

pub fn dirs(root: &Path) -> Dirs {
    Dirs {
        src: root.join("src"),
        dst: root.join("dst"),
    }
}

/// Runs the worker's session in this process against a fake privd on a socket pair. Returns the
/// worker's exit code and what the fake saw.
pub fn session(
    j: JobSpec,
    store: &SharedStore,
    behavior: Behavior,
    cfg: &WorkerConfig,
) -> (i32, Outcome) {
    static LOG: std::sync::Once = std::sync::Once::new();
    LOG.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_target(false)
            .try_init();
    });
    let (worker_end, privd_end) = UnixStream::pair().unwrap();
    let fake = Fake::new(privd_end, j.job, j.secrets, Arc::clone(store), behavior);
    let handle = std::thread::spawn(move || fake.run());
    let code = serve(worker_end, cfg);
    // the worker's end is closed by `serve` returning (its threads end on EOF)
    let out = handle.join().expect("the fake privd panicked");
    (code, out)
}

pub fn run_ok(j: JobSpec, store: &SharedStore, cfg: &WorkerConfig) -> pb::JobResult {
    let (code, out) = session(j, store, Behavior::default(), cfg);
    assert_eq!(code, 0, "violations: {:?}", out.worker_violations);
    assert!(
        out.worker_violations.is_empty(),
        "{:?}",
        out.worker_violations
    );
    assert!(out.denied.is_empty(), "privd denied {:?}", out.denied);
    assert!(out.bye, "no Bye");
    let r = out.result.expect("no JobResult");
    assert!(
        r.ok,
        "the job failed with {:?}",
        pb::WorkerError::try_from(r.error)
    );
    r
}

pub fn run_failing(
    j: JobSpec,
    store: &SharedStore,
    cfg: &WorkerConfig,
    want: pb::WorkerError,
) -> Outcome {
    let (code, out) = session(j, store, Behavior::default(), cfg);
    assert_eq!(code, 0, "violations: {:?}", out.worker_violations);
    assert!(
        out.worker_violations.is_empty(),
        "{:?}",
        out.worker_violations
    );
    let r = out.result.clone().expect("no JobResult");
    assert!(!r.ok);
    assert_eq!(
        pb::WorkerError::try_from(r.error).unwrap(),
        want,
        "ops: {:?}",
        out.ops
    );
    out
}

// ----- trees -----

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::PathBuf;

pub fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

/// Deterministic incompressible bytes.
pub fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

pub fn write(path: &Path, data: &[u8], mode: u32) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, data).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// A small desktop-like tree: binary data over one pack frame, modes, a symlink, an empty file.
pub fn make_tree(src: &Path) {
    fs::create_dir_all(src).unwrap();
    write(
        &src.join("etc/passwd"),
        b"root:x:0:0::/root:/bin/sh\n",
        0o644,
    );
    write(
        &src.join("etc/shadow"),
        b"root:!:19000:0:99999:7:::\n",
        0o640,
    );
    write(
        &src.join("home/user/big.bin"),
        &noise(1, 5 * 1024 * 1024 + 123),
        0o600,
    );
    write(&src.join("home/user/small.txt"), b"hello\n", 0o644);
    write(&src.join("home/user/empty"), b"", 0o644);
    write(&src.join("usr/bin/tool"), b"#!/bin/sh\nexit 0\n", 0o755);
    fs::create_dir_all(src.join("srv/private")).unwrap();
    fs::set_permissions(src.join("srv/private"), fs::Permissions::from_mode(0o700)).unwrap();
    write(&src.join("srv/private/key"), &noise(2, 4096), 0o400);
    symlink("small.txt", src.join("home/user/link")).unwrap();
}

#[derive(Debug, PartialEq, Eq)]
pub enum Kind {
    File(Vec<u8>),
    Dir,
    Link(PathBuf),
}

pub fn snapshot_tree(root: &Path) -> BTreeMap<PathBuf, (Kind, u32, u32, u32)> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_owned()];
    while let Some(dir) = stack.pop() {
        for e in fs::read_dir(&dir).unwrap() {
            let p = e.unwrap().path();
            let md = fs::symlink_metadata(&p).unwrap();
            let rel = p.strip_prefix(root).unwrap().to_owned();
            let ft = md.file_type();
            let kind = if ft.is_symlink() {
                Kind::Link(fs::read_link(&p).unwrap())
            } else if ft.is_dir() {
                stack.push(p.clone());
                Kind::Dir
            } else {
                Kind::File(fs::read(&p).unwrap())
            };
            let mode = if ft.is_symlink() {
                0
            } else {
                md.mode() & 0o7777
            };
            out.insert(rel, (kind, mode, md.uid(), md.gid()));
        }
    }
    out
}

/// Every entry of `src` is in `dst` with the same bytes and mode (and owner, when root); `dst` has
/// nothing else but the mount points a restore recreates.
pub fn assert_same_tree(src: &Path, dst: &Path) {
    let a = snapshot_tree(src);
    let b = snapshot_tree(dst);
    for (path, (kind, mode, uid, gid)) in &a {
        let got = b
            .get(path)
            .unwrap_or_else(|| panic!("missing in the restore: {}", path.display()));
        assert_eq!(&got.0, kind, "{}", path.display());
        assert_eq!(got.1, *mode, "mode of {}", path.display());
        if is_root() {
            assert_eq!((got.2, got.3), (*uid, *gid), "owner of {}", path.display());
        }
    }
    let mount_points: Vec<PathBuf> = hx_backup::rules::MOUNT_POINTS
        .iter()
        .map(|(p, _)| PathBuf::from(p.trim_start_matches('/')))
        .collect();
    for path in b.keys() {
        if !a.contains_key(path) {
            assert!(
                mount_points
                    .iter()
                    .any(|m| m == path || m.starts_with(path)),
                "unexpected in the restore: {}",
                path.display()
            );
        }
    }
}

/// A directory chain whose path is longer than `PATH_MAX` (made with `mkdirat` steps, as no single
/// path can name it), with a file at the bottom.
pub fn make_deep_chain(base: &Path, links: usize) {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    fs::create_dir_all(base).unwrap();
    let c = CString::new(base.to_str().unwrap()).unwrap();
    // SAFETY: valid NUL-terminated paths and descriptors owned here.
    let mut fd =
        unsafe { OwnedFd::from_raw_fd(libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY)) };
    let name = CString::new("d".repeat(200)).unwrap();
    for _ in 0..links {
        // SAFETY: as above.
        unsafe {
            assert_eq!(libc::mkdirat(fd.as_raw_fd(), name.as_ptr(), 0o755), 0);
            let next = libc::openat(
                fd.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY,
            );
            assert!(next >= 0);
            fd = OwnedFd::from_raw_fd(next);
        }
    }
    let f = CString::new("bottom").unwrap();
    // SAFETY: as above.
    unsafe {
        let x = libc::openat(
            fd.as_raw_fd(),
            f.as_ptr(),
            libc::O_CREAT | libc::O_WRONLY,
            0o644,
        );
        assert!(x >= 0);
        libc::close(x);
    }
}
