//! The rig of the backup runner tests: a fake worker and a fake Drive helper that speak the
//! repository link over real unix sockets, the fake host and env of `privd::backup::testing`, and
//! a manual monotonic clock. Nothing here touches Incus, systemd or the network.

#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use bytes::Bytes;
use hx_agent::privd::backup::clock::ManualMono;
use hx_agent::privd::backup::runner::{JobHandle, JobRequest, JobRunner, RepoPassword};
use hx_agent::privd::backup::spec::{BackupParams, JobSpec};
use hx_agent::privd::backup::testing::{FakeEnv, FakeHost, StartInfo};
use hx_agent::privd::backup::{BackupConfig, JobOutcome, Timing};
use hx_ipc::frame::Decoder;
use hx_ipc::recv::NoCmsgReader;
use hx_ipc::repo::pb::{self, ErrorClass, ObjectType, repo_frame::Frame as F};
use hx_ipc::repo::{
    self, Endpoint, Incoming, LinkState, RepoFramePolicy, encode_data_header, encode_message,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use zeroize::Zeroizing;

pub const KEY: &[u8] = b"fake-backup-key-0123456789-abcdefghij";

pub fn sha(body: &[u8]) -> [u8; 32] {
    Sha256::digest(body).into()
}

pub fn body(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ----- one end of a link -------------------------------------------------------------------

/// What `Peer::next` returns.
pub enum Got {
    Msg(pb::RepoFrame),
    Data {
        stream: u64,
        end: bool,
        payload: Bytes,
    },
    Secret {
        slot: u8,
        secret: Vec<u8>,
    },
}

pub struct Peer {
    pub stream: UnixStream,
    dec: Decoder<RepoFramePolicy>,
    pub st: LinkState,
    me: Endpoint,
    pub mute: Arc<AtomicBool>,
}

impl Peer {
    pub fn new(stream: UnixStream, me: Endpoint) -> Self {
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        Self {
            stream,
            dec: Decoder::new(RepoFramePolicy::new(me)),
            st: LinkState::new(me),
            me,
            mute: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn set_poll(&mut self, d: Duration) {
        self.stream.set_read_timeout(Some(d)).unwrap();
    }

    /// The next frame, `Ok(None)` on a read timeout, `Err` at the end of the stream.
    pub fn poll(&mut self) -> Result<Option<Got>, String> {
        loop {
            let raw = match self.dec.read_from(&mut NoCmsgReader(&self.stream)) {
                Ok(Some(r)) => r,
                Ok(None) => return Err("closed".into()),
                Err(hx_ipc::ReadError::Io(e))
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(None);
                }
                Err(e) => return Err(e.to_string()),
            };
            let incoming = repo::decode(raw, self.me).map_err(|e| e.to_string())?;
            self.st.received(&incoming).map_err(|e| e.0.to_string())?;
            match incoming {
                Incoming::Message(f) => {
                    match &f.frame {
                        Some(F::Ping(p)) => {
                            if !self.mute.load(Ordering::SeqCst) {
                                self.send(F::Pong(pb::Pong { nonce: p.nonce })).ok();
                            }
                            continue;
                        }
                        Some(F::Pong(_)) => continue,
                        _ => {}
                    }
                    return Ok(Some(Got::Msg(f)));
                }
                Incoming::Data(d) => {
                    return Ok(Some(Got::Data {
                        stream: d.stream_id,
                        end: d.end,
                        payload: d.payload,
                    }));
                }
                Incoming::Secret(s) => {
                    return Ok(Some(Got::Secret {
                        slot: s.slot,
                        secret: s.secret.expose().to_vec(),
                    }));
                }
            }
        }
    }

    /// The next frame; a timeout is an error here.
    pub fn next(&mut self) -> Result<Got, String> {
        loop {
            match self.poll()? {
                Some(g) => return Ok(g),
                None => return Err("timeout".into()),
            }
        }
    }

    pub fn send(&mut self, f: F) -> Result<(), String> {
        let frame = pb::RepoFrame { frame: Some(f) };
        self.st.sent_message(&frame).map_err(|e| e.0.to_string())?;
        let bytes = encode_message(&frame, self.me.peer()).map_err(|e| e.to_string())?;
        (&self.stream).write_all(&bytes).map_err(|e| e.to_string())
    }

    pub fn send_data(&mut self, stream_id: u64, end: bool, payload: &[u8]) -> Result<(), String> {
        self.st
            .sent_data(stream_id, end, payload.len())
            .map_err(|e| e.0.to_string())?;
        let h = encode_data_header(stream_id, end, payload.len()).map_err(|e| e.to_string())?;
        let mut w = &self.stream;
        w.write_all(&h).map_err(|e| e.to_string())?;
        w.write_all(payload).map_err(|e| e.to_string())
    }

    pub fn send_raw(&mut self, bytes: &[u8]) {
        let _ = (&self.stream).write_all(bytes);
    }

    pub fn close(&self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

// ----- the fake worker ----------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    Done,
    Error(ErrorClass),
    List(Vec<(Vec<u8>, u32)>),
    Read(Vec<u8>),
}

pub struct WorkerPeer {
    pub p: Peer,
    pub job: pb::Job,
    pub secrets: Vec<(u8, Vec<u8>)>,
    next_req: u64,
    done: HashMap<u64, Reply>,
    partial: HashMap<u64, (Vec<u8>, u32)>,
    pub cancelled: bool,
    pub frames: usize,
}

impl WorkerPeer {
    /// Binds `socket`, accepts the one connection, and does the handshake of ipc.md section 26:
    /// `Hello`, `HelloAck`, `Job` and its secrets.
    pub fn accept(socket: &std::path::Path) -> Self {
        let _ = std::fs::remove_file(socket);
        let l = UnixListener::bind(socket).expect("bind the worker socket");
        let (s, _) = l.accept().expect("accept privd");
        drop(l);
        let mut p = Peer::new(s, Endpoint::Worker);
        let Ok(Got::Msg(m)) = p.next() else {
            panic!("no Hello")
        };
        let Some(F::Hello(h)) = m.frame else {
            panic!("not Hello: {m:?}")
        };
        assert_eq!(h.major, repo::VERSION_MAJOR);
        p.send(F::HelloAck(pb::HelloAck {
            major: 1,
            minor: 0,
            software: "hx-fake-worker".into(),
        }))
        .unwrap();
        let Ok(Got::Msg(m)) = p.next() else {
            panic!("no Job")
        };
        let Some(F::Job(job)) = m.frame else {
            panic!("not a Job: {m:?}")
        };
        let mut secrets = Vec::new();
        for _ in 0..job.secret_slots.len() {
            let Ok(Got::Secret { slot, secret }) = p.next() else {
                panic!("no secret")
            };
            secrets.push((slot, secret));
        }
        Self {
            p,
            job,
            secrets,
            next_req: 1,
            done: HashMap::new(),
            partial: HashMap::new(),
            cancelled: false,
            frames: 0,
        }
    }

    /// Processes one incoming frame (or a timeout when `poll` is set short).
    pub fn pump(&mut self) -> Result<(), String> {
        let Some(g) = self.p.poll()? else {
            return Ok(());
        };
        self.frames += 1;
        match g {
            Got::Data {
                stream,
                end,
                payload,
            } => {
                let (buf, size) = self.partial.get_mut(&stream).ok_or("data for no read")?;
                buf.extend_from_slice(&payload);
                if end {
                    assert_eq!(buf.len() as u32, *size);
                    let (buf, _) = self.partial.remove(&stream).unwrap();
                    self.done.insert(stream, Reply::Read(buf));
                }
            }
            Got::Secret { .. } => return Err("a secret after the job".into()),
            Got::Msg(m) => match m.frame {
                Some(F::Cancel(_)) => self.cancelled = true,
                Some(F::Response(r)) => {
                    use pb::repo_response::Result as R;
                    let id = r.req_id;
                    match r.result.unwrap() {
                        R::Done(_) => {
                            self.done.insert(id, Reply::Done);
                        }
                        R::Error(e) => {
                            self.partial.remove(&id);
                            self.done
                                .insert(id, Reply::Error(ErrorClass::try_from(e.class).unwrap()));
                        }
                        R::ListPage(pg) => {
                            let entry = self.done.entry(id).or_insert(Reply::List(vec![]));
                            if let Reply::List(v) = entry {
                                v.extend(pg.entries.iter().map(|e| (e.id.to_vec(), e.size)));
                            }
                            // `last` completes it; the entry above is the answer.
                            if !pg.last {
                                self.partial.insert(id, (vec![], u32::MAX));
                            } else {
                                self.partial.remove(&id);
                            }
                        }
                        R::ReadBegin(b) => {
                            self.partial.insert(id, (Vec::new(), b.size));
                            if b.size == 0 {
                                // the empty END frame follows
                            }
                        }
                        R::QuotaResult(_) => {}
                    }
                }
                Some(F::Bye(_)) => return Err("bye".into()),
                other => return Err(format!("unexpected frame {other:?}")),
            },
        }
        Ok(())
    }

    /// Short poll interval for scripts that wait for a cancel or a time-out.
    pub fn poll_every(&mut self, d: Duration) {
        self.p.set_poll(d);
    }

    pub fn request(&mut self, op: pb::repo_request::Op) -> u64 {
        let id = self.next_req;
        self.next_req += 1;
        self.p
            .send(F::Request(pb::RepoRequest {
                req_id: id,
                op: Some(op),
            }))
            .unwrap();
        id
    }

    pub fn wait(&mut self, id: u64) -> Reply {
        loop {
            if !self.partial.contains_key(&id)
                && let Some(r) = self.done.remove(&id)
            {
                return r;
            }
            self.pump()
                .unwrap_or_else(|e| panic!("worker waiting for request {id}: {e}"));
        }
    }

    pub fn call(&mut self, op: pb::repo_request::Op) -> Reply {
        let id = self.request(op);
        self.wait(id)
    }

    pub fn list(&mut self, ty: ObjectType) -> Reply {
        self.call(pb::repo_request::Op::List(pb::List {
            object_type: ty as i32,
        }))
    }

    pub fn read(&mut self, ty: ObjectType, id: &[u8; 32]) -> Reply {
        self.call(pb::repo_request::Op::ReadFull(pb::ReadFull {
            object_type: ty as i32,
            id: Bytes::copy_from_slice(id),
        }))
    }

    pub fn remove(&mut self, ty: ObjectType, id: &[u8; 32]) -> Reply {
        self.call(pb::repo_request::Op::Remove(pb::Remove {
            object_type: ty as i32,
            id: Bytes::copy_from_slice(id),
        }))
    }

    /// Starts a write and sends all its data in frames of at most 1 MiB; does not wait.
    pub fn start_write(&mut self, ty: ObjectType, id: &[u8; 32], data: &[u8]) -> u64 {
        let req = self.request(pb::repo_request::Op::Write(pb::Write {
            object_type: ty as i32,
            id: Bytes::copy_from_slice(id),
            size: data.len() as u32,
        }));
        self.send_body(req, data, usize::MAX);
        req
    }

    /// Sends the body of `req` in frames, at most `max_frames` of them without `END` (then stops).
    pub fn send_body(&mut self, req: u64, data: &[u8], max_frames: usize) {
        let chunks: Vec<&[u8]> = if data.is_empty() {
            vec![&[][..]]
        } else {
            data.chunks(1024 * 1024).collect()
        };
        let n = chunks.len();
        for (i, c) in chunks.into_iter().enumerate() {
            if i >= max_frames {
                return;
            }
            self.p.send_data(req, i + 1 == n, c).unwrap();
        }
    }

    pub fn write(&mut self, ty: ObjectType, id: &[u8; 32], data: &[u8]) -> Reply {
        let req = self.start_write(ty, id, data);
        self.wait(req)
    }

    /// Writes `data` under its own hash.
    pub fn put(&mut self, ty: ObjectType, data: &[u8]) -> [u8; 32] {
        let id = sha(data);
        assert_eq!(self.write(ty, &id, data), Reply::Done, "write {ty:?}");
        id
    }

    pub fn progress(&mut self, phase: pb::ProgressPhase, done: u64, total: u64) {
        self.p
            .send(F::Progress(pb::Progress {
                phase: phase as i32,
                bytes_done: done,
                bytes_total: total,
                ..Default::default()
            }))
            .unwrap();
    }

    pub fn finish_ok(&mut self, r: pb::JobResult) {
        self.p
            .send(F::Result(pb::JobResult { ok: true, ..r }))
            .unwrap();
        self.p.send(F::Bye(pb::Bye {})).unwrap();
    }

    pub fn finish_err(&mut self, e: pb::WorkerError) {
        self.p
            .send(F::Result(pb::JobResult {
                ok: false,
                error: e as i32,
                ..Default::default()
            }))
            .unwrap();
        self.p.send(F::Bye(pb::Bye {})).unwrap();
    }

    /// Pumps until a `Cancel` has arrived (or the link ends).
    pub fn wait_cancel(&mut self) {
        self.poll_every(Duration::from_millis(20));
        let started = Instant::now();
        while !self.cancelled {
            if self.pump().is_err() || started.elapsed() > Duration::from_secs(20) {
                return;
            }
        }
    }

    /// Pumps (answering pings) until the link ends.
    pub fn until_closed(&mut self) {
        self.poll_every(Duration::from_millis(20));
        while self.pump().is_ok() {}
    }
}

// ----- the fake Drive helper ------------------------------------------------------------------

pub type Store = BTreeMap<(i32, Vec<u8>), Vec<u8>>;

#[derive(Debug, Clone, PartialEq)]
pub enum Seen {
    Hello,
    Open(String),
    Request(String),
    Data { stream: u64, len: usize, end: bool },
    CancelRequest(u64),
}

pub enum DriveCmd {
    Event(pb::Event),
    /// Close the link between two frames.
    Close,
    /// Write half of a frame and close.
    CutClose,
}

#[derive(Default)]
pub struct DriveKnobs {
    /// `OpenRepo` is answered with this error.
    pub open_error: Option<ErrorClass>,
    /// A `Write` of this type is answered with this error after its `END`.
    pub write_error: Option<(ObjectType, ErrorClass)>,
    /// `List` requests are held while this is true.
    pub hold_lists: bool,
    /// A download of an object sends this many frames, then `SESSION_FAILED` with the class and
    /// closes.
    pub fail_reads: Option<(usize, ErrorClass)>,
    /// Never answer a `Write` (the upload is held, as for a capped upload).
    pub hold_writes: bool,
}

pub struct DriveCtl {
    pub store: Arc<Mutex<Store>>,
    pub seen: Arc<Mutex<Vec<Seen>>>,
    pub knobs: Arc<Mutex<DriveKnobs>>,
    pub mute: Arc<AtomicBool>,
    pub cmd: mpsc::Sender<DriveCmd>,
    pub opens: Arc<Mutex<Vec<pb::OpenRepo>>>,
    pub connections: Arc<Mutex<usize>>,
}

impl DriveCtl {
    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    pub fn objects(&self, ty: ObjectType) -> Vec<Vec<u8>> {
        self.store
            .lock()
            .unwrap()
            .keys()
            .filter(|(t, _)| *t == ty as i32)
            .map(|(_, id)| id.clone())
            .collect()
    }

    pub fn put(&self, ty: ObjectType, id: &[u8; 32], data: &[u8]) {
        self.store
            .lock()
            .unwrap()
            .insert((ty as i32, id.to_vec()), data.to_vec());
    }
}

fn start_drive(socket: PathBuf) -> DriveCtl {
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).expect("bind the drive socket");
    let (tx, rx) = mpsc::channel();
    let ctl = DriveCtl {
        store: Arc::default(),
        seen: Arc::default(),
        knobs: Arc::default(),
        mute: Arc::default(),
        cmd: tx,
        opens: Arc::default(),
        connections: Arc::default(),
    };
    let (store, seen, knobs, mute, opens, conns) = (
        ctl.store.clone(),
        ctl.seen.clone(),
        ctl.knobs.clone(),
        ctl.mute.clone(),
        ctl.opens.clone(),
        ctl.connections.clone(),
    );
    std::thread::spawn(move || {
        let rx = rx;
        for conn in listener.incoming() {
            let Ok(conn) = conn else { return };
            *conns.lock().unwrap() += 1;
            serve_drive(conn, &store, &seen, &knobs, &mute, &opens, &rx);
        }
    });
    ctl
}

fn serve_drive(
    conn: UnixStream,
    store: &Arc<Mutex<Store>>,
    seen: &Arc<Mutex<Vec<Seen>>>,
    knobs: &Arc<Mutex<DriveKnobs>>,
    mute: &Arc<AtomicBool>,
    opens: &Arc<Mutex<Vec<pb::OpenRepo>>>,
    cmds: &mpsc::Receiver<DriveCmd>,
) {
    let mut p = Peer::new(conn, Endpoint::DriveHelper);
    p.mute = mute.clone();
    p.set_poll(Duration::from_millis(10));
    let note = |s: Seen| seen.lock().unwrap().push(s);
    let mut uploads: HashMap<u64, (pb::Write, Vec<u8>)> = HashMap::new();
    let mut held_lists: Vec<(u64, ObjectType)> = Vec::new();
    let mut aborted: Vec<u64> = Vec::new();
    loop {
        while let Ok(c) = cmds.try_recv() {
            match c {
                DriveCmd::Event(e) => {
                    let _ = p.send(F::Event(e));
                }
                DriveCmd::Close => {
                    p.close();
                    return;
                }
                DriveCmd::CutClose => {
                    // The prefix of a frame that never completes.
                    p.send_raw(&[200, 0, 0, 0, 1, 1, 2, 3]);
                    p.close();
                    return;
                }
            }
        }
        // Held lists are answered once released.
        if !knobs.lock().unwrap().hold_lists {
            for (id, ty) in std::mem::take(&mut held_lists) {
                answer_list(&mut p, store, id, ty);
            }
        }
        let g = match p.poll() {
            Ok(Some(g)) => g,
            Ok(None) => continue,
            Err(_) => return,
        };
        match g {
            Got::Secret { .. } => return,
            Got::Data {
                stream,
                end,
                payload,
            } => {
                note(Seen::Data {
                    stream,
                    len: payload.len(),
                    end,
                });
                if aborted.contains(&stream) {
                    continue;
                }
                if let Some((_, buf)) = uploads.get_mut(&stream) {
                    buf.extend_from_slice(&payload);
                    if end {
                        let (w, buf) = uploads.remove(&stream).unwrap();
                        let (hold, fail) = {
                            let k = knobs.lock().unwrap();
                            (
                                k.hold_writes,
                                k.write_error.filter(|(t, _)| *t as i32 == w.object_type),
                            )
                        };
                        if hold {
                            uploads.insert(stream, (w, buf));
                            continue;
                        }
                        if let Some((_, class)) = fail {
                            let _ = p.send(F::Response(pb::RepoResponse {
                                req_id: stream,
                                result: Some(pb::repo_response::Result::Error(pb::RepoError {
                                    class: class as i32,
                                    retry_after_ms: 0,
                                })),
                            }));
                        } else {
                            store
                                .lock()
                                .unwrap()
                                .insert((w.object_type, w.id.to_vec()), buf);
                            let _ = p.send(F::Response(pb::RepoResponse {
                                req_id: stream,
                                result: Some(pb::repo_response::Result::Done(pb::Done {})),
                            }));
                        }
                    }
                }
            }
            Got::Msg(m) => match m.frame {
                Some(F::Hello(_)) => {
                    note(Seen::Hello);
                    let _ = p.send(F::HelloAck(pb::HelloAck {
                        major: 1,
                        minor: 0,
                        software: "hx-fake-drive".into(),
                    }));
                }
                Some(F::Bye(_)) => return,
                Some(F::CancelRequest(c)) => {
                    note(Seen::CancelRequest(c.req_id));
                    held_lists.retain(|(id, _)| *id != c.req_id);
                    let was_upload = uploads.remove(&c.req_id).is_some();
                    if was_upload {
                        aborted.push(c.req_id);
                    }
                    let _ = p.send(F::Response(pb::RepoResponse {
                        req_id: c.req_id,
                        result: Some(pb::repo_response::Result::Error(pb::RepoError {
                            class: ErrorClass::Cancelled as i32,
                            retry_after_ms: 0,
                        })),
                    }));
                }
                Some(F::Request(r)) => {
                    use pb::repo_request::Op;
                    let id = r.req_id;
                    let done = |p: &mut Peer| {
                        let _ = p.send(F::Response(pb::RepoResponse {
                            req_id: id,
                            result: Some(pb::repo_response::Result::Done(pb::Done {})),
                        }));
                    };
                    let err = |p: &mut Peer, c: ErrorClass| {
                        let _ = p.send(F::Response(pb::RepoResponse {
                            req_id: id,
                            result: Some(pb::repo_response::Result::Error(pb::RepoError {
                                class: c as i32,
                                retry_after_ms: 0,
                            })),
                        }));
                    };
                    match r.op.unwrap() {
                        Op::OpenRepo(o) => {
                            note(Seen::Open(o.folder.clone()));
                            opens.lock().unwrap().push(o);
                            match knobs.lock().unwrap().open_error {
                                Some(c) => err(&mut p, c),
                                None => done(&mut p),
                            }
                        }
                        Op::Create(_) => {
                            note(Seen::Request("create".into()));
                            done(&mut p);
                        }
                        Op::List(l) => {
                            note(Seen::Request(format!("list {}", l.object_type)));
                            let ty = ObjectType::try_from(l.object_type).unwrap();
                            if knobs.lock().unwrap().hold_lists {
                                held_lists.push((id, ty));
                            } else {
                                answer_list(&mut p, store, id, ty);
                            }
                        }
                        Op::ReadFull(x) => {
                            note(Seen::Request(format!("read {}", x.object_type)));
                            let obj = store
                                .lock()
                                .unwrap()
                                .get(&(x.object_type, x.id.to_vec()))
                                .cloned();
                            match obj {
                                None => err(&mut p, ErrorClass::NotFound),
                                Some(data) => {
                                    let fail = knobs.lock().unwrap().fail_reads;
                                    let _ = p.send(F::Response(pb::RepoResponse {
                                        req_id: id,
                                        result: Some(pb::repo_response::Result::ReadBegin(
                                            pb::ReadBegin {
                                                size: data.len() as u32,
                                            },
                                        )),
                                    }));
                                    let chunks: Vec<&[u8]> = if data.is_empty() {
                                        vec![&[][..]]
                                    } else {
                                        data.chunks(1024 * 1024).collect()
                                    };
                                    let n = chunks.len();
                                    for (i, c) in chunks.into_iter().enumerate() {
                                        if let Some((after, class)) = fail
                                            && i >= after
                                        {
                                            let _ = p.send(F::Event(pb::Event {
                                                kind: pb::EventKind::SessionFailed as i32,
                                                until_ms: 0,
                                                error_class: class as i32,
                                            }));
                                            p.close();
                                            return;
                                        }
                                        let _ = p.send_data(id, i + 1 == n, c);
                                    }
                                }
                            }
                        }
                        Op::Write(w) => {
                            note(Seen::Request(format!("write {}", w.object_type)));
                            uploads.insert(id, (w, Vec::new()));
                        }
                        Op::Remove(x) => {
                            note(Seen::Request(format!("remove {}", x.object_type)));
                            store
                                .lock()
                                .unwrap()
                                .remove(&(x.object_type, x.id.to_vec()));
                            done(&mut p);
                        }
                        Op::ReadPartial(_) | Op::Quota(_) | Op::SetUploadRate(_) => {
                            err(&mut p, ErrorClass::Internal)
                        }
                    }
                }
                _ => {}
            },
        }
    }
}

fn answer_list(p: &mut Peer, store: &Arc<Mutex<Store>>, id: u64, ty: ObjectType) {
    let entries: Vec<pb::ListEntry> = store
        .lock()
        .unwrap()
        .iter()
        .filter(|((t, _), _)| *t == ty as i32)
        .map(|((_, oid), data)| pb::ListEntry {
            id: Bytes::copy_from_slice(oid),
            size: data.len() as u32,
        })
        .collect();
    let _ = p.send(F::Response(pb::RepoResponse {
        req_id: id,
        result: Some(pb::repo_response::Result::ListPage(pb::ListPage {
            entries,
            last: true,
        })),
    }));
}

// ----- the rig --------------------------------------------------------------------------------

pub struct Rig {
    pub dir: TempDir,
    pub mono: Arc<ManualMono>,
    pub env: Arc<FakeEnv>,
    pub host: Arc<FakeHost>,
    pub runner: JobRunner<Arc<FakeHost>, FakeEnv>,
    pub drive: DriveCtl,
    pub cfg: BackupConfig,
}

pub type Script = Arc<dyn Fn(&mut WorkerPeer) + Send + Sync>;

impl Rig {
    /// A rig whose runner has not recovered yet.
    pub fn raw() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        for d in ["state", "run", "creds", "credsrt"] {
            std::fs::create_dir_all(p.join(d)).unwrap();
        }
        std::fs::set_permissions(p.join("run"), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(p.join("creds/drive-token.cred"), b"sealed-fake").unwrap();
        std::fs::write(p.join("credsrt/backup-key"), KEY).unwrap();
        std::fs::set_permissions(
            p.join("credsrt/backup-key"),
            std::fs::Permissions::from_mode(0o400),
        )
        .unwrap();
        std::fs::write(p.join("worker-binary"), b"\x7fELF-fake-worker").unwrap();
        let cfg = BackupConfig {
            state_dir: p.join("state"),
            run_dir: p.join("run"),
            drive_socket: p.join("drive.sock"),
            drive_cred: p.join("creds/drive-token.cred"),
            credentials_dir: Some(p.join("credsrt")),
            worker_binary: p.join("worker-binary"),
            expected_owner: None,
            instance_prefix: "hx-".into(),
            agent_version: "0.0.0-test".into(),
            timing: Timing::fast(),
        };
        let mono = Arc::new(ManualMono::new());
        let env = FakeEnv::new(&["main"]);
        let host = FakeHost::new(cfg.run_dir.clone());
        let drive = start_drive(cfg.drive_socket.clone());
        let runner = JobRunner::new(cfg.clone(), host.clone(), env.clone(), mono.clone());
        Self {
            dir,
            mono,
            env,
            host,
            runner,
            drive,
            cfg,
        }
    }

    /// A rig whose runner has recovered (admits jobs).
    pub async fn ready() -> Self {
        let r = Self::raw();
        let rep = r.runner.recover().await;
        assert!(rep.complete, "{rep:?}");
        r
    }

    /// Runs `script` as the worker of every job this rig starts.
    pub fn worker(&self, script: impl Fn(&mut WorkerPeer) + Send + Sync + 'static) {
        let script: Script = Arc::new(script);
        let host = self.host.clone();
        self.host.set_on_start(move |info: StartInfo| {
            let (script, host) = (script.clone(), host.clone());
            std::thread::spawn(move || {
                let mut w = WorkerPeer::accept(&info.socket);
                script(&mut w);
                // The worker exits and Incus deletes the ephemeral helper.
                drop(w);
                host.helper_exited(info.job);
            });
        });
    }

    pub fn request(&self, spec: JobSpec) -> JobRequest {
        JobRequest {
            desktop_id: "main".into(),
            spec,
            repo_password: RepoPassword::HostBackupKey,
            new_key_password: None,
            takeover: false,
            folder: None,
            progress: None,
        }
    }

    pub fn backup_request(&self) -> JobRequest {
        self.request(JobSpec::Backup(BackupParams::default()))
    }

    /// Moves the monotonic clock by `total_ms` in steps of `step_ms`, letting the loops run
    /// between steps (so that pings and pongs go round).
    pub async fn advance(&self, total_ms: u64, step_ms: u64) {
        let mut left = total_ms;
        while left > 0 {
            let s = left.min(step_ms);
            self.mono.advance_ms(s);
            left -= s;
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Waits for the outcome, with a real-time bound.
    pub async fn outcome(&self, h: &JobHandle) -> Arc<JobOutcome> {
        tokio::time::timeout(Duration::from_secs(30), h.finished())
            .await
            .expect("the job did not finish in 30 s")
    }

    /// Polls `f` until it is true (real time, at most 20 s).
    pub async fn until(&self, what: &str, f: impl Fn() -> bool) {
        let t = Instant::now();
        while !f() {
            assert!(
                t.elapsed() < Duration::from_secs(20),
                "timed out waiting for {what}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub fn audit(&self) -> String {
        self.env.audit_log().join("\n")
    }

    pub fn desktop_dir(&self) -> PathBuf {
        self.cfg.state_dir.join("backup/main")
    }
}

/// A valid manifest of a snapshot, as the worker's `RESTORE_PLAN` returns it.
pub fn manifest_json(snapshot_hex: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "format_version": 1,
        "created_at": "2026-11-27T03:00:00Z",
        "agent_version": "0.1.0",
        "distro": {"id": "ubuntu", "version_id": "24.04", "pretty_name": "Ubuntu 24.04"},
        "desktop": "xfce",
        "preset": "basic",
        "docker_mode": null,
        "container_config": {"limits.cpu": "2"},
        "source_sizes": {"files": 10, "directories": 2, "bytes": 1000, "excluded_paths": 0},
        "rustic_snapshot_id": snapshot_hex,
    }))
    .unwrap()
}

pub fn zeroizing(b: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(b.to_vec())
}
