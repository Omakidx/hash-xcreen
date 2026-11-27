//! Test support for the Drive helper: the fake Google (`fake`), a fake `hx-privd` end of the Drive
//! link (`PrivdEnd`, which speaks the real codec and `LinkState` of `hx_ipc::repo`), and a `Rig` that
//! wires a helper session to the fake with scaled timing. No test reaches a real network.
#![allow(dead_code)]

pub mod fake;

use std::collections::HashMap;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use hx_backup_worker::drive::DriveConfig;
use hx_backup_worker::drive::creds::ClientConfig;
use hx_backup_worker::drive::retry::Timing;
use hx_backup_worker::drive::server::{End, serve_connection};
use hx_backup_worker::drive::transport::HttpConfig;
use hx_ipc::frame::Decoder;
use hx_ipc::recv::NoCmsgReader;
use hx_ipc::repo::{
    self, Endpoint, Incoming, LinkState, RepoFramePolicy, encode_data_header, encode_message, pb,
};

pub use fake::*;

pub const SERVER_A: [u8; 16] = [0xa1; 16];
pub const SERVER_B: [u8; 16] = [0xb2; 16];
pub const JOB: [u8; 16] = [7; 16];

pub type T = pb::ObjectType;
pub type EC = pb::ErrorClass;

/// 32 bytes that are not all zero and whose first byte is `n`.
pub fn id(n: u8) -> [u8; 32] {
    let mut i = [n.wrapping_add(1); 32];
    i[0] = n;
    i
}

pub fn hex(id: &[u8]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// The path of an object in the fake, below the repository folder `repo`.
pub fn path_of(ty: T, id: &[u8; 32]) -> String {
    let h = hex(id);
    match ty {
        T::Config => "repo/config".into(),
        T::Key => format!("repo/keys/{h}"),
        T::Snapshot => format!("repo/snapshots/{h}"),
        T::Index => format!("repo/index/{h}"),
        T::Pack => format!("repo/data/{}/{h}", &h[..2]),
        T::Unspecified => unreachable!(),
    }
}

pub fn data(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// What a request ended with, as privd sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    Done,
    Quota(pb::QuotaResult),
    List(Vec<(Vec<u8>, u32)>),
    Read(Vec<u8>),
    Error(EC, u32),
}

impl Reply {
    pub fn class(&self) -> Option<EC> {
        match self {
            Reply::Error(c, _) => Some(*c),
            _ => None,
        }
    }

    pub fn ok(self) -> Reply {
        if let Reply::Error(c, _) = &self {
            panic!("unexpected error {c:?}");
        }
        self
    }
}

#[derive(Default)]
struct Partial {
    pages: Vec<(Vec<u8>, u32)>,
    read: Option<(Vec<u8>, u32)>,
}

/// The privd end of the Drive link: real codec, real `LinkState` at `PrivdDriveLink`.
pub struct PrivdEnd {
    pub stream: UnixStream,
    dec: Decoder<RepoFramePolicy>,
    pub st: LinkState,
    next_req: u64,
    pub events: Vec<pb::Event>,
    pub pongs: Vec<u64>,
    pub pages_seen: usize,
    pub frames_seen: usize,
    pub pong_at_frame: Option<usize>,
    pub software: Option<String>,
    done: HashMap<u64, Reply>,
    partial: HashMap<u64, Partial>,
}

impl PrivdEnd {
    pub fn new(stream: UnixStream) -> Self {
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        Self {
            stream,
            dec: Decoder::new(RepoFramePolicy::new(Endpoint::PrivdDriveLink)),
            st: LinkState::new(Endpoint::PrivdDriveLink),
            next_req: 1,
            events: vec![],
            pongs: vec![],
            pages_seen: 0,
            frames_seen: 0,
            pong_at_frame: None,
            software: None,
            done: HashMap::new(),
            partial: HashMap::new(),
        }
    }

    pub fn send_frame(&mut self, f: pb::repo_frame::Frame) {
        let f = pb::RepoFrame { frame: Some(f) };
        self.st
            .sent_message(&f)
            .expect("privd end broke a rule of the link");
        let bytes = encode_message(&f, Endpoint::DriveHelper).unwrap();
        self.stream.write_all(&bytes).unwrap();
    }

    pub fn send_raw(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).unwrap();
    }

    pub fn hello(&mut self) {
        self.send_frame(pb::repo_frame::Frame::Hello(pb::Hello {
            major: repo::VERSION_MAJOR,
            minor: repo::VERSION_MINOR,
            job_id: bytes::Bytes::copy_from_slice(&JOB),
        }));
        while !self.st.is_open() {
            self.pump().expect("HelloAck");
        }
    }

    pub fn ping(&mut self, nonce: u64) {
        self.send_frame(pb::repo_frame::Frame::Ping(pb::Ping { nonce }));
    }

    pub fn bye(&mut self) {
        self.send_frame(pb::repo_frame::Frame::Bye(pb::Bye {}));
    }

    pub fn request(&mut self, op: pb::repo_request::Op) -> u64 {
        let req_id = self.next_req;
        self.next_req += 1;
        self.send_frame(pb::repo_frame::Frame::Request(pb::RepoRequest {
            req_id,
            op: Some(op),
        }));
        req_id
    }

    pub fn cancel(&mut self, req_id: u64) {
        self.send_frame(pb::repo_frame::Frame::CancelRequest(pb::CancelRequest {
            req_id,
        }));
    }

    pub fn data_frame(&mut self, req_id: u64, payload: &[u8], end: bool) {
        self.st
            .sent_data(req_id, end, payload.len())
            .expect("privd end broke a data rule");
        let h = encode_data_header(req_id, end, payload.len()).unwrap();
        self.stream.write_all(&h).unwrap();
        self.stream.write_all(payload).unwrap();
    }

    /// The whole body of an upload, in chunks, ending with END.
    pub fn upload(&mut self, req_id: u64, body: &[u8]) {
        let mut chunks = body.chunks(256 * 1024).peekable();
        if chunks.peek().is_none() {
            self.data_frame(req_id, &[], true);
            return;
        }
        while let Some(c) = chunks.next() {
            self.data_frame(req_id, c, chunks.peek().is_none());
        }
    }

    /// Reads and processes one frame. `Err` is a read error or timeout.
    pub fn pump(&mut self) -> Result<(), String> {
        let raw = match self.dec.read_from(&mut NoCmsgReader(&self.stream)) {
            Ok(Some(f)) => f,
            Ok(None) => return Err("closed".into()),
            Err(e) => return Err(format!("{e}")),
        };
        let incoming = repo::decode(raw, Endpoint::PrivdDriveLink).map_err(|e| e.to_string())?;
        self.st.received(&incoming).map_err(|e| e.0.to_string())?;
        self.frames_seen += 1;
        match incoming {
            Incoming::Data(d) => {
                let p = self
                    .partial
                    .get_mut(&d.stream_id)
                    .expect("data for a stream");
                let (buf, size) = p.read.as_mut().expect("data before ReadBegin");
                buf.extend_from_slice(&d.payload);
                if d.end {
                    assert_eq!(buf.len() as u32, *size, "stream size");
                    let (buf, _) = p.read.take().unwrap();
                    self.partial.remove(&d.stream_id);
                    self.done.insert(d.stream_id, Reply::Read(buf));
                }
            }
            Incoming::Secret(_) => unreachable!(),
            Incoming::Message(m) => {
                use pb::repo_frame::Frame as F;
                use pb::repo_response::Result as R;
                match m.frame.unwrap() {
                    F::HelloAck(a) => self.software = Some(a.software),
                    F::Pong(p) => {
                        self.pongs.push(p.nonce);
                        self.pong_at_frame.get_or_insert(self.frames_seen);
                    }
                    F::Event(e) => self.events.push(e),
                    F::Response(r) => {
                        let req = r.req_id;
                        match r.result.unwrap() {
                            R::Done(_) => {
                                self.done.insert(req, Reply::Done);
                            }
                            R::QuotaResult(q) => {
                                self.done.insert(req, Reply::Quota(q));
                            }
                            R::Error(e) => {
                                self.partial.remove(&req);
                                let class = pb::ErrorClass::try_from(e.class).unwrap();
                                self.done.insert(req, Reply::Error(class, e.retry_after_ms));
                            }
                            R::ListPage(p) => {
                                self.pages_seen += 1;
                                let part = self.partial.entry(req).or_default();
                                part.pages
                                    .extend(p.entries.iter().map(|e| (e.id.to_vec(), e.size)));
                                if p.last {
                                    let part = self.partial.remove(&req).unwrap();
                                    self.done.insert(req, Reply::List(part.pages));
                                }
                            }
                            R::ReadBegin(b) => {
                                let part = self.partial.entry(req).or_default();
                                part.read = Some((Vec::new(), b.size));
                                if b.size == 0 {
                                    // the empty END frame follows
                                }
                            }
                        }
                    }
                    other => panic!("unexpected frame from the helper: {other:?}"),
                }
            }
        }
        Ok(())
    }

    /// Pumps until `req_id` has its reply.
    pub fn wait(&mut self, req_id: u64) -> Reply {
        loop {
            if let Some(r) = self.done.remove(&req_id) {
                return r;
            }
            self.pump()
                .unwrap_or_else(|e| panic!("waiting for request {req_id}: {e}"));
        }
    }

    /// Pumps until `req_id` has begun a download (its `ReadBegin` arrived).
    pub fn wait_read_begin(&mut self, req_id: u64) {
        while self.partial.get(&req_id).is_none_or(|p| p.read.is_none()) {
            self.pump().expect("ReadBegin");
        }
    }

    /// Pumps for `d` (or until the link closes) collecting whatever arrives.
    pub fn pump_for(&mut self, d: Duration) {
        let _ = self
            .stream
            .set_read_timeout(Some(Duration::from_millis(50)));
        let end = Instant::now() + d;
        while Instant::now() < end {
            let _ = self.pump();
        }
        let _ = self.stream.set_read_timeout(Some(Duration::from_secs(30)));
    }

    pub fn call(&mut self, op: pb::repo_request::Op) -> Reply {
        let r = self.request(op);
        self.wait(r)
    }

    pub fn open(&mut self, folder: &str, create: bool, server: [u8; 16], takeover: bool) -> Reply {
        self.call(pb::repo_request::Op::OpenRepo(pb::OpenRepo {
            folder: folder.to_owned(),
            create,
            server_id: bytes::Bytes::copy_from_slice(&server),
            takeover,
        }))
    }

    pub fn create(&mut self) -> Reply {
        self.call(pb::repo_request::Op::Create(pb::Create {}))
    }

    pub fn write(&mut self, ty: T, id: &[u8; 32], body: &[u8]) -> Reply {
        let r = self.request(pb::repo_request::Op::Write(pb::Write {
            object_type: ty as i32,
            id: bytes::Bytes::copy_from_slice(id),
            size: body.len() as u32,
        }));
        self.upload(r, body);
        self.wait(r)
    }

    pub fn list(&mut self, ty: T) -> Reply {
        self.call(pb::repo_request::Op::List(pb::List {
            object_type: ty as i32,
        }))
    }

    pub fn read_full(&mut self, ty: T, id: &[u8; 32]) -> Reply {
        self.call(pb::repo_request::Op::ReadFull(pb::ReadFull {
            object_type: ty as i32,
            id: bytes::Bytes::copy_from_slice(id),
        }))
    }

    pub fn read_partial(&mut self, ty: T, id: &[u8; 32], offset: u32, length: u32) -> Reply {
        self.call(pb::repo_request::Op::ReadPartial(pb::ReadPartial {
            object_type: ty as i32,
            id: bytes::Bytes::copy_from_slice(id),
            offset,
            length,
        }))
    }

    pub fn remove(&mut self, ty: T, id: &[u8; 32]) -> Reply {
        self.call(pb::repo_request::Op::Remove(pb::Remove {
            object_type: ty as i32,
            id: bytes::Bytes::copy_from_slice(id),
        }))
    }

    pub fn set_rate(&mut self, bps: u64) -> Reply {
        self.call(pb::repo_request::Op::SetUploadRate(pb::SetUploadRate {
            bytes_per_s: bps,
        }))
    }

    pub fn quota(&mut self) -> Reply {
        self.call(pb::repo_request::Op::Quota(pb::Quota {}))
    }

    pub fn event_kinds(&self) -> Vec<pb::EventKind> {
        self.events
            .iter()
            .map(|e| pb::EventKind::try_from(e.kind).unwrap())
            .collect()
    }

    pub fn count_events(&self, k: pb::EventKind) -> usize {
        self.event_kinds().iter().filter(|x| **x == k).count()
    }
}

/// Test timing: fast backoff, generous attempt timeouts, a short lease cache.
pub fn test_timing() -> Timing {
    let mut t = Timing::production();
    t.initial = Duration::from_millis(10);
    t.max_delay = Duration::from_millis(80);
    t.daily_pause = Duration::from_millis(150);
    t.idle = Duration::from_secs(10);
    t.request_budget = Duration::from_secs(120);
    t.lease_cache = Duration::from_millis(400);
    t
}

pub struct Rig {
    pub fake: FakeGoogle,
    pub dir: tempfile::TempDir,
    pub cfg: DriveConfig,
}

pub fn token_json() -> String {
    format!(r#"{{"refresh_token":"{REFRESH_TOKEN}"}}"#)
}

pub fn client_json() -> String {
    format!(r#"{{"client_id":"{CLIENT_ID}","client_secret":"{CLIENT_SECRET}"}}"#)
}

impl Rig {
    pub fn new() -> Self {
        Self::with(|_| {})
    }

    pub fn with(f: impl FnOnce(&mut DriveConfig)) -> Self {
        if std::env::var_os("HX_TEST_LOG").is_some() {
            let _ = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_writer(std::io::stderr)
                .try_init();
        }
        let fake = FakeGoogle::start();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("drive-token"), token_json()).unwrap();
        let mut cfg = DriveConfig {
            client: ClientConfig::parse(client_json().as_bytes()).unwrap(),
            credentials_dir: Some(dir.path().to_owned()),
            http: HttpConfig {
                extra_roots_pem: Some(fake.cert_pem.clone().into_bytes()),
                api_addr: Some(fake.addr.to_string()),
            },
            timing: test_timing(),
            silence: Duration::from_secs(30),
            hostname: b"test host/1".to_vec(),
        };
        f(&mut cfg);
        Self { fake, dir, cfg }
    }

    pub fn session(&self) -> Session {
        let (a, b) = UnixStream::pair().unwrap();
        let cfg = self.cfg.clone();
        let handle = std::thread::spawn(move || serve_connection(b, &cfg));
        Session {
            env: PrivdEnd::new(a),
            handle: Some(handle),
        }
    }

    /// A session with the handshake done and the repository `repo` opened (created).
    pub fn open_session(&self) -> Session {
        let mut s = self.session();
        s.env.hello();
        s.env.open("repo", true, SERVER_A, false).ok();
        s
    }

    pub fn lease(&self) -> Option<serde_json::Value> {
        self.fake
            .with(|m| m.get("repo/hx-lease.json"))
            .map(|b| serde_json::from_slice(&b).unwrap())
    }

    pub fn put_lease(&self, server: &[u8; 16], generation: u64) {
        let v = format!(
            r#"{{"format":1,"server_id":"{}","generation":{generation},"taken_at":1,"hostname_hint":"other"}}"#,
            hex(server)
        );
        self.fake
            .with(|m| m.put("repo/hx-lease.json", v.as_bytes()));
    }
}

pub struct Session {
    pub env: PrivdEnd,
    handle: Option<JoinHandle<End>>,
}

impl Session {
    /// Ends the session (Bye) and returns how the helper saw it end.
    pub fn finish(mut self) -> End {
        self.env.bye();
        self.join()
    }

    pub fn join(mut self) -> End {
        let h = self.handle.take().unwrap();
        let _ = self.env.stream.shutdown(std::net::Shutdown::Both);
        h.join().unwrap()
    }

    /// Waits for the helper's end of the session without closing it first.
    pub fn join_without_closing(mut self) -> End {
        self.handle.take().unwrap().join().unwrap()
    }
}

pub fn temp_socket_path(dir: &tempfile::TempDir, name: &str) -> PathBuf {
    dir.path().join(name)
}

pub fn arc<T>(v: T) -> Arc<T> {
    Arc::new(v)
}
