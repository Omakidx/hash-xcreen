//! One link session of the Drive helper (ipc.md §25 to §27, §29, §31, §32).
//!
//! ```text
//! reader (the calling thread)          writer thread               session runtime (tokio)
//!   Decoder -> decode -> LinkState  --> ctl queue  --\
//!   Hello, Ping, Cancel: answered here  out queue  ---+-> LinkState --> socket   one task per request:
//!   Write: data frames collected here, the task starts at END                    OpenDAL + retries -> out
//! ```
//!
//! The reader never waits for Drive or for the data queue: uploads are held whole until their
//! `END`, so a request that is stuck in a backoff or at the daily-limit gate cannot stop the link
//! from answering `Ping`, and the replies that only the reader sends (`HelloAck`, `Pong`, the
//! answer to a cancelled upload) go through the `ctl` queue, which is unbounded (a few frames per
//! request at most) and which the writer empties before it takes anything from the data queue. So a
//! link whose data frames are backed up still answers. Every frame goes through [`LinkState`] in
//! both directions, so a local bug shows as an error here and not as a peer's closed link. Nothing
//! a peer sent is logged.

use std::collections::HashMap;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use hx_ipc::frame::Decoder;
use hx_ipc::recv::NoCmsgReader;
use hx_ipc::repo::{
    self, Endpoint, Incoming, LinkState, RepoFramePolicy, encode_data_header, encode_message, pb,
};
use tokio::runtime::Handle;
use tokio::sync::{mpsc, watch};

use super::DriveConfig;
use super::creds::Token;
use super::gdrive::{Drive, Id, OpenParams, ReadStream, Repo};
use super::rate::UploadRate;
use super::retry::{Cancel, CancelHandle, DriveError, Retrier};
use super::transport::GoogleTransport;

use pb::ErrorClass as EC;

/// How a session ended. The helper itself goes on (ipc.md §24): this is only for the log and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum End {
    /// privd sent `Bye`.
    Bye,
    /// The link closed without `Bye`.
    Lost,
    /// privd sent nothing for the silence timeout.
    Silent,
    /// A rule of the link was broken (the text names the rule).
    Violation(&'static str),
    /// The helper could not write to the link (or its own frame broke a rule).
    WriteFailed,
}

#[allow(clippy::large_enum_variant)] // at most 16 queued; boxing would only add an allocation per frame
enum Out {
    Message(pb::RepoFrame),
    Data {
        stream_id: u64,
        end: bool,
        payload: Bytes,
    },
    /// Close the link. Only the writer closes it, between two frames (ipc.md §29, §32).
    Close,
}

/// The largest `Write` of a `PACK` or an `INDEX` the helper buffers (ipc.md §29, "Memory").
const WRITE_CAP: u32 = 72 * 1024 * 1024;

/// What a request task has to send at its end.
enum Answer {
    /// One final message (`Done`, `QuotaResult`).
    Final(pb::repo_response::Result),
    /// The pages or the stream were the answer.
    Sent,
}

type RepoCell = Option<Result<Arc<Repo>, DriveError>>;

struct Shared {
    state: Arc<Mutex<LinkState>>,
    out: mpsc::Sender<Out>,
    /// Replies of the reader: the writer empties this queue first.
    ctl: mpsc::UnboundedSender<Out>,
    /// The deadline of each request.
    budget: Duration,
    cancels: Mutex<HashMap<u64, CancelHandle>>,
    drive: Result<Arc<Drive>, DriveError>,
    repo: watch::Sender<RepoCell>,
    rate: Arc<UploadRate>,
}

struct Upload {
    ty: pb::ObjectType,
    id: Id,
    chunks: Vec<Bytes>,
    cancel: Cancel,
}

fn frame(f: pb::repo_frame::Frame) -> pb::RepoFrame {
    pb::RepoFrame { frame: Some(f) }
}

fn response(req_id: u64, result: pb::repo_response::Result) -> Out {
    Out::Message(frame(pb::repo_frame::Frame::Response(pb::RepoResponse {
        req_id,
        result: Some(result),
    })))
}

fn error_response(req_id: u64, e: DriveError) -> Out {
    response(
        req_id,
        pb::repo_response::Result::Error(pb::RepoError {
            class: e.class as i32,
            retry_after_ms: e.retry_after_ms,
        }),
    )
}

fn id_of(bytes: &[u8]) -> Id {
    let mut id = [0u8; 32];
    if bytes.len() == 32 {
        id.copy_from_slice(bytes);
    }
    id
}

fn object_type(v: i32) -> pb::ObjectType {
    pb::ObjectType::try_from(v).unwrap_or(pb::ObjectType::Unspecified)
}

impl Shared {
    async fn wait_repo(&self, cancel: &Cancel) -> Result<Arc<Repo>, DriveError> {
        let mut rx = self.repo.subscribe();
        let cell = cancel
            .guard(async { rx.wait_for(Option::is_some).await.map(|c| c.clone()) })
            .await?
            .map_err(|_| DriveError::new(EC::Internal))?;
        match cell {
            Some(Ok(r)) => Ok(r),
            _ => Err(DriveError::new(EC::Internal)),
        }
    }

    async fn send(&self, o: Out) {
        let _ = self.out.send(o).await;
    }

    /// `OpenRepo`. Whatever happens, the cell is set, so that no later request waits for ever.
    async fn serve_open(&self, o: &pb::OpenRepo, cancel: &Cancel) -> Result<(), DriveError> {
        let r = self.open_repo(o, cancel).await;
        match &r {
            Ok(repo) => self.repo.send_replace(Some(Ok(repo.clone()))),
            Err(e) => self.repo.send_replace(Some(Err(*e))),
        };
        r.map(|_| ())
    }

    async fn open_repo(&self, o: &pb::OpenRepo, cancel: &Cancel) -> Result<Arc<Repo>, DriveError> {
        let drive = self.drive.clone()?;
        // The codec has checked the length; a wrong one is still no panic.
        let server_id = <[u8; 16]>::try_from(o.server_id.as_ref())
            .map_err(|_| DriveError::new(EC::Internal))?;
        let params = OpenParams {
            folder: o.folder.clone(),
            create: o.create,
            server_id,
            takeover: o.takeover,
        };
        drive.open(&params, cancel).await.map(Arc::new)
    }

    /// Answers one request; the answer is sent here.
    async fn serve(
        self: Arc<Self>,
        req_id: u64,
        op: pb::repo_request::Op,
        upload: Option<Upload>,
        cancel: Cancel,
    ) {
        use pb::repo_request::Op;
        let result: Result<Answer, DriveError> = async {
            let done = || Ok(Answer::Final(pb::repo_response::Result::Done(pb::Done {})));
            match op {
                Op::OpenRepo(o) => {
                    self.serve_open(&o, &cancel).await?;
                    done()
                }
                Op::Quota(_) => {
                    let q = self.wait_repo(&cancel).await?.quota(&cancel).await?;
                    Ok(Answer::Final(pb::repo_response::Result::QuotaResult(
                        pb::QuotaResult {
                            limit: q.limit,
                            usage: q.usage,
                            usage_in_trash: q.usage_in_trash,
                        },
                    )))
                }
                Op::SetUploadRate(r) => {
                    self.rate.set(r.bytes_per_s);
                    done()
                }
                Op::Create(_) => {
                    self.wait_repo(&cancel).await?.create(&cancel).await?;
                    done()
                }
                Op::Remove(r) => {
                    let repo = self.wait_repo(&cancel).await?;
                    repo.remove(object_type(r.object_type), &id_of(&r.id), &cancel)
                        .await?;
                    done()
                }
                Op::Write(_) => {
                    let up = upload.ok_or(DriveError::new(EC::Internal))?;
                    let repo = self.wait_repo(&cancel).await?;
                    repo.write(up.ty, &up.id, up.chunks, &cancel).await?;
                    done()
                }
                Op::List(l) => {
                    let repo = self.wait_repo(&cancel).await?;
                    let entries = repo.list(object_type(l.object_type), &cancel).await?;
                    self.send_list(req_id, entries).await;
                    Ok(Answer::Sent)
                }
                Op::ReadFull(r) => {
                    let repo = self.wait_repo(&cancel).await?;
                    let rs = repo
                        .open_read(object_type(r.object_type), &id_of(&r.id), None, &cancel)
                        .await?;
                    self.stream_read(req_id, rs, &cancel).await
                }
                Op::ReadPartial(r) => {
                    let repo = self.wait_repo(&cancel).await?;
                    let rs = repo
                        .open_read(
                            object_type(r.object_type),
                            &id_of(&r.id),
                            Some((r.offset, r.length)),
                            &cancel,
                        )
                        .await?;
                    self.stream_read(req_id, rs, &cancel).await
                }
            }
        }
        .await;
        self.cancels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&req_id);
        match result {
            Ok(Answer::Final(r)) => self.send(response(req_id, r)).await,
            // A listing and a read have sent their own answer.
            Ok(Answer::Sent) => {}
            Err(e) => self.send(error_response(req_id, e)).await,
        }
    }

    async fn send_list(&self, req_id: u64, entries: Vec<(Id, u32)>) {
        let mut pages = entries.chunks(repo::MAX_LIST_PAGE_ENTRIES).peekable();
        if pages.peek().is_none() {
            self.send(response(
                req_id,
                pb::repo_response::Result::ListPage(pb::ListPage {
                    entries: vec![],
                    last: true,
                }),
            ))
            .await;
            return;
        }
        while let Some(page) = pages.next() {
            let last = pages.peek().is_none();
            self.send(response(
                req_id,
                pb::repo_response::Result::ListPage(pb::ListPage {
                    entries: page
                        .iter()
                        .map(|(id, size)| pb::ListEntry {
                            id: Bytes::copy_from_slice(id),
                            size: *size,
                        })
                        .collect(),
                    last,
                }),
            ))
            .await;
        }
    }

    /// `ReadBegin` and the data stream, a chunk at a time. From `ReadBegin` on the stream runs to
    /// its `END`, whatever happens to the request (ipc.md §29), and a failure of the source cannot
    /// be an answer (§25): the link is closed. The permit of a chunk is kept until its frames are
    /// queued.
    async fn stream_read(
        &self,
        req_id: u64,
        mut rs: ReadStream,
        cancel: &Cancel,
    ) -> Result<Answer, DriveError> {
        if cancel.is_cancelled() {
            return Err(DriveError::new(EC::Cancelled));
        }
        let size = rs.size() as usize;
        self.send(response(
            req_id,
            pb::repo_response::Result::ReadBegin(pb::ReadBegin { size: rs.size() }),
        ))
        .await;
        // Cancelling no longer applies, and neither does the request's deadline: the request has
        // been answered, and only the no-progress timer watches the rest.
        let go = Cancel::never_with_limit(Duration::from_secs(u64::from(u32::MAX)));
        if size == 0 {
            self.send(Out::Data {
                stream_id: req_id,
                end: true,
                payload: Bytes::new(),
            })
            .await;
            return Ok(Answer::Sent);
        }
        let mut sent = 0usize;
        while sent < size {
            let chunk = match rs.next_chunk(&go).await {
                Ok(Some(c)) if sent + c.len() <= size => c,
                _ => {
                    eprintln!(
                        "hx-backup-worker: a download failed after ReadBegin: closing the link"
                    );
                    // The writer closes the link between two frames, so privd sees a clean end.
                    let _ = self.ctl.send(Out::Close);
                    return Ok(Answer::Sent);
                }
            };
            let mut frame = BytesMut::with_capacity(repo::MAX_DATA_PAYLOAD.min(size - sent));
            for part in &chunk.parts {
                let mut part = part.clone();
                while !part.is_empty() {
                    let room = repo::MAX_DATA_PAYLOAD - frame.len();
                    let take = part.len().min(room);
                    frame.extend_from_slice(&part.split_to(take));
                    if frame.len() == repo::MAX_DATA_PAYLOAD {
                        sent += frame.len();
                        let payload = std::mem::replace(
                            &mut frame,
                            BytesMut::with_capacity(repo::MAX_DATA_PAYLOAD.min(size - sent)),
                        );
                        self.send(Out::Data {
                            stream_id: req_id,
                            end: sent == size,
                            payload: payload.freeze(),
                        })
                        .await;
                    }
                }
            }
            if !frame.is_empty() {
                sent += frame.len();
                self.send(Out::Data {
                    stream_id: req_id,
                    end: sent == size,
                    payload: frame.freeze(),
                })
                .await;
            }
            // `chunk` (and its permit) ends here: its frames are queued.
        }
        Ok(Answer::Sent)
    }
}

fn write_out(
    stream: &mut UnixStream,
    state: &Mutex<LinkState>,
    item: Out,
) -> Result<(), &'static str> {
    match item {
        Out::Message(f) => {
            state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .sent_message(&f)
                .map_err(|e| e.0)?;
            let bytes = encode_message(&f, Endpoint::PrivdDriveLink).map_err(|_| "encode")?;
            stream.write_all(&bytes).map_err(|_| "write")
        }
        Out::Close => Err("closed"),
        Out::Data {
            stream_id,
            end,
            payload,
        } => {
            state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .sent_data(stream_id, end, payload.len())
                .map_err(|e| e.0)?;
            let header = encode_data_header(stream_id, end, payload.len()).map_err(|_| "encode")?;
            stream.write_all(&header).map_err(|_| "write")?;
            stream.write_all(&payload).map_err(|_| "write")
        }
    }
}

/// Serves one connection until it ends. Builds the session's runtime, which is dropped (and every
/// request task with it) when the connection ends.
pub fn serve_connection(stream: UnixStream, cfg: &DriveConfig) -> End {
    let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .thread_name("hx-drive")
        .enable_all()
        .build()
    else {
        eprintln!("hx-backup-worker: cannot start the session runtime");
        return End::Lost;
    };
    let (end, writer) = serve(&rt, stream, cfg);
    rt.shutdown_timeout(Duration::from_secs(3));
    let write_failed = writer.is_some_and(|w| !w.join().unwrap_or(false));
    if write_failed && !matches!(end, End::Bye | End::Violation(_)) {
        return End::WriteFailed;
    }
    end
}

fn build_drive(
    rt: &tokio::runtime::Runtime,
    cfg: &DriveConfig,
    rate: Arc<UploadRate>,
    retrier: Arc<Retrier>,
) -> Result<Arc<Drive>, DriveError> {
    // No usable token: nothing to refresh, and the remedy is the one for a revoked token.
    let token = match Token::load(cfg.credentials_dir.as_deref()) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("drive token unusable: {e}");
            return Err(DriveError::new(EC::AuthRevoked));
        }
    };
    let _enter = rt.enter();
    let transport = GoogleTransport::new(&cfg.http, rate, cfg.timing).map_err(|e| {
        tracing::error!("{e}");
        DriveError::new(EC::Internal)
    })?;
    Ok(Arc::new(Drive::new(
        retrier,
        transport,
        cfg.client.clone(),
        token,
        &cfg.hostname,
    )))
}

fn serve(
    rt: &tokio::runtime::Runtime,
    stream: UnixStream,
    cfg: &DriveConfig,
) -> (End, Option<std::thread::JoinHandle<bool>>) {
    let rate = Arc::new(UploadRate::new());
    let retrier = Arc::new(Retrier::new(cfg.timing));
    let (out_tx, out_rx) = mpsc::channel::<Out>(cfg.timing.out_queue);
    let (ctl_tx, ctl_rx) = mpsc::unbounded_channel::<Out>();
    let (ev_tx, mut ev_rx) = mpsc::channel::<pb::Event>(64);
    retrier.set_events(ev_tx);
    let drive = build_drive(rt, cfg, rate.clone(), retrier);
    let (repo_tx, _) = watch::channel::<RepoCell>(None);
    let state = Arc::new(Mutex::new(LinkState::new(Endpoint::DriveHelper)));
    let shared = Arc::new(Shared {
        state: state.clone(),
        out: out_tx.clone(),
        ctl: ctl_tx,
        budget: cfg.timing.request_budget,
        cancels: Mutex::new(HashMap::new()),
        drive,
        repo: repo_tx,
        rate,
    });

    // The writer: the only owner of the write half.
    let Ok(mut wstream) = stream.try_clone() else {
        return (End::Lost, None);
    };
    let writer = {
        let state = state.clone();
        let mut out_rx = out_rx;
        let mut ctl_rx = ctl_rx;
        std::thread::Builder::new()
            .name("hx-drive-writer".into())
            .spawn(move || {
                let Ok(rt) = tokio::runtime::Builder::new_current_thread().build() else {
                    return false;
                };
                rt.block_on(async move {
                    loop {
                        // The control queue first, always.
                        let item = tokio::select! {
                            biased;
                            Some(c) = ctl_rx.recv() => c,
                            o = out_rx.recv() => match o {
                                Some(o) => o,
                                None => match ctl_rx.try_recv() {
                                    Ok(c) => c,
                                    Err(_) => return true,
                                },
                            },
                        };
                        if matches!(item, Out::Close) {
                            // Between two frames: privd's decoder ends cleanly.
                            let _ = wstream.shutdown(std::net::Shutdown::Both);
                            return true;
                        }
                        if let Err(rule) = write_out(&mut wstream, &state, item) {
                            eprintln!("hx-backup-worker: drive link write failed: {rule}");
                            let _ = wstream.shutdown(std::net::Shutdown::Both);
                            return false;
                        }
                    }
                })
            })
    };
    let Ok(writer) = writer else {
        return (End::Lost, None);
    };
    let events = {
        let out = out_tx.clone();
        rt.spawn(async move {
            while let Some(ev) = ev_rx.recv().await {
                let f = frame(pb::repo_frame::Frame::Event(ev));
                if out.send(Out::Message(f)).await.is_err() {
                    return;
                }
            }
        })
    };

    let end = read_loop(rt.handle(), &stream, &shared, cfg.silence);

    events.abort();
    drop(shared);
    drop(out_tx);
    // Close the socket so that a blocked writer is released. The caller drops the runtime, which
    // ends the request tasks and so drops their senders; the writer then stops, and is joined.
    let _ = stream.shutdown(std::net::Shutdown::Both);
    (end, Some(writer))
}

fn read_loop(handle: &Handle, stream: &UnixStream, shared: &Arc<Shared>, silence: Duration) -> End {
    let _ = stream.set_read_timeout(Some(silence));
    let mut decoder = Decoder::new(RepoFramePolicy::new(Endpoint::DriveHelper));
    let mut reader = NoCmsgReader(stream);
    let mut uploads: HashMap<u64, Upload> = HashMap::new();
    loop {
        let raw = match decoder.read_from(&mut reader) {
            Ok(Some(f)) => f,
            Ok(None) => return End::Lost,
            Err(e) if e.is_violation() => {
                eprintln!("hx-backup-worker: drive link violation: {e}");
                return End::Violation("framing");
            }
            Err(hx_ipc::error::ReadError::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return End::Silent;
            }
            Err(_) => return End::Lost,
        };
        let incoming = match repo::decode(raw, Endpoint::DriveHelper) {
            Ok(i) => i,
            Err(e) => {
                eprintln!("hx-backup-worker: drive link violation: {e}");
                return End::Violation("frame");
            }
        };
        let disp = match shared
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .received(&incoming)
        {
            Ok(d) => d,
            Err(e) => {
                eprintln!("hx-backup-worker: drive link violation: {e}");
                return End::Violation(e.0);
            }
        };
        match incoming {
            Incoming::Secret(_) => return End::Violation("secret"),
            Incoming::Data(d) => {
                if disp.discard {
                    continue;
                }
                let Some(up) = uploads.get_mut(&d.stream_id) else {
                    continue;
                };
                if !d.payload.is_empty() {
                    up.chunks.push(d.payload);
                }
                if d.end
                    && let Some(up) = uploads.remove(&d.stream_id)
                {
                    start(
                        handle,
                        shared,
                        d.stream_id,
                        pb::repo_request::Op::Write(pb::Write {
                            object_type: up.ty as i32,
                            id: Bytes::copy_from_slice(&up.id),
                            size: 0,
                        }),
                        Some(up),
                    );
                }
            }
            Incoming::Message(m) => {
                use pb::repo_frame::Frame as F;
                match m.frame {
                    Some(F::Hello(_)) => {
                        shared
                            .ctl
                            .send(Out::Message(frame(F::HelloAck(pb::HelloAck {
                                major: repo::VERSION_MAJOR,
                                minor: repo::VERSION_MINOR,
                                software: crate::SOFTWARE.to_owned(),
                            }))))
                            .ok();
                    }
                    Some(F::Ping(p)) => {
                        shared
                            .ctl
                            .send(Out::Message(frame(F::Pong(pb::Pong { nonce: p.nonce }))))
                            .ok();
                    }
                    Some(F::Request(r)) => {
                        let req_id = r.req_id;
                        let Some(op) = r.op else { continue };
                        if let pb::repo_request::Op::Write(w) = &op {
                            let ty = object_type(w.object_type);
                            if matches!(ty, pb::ObjectType::Pack | pb::ObjectType::Index)
                                && w.size > WRITE_CAP
                            {
                                // Nothing of it is buffered: its data frames find no upload and
                                // are dropped (ipc.md §29, "Memory").
                                shared
                                    .ctl
                                    .send(error_response(req_id, DriveError::new(EC::Internal)))
                                    .ok();
                                continue;
                            }
                            let (h, cancel) = Cancel::with_limit(shared.budget);
                            shared
                                .cancels
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .insert(req_id, h);
                            uploads.insert(
                                req_id,
                                Upload {
                                    ty: object_type(w.object_type),
                                    id: id_of(&w.id),
                                    chunks: Vec::new(),
                                    cancel,
                                },
                            );
                            // The task starts at END; an empty object has only its END frame.
                            continue;
                        }
                        start(handle, shared, req_id, op, None);
                    }
                    Some(F::CancelRequest(c)) => {
                        if let Some(up) = uploads.remove(&c.req_id) {
                            // END has not arrived: answer now, the upload is closed as in §25.
                            drop(up);
                            shared
                                .cancels
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .remove(&c.req_id);
                            shared
                                .ctl
                                .send(error_response(c.req_id, DriveError::new(EC::Cancelled)))
                                .ok();
                        } else if let Some(h) = shared
                            .cancels
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .get(&c.req_id)
                        {
                            let _ = h.send(true);
                        }
                    }
                    Some(F::Bye(_)) => return End::Bye,
                    _ => {}
                }
            }
        }
    }
}

/// Starts the task of a request. A `Write` is started only at its `END`, with its upload.
fn start(
    handle: &Handle,
    shared: &Arc<Shared>,
    req_id: u64,
    op: pb::repo_request::Op,
    upload: Option<Upload>,
) {
    let cancel = match &upload {
        Some(u) => u.cancel.clone(),
        None => {
            let (h, c) = Cancel::with_limit(shared.budget);
            shared
                .cancels
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(req_id, h);
            c
        }
    };
    let shared = shared.clone();
    // A panic in the work of one request (a bug) must not leave privd waiting for an answer: the
    // outer task answers `INTERNAL` if the request is still outstanding.
    let is_open = matches!(op, pb::repo_request::Op::OpenRepo(_));
    let inner = handle.spawn(shared.clone().serve(req_id, op, upload, cancel));
    handle.spawn(async move {
        if inner.await.is_err_and(|e| e.is_panic()) {
            eprintln!("hx-backup-worker: a request task panicked (answered INTERNAL)");
            if is_open {
                // No later request may wait for a repository that will never come.
                shared.repo.send_if_modified(|c| {
                    let unset = c.is_none();
                    if unset {
                        *c = Some(Err(DriveError::new(EC::Internal)));
                    }
                    unset
                });
            }
            let live = shared
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_outstanding(req_id);
            if live {
                shared
                    .send(error_response(req_id, DriveError::new(EC::Internal)))
                    .await;
            }
        }
    });
}
