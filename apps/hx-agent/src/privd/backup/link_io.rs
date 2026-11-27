//! The I/O of one repository link: a reader thread and a writer thread over a blocking unix
//! socket, and the async [`Link`] the job loop drives (ipc.md sections 24, 25 and 32).
//!
//! * **Reading.** One thread per link reads with `recvmsg` through [`NoCmsgReader`] (a control
//!   message or `MSG_CTRUNC` is a violation, section 24, "No descriptors"), decodes and validates
//!   every frame with [`repo::decode`] and hands it to the loop through a one-slot channel. Before
//!   it reads a frame it takes one of the **16 frame slots** of the relay budget (section 25) and
//!   waits until the queue of the *other* link holds less than two data frames: privd reads the
//!   next chunk only after it has written the previous one. The slot travels with the frame and is
//!   released when the frame has been written to the other link or dropped.
//! * **Writing.** One thread per link drains an [`OutQueue`]: control frames first, then data. A
//!   write that makes no progress for 120 s fails the link.
//! * **Silence.** The reader stamps `last_rx` on every read that returns bytes, so a frame that
//!   arrives slowly keeps the link alive (section 32). While the reader is held back on purpose
//!   (the other link is slow) it stamps too: a peer that privd is not reading is not silent.
//!
//! The end of the stream at a frame boundary is [`LinkEvent::Eof`] and a frame cut short is
//! [`LinkEvent::Cut`]: the Drive link treats the first as the loss of the session and the second
//! as a violation (section 32).

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use bytes::Bytes;
use hx_ipc::error::{FrameError, ReadError};
use hx_ipc::frame::Decoder;
use hx_ipc::recv::NoCmsgReader;
use hx_ipc::repo::{
    self, DATA_FRAME_HEADER_LEN, Endpoint, Incoming, LinkState, RepoFramePolicy,
    encode_data_header, encode_message, encode_secret, pb,
};
use tokio::runtime::Handle;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use zeroize::Zeroizing;

use super::clock::Monotonic;

/// The reader waits while the other link has this many data bytes queued: two full frames.
pub const SINK_LIMIT: usize = 2 * 1024 * 1024;

/// The control queue of a link holds at most this many bytes: [`CTL_SOFT`] plus the 17 frames of
/// 64 KiB that the channel and the decoder can still deliver after the other link's reader has
/// seen the soft limit, rounded up. Honest traffic never reaches it; a peer that lets it fill by
/// not reading is dead (ipc.md section 25).
pub const CTL_LIMIT: usize = 1280 * 1024;

/// The reader of the other link waits while this many control bytes are queued.
pub const CTL_SOFT: usize = 64 * 1024;

/// Data frames queued on a link at most (the "2 frames per stream" rule, over 2 streams).
pub const MAX_DATA_FRAMES: usize = 4;

/// A write that makes no progress for this long fails the link.
const WRITE_STALL: Duration = Duration::from_secs(120);

/// What a reader thread reports.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // one per frame; boxing would only add an allocation
pub enum LinkEvent {
    /// A decoded, validated frame, and the relay slot it holds.
    Frame(Incoming, Option<OwnedSemaphorePermit>),
    /// The stream ended at a frame boundary.
    Eof,
    /// The stream ended inside a frame.
    Cut,
    /// The peer broke a rule of the codec (the text names the rule, never peer data).
    Violation(String),
    /// The socket failed (a reset counts as the loss of the link).
    Io,
    /// The writer could not write.
    WriteFailed,
}

/// One thing for the writer thread.
pub enum Out {
    /// An encoded kind-1 frame.
    Msg(Vec<u8>),
    /// An encoded kind-2 frame; wiped when dropped.
    Secret(Zeroizing<Vec<u8>>),
    /// A kind-3 frame: header, the payload exactly as it was read, and the relay slot it holds.
    Data {
        /// The 14 bytes before the payload.
        header: [u8; DATA_FRAME_HEADER_LEN],
        /// The payload.
        payload: Bytes,
        /// Released when the frame has been written.
        _permit: Option<OwnedSemaphorePermit>,
    },
    /// Close the link after everything before it has been written.
    Close,
}

#[derive(Default)]
struct QueueInner {
    ctl: VecDeque<Out>,
    data: VecDeque<Out>,
    data_bytes: usize,
    ctl_bytes: usize,
    pong: Option<Vec<u8>>,
    closed: bool,
    /// Bumped by `reopen`: a writer thread of an earlier generation stops.
    generation: u64,
    /// The most control bytes ever queued at once.
    peak_ctl: usize,
}

/// Why a push to a queue failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushError {
    /// The queue is closed.
    Closed,
    /// The control queue is over its cap: the peer is not reading.
    Overflow,
}

fn ctl_len(o: &Out) -> usize {
    match o {
        Out::Msg(b) => b.len(),
        Out::Secret(b) => b.len(),
        _ => 0,
    }
}

/// The outgoing queue of a link: control frames go first, data frames wait behind them.
#[derive(Default)]
pub struct OutQueue {
    inner: Mutex<QueueInner>,
    cv: Condvar,
}

impl OutQueue {
    /// An empty, open queue.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, QueueInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Queues a control item. At most [`CTL_LIMIT`] bytes are held: past that the peer is not
    /// reading and the push is refused.
    pub fn push_ctl(&self, out: Out) -> Result<(), PushError> {
        let mut g = self.lock();
        if g.closed {
            return Err(PushError::Closed);
        }
        let n = ctl_len(&out);
        if g.ctl_bytes + n > CTL_LIMIT {
            return Err(PushError::Overflow);
        }
        g.ctl_bytes += n;
        g.peak_ctl = g.peak_ctl.max(g.ctl_bytes);
        g.ctl.push_back(out);
        self.cv.notify_all();
        Ok(())
    }

    /// Queues a `Pong`: at most one is ever pending, a newer one replaces it.
    pub fn set_pong(&self, bytes: Vec<u8>) -> Result<(), PushError> {
        let mut g = self.lock();
        if g.closed {
            return Err(PushError::Closed);
        }
        g.pong = Some(bytes);
        g.peak_ctl = g.peak_ctl.max(g.ctl_bytes);
        self.cv.notify_all();
        Ok(())
    }

    /// Queues a data frame of `len` payload bytes; `false` when the queue is closed.
    pub fn push_data(&self, out: Out, len: usize) -> bool {
        let mut g = self.lock();
        if g.closed {
            return false;
        }
        g.data.push_back(out);
        g.data_bytes += len;
        self.cv.notify_all();
        true
    }

    /// The next item, blocking; `None` once the queue is closed (what is still queued is dropped).
    pub fn pop(&self, generation: u64) -> Option<(Out, usize)> {
        let mut g = self.lock();
        loop {
            if g.closed || g.generation != generation {
                return None;
            }
            if let Some(b) = g.pong.take() {
                return Some((Out::Msg(b), 0));
            }
            if let Some(o) = g.ctl.pop_front() {
                g.ctl_bytes = g.ctl_bytes.saturating_sub(ctl_len(&o));
                self.cv.notify_all();
                return Some((o, 0));
            }
            if let Some(o) = g.data.pop_front() {
                let len = match &o {
                    Out::Data { payload, .. } => payload.len(),
                    _ => 0,
                };
                return Some((o, len));
            }
            g = self.cv.wait(g).unwrap_or_else(|e| e.into_inner());
        }
    }

    /// Called by the writer of `generation` after it wrote a data frame of `len` bytes; a writer
    /// of an earlier generation does not touch the counters of the queue it no longer owns.
    fn written(&self, generation: u64, len: usize) {
        let mut g = self.lock();
        if g.generation != generation {
            return;
        }
        g.data_bytes = g.data_bytes.saturating_sub(len);
        self.cv.notify_all();
    }

    /// The most control bytes this queue has ever held at once.
    pub fn peak_ctl_bytes(&self) -> usize {
        self.lock().peak_ctl
    }

    /// Closes the queue only if it still belongs to `generation` (the writer of a connection
    /// that has been replaced must not close the next connection's queue).
    pub fn close_if(&self, generation: u64) {
        self.close_if_with(generation, || {});
    }

    /// The comparison and the close under one lock guard: a `reopen` cannot fall between them.
    /// `between` runs after the comparison, with the lock held (a seam for the tests).
    fn close_if_with(&self, generation: u64, between: impl FnOnce()) {
        let mut g = self.lock();
        if g.generation != generation {
            return;
        }
        between();
        Self::close_locked(&mut g);
        self.cv.notify_all();
    }

    /// Data bytes queued and not yet written.
    pub fn data_bytes(&self) -> usize {
        self.lock().data_bytes
    }

    /// Control bytes queued and not yet written.
    pub fn ctl_bytes(&self) -> usize {
        self.lock().ctl_bytes
    }

    /// Data frames queued and not yet written (`written` is called per frame).
    pub fn data_frames(&self) -> usize {
        self.lock().data.len()
    }

    /// Waits up to `timeout` until the queue is below `limit` data bytes, below
    /// [`MAX_DATA_FRAMES`] data frames and below [`CTL_SOFT`] control bytes. `true` when it is
    /// (or the queue is closed).
    pub fn wait_below(&self, limit: usize, timeout: Duration) -> bool {
        let full = |q: &QueueInner| {
            q.data_bytes >= limit || q.data.len() >= MAX_DATA_FRAMES || q.ctl_bytes >= CTL_SOFT
        };
        let g = self.lock();
        let (g, _) = self
            .cv
            .wait_timeout_while(g, timeout, |q| !q.closed && full(q))
            .unwrap_or_else(|e| e.into_inner());
        g.closed || !full(&g)
    }

    /// The generation a writer thread belongs to.
    pub fn generation(&self) -> u64 {
        self.lock().generation
    }

    /// Opens a closed queue again (a reconnect of the worker link reuses it). The writer thread
    /// of the link that was closed belongs to the old generation and stops.
    pub fn reopen(&self) {
        let mut g = self.lock();
        g.closed = false;
        g.generation += 1;
        g.ctl.clear();
        g.data.clear();
        g.data_bytes = 0;
        g.ctl_bytes = 0;
        g.pong = None;
        self.cv.notify_all();
    }

    /// Closes the queue: the writer stops and what is queued is dropped.
    pub fn close(&self) {
        let mut g = self.lock();
        Self::close_locked(&mut g);
        self.cv.notify_all();
    }

    fn close_locked(g: &mut QueueInner) {
        g.closed = true;
        g.ctl.clear();
        g.data.clear();
        g.data_bytes = 0;
        g.ctl_bytes = 0;
        g.pong = None;
    }

    /// Whether the queue is closed.
    pub fn is_closed(&self) -> bool {
        self.lock().closed
    }
}

struct Stamping<'a> {
    inner: NoCmsgReader<&'a UnixStream>,
    last_rx: &'a AtomicU64,
    mono: &'a dyn Monotonic,
}

impl Read for Stamping<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.last_rx.store(self.mono.now_ms(), Ordering::SeqCst);
        }
        Ok(n)
    }
}

#[allow(clippy::too_many_arguments)]
fn run_reader(
    stream: UnixStream,
    endpoint: Endpoint,
    budget: Arc<Semaphore>,
    handle: Handle,
    sink: Arc<OutQueue>,
    tx: mpsc::Sender<LinkEvent>,
    last_rx: Arc<AtomicU64>,
    mono: Arc<dyn Monotonic>,
) {
    let mut dec = Decoder::new(RepoFramePolicy::new(endpoint));
    loop {
        // privd reads the next chunk only after it has written the previous one.
        while !sink.wait_below(SINK_LIMIT, Duration::from_millis(100)) {
            last_rx.store(mono.now_ms(), Ordering::SeqCst);
        }
        // A reader that waits for a slot is not blocked by its peer: it keeps its link's
        // silence clock fresh (ipc.md section 25).
        let permit = loop {
            if let Ok(p) = budget.clone().try_acquire_owned() {
                break p;
            }
            let acquired = handle.block_on(async {
                tokio::time::timeout(Duration::from_millis(100), budget.clone().acquire_owned())
                    .await
            });
            match acquired {
                Ok(Ok(p)) => break p,
                Ok(Err(_)) => return,
                Err(_) => {
                    last_rx.store(mono.now_ms(), Ordering::SeqCst);
                    if tx.is_closed() {
                        return;
                    }
                }
            }
        };
        let mut r = Stamping {
            inner: NoCmsgReader(&stream),
            last_rx: &last_rx,
            mono: mono.as_ref(),
        };
        let event = match dec.read_from(&mut r) {
            Ok(Some(raw)) => match repo::decode(raw, endpoint) {
                // A kind-1 frame is at most 64 KiB and the channel holds a few: it gives its slot
                // back at once. Only a data frame (up to 1 MiB, relayed without copying) holds
                // its slot until it has been written to the other link.
                Ok(incoming @ Incoming::Data(_)) => LinkEvent::Frame(incoming, Some(permit)),
                Ok(incoming) => LinkEvent::Frame(incoming, None),
                Err(e) => LinkEvent::Violation(e.to_string().chars().take(100).collect()),
            },
            Ok(None) => LinkEvent::Eof,
            Err(ReadError::Frame(FrameError::Truncated)) => LinkEvent::Cut,
            Err(ReadError::Io(_)) => LinkEvent::Io,
            Err(e) => LinkEvent::Violation(e.to_string().chars().take(100).collect()),
        };
        let last = !matches!(event, LinkEvent::Frame(..));
        if tx.blocking_send(event).is_err() || last {
            return;
        }
    }
}

fn run_writer(stream: UnixStream, q: Arc<OutQueue>, tx: mpsc::Sender<LinkEvent>, generation: u64) {
    writer_loop(stream, q, tx, generation, &|| {});
}

/// The writer's loop. `generation` is the one the queue had when the link was made (taken by the
/// spawner, not here): everything the loop does to the shared queue is checked against it.
/// `before_write` is a seam for the tests.
fn writer_loop(
    mut stream: UnixStream,
    q: Arc<OutQueue>,
    tx: mpsc::Sender<LinkEvent>,
    generation: u64,
    before_write: &dyn Fn(),
) {
    let _ = stream.set_write_timeout(Some(WRITE_STALL));
    while let Some((item, data_len)) = q.pop(generation) {
        before_write();
        let r = match &item {
            Out::Msg(b) => stream.write_all(b),
            Out::Secret(b) => stream.write_all(b),
            Out::Data {
                header, payload, ..
            } => stream
                .write_all(header)
                .and_then(|()| stream.write_all(payload)),
            Out::Close => {
                let _ = stream.shutdown(std::net::Shutdown::Both);
                q.close_if(generation);
                return;
            }
        };
        if matches!(item, Out::Data { .. }) {
            q.written(generation, data_len);
        }
        if r.is_err() {
            let _ = tx.blocking_send(LinkEvent::WriteFailed);
            let _ = stream.shutdown(std::net::Shutdown::Both);
            q.close_if(generation);
            return;
        }
    }
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

/// What a send on a link can fail with: the rule (the state machine's or the codec's) or a link
/// that is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    /// The link's state machine or the codec refused the frame: a bug of privd's own.
    Rule(&'static str),
    /// The queue is closed.
    Closed,
    /// The control queue is over its cap: the peer is not reading.
    Overflow,
}

impl From<PushError> for SendError {
    fn from(e: PushError) -> Self {
        match e {
            PushError::Closed => Self::Closed,
            PushError::Overflow => Self::Overflow,
        }
    }
}

/// One link as the job loop sees it.
pub struct Link {
    /// `"worker"` or `"drive"`, for audit lines.
    pub name: &'static str,
    /// The stateful rules of this end.
    pub state: LinkState,
    peer: Endpoint,
    /// The outgoing queue.
    pub q: Arc<OutQueue>,
    /// What the reader reports.
    pub rx: mpsc::Receiver<LinkEvent>,
    /// Monotonic time of the last byte read.
    pub last_rx: Arc<AtomicU64>,
    shutdown: UnixStream,
    /// Monotonic time at which the next `Ping` is due.
    pub next_ping_ms: u64,
    nonce: u64,
    /// False once the link has ended or been closed.
    pub open: bool,
}

/// What a link needs from the runner to start.
pub struct LinkParts {
    /// The relay budget (frame slots) shared by every job.
    pub budget: Arc<Semaphore>,
    /// The runtime the reader thread blocks on for the budget.
    pub handle: Handle,
    /// The clock.
    pub mono: Arc<dyn Monotonic>,
    /// How often privd pings (15 s; ipc.md section 32).
    pub ping_interval: Duration,
}

impl Link {
    /// Starts the reader and writer threads on `stream`. `me` is the endpoint of privd on this
    /// link (it decodes for it); `own_q` is this link's outgoing queue and `other_q` the queue of
    /// the other link, which this link's reader waits on.
    pub fn spawn(
        name: &'static str,
        stream: UnixStream,
        me: Endpoint,
        own_q: Arc<OutQueue>,
        other_q: Arc<OutQueue>,
        parts: &LinkParts,
    ) -> io::Result<Self> {
        let (tx, rx) = mpsc::channel(16);
        let last_rx = Arc::new(AtomicU64::new(parts.mono.now_ms()));
        let rstream = stream.try_clone()?;
        let wstream = stream.try_clone()?;
        {
            let (budget, handle, mono, last_rx, tx) = (
                parts.budget.clone(),
                parts.handle.clone(),
                parts.mono.clone(),
                last_rx.clone(),
                tx.clone(),
            );
            std::thread::Builder::new()
                .name(format!("hx-bkp-{name}-rd"))
                .spawn(move || {
                    run_reader(rstream, me, budget, handle, other_q, tx, last_rx, mono)
                })?;
        }
        {
            let q = own_q.clone();
            // The generation is read here, before the thread exists: a thread that starts late
            // must not adopt the generation of a reconnect.
            let generation = q.generation();
            std::thread::Builder::new()
                .name(format!("hx-bkp-{name}-wr"))
                .spawn(move || run_writer(wstream, q, tx, generation))?;
        }
        Ok(Self {
            name,
            state: LinkState::new(me),
            peer: me.peer(),
            q: own_q,
            rx,
            last_rx,
            shutdown: stream,
            next_ping_ms: parts.mono.now_ms()
                + u64::try_from(parts.ping_interval.as_millis()).unwrap_or(u64::MAX),
            nonce: 0,
            open: true,
        })
    }

    /// Sends a kind-1 frame: the state machine first (a frame it refuses is a bug of privd's
    /// own), then the codec (which validates it for the peer), then the control queue.
    pub fn send(&mut self, frame: &pb::RepoFrame) -> Result<(), SendError> {
        self.state
            .sent_message(frame)
            .map_err(|e| SendError::Rule(e.0))?;
        let bytes = encode_message(frame, self.peer).map_err(|_| SendError::Rule("encode"))?;
        let r = if matches!(frame.frame, Some(pb::repo_frame::Frame::Pong(_))) {
            self.q.set_pong(bytes)
        } else {
            self.q.push_ctl(Out::Msg(bytes))
        };
        r.map_err(SendError::from)
    }

    /// Sends one data frame.
    pub fn send_data(
        &mut self,
        stream_id: u64,
        end: bool,
        payload: Bytes,
        permit: Option<OwnedSemaphorePermit>,
    ) -> Result<(), SendError> {
        self.state
            .sent_data(stream_id, end, payload.len())
            .map_err(|e| SendError::Rule(e.0))?;
        let header = encode_data_header(stream_id, end, payload.len())
            .map_err(|_| SendError::Rule("encode"))?;
        let len = payload.len();
        let ok = self.q.push_data(
            Out::Data {
                header,
                payload,
                _permit: permit,
            },
            len,
        );
        if ok { Ok(()) } else { Err(SendError::Closed) }
    }

    /// Sends one secret frame (the worker link).
    pub fn send_secret(&mut self, slot: u8, secret: &[u8]) -> Result<(), SendError> {
        self.state
            .sent_secret(0, slot, secret.len())
            .map_err(|e| SendError::Rule(e.0))?;
        let framed = encode_secret(0, slot, secret).map_err(|_| SendError::Rule("encode"))?;
        self.q
            .push_ctl(Out::Secret(framed))
            .map_err(SendError::from)
    }

    /// `Ping` with a fresh nonce.
    pub fn ping(&mut self) -> Result<(), SendError> {
        self.nonce += 1;
        self.send(&frame(pb::repo_frame::Frame::Ping(pb::Ping {
            nonce: self.nonce,
        })))
    }

    /// `Pong` for `nonce`.
    pub fn pong(&mut self, nonce: u64) -> Result<(), SendError> {
        self.send(&frame(pb::repo_frame::Frame::Pong(pb::Pong { nonce })))
    }

    /// Ends the link. With `bye` the session is closed in order (`Bye`, then everything queued
    /// before it is written, then the close); without it the queue is dropped and the socket is
    /// shut down at once.
    pub fn close(&mut self, bye: bool) {
        if !self.open {
            return;
        }
        self.open = false;
        if bye && self.state.is_open() {
            let _ = self.send(&frame(pb::repo_frame::Frame::Bye(pb::Bye {})));
            if self.q.push_ctl(Out::Close).is_ok() {
                return;
            }
        }
        self.q.close();
        let _ = self.shutdown.shutdown(std::net::Shutdown::Both);
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        self.q.close();
        let _ = self.shutdown.shutdown(std::net::Shutdown::Both);
    }
}

/// A one-variant frame.
pub fn frame(f: pb::repo_frame::Frame) -> pb::RepoFrame {
    pb::RepoFrame { frame: Some(f) }
}

/// Connects to a unix socket, retrying every `retry` until `window_ms` of the monotonic clock
/// have passed. The stream is returned in blocking mode.
pub async fn connect_unix(
    path: &Path,
    window_ms: u64,
    retry: Duration,
    mono: &dyn Monotonic,
) -> io::Result<UnixStream> {
    let started = mono.now_ms();
    loop {
        match tokio::net::UnixStream::connect(path).await {
            Ok(s) => {
                let s = s.into_std()?;
                s.set_nonblocking(false)?;
                return Ok(s);
            }
            Err(e) => {
                if mono.now_ms().saturating_sub(started) >= window_ms {
                    return Err(e);
                }
                tokio::time::sleep(retry).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_control_cap_holds_what_a_reader_can_still_deliver_after_the_soft_limit() {
        // The other link's reader stops at CTL_SOFT, but 16 frames sit in its channel and one is
        // being decoded: an honest worker that is slow must never meet the cap (ipc.md section 25).
        // A message of the repository link is at most 64 KiB (hx-ipc's MAX_MESSAGE_LENGTH) plus
        // its 4-byte header.
        let frame = 64 * 1024 + 4;
        assert!(
            CTL_LIMIT >= CTL_SOFT + 17 * frame,
            "{CTL_LIMIT} < {}",
            CTL_SOFT + 17 * frame
        );
    }

    #[test]
    fn control_frames_are_written_before_data_and_a_closed_queue_stops() {
        let q = OutQueue::new();
        q.push_data(
            Out::Data {
                header: [0; DATA_FRAME_HEADER_LEN],
                payload: Bytes::from_static(b"abc"),
                _permit: None,
            },
            3,
        );
        q.push_ctl(Out::Msg(vec![1])).unwrap();
        assert_eq!(q.data_bytes(), 3);
        assert!(matches!(q.pop(q.generation()), Some((Out::Msg(_), 0))));
        assert!(matches!(q.pop(q.generation()), Some((Out::Data { .. }, 3))));
        q.written(q.generation(), 3);
        assert_eq!(q.data_bytes(), 0);
        q.close();
        assert!(q.pop(q.generation()).is_none());
        assert_eq!(q.push_ctl(Out::Msg(vec![2])), Err(PushError::Closed));
    }

    #[test]
    fn the_reader_waits_while_the_other_link_is_backed_up() {
        let q = OutQueue::new();
        assert!(q.wait_below(10, Duration::from_millis(5)));
        q.push_data(
            Out::Data {
                header: [0; DATA_FRAME_HEADER_LEN],
                payload: Bytes::from(vec![0u8; 20]),
                _permit: None,
            },
            20,
        );
        assert!(!q.wait_below(10, Duration::from_millis(5)));
        q.written(q.generation(), 20);
        assert!(q.wait_below(10, Duration::from_millis(5)));
    }

    #[test]
    fn the_control_queue_is_capped_and_a_pong_flood_costs_one_slot() {
        let q = OutQueue::new();
        // A Ping flood: a million pongs, one pending.
        for _ in 0..1_000_000 {
            q.set_pong(vec![0; 12]).unwrap();
        }
        assert_eq!(
            q.ctl_bytes(),
            0,
            "pongs are not queued, they replace each other"
        );
        assert!(matches!(q.pop(q.generation()), Some((Out::Msg(b), 0)) if b.len() == 12));
        // Requests and answers are bounded in bytes.
        let mut pushed = 0;
        loop {
            match q.push_ctl(Out::Msg(vec![0; 1000])) {
                Ok(()) => pushed += 1,
                Err(e) => {
                    assert_eq!(e, PushError::Overflow);
                    break;
                }
            }
            assert!(pushed < 10_000, "unbounded");
        }
        assert!(q.ctl_bytes() <= CTL_LIMIT);
        assert_eq!(pushed, CTL_LIMIT / 1000);
        // Control bytes hold the reader of the other link back.
        assert!(!q.wait_below(SINK_LIMIT, Duration::from_millis(5)));
    }

    #[test]
    fn data_frames_are_bounded_by_count_as_well_as_bytes() {
        let q = OutQueue::new();
        for _ in 0..MAX_DATA_FRAMES {
            q.push_data(
                Out::Data {
                    header: [0; DATA_FRAME_HEADER_LEN],
                    payload: Bytes::from_static(b"x"),
                    _permit: None,
                },
                1,
            );
        }
        assert!(!q.wait_below(SINK_LIMIT, Duration::from_millis(5)));
        assert_eq!(q.data_frames(), MAX_DATA_FRAMES);
    }

    fn parts(budget: Arc<Semaphore>, mono: Arc<super::super::clock::ManualMono>) -> LinkParts {
        LinkParts {
            budget,
            handle: Handle::current(),
            mono,
            ping_interval: Duration::from_secs(15),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_ping_flood_on_a_link_queues_nothing() {
        let (a, _b) = UnixStream::pair().unwrap();
        let mono = Arc::new(super::super::clock::ManualMono::new());
        let p = parts(Arc::new(Semaphore::new(4)), mono);
        let mut link = Link::spawn(
            "worker",
            a,
            Endpoint::PrivdWorkerLink,
            OutQueue::new(),
            OutQueue::new(),
            &p,
        )
        .unwrap();
        link.send(&frame(pb::repo_frame::Frame::Hello(pb::Hello {
            major: repo::VERSION_MAJOR,
            minor: 0,
            job_id: Bytes::from(vec![1u8; 16]),
        })))
        .unwrap();
        // The peer never reads: 100 000 pongs are still only one pending frame.
        for n in 0..100_000u64 {
            link.pong(n).expect("a pong is never refused");
        }
        assert_eq!(link.q.ctl_bytes(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reader_that_is_held_back_keeps_the_silence_clock_of_its_link_fresh() {
        // Held back by the other link's queue (4 data frames), and by an empty budget.
        for starve_budget in [false, true] {
            let (a, _b) = UnixStream::pair().unwrap();
            let mono = Arc::new(super::super::clock::ManualMono::new());
            let other = OutQueue::new();
            let budget = Arc::new(Semaphore::new(if starve_budget { 0 } else { 4 }));
            if !starve_budget {
                for _ in 0..MAX_DATA_FRAMES {
                    other.push_data(
                        Out::Data {
                            header: [0; DATA_FRAME_HEADER_LEN],
                            payload: Bytes::from_static(b"x"),
                            _permit: None,
                        },
                        1,
                    );
                }
            }
            let start = mono.now_ms();
            let link = Link::spawn(
                "drive",
                a,
                Endpoint::PrivdDriveLink,
                OutQueue::new(),
                other,
                &parts(budget, mono.clone()),
            )
            .unwrap();
            mono.advance_ms(10_000);
            let t = std::time::Instant::now();
            while link.last_rx.load(Ordering::SeqCst) < start + 10_000 {
                assert!(
                    t.elapsed() < Duration::from_secs(5),
                    "starve_budget={starve_budget}: the clock of a held-back reader went stale"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }

    #[test]
    fn an_old_writer_that_starts_late_neither_steals_frames_nor_closes_the_new_queue() {
        let (a, b) = UnixStream::pair().unwrap();
        let q = OutQueue::new();
        let old_gen = q.generation();
        let (tx, _rx) = mpsc::channel(4);
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let (q2, b2) = (q.clone(), barrier.clone());
        // The old writer exists, but runs only after the reconnect.
        let old = std::thread::spawn(move || {
            b2.wait();
            writer_loop(a, q2, tx, old_gen, &|| {});
        });
        q.close();
        q.reopen();
        assert_ne!(q.generation(), old_gen);
        q.push_ctl(Out::Msg(vec![1, 2, 3])).unwrap();
        barrier.wait();
        old.join().unwrap();
        assert!(!q.is_closed(), "the old writer closed the new queue");
        assert_eq!(
            q.ctl_bytes(),
            3,
            "the old writer took a frame of the new connection"
        );
        // Nothing reached the old connection's peer.
        let mut buf = [0u8; 8];
        b.set_nonblocking(true).unwrap();
        assert!(std::io::Read::read(&mut &b, &mut buf).map_or(true, |n| n == 0));
    }

    #[test]
    fn an_old_writer_that_fails_after_the_reconnect_does_not_close_the_new_queue() {
        let (a, b) = UnixStream::pair().unwrap();
        drop(b); // the peer is gone: the write fails
        let q = OutQueue::new();
        let old_gen = q.generation();
        q.push_ctl(Out::Msg(vec![9; 4])).unwrap();
        let (tx, _rx) = mpsc::channel(4);
        let at_write = Arc::new(std::sync::Barrier::new(2));
        let go = Arc::new(std::sync::Barrier::new(2));
        let (q2, at2, go2) = (q.clone(), at_write.clone(), go.clone());
        let old = std::thread::spawn(move || {
            writer_loop(a, q2, tx, old_gen, &|| {
                at2.wait(); // popped, about to write
                go2.wait();
            });
        });
        at_write.wait();
        // The reconnect happens between the pop and the failing write.
        q.close();
        q.reopen();
        q.push_ctl(Out::Msg(vec![1])).unwrap();
        go.wait();
        old.join().unwrap();
        assert!(
            !q.is_closed(),
            "the failure of the old connection closed the new queue"
        );
        assert_eq!(q.ctl_bytes(), 1);
    }

    #[test]
    fn an_old_writer_that_pops_close_after_the_reconnect_does_not_close_the_new_queue() {
        let (a, _b) = UnixStream::pair().unwrap();
        let q = OutQueue::new();
        let old_gen = q.generation();
        q.push_ctl(Out::Close).unwrap();
        let (tx, _rx) = mpsc::channel(4);
        let at_pop = Arc::new(std::sync::Barrier::new(2));
        let go = Arc::new(std::sync::Barrier::new(2));
        let (q2, at2, go2) = (q.clone(), at_pop.clone(), go.clone());
        let old = std::thread::spawn(move || {
            writer_loop(a, q2, tx, old_gen, &|| {
                at2.wait(); // popped the Close, about to act on it
                go2.wait();
            });
        });
        at_pop.wait();
        q.close();
        q.reopen();
        q.push_ctl(Out::Msg(vec![1])).unwrap();
        go.wait();
        old.join().unwrap();
        assert!(!q.is_closed(), "the old Close closed the new queue");
        assert_eq!(q.ctl_bytes(), 1);
    }

    #[test]
    fn an_old_writer_does_not_touch_the_data_counters_of_the_new_queue() {
        let (a, _b) = UnixStream::pair().unwrap();
        let q = OutQueue::new();
        let old_gen = q.generation();
        let frame = |n: usize| Out::Data {
            header: [0; DATA_FRAME_HEADER_LEN],
            payload: Bytes::from(vec![7u8; n]),
            _permit: None,
        };
        assert!(q.push_data(frame(3), 3));
        let (tx, _rx) = mpsc::channel(4);
        let at_pop = Arc::new(std::sync::Barrier::new(2));
        let go = Arc::new(std::sync::Barrier::new(2));
        let (q2, at2, go2) = (q.clone(), at_pop.clone(), go.clone());
        let old = std::thread::spawn(move || {
            writer_loop(a, q2, tx, old_gen, &|| {
                at2.wait(); // popped its frame, about to write it
                go2.wait();
            });
        });
        at_pop.wait();
        q.close();
        q.reopen();
        assert!(q.push_data(frame(5), 5));
        go.wait();
        old.join().unwrap();
        assert_eq!(
            q.data_bytes(),
            5,
            "the old writer took its 3 bytes off the new queue's counter"
        );
    }

    #[test]
    fn a_reopen_cannot_fall_between_the_generation_check_and_the_close() {
        let q = OutQueue::new();
        let old_gen = q.generation();
        let (in_gap_tx, in_gap_rx) = std::sync::mpsc::channel::<()>();
        let (q2, tx2) = (q.clone(), in_gap_tx);
        let closer = std::thread::spawn(move || {
            q2.close_if_with(old_gen, || {
                // The check has passed. Let the reconnect try to happen now, and give it time.
                tx2.send(()).unwrap();
                std::thread::sleep(Duration::from_millis(150));
            });
        });
        in_gap_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        q.reopen();
        closer.join().unwrap();
        assert!(
            !q.is_closed(),
            "the close of the old generation closed the new queue"
        );
        assert_ne!(q.generation(), old_gen);
    }
}
