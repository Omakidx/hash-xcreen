//! State shared by the tasks of one link: the consumer inbox, the output queues, flow-control
//! credits, the stream formats in force and the video state.
//!
//! Every queue is bounded and says what happens when it is full:
//!
//! | Queue | Bound | When full |
//! |---|---|---|
//! | video frames | `max(2 x max_frame_bytes, 12 MiB)` bytes | the oldest undelivered frames are evicted (reported `DROPPED`, resync) |
//! | events | 256 | the oldest event is dropped and counted |
//! | cursor position | 1 (latest wins) | replaced |
//! | transfer events | 512, data limited by credits (1 MiB per transfer, 4 MiB per link) | the link faults (the consumer stopped reading) |
//! | `ctl` input (P0) | 4 096 | the link faults (the session does not read) |
//! | `ctl` P1, P2 | 512, 64 | the link faults (P1), the oldest is dropped (P2) |
//! | `bulk` writer | 16 frames | the sender waits (only `bulk` is affected) |

use super::config::LinkConfig;
use super::types::{
    Counters, FailureClass, Frame, LinkClosed, LinkEvent, SessionInfo, StreamFormat, TransferEvent,
};
use bytes::Bytes;
use hx_ipc::link::budget::{LINK_UNREAD_LIMIT, RateWindow, TRANSFER_UNREAD_LIMIT, limits};
use hx_ipc::link::frames::encode_gateway_message;
use hx_ipc::link::pb;
use hx_proto::datagram::{MouseCoalescer, MouseMove};
use hx_proto::order::serial_gt;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, mpsc, watch};

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// ----- flow-control credits for incoming bulk data -----

/// Unread incoming transfer bytes. The `bulk` reader stops reading while the consumer holds
/// 1 MiB for any transfer or 4 MiB in all (`docs/ipc.md` section 16).
///
/// `room()` is lock-free (two atomics); the per-transfer map is only touched, for O(1) work,
/// when a chunk is handed out or returned. An entry lives only while its transfer has unread
/// bytes or has not ended, so the map is bounded by the transfers in flight (at most 4) plus the
/// ones whose chunks the consumer still holds.
#[derive(Debug, Default)]
pub(crate) struct Credits {
    link: AtomicU64,
    /// Transfers whose unread bytes are at the per-transfer limit.
    at_limit: AtomicUsize,
    per: Mutex<HashMap<u32, Entry>>,
    wake: Notify,
}

#[derive(Debug, Default)]
struct Entry {
    unread: u64,
    /// The transfer ended or was aborted: the entry goes when its last chunk is returned.
    ended: bool,
}

impl Credits {
    pub(crate) fn acquire(self: &Arc<Self>, id: u32, n: usize) -> Credit {
        let n = n as u64;
        self.link.fetch_add(n, Relaxed);
        {
            let mut per = lock(&self.per);
            let e = per.entry(id).or_default();
            let before = e.unread >= TRANSFER_UNREAD_LIMIT;
            e.unread += n;
            e.ended = false;
            if !before && e.unread >= TRANSFER_UNREAD_LIMIT {
                self.at_limit.fetch_add(1, Relaxed);
            }
        }
        Credit {
            credits: self.clone(),
            id,
            n,
        }
    }

    /// O(1) and lock-free.
    fn room(&self) -> bool {
        self.link.load(Relaxed) < LINK_UNREAD_LIMIT && self.at_limit.load(Relaxed) == 0
    }

    /// Returns once the reader may read another frame.
    pub(crate) async fn wait_room(&self) {
        loop {
            let notified = self.wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.room() {
                return;
            }
            notified.await;
        }
    }

    /// The transfer ended (or was aborted): its entry is removed now if nothing is unread, else
    /// when the consumer returns the last chunk.
    pub(crate) fn forget(&self, id: u32) {
        let mut per = lock(&self.per);
        if let Some(e) = per.get_mut(&id) {
            if e.unread == 0 {
                per.remove(&id);
            } else {
                e.ended = true;
            }
        }
    }

    /// Entries in the per-transfer map (tests and metrics).
    #[cfg(test)]
    pub(crate) fn entries(&self) -> usize {
        lock(&self.per).len()
    }
}

/// Held by a [`TransferChunk`](super::TransferChunk): dropping it returns the bytes.
pub(crate) struct Credit {
    credits: Arc<Credits>,
    id: u32,
    n: u64,
}

impl std::fmt::Debug for Credit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credit")
            .field("id", &self.id)
            .field("n", &self.n)
            .finish()
    }
}

impl Drop for Credit {
    fn drop(&mut self) {
        let c = &self.credits;
        c.link.fetch_sub(self.n, Relaxed);
        {
            // A short critical section: two hash operations, never anything slow.
            let mut per = lock(&c.per);
            if let Some(e) = per.get_mut(&self.id) {
                let before = e.unread >= TRANSFER_UNREAD_LIMIT;
                e.unread = e.unread.saturating_sub(self.n);
                if before && e.unread < TRANSFER_UNREAD_LIMIT {
                    c.at_limit.fetch_sub(1, Relaxed);
                }
                if e.unread == 0 && e.ended {
                    per.remove(&self.id);
                }
            }
        }
        c.wake.notify_waiters();
    }
}

// ----- the consumer inbox -----

#[derive(Default)]
struct InboxState {
    events: VecDeque<LinkEvent>,
    pos: Option<hx_proto::pb::CursorPosition>,
    transfers: VecDeque<TransferEvent>,
    frames: VecDeque<Frame>,
    frame_bytes: u64,
}

const EVENT_CAP: usize = 256;
const TRANSFER_CAP: usize = 512;

/// Everything the consumer reads, behind one lock and one wake-up.
pub(crate) struct Inbox {
    st: Mutex<InboxState>,
    pub(crate) wake: Notify,
}

impl Inbox {
    pub(crate) fn new() -> Self {
        Self {
            st: Mutex::new(InboxState::default()),
            wake: Notify::new(),
        }
    }

    /// Queues an event; returns true if the oldest one had to be dropped.
    pub(crate) fn push_event(&self, ev: LinkEvent) -> bool {
        let mut s = lock(&self.st);
        let dropped = s.events.len() >= EVENT_CAP;
        if dropped {
            s.events.pop_front();
        }
        s.events.push_back(ev);
        drop(s);
        self.wake.notify_one();
        dropped
    }

    pub(crate) fn push_position(&self, p: hx_proto::pb::CursorPosition) {
        lock(&self.st).pos = Some(p);
        self.wake.notify_one();
    }

    /// False if the consumer stopped reading transfer events.
    pub(crate) fn push_transfer(&self, t: TransferEvent) -> bool {
        let mut s = lock(&self.st);
        if s.transfers.len() >= TRANSFER_CAP {
            return false;
        }
        s.transfers.push_back(t);
        drop(s);
        self.wake.notify_one();
        true
    }

    /// Queues a frame within `pool` bytes. Returns the numbers of the frames evicted to make
    /// room (oldest first).
    pub(crate) fn push_frame(&self, f: Frame, pool: u64) -> Vec<u32> {
        let mut evicted = Vec::new();
        let mut s = lock(&self.st);
        let len = f.body.len() as u64;
        while s.frame_bytes + len > pool {
            let Some(old) = s.frames.pop_front() else {
                break;
            };
            s.frame_bytes -= old.body.len() as u64;
            evicted.push(old.number());
        }
        s.frame_bytes += len;
        s.frames.push_back(f);
        drop(s);
        self.wake.notify_one();
        evicted
    }

    /// Removes queued frames numbered up to `up_to` (serial arithmetic); returns their numbers.
    pub(crate) fn cancel_frames_up_to(&self, up_to: u32) -> Vec<u32> {
        let mut s = lock(&self.st);
        let mut gone = Vec::new();
        let mut kept = VecDeque::with_capacity(s.frames.len());
        let mut bytes = 0;
        for f in s.frames.drain(..).collect::<Vec<_>>() {
            if serial_gt(f.number(), up_to) {
                bytes += f.body.len() as u64;
                kept.push_back(f);
            } else {
                gone.push(f.number());
            }
        }
        s.frames = kept;
        s.frame_bytes = bytes;
        gone
    }

    /// Removes every queued frame; returns their numbers.
    pub(crate) fn drain_frames(&self) -> Vec<u32> {
        let mut s = lock(&self.st);
        s.frame_bytes = 0;
        s.frames.drain(..).map(|f| f.number()).collect()
    }

    /// The next thing for the consumer: events, then the cursor position, transfers, frames.
    pub(crate) fn pop(&self) -> Option<LinkEvent> {
        let mut s = lock(&self.st);
        if let Some(e) = s.events.pop_front() {
            return Some(e);
        }
        if let Some(p) = s.pos.take() {
            return Some(LinkEvent::Cursor(super::types::CursorUpdate::Position(p)));
        }
        if let Some(t) = s.transfers.pop_front() {
            return Some(LinkEvent::Transfer(t));
        }
        let f = s.frames.pop_front()?;
        s.frame_bytes -= f.body.len() as u64;
        Some(LinkEvent::Frame(f))
    }

    /// Only the ordinary events (not frames, positions or transfers): what is still delivered
    /// after the link ended.
    pub(crate) fn pop_event_only(&self) -> Option<LinkEvent> {
        lock(&self.st).events.pop_front()
    }

    pub(crate) fn queued_frame_bytes(&self) -> u64 {
        lock(&self.st).frame_bytes
    }
}

// ----- the control output queues -----

/// Result of looking at the output queues.
pub(crate) enum Pop {
    Frame(Vec<u8>),
    /// Nothing ready before this instant (a mouse message waiting out its spacing).
    Wait(Instant),
    Empty,
}

struct OutState {
    p0: VecDeque<Vec<u8>>,
    mouse: MouseCoalescer,
    mouse_out: VecDeque<pb::Mouse>,
    mouse_seq: u32,
    last_mouse: Option<Instant>,
    p1: VecDeque<Vec<u8>>,
    p2: VecDeque<Vec<u8>>,
}

const P0_CAP: usize = 4_096;
const P1_CAP: usize = 512;
const P2_CAP: usize = 64;
/// Gateway to session motion goes out at most this often (section 13: 1 000 per second).
const MOUSE_SPACING: Duration = Duration::from_millis(1);

/// The `ctl` gateway-to-session queues, drained in strict priority order by one writer task
/// (`docs/ipc.md` section 17): P0 input events then the single-slot mouse; P1 feedback, IDR
/// requests, reconfigure, start/stop, ping; P2 statistics and goodbye.
pub(crate) struct OutQ {
    st: Mutex<OutState>,
    pub(crate) wake: Notify,
}

impl OutQ {
    pub(crate) fn new() -> Self {
        Self {
            st: Mutex::new(OutState {
                p0: VecDeque::new(),
                mouse: MouseCoalescer::new(),
                mouse_out: VecDeque::new(),
                mouse_seq: 0,
                last_mouse: None,
                p1: VecDeque::new(),
                p2: VecDeque::new(),
            }),
            wake: Notify::new(),
        }
    }

    /// `false`: the queue is full (the session is not reading).
    pub(crate) fn push_p0(&self, f: Vec<u8>) -> bool {
        let mut s = lock(&self.st);
        if s.p0.len() >= P0_CAP {
            return false;
        }
        s.p0.push_back(f);
        drop(s);
        self.wake.notify_one();
        true
    }

    pub(crate) fn push_p1(&self, f: Vec<u8>) -> bool {
        let mut s = lock(&self.st);
        if s.p1.len() >= P1_CAP {
            return false;
        }
        s.p1.push_back(f);
        drop(s);
        self.wake.notify_one();
        true
    }

    pub(crate) fn push_p2(&self, f: Vec<u8>) {
        let mut s = lock(&self.st);
        if s.p2.len() >= P2_CAP {
            s.p2.pop_front();
        }
        s.p2.push_back(f);
        drop(s);
        self.wake.notify_one();
    }

    /// Latest-wins pointer motion; absolute and relative are merged (protocol.md 7.1).
    pub(crate) fn push_mouse(&self, m: MouseMove) {
        lock(&self.st).mouse.push(m);
        self.wake.notify_one();
    }

    pub(crate) fn pop(&self, now: Instant) -> Pop {
        let mut s = lock(&self.st);
        if let Some(f) = s.p0.pop_front() {
            return Pop::Frame(f);
        }
        if s.mouse_out.is_empty()
            && let Some(u) = s.mouse.take()
        {
            for (relative, (x, y)) in u
                .absolute
                .map(|a| (false, a))
                .into_iter()
                .chain(u.relative.map(|r| (true, r)))
            {
                s.mouse_seq = s.mouse_seq.wrapping_add(1);
                let seq = s.mouse_seq;
                s.mouse_out.push_back(pb::Mouse {
                    seq,
                    relative,
                    x,
                    y,
                });
            }
        }
        if !s.mouse_out.is_empty() {
            let due = s.last_mouse.map_or(now, |t| t + MOUSE_SPACING);
            if due > now {
                return Pop::Wait(due);
            }
            if let Some(m) = s.mouse_out.pop_front() {
                s.last_mouse = Some(now);
                let msg = pb::GatewayToSession {
                    message: Some(pb::gateway_to_session::Message::Mouse(m)),
                };
                if let Ok(f) = encode_gateway_message(&msg) {
                    return Pop::Frame(f);
                }
            }
        }
        if let Some(f) = s.p1.pop_front() {
            return Pop::Frame(f);
        }
        if let Some(f) = s.p2.pop_front() {
            return Pop::Frame(f);
        }
        Pop::Empty
    }
}

// ----- stream formats and video state -----

/// The formats announced by `stream_format`, newest last.
#[derive(Default)]
pub(crate) struct FormatList {
    list: VecDeque<Arc<StreamFormat>>,
}

impl FormatList {
    pub(crate) fn push(&mut self, f: StreamFormat) {
        if self.list.len() >= 8 {
            self.list.pop_front();
        }
        self.list.push_back(Arc::new(f));
    }

    /// The format in force for frame `n`: the newest announced one whose `first_frame` is not
    /// after `n`.
    pub(crate) fn in_force(&self, n: u32) -> Option<Arc<StreamFormat>> {
        self.list
            .iter()
            .rev()
            .find(|f| !serial_gt(f.first_frame, n))
            .cloned()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.list.is_empty()
    }
}

pub(crate) struct VideoState {
    /// The newest frame number accepted on this link.
    pub newest: Option<u32>,
    /// After a cancel or drop: discard everything up to the next `KEY | RESYNC` frame.
    pub gate_armed: bool,
    pub attempts_rl: RateWindow,
    pub frames_rl: RateWindow,
    pub idr_rl: RateWindow,
    pub request_idr_rl: RateWindow,
    pub idr_retry: bool,
    pub last_delivered: u32,
}

// ----- transfers -----

pub(crate) struct InXfer {
    pub size: u64,
    pub got: u64,
    pub clipboard: bool,
}

#[derive(Default)]
pub(crate) struct XferState {
    pub incoming: HashMap<u32, InXfer>,
    /// Ids the gateway ended or aborted whose in-flight frames may still arrive.
    pub recent: VecDeque<u32>,
    /// Transfers the gateway is sending: id to "is a clipboard".
    pub outgoing: HashMap<u32, bool>,
    /// Outgoing transfers the session or the owner aborted.
    pub out_aborted: HashSet<u32>,
    pub next_id: u32,
    pub clipboard_rl: Option<RateWindow>,
}

impl XferState {
    pub(crate) fn remember(&mut self, id: u32) {
        if self.recent.len() >= 64 {
            self.recent.pop_front();
        }
        self.recent.push_back(id);
    }
}

pub(crate) struct Pings {
    pub next_nonce: u64,
    pub pending: VecDeque<(u64, Instant)>,
    pub pong_rl: RateWindow,
    pub last_ping: Instant,
    pub rtt_us: u32,
}

/// A frame for the `bulk` writer task.
pub(crate) enum BulkOut {
    Frame(Vec<u8>),
    Data { id: u32, data: Bytes },
}

pub(crate) struct Shared {
    pub cfg: LinkConfig,
    pub info: SessionInfo,
    pub minor: u8,
    pub negotiated: Vec<hx_proto::VideoCodec>,
    closed_flag: AtomicBool,
    closed: Mutex<Option<LinkClosed>>,
    close_tx: watch::Sender<bool>,
    pub inbox: Inbox,
    pub out: OutQ,
    pub video: Mutex<VideoState>,
    pub formats: Mutex<FormatList>,
    pub fmt_notify: Notify,
    pub credits: Arc<Credits>,
    pub counters: Mutex<Counters>,
    pub pings: Mutex<Pings>,
    pub xfer: Mutex<XferState>,
    pub epoch: AtomicU32,
    pub epoch_set: AtomicBool,
    pub clipboard_allowed: AtomicBool,
    pub files_allowed: AtomicBool,
    pub bulk_tx: mpsc::Sender<BulkOut>,
    /// Transfer aborts, written ahead of queued bulk data. Separate from `bulk_tx` so that an
    /// upload filling that channel can neither delay an abort behind its data nor make the abort
    /// fail (review L1).
    aborts: Mutex<VecDeque<Vec<u8>>>,
    pub abort_wake: Notify,
    pub events_rl: Mutex<EventRates>,
    pub cursor_rl: Mutex<CursorRates>,
}

/// Rate windows for the message classes that are dropped, not punished, when over their limit.
pub(crate) struct EventRates {
    pub stats: RateWindow,
    pub event: RateWindow,
    pub stream_format: RateWindow,
    pub cancel: RateWindow,
    pub unknown: RateWindow,
}

pub(crate) struct CursorRates {
    pub shapes: RateWindow,
    pub shape_bytes: VecDeque<(Instant, usize)>,
}

impl Shared {
    pub(crate) fn new(
        cfg: LinkConfig,
        info: SessionInfo,
        minor: u8,
        bulk_tx: mpsc::Sender<BulkOut>,
    ) -> Arc<Self> {
        let ceiling = {
            let a = if info.max_fps == 0 { 240 } else { info.max_fps };
            let b = if cfg.max_fps == 0 { 240 } else { cfg.max_fps };
            a.min(b) as usize
        };
        let now = Instant::now();
        let mut nonce = [0u8; 8];
        let _ = rustix::rand::getrandom(&mut nonce, rustix::rand::GetRandomFlags::empty());
        Arc::new(Self {
            negotiated: info.codecs.clone(),
            minor,
            close_tx: watch::channel(false).0,
            closed_flag: AtomicBool::new(false),
            closed: Mutex::new(None),
            inbox: Inbox::new(),
            out: OutQ::new(),
            video: Mutex::new(VideoState {
                newest: None,
                gate_armed: false,
                // Attempts beyond 4 x the allowed rate in a second are a flood, not a busy
                // desktop: they close the link instead of being dropped one by one.
                attempts_rl: RateWindow::per_second(limits::video_frames(ceiling) * 4),
                frames_rl: RateWindow::per_second(limits::video_frames(ceiling)),
                idr_rl: RateWindow::per_second(limits::IDR_FRAMES),
                request_idr_rl: RateWindow::per_second(limits::REQUEST_IDR),
                idr_retry: false,
                last_delivered: 0,
            }),
            formats: Mutex::new(FormatList::default()),
            fmt_notify: Notify::new(),
            credits: Arc::new(Credits::default()),
            counters: Mutex::new(Counters::default()),
            pings: Mutex::new(Pings {
                next_nonce: u64::from_le_bytes(nonce),
                pending: VecDeque::new(),
                pong_rl: RateWindow::per_second(limits::PONG),
                last_ping: now,
                rtt_us: 0,
            }),
            xfer: Mutex::new(XferState {
                next_id: 1,
                clipboard_rl: Some(RateWindow::per_second(limits::CLIPBOARD_TRANSFERS)),
                ..XferState::default()
            }),
            epoch: AtomicU32::new(0),
            epoch_set: AtomicBool::new(false),
            clipboard_allowed: AtomicBool::new(cfg.clipboard_allowed),
            files_allowed: AtomicBool::new(cfg.files_allowed),
            bulk_tx,
            aborts: Mutex::new(VecDeque::new()),
            abort_wake: Notify::new(),
            events_rl: Mutex::new(EventRates {
                stats: RateWindow::per_second(limits::STATS),
                event: RateWindow::per_second(limits::EVENT),
                stream_format: RateWindow::per_second(limits::STREAM_FORMAT),
                cancel: RateWindow::per_second(limits::CANCEL_FRAMES),
                unknown: RateWindow::per_second(limits::UNKNOWN_VARIANTS),
            }),
            cursor_rl: Mutex::new(CursorRates {
                shapes: RateWindow::per_second(limits::CURSOR_SHAPES),
                shape_bytes: VecDeque::new(),
            }),
            info,
            cfg,
        })
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed_flag.load(Relaxed)
    }

    /// Completes when the link has ended.
    pub(crate) async fn wait_closed(&self) {
        let mut rx = self.close_tx.subscribe();
        let _ = rx.wait_for(|v| *v).await;
    }

    pub(crate) fn closed_reason(&self) -> Option<LinkClosed> {
        lock(&self.closed).clone()
    }

    /// Ends the link. The first call wins; every task notices and returns.
    pub(crate) fn fail(&self, class: FailureClass, detail: impl Into<String>) {
        {
            let mut c = lock(&self.closed);
            if c.is_some() {
                return;
            }
            *c = Some(LinkClosed::new(class, detail));
        }
        self.closed_flag.store(true, Relaxed);
        let _ = self.close_tx.send(true);
        self.inbox.wake.notify_waiters();
        self.inbox.wake.notify_one();
        self.out.wake.notify_one();
    }

    /// Queues an encoded `TransferAbort` for the `bulk` writer. Never fails because an upload
    /// is in progress; a session that provokes more than 1 024 unwritten aborts is not reading
    /// `bulk` at all, which ends the link as a fault.
    pub(crate) fn queue_abort(&self, frame: Vec<u8>) {
        {
            let mut q = lock(&self.aborts);
            if q.len() >= 1_024 {
                drop(q);
                self.fail(
                    FailureClass::Fault,
                    "bulk abort queue full: the session is not reading",
                );
                return;
            }
            q.push_back(frame);
        }
        self.abort_wake.notify_one();
    }

    pub(crate) fn pop_abort(&self) -> Option<Vec<u8>> {
        lock(&self.aborts).pop_front()
    }

    pub(crate) fn count(&self, f: impl FnOnce(&mut Counters)) {
        f(&mut lock(&self.counters));
    }

    /// Queues a message at priority P1; a full queue is a link fault.
    pub(crate) fn send_p1(&self, m: pb::gateway_to_session::Message) -> bool {
        match encode_gateway_message(&pb::GatewayToSession { message: Some(m) }) {
            Ok(f) => {
                if self.is_closed() {
                    return false;
                }
                if !self.out.push_p1(f) {
                    self.fail(
                        FailureClass::Fault,
                        "ctl queue full: the session is not reading",
                    );
                    return false;
                }
                true
            }
            Err(_) => false,
        }
    }

    /// Reports frames as not delivered (`outcome`), 64 per message.
    pub(crate) fn report_frames(&self, numbers: &[u32], outcome: pb::FrameOutcome) {
        for chunk in numbers.chunks(hx_ipc::link::validate::MAX_FEEDBACK_RESULTS) {
            let results = chunk
                .iter()
                .map(|n| pb::FrameResult {
                    frame_number: *n,
                    outcome: outcome as i32,
                    bytes: 0,
                    elapsed_us: 0,
                    queued_us: 0,
                })
                .collect();
            self.send_p1(pb::gateway_to_session::Message::FrameFeedback(
                pb::FrameFeedback { results },
            ));
        }
    }

    /// After a cancel or a drop: discard non-key frames until `KEY | RESYNC`, and ask for one
    /// (at most 2 requests per second; a refused request is retried by the maintenance task).
    pub(crate) fn arm_resync(&self) {
        lock(&self.video).gate_armed = true;
        self.request_idr();
    }

    pub(crate) fn request_idr(&self) {
        if !self.epoch_set.load(Relaxed) {
            return;
        }
        let (allowed, last) = {
            let mut v = lock(&self.video);
            let allowed = v.request_idr_rl.allow(Instant::now());
            v.idr_retry = !allowed;
            (allowed, v.last_delivered)
        };
        if allowed {
            self.send_p1(pb::gateway_to_session::Message::RequestIdr(
                pb::RequestIdr {
                    epoch: self.epoch.load(Relaxed),
                    last_decoded_frame: last,
                },
            ));
        }
    }
}

#[cfg(test)]
mod credit_tests {
    use super::*;

    #[test]
    fn the_per_transfer_map_is_bounded_when_data_and_end_arrive_back_to_back() {
        // Review M3: 10 000 tiny transfers, each `Data` then `End`, while the consumer holds the
        // chunks of the last 8. Before the fix every ended transfer with unread bytes leaked its
        // entry for ever.
        let credits = Arc::new(Credits::default());
        let mut held = VecDeque::new();
        for id in 1..=10_000u32 {
            let id = id * 2;
            held.push_back(credits.acquire(id, 100));
            credits.forget(id); // the End frame
            if held.len() > 8 {
                held.pop_front();
            }
            assert!(
                credits.entries() <= 9,
                "{} entries at {id}",
                credits.entries()
            );
        }
        held.clear();
        assert_eq!(
            credits.entries(),
            0,
            "everything is released with the chunks"
        );
        assert_eq!(credits.link.load(Relaxed), 0);
        assert_eq!(credits.at_limit.load(Relaxed), 0);
        // An abort of a transfer that never delivered data leaves nothing either.
        credits.forget(4);
        assert_eq!(credits.entries(), 0);
    }

    #[tokio::test]
    async fn the_limits_are_tracked_without_scanning() {
        let credits = Arc::new(Credits::default());
        credits.wait_room().await;
        // One transfer at 1 MiB pauses the lane; so does 4 MiB spread over transfers.
        let big = credits.acquire(2, TRANSFER_UNREAD_LIMIT as usize);
        assert!(!credits.room());
        assert_eq!(credits.at_limit.load(Relaxed), 1);
        let waiter = {
            let c = credits.clone();
            tokio::spawn(async move { c.wait_room().await })
        };
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        drop(big);
        waiter.await.unwrap();
        assert!(credits.room());
        let held: Vec<_> = (0..4u32)
            .map(|i| credits.acquire(2 * (i + 1), (LINK_UNREAD_LIMIT / 4) as usize - 1))
            .collect();
        // Each is just under the per-transfer limit, together they are just under the link's;
        // one more byte anywhere crosses the link limit.
        assert!(credits.room());
        let more = credits.acquire(100, 8);
        assert!(!credits.room());
        drop(more);
        drop(held);
        assert!(credits.room());
        assert_eq!(credits.at_limit.load(Relaxed), 0);
    }
}
