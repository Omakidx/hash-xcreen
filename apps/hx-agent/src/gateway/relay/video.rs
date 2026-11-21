//! Video toward one client: the bounded frame queue the event pump fills, the window of frames
//! in flight, the feedback to the session's congestion controller and the sender task.
//!
//! # Bounds (ipc.md 15.2)
//!
//! A frame the link client hands out (`LinkEvent::Frame`) is no longer counted by its pool, so
//! the relay counts it itself, in two places and nowhere else:
//!
//! * **Queued** ([`FrameQueue`]): at most 4 frames and `2 x max(max_frame_bytes, 4 MiB)` bytes.
//!   The event pump pushes without waiting; when the queue is over a bound the **oldest** frames
//!   are evicted (and reported `DROPPED`), so a slow client never makes the pump, and with it the
//!   session's writer, wait.
//! * **In flight** ([`VideoShared`]): frames handed to the transport and not yet acknowledged, at
//!   most 16 and `max(2 x max_frame_bytes, 12 MiB)` bytes. A frame that would overflow the window
//!   makes the sender cancel everything in flight (`STALE_FRAME`) and, unless it is itself a key
//!   frame, be dropped; frames older than 1 s are cancelled by the sender's tick.
//!
//! Every cancel or drop breaks the H.264 chain: until a `KEY` frame arrives the sender drops
//! every non-key frame, and the feedback it reports (`CANCELLED`, `DROPPED`) makes the link
//! client ask the session for an IDR (at most 2 per second).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hx_ipc::link::{MEDIA_HEADER_LEN, pb};
use hx_proto::channel::CloseCode;
use hx_proto::order::serial_gt;
use hx_proto::pb::{ControlMessage, control_message::Message as Ctl};
use hx_transport::{AckOutcome, Connection, FrameAck, FrameTicket};
use tokio::sync::{Notify, watch};

use super::util::lock;
use crate::link::{Frame, StreamFormat};

/// Frames queued for the sender.
const QUEUE_FRAMES: usize = 4;
/// Frames in flight at most.
const INFLIGHT_FRAMES: usize = 16;
/// A frame not delivered after this long is cancelled.
const STALE_AFTER: Duration = Duration::from_secs(1);
/// How long handing one frame to the transport may take (stream credit): about 100 ms
/// (ipc.md 15.2), a little more so that a busy runtime is not mistaken for a stuck client.
const SEND_BUDGET: Duration = Duration::from_millis(150);
/// A control write (`StreamInfo`) that does not finish in this long means the client does not
/// read its control channel.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
/// Results kept for the feedback task.
const FEEDBACK_CAP: usize = 256;
/// Results per `frame_feedback` message.
const FEEDBACK_BATCH: usize = 64;

/// The bounded queue between the event pump and the sender task. Pushing never waits.
pub(super) struct FrameQueue {
    q: Mutex<(VecDeque<Frame>, u64)>,
    max_frames: usize,
    max_bytes: u64,
    pub(super) notify: Notify,
}

impl FrameQueue {
    fn new(max_bytes: u64) -> Self {
        Self {
            q: Mutex::new((VecDeque::new(), 0)),
            max_frames: QUEUE_FRAMES,
            max_bytes,
            notify: Notify::new(),
        }
    }

    /// Queues `f`; returns the older frames that had to go to stay within the bounds.
    pub(super) fn push(&self, f: Frame) -> Vec<Frame> {
        let mut evicted = Vec::new();
        {
            let mut g = lock(&self.q);
            g.1 += f.wire().len() as u64;
            g.0.push_back(f);
            while g.0.len() > 1 && (g.0.len() > self.max_frames || g.1 > self.max_bytes) {
                if let Some(old) = g.0.pop_front() {
                    g.1 -= old.wire().len() as u64;
                    evicted.push(old);
                }
            }
        }
        self.notify.notify_one();
        evicted
    }

    fn pop(&self) -> Option<Frame> {
        let mut g = lock(&self.q);
        let f = g.0.pop_front()?;
        g.1 -= f.wire().len() as u64;
        Some(f)
    }

    /// Removes the frames numbered up to `n` (serial arithmetic).
    fn remove_up_to(&self, n: u32) -> Vec<Frame> {
        let mut g = lock(&self.q);
        let mut out = Vec::new();
        let mut keep = VecDeque::new();
        let mut bytes = 0;
        for f in g.0.drain(..) {
            if serial_gt(f.number(), n) {
                bytes += f.wire().len() as u64;
                keep.push_back(f);
            } else {
                out.push(f);
            }
        }
        *g = (keep, bytes);
        out
    }

    /// Empties the queue.
    pub(super) fn clear(&self) -> Vec<Frame> {
        let mut g = lock(&self.q);
        g.1 = 0;
        g.0.drain(..).collect()
    }

    /// Bytes queued.
    pub(super) fn queued_bytes(&self) -> u64 {
        lock(&self.q).1
    }
}

/// Results waiting to go to the session, in a bounded buffer: a push never waits (it runs on a
/// transport task); beyond the bound the oldest result goes and `lost` asks for an IDR instead.
pub(super) struct Feedback {
    buf: Mutex<VecDeque<pb::FrameResult>>,
    lost: AtomicBool,
    pub(super) notify: Notify,
}

impl Feedback {
    fn new() -> Self {
        Self {
            buf: Mutex::new(VecDeque::new()),
            lost: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    pub(super) fn push(&self, r: pb::FrameResult) {
        {
            let mut b = lock(&self.buf);
            if b.len() >= FEEDBACK_CAP {
                b.pop_front();
                self.lost.store(true, Relaxed);
            }
            b.push_back(r);
        }
        self.notify.notify_one();
    }

    pub(super) fn take(&self) -> Vec<pb::FrameResult> {
        let mut b = lock(&self.buf);
        let n = b.len().min(FEEDBACK_BATCH);
        b.drain(..n).collect()
    }

    pub(super) fn take_lost(&self) -> bool {
        self.lost.swap(false, Relaxed)
    }
}

struct Entry {
    number: u32,
    bytes: usize,
    queued_us: u32,
    since: Instant,
    ticket: Option<FrameTicket>,
    cancelled: bool,
}

#[derive(Default)]
struct InFlight {
    entries: VecDeque<Entry>,
    bytes: u64,
}

/// What the sender, the ack handler and the takeover steps share.
pub(super) struct VideoShared {
    pub(super) queue: FrameQueue,
    pub(super) feedback: Feedback,
    inflight: Mutex<InFlight>,
    inflight_cap_bytes: u64,
    /// The decode chain is broken: drop non-key frames until a key frame.
    pub(super) broken: AtomicBool,
    last_key: AtomicU32,
    have_key: AtomicBool,
    pub(super) last_delivered: AtomicU32,
    /// Payload bytes acknowledged as delivered (for the delivery rate).
    pub(super) delivered_bytes: AtomicU64,
    /// Frames handed to the transport (interval counter for `ServerStats`).
    pub(super) sent: AtomicU32,
    /// Frames cancelled or dropped (interval counter for `ServerStats`).
    pub(super) dropped: AtomicU32,
    /// Totals since the client attached (for [`super::RelaySnapshot`]).
    pub(super) total_sent: AtomicU64,
    pub(super) total_dropped: AtomicU64,
    pub(super) total_cancelled: AtomicU64,
}

impl VideoShared {
    pub(super) fn new(max_frame_bytes: u32) -> Arc<Self> {
        let frame = u64::from(max_frame_bytes);
        Arc::new(Self {
            queue: FrameQueue::new(2 * frame.max(4 * 1024 * 1024)),
            feedback: Feedback::new(),
            inflight: Mutex::new(InFlight::default()),
            inflight_cap_bytes: (2 * frame).max(12 * 1024 * 1024),
            broken: AtomicBool::new(false),
            last_key: AtomicU32::new(0),
            have_key: AtomicBool::new(false),
            last_delivered: AtomicU32::new(0),
            delivered_bytes: AtomicU64::new(0),
            sent: AtomicU32::new(0),
            dropped: AtomicU32::new(0),
            total_sent: AtomicU64::new(0),
            total_dropped: AtomicU64::new(0),
            total_cancelled: AtomicU64::new(0),
        })
    }

    /// Queued and in-flight frames and bytes: `(queued_bytes, inflight_frames, inflight_bytes)`.
    pub(super) fn occupancy(&self) -> (u64, usize, u64) {
        let (n, b) = self.counts();
        (self.queue.queued_bytes(), n, b)
    }

    fn result(
        number: u32,
        outcome: pb::FrameOutcome,
        bytes: usize,
        elapsed: Duration,
        queued_us: u32,
    ) -> pb::FrameResult {
        pb::FrameResult {
            frame_number: number,
            outcome: outcome as i32,
            bytes: u32::try_from(bytes).unwrap_or(u32::MAX),
            elapsed_us: u32::try_from(elapsed.as_micros()).unwrap_or(u32::MAX),
            queued_us,
        }
    }

    /// Reports a frame the relay discarded without sending it.
    pub(super) fn report_dropped(&self, f: &Frame) {
        self.dropped.fetch_add(1, Relaxed);
        self.total_dropped.fetch_add(1, Relaxed);
        let queued = u32::try_from(f.received_at.elapsed().as_micros()).unwrap_or(u32::MAX);
        self.feedback.push(Self::result(
            f.number(),
            pb::FrameOutcome::Dropped,
            f.header.payload_len as usize,
            Duration::ZERO,
            queued,
        ));
        self.broken.store(true, Relaxed);
    }

    /// The transport's outcome for one frame (runs on a transport task: short and non-blocking).
    pub(super) fn on_ack(&self, ack: FrameAck) {
        let entry = {
            let mut s = lock(&self.inflight);
            let Some(pos) = s.entries.iter().position(|e| e.number == ack.frame_number) else {
                return;
            };
            let e = s.entries.remove(pos);
            if let Some(e) = &e {
                s.bytes = s.bytes.saturating_sub(e.bytes as u64);
            }
            e
        };
        let Some(e) = entry else { return };
        let outcome = match ack.outcome {
            AckOutcome::Delivered => pb::FrameOutcome::Delivered,
            AckOutcome::Cancelled => pb::FrameOutcome::Cancelled,
            AckOutcome::Rejected(_) => pb::FrameOutcome::Rejected,
            // The connection is gone: the session is told with `stop`, not with feedback.
            AckOutcome::ConnectionLost => return,
        };
        if outcome == pb::FrameOutcome::Delivered {
            self.delivered_bytes.fetch_add(e.bytes as u64, Relaxed);
            if serial_gt(ack.frame_number, self.last_delivered.load(Relaxed)) {
                self.last_delivered.store(ack.frame_number, Relaxed);
            }
        } else {
            self.dropped.fetch_add(1, Relaxed);
            self.total_cancelled.fetch_add(1, Relaxed);
            // A frame older than the newest key frame sent does not break the chain.
            let before_key = self.have_key.load(Relaxed)
                && serial_gt(self.last_key.load(Relaxed), ack.frame_number);
            if !before_key {
                self.broken.store(true, Relaxed);
            }
        }
        self.feedback.push(Self::result(
            ack.frame_number,
            outcome,
            e.bytes,
            ack.elapsed,
            e.queued_us,
        ));
    }

    fn counts(&self) -> (usize, u64) {
        let s = lock(&self.inflight);
        (s.entries.len(), s.bytes)
    }

    fn register(&self, number: u32, bytes: usize, queued_us: u32) {
        let mut s = lock(&self.inflight);
        s.bytes += bytes as u64;
        s.entries.push_back(Entry {
            number,
            bytes,
            queued_us,
            since: Instant::now(),
            ticket: None,
            cancelled: false,
        });
    }

    /// The transport accepted the frame: remember its ticket (cancelling at once if a cancel
    /// came in between), unless the outcome is already known.
    fn attach(&self, number: u32, ticket: FrameTicket) {
        let mut s = lock(&self.inflight);
        if let Some(e) = s.entries.iter_mut().find(|e| e.number == number) {
            if e.cancelled {
                ticket.cancel();
            }
            e.ticket = Some(ticket);
        }
    }

    /// The transport refused the frame: forget it.
    fn unregister(&self, number: u32) {
        let mut s = lock(&self.inflight);
        if let Some(pos) = s.entries.iter().position(|e| e.number == number)
            && let Some(e) = s.entries.remove(pos)
        {
            s.bytes = s.bytes.saturating_sub(e.bytes as u64);
        }
    }

    fn cancel_where(&self, mut pick: impl FnMut(&Entry) -> bool) -> usize {
        let mut s = lock(&self.inflight);
        let mut n = 0;
        for e in s.entries.iter_mut().filter(|e| !e.cancelled) {
            if pick(e) {
                e.cancelled = true;
                if let Some(t) = &e.ticket {
                    t.cancel();
                }
                n += 1;
            }
        }
        n
    }

    /// Cancels every frame in flight (takeover step 2, a full window).
    pub(super) fn cancel_all(&self) -> usize {
        self.cancel_where(|_| true)
    }

    /// Cancels the frames numbered up to `n` (the session's `cancel_frames`), in flight and
    /// queued.
    pub(super) fn cancel_up_to(&self, n: u32) {
        self.cancel_where(|e| !serial_gt(e.number, n));
        for f in self.queue.remove_up_to(n) {
            self.report_dropped(&f);
        }
    }

    fn cancel_stale(&self) {
        let now = Instant::now();
        self.cancel_where(|e| now.saturating_duration_since(e.since) >= STALE_AFTER);
    }

    /// In-flight frames (tests).
    #[cfg(test)]
    pub(super) fn inflight_frames(&self) -> usize {
        self.counts().0
    }
}

/// What `StreamInfo` was last sent for.
#[derive(Clone, Copy, PartialEq, Eq)]
struct SentFormat {
    codec: hx_proto::VideoCodec,
    width: u32,
    height: u32,
    fps: u32,
    first_frame: u32,
}

impl SentFormat {
    fn of(f: &StreamFormat) -> Self {
        Self {
            codec: f.codec,
            width: f.width,
            height: f.height,
            fps: f.fps,
            first_frame: f.first_frame,
        }
    }
}

/// The sender task of one client.
pub(super) async fn sender(
    conn: Connection,
    video: Arc<VideoShared>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut sent_format: Option<SentFormat> = None;
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        while let Some(frame) = video.queue.pop() {
            if *shutdown.borrow() {
                return;
            }
            if !send_frame(&conn, &video, &mut sent_format, frame).await {
                return;
            }
        }
        tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            () = video.queue.notify.notified() => {}
            _ = tick.tick() => video.cancel_stale(),
        }
    }
}

/// Sends one frame. `false` ends the task (the connection is gone or unusable).
async fn send_frame(
    conn: &Connection,
    video: &Arc<VideoShared>,
    sent_format: &mut Option<SentFormat>,
    frame: Frame,
) -> bool {
    let key = frame.is_key();
    let number = frame.number();
    let payload_len = frame.header.payload_len as usize;
    // A broken chain: nothing but a key frame is worth sending.
    if video.broken.load(Relaxed) && !key {
        video.report_dropped(&frame);
        return true;
    }
    let (n, bytes) = video.counts();
    let full =
        n >= INFLIGHT_FRAMES || (n > 0 && bytes + payload_len as u64 > video.inflight_cap_bytes);
    if full {
        // The client is not keeping up: everything in flight is stale (ipc.md 15.2).
        video.cancel_all();
        if !key || n >= 2 * INFLIGHT_FRAMES {
            video.report_dropped(&frame);
            return true;
        }
    }
    if key {
        video.last_key.store(number, Relaxed);
        video.have_key.store(true, Relaxed);
        video.broken.store(false, Relaxed);
    }
    let fmt = SentFormat::of(&frame.format);
    if *sent_format != Some(fmt) {
        let m = ControlMessage::new(Ctl::StreamInfo(hx_proto::pb::StreamInfo {
            codec: fmt.codec as i32,
            width: fmt.width,
            height: fmt.height,
            fps: fmt.fps,
            first_frame: fmt.first_frame,
        }));
        match tokio::time::timeout(CONTROL_TIMEOUT, conn.send_control(&m)).await {
            Ok(Ok(())) => *sent_format = Some(fmt),
            Ok(Err(_)) => return false,
            Err(_) => {
                // A half-written message cannot be skipped: the connection is unusable.
                let c = conn.clone();
                tokio::spawn(async move { c.close(CloseCode::Busy, "not reading").await });
                return false;
            }
        }
    }
    let queued_us = u32::try_from(frame.received_at.elapsed().as_micros()).unwrap_or(u32::MAX);
    video.register(number, payload_len, queued_us);
    let payload = frame.wire().slice(MEDIA_HEADER_LEN..);
    match tokio::time::timeout(SEND_BUDGET, conn.send_video_frame(frame.header, payload)).await {
        Ok(Ok(ticket)) => {
            video.sent.fetch_add(1, Relaxed);
            video.total_sent.fetch_add(1, Relaxed);
            video.attach(number, ticket);
            true
        }
        Ok(Err(_)) => {
            video.unregister(number);
            video.report_dropped(&frame);
            conn.close_info().is_none()
        }
        Err(_) => {
            // No stream credit within the budget: not queued (ipc.md 15.2).
            video.unregister(number);
            video.cancel_all();
            video.report_dropped(&frame);
            true
        }
    }
}

/// The feedback task: batches results into `frame_feedback` messages for the session.
pub(super) async fn feedback_task(
    link: crate::link::LinkClient,
    video: Arc<VideoShared>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            () = video.feedback.notify.notified() => {}
        }
        // Let a burst of acknowledgements gather into one message.
        tokio::time::sleep(Duration::from_millis(2)).await;
        loop {
            let batch = video.feedback.take();
            if batch.is_empty() {
                break;
            }
            if link.frame_feedback(&batch).is_err() {
                return;
            }
        }
        if video.feedback.take_lost() {
            let _ = link.request_idr(video.last_delivered.load(Relaxed));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ack(n: u32, outcome: AckOutcome) -> FrameAck {
        FrameAck {
            frame_number: n,
            bytes: 100,
            elapsed: Duration::from_millis(3),
            outcome,
        }
    }

    fn frame(n: u32, key: bool, payload: usize) -> Frame {
        use hx_proto::media::{FLAG_KEY, MediaHeader};
        Frame {
            header: MediaHeader {
                codec: hx_proto::VideoCodec::H264,
                flags: if key { FLAG_KEY } else { 0 },
                frame_number: n,
                capture_timestamp_us: 0,
                payload_len: payload as u32,
            },
            format: Arc::new(StreamFormat {
                epoch: 1,
                codec: hx_proto::VideoCodec::H264,
                width: 64,
                height: 64,
                fps: 30,
                first_frame: 0,
            }),
            received_at: Instant::now(),
            body: bytes::Bytes::from(vec![0u8; MEDIA_HEADER_LEN + payload]),
        }
    }

    #[test]
    fn the_frame_queue_evicts_the_oldest_and_never_exceeds_its_bounds() {
        let q = FrameQueue::new(100_000);
        let mut evicted = Vec::new();
        for n in 0..10 {
            evicted.extend(
                q.push(frame(n, n == 0, 1_000))
                    .into_iter()
                    .map(|f| f.number()),
            );
        }
        assert_eq!(evicted, [0, 1, 2, 3, 4, 5], "the four newest stay");
        assert_eq!(q.pop().unwrap().number(), 6);
        // Bytes: a frame bigger than the byte bound still queues (it is the only one), and
        // pushes out everything older.
        let q = FrameQueue::new(5_000);
        q.push(frame(1, true, 2_000));
        q.push(frame(2, false, 2_000));
        let out = q.push(frame(3, false, 2_000));
        assert_eq!(out.len(), 1);
        assert!(q.queued_bytes() <= 5_000 + 1_000);
        let out = q.push(frame(4, true, 50_000));
        assert_eq!(out.len(), 2);
        assert_eq!(q.pop().unwrap().number(), 4);
        assert!(q.pop().is_none());
        assert_eq!(q.queued_bytes(), 0);
        // A cancel up to a number removes the older queued frames only.
        let q = FrameQueue::new(100_000);
        for n in 5..9 {
            q.push(frame(n, false, 10));
        }
        let gone: Vec<u32> = q.remove_up_to(6).iter().map(|f| f.number()).collect();
        assert_eq!(gone, [5, 6]);
        assert_eq!(q.pop().unwrap().number(), 7);
    }

    #[test]
    fn feedback_is_bounded_and_flags_what_it_lost() {
        let fb = Feedback::new();
        for i in 0..(FEEDBACK_CAP as u32 + 10) {
            fb.push(VideoShared::result(
                i,
                pb::FrameOutcome::Delivered,
                1,
                Duration::ZERO,
                0,
            ));
        }
        assert!(fb.take_lost());
        assert!(!fb.take_lost());
        let mut total = 0;
        loop {
            let b = fb.take();
            if b.is_empty() {
                break;
            }
            assert!(b.len() <= FEEDBACK_BATCH);
            total += b.len();
        }
        assert_eq!(total, FEEDBACK_CAP);
    }

    #[test]
    fn acks_become_feedback_and_a_cancel_breaks_the_chain_only_after_the_last_key() {
        let v = VideoShared::new(4 * 1024 * 1024);
        v.last_key.store(10, Relaxed);
        v.have_key.store(true, Relaxed);
        v.register(9, 100, 5);
        v.register(11, 100, 6);
        // A frame older than the newest key does not break the chain.
        v.on_ack(ack(9, AckOutcome::Cancelled));
        assert!(!v.broken.load(Relaxed));
        v.on_ack(ack(11, AckOutcome::Cancelled));
        assert!(v.broken.load(Relaxed));
        let r = v.feedback.take();
        assert_eq!(r.len(), 2);
        assert_eq!(r[1].outcome, pb::FrameOutcome::Cancelled as i32);
        assert_eq!(r[1].queued_us, 6);
        assert_eq!(v.inflight_frames(), 0);
        // An ack for an unknown frame, or for a lost connection, produces nothing.
        v.on_ack(ack(99, AckOutcome::Delivered));
        v.register(12, 100, 0);
        v.on_ack(ack(12, AckOutcome::ConnectionLost));
        assert!(v.feedback.take().is_empty());
    }

    #[test]
    fn delivered_acks_update_the_rate_counters() {
        let v = VideoShared::new(4 * 1024 * 1024);
        v.register(1, 4_000, 0);
        v.on_ack(ack(1, AckOutcome::Delivered));
        assert_eq!(v.delivered_bytes.load(Relaxed), 4_000);
        assert_eq!(v.last_delivered.load(Relaxed), 1);
    }
}
