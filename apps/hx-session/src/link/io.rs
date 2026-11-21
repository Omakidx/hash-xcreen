//! Blocking lane I/O for the session end: a bounded frame reader and the output queue of the
//! control lane.
//!
//! The reader is the session's counterpart of the gateway's: it reads **only** through
//! [`NoCmsgReader`] (a descriptor or any control message is a violation), checks every limit of
//! `docs/ipc.md` section 13 before allocating (the [`Decoder`] does that), and bounds time:
//! a frame must arrive within a deadline that grows with its size, and an idle lane is closed
//! after `idle_limit`. Byte budgets and per-second frame counts are enforced here too.

use hx_ipc::ReadError;
use hx_ipc::frame::{Decoder, RawFrame};
use hx_ipc::link::budget::{ByteBudget, RateWindow, lane_frame_limit};
use hx_ipc::link::{Lane, LinkPolicy, Role};
use hx_ipc::recv::NoCmsgReader;
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

/// How often a blocked read wakes to look at the `closed` flag and the clocks.
const POLL: Duration = Duration::from_millis(100);
/// Base time a frame has to arrive in once its first byte is in.
pub(crate) const BODY_BASE: Duration = Duration::from_secs(5);
/// A frame body must arrive at least this fast (bytes per second) beyond the base time.
const BODY_MIN_RATE: u64 = 256 * 1024;

/// Why a lane stopped.
#[derive(Debug)]
pub(crate) enum LaneError {
    /// The link was closed locally.
    Closed,
    /// The peer closed the lane at a frame boundary.
    Eof,
    /// Nothing arrived for the idle limit.
    Idle,
    /// The transport failed.
    Io(io::Error),
    /// The peer broke the contract: the link is dropped.
    Violation(String),
}

impl LaneError {
    pub(crate) fn text(&self) -> String {
        match self {
            LaneError::Closed => "closed".into(),
            LaneError::Eof => "peer closed the lane".into(),
            LaneError::Idle => "idle timeout".into(),
            LaneError::Io(e) => format!("io: {e}"),
            LaneError::Violation(v) => format!("violation: {v}"),
        }
    }
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

/// Reads frames from one lane.
pub(crate) struct LaneReader {
    stream: UnixStream,
    decoder: Decoder<LinkPolicy>,
    budget: Option<ByteBudget>,
    frame_rate: Option<RateWindow>,
    frame_started: Option<Instant>,
    frame_deadline: Duration,
    last_byte: Instant,
    idle_limit: Option<Duration>,
    buf: Box<[u8; 65_536]>,
    policy: LinkPolicy,
}

impl LaneReader {
    /// A reader for the session's end of `lane`. `idle_limit` closes a lane that stays silent.
    pub(crate) fn new(
        stream: UnixStream,
        lane: Lane,
        policy: LinkPolicy,
        idle_limit: Option<Duration>,
    ) -> io::Result<Self> {
        stream.set_read_timeout(Some(POLL))?;
        let now = Instant::now();
        Ok(Self {
            stream,
            decoder: Decoder::new(policy),
            budget: ByteBudget::for_lane(Role::Session, lane, now),
            frame_rate: lane_frame_limit(Role::Session, lane).map(RateWindow::per_second),
            frame_started: None,
            frame_deadline: BODY_BASE,
            last_byte: now,
            idle_limit,
            buf: Box::new([0; 65_536]),
            policy,
        })
    }

    pub(crate) fn policy(&self) -> &LinkPolicy {
        &self.policy
    }

    /// True if the socket has data (or an end of stream) waiting. Never blocks.
    pub(crate) fn readable_now(&self) -> bool {
        use rustix::event::{PollFd, PollFlags, poll};
        let zero = rustix::time::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let mut fds = [PollFd::new(&self.stream, PollFlags::IN)];
        matches!(poll(&mut fds, Some(&zero)), Ok(n) if n > 0)
    }

    /// The next complete frame. Blocks, waking every [`POLL`] to look at `closed`.
    pub(crate) fn next(&mut self, closed: &AtomicBool) -> Result<RawFrame, LaneError> {
        loop {
            if closed.load(Relaxed) {
                return Err(LaneError::Closed);
            }
            let now = Instant::now();
            if let Some(b) = &mut self.budget {
                // Beyond the budget the session stops reading: backpressure, not discard. A lane
                // that keeps data waiting at an empty bucket for 3 s is a violation.
                if self.decoder.at_boundary() && b.allowance(now) == 0 {
                    b.note_pending(true, now);
                    if b.violated(now) {
                        return Err(LaneError::Violation("byte budget exceeded".into()));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
                b.note_pending(false, now);
            }
            let want = self.decoder.wants().min(self.buf.len());
            let n = match NoCmsgReader(&self.stream).read(&mut self.buf[..want]) {
                Ok(0) => {
                    return match self.decoder.finish() {
                        Ok(()) => Err(LaneError::Eof),
                        Err(e) => Err(LaneError::Violation(e.to_string())),
                    };
                }
                Ok(n) => n,
                Err(e) if is_timeout(&e) => {
                    self.check_timers(Instant::now())?;
                    continue;
                }
                Err(e) => {
                    return Err(match ReadError::from(e) {
                        ReadError::Io(e) => LaneError::Io(e),
                        other => LaneError::Violation(other.to_string()),
                    });
                }
            };
            let now = Instant::now();
            self.last_byte = now;
            let was_boundary = self.decoder.at_boundary();
            let (_used, frame) = self
                .decoder
                .feed(&self.buf[..n])
                .map_err(|e| LaneError::Violation(e.to_string()))?;
            if was_boundary && self.frame_started.is_none() {
                self.frame_started = Some(now);
                self.frame_deadline = BODY_BASE;
            }
            if let Some(frame) = frame {
                self.frame_started = None;
                let len = frame.body.len() as u64 + 1;
                if let Some(b) = &mut self.budget {
                    b.consume(len + 4, now);
                }
                if let Some(rate) = &mut self.frame_rate
                    && !rate.allow(now)
                {
                    return Err(LaneError::Violation("frame-count limit exceeded".into()));
                }
                return Ok(frame);
            }
            // The body being read gets a deadline that grows with its size (a drip that never
            // pauses long enough to time out still runs out of time).
            if !self.decoder.at_boundary() {
                let remaining = self.decoder.wants() as u64;
                self.frame_deadline = self
                    .frame_deadline
                    .max(BODY_BASE + Duration::from_millis(remaining * 1000 / BODY_MIN_RATE));
            }
            self.check_timers(now)?;
        }
    }

    fn check_timers(&mut self, now: Instant) -> Result<(), LaneError> {
        if let Some(start) = self.frame_started {
            if now.duration_since(start) > self.frame_deadline {
                return Err(LaneError::Violation("frame body timed out".into()));
            }
        } else if let Some(limit) = self.idle_limit
            && now.duration_since(self.last_byte) > limit
        {
            return Err(LaneError::Idle);
        }
        Ok(())
    }
}

/// Reads exactly `buf.len()` bytes within `deadline`, through [`NoCmsgReader`] (a descriptor sent
/// in the preamble is refused like any other).
pub(crate) fn read_exact_deadline(
    stream: &UnixStream,
    buf: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    let mut filled = 0;
    stream.set_read_timeout(Some(POLL))?;
    while filled < buf.len() {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        match NoCmsgReader(stream).read(&mut buf[filled..]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => filled += n,
            Err(e) if is_timeout(&e) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Writes all of `bytes`; a socket that accepts nothing for its write timeout is an error.
pub(crate) fn write_all(mut stream: &UnixStream, bytes: &[u8]) -> io::Result<()> {
    stream.write_all(bytes)
}

/// Bounds of the control output queue.
const OUT_MAX_FRAMES: usize = 256;
const OUT_MAX_BYTES: usize = 2 * 1024 * 1024;
/// Cursor positions go out at most this often (section 13: one per millisecond).
const POS_SPACING: Duration = Duration::from_millis(1);

struct OutState {
    queue: VecDeque<Vec<u8>>,
    queued_bytes: usize,
    pos: Option<Vec<u8>>,
    last_pos: Option<Instant>,
}

/// The `ctl` session-to-gateway queue: strictly bounded, FIFO for messages, latest-wins for the
/// cursor position. One writer thread drains it ([`CtlOut::next`]).
pub(crate) struct CtlOut {
    state: Mutex<OutState>,
    cv: Condvar,
}

/// The queue is full: its consumer is not keeping up.
#[derive(Debug)]
pub(crate) struct OutFull;

impl CtlOut {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(OutState {
                queue: VecDeque::new(),
                queued_bytes: 0,
                pos: None,
                last_pos: None,
            }),
            cv: Condvar::new(),
        }
    }

    /// Queues one whole encoded frame. A full queue means the gateway stopped reading `ctl`;
    /// the caller closes the link.
    pub(crate) fn push(&self, frame: Vec<u8>) -> Result<(), OutFull> {
        let mut s = self.state.lock().map_err(|_| OutFull)?;
        if s.queue.len() >= OUT_MAX_FRAMES || s.queued_bytes + frame.len() > OUT_MAX_BYTES {
            return Err(OutFull);
        }
        s.queued_bytes += frame.len();
        s.queue.push_back(frame);
        self.cv.notify_one();
        Ok(())
    }

    /// Replaces the pending cursor position (latest wins).
    pub(crate) fn push_position(&self, frame: Vec<u8>) {
        if let Ok(mut s) = self.state.lock() {
            s.pos = Some(frame);
            self.cv.notify_one();
        }
    }

    /// Wakes the writer so it can notice a closed link.
    pub(crate) fn wake(&self) {
        self.cv.notify_all();
    }

    /// The next frame to write, waiting up to `wait`. Messages first, then the position,
    /// spaced at least a millisecond apart.
    pub(crate) fn next(&self, wait: Duration, closed: &AtomicBool) -> Option<Vec<u8>> {
        let deadline = Instant::now() + wait;
        let mut s = self.state.lock().ok()?;
        loop {
            if closed.load(Relaxed) {
                return None;
            }
            if let Some(f) = s.queue.pop_front() {
                s.queued_bytes -= f.len();
                return Some(f);
            }
            let now = Instant::now();
            if s.pos.is_some() {
                let due = s.last_pos.map_or(now, |t| t + POS_SPACING);
                if due <= now {
                    s.last_pos = Some(now);
                    return s.pos.take();
                }
                let (g, _) = self.cv.wait_timeout(s, due - now).ok()?;
                s = g;
                continue;
            }
            if now >= deadline {
                return None;
            }
            let (g, _) = self.cv.wait_timeout(s, deadline - now).ok()?;
            s = g;
        }
    }
}

/// The policy the session applies when reading `lane` (default `max_frame_bytes` is irrelevant
/// to the session's own receive side: it only receives `ctl` G to S and `bulk`).
pub(crate) fn session_policy(lane: Lane) -> LinkPolicy {
    LinkPolicy::new(Role::Session, lane)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hx_ipc::frame::encode_frame;
    use hx_ipc::link::KIND_GATEWAY_TO_SESSION;
    use std::sync::atomic::AtomicBool;

    fn pair() -> (UnixStream, UnixStream) {
        UnixStream::pair().unwrap()
    }

    #[test]
    fn reads_frames_and_reports_a_clean_eof() {
        let (a, mut b) = pair();
        let mut r = LaneReader::new(
            a,
            Lane::Ctl,
            session_policy(Lane::Ctl),
            Some(Duration::from_secs(5)),
        )
        .unwrap();
        let closed = AtomicBool::new(false);
        b.write_all(&encode_frame(KIND_GATEWAY_TO_SESSION, &[0x32, 0x00], 16_384).unwrap())
            .unwrap();
        let f = r.next(&closed).unwrap();
        assert_eq!(
            (f.kind, f.body.as_ref()),
            (KIND_GATEWAY_TO_SESSION, &[0x32, 0x00][..])
        );
        drop(b);
        assert!(matches!(r.next(&closed), Err(LaneError::Eof)));
    }

    #[test]
    fn a_frame_cut_by_close_is_a_violation_and_an_oversize_length_is_refused() {
        let (a, mut b) = pair();
        let mut r = LaneReader::new(a, Lane::Ctl, session_policy(Lane::Ctl), None).unwrap();
        let closed = AtomicBool::new(false);
        let wire = encode_frame(KIND_GATEWAY_TO_SESSION, &[1, 2, 3, 4], 16_384).unwrap();
        b.write_all(&wire[..wire.len() - 1]).unwrap();
        drop(b);
        assert!(matches!(r.next(&closed), Err(LaneError::Violation(_))));

        let (a, mut b) = pair();
        let mut r = LaneReader::new(a, Lane::Ctl, session_policy(Lane::Ctl), None).unwrap();
        b.write_all(&(16_385u32).to_le_bytes()).unwrap();
        assert!(matches!(r.next(&closed), Err(LaneError::Violation(_))));
    }

    #[test]
    fn a_byte_on_the_media_lane_is_a_violation() {
        let (a, mut b) = pair();
        let mut r = LaneReader::new(a, Lane::Media, session_policy(Lane::Media), None).unwrap();
        b.write_all(&[0]).unwrap();
        let closed = AtomicBool::new(false);
        assert!(matches!(r.next(&closed), Err(LaneError::Violation(_))));
    }

    #[test]
    fn idle_and_closed_are_reported() {
        let (a, _b) = pair();
        let mut r = LaneReader::new(
            a,
            Lane::Ctl,
            session_policy(Lane::Ctl),
            Some(Duration::from_millis(250)),
        )
        .unwrap();
        let closed = AtomicBool::new(false);
        assert!(matches!(r.next(&closed), Err(LaneError::Idle)));
        closed.store(true, Relaxed);
        assert!(matches!(r.next(&closed), Err(LaneError::Closed)));
    }

    #[test]
    fn output_queue_is_bounded_and_positions_coalesce() {
        let out = CtlOut::new();
        let closed = AtomicBool::new(false);
        for _ in 0..OUT_MAX_FRAMES {
            out.push(vec![1; 10]).unwrap();
        }
        assert!(out.push(vec![1]).is_err());
        let mut q = 0;
        while out.next(Duration::from_millis(1), &closed).is_some() {
            q += 1;
        }
        assert_eq!(q, OUT_MAX_FRAMES);
        out.push_position(vec![1]);
        out.push_position(vec![2]);
        out.push_position(vec![3]);
        assert_eq!(out.next(Duration::from_millis(10), &closed), Some(vec![3]));
        assert_eq!(out.next(Duration::from_millis(5), &closed), None);
        // The byte bound holds too.
        assert!(out.push(vec![0; OUT_MAX_BYTES + 1]).is_err());
    }
}
