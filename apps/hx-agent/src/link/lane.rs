//! Async lane I/O of the gateway end: a bounded frame reader and a stall-aware writer.
//!
//! Everything the session sends is hostile input. [`LaneReader`] reads **only** with
//! `recvmsg` through [`hx_ipc::recv::recv_no_cmsg`] (a descriptor or any control message is a
//! violation), feeds the sans-I/O [`Decoder`] (which checks every length before allocating), and
//! adds what the decoder cannot: time and volume.
//!
//! * a frame must arrive within a deadline that grows with its size (`BODY_BASE` plus the length
//!   at `BODY_MIN_RATE`), so a drip cannot hold a lane;
//! * an idle limit closes a lane that must not stay silent (`ctl`);
//! * a [`ByteBudget`] stops reading beyond the lane's rate (backpressure, not discard) and a
//!   lane that keeps data waiting at an empty bucket for 3 s is a violation;
//! * the per-second frame-count limit (`lane_frame_limit`) is a violation when exceeded.

use super::shared::Credits;
use hx_ipc::ReadError;
use hx_ipc::frame::{Decoder, RawFrame};
use hx_ipc::link::budget::{ByteBudget, RateWindow, lane_frame_limit};
use hx_ipc::link::{KIND_VIDEO, Lane, LinkPolicy, Role};
use hx_ipc::recv::recv_no_cmsg;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::Interest;
use tokio::net::UnixStream;
use tokio::time::{Instant, timeout};

/// Time a frame has to arrive in once its first byte is in.
pub(crate) const BODY_BASE: Duration = Duration::from_secs(5);
/// A frame body must arrive at least this fast (bytes per second) beyond the base time.
pub(crate) const BODY_MIN_RATE: u64 = 256 * 1024;

/// Why a lane stopped.
#[derive(Debug)]
pub(crate) enum LaneFail {
    /// The session closed the lane at a frame boundary.
    Eof,
    /// Nothing arrived for the idle limit.
    Idle,
    /// The transport failed.
    Io(io::Error),
    /// The session broke the contract.
    Violation(String),
}

impl LaneFail {
    pub(crate) fn text(&self) -> String {
        match self {
            LaneFail::Eof => "the session closed the lane".into(),
            LaneFail::Idle => "no data within the liveness timeout".into(),
            LaneFail::Io(e) => format!("io: {e}"),
            LaneFail::Violation(v) => v.clone(),
        }
    }
}

/// One `recvmsg`, waiting for readiness. A control message is an `InvalidData` error that
/// [`ReadError::from`] turns into a violation.
async fn read_some(s: &UnixStream, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        s.readable().await?;
        match s.try_io(Interest::READABLE, || recv_no_cmsg(s, buf)) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

/// Reads exactly `buf.len()` bytes through `recvmsg` (the preamble answer).
pub(crate) async fn read_exact(s: &UnixStream, buf: &mut [u8]) -> Result<(), LaneFail> {
    let mut filled = 0;
    while filled < buf.len() {
        match read_some(s, &mut buf[filled..]).await {
            Ok(0) => return Err(LaneFail::Eof),
            Ok(n) => filled += n,
            Err(e) => {
                return Err(match ReadError::from(e) {
                    ReadError::Io(e) => LaneFail::Io(e),
                    other => LaneFail::Violation(other.to_string()),
                });
            }
        }
    }
    Ok(())
}

/// A write that makes no progress for the stall time failed.
#[derive(Debug)]
pub(crate) enum WriteFail {
    Stall,
    Io(io::Error),
}

/// Writes all of `buf`; no progress for `stall` is a [`WriteFail::Stall`].
pub(crate) async fn write_all_stall(
    s: &UnixStream,
    mut buf: &[u8],
    stall: Duration,
) -> Result<(), WriteFail> {
    while !buf.is_empty() {
        match timeout(stall, s.writable()).await {
            Err(_) => return Err(WriteFail::Stall),
            Ok(Err(e)) => return Err(WriteFail::Io(e)),
            Ok(Ok(())) => match s.try_write(buf) {
                Ok(0) => return Err(WriteFail::Io(io::ErrorKind::WriteZero.into())),
                Ok(n) => buf = &buf[n..],
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(WriteFail::Io(e)),
            },
        }
    }
    Ok(())
}

/// Reads frames from one lane.
pub(crate) struct LaneReader {
    stream: Arc<UnixStream>,
    decoder: Decoder<LinkPolicy>,
    policy: LinkPolicy,
    budget: Option<ByteBudget>,
    frame_rate: Option<RateWindow>,
    idle_limit: Option<Duration>,
    last_byte: Instant,
    frame_started: Option<Instant>,
    frame_deadline: Duration,
    buf: Box<[u8; 65_536]>,
    /// Pauses the lane while a consumer holds too much unread bulk data.
    credits: Option<Arc<Credits>>,
}

impl LaneReader {
    pub(crate) fn new(
        stream: Arc<UnixStream>,
        lane: Lane,
        policy: LinkPolicy,
        idle_limit: Option<Duration>,
        credits: Option<Arc<Credits>>,
    ) -> Self {
        let now = Instant::now();
        Self {
            stream,
            decoder: Decoder::new(policy),
            policy,
            budget: ByteBudget::for_lane(Role::Gateway, lane, now.into_std()),
            frame_rate: lane_frame_limit(Role::Gateway, lane).map(RateWindow::per_second),
            idle_limit,
            last_byte: now,
            frame_started: None,
            frame_deadline: BODY_BASE,
            buf: Box::new([0; 65_536]),
            credits,
        }
    }

    pub(crate) fn policy(&self) -> &LinkPolicy {
        &self.policy
    }

    /// Changes the idle limit (after the handshake, the `ctl` liveness timeout applies).
    pub(crate) fn set_idle_limit(&mut self, limit: Option<Duration>) {
        self.idle_limit = limit;
    }

    /// The next complete frame.
    pub(crate) async fn next(&mut self) -> Result<RawFrame, LaneFail> {
        loop {
            // Downstream flow control: a consumer that holds too much pauses the lane. That is
            // not the session's doing, so it is not starvation.
            if self.decoder.at_boundary()
                && let Some(c) = &self.credits
            {
                c.wait_room().await;
                self.last_byte = Instant::now();
            }
            let now = Instant::now();
            if let Some(b) = &mut self.budget
                && self.decoder.at_boundary()
            {
                if b.allowance(now.into_std()) == 0 {
                    let pending = timeout(Duration::ZERO, self.stream.readable())
                        .await
                        .is_ok();
                    b.note_pending(pending, now.into_std());
                    if b.violated(now.into_std()) {
                        return Err(LaneFail::Violation("byte budget exceeded".into()));
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
                // Positive allowance: no verdict. Only an idle peer or a recovered bucket resets
                // the starvation clock, not merely touching zero between two frames.
                b.note_pending(true, now.into_std());
            }
            let want = self.decoder.wants().min(self.buf.len());
            // How long this read may take: the frame deadline mid-frame, the idle limit between
            // frames (none: the lane may stay silent).
            let limit = match self.frame_started {
                Some(start) => Some(
                    self.frame_deadline
                        .saturating_sub(now.saturating_duration_since(start)),
                ),
                None => self
                    .idle_limit
                    .map(|l| l.saturating_sub(now.saturating_duration_since(self.last_byte))),
            };
            let read = match limit {
                Some(l) => match timeout(l, read_some(&self.stream, &mut self.buf[..want])).await {
                    Ok(r) => r,
                    Err(_) => {
                        return Err(if self.frame_started.is_some() {
                            LaneFail::Violation("frame body timed out".into())
                        } else {
                            LaneFail::Idle
                        });
                    }
                },
                None => read_some(&self.stream, &mut self.buf[..want]).await,
            };
            let n = match read {
                Ok(0) => {
                    return match self.decoder.finish() {
                        Ok(()) => Err(LaneFail::Eof),
                        Err(e) => Err(LaneFail::Violation(e.to_string())),
                    };
                }
                Ok(n) => n,
                Err(e) => {
                    return Err(match ReadError::from(e) {
                        ReadError::Io(e) => LaneFail::Io(e),
                        other => LaneFail::Violation(other.to_string()),
                    });
                }
            };
            let now = Instant::now();
            self.last_byte = now;
            let was_boundary = self.decoder.at_boundary();
            let (_used, frame) = self
                .decoder
                .feed(&self.buf[..n])
                .map_err(|e| LaneFail::Violation(e.to_string()))?;
            if was_boundary && self.frame_started.is_none() {
                self.frame_started = Some(now);
                self.frame_deadline = BODY_BASE;
            }
            if let Some(frame) = frame {
                self.frame_started = None;
                if let Some(b) = &mut self.budget {
                    b.consume(frame.body.len() as u64 + 5, now.into_std());
                }
                // Video has its own `2 x max_fps` limit; every other kind counts here.
                if frame.kind != KIND_VIDEO
                    && let Some(r) = &mut self.frame_rate
                    && !r.allow(now.into_std())
                {
                    return Err(LaneFail::Violation("frame-count limit exceeded".into()));
                }
                return Ok(frame);
            }
            if !self.decoder.at_boundary() {
                let remaining = self.decoder.wants() as u64;
                self.frame_deadline = self
                    .frame_deadline
                    .max(BODY_BASE + Duration::from_millis(remaining * 1000 / BODY_MIN_RATE));
            }
        }
    }
}

/// The policy the gateway applies when reading `lane` of a link with this frame cap.
pub(crate) fn gateway_policy(lane: Lane, max_frame_bytes: u32) -> io::Result<LinkPolicy> {
    LinkPolicy::new(Role::Gateway, lane)
        .with_max_frame_bytes(max_frame_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
}
