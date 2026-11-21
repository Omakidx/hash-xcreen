//! The public value types of the gateway link client: what the session reported, the events the
//! gateway core consumes, and why a link ended.

use bytes::Bytes;
use hx_ipc::link::MEDIA_HEADER_LEN;
use hx_ipc::link::pb;
use hx_proto::VideoCodec;
use hx_proto::media::MediaHeader;
use hx_proto::pb::{CursorPosition, CursorShape, TransferHeader};
use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;

/// What the session said about itself in `info` (validated; `software` is sanitised and
/// log-only, never shown to a client).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    /// Sanitised `info.software` (at most 128 bytes). Log only.
    pub software: String,
    /// The `info.features` bits (`hx_ipc::link::validate::FEATURE_*`).
    pub features: u64,
    /// The codecs both ends accept (the intersection, never empty), in the session's order.
    pub codecs: Vec<VideoCodec>,
    /// The display size at connect.
    pub display: (u32, u32),
    /// The session's frame-rate ceiling (0: not stated).
    pub max_fps: u32,
}

impl SessionInfo {
    /// True if the session reports input injection.
    pub fn has_input(&self) -> bool {
        self.features & hx_ipc::link::validate::FEATURE_INPUT != 0
    }

    /// True if the session reports clipboard support.
    pub fn has_clipboard(&self) -> bool {
        self.features & hx_ipc::link::validate::FEATURE_CLIPBOARD != 0
    }

    /// True if the session reports file transfer support.
    pub fn has_file_transfer(&self) -> bool {
        self.features & hx_ipc::link::validate::FEATURE_FILE_TRANSFER != 0
    }

    /// True if the session reports RandR resize.
    pub fn has_resize(&self) -> bool {
        self.features & hx_ipc::link::validate::FEATURE_RESIZE != 0
    }
}

/// The picture format from `first_frame` on: what the client's `StreamInfo` (protocol.md 5.2) is
/// built from. `first_frame` is carried unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamFormat {
    /// The client epoch (the value of the `start` that produced it).
    pub epoch: u32,
    /// The codec (in the negotiated set).
    pub codec: VideoCodec,
    /// Coded width.
    pub width: u32,
    /// Coded height.
    pub height: u32,
    /// Frame rate.
    pub fps: u32,
    /// The first frame number this format applies to.
    pub first_frame: u32,
}

/// One validated video frame, ready to be forwarded.
///
/// The gateway builds the client's media stream from [`Frame::wire`]: those bytes are exactly
/// protocol.md section 6's 20-byte media header followed by the payload (channel byte `0x05`
/// first on QUIC; the identical bytes inside a `0x05` message on WebSocket). Nothing is
/// re-encoded or concatenated. The fields below are what the gateway needs besides that: the
/// frame number for acks and feedback, `KEY`/`RESYNC`, the capture time and the format.
#[derive(Debug, Clone)]
pub struct Frame {
    /// The validated header (`frame_number`, `flags`, `capture_timestamp_us`, `payload_len`).
    pub header: MediaHeader,
    /// The format in force for this frame.
    pub format: Arc<StreamFormat>,
    /// When the frame was completely read from the session.
    pub received_at: Instant,
    pub(crate) body: Bytes,
}

impl Frame {
    /// The frame number (wraps modulo 2^32; compare with serial arithmetic).
    pub fn number(&self) -> u32 {
        self.header.frame_number
    }

    /// `KEY`: decodes without earlier frames.
    pub fn is_key(&self) -> bool {
        self.header.is_key()
    }

    /// `RESYNC`: answers a start, an IDR request or a cancel.
    pub fn is_resync(&self) -> bool {
        self.header.is_resync()
    }

    /// Header and payload exactly as received: the body of the client's video stream.
    pub fn wire(&self) -> &Bytes {
        &self.body
    }

    /// The encoded payload.
    pub fn payload(&self) -> &[u8] {
        &self.body[MEDIA_HEADER_LEN..]
    }
}

/// A cursor update, validated like a client-supplied one (protocol.md 5.4).
#[derive(Debug, Clone, PartialEq)]
pub enum CursorUpdate {
    /// A new shape (RGBA, straight alpha, at most 256 x 256, hotspot inside the image).
    Shape(CursorShape),
    /// The latest position; coalesced, never queued.
    Position(CursorPosition),
}

/// A session `event` for logs and metrics; the text is sanitised and **must not** be forwarded
/// to a client (ipc.md 19.1 rule 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEvent {
    /// What happened.
    pub kind: pb::EventKind,
    /// Sanitised text, at most 256 bytes. Log only.
    pub message: String,
}

/// A chunk of an incoming transfer. Holding it counts against the unread limits of section 16;
/// the lane resumes when it is dropped, so a stalled consumer pauses `bulk` and nothing else.
#[derive(Debug)]
pub struct TransferChunk {
    /// The transfer id.
    pub id: u32,
    /// 1 to 65 536 bytes.
    pub data: Bytes,
    pub(crate) _credit: super::shared::Credit,
}

/// What the session does on the `bulk` lane.
#[derive(Debug)]
pub enum TransferEvent {
    /// The session wants to send something. Header and size are validated and within policy;
    /// the gateway opens a client stream (or refuses with
    /// [`LinkClient::abort_transfer`](super::LinkClient::abort_transfer)).
    Open {
        /// The session's (even) id.
        id: u32,
        /// Clipboard or file.
        channel: pb::TransferChannel,
        /// The validated header.
        header: TransferHeader,
    },
    /// Body bytes.
    Data(TransferChunk),
    /// The body is complete and its size matches the header.
    End {
        /// The transfer id.
        id: u32,
    },
    /// The transfer ended early: the session aborted it, or the gateway aborted it because the
    /// body did not match the header or the session broke a transfer limit.
    Aborted {
        /// The transfer id.
        id: u32,
        /// A protocol.md section 8 transfer code (`0x100` error, `0x101` rejected).
        code: u32,
        /// True for a transfer the gateway was sending.
        outgoing: bool,
    },
}

/// Everything the gateway core receives from a link, in one stream.
#[derive(Debug)]
pub enum LinkEvent {
    /// A video frame (bounded queue; see the module docs for what is dropped and how).
    Frame(Frame),
    /// A new stream format (informational: every frame carries its own).
    StreamFormat(StreamFormat),
    /// Cursor shape or position.
    Cursor(CursorUpdate),
    /// The session wants frames up to this number cancelled in transit. Already validated
    /// (not newer than the newest frame received, not more than 256 behind it); frames still
    /// queued in the link client have been dropped and reported already.
    CancelFrames {
        /// Cancel every undelivered frame numbered up to this one (serial arithmetic).
        up_to_frame: u32,
    },
    /// Interval statistics (at most 4 per second): logs, metrics, admin `Status`.
    Stats(pb::SessionStats),
    /// A session event (log only).
    Event(SessionEvent),
    /// A transfer started, delivered data, ended or was aborted.
    Transfer(TransferEvent),
    /// The session said goodbye; the link closes next.
    SessionGoodbye {
        /// A protocol.md section 8 close code.
        code: u32,
    },
    /// The link ended. Always the last event; see [`LinkClosed`].
    Closed(LinkClosed),
}

/// How a link ended, for the reconnect policy and the log (`docs/ipc.md` 19.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailureClass {
    /// The desktop could not be reached: connection refused (stale socket after a stop), a
    /// reset right after accept (the proxy could not reach the container side), a missing
    /// socket, no preamble answer or no `info` in time. Not a fault of the session; redial with
    /// backoff.
    Unavailable,
    /// The session speaks a different link major version: record `session_outdated` and ask
    /// privd for `InstallSession`.
    Outdated,
    /// The session offers nothing the gateway accepts (no common codec). Redialling will not
    /// help; like `Outdated` it needs an update.
    Incompatible,
    /// The session broke the contract (malformed frame or preamble, forbidden kind, oversize
    /// length, bad media header or bitstream, a byte on the silent direction, a frame-count or
    /// byte-budget overage, a second `info`). Counts as a fault.
    Violation,
    /// The link stopped working without the session misbehaving: it went silent (liveness), a
    /// write on `ctl` stalled, the connection broke while running. Counts as a fault.
    Fault,
    /// The session said goodbye. Unlike an owner's close this is the session's doing, so it
    /// counts as a fault and is redialled with backoff: a hostile session cannot make the
    /// gateway redial without throttle by saying goodbye in a loop (review M4). A real shutdown
    /// of the daemon costs one fault.
    SessionGoodbye,
    /// Closed on purpose by the owner of the link (a close, or every handle dropped).
    Closed,
}

impl FailureClass {
    /// True for the classes that count toward "5 faults in 10 minutes" (violations, faults and
    /// a session goodbye).
    pub fn is_fault(self) -> bool {
        matches!(
            self,
            FailureClass::Violation | FailureClass::Fault | FailureClass::SessionGoodbye
        )
    }
}

/// The final event of a link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkClosed {
    /// Classification for the reconnect policy.
    pub class: FailureClass,
    /// A short, sanitised reason for the log (never peer bytes beyond sanitised text).
    pub detail: String,
}

impl LinkClosed {
    pub(crate) fn new(class: FailureClass, detail: impl Into<String>) -> Self {
        Self {
            class,
            detail: hx_ipc::text::sanitize_text(&detail.into(), 200),
        }
    }
}

/// Why [`LinkClient::connect`](super::LinkClient::connect) failed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{class:?}: {detail}")]
pub struct ConnectError {
    /// Classification (the same classes as a running link).
    pub class: FailureClass,
    /// Sanitised reason for the log.
    pub detail: String,
    /// The session accepted the connection and closed it (or reset it) right after the
    /// preamble, as opposed to refusing it, not being there or staying silent. An honest session
    /// of another link major version does this (ipc.md 12.2); so does a proxy that cannot reach
    /// the container. [`ReconnectPolicy`](super::ReconnectPolicy) uses it to guess `Outdated`.
    pub closed_after_preamble: bool,
}

impl ConnectError {
    pub(crate) fn new(class: FailureClass, detail: impl Into<String>) -> Self {
        Self {
            class,
            detail: hx_ipc::text::sanitize_text(&detail.into(), 200),
            closed_after_preamble: false,
        }
    }

    pub(crate) fn after_preamble(mut self) -> Self {
        self.closed_after_preamble = true;
        self
    }
}

/// A command could not be queued.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SendError {
    /// The link is closed (see the [`LinkEvent::Closed`] event for why).
    #[error("the link is closed")]
    Closed,
    /// The message breaks a rule of the contract (a local bug: the gateway validates before
    /// sending).
    #[error("invalid message: {0}")]
    Invalid(String),
}

/// A transfer could not be started or continued.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TransferError {
    /// The link is closed.
    #[error("the link is closed")]
    Closed,
    /// Clipboard or file transfer is switched off by policy.
    #[error("this kind of transfer is disabled")]
    Disabled,
    /// Too many transfers in flight (4 per direction).
    #[error("too many concurrent transfers")]
    TooMany,
    /// The header breaks a rule (name, mime, size above the limit).
    #[error("invalid transfer header: {0}")]
    Invalid(String),
    /// The session aborted the transfer, a newer clipboard transfer replaced it, or the owner
    /// aborted it.
    #[error("the transfer was aborted")]
    Aborted,
    /// More bytes were written than the header announced, or `finish` came early.
    #[error("the body does not match the announced size")]
    SizeMismatch,
}

/// Counters of everything the link client ignored, dropped or refused: metrics and tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    /// `ctl` frames that decoded to no known variant.
    pub unknown_variants: u64,
    /// Frames not newer than the last accepted one.
    pub stale_frames: u64,
    /// Frames dropped by the `2 x max_fps` or 4 IDR per second limits.
    pub rate_limited_frames: u64,
    /// Frames dropped because they belonged to another epoch, or were discarded while waiting
    /// for a `KEY | RESYNC` frame.
    pub discarded_frames: u64,
    /// Frames evicted from the video pool because the consumer did not take them in time.
    pub evicted_frames: u64,
    /// `stream_format` messages dropped (rate or range).
    pub bad_stream_formats: u64,
    /// `cancel_frames` ignored (rate or range).
    pub ignored_cancels: u64,
    /// Cursor shapes dropped by the rate or byte limits.
    pub dropped_shapes: u64,
    /// `stats` and `event` messages dropped by their rate limits.
    pub dropped_stats_events: u64,
    /// `pong`s with a nonce the gateway did not send, or a repeat.
    pub unexpected_pongs: u64,
    /// Transfers refused (limit, policy) without ending the link.
    pub refused_transfers: u64,
    /// Events dropped because the consumer let the event queue fill.
    pub dropped_events: u64,
}
