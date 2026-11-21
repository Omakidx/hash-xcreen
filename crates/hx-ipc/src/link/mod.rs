//! The session link between `hx-gatewayd` and `hx-session` (`docs/ipc.md` Part 2).
//!
//! * [`pb`]: the `hx.link.v1` messages (control lane and bulk lane);
//! * [`preamble`]: the 8-byte preamble and 16-byte `link_id` of every lane, version negotiation;
//! * [`LinkPolicy`]: which frame kinds and lengths a receiver accepts on each lane, in each
//!   direction (a byte on `media` gateway to session is a violation);
//! * [`frames`]: typed parsing and encoding of every lane frame;
//! * [`validate`]: the message-level limits of section 13 and the sanitiser for session text;
//! * [`budget`]: the byte budgets and message rates of sections 13 and 17 as sans-I/O state.
//!
//! Everything here is pure. Link input is hostile (section 10): decoders return values, never
//! panic, and check every length before allocating.

use crate::error::FrameError;
use crate::frame::FramePolicy;

pub mod budget;
pub mod frames;
pub mod preamble;
pub mod validate;

/// Generated `hx.link.v1` types. The shared `hx.v1` types they use are `hx_proto::pb`'s.
pub use crate::generated_link::hx::link::v1 as pb;

/// Link protocol version spoken by this crate: `1.0`.
pub const LINK_MAJOR: u8 = 1;
/// Minor version.
pub const LINK_MINOR: u8 = 0;

/// Kind byte on `ctl`, session to gateway: a protobuf `SessionToGateway`.
pub const KIND_SESSION_TO_GATEWAY: u8 = 0x01;
/// Kind byte on `ctl`, gateway to session: a protobuf `GatewayToSession`.
pub const KIND_GATEWAY_TO_SESSION: u8 = 0x02;
/// Kind byte on `media`: a video frame (20-byte media header plus payload).
pub const KIND_VIDEO: u8 = 0x10;
/// Kind byte on `media`: an audio packet (reserved).
pub const KIND_AUDIO: u8 = 0x11;
/// Kind byte on `bulk`: a protobuf `TransferOpen`.
pub const KIND_TRANSFER_OPEN: u8 = 0x20;
/// Kind byte on `bulk`: transfer data, `id` u32 plus raw bytes.
pub const KIND_TRANSFER_DATA: u8 = 0x21;
/// Kind byte on `bulk`: end of a transfer, `id` u32.
pub const KIND_TRANSFER_END: u8 = 0x22;
/// Kind byte on `bulk`: abort of a transfer, `id` u32 plus `code` u32.
pub const KIND_TRANSFER_ABORT: u8 = 0x23;

/// Maximum `length` of `ctl` session to gateway: the 327 680-byte cursor limit plus protobuf
/// overhead (section 13: 327 685, including the kind byte).
pub const MAX_CTL_S2G_LENGTH: u32 = 327_685;
/// Maximum `length` of `ctl` gateway to session.
pub const MAX_CTL_G2S_LENGTH: u32 = 16_384;
/// Maximum `length` of an audio frame (reserved).
pub const MAX_AUDIO_LENGTH: u32 = 1_110;
/// Maximum `length` of `TransferOpen`.
pub const MAX_TRANSFER_OPEN_LENGTH: u32 = 4_200;
/// Largest transfer data chunk.
pub const MAX_TRANSFER_CHUNK: usize = 65_536;
/// Maximum `length` of a transfer data frame: kind byte, `id` and a full chunk.
pub const MAX_TRANSFER_DATA_LENGTH: u32 = 65_541;
/// Exact `length` of a transfer end frame.
pub const TRANSFER_END_LENGTH: u32 = 5;
/// Exact `length` of a transfer abort frame.
pub const TRANSFER_ABORT_LENGTH: u32 = 9;
/// Bytes of the media header at the start of a video frame body.
pub const MEDIA_HEADER_LEN: usize = 20;
/// Bytes a video frame adds to its payload: media header plus kind byte (`max length` is
/// `max_frame_bytes + 21`).
pub const VIDEO_OVERHEAD: u32 = MEDIA_HEADER_LEN as u32 + 1;
/// Default `max_frame_bytes`: 4 MiB.
pub const DEFAULT_MAX_FRAME_BYTES: u32 = 4 * 1024 * 1024;
/// Largest configurable `max_frame_bytes`: the protocol's 16 MiB video payload limit.
pub const MAX_FRAME_BYTES_CEILING: u32 = 16 * 1024 * 1024;

/// One of the three unix connections of a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Lane {
    /// Control: handshake, input, cursor, feedback, events (lane id 1).
    Ctl = 1,
    /// Media: video and audio, session to gateway (lane id 2).
    Media = 2,
    /// Bulk: clipboard and file transfers, both directions (lane id 3).
    Bulk = 3,
}

impl Lane {
    /// The lane id of the preamble.
    pub fn id(self) -> u8 {
        self as u8
    }

    /// Parses a lane id; `None` outside 1 to 3.
    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            1 => Some(Lane::Ctl),
            2 => Some(Lane::Media),
            3 => Some(Lane::Bulk),
            _ => None,
        }
    }
}

/// Which end of the link a piece of code is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// `hx-gatewayd`: dials, opens `ctl` first, treats everything it reads as hostile.
    Gateway,
    /// `hx-session`: listens, accepts one link at a time.
    Session,
}

impl Role {
    /// The other end.
    pub fn peer(self) -> Role {
        match self {
            Role::Gateway => Role::Session,
            Role::Session => Role::Gateway,
        }
    }
}

/// What the **receiving** end of one lane accepts (`docs/ipc.md` section 13).
///
/// | Lane | Gateway receives | Session receives |
/// |---|---|---|
/// | `ctl` | `0x01` up to 327 685 | `0x02` up to 16 384 |
/// | `media` | `0x10` up to `max_frame_bytes + 21`, `0x11` up to 1 110 | nothing: any byte is a violation |
/// | `bulk` | `0x20` to `0x23` | `0x20` to `0x23` |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkPolicy {
    receiver: Role,
    lane: Lane,
    max_frame_bytes: u32,
}

impl LinkPolicy {
    /// The policy of `receiver` reading `lane`, with the default 4 MiB `max_frame_bytes`.
    pub fn new(receiver: Role, lane: Lane) -> Self {
        Self {
            receiver,
            lane,
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        }
    }

    /// Sets `max_frame_bytes` (1 to 16 MiB). It bounds a video payload: the largest `media`
    /// frame is `max_frame_bytes + 21`.
    pub fn with_max_frame_bytes(mut self, max_frame_bytes: u32) -> Result<Self, FrameError> {
        if !(1..=MAX_FRAME_BYTES_CEILING).contains(&max_frame_bytes) {
            return Err(FrameError::Invalid("max_frame_bytes"));
        }
        self.max_frame_bytes = max_frame_bytes;
        Ok(self)
    }

    /// The configured `max_frame_bytes`.
    pub fn max_frame_bytes(&self) -> u32 {
        self.max_frame_bytes
    }

    /// The lane.
    pub fn lane(&self) -> Lane {
        self.lane
    }

    /// The receiving role.
    pub fn receiver(&self) -> Role {
        self.receiver
    }

    /// The largest `length` that `kind` may have when it is sent **to** `receiver` on `lane`.
    /// Used by encoders so that the sender refuses what the receiver would drop.
    pub fn limit_for(&self, kind: u8) -> Result<u32, FrameError> {
        self.max_length(kind)
    }

    fn video_max(&self) -> u32 {
        self.max_frame_bytes + VIDEO_OVERHEAD
    }
}

fn is_defined_kind(kind: u8) -> bool {
    matches!(
        kind,
        KIND_SESSION_TO_GATEWAY
            | KIND_GATEWAY_TO_SESSION
            | KIND_VIDEO
            | KIND_AUDIO
            | KIND_TRANSFER_OPEN
            | KIND_TRANSFER_DATA
            | KIND_TRANSFER_END
            | KIND_TRANSFER_ABORT
    )
}

impl FramePolicy for LinkPolicy {
    fn absolute_max_length(&self) -> u32 {
        match (self.lane, self.receiver) {
            (Lane::Ctl, Role::Gateway) => MAX_CTL_S2G_LENGTH,
            (Lane::Ctl, Role::Session) => MAX_CTL_G2S_LENGTH,
            (Lane::Media, Role::Gateway) => self.video_max().max(MAX_AUDIO_LENGTH),
            // The gateway to session direction of `media` is unused.
            (Lane::Media, Role::Session) => 0,
            (Lane::Bulk, _) => MAX_TRANSFER_DATA_LENGTH.max(MAX_TRANSFER_OPEN_LENGTH),
        }
    }

    fn max_length(&self, kind: u8) -> Result<u32, FrameError> {
        let limit = match (self.lane, self.receiver, kind) {
            (Lane::Ctl, Role::Gateway, KIND_SESSION_TO_GATEWAY) => MAX_CTL_S2G_LENGTH,
            (Lane::Ctl, Role::Session, KIND_GATEWAY_TO_SESSION) => MAX_CTL_G2S_LENGTH,
            (Lane::Media, Role::Gateway, KIND_VIDEO) => self.video_max(),
            (Lane::Media, Role::Gateway, KIND_AUDIO) => MAX_AUDIO_LENGTH,
            (Lane::Bulk, _, KIND_TRANSFER_OPEN) => MAX_TRANSFER_OPEN_LENGTH,
            (Lane::Bulk, _, KIND_TRANSFER_DATA) => MAX_TRANSFER_DATA_LENGTH,
            (Lane::Bulk, _, KIND_TRANSFER_END) => TRANSFER_END_LENGTH,
            (Lane::Bulk, _, KIND_TRANSFER_ABORT) => TRANSFER_ABORT_LENGTH,
            _ if is_defined_kind(kind) => return Err(FrameError::KindNotAllowed(kind)),
            _ => return Err(FrameError::UnknownKind(kind)),
        };
        Ok(limit)
    }
}
