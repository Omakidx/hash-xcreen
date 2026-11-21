//! Error types shared by the framing layer. None of them carries peer-controlled bulk data.

use std::io;

use thiserror::Error;

/// Why a frame was rejected by [`crate::frame::Decoder`] or refused by an encoder.
///
/// On a receiver every variant is a **violation**: the connection is closed (privd and the
/// admin socket, `docs/ipc.md` section 4) or the link is dropped (section 19.2).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FrameError {
    /// `length` is zero; it must at least count the kind byte.
    #[error("zero frame length")]
    ZeroLength,
    /// `length` above the limit for this lane, direction or kind.
    #[error("frame length {length} exceeds the limit {max}")]
    TooLong {
        /// The announced length.
        length: u32,
        /// The limit that applied.
        max: u32,
    },
    /// A kind byte this framing does not define.
    #[error("unknown frame kind {0:#04x}")]
    UnknownKind(u8),
    /// A defined kind that is not valid on this lane or in this direction.
    #[error("frame kind {0:#04x} is not valid here")]
    KindNotAllowed(u8),
    /// A byte arrived on a lane direction that must stay silent (`media` gateway to session).
    #[error("data received in a direction that carries none")]
    ForbiddenDirection,
    /// The stream ended inside a frame.
    #[error("stream ended inside a frame")]
    Truncated,
    /// A body whose layout is wrong for its kind (wrong fixed size, short header, ...).
    #[error("malformed {0} frame body")]
    BadBody(&'static str),
    /// A protobuf body that failed to decode.
    #[error("protobuf body failed to decode: {0}")]
    Decode(String),
    /// A decoded message that breaks a rule of the contract (`what` names it).
    #[error("invalid message: {0}")]
    Invalid(&'static str),
    /// A shared `hx.v1` message or media header failed `hx-proto`'s validation (the text names the
    /// rule, never carries peer data).
    #[error("client-protocol rule violated: {0}")]
    Proto(String),
    /// The decoder already reported an error and must not be used again.
    #[error("decoder is poisoned by an earlier error")]
    Poisoned,
}

/// A control message (for example `SCM_RIGHTS`) or `MSG_CTRUNC` on a socket that must carry
/// only bytes (`docs/ipc.md` section 3, section 19.1 rule 8). Always a violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("ancillary data (file descriptors or credentials) received on a data-only socket")]
pub struct AncillaryData;

/// Error of [`crate::frame::Decoder::read_from`].
#[derive(Debug, Error)]
pub enum ReadError {
    /// The peer broke the framing.
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// A control message arrived with the data.
    #[error(transparent)]
    Ancillary(#[from] AncillaryData),
    /// The transport failed (including read timeouts).
    #[error("io: {0}")]
    Io(io::Error),
}

impl ReadError {
    /// True for peer misbehaviour (framing or ancillary data), false for transport errors.
    pub fn is_violation(&self) -> bool {
        !matches!(self, ReadError::Io(_))
    }
}

impl From<io::Error> for ReadError {
    fn from(e: io::Error) -> Self {
        match e
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<AncillaryData>())
        {
            Some(a) => ReadError::Ancillary(*a),
            None => ReadError::Io(e),
        }
    }
}
