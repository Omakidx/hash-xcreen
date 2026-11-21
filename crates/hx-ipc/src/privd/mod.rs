//! The `hx-privd` socket (`docs/ipc.md` Part 1, sections 3 to 8).
//!
//! * [`pb`]: the `hx.privd.v1` messages;
//! * [`PrivdPolicy`]: the framing limits (kind 1 message at most 65 536, kind 2 secret at most
//!   8 192, `length` counted with the kind byte);
//! * [`decode`] / [`encode_message`] / [`encode_secret`]: turn frames into [`Incoming`] values
//!   and back, validating before anything is returned;
//! * [`commands`]: per-command class, deadline, Admin-only arguments, and the syntax of shared
//!   argument types.
//!
//! Peer authentication (`SO_PEERCRED`) is in [`crate::peer`].

use std::time::Duration;

use bytes::BytesMut;
use prost::Message;
use zeroize::Zeroizing;

use crate::error::FrameError;
use crate::frame::{FramePolicy, RawFrame, encode_frame};
use crate::secret::{SECRET_HEADER_LEN, SecretFrame};

pub mod commands;
mod validate;

pub use commands::{
    CommandClass, CommandInfo, DEFAULT_DEADLINE_MS, admin_only_argument, command_info,
    gateway_denied, is_valid_desktop_id, is_valid_snapshot_name, is_valid_update_version,
    is_valid_username_syntax, snapshot_kind_of,
};
pub use validate::{check_secret_against_slot, validate_frame, validate_request};

/// Generated `hx.privd.v1` types.
pub use crate::generated_privd::hx::privd::v1 as pb;

/// Protocol version spoken on this socket (`Hello` / `HelloAck`).
pub const VERSION_MAJOR: u32 = 1;
/// Minor version.
pub const VERSION_MINOR: u32 = 0;

/// Kind byte of a protobuf [`pb::Frame`].
pub const KIND_MESSAGE: u8 = 1;
/// Kind byte of a raw secret frame.
pub const KIND_SECRET: u8 = 2;

/// Maximum `length` of a kind-1 frame (kind byte plus body).
pub const MAX_MESSAGE_LENGTH: u32 = 65_536;
/// Maximum `length` of a kind-2 frame.
pub const MAX_SECRET_LENGTH: u32 = 8_192;
/// Largest secret a kind-2 frame can carry: its limit minus the kind byte and the 9-byte header.
pub const MAX_SECRET_BYTES: usize = MAX_SECRET_LENGTH as usize - 1 - SECRET_HEADER_LEN;
/// Largest plain password (`hx_provision::Secrets::with_user_password` rules).
pub const MAX_PASSWORD_BYTES: usize = 1_024;
/// Exact length of a `MAC_INPUT` secret and of a `PepperVerify` expected verifier.
pub const MAC_LEN: usize = 32;
/// Length of `upload_nonce`.
pub const UPLOAD_NONCE_LEN: usize = 16;

/// Maximum length of `Hello.software`.
pub const MAX_SOFTWARE_LEN: usize = 64;
/// Maximum length of an `Error.message`.
pub const MAX_ERROR_MESSAGE_LEN: usize = 256;
/// Maximum length of a `Progress.step`.
pub const MAX_PROGRESS_STEP_LEN: usize = 128;
/// Maximum number of secret slots on one request.
pub const MAX_SECRET_SLOTS: usize = 4;

/// `Hello` must arrive within this long of accept.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// The body of a frame must arrive within this long of its header.
pub const BODY_TIMEOUT: Duration = Duration::from_secs(5);
/// An idle connection is closed after this long.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// A caller that will not read a `Response` within this long is disconnected.
pub const RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Which end of the socket a decoder or encoder serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// privd (or the gatewayd admin socket): receives requests, `Hello`, `Cancel` and secrets.
    Server,
    /// The caller: receives `HelloAck`, `Progress` and `Response` only.
    Client,
}

/// Framing limits for the privd socket and the admin socket (same framing, section 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivdPolicy {
    side: Side,
}

impl PrivdPolicy {
    /// The policy for the receiving `side`.
    pub fn new(side: Side) -> Self {
        Self { side }
    }

    /// The side this policy decodes for.
    pub fn side(&self) -> Side {
        self.side
    }
}

impl FramePolicy for PrivdPolicy {
    fn absolute_max_length(&self) -> u32 {
        match self.side {
            Side::Server => MAX_MESSAGE_LENGTH.max(MAX_SECRET_LENGTH),
            Side::Client => MAX_MESSAGE_LENGTH,
        }
    }

    fn max_length(&self, kind: u8) -> Result<u32, FrameError> {
        match (kind, self.side) {
            (KIND_MESSAGE, _) => Ok(MAX_MESSAGE_LENGTH),
            (KIND_SECRET, Side::Server) => Ok(MAX_SECRET_LENGTH),
            (KIND_SECRET, Side::Client) => Err(FrameError::KindNotAllowed(kind)),
            _ => Err(FrameError::UnknownKind(kind)),
        }
    }

    fn is_sensitive(&self, kind: u8) -> bool {
        kind == KIND_SECRET
    }
}

/// A decoded, validated incoming frame.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // one value per received frame; boxing would only add an allocation
pub enum Incoming {
    /// A kind-1 protobuf frame.
    Message(pb::Frame),
    /// A kind-2 raw secret.
    Secret(SecretFrame),
}

/// Decodes and validates one frame received on `side`.
///
/// For a kind-1 frame: the protobuf must decode, exactly one variant must be set, the variant
/// must be one that may travel towards `side`, and the contract's field rules must hold
/// ([`validate_frame`]). For a kind-2 frame the body is parsed and the input buffer zeroized.
pub fn decode(raw: RawFrame, side: Side) -> Result<Incoming, FrameError> {
    match raw.kind {
        KIND_MESSAGE => {
            // Bound repeated-field counts before prost allocates an element per occurrence.
            crate::prescan::check_privd_frame(&raw.body, MAX_SECRET_SLOTS)?;
            let frame = pb::Frame::decode(raw.body.as_ref())
                .map_err(|e| FrameError::Decode(e.to_string()))?;
            validate_frame(&frame, side)?;
            Ok(Incoming::Message(frame))
        }
        KIND_SECRET if side == Side::Server => {
            Ok(Incoming::Secret(SecretFrame::from_body(raw.body)?))
        }
        KIND_SECRET => Err(FrameError::KindNotAllowed(KIND_SECRET)),
        k => Err(FrameError::UnknownKind(k)),
    }
}

/// Encodes a kind-1 frame for the peer on `to`, after checking it would be accepted there.
pub fn encode_message(frame: &pb::Frame, to: Side) -> Result<Vec<u8>, FrameError> {
    validate_frame(frame, to)?;
    let body = frame.encode_to_vec();
    encode_frame(KIND_MESSAGE, &body, MAX_MESSAGE_LENGTH)
}

/// Encodes a kind-2 secret frame (caller to privd). The result is zeroized on drop.
pub fn encode_secret(
    request_id: u64,
    slot: u8,
    secret: &[u8],
) -> Result<Zeroizing<Vec<u8>>, FrameError> {
    if secret.is_empty() || secret.len() > MAX_SECRET_BYTES {
        return Err(FrameError::Invalid("secret length"));
    }
    let body = SecretFrame::encode_body(request_id, slot, secret);
    let framed = encode_frame(KIND_SECRET, &body, MAX_SECRET_LENGTH)?;
    Ok(Zeroizing::new(framed))
}

/// A kind-1 frame's protobuf body as a `BytesMut`, for tests and fuzz targets that build a
/// [`RawFrame`] by hand.
pub fn message_raw_frame(frame: &pb::Frame) -> RawFrame {
    RawFrame {
        kind: KIND_MESSAGE,
        body: BytesMut::from(frame.encode_to_vec().as_slice()),
    }
}
