//! Typed link frames: parsing what a receiver got and encoding what a sender writes
//! (`docs/ipc.md` sections 13 to 16).
//!
//! [`parse`] takes a [`RawFrame`] already accepted by a [`LinkPolicy`] decoder (so its kind and
//! length are valid for the lane and direction) and checks the body layout: fixed sizes, the
//! media header, `payload_len == length - 21`, transfer ids and headers. A failure is a
//! violation. An unknown protobuf variant is **not** a violation: it parses to
//! [`LinkFrame::UnknownVariant`] and is to be ignored and counted (section 19.1, rule 5).

use bytes::{Bytes, BytesMut};
use hx_proto::media::MediaHeader;
use hx_proto::message::Wire;
use prost::Message;

use super::validate::{validate_gateway_message, validate_session_message, validate_transfer_open};
use super::{
    KIND_AUDIO, KIND_GATEWAY_TO_SESSION, KIND_SESSION_TO_GATEWAY, KIND_TRANSFER_ABORT,
    KIND_TRANSFER_DATA, KIND_TRANSFER_END, KIND_TRANSFER_OPEN, KIND_VIDEO, Lane, LinkPolicy,
    MAX_TRANSFER_CHUNK, MEDIA_HEADER_LEN, Role, TRANSFER_ABORT_LENGTH, TRANSFER_END_LENGTH, pb,
};
use crate::error::FrameError;
use crate::frame::{PREFIX_LEN, RawFrame, encode_frame, encode_prefix};

/// A video frame body: the media header already validated, and the whole body (header followed
/// by payload) kept as one `Bytes` so the gateway can forward it unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoFrame {
    /// The decoded 20-byte header.
    pub header: MediaHeader,
    /// Header plus payload, exactly as received (`length - 1` bytes).
    pub body: Bytes,
}

impl VideoFrame {
    /// The encoded payload (after the 20-byte header).
    pub fn payload(&self) -> &[u8] {
        &self.body[MEDIA_HEADER_LEN..]
    }
}

/// A reserved audio packet (`kind 0x11`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioFrame {
    /// Sequence number.
    pub seq: u32,
    /// Timestamp.
    pub timestamp: u32,
    /// One Opus packet, 1 to 1 100 bytes.
    pub packet: Bytes,
}

/// A parsed, layout-checked link frame.
#[derive(Debug, Clone, PartialEq)]
pub enum LinkFrame {
    /// `ctl`, received by the gateway.
    FromSession(pb::SessionToGateway),
    /// `ctl`, received by the session.
    FromGateway(pb::GatewayToSession),
    /// A `ctl` frame whose protobuf decoded but carries no variant this version knows: ignore it
    /// and count it.
    UnknownVariant,
    /// `media`: video.
    Video(VideoFrame),
    /// `media`: audio (reserved).
    Audio(AudioFrame),
    /// `bulk`: a transfer starts.
    TransferOpen(pb::TransferOpen),
    /// `bulk`: 1 to 65 536 bytes of a transfer.
    TransferData {
        /// Transfer id.
        id: u32,
        /// The chunk.
        data: Bytes,
    },
    /// `bulk`: end of a transfer.
    TransferEnd {
        /// Transfer id.
        id: u32,
    },
    /// `bulk`: abort of a transfer.
    TransferAbort {
        /// Transfer id.
        id: u32,
        /// A protocol.md section 8 transfer code.
        code: u32,
    },
}

fn proto_err(e: impl std::fmt::Display) -> FrameError {
    FrameError::Proto(e.to_string())
}

fn read_u32(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn transfer_id(body: &[u8], what: &'static str) -> Result<u32, FrameError> {
    match read_u32(body, 0) {
        Some(id) if id != 0 => Ok(id),
        _ => Err(FrameError::BadBody(what)),
    }
}

/// Parses one frame that `policy`'s decoder accepted, and applies the message-level rules that
/// need no connection state.
///
/// `max_file_bytes` is the configured file-size limit applied to `TransferOpen` headers.
pub fn parse(
    policy: &LinkPolicy,
    raw: RawFrame,
    max_file_bytes: u64,
) -> Result<LinkFrame, FrameError> {
    let RawFrame { kind, body } = raw;
    match kind {
        KIND_SESSION_TO_GATEWAY => {
            let msg = pb::SessionToGateway::decode(body.as_ref())
                .map_err(|e| FrameError::Decode(e.to_string()))?;
            if msg.message.is_none() {
                return Ok(LinkFrame::UnknownVariant);
            }
            validate_session_message(&msg)?;
            Ok(LinkFrame::FromSession(msg))
        }
        KIND_GATEWAY_TO_SESSION => {
            let msg = pb::GatewayToSession::decode(body.as_ref())
                .map_err(|e| FrameError::Decode(e.to_string()))?;
            if msg.message.is_none() {
                return Ok(LinkFrame::UnknownVariant);
            }
            validate_gateway_message(&msg)?;
            Ok(LinkFrame::FromGateway(msg))
        }
        KIND_VIDEO => parse_video(policy, body.freeze()),
        KIND_AUDIO => {
            // seq u32 + timestamp u32 + packet 1..=1100
            let b = body.freeze();
            if !(9..=8 + 1_100).contains(&b.len()) {
                return Err(FrameError::BadBody("audio"));
            }
            let seq = read_u32(&b, 0).ok_or(FrameError::BadBody("audio"))?;
            let timestamp = read_u32(&b, 4).ok_or(FrameError::BadBody("audio"))?;
            Ok(LinkFrame::Audio(AudioFrame {
                seq,
                timestamp,
                packet: b.slice(8..),
            }))
        }
        KIND_TRANSFER_OPEN => {
            let open = pb::TransferOpen::decode(body.as_ref())
                .map_err(|e| FrameError::Decode(e.to_string()))?;
            // The sender is the peer of the receiver: ids are odd from the gateway, even from
            // the session.
            validate_transfer_open(&open, policy.receiver().peer(), max_file_bytes)?;
            Ok(LinkFrame::TransferOpen(open))
        }
        KIND_TRANSFER_DATA => {
            let b = body.freeze();
            let id = transfer_id(&b, "transfer data")?;
            let data = b.slice(4..);
            if data.is_empty() || data.len() > MAX_TRANSFER_CHUNK {
                return Err(FrameError::BadBody("transfer data"));
            }
            Ok(LinkFrame::TransferData { id, data })
        }
        KIND_TRANSFER_END => {
            if body.len() as u32 + 1 != TRANSFER_END_LENGTH {
                return Err(FrameError::BadBody("transfer end"));
            }
            Ok(LinkFrame::TransferEnd {
                id: transfer_id(&body, "transfer end")?,
            })
        }
        KIND_TRANSFER_ABORT => {
            if body.len() as u32 + 1 != TRANSFER_ABORT_LENGTH {
                return Err(FrameError::BadBody("transfer abort"));
            }
            let id = transfer_id(&body, "transfer abort")?;
            let code = read_u32(&body, 4).ok_or(FrameError::BadBody("transfer abort"))?;
            Ok(LinkFrame::TransferAbort { id, code })
        }
        k => Err(FrameError::UnknownKind(k)),
    }
}

/// A video body is exactly the 20-byte media header and `payload_len` payload bytes
/// (`payload_len == length - 21`, section 15.1).
fn parse_video(policy: &LinkPolicy, body: Bytes) -> Result<LinkFrame, FrameError> {
    let head = body
        .get(..MEDIA_HEADER_LEN)
        .ok_or(FrameError::BadBody("video"))?;
    let header = MediaHeader::decode(head).map_err(proto_err)?;
    let payload = body.len() - MEDIA_HEADER_LEN;
    if header.payload_len as usize != payload {
        return Err(FrameError::BadBody("video payload_len"));
    }
    if header.payload_len > policy.max_frame_bytes() {
        return Err(FrameError::TooLong {
            length: header.payload_len,
            max: policy.max_frame_bytes(),
        });
    }
    Ok(LinkFrame::Video(VideoFrame { header, body }))
}

// ----- encoding -----

/// A receiver's policy for the lane a message is written to, or an error if that lane never
/// carries it. The sender checks against what the peer would accept.
fn peer_policy(sender: Role, lane: Lane) -> LinkPolicy {
    LinkPolicy::new(sender.peer(), lane)
}

/// Encodes a `ctl` message from the session to the gateway (one whole frame).
pub fn encode_session_message(msg: &pb::SessionToGateway) -> Result<Vec<u8>, FrameError> {
    validate_session_message(msg)?;
    let limit = peer_policy(Role::Session, Lane::Ctl).limit_for(KIND_SESSION_TO_GATEWAY)?;
    encode_frame(KIND_SESSION_TO_GATEWAY, &msg.encode_to_vec(), limit)
}

/// Encodes a `ctl` message from the gateway to the session (one whole frame, at most 16 384
/// bytes).
pub fn encode_gateway_message(msg: &pb::GatewayToSession) -> Result<Vec<u8>, FrameError> {
    validate_gateway_message(msg)?;
    let limit = peer_policy(Role::Gateway, Lane::Ctl).limit_for(KIND_GATEWAY_TO_SESSION)?;
    encode_frame(KIND_GATEWAY_TO_SESSION, &msg.encode_to_vec(), limit)
}

/// The 25 bytes that precede the payload of a video frame: frame prefix (5) and media header
/// (20). Write these, then the payload, so the payload is never copied. `max_frame_bytes` is the
/// receiver's configured limit.
pub fn encode_video_prefix(
    header: &MediaHeader,
    max_frame_bytes: u32,
) -> Result<[u8; PREFIX_LEN + MEDIA_HEADER_LEN], FrameError> {
    let policy = peer_policy(Role::Session, Lane::Media).with_max_frame_bytes(max_frame_bytes)?;
    if header.payload_len > max_frame_bytes {
        return Err(FrameError::TooLong {
            length: header.payload_len,
            max: max_frame_bytes,
        });
    }
    let body_len = MEDIA_HEADER_LEN + header.payload_len as usize;
    let prefix = encode_prefix(KIND_VIDEO, body_len, policy.limit_for(KIND_VIDEO)?)?;
    let h = header.encode().map_err(proto_err)?;
    let mut out = [0; PREFIX_LEN + MEDIA_HEADER_LEN];
    out[..PREFIX_LEN].copy_from_slice(&prefix);
    out[PREFIX_LEN..].copy_from_slice(&h);
    Ok(out)
}

/// Encodes a whole audio frame (reserved).
pub fn encode_audio(seq: u32, timestamp: u32, packet: &[u8]) -> Result<Vec<u8>, FrameError> {
    if packet.is_empty() || packet.len() > 1_100 {
        return Err(FrameError::BadBody("audio"));
    }
    let mut body = Vec::with_capacity(8 + packet.len());
    body.extend_from_slice(&seq.to_le_bytes());
    body.extend_from_slice(&timestamp.to_le_bytes());
    body.extend_from_slice(packet);
    let limit = peer_policy(Role::Session, Lane::Media).limit_for(KIND_AUDIO)?;
    encode_frame(KIND_AUDIO, &body, limit)
}

/// Encodes a `TransferOpen` frame sent by `sender`.
pub fn encode_transfer_open(
    sender: Role,
    open: &pb::TransferOpen,
    max_file_bytes: u64,
) -> Result<Vec<u8>, FrameError> {
    validate_transfer_open(open, sender, max_file_bytes)?;
    let limit = peer_policy(sender, Lane::Bulk).limit_for(KIND_TRANSFER_OPEN)?;
    encode_frame(KIND_TRANSFER_OPEN, &open.encode_to_vec(), limit)
}

/// The 9 bytes that precede the data of a transfer data frame (prefix and `id`); write them,
/// then `len` bytes of data.
pub fn encode_transfer_data_prefix(
    id: u32,
    len: usize,
) -> Result<[u8; PREFIX_LEN + 4], FrameError> {
    if id == 0 || len == 0 || len > MAX_TRANSFER_CHUNK {
        return Err(FrameError::BadBody("transfer data"));
    }
    let prefix = encode_prefix(KIND_TRANSFER_DATA, 4 + len, super::MAX_TRANSFER_DATA_LENGTH)?;
    let mut out = [0; PREFIX_LEN + 4];
    out[..PREFIX_LEN].copy_from_slice(&prefix);
    out[PREFIX_LEN..].copy_from_slice(&id.to_le_bytes());
    Ok(out)
}

/// Encodes a transfer end frame.
pub fn encode_transfer_end(id: u32) -> Result<Vec<u8>, FrameError> {
    if id == 0 {
        return Err(FrameError::BadBody("transfer end"));
    }
    encode_frame(KIND_TRANSFER_END, &id.to_le_bytes(), TRANSFER_END_LENGTH)
}

/// Encodes a transfer abort frame.
pub fn encode_transfer_abort(id: u32, code: u32) -> Result<Vec<u8>, FrameError> {
    if id == 0 {
        return Err(FrameError::BadBody("transfer abort"));
    }
    let mut body = [0u8; 8];
    body[..4].copy_from_slice(&id.to_le_bytes());
    body[4..].copy_from_slice(&code.to_le_bytes());
    encode_frame(KIND_TRANSFER_ABORT, &body, TRANSFER_ABORT_LENGTH)
}

/// Re-exported so callers can build a [`RawFrame`] in tests and fuzz targets.
pub fn raw(kind: u8, body: &[u8]) -> RawFrame {
    RawFrame {
        kind,
        body: BytesMut::from(body),
    }
}

/// Validates a shared client-protocol message through `hx-proto`'s rules.
pub(crate) fn wire_validate<M: Wire>(m: &M) -> Result<(), FrameError> {
    m.validate().map_err(proto_err)
}
