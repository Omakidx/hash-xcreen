//! Mouse-motion and audio datagram formats (protocol §7).
//!
//! A datagram, and equally a WebSocket message of the same channel, is the channel id byte
//! followed by the body. [`decode_datagram`] takes the whole thing, channel byte included.

use bytes::Bytes;

use crate::{channel::ChannelId, error::ProtoError, order::serial_gt};

/// Size of an encoded mouse-motion datagram including the channel byte.
pub const MOUSE_MOVE_LEN: usize = 14;
/// Size of the audio datagram header including the channel byte.
pub const AUDIO_HEADER_LEN: usize = 9;
/// Largest Opus packet in an audio datagram.
pub const MAX_AUDIO_PAYLOAD: usize = 1_100;
/// Mouse flag: `x`, `y` are relative deltas.
pub const MOUSE_FLAG_RELATIVE: u8 = 1;

/// A mouse-motion datagram (client to server).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MouseMove {
    /// `x`, `y` are deltas instead of absolute remote pixel coordinates.
    pub relative: bool,
    /// Sequence number, wrapping, serial arithmetic.
    pub seq: u32,
    /// X coordinate or delta.
    pub x: i32,
    /// Y coordinate or delta.
    pub y: i32,
}

impl MouseMove {
    /// Encode, channel byte first.
    pub fn encode(&self) -> [u8; MOUSE_MOVE_LEN] {
        let mut b = [0u8; MOUSE_MOVE_LEN];
        b[0] = ChannelId::MouseMove as u8;
        b[1] = if self.relative {
            MOUSE_FLAG_RELATIVE
        } else {
            0
        };
        b[2..6].copy_from_slice(&self.seq.to_le_bytes());
        b[6..10].copy_from_slice(&self.x.to_le_bytes());
        b[10..14].copy_from_slice(&self.y.to_le_bytes());
        b
    }

    fn decode_body(buf: &[u8]) -> Result<Self, ProtoError> {
        let b: &[u8; MOUSE_MOVE_LEN] = match buf.len() {
            n if n < MOUSE_MOVE_LEN => {
                return Err(ProtoError::Truncated {
                    need: MOUSE_MOVE_LEN,
                    have: n,
                });
            }
            n if n > MOUSE_MOVE_LEN => {
                return Err(ProtoError::TrailingBytes {
                    extra: n - MOUSE_MOVE_LEN,
                });
            }
            _ => buf.try_into().map_err(|_| ProtoError::Truncated {
                need: MOUSE_MOVE_LEN,
                have: buf.len(),
            })?,
        };
        if b[1] & !MOUSE_FLAG_RELATIVE != 0 {
            return Err(ProtoError::ReservedFlags(u16::from(b[1])));
        }
        Ok(Self {
            relative: b[1] & MOUSE_FLAG_RELATIVE != 0,
            seq: u32::from_le_bytes([b[2], b[3], b[4], b[5]]),
            x: i32::from_le_bytes([b[6], b[7], b[8], b[9]]),
            y: i32::from_le_bytes([b[10], b[11], b[12], b[13]]),
        })
    }
}

/// An audio datagram (server to client): one Opus packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioPacket {
    /// Packet sequence number, wrapping.
    pub seq: u32,
    /// Opus sample clock (48 kHz) of the first sample, wrapping.
    pub timestamp: u32,
    /// The Opus packet, 1..=[`MAX_AUDIO_PAYLOAD`] bytes.
    pub payload: Bytes,
}

impl AudioPacket {
    /// Encode, channel byte first. Fails for an empty or oversized payload.
    pub fn encode(&self) -> Result<Bytes, ProtoError> {
        if self.payload.is_empty() {
            return Err(ProtoError::Empty {
                what: "audio payload",
            });
        }
        if self.payload.len() > MAX_AUDIO_PAYLOAD {
            return Err(ProtoError::TooLarge {
                what: "audio payload",
                len: self.payload.len(),
                max: MAX_AUDIO_PAYLOAD,
            });
        }
        let mut v = Vec::with_capacity(AUDIO_HEADER_LEN + self.payload.len());
        v.push(ChannelId::Audio as u8);
        v.extend_from_slice(&self.seq.to_le_bytes());
        v.extend_from_slice(&self.timestamp.to_le_bytes());
        v.extend_from_slice(&self.payload);
        Ok(Bytes::from(v))
    }

    fn decode_body(buf: &[u8]) -> Result<Self, ProtoError> {
        let (head, payload) =
            buf.split_at_checked(AUDIO_HEADER_LEN)
                .ok_or(ProtoError::Truncated {
                    need: AUDIO_HEADER_LEN + 1,
                    have: buf.len(),
                })?;
        if payload.is_empty() {
            return Err(ProtoError::Empty {
                what: "audio payload",
            });
        }
        if payload.len() > MAX_AUDIO_PAYLOAD {
            return Err(ProtoError::TooLarge {
                what: "audio payload",
                len: payload.len(),
                max: MAX_AUDIO_PAYLOAD,
            });
        }
        Ok(Self {
            seq: u32::from_le_bytes([head[1], head[2], head[3], head[4]]),
            timestamp: u32::from_le_bytes([head[5], head[6], head[7], head[8]]),
            payload: Bytes::copy_from_slice(payload),
        })
    }
}

/// A decoded datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Datagram {
    /// Mouse motion.
    MouseMove(MouseMove),
    /// Audio packet.
    Audio(AudioPacket),
}

/// Decode a datagram (or WebSocket message of a datagram channel), channel byte included.
/// Total: never panics. Channels that are not datagram channels are an error.
pub fn decode_datagram(buf: &[u8]) -> Result<Datagram, ProtoError> {
    let first = *buf
        .first()
        .ok_or(ProtoError::Truncated { need: 1, have: 0 })?;
    match ChannelId::from_u8(first)? {
        ChannelId::MouseMove => MouseMove::decode_body(buf).map(Datagram::MouseMove),
        ChannelId::Audio => AudioPacket::decode_body(buf).map(Datagram::Audio),
        _ => Err(ProtoError::Invalid {
            field: "datagram",
            reason: "channel is not a datagram channel",
        }),
    }
}

/// Coalesced pointer motion ready for the consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MouseUpdate {
    /// Latest absolute position, if any arrived since the last [`MouseCoalescer::take`].
    pub absolute: Option<(i32, i32)>,
    /// Sum of relative deltas that arrived since the last take.
    pub relative: Option<(i32, i32)>,
}

/// Latest-wins merging of mouse datagrams (protocol §7.1).
#[derive(Debug, Default)]
pub struct MouseCoalescer {
    newest_seq: Option<u32>,
    pending: MouseUpdate,
    dropped_stale: u64,
}

impl MouseCoalescer {
    /// New, empty coalescer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one datagram. Returns `false` if it was stale (not newer than the newest seen).
    pub fn push(&mut self, m: MouseMove) -> bool {
        if let Some(newest) = self.newest_seq
            && !serial_gt(m.seq, newest)
        {
            self.dropped_stale += 1;
            return false;
        }
        self.newest_seq = Some(m.seq);
        if m.relative {
            let (px, py) = self.pending.relative.unwrap_or((0, 0));
            self.pending.relative = Some((px.saturating_add(m.x), py.saturating_add(m.y)));
        } else {
            self.pending.absolute = Some((m.x, m.y));
        }
        true
    }

    /// Take the coalesced motion, if any.
    pub fn take(&mut self) -> Option<MouseUpdate> {
        if self.pending == MouseUpdate::default() {
            None
        } else {
            Some(std::mem::take(&mut self.pending))
        }
    }

    /// Datagrams rejected as stale so far.
    pub fn dropped_stale(&self) -> u64 {
        self.dropped_stale
    }
}
