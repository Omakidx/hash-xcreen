//! The fixed little-endian media header (protocol §6).
//!
//! ```text
//! offset size field
//!  0     1    version (= 1)
//!  1     1    codec (VideoCodec number)
//!  2     2    flags (bit 0 KEY, bit 1 RESYNC)
//!  4     4    frame_number
//!  8     8    capture_timestamp_us
//! 16     4    payload_len
//! ```

use crate::{error::ProtoError, pb::VideoCodec};

/// Size of the media header in bytes.
pub const MEDIA_HEADER_LEN: usize = 20;
/// The only defined header layout version.
pub const MEDIA_HEADER_VERSION: u8 = 1;
/// Largest accepted video payload (16 MiB).
pub const MAX_VIDEO_PAYLOAD: u32 = 16 * 1024 * 1024;

/// Frame flag: decodes without earlier frames.
pub const FLAG_KEY: u16 = 1 << 0;
/// Frame flag: fresh image sent after stale frames were cancelled; the decoder restarts.
pub const FLAG_RESYNC: u16 = 1 << 1;
/// All flag bits defined in version 1; any other bit is rejected.
pub const FLAGS_KNOWN: u16 = FLAG_KEY | FLAG_RESYNC;

/// Decoded media header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaHeader {
    /// Codec of the payload (never `Unspecified`).
    pub codec: VideoCodec,
    /// `FLAG_*` bits.
    pub flags: u16,
    /// Frame number, wrapping, compared with serial arithmetic.
    pub frame_number: u32,
    /// Capture time in microseconds on the sender's monotonic clock.
    pub capture_timestamp_us: u64,
    /// Payload length in bytes, at most [`MAX_VIDEO_PAYLOAD`].
    pub payload_len: u32,
}

fn codec_from_u8(b: u8) -> Result<VideoCodec, ProtoError> {
    match VideoCodec::try_from(i32::from(b)) {
        Ok(VideoCodec::Unspecified) | Err(_) => Err(ProtoError::UnknownCodec(b)),
        Ok(c) => Ok(c),
    }
}

impl MediaHeader {
    /// True if the `KEY` flag is set.
    pub fn is_key(&self) -> bool {
        self.flags & FLAG_KEY != 0
    }

    /// True if the `RESYNC` flag is set.
    pub fn is_resync(&self) -> bool {
        self.flags & FLAG_RESYNC != 0
    }

    fn validate(&self) -> Result<(), ProtoError> {
        if self.codec == VideoCodec::Unspecified {
            return Err(ProtoError::UnknownCodec(0));
        }
        if self.flags & !FLAGS_KNOWN != 0 {
            return Err(ProtoError::ReservedFlags(self.flags));
        }
        if self.payload_len > MAX_VIDEO_PAYLOAD {
            return Err(ProtoError::TooLarge {
                what: "video payload",
                len: self.payload_len as usize,
                max: MAX_VIDEO_PAYLOAD as usize,
            });
        }
        Ok(())
    }

    /// Encode to the 20-byte wire form. Fails if the header would not pass [`decode`](Self::decode).
    pub fn encode(&self) -> Result<[u8; MEDIA_HEADER_LEN], ProtoError> {
        self.validate()?;
        let mut b = [0u8; MEDIA_HEADER_LEN];
        b[0] = MEDIA_HEADER_VERSION;
        // `validate` guarantees a defined codec number, which fits in a byte.
        b[1] = self.codec as i32 as u8;
        b[2..4].copy_from_slice(&self.flags.to_le_bytes());
        b[4..8].copy_from_slice(&self.frame_number.to_le_bytes());
        b[8..16].copy_from_slice(&self.capture_timestamp_us.to_le_bytes());
        b[16..20].copy_from_slice(&self.payload_len.to_le_bytes());
        Ok(b)
    }

    /// Decode and validate exactly [`MEDIA_HEADER_LEN`] bytes. Total: never panics.
    ///
    /// Rejects wrong lengths, an unknown layout version, an unknown codec, reserved flag bits
    /// and a payload length above [`MAX_VIDEO_PAYLOAD`].
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let b: &[u8; MEDIA_HEADER_LEN] = match buf.len() {
            n if n < MEDIA_HEADER_LEN => {
                return Err(ProtoError::Truncated {
                    need: MEDIA_HEADER_LEN,
                    have: n,
                });
            }
            n if n > MEDIA_HEADER_LEN => {
                return Err(ProtoError::TrailingBytes {
                    extra: n - MEDIA_HEADER_LEN,
                });
            }
            _ => match buf.try_into() {
                Ok(b) => b,
                Err(_) => {
                    return Err(ProtoError::Truncated {
                        need: MEDIA_HEADER_LEN,
                        have: buf.len(),
                    });
                }
            },
        };
        if b[0] != MEDIA_HEADER_VERSION {
            return Err(ProtoError::UnsupportedVersion(b[0]));
        }
        let codec = codec_from_u8(b[1])?;
        let h = Self {
            codec,
            flags: u16::from_le_bytes([b[2], b[3]]),
            frame_number: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            capture_timestamp_us: u64::from_le_bytes([
                b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
            ]),
            payload_len: u32::from_le_bytes([b[16], b[17], b[18], b[19]]),
        };
        h.validate()?;
        Ok(h)
    }

    /// Decode a complete frame held in memory (header followed by exactly `payload_len` bytes),
    /// as carried in one WebSocket message. Returns the header and the payload slice.
    pub fn decode_frame(buf: &[u8]) -> Result<(Self, &[u8]), ProtoError> {
        let (head, payload) =
            buf.split_at_checked(MEDIA_HEADER_LEN)
                .ok_or(ProtoError::Truncated {
                    need: MEDIA_HEADER_LEN,
                    have: buf.len(),
                })?;
        let h = Self::decode(head)?;
        let want = h.payload_len as usize;
        match payload.len() {
            n if n < want => Err(ProtoError::Truncated {
                need: MEDIA_HEADER_LEN + want,
                have: buf.len(),
            }),
            n if n > want => Err(ProtoError::TrailingBytes { extra: n - want }),
            _ => Ok((h, payload)),
        }
    }
}
