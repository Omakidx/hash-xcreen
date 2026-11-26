//! Kind-3 data frames (`docs/ipc.md` section 25): `stream_id` u64 LE, `flags` u8 (bit 0 `END`,
//! every other bit zero), then 0 to 1 048 576 bytes of payload.
//!
//! The payload is **encrypted repository data** (rustic encrypts config, keys, snapshots,
//! indexes and packs before they leave the engine), never a password or a Google credential, so
//! kind 3 is not a sensitive kind for the decoder: a half-received data frame is not zeroized on
//! drop, which keeps a mid-frame disconnect from costing a 1 MiB memset. The payload still goes
//! nowhere but the other link, and privd relays it without copying: [`DataFrame::from_body`]
//! splits the decoder's own buffer, and [`encode_data_header`] lets a writer send the 14 header
//! bytes and the payload with one vectored write.

use bytes::{Bytes, BytesMut};

use super::limits::{
    DATA_FRAME_HEADER_LEN, DATA_HEADER_LEN, FLAG_END, KIND_DATA, MAX_DATA_LENGTH, MAX_DATA_PAYLOAD,
};
use crate::error::FrameError;
use crate::frame::encode_prefix;

/// A decoded kind-3 frame.
#[derive(Clone, PartialEq, Eq)]
pub struct DataFrame {
    /// The `req_id` of the request this stream belongs to; never zero.
    pub stream_id: u64,
    /// The `END` flag: the last frame of the stream.
    pub end: bool,
    /// The payload: a view into the buffer the decoder filled (no copy).
    pub payload: Bytes,
}

/// Shows the stream and the payload length, never payload bytes.
impl std::fmt::Debug for DataFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataFrame")
            .field("stream_id", &self.stream_id)
            .field("end", &self.end)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl DataFrame {
    /// Parses the body of a kind-3 frame by **splitting the buffer**: the payload is the same
    /// allocation as `body`, 9 bytes further on.
    ///
    /// Errors: a body shorter than the header, a payload over 1 MiB, a flag bit other than
    /// `END`, a zero `stream_id`.
    pub fn from_body(mut body: BytesMut) -> Result<Self, FrameError> {
        if body.len() < DATA_HEADER_LEN {
            return Err(FrameError::BadBody("data"));
        }
        if body.len() - DATA_HEADER_LEN > MAX_DATA_PAYLOAD {
            return Err(FrameError::TooLong {
                length: u32::try_from(body.len().saturating_add(1)).unwrap_or(u32::MAX),
                max: MAX_DATA_LENGTH,
            });
        }
        let mut id = [0u8; 8];
        id.copy_from_slice(&body[..8]);
        let stream_id = u64::from_le_bytes(id);
        let flags = body[8];
        if flags & !FLAG_END != 0 {
            return Err(FrameError::Invalid("data.flags"));
        }
        if stream_id == 0 {
            return Err(FrameError::Invalid("data.stream_id"));
        }
        let payload = body.split_off(DATA_HEADER_LEN).freeze();
        Ok(Self {
            stream_id,
            end: flags & FLAG_END != 0,
            payload,
        })
    }
}

/// The prefix of a data frame for a payload of `payload_len` bytes: length, kind byte,
/// `stream_id`, `flags`. Send it, then the payload, as one vectored write. Refuses what the
/// receiver would refuse.
pub fn encode_data_header(
    stream_id: u64,
    end: bool,
    payload_len: usize,
) -> Result<[u8; DATA_FRAME_HEADER_LEN], FrameError> {
    if stream_id == 0 {
        return Err(FrameError::Invalid("data.stream_id"));
    }
    if payload_len > MAX_DATA_PAYLOAD {
        return Err(FrameError::TooLong {
            length: u32::try_from(payload_len.saturating_add(1 + DATA_HEADER_LEN))
                .unwrap_or(u32::MAX),
            max: MAX_DATA_LENGTH,
        });
    }
    let prefix = encode_prefix(KIND_DATA, DATA_HEADER_LEN + payload_len, MAX_DATA_LENGTH)?;
    let mut out = [0u8; DATA_FRAME_HEADER_LEN];
    out[..prefix.len()].copy_from_slice(&prefix);
    out[prefix.len()..prefix.len() + 8].copy_from_slice(&stream_id.to_le_bytes());
    out[DATA_FRAME_HEADER_LEN - 1] = if end { FLAG_END } else { 0 };
    Ok(out)
}

/// A whole data frame in one buffer (header, then payload). For tests and small frames; a relay
/// uses [`encode_data_header`] and writes the payload from where it already is.
pub fn encode_data(stream_id: u64, end: bool, payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    let header = encode_data_header(stream_id, end, payload.len())?;
    let mut out = Vec::with_capacity(header.len() + payload.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(payload);
    Ok(out)
}
