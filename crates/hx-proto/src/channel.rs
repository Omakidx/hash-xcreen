//! Channel ids, close and reset codes, size limits and stream priorities (protocol §3, §8).

use crate::error::ProtoError;

/// First byte of every stream, datagram and WebSocket message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ChannelId {
    /// Control stream (both directions).
    Control = 0x01,
    /// Keys, buttons and scroll (client to server).
    Input = 0x02,
    /// Mouse motion datagrams (client to server).
    MouseMove = 0x03,
    /// Cursor shape and position (server to client).
    Cursor = 0x04,
    /// Video, one stream per frame (server to client).
    Video = 0x05,
    /// Audio datagrams (server to client).
    Audio = 0x06,
    /// Clipboard transfers (both directions).
    Clipboard = 0x07,
    /// File transfers (both directions).
    File = 0x08,
    /// Per-frame acknowledgement, WebSocket only (client to server).
    FrameAck = 0x09,
}

impl ChannelId {
    /// Parse a channel id byte.
    pub fn from_u8(b: u8) -> Result<Self, ProtoError> {
        Ok(match b {
            0x01 => Self::Control,
            0x02 => Self::Input,
            0x03 => Self::MouseMove,
            0x04 => Self::Cursor,
            0x05 => Self::Video,
            0x06 => Self::Audio,
            0x07 => Self::Clipboard,
            0x08 => Self::File,
            0x09 => Self::FrameAck,
            other => return Err(ProtoError::UnknownChannel(other)),
        })
    }
}

/// Connection close codes (QUIC application error codes; WebSocket uses `4000 + code`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum CloseCode {
    /// Normal end of session.
    NoError = 0,
    /// Malformed, oversized, unexpected or forbidden message or channel.
    ProtocolError = 1,
    /// Different major version.
    UpdateRequired = 2,
    /// No valid `Hello` in time.
    HelloTimeout = 3,
    /// Peer not allowed.
    Unauthorized = 4,
    /// Server cannot take another session.
    Busy = 5,
    /// `INTENT_PAIR` while no pairing token is valid.
    PairingClosed = 6,
    /// Server is stopping.
    Shutdown = 7,
    /// Server fault.
    InternalError = 8,
    /// Another device took over this desktop (protocol 1.1, §5.7).
    TakenOver = 9,
}

impl CloseCode {
    /// Numeric code.
    pub const fn code(self) -> u32 {
        self as u32
    }

    /// Parse a received code. Unknown codes map to [`CloseCode::InternalError`] (protocol §8).
    pub fn from_code(code: u64) -> Self {
        match code {
            0 => Self::NoError,
            1 => Self::ProtocolError,
            2 => Self::UpdateRequired,
            3 => Self::HelloTimeout,
            4 => Self::Unauthorized,
            5 => Self::Busy,
            6 => Self::PairingClosed,
            7 => Self::Shutdown,
            9 => Self::TakenOver,
            _ => Self::InternalError,
        }
    }

    /// WebSocket close code (`4000 + code`, the private-use range).
    pub const fn websocket_code(self) -> u16 {
        4000 + self as u16
    }

    /// Parse a WebSocket close code; codes outside 4000..=4999 are not ours.
    pub fn from_websocket_code(code: u16) -> Option<Self> {
        if (4000..5000).contains(&code) {
            Some(Self::from_code(u64::from(code - 4000)))
        } else {
            None
        }
    }
}

/// Stream reset code: the sender cancelled a video frame that queued too long.
pub const RESET_STALE_FRAME: u32 = 0x57A1E;
/// Stream reset code: a transfer body did not match its header.
pub const RESET_TRANSFER_ERROR: u32 = 0x100;
/// Stream stop code: the receiver refused a transfer.
pub const STOP_TRANSFER_REJECTED: u32 = 0x101;

/// Maximum encoded control message.
pub const MAX_CONTROL_MESSAGE: usize = 65_536;
/// Maximum encoded input message.
pub const MAX_INPUT_MESSAGE: usize = 1_024;
/// Maximum encoded cursor message (256 x 256 RGBA plus overhead).
pub const MAX_CURSOR_MESSAGE: usize = 327_680;
/// Maximum encoded transfer header.
pub const MAX_TRANSFER_HEADER: usize = 4_096;
/// Maximum clipboard transfer body.
pub const MAX_CLIPBOARD_SIZE: u64 = 64 * 1024 * 1024;
/// Maximum file transfer body and the default limit: 4 GiB (protocol §5.6).
pub const MAX_FILE_SIZE: u64 = 4 * 1024 * 1024 * 1024;
/// Maximum sanitised device name in `Goodbye.peer_device_name` (protocol §5.7).
pub const MAX_DEVICE_NAME: usize = 64;
/// Length of a device id (protocol §11.1).
pub const DEVICE_ID_LEN: usize = 16;
/// Largest `ServerStats.interval_ms` (protocol §5.8).
pub const MAX_STATS_INTERVAL_MS: u32 = 60_000;
/// Maximum WebSocket transfer chunk.
pub const MAX_TRANSFER_CHUNK: usize = 65_536;
/// Maximum cursor image edge in pixels.
pub const MAX_CURSOR_EDGE: u32 = 256;
/// Maximum opaque pairing/auth envelope payload.
pub const MAX_OPAQUE: usize = 4_096;

/// Stream priorities for `quinn::SendStream::set_priority` (higher is sent first).
pub mod priority {
    /// Keys and buttons.
    pub const INPUT: i32 = 100;
    /// Control.
    pub const CONTROL: i32 = 50;
    /// Cursor.
    pub const CURSOR: i32 = 50;
    /// Video frames.
    pub const VIDEO: i32 = 0;
    /// Clipboard and file transfers.
    pub const TRANSFER: i32 = -100;
}
