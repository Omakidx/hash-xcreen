//! Strict encode/decode/validate for protobuf messages, and length-prefix framing (protocol §5).
//!
//! `prost` decoding is total (never panics); on top of it every message type that crosses a
//! channel has a [`Wire`] implementation with its size limit and semantic validation, so a
//! value returned by [`decode`] always satisfies the rules of `docs/protocol.md`.

use bytes::Bytes;
use prost::Message;

use crate::{
    channel::{
        MAX_CLIPBOARD_SIZE, MAX_CONTROL_MESSAGE, MAX_CURSOR_EDGE, MAX_CURSOR_MESSAGE,
        MAX_INPUT_MESSAGE, MAX_OPAQUE, MAX_TRANSFER_HEADER,
    },
    error::ProtoError,
    pb::{
        self, ControlMessage, CursorEvent, InputEvent, TransferHeader, VideoCodec,
        control_message::Message as Ctl, cursor_event::Event as Cur, input_event::Event as Inp,
    },
};

/// Length prefix size of a framed message.
pub const FRAME_PREFIX_LEN: usize = 4;
/// Largest remote dimension in pixels.
pub const MAX_DIMENSION: u32 = 16_384;
/// Highest USB HID keyboard usage accepted.
pub const MAX_SCANCODE: u32 = 0xE7;

/// A protobuf message that travels on a channel, with that channel's limit and validation.
pub trait Wire: Message + Default + Sized {
    /// Maximum encoded size.
    const MAX_LEN: usize;
    /// Semantic validation of a decoded (or about to be encoded) message.
    fn validate(&self) -> Result<(), ProtoError>;
}

/// Decode and validate one message (no length prefix). Total: never panics.
pub fn decode<M: Wire>(buf: &[u8]) -> Result<M, ProtoError> {
    if buf.is_empty() {
        return Err(ProtoError::Empty { what: "message" });
    }
    if buf.len() > M::MAX_LEN {
        return Err(ProtoError::TooLarge {
            what: "message",
            len: buf.len(),
            max: M::MAX_LEN,
        });
    }
    let m = M::decode(buf).map_err(|e| ProtoError::Decode(e.to_string()))?;
    m.validate()?;
    Ok(m)
}

/// Validate and encode one message (no length prefix).
pub fn encode<M: Wire>(m: &M) -> Result<Bytes, ProtoError> {
    m.validate()?;
    let len = m.encoded_len();
    if len == 0 {
        return Err(ProtoError::Empty { what: "message" });
    }
    if len > M::MAX_LEN {
        return Err(ProtoError::TooLarge {
            what: "message",
            len,
            max: M::MAX_LEN,
        });
    }
    Ok(Bytes::from(m.encode_to_vec()))
}

/// Validate and encode one message with its `u32` little-endian length prefix.
pub fn encode_framed<M: Wire>(m: &M) -> Result<Bytes, ProtoError> {
    let body = encode(m)?;
    let mut v = Vec::with_capacity(FRAME_PREFIX_LEN + body.len());
    v.extend_from_slice(&(body.len() as u32).to_le_bytes());
    v.extend_from_slice(&body);
    Ok(Bytes::from(v))
}

/// Parse a frame length prefix and check it against `max`. A zero or oversized length is an error.
pub fn parse_frame_len(prefix: [u8; FRAME_PREFIX_LEN], max: usize) -> Result<usize, ProtoError> {
    let len = u32::from_le_bytes(prefix) as usize;
    if len == 0 {
        return Err(ProtoError::Empty { what: "frame" });
    }
    if len > max {
        return Err(ProtoError::TooLarge {
            what: "frame",
            len,
            max,
        });
    }
    Ok(len)
}

/// Split one framed message off the front of `buf`. Returns the decoded message and the rest.
/// Convenience for in-memory buffers, tests and fuzzing; stream readers use [`parse_frame_len`].
pub fn decode_framed<M: Wire>(buf: &[u8]) -> Result<(M, &[u8]), ProtoError> {
    let (prefix, rest) = buf
        .split_at_checked(FRAME_PREFIX_LEN)
        .ok_or(ProtoError::Truncated {
            need: FRAME_PREFIX_LEN,
            have: buf.len(),
        })?;
    let mut p = [0u8; FRAME_PREFIX_LEN];
    p.copy_from_slice(prefix);
    let len = parse_frame_len(p, M::MAX_LEN)?;
    let (body, rest) = rest.split_at_checked(len).ok_or(ProtoError::Truncated {
        need: FRAME_PREFIX_LEN + len,
        have: buf.len(),
    })?;
    Ok((decode(body)?, rest))
}

fn invalid(field: &'static str, reason: &'static str) -> ProtoError {
    ProtoError::Invalid { field, reason }
}

fn check_str(field: &'static str, s: &str, max: usize) -> Result<(), ProtoError> {
    if s.len() > max {
        Err(invalid(field, "string too long"))
    } else {
        Ok(())
    }
}

fn check_codec(field: &'static str, v: i32, allow_unspecified: bool) -> Result<(), ProtoError> {
    match VideoCodec::try_from(v) {
        Ok(VideoCodec::Unspecified) if allow_unspecified => Ok(()),
        Ok(VideoCodec::Unspecified) => Err(invalid(field, "codec must be set")),
        Ok(_) => Ok(()),
        Err(_) => Err(invalid(field, "unknown codec")),
    }
}

fn check_caps(c: &pb::Capabilities) -> Result<(), ProtoError> {
    if c.video_codecs.len() > 16 {
        return Err(invalid("capabilities.video_codecs", "too many codecs"));
    }
    for v in &c.video_codecs {
        check_codec("capabilities.video_codecs", *v, false)?;
    }
    Ok(())
}

impl Wire for ControlMessage {
    const MAX_LEN: usize = MAX_CONTROL_MESSAGE;

    fn validate(&self) -> Result<(), ProtoError> {
        let Some(m) = &self.message else {
            return Err(invalid("control_message", "no variant set"));
        };
        match m {
            Ctl::Hello(h) => {
                if h.version.is_none() {
                    return Err(invalid("hello.version", "missing"));
                }
                if let Some(c) = &h.capabilities {
                    check_caps(c)?;
                }
                if !matches!(
                    pb::Intent::try_from(h.intent),
                    Ok(pb::Intent::Session | pb::Intent::Pair)
                ) {
                    return Err(invalid("hello.intent", "must be SESSION or PAIR"));
                }
                check_str("hello.software", &h.software, 128)?;
                check_str("hello.device_name", &h.device_name, 64)?;
            }
            Ctl::HelloAck(a) => {
                if a.version.is_none() {
                    return Err(invalid("hello_ack.version", "missing"));
                }
                if let Some(c) = &a.capabilities {
                    check_caps(c)?;
                }
                if a.session_id.len() != 16 {
                    return Err(invalid("hello_ack.session_id", "must be 16 bytes"));
                }
                check_str("hello_ack.software", &a.software, 128)?;
            }
            Ctl::Refuse(r) => {
                if !matches!(
                    pb::RefuseReason::try_from(r.reason),
                    Ok(pb::RefuseReason::UpdateRequired
                        | pb::RefuseReason::Unauthorized
                        | pb::RefuseReason::Busy
                        | pb::RefuseReason::PairingClosed)
                ) {
                    return Err(invalid("refuse.reason", "unknown reason"));
                }
                check_str("refuse.message", &r.message, 256)?;
            }
            Ctl::ViewConfig(v) => {
                check_codec("view_config.codec", v.codec, true)?;
                if v.max_fps > 240 {
                    return Err(invalid("view_config.max_fps", "above 240"));
                }
                match (v.width, v.height) {
                    (0, 0) => {}
                    (w, h)
                        if (1..=MAX_DIMENSION).contains(&w) && (1..=MAX_DIMENSION).contains(&h) => {
                    }
                    _ => {
                        return Err(invalid(
                            "view_config.size",
                            "width and height must both be 0 or in 1..=16384",
                        ));
                    }
                }
                if v.scale_percent != 0 && !(50..=400).contains(&v.scale_percent) {
                    return Err(invalid(
                        "view_config.scale_percent",
                        "must be 0 or 50..=400",
                    ));
                }
            }
            Ctl::StreamInfo(s) => {
                check_codec("stream_info.codec", s.codec, false)?;
                if !(1..=MAX_DIMENSION).contains(&s.width)
                    || !(1..=MAX_DIMENSION).contains(&s.height)
                {
                    return Err(invalid(
                        "stream_info.size",
                        "width and height must be in 1..=16384",
                    ));
                }
                if s.fps > 240 {
                    return Err(invalid("stream_info.fps", "above 240"));
                }
            }
            Ctl::RequestKeyframe(_) | Ctl::Ping(_) | Ctl::Pong(_) | Ctl::Stats(_) => {}
            Ctl::Goodbye(g) => check_str("goodbye.message", &g.message, 256)?,
            Ctl::Pairing(o) | Ctl::Auth(o) => {
                if o.data.len() > MAX_OPAQUE {
                    return Err(invalid("opaque.data", "too long"));
                }
            }
        }
        Ok(())
    }
}

impl Wire for InputEvent {
    const MAX_LEN: usize = MAX_INPUT_MESSAGE;

    fn validate(&self) -> Result<(), ProtoError> {
        match &self.event {
            None => Err(invalid("input_event", "no variant set")),
            Some(Inp::Key(k)) if k.scancode > MAX_SCANCODE => {
                Err(invalid("key.scancode", "above 0xE7"))
            }
            Some(Inp::Button(b)) => match pb::MouseButton::try_from(b.button) {
                Ok(pb::MouseButton::Unspecified) | Err(_) => {
                    Err(invalid("button.button", "unknown button"))
                }
                Ok(_) => Ok(()),
            },
            Some(_) => Ok(()),
        }
    }
}

impl Wire for CursorEvent {
    const MAX_LEN: usize = MAX_CURSOR_MESSAGE;

    fn validate(&self) -> Result<(), ProtoError> {
        match &self.event {
            None => Err(invalid("cursor_event", "no variant set")),
            Some(Cur::Position(_)) => Ok(()),
            Some(Cur::Shape(s)) => {
                if !(1..=MAX_CURSOR_EDGE).contains(&s.width)
                    || !(1..=MAX_CURSOR_EDGE).contains(&s.height)
                {
                    return Err(invalid("shape.size", "width and height must be in 1..=256"));
                }
                let want = (s.width as usize) * (s.height as usize) * 4;
                if s.rgba.len() != want {
                    return Err(invalid("shape.rgba", "length must be width*height*4"));
                }
                if s.hotspot_x >= s.width || s.hotspot_y >= s.height {
                    return Err(invalid("shape.hotspot", "outside the image"));
                }
                Ok(())
            }
        }
    }
}

impl Wire for TransferHeader {
    const MAX_LEN: usize = MAX_TRANSFER_HEADER;

    fn validate(&self) -> Result<(), ProtoError> {
        if self.mime.is_empty() {
            return Err(invalid("transfer.mime", "must not be empty"));
        }
        check_str("transfer.mime", &self.mime, 255)?;
        check_str("transfer.name", &self.name, 255)?;
        if !self.name.is_empty() {
            file_name_problem(&self.name)
                .map_or(Ok(()), |reason| Err(invalid("transfer.name", reason)))?;
        }
        Ok(())
    }
}

/// Why `name` is not an acceptable file-name hint, or `None` if it is.
///
/// The name is only a display hint: receivers MUST write inside a directory of their own
/// choosing and never use it as a path. These checks keep obviously dangerous or confusing
/// names off the wire on every platform (protocol §5.5).
pub fn file_name_problem(name: &str) -> Option<&'static str> {
    if name == "." || name == ".." {
        return Some("is a dot name");
    }
    for c in name.chars() {
        match c {
            '/' | '\\' => return Some("contains a path separator"),
            ':' => return Some("contains a colon"),
            '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{061C}' => {
                return Some("contains a bidirectional control character");
            }
            c if c.is_control() => return Some("contains a control character"),
            _ => {}
        }
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return Some("ends with a dot or space");
    }
    let stem = name.split('.').next().unwrap_or("").trim_end_matches(' ');
    let upper = stem.to_ascii_uppercase();
    let reserved = matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((upper.starts_with("COM") || upper.starts_with("LPT"))
            && upper.len() == 4
            && matches!(upper.as_bytes().get(3), Some(b'1'..=b'9')));
    if reserved {
        return Some("is a reserved device name");
    }
    None
}

impl TransferHeader {
    /// Clipboard-specific rule: no name, size within [`MAX_CLIPBOARD_SIZE`].
    pub fn validate_clipboard(&self) -> Result<(), ProtoError> {
        if !self.name.is_empty() {
            return Err(invalid("transfer.name", "must be empty for clipboard"));
        }
        if self.size > MAX_CLIPBOARD_SIZE {
            return Err(invalid("transfer.size", "above the clipboard limit"));
        }
        Ok(())
    }
}

/// Convenience constructors for the common envelopes.
impl ControlMessage {
    /// Wrap a variant.
    pub fn new(m: Ctl) -> Self {
        Self { message: Some(m) }
    }
}
