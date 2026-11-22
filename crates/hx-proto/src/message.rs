//! Strict encode/decode/validate for protobuf messages, and length-prefix framing (protocol §5).
//!
//! `prost` decoding is total (never panics); on top of it every message type that crosses a
//! channel has a [`Wire`] implementation with its size limit and semantic validation, so a
//! value returned by [`decode`] always satisfies the rules of `docs/protocol.md`.

use bytes::Bytes;
use prost::Message;

use crate::{
    channel::{
        DEVICE_ID_LEN, MAX_CLIPBOARD_SIZE, MAX_CONTROL_MESSAGE, MAX_CURSOR_EDGE,
        MAX_CURSOR_MESSAGE, MAX_DEVICE_LIST, MAX_DEVICE_NAME, MAX_FILE_SIZE, MAX_INPUT_MESSAGE,
        MAX_OPAQUE, MAX_PAIRING_CODE, MAX_SETUP_PASSWORD, MAX_SETUP_PIN, MAX_SETUP_USERNAME,
        MAX_SETUP_WARNINGS, MAX_STATS_INTERVAL_MS, MAX_TRANSFER_HEADER,
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
/// Shortest lifetime a client may request for a pairing code, in seconds (1.3).
pub const MIN_PAIRING_CODE_TTL_S: u32 = 60;
/// Longest lifetime a client may request for a pairing code, in seconds (1.3).
pub const MAX_PAIRING_CODE_TTL_S: u32 = 900;
/// Most bytes of a desktop password (privd and libxcrypt read no more).
pub const MAX_PASSWORD_BYTES: usize = 511;
/// Fewest and most digits of a PIN.
pub const PIN_LEN: std::ops::RangeInclusive<usize> = 6..=16;
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
    if c.max_file_bytes > MAX_FILE_SIZE {
        return Err(invalid("capabilities.max_file_bytes", "above 4 GiB"));
    }
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
                    Ok(pb::Intent::Session
                        | pb::Intent::Pair
                        | pb::Intent::Setup
                        | pb::Intent::Reinstate)
                ) {
                    return Err(invalid(
                        "hello.intent",
                        "must be SESSION, PAIR, SETUP or REINSTATE",
                    ));
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
                        | pb::RefuseReason::PairingClosed
                        | pb::RefuseReason::SetupClosed)
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
            Ctl::Goodbye(g) => {
                check_str("goodbye.message", &g.message, 256)?;
                check_str(
                    "goodbye.peer_device_name",
                    &g.peer_device_name,
                    MAX_DEVICE_NAME,
                )?;
                device_name_problem(&g.peer_device_name)
                    .map_or(Ok(()), |r| Err(invalid("goodbye.peer_device_name", r)))?;
                if !g.peer_device_id.is_empty() && g.peer_device_id.len() != DEVICE_ID_LEN {
                    return Err(invalid(
                        "goodbye.peer_device_id",
                        "must be empty or 16 bytes",
                    ));
                }
            }
            Ctl::ServerStats(s) => {
                if !(1..=MAX_STATS_INTERVAL_MS).contains(&s.interval_ms) {
                    return Err(invalid("server_stats.interval_ms", "must be 1..=60000"));
                }
                if s.fps_ceiling > 240 {
                    return Err(invalid("server_stats.fps_ceiling", "above 240"));
                }
            }
            Ctl::DeviceMgmt(d) => d.validate_body()?,
            Ctl::Setup(s) => s.validate_body()?,
            Ctl::Pairing(o) | Ctl::Auth(o) => {
                if o.data.len() > MAX_OPAQUE {
                    return Err(invalid("opaque.data", "too long"));
                }
            }
        }
        Ok(())
    }
}

/// Which way a `DeviceMgmt` or `SetupMessage` body travels (protocol §5.9, §5.10). One
/// envelope carries both directions, so the transport cannot enforce the role from the variant
/// alone: the receiving application checks it with [`pb::DeviceMgmt::direction`] or
/// [`pb::SetupMessage::direction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MgmtDirection {
    /// A request: only a client sends it.
    ClientToServer,
    /// A response or an event: only the server sends it.
    ServerToClient,
}

impl pb::DeviceMgmt {
    /// The direction this body may travel, or `None` if no body is set.
    pub fn direction(&self) -> Option<MgmtDirection> {
        use pb::device_mgmt::Body as B;
        Some(match self.body.as_ref()? {
            B::List(_) | B::Revoke(_) | B::CreatePairingCode(_) => MgmtDirection::ClientToServer,
            B::DeviceList(_) | B::RevokeResult(_) | B::Event(_) | B::PairingCodeIssued(_) => {
                MgmtDirection::ServerToClient
            }
        })
    }

    /// Structure and field rules (protocol §5.9), independent of direction.
    fn validate_body(&self) -> Result<(), ProtoError> {
        use pb::device_mgmt::Body as B;
        let Some(body) = &self.body else {
            return Err(invalid("device_mgmt", "no body set"));
        };
        // Requests and their answers carry the request id; a pushed event never does.
        match (body, self.request_id) {
            (B::Event(_), 0) => {}
            (B::Event(_), _) => return Err(invalid("device_mgmt.request_id", "must be 0")),
            (_, 0) => return Err(invalid("device_mgmt.request_id", "must not be 0")),
            _ => {}
        }
        match body {
            B::List(_) => Ok(()),
            B::CreatePairingCode(c) => {
                if !(MIN_PAIRING_CODE_TTL_S..=MAX_PAIRING_CODE_TTL_S).contains(&c.expires_in_s) {
                    return Err(invalid(
                        "create_pairing_code.expires_in_s",
                        "must be 60..=900",
                    ));
                }
                Ok(())
            }
            B::PairingCodeIssued(c) => {
                let status = match pb::PairingCodeStatus::try_from(c.status) {
                    Ok(pb::PairingCodeStatus::Unspecified) | Err(_) => {
                        return Err(invalid("pairing_code_issued.status", "unknown status"));
                    }
                    Ok(s) => s,
                };
                if status == pb::PairingCodeStatus::Ok {
                    if c.code.is_empty()
                        || c.code.len() > MAX_PAIRING_CODE
                        || !c
                            .code
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    {
                        return Err(invalid(
                            "pairing_code_issued.code",
                            "must be 1..=16 ASCII letters, digits or dashes",
                        ));
                    }
                } else if !c.code.is_empty() {
                    return Err(invalid(
                        "pairing_code_issued.code",
                        "must be empty unless the status is OK",
                    ));
                }
                if c.retry_after_s != 0 && status != pb::PairingCodeStatus::RateLimited {
                    return Err(invalid(
                        "pairing_code_issued.retry_after_s",
                        "must be 0 unless the status is RATE_LIMITED",
                    ));
                }
                Ok(())
            }
            B::Revoke(r) => check_device_id("revoke.device_id", &r.device_id, false),
            B::RevokeResult(r) => match pb::RevokeStatus::try_from(r.status) {
                Ok(pb::RevokeStatus::Unspecified) | Err(_) => {
                    Err(invalid("revoke_result.status", "unknown status"))
                }
                Ok(_) => Ok(()),
            },
            B::DeviceList(l) => {
                if l.devices.len() > MAX_DEVICE_LIST {
                    return Err(invalid("device_list.devices", "too many devices"));
                }
                let mut current = 0;
                for d in &l.devices {
                    check_device_info(d)?;
                    current += usize::from(d.current);
                }
                if current > 1 {
                    return Err(invalid(
                        "device_list.devices",
                        "more than one current device",
                    ));
                }
                Ok(())
            }
            B::Event(e) => {
                match pb::DeviceEventKind::try_from(e.kind) {
                    Ok(pb::DeviceEventKind::Unspecified) | Err(_) => {
                        return Err(invalid("device_event.kind", "unknown kind"));
                    }
                    Ok(_) => {}
                }
                match &e.device {
                    Some(d) => check_device_info(d)?,
                    None => return Err(invalid("device_event.device", "missing")),
                }
                check_device_id("device_event.by_device_id", &e.by_device_id, true)
            }
        }
    }
}

fn check_device_id(field: &'static str, id: &[u8], allow_empty: bool) -> Result<(), ProtoError> {
    if id.len() == DEVICE_ID_LEN || (allow_empty && id.is_empty()) {
        Ok(())
    } else if allow_empty {
        Err(invalid(field, "must be empty or 16 bytes"))
    } else {
        Err(invalid(field, "must be 16 bytes"))
    }
}

fn check_device_info(d: &pb::DeviceInfo) -> Result<(), ProtoError> {
    check_device_id("device.device_id", &d.device_id, false)?;
    check_str("device.name", &d.name, MAX_DEVICE_NAME)?;
    device_name_problem(&d.name).map_or(Ok(()), |r| Err(invalid("device.name", r)))?;
    let reason = pb::DeviceRevokeReason::try_from(d.revoke_reason)
        .map_err(|_| invalid("device.revoke_reason", "unknown reason"))?;
    match pb::DeviceStatus::try_from(d.status) {
        Ok(pb::DeviceStatus::Active) => {
            if reason != pb::DeviceRevokeReason::Unspecified || d.revoked_unix != 0 {
                return Err(invalid(
                    "device.status",
                    "an active device has no revocation",
                ));
            }
        }
        Ok(pb::DeviceStatus::Revoked) => {
            if reason == pb::DeviceRevokeReason::Unspecified {
                return Err(invalid(
                    "device.revoke_reason",
                    "a revoked device needs a reason",
                ));
            }
        }
        Ok(pb::DeviceStatus::Unspecified) | Err(_) => {
            return Err(invalid("device.status", "unknown status"));
        }
    }
    Ok(())
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
        check_str("transfer.mime", &self.mime, 255)?;
        mime_problem(&self.mime).map_or(Ok(()), |reason| Err(invalid("transfer.mime", reason)))?;
        check_str("transfer.name", &self.name, 255)?;
        if !self.name.is_empty() {
            file_name_problem(&self.name)
                .map_or(Ok(()), |reason| Err(invalid("transfer.name", reason)))?;
        }
        Ok(())
    }
}

/// True for characters that must never appear in a device name shown to a user: control
/// characters (C0, C1, DEL), bidirectional controls and invisible characters (the same sets
/// that file names reject, protocol §3.1).
fn is_unsafe_display_char(c: char) -> bool {
    matches!(
        c,
        '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{061C}'
            | '\u{200B}'..='\u{200D}'
            | '\u{2060}'
            | '\u{FEFF}'
            | '\u{180E}'
    ) || c.is_control()
}

/// Why `name` is not an acceptable sanitised device name, or `None` if it is: control, bidi
/// and invisible characters are rejected; length is checked separately (protocol §5.7).
pub fn device_name_problem(name: &str) -> Option<&'static str> {
    name.chars()
        .any(is_unsafe_display_char)
        .then_some("contains a control, bidirectional or invisible character")
}

/// Sanitise a peer-supplied device name for display or for `Goodbye.peer_device_name`:
/// drop control, bidirectional and invisible characters, trim surrounding whitespace and cut
/// to at most [`MAX_DEVICE_NAME`] bytes on a character boundary (protocol §5.7). The result
/// always passes the receiver's validation.
pub fn sanitize_device_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter(|c| !is_unsafe_display_char(*c))
        .collect();
    let mut out = String::new();
    for c in cleaned.trim().chars() {
        if out.len() + c.len_utf8() > MAX_DEVICE_NAME {
            break;
        }
        out.push(c);
    }
    out.trim_end().to_owned()
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
            '\u{200B}'..='\u{200D}' | '\u{2060}' | '\u{FEFF}' | '\u{180E}' => {
                return Some("contains an invisible character");
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
    let numbered = |prefix: &str| {
        upper.strip_prefix(prefix).is_some_and(|rest| {
            let mut it = rest.chars();
            matches!(
                (it.next(), it.next()),
                (Some('1'..='9' | '\u{B9}' | '\u{B2}' | '\u{B3}'), None)
            )
        })
    };
    let reserved = matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || numbered("COM")
        || numbered("LPT");
    if reserved {
        return Some("is a reserved device name");
    }
    None
}

/// Why `mime` is not an acceptable media type, or `None` if it is: `type/subtype` made of
/// token characters, optionally followed by `;`-separated printable-ASCII parameters.
pub fn mime_problem(mime: &str) -> Option<&'static str> {
    if mime.is_empty() {
        return Some("must not be empty");
    }
    if !mime.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return Some("contains a control or non-ASCII character");
    }
    let (essence, _params) = mime.split_once(';').unwrap_or((mime, ""));
    let is_token = |t: &str| {
        !t.is_empty()
            && t.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$&^_.+-".contains(&b))
    };
    match essence.trim_end().split_once('/') {
        Some((t, sub)) if is_token(t) && is_token(sub) => None,
        _ => Some("is not type/subtype"),
    }
}

impl TransferHeader {
    /// File-specific rule (protocol §5.6): `size` must not exceed `limit`, the effective limit
    /// (`Negotiated::max_file_bytes`), itself never above [`MAX_FILE_SIZE`]. Call after
    /// [`Wire::validate`]. A failure means refuse the transfer (`TRANSFER_REJECTED`), not a
    /// protocol error.
    pub fn validate_file(&self, limit: u64) -> Result<(), ProtoError> {
        if self.size > limit.min(MAX_FILE_SIZE) {
            return Err(invalid("transfer.size", "above the file size limit"));
        }
        Ok(())
    }

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

/// Why `pw` cannot be the desktop user's password, or `None` when it can: 1 to
/// [`MAX_PASSWORD_BYTES`] bytes of valid UTF-8 without NUL, CR or LF. The one checker shared by
/// the setup client and the gateway (protocol §5.10); the messages never include the value.
pub fn password_problem(pw: &[u8]) -> Option<&'static str> {
    if pw.is_empty() {
        return Some("must not be empty");
    }
    if pw.len() > MAX_PASSWORD_BYTES {
        return Some("is longer than 511 bytes");
    }
    if pw.iter().any(|b| matches!(b, 0 | b'\n' | b'\r')) {
        return Some("contains a NUL, carriage return or newline");
    }
    if std::str::from_utf8(pw).is_err() {
        return Some("is not valid UTF-8");
    }
    None
}

/// Why `pin` cannot be a PIN, or `None` when it can: 6 to 16 ASCII digits.
pub fn pin_problem(pin: &[u8]) -> Option<&'static str> {
    if !PIN_LEN.contains(&pin.len()) {
        return Some("must be 6 to 16 digits");
    }
    if !pin.iter().all(u8::is_ascii_digit) {
        return Some("must be digits only");
    }
    None
}

impl pb::SetupMessage {
    /// The direction this body may travel, or `None` if no body is set.
    pub fn direction(&self) -> Option<MgmtDirection> {
        use pb::setup_message::Body as B;
        Some(match self.body.as_ref()? {
            B::SetPin(_) | B::Start(_) | B::Cancel(_) | B::Finish(_) => {
                MgmtDirection::ClientToServer
            }
            B::State(_) | B::Ack(_) | B::Progress(_) | B::Result(_) => {
                MgmtDirection::ServerToClient
            }
        })
    }

    /// Structure and hard size caps (protocol §5.10), independent of direction. Semantic
    /// checks (PIN digits, password rules, user name, enum values, Docker acknowledgement) are
    /// the receiver's business and are answered with `SetupAck`, not a protocol error.
    fn validate_body(&self) -> Result<(), ProtoError> {
        use pb::setup_message::Body as B;
        let Some(body) = &self.body else {
            return Err(invalid("setup", "no body set"));
        };
        // Requests and their acks carry the request id; pushes never do.
        match (body, self.request_id) {
            (B::State(_) | B::Progress(_) | B::Result(_), 0) => {}
            (B::State(_) | B::Progress(_) | B::Result(_), _) => {
                return Err(invalid("setup.request_id", "must be 0"));
            }
            (_, 0) => return Err(invalid("setup.request_id", "must not be 0")),
            _ => {}
        }
        match body {
            B::SetPin(p) => {
                if p.pin.len() > MAX_SETUP_PIN {
                    return Err(invalid("set_pin.pin", "too long"));
                }
            }
            B::Start(s) => {
                if s.password.len() > MAX_SETUP_PASSWORD {
                    return Err(invalid("start.password", "too long"));
                }
                if let Some(o) = &s.options {
                    check_setup_options(o)?;
                }
            }
            B::Cancel(_) | B::Finish(_) => {}
            B::State(s) => {
                if let Some(h) = &s.host {
                    check_str("state.host.os", &h.os, 64)?;
                    check_str("state.host.arch", &h.arch, 16)?;
                }
                if let Some(p) = &s.last_progress {
                    check_setup_progress(p)?;
                }
                if let Some(r) = &s.last_result {
                    check_setup_result(r)?;
                }
            }
            B::Ack(a) => {
                check_str("ack.field", &a.field, 64)?;
                check_str("ack.message", &a.message, 256)?;
            }
            B::Progress(p) => check_setup_progress(p)?,
            B::Result(r) => check_setup_result(r)?,
        }
        Ok(())
    }
}

fn check_setup_options(o: &pb::SetupOptions) -> Result<(), ProtoError> {
    check_str("options.username", &o.username, MAX_SETUP_USERNAME)?;
    if let Some(l) = &o.limits {
        if l.cpu > 1024 {
            return Err(invalid("options.limits.cpu", "above 1024"));
        }
        if l.memory_mib > 16_777_216 {
            return Err(invalid("options.limits.memory_mib", "above 16777216"));
        }
        if l.disk_gib > 65_536 {
            return Err(invalid("options.limits.disk_gib", "above 65536"));
        }
    }
    if let Some(s) = &o.settings {
        check_str("options.settings.hostname", &s.hostname, 63)?;
        check_str("options.settings.timezone", &s.timezone, 64)?;
        check_str("options.settings.locale", &s.locale, 32)?;
        check_str("options.settings.keyboard", &s.keyboard, 40)?;
    }
    Ok(())
}

fn check_setup_progress(p: &pb::SetupProgress) -> Result<(), ProtoError> {
    check_str("progress.step", &p.step, 128)?;
    if p.percent > 100 && p.percent != 255 {
        return Err(invalid("progress.percent", "must be 0..=100 or 255"));
    }
    Ok(())
}

fn check_setup_result(r: &pb::SetupResult) -> Result<(), ProtoError> {
    check_str("result.reason", &r.reason, 256)?;
    if r.warnings.len() > MAX_SETUP_WARNINGS {
        return Err(invalid("result.warnings", "too many warnings"));
    }
    for w in &r.warnings {
        check_str("result.warnings", w, 256)?;
    }
    if let Some(d) = &r.docker {
        check_str("result.docker.docker_version", &d.docker_version, 64)?;
        check_str("result.docker.found", &d.found, 64)?;
        check_str("result.docker.required", &d.required, 64)?;
        check_str("result.docker.hint", &d.hint, 256)?;
    }
    if let Some(e) = &r.error {
        check_str("result.error.message", &e.message, 256)?;
    }
    Ok(())
}
