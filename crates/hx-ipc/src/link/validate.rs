//! Message-level limits of `docs/ipc.md` sections 13, 14 and 16, and the sanitiser for
//! session-supplied text (section 19.1, rule 3).
//!
//! The functions here are stateless. Rules that need the connection's history (the newest frame
//! number, whether `info` was already received, transfer ids in use) have a `check_*` helper that
//! takes that history as an argument.

use hx_proto::VideoCodec;
use hx_proto::message::file_name_problem;
use hx_proto::order::serial_gt;

use super::frames::wire_validate;
use super::{Role, pb};
use crate::error::FrameError;

/// `info.features` bit: audio.
pub const FEATURE_AUDIO: u64 = 1 << 0;
/// `info.features` bit: clipboard.
pub const FEATURE_CLIPBOARD: u64 = 1 << 1;
/// `info.features` bit: file transfer.
pub const FEATURE_FILE_TRANSFER: u64 = 1 << 2;
/// `info.features` bit: input injection (XTest) available.
pub const FEATURE_INPUT: u64 = 1 << 8;
/// `info.features` bit: RandR resize available.
pub const FEATURE_RESIZE: u64 = 1 << 9;

/// Longest `info.software`.
pub const MAX_SOFTWARE_LEN: usize = 128;
/// Longest event or goodbye `message`.
pub const MAX_MESSAGE_LEN: usize = 256;
/// At most this many codecs in `info`.
pub const MAX_INFO_CODECS: usize = 4;
/// At most this many results in one `frame_feedback`.
pub const MAX_FEEDBACK_RESULTS: usize = 64;
/// Display and stream dimension limit per side.
pub const MAX_DIMENSION: u32 = 16_384;
/// `width * height` limit (7680 x 4320).
pub const MAX_PIXELS: u64 = 33_177_600;
/// Frame rate ceiling.
pub const MAX_FPS: u32 = 240;
/// `bitrate_cap_kbps` range when not 0.
pub const BITRATE_CAP_KBPS: std::ops::RangeInclusive<u32> = 100..=100_000;
/// `scale_percent` range when not 0.
pub const SCALE_PERCENT: std::ops::RangeInclusive<u32> = 50..=400;
/// Largest clipboard transfer.
pub const MAX_CLIPBOARD_BYTES: u64 = 64 * 1024 * 1024;
/// Default file-size limit (4 GiB, configurable lower).
pub const DEFAULT_MAX_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// How far behind the newest frame number `stream_format.first_frame` may be.
pub const FIRST_FRAME_BEHIND: u32 = 8;
/// How far ahead of the newest frame number `stream_format.first_frame` may be.
pub const FIRST_FRAME_AHEAD: u32 = 1_024;
/// How far behind the newest frame number `cancel_frames.up_to_frame` may be.
pub const CANCEL_BEHIND: u32 = 256;

fn require(cond: bool, what: &'static str) -> Result<(), FrameError> {
    if cond {
        Ok(())
    } else {
        Err(FrameError::Invalid(what))
    }
}

pub use crate::text::sanitize_text;

/// `StreamConfig` ranges (section 14.1): the gateway before sending, the session on receipt.
///
/// An unsupported `codec` is not an error here: the session ignores it and answers with a
/// `CAPTURE_ERROR` event, see [`config_codec_supported`].
pub fn validate_stream_config(c: &pb::StreamConfig) -> Result<(), FrameError> {
    require(
        c.max_fps == 0 || (1..=MAX_FPS).contains(&c.max_fps),
        "stream_config.max_fps",
    )?;
    require(
        c.bitrate_cap_kbps == 0 || BITRATE_CAP_KBPS.contains(&c.bitrate_cap_kbps),
        "stream_config.bitrate_cap_kbps",
    )?;
    let size_unset = c.width == 0 && c.height == 0;
    let size_set =
        (1..=MAX_DIMENSION).contains(&c.width) && (1..=MAX_DIMENSION).contains(&c.height);
    require(size_unset || size_set, "stream_config.width/height")?;
    require(
        c.scale_percent == 0 || SCALE_PERCENT.contains(&c.scale_percent),
        "stream_config.scale_percent",
    )
}

/// True if `codec` may be produced in v1 (`H264`); 0 (unset on a `reconfigure`) keeps the
/// current codec.
pub fn config_codec_supported(c: &pb::StreamConfig) -> bool {
    matches!(
        VideoCodec::try_from(c.codec),
        Ok(VideoCodec::H264 | VideoCodec::Unspecified)
    )
}

/// `stream_format` rules (section 13). `newest_frame` is the newest frame number the gateway has
/// received on `media`, if any; `negotiated` the codecs from `info` intersected with policy.
pub fn check_stream_format(
    f: &pb::StreamFormat,
    newest_frame: Option<u32>,
    negotiated: &[VideoCodec],
) -> Result<(), FrameError> {
    require(
        (1..=MAX_DIMENSION).contains(&f.width) && (1..=MAX_DIMENSION).contains(&f.height),
        "stream_format.width/height",
    )?;
    require(
        u64::from(f.width) * u64::from(f.height) <= MAX_PIXELS,
        "stream_format.pixels",
    )?;
    require((1..=MAX_FPS).contains(&f.fps), "stream_format.fps")?;
    let codec = VideoCodec::try_from(f.codec).ok();
    require(
        codec.is_some_and(|c| c != VideoCodec::Unspecified && negotiated.contains(&c)),
        "stream_format.codec",
    )?;
    if let Some(newest) = newest_frame {
        let first = f.first_frame;
        let behind = newest.wrapping_sub(first) <= FIRST_FRAME_BEHIND && !serial_gt(first, newest);
        let ahead = serial_gt(first, newest) && first.wrapping_sub(newest) <= FIRST_FRAME_AHEAD;
        require(
            behind || ahead || first == newest,
            "stream_format.first_frame",
        )?;
    }
    Ok(())
}

/// `cancel_frames` rule (section 13): not newer than the newest frame received and not more
/// than 256 behind it. A failure means "ignore and count", not a violation.
pub fn check_cancel_frames(up_to_frame: u32, newest_frame: u32) -> bool {
    !serial_gt(up_to_frame, newest_frame) && newest_frame.wrapping_sub(up_to_frame) <= CANCEL_BEHIND
}

/// `info` rules (section 13): text length, display size, codec count. `info` is accepted once
/// per link as the first `ctl` message; enforcing that is the caller's (a second `info` is a
/// violation).
pub fn validate_info(i: &pb::Info) -> Result<(), FrameError> {
    require(i.software.len() <= MAX_SOFTWARE_LEN, "info.software")?;
    require(i.codecs.len() <= MAX_INFO_CODECS, "info.codecs")?;
    let d = i.display.as_ref();
    require(
        d.is_some_and(|d| {
            (1..=MAX_DIMENSION).contains(&d.width) && (1..=MAX_DIMENSION).contains(&d.height)
        }),
        "info.display",
    )
}

/// Rules for a message from the session, applied before the gateway acts on it: string lengths,
/// the shared cursor validation (protocol.md section 5.4), `info` and enum values.
pub fn validate_session_message(m: &pb::SessionToGateway) -> Result<(), FrameError> {
    use pb::session_to_gateway::Message as M;
    match &m.message {
        None => Ok(()),
        Some(M::Info(i)) => validate_info(i),
        Some(M::StreamFormat(_)) => Ok(()),
        Some(M::Cursor(c)) => wire_validate(c),
        Some(M::CancelFrames(_)) | Some(M::Stats(_)) | Some(M::Pong(_)) => Ok(()),
        Some(M::Event(e)) => {
            require(e.message.len() <= MAX_MESSAGE_LEN, "event.message")?;
            require(
                e.kind != 0 && pb::EventKind::try_from(e.kind).is_ok(),
                "event.kind",
            )
        }
        Some(M::Goodbye(g)) => require(g.message.len() <= MAX_MESSAGE_LEN, "goodbye.message"),
    }
}

/// Rules for a message from the gateway, applied before sending and again on receipt.
pub fn validate_gateway_message(m: &pb::GatewayToSession) -> Result<(), FrameError> {
    use pb::gateway_to_session::Message as M;
    match &m.message {
        None => Ok(()),
        Some(M::Start(s)) => s.config.as_ref().map_or(Ok(()), validate_stream_config),
        Some(M::Reconfigure(r)) => r.config.as_ref().map_or(Ok(()), validate_stream_config),
        Some(M::Input(e)) => wire_validate(e),
        Some(M::FrameFeedback(f)) => {
            require(
                f.results.len() <= MAX_FEEDBACK_RESULTS,
                "frame_feedback.results",
            )?;
            require(
                f.results
                    .iter()
                    .all(|r| r.outcome != 0 && pb::FrameOutcome::try_from(r.outcome).is_ok()),
                "frame_feedback.outcome",
            )
        }
        Some(M::Goodbye(g)) => require(g.message.len() <= MAX_MESSAGE_LEN, "goodbye.message"),
        Some(M::Stop(_))
        | Some(M::RequestIdr(_))
        | Some(M::Mouse(_))
        | Some(M::TransportStats(_))
        | Some(M::ClientStats(_))
        | Some(M::Ping(_)) => Ok(()),
    }
}

/// `TransferOpen` rules (section 16): non-zero id of the sender's parity (odd from the gateway,
/// even from the session), a known channel, the protocol header validation (printable-ASCII
/// `mime`, file-name rules), an empty name and the 64 MiB limit for the clipboard, and
/// `max_file_bytes` for files. `sender` is the role that sent the open.
pub fn validate_transfer_open(
    open: &pb::TransferOpen,
    sender: Role,
    max_file_bytes: u64,
) -> Result<(), FrameError> {
    let odd = open.id % 2 == 1;
    require(
        open.id != 0 && odd == (sender == Role::Gateway),
        "transfer_open.id",
    )?;
    let header = open
        .header
        .as_ref()
        .ok_or(FrameError::Invalid("transfer_open.header"))?;
    wire_validate(header)?;
    match pb::TransferChannel::try_from(open.channel) {
        Ok(pb::TransferChannel::Clipboard) => header
            .validate_clipboard()
            .map_err(|e| FrameError::Proto(e.to_string())),
        Ok(pb::TransferChannel::File) => {
            require(!header.name.is_empty(), "transfer_open.header.name")?;
            require(
                file_name_problem(&header.name).is_none(),
                "transfer_open.header.name",
            )?;
            require(header.size <= max_file_bytes, "transfer_open.header.size")
        }
        _ => Err(FrameError::Invalid("transfer_open.channel")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_frames_window() {
        assert!(check_cancel_frames(100, 100));
        assert!(check_cancel_frames(100u32.wrapping_sub(256), 100));
        assert!(!check_cancel_frames(100u32.wrapping_sub(257), 100));
        assert!(!check_cancel_frames(101, 100));
        // across the wrap
        assert!(check_cancel_frames(u32::MAX - 3, 5));
        assert!(!check_cancel_frames(6, 5));
    }

    #[test]
    fn first_frame_window() {
        let f = |first| pb::StreamFormat {
            epoch: 1,
            codec: VideoCodec::H264 as i32,
            width: 1920,
            height: 1080,
            fps: 60,
            first_frame: first,
        };
        let codecs = [VideoCodec::H264];
        assert!(check_stream_format(&f(1_000), Some(1_000), &codecs).is_ok());
        assert!(check_stream_format(&f(992), Some(1_000), &codecs).is_ok());
        assert!(check_stream_format(&f(991), Some(1_000), &codecs).is_err());
        assert!(check_stream_format(&f(2_024), Some(1_000), &codecs).is_ok());
        assert!(check_stream_format(&f(2_025), Some(1_000), &codecs).is_err());
        assert!(check_stream_format(&f(7), Some(u32::MAX - 2), &codecs).is_ok());
        assert!(check_stream_format(&f(1_000_000), None, &codecs).is_ok());
    }
}
