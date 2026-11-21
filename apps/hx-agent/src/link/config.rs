//! Settings of the gateway end of the session link. The defaults are the numbers of
//! `docs/ipc.md` Part 2.

use hx_ipc::link::{DEFAULT_MAX_FRAME_BYTES, MAX_FRAME_BYTES_CEILING};
use hx_proto::VideoCodec;
use std::time::Duration;

/// Configuration of one [`LinkClient`](super::LinkClient).
#[derive(Debug, Clone)]
pub struct LinkConfig {
    /// Largest video payload accepted (section 13): 4 MiB by default, up to the protocol's
    /// 16 MiB. It also sizes the video pool: `max(2 x max_frame_bytes, 12 MiB)`.
    pub max_frame_bytes: u32,
    /// Largest file accepted from the session and sent to it (section 16): 4 GiB by default,
    /// configurable lower.
    pub max_file_bytes: u64,
    /// Codecs the gateway accepts; the negotiated set is the intersection with `info.codecs`.
    /// Audio is not negotiated in Phase 1.
    pub codecs: Vec<VideoCodec>,
    /// Frame-rate ceiling the gateway expects (`StreamConfig.max_fps`, 0: unknown). With the
    /// session's own `info.max_fps` it sets the video rate limit of `2 x max_fps` frames per
    /// second.
    pub max_fps: u32,
    /// Whether session-initiated clipboard transfers are accepted. Changeable at runtime with
    /// [`LinkClient::set_policy`](super::LinkClient::set_policy).
    pub clipboard_allowed: bool,
    /// Whether file transfers are accepted and may be sent. Changeable at runtime.
    pub files_allowed: bool,
    /// Timeout of each `connect(2)`.
    pub connect_timeout: Duration,
    /// Preamble and `info` must complete within this long of connecting (5 s, section 12.2).
    pub handshake_timeout: Duration,
    /// The extra lanes must be answered within this long after `info` (5 s).
    pub extra_lanes_timeout: Duration,
    /// `ping` period (2 s, section 12.3).
    pub ping_interval: Duration,
    /// No `ctl` traffic from the session for this long closes the link (10 s).
    pub liveness_timeout: Duration,
    /// A write on `ctl` that makes no progress for this long is a link fault (2 s, section 17).
    pub ctl_write_stall: Duration,
    /// The same for `bulk` (the lowest priority lane; a stalled session must not hold it forever).
    pub bulk_write_stall: Duration,
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            max_file_bytes: hx_proto::channel::MAX_FILE_SIZE,
            codecs: vec![VideoCodec::H264],
            max_fps: 0,
            clipboard_allowed: true,
            files_allowed: true,
            connect_timeout: Duration::from_secs(3),
            handshake_timeout: Duration::from_secs(5),
            extra_lanes_timeout: Duration::from_secs(5),
            ping_interval: Duration::from_secs(2),
            liveness_timeout: Duration::from_secs(10),
            ctl_write_stall: Duration::from_secs(2),
            bulk_write_stall: Duration::from_secs(15),
        }
    }
}

impl LinkConfig {
    /// The video pool: at least one maximum-size frame, in fact two (section 13).
    pub fn video_pool_bytes(&self) -> u64 {
        (u64::from(self.max_frame_bytes) * 2).max(12 * 1024 * 1024)
    }

    /// Checks the values against the contract's ranges.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !(1..=MAX_FRAME_BYTES_CEILING).contains(&self.max_frame_bytes) {
            return Err("max_frame_bytes outside 1 to 16 MiB");
        }
        if self.max_file_bytes == 0 || self.max_file_bytes > hx_proto::channel::MAX_FILE_SIZE {
            return Err("max_file_bytes outside 1 to 4 GiB");
        }
        if self.max_fps > 240 {
            return Err("max_fps above 240");
        }
        if self.codecs.is_empty() {
            return Err("no codec allowed");
        }
        Ok(())
    }
}
