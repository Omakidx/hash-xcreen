use crate::pool::PooledBuf;

/// Video codecs this crate can produce.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Codec {
    /// H.264 in Annex B byte-stream form, SPS/PPS repeated on every keyframe.
    H264,
}

/// Monotonic timestamps ([`crate::mono_ns`]) taken as a frame moved through the pipeline,
/// 0 when a stage did not record one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FrameTiming {
    /// The damage behind this frame first arrived.
    pub t_damage_ns: u64,
    /// The screen was read.
    pub t_capture_ns: u64,
    /// Colour conversion finished.
    pub t_convert_ns: u64,
    pub t_encode_start_ns: u64,
    pub t_encode_end_ns: u64,
}

/// One encoded video frame, ready to be framed and sent.
#[derive(Debug)]
pub struct EncodedFrame {
    /// Counts encoded frames from 0 on this encoder; restarts if the encoder is recreated.
    pub frame_no: u64,
    pub codec: Codec,
    /// A client can start decoding here: an IDR frame, or a recovery point when gradual
    /// intra refresh is on.
    pub keyframe: bool,
    /// An IDR frame: every earlier frame can be forgotten. A client that joins or resyncs
    /// needs this, and it is what [`crate::encode::X264Encoder::request_idr`] produces.
    pub idr: bool,
    pub width: u32,
    pub height: u32,
    /// Average quantiser (H.264 QP, 0 to 51) the rate control chose for the frame, when the
    /// encoder reports it. A key frame far above the `crf` target was starved by the VBV: its
    /// picture is coarse until later frames refine it.
    pub qp: Option<u8>,
    pub timing: FrameTiming,
    /// The bitstream; returned to the encoder's pool when dropped.
    pub data: PooledBuf,
}

impl EncodedFrame {
    /// The bitstream bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }
}
