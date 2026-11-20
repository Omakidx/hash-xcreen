//! The encode side: colour conversion and the x264 H.264 encoder.
//!
//! Frames flow `BGRX pixels --convert_bgrx--> YuvFrame --X264Encoder::encode--> EncodedFrame`.
//! Both ends reuse their buffers, so the steady state does not allocate.

mod convert;
pub mod h264;
mod x264;

pub use convert::{Plane, YuvFormat, YuvFrame, convert_bgrx, even_size};
pub use x264::{EncoderConfig, FrameMeta, X264Encoder};

use thiserror::Error;

/// Encoding failures. The encoder never panics on bad input or libavcodec errors.
#[derive(Debug, Error)]
pub enum EncodeError {
    /// A setting or an input picture is invalid.
    #[error("invalid encoder input: {0}")]
    Config(String),
    /// The FFmpeg build has no libx264.
    #[error("libx264 is not available in this FFmpeg build")]
    EncoderMissing,
    /// libavcodec refused to open the encoder.
    #[error("cannot open the encoder: {0}")]
    Open(ffmpeg_next::Error),
    /// libavcodec failed while encoding.
    #[error("encoding failed: {0}")]
    Encode(ffmpeg_next::Error),
    /// Colour conversion failed.
    #[error("colour conversion failed: {0}")]
    Convert(String),
}
