//! Video: a decode thread (software FFmpeg H.264 into RGBA), a frame pool, stats, and the
//! presentation behind the [`Presenter`] trait.
//!
//! Only the CPU-upload path exists ([`CpuPresenter`]: a Slint `Image` from a `SharedPixelBuffer`).
//! The VAAPI to DMA-BUF to OpenGL path of spike S1 plugs in later by implementing [`Presenter`];
//! nothing else changes (no GPU code here).

pub mod decode;
pub mod pool;
pub mod present;
pub mod stats;
pub mod worker;

pub use decode::{DecodeError, Decoder, Picture, yuv420_to_rgba};
pub use pool::FramePool;
pub use present::{CpuPresenter, FrameSink, PresentKind, Presenter};
pub use stats::Stats;
pub use worker::{DecodeThread, spawn_decoder};
