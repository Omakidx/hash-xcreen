//! Video encode and decode through libavcodec, plus colour conversion.
//!
//! This crate currently holds the **encode** side ([`encode`]): BGRA to YUV conversion and an
//! x264 H.264 encoder tuned for remote desktop. The decode side is added next to it in a
//! `decode` module. Everything shared by both directions lives at the crate root:
//! [`Codec`], [`EncodedFrame`] and the timestamp clock.

mod clock;
pub mod encode;
mod frame;
pub mod pool;

pub use clock::mono_ns;
pub use frame::{Codec, EncodedFrame, FrameTiming};
