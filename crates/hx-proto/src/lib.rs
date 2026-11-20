//! Wire protocol: protobuf control messages, binary media headers and versioning.
//!
//! This crate is the pure (no I/O) half of protocol 1.0 as specified in `docs/protocol.md`:
//!
//! * [`pb`]: the generated protobuf types (`hx.v1`), plus [`message`] with strict, total
//!   encode/decode/validate entry points and length-prefix framing;
//! * [`media`]: the fixed 20-byte little-endian video header;
//! * [`datagram`]: mouse-motion and audio datagram formats, and [`datagram::MouseCoalescer`];
//! * [`channel`]: channel ids, close and reset codes, limits and priorities;
//! * [`version`]: version and capability negotiation as pure functions;
//! * [`order`]: the client-side frame [`order::ReorderWindow`].
//!
//! Everything here is safe to run on untrusted network input: decoders never panic and check
//! sizes before allocating. [`media::MediaHeader::decode`], [`datagram::decode_datagram`] and
//! [`message::decode`] are the intended fuzz-target entry points.

#![forbid(unsafe_code)]

pub mod channel;
pub mod datagram;
pub mod error;
pub mod media;
pub mod message;
pub mod order;
pub mod version;

/// Generated protobuf types for package `hx.v1` (see `proto/hx.proto`).
#[allow(clippy::all, missing_docs)]
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/hx.v1.rs"));
}

pub use error::ProtoError;
pub use pb::VideoCodec;
