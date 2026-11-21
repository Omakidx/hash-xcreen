//! Internal IPC of hash-xcreen: framing and message schemas for `hx-privd`, the `hx-gatewayd`
//! admin socket and the session link. The contract is `docs/ipc.md`; this crate is its
//! implementation of record for everything below the daemons' logic.
//!
//! # Layers
//!
//! 1. [`frame`]: the one frame shape (`u32` LE length, kind byte, body) and an incremental
//!    [`frame::Decoder`] that checks every limit **before allocating**. A
//!    [`frame::FramePolicy`] says which kinds and lengths a stream accepts.
//! 2. [`recv`]: reading with `recvmsg` so that a control message or `MSG_CTRUNC` (a descriptor
//!    sent with `SCM_RIGHTS`, for example) is refused, never installed. Always read sockets
//!    through [`recv::NoCmsgReader`] or [`recv::recv_no_cmsg`].
//! 3. Messages and rules per socket: [`privd`] and [`admin`] (feature `privd`), [`link`]
//!    (feature `link`).
//!
//! # Features
//!
//! | Feature | Contents | Extra dependencies |
//! |---|---|---|
//! | `privd` (default) | `hx.privd.v1` and `hx.gatewayd_admin.v1` schemas, [`privd`], [`admin`], [`secret`], [`peer`] | none |
//! | `link` (default) | `hx.link.v1` schema and [`link`] | `hx-proto` (the shared `hx.v1` types) |
//!
//! `hx-session` enables only `link` (`default-features = false, features = ["link"]`): it
//! compiles neither the privd messages nor anything that pulls in `quinn` (this crate has no
//! network dependency at all).
//!
//! # Reading a stream
//!
//! ```
//! # #[cfg(feature = "privd")] {
//! use hx_ipc::frame::Decoder;
//! use hx_ipc::privd::{self, PrivdPolicy, Side, pb};
//!
//! // A caller encodes a Ping; privd's side of the socket decodes it.
//! let ping = pb::Frame { frame: Some(pb::frame::Frame::Ping(pb::Ping { nonce: 7 })) };
//! let wire = privd::encode_message(&ping, Side::Server).unwrap();
//!
//! let mut decoder = Decoder::new(PrivdPolicy::new(Side::Server));
//! let mut input = &wire[..]; // for a socket: hx_ipc::recv::NoCmsgReader(&stream)
//! let raw = decoder.read_from(&mut input).unwrap().unwrap();
//! match privd::decode(raw, Side::Server).unwrap() {
//!     privd::Incoming::Message(f) => assert_eq!(f, ping),
//!     privd::Incoming::Secret(_) => unreachable!(),
//! }
//! # }
//! ```
//!
//! Errors from the decoder, from `decode`/`parse` and from the `validate_*` functions are all
//! **violations** of the peer's: close the connection (privd, admin) or drop the link (session
//! link, `docs/ipc.md` section 19.2). Transport errors are [`ReadError::Io`].
//!
//! # Not here
//!
//! * the time limits (5 s hello, 5 s body, 10 minute idle) are constants for the I/O layer
//!   (`privd::HELLO_TIMEOUT` and friends); this crate never sleeps;
//! * `mlock`, `PR_SET_DUMPABLE` and `openat2` belong to privd itself;
//! * the HPKE sealed form of secrets (Phase 2): only the proto fields are reserved;
//! * the H.264 Annex B / SPS sanity check of `docs/ipc.md` section 15.1 (it needs the stream
//!   state of the relay and belongs with the gateway's media path).

#![forbid(unsafe_code)]

pub mod error;
pub mod frame;
pub mod recv;
pub mod text;

#[cfg(feature = "privd")]
pub mod admin;
#[cfg(feature = "privd")]
pub mod peer;
#[cfg(feature = "privd")]
pub mod privd;
#[cfg(feature = "privd")]
pub mod secret;

#[cfg(feature = "link")]
pub mod link;

/// Generated code for `hx.privd.v1` and `hx.gatewayd_admin.v1`.
#[cfg(feature = "privd")]
#[allow(clippy::all, missing_docs)]
mod generated_privd {
    include!(concat!(env!("OUT_DIR"), "/_privd_includes.rs"));
}

/// Generated code for `hx.link.v1`.
#[cfg(feature = "link")]
#[allow(clippy::all, missing_docs)]
mod generated_link {
    include!(concat!(env!("OUT_DIR"), "/_link_includes.rs"));
}

pub use error::{AncillaryData, FrameError, ReadError};
pub use frame::{Decoder, FramePolicy, RawFrame};
pub use recv::{NoCmsgReader, recv_no_cmsg};
