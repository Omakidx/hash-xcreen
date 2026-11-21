//! In-container session daemon: capture, encode, audio, clipboard and input. Holds no secrets.
//!
//! This library holds the protocol-independent media path of the daemon: [`pipeline`] runs
//! capture, colour conversion and x264 encoding on dedicated threads and hands out
//! [`hx_codec::EncodedFrame`]s plus a separate cursor event stream. The session link ([`link`])
//! wires it, the congestion controller, the input gate and the clipboard to the gateway.
//!
//! The pipeline lives here, not in `hx-capture` or `hx-codec`, because it is the only place
//! that needs both: `hx-codec` is also the client's decoder crate and must not pull in X11,
//! and `hx-capture` must not know about video codecs.

#![deny(unsafe_code)]

pub mod clipboard;
pub mod congestion;
pub mod input;
pub mod link;
pub mod pacing;
pub mod pipeline;
pub mod stats;
