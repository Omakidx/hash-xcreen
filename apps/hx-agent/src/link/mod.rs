//! Gateway side of the session link to hx-session (ipc.md Part 2).
//!
//! `hx-gatewayd` dials the desktop, relays what the client needs to the session and treats
//! **every byte the session sends as hostile** (the session runs as the desktop user inside the
//! container; malware there has the same uid). This module is the transport-agnostic client of
//! the link: it knows nothing about QUIC, WebSocket or the gateway's authentication. The
//! gateway core plugs a desktop in through [`LinkClient`] and [`LinkEvents`] (or
//! [`LinkKeeper`], which adds the redial policy and the 30 s keep).
//!
//! # Using it
//!
//! ```no_run
//! # use hx_agent::link::{LinkClient, LinkConfig, LinkEvent};
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! let (link, mut events) =
//!     LinkClient::connect("/run/hx/link/desktop.sock", LinkConfig::default()).await?;
//! // Start streaming for client epoch 1.
//! link.start(
//!     1,
//!     hx_ipc::link::pb::StreamConfig {
//!         codec: hx_proto::VideoCodec::H264 as i32,
//!         clipboard_enabled: true,
//!         file_transfer_enabled: true,
//!         ..Default::default()
//!     },
//! )?;
//! loop {
//!     match events.next().await {
//!         LinkEvent::Frame(f) => {
//!             // f.wire() is the body of the client's video stream (media header + payload);
//!             // f.number(), f.is_key(), f.is_resync(), f.format give the rest.
//!             # let _ = f;
//!         }
//!         LinkEvent::Closed(why) => break println!("link ended: {:?}", why.class),
//!         other => { # let _ = other; }
//!     }
//! }
//! # Ok(()) }
//! ```
//!
//! # What the gateway core must do
//!
//! * Send a [`FrameResult`](hx_ipc::link::pb::FrameResult) per frame through
//!   [`LinkClient::frame_feedback`] as soon as it is known: `DELIVERED` with `bytes`, `elapsed_us`
//!   and `queued_us`, or `CANCELLED`/`REJECTED`/`DROPPED`. The session's congestion controller
//!   lives on this feedback.
//! * Build the client's `StreamInfo` from [`Frame::format`] (the format in force for that frame,
//!   with `first_frame`) and forward [`Frame::wire`] unchanged as the video stream body.
//! * On [`LinkEvent::CancelFrames`] reset the client streams numbered up to `up_to_frame` with
//!   `STALE_FRAME`.
//! * Never forward a session-supplied string to a client ([`SessionEvent::message`],
//!   [`SessionInfo::software`] are log-only). The only text that may reach a client is a file
//!   name in a [`TransferEvent::Open`], which has passed the protocol.md validation.
//! * Report [`LinkEvent::Closed`] to [`LinkKeeper::on_closed`] and send the client
//!   `Goodbye(INTERNAL_ERROR)` for any class except [`FailureClass::Closed`] (an owner's
//!   own close).
//!
//! # Structure and bounds
//!
//! One link is three unix connections (`ctl`, `media`, `bulk`). Tasks, all ending the link
//! together when one fails: a reader per lane, a `ctl` writer with the strict priority order of
//! section 17, a `bulk` writer, and a maintenance task (ping every 2 s, IDR retry).
//!
//! * Reads use `recvmsg` only ([`hx_ipc::recv`]): a descriptor or control message is a
//!   violation. Lengths are checked before allocation. A frame body has a deadline that grows
//!   with its size; `ctl` closes after 10 s of silence; the preamble and `info` have 5 s.
//! * Byte budgets and per-second frame counts of section 13 apply per lane; beyond a byte
//!   budget the lane is simply not read (backpressure), a frame-count overage is a violation.
//! * The video pool holds `max(2 x max_frame_bytes, 12 MiB)`. The media lane is **always
//!   drained**: when the consumer is slow the oldest queued frames are evicted, reported
//!   `DROPPED`, and the link client discards non-key frames until a `KEY | RESYNC` frame and asks
//!   for an IDR (2 per second at most). A slow client therefore never pauses the session's writer.
//! * Incoming transfer data is limited to 1 MiB unread per transfer and 4 MiB per link: a
//!   consumer that does not drop its [`TransferChunk`]s pauses `bulk` and nothing else.
//! * Input is P0 (4 096 deep), pointer motion is a single coalescing slot (at most 1 000 per
//!   second), feedback and control are P1, statistics and goodbye are P2. A queue that fills
//!   because the session does not read ends the link as a fault.
//!
//! # Link loss
//!
//! [`FailureClass`] separates "desktop unavailable" (refused, reset after accept, silent), an
//! outdated or incompatible session, a protocol violation, other faults and a deliberate close.
//! [`ReconnectPolicy`] turns that into the redial schedule of section 19.2 and [`LinkKeeper`]
//! adds the 30 s keep after the last client (section 18).

pub mod annexb;
mod client;
mod config;
mod connect;
mod lane;
mod policy;
mod shared;
mod tasks;
mod types;

pub use client::{LinkClient, LinkEvents, TransferSender};
pub use config::LinkConfig;
pub use policy::{
    Advice, Attached, BACKOFF_MAX, BACKOFF_MIN, DesktopState, DialError, FAULT_WINDOW,
    FAULTS_BEFORE_RESTART, IDLE_KEEP, INSTALLS_BEFORE_UNAVAILABLE, LinkKeeper,
    OUTDATED_GUESS_AFTER, RESTART_WINDOW, RESTARTS_BEFORE_UNAVAILABLE, ReconnectPolicy,
    UNAVAILABLE_RETRY,
};
pub use types::{
    ConnectError, Counters, CursorUpdate, FailureClass, Frame, LinkClosed, LinkEvent, SendError,
    SessionEvent, SessionInfo, StreamFormat, TransferChunk, TransferError, TransferEvent,
};
