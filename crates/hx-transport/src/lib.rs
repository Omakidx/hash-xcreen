//! QUIC and WebSocket-over-TLS transports behind one channel API (protocol 1.0).
//!
//! * [`Server`] binds one QUIC endpoint (ALPN `hx/1`, with a pluggable `h3` slot for the
//!   Phase 3 browser transport) and a WebSocket listener on the same port number. It
//!   yields [`PendingSession`]s whose hello exchange and version check already passed; the
//!   application then calls [`PendingSession::accept`] or [`PendingSession::refuse`].
//! * [`Client`] connects over QUIC, over WebSocket, or QUIC with fallback.
//! * Both produce a [`Connection`] with typed send/receive per channel (control, input,
//!   mouse datagrams, cursor, per-frame video streams with acks, audio datagrams,
//!   clipboard and file transfers) that behaves the same on either transport.
//!
//! TLS is injected: callers pass `rustls` server/client configs (identity, pinning,
//! client-certificate verification). This crate sets only ALPN. The wire format is specified
//! in `docs/protocol.md`; message types live in `hx-proto`.

#![forbid(unsafe_code)]

pub mod ack;
pub mod client;
pub mod conn;
pub mod error;
mod quic;
pub mod server;
pub mod transfer;
mod ws;

#[cfg(feature = "fuzzing")]
pub use ws::fuzz;

pub use ack::{AckHandler, AckOutcome, FrameAck, FrameTicket};
pub use client::{Client, ClientHello, ClientOptions, Target, TransportPreference};
pub use conn::{
    Connection, ConnectionOptions, ConnectionStats, PeerInfo, Role, TransportKind, VideoFrame,
};
pub use error::{CloseInfo, Error, Result};
pub use server::{H3Handler, PendingSession, Server, ServerHello, ServerOptions};
pub use transfer::{IncomingTransfer, TransferKind, TransferSender};
