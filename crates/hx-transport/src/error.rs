//! Errors of the transport layer.

use std::fmt;

use hx_proto::{
    ProtoError,
    channel::CloseCode,
    pb::RefuseReason,
    version::{NegotiateError, ProtocolVersion},
};

/// How and why a connection ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseInfo {
    /// Protocol close code (protocol §8).
    pub code: CloseCode,
    /// Human-readable reason, for logs only.
    pub reason: String,
    /// True if the peer closed, false if this side did.
    pub by_peer: bool,
}

impl fmt::Display for CloseInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} by {}: {}",
            self.code,
            if self.by_peer { "peer" } else { "local side" },
            self.reason
        )
    }
}

/// Transport error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Socket error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// QUIC or WebSocket transport failure.
    #[error("transport error: {0}")]
    Transport(String),
    /// TLS configuration or handshake failure.
    #[error("TLS error: {0}")]
    Tls(String),
    /// The connection is closed.
    #[error("connection closed ({0})")]
    Closed(CloseInfo),
    /// One channel ended without the connection closing.
    #[error("channel closed")]
    ChannelClosed,
    /// The server refused the `Hello` (client side).
    #[error("refused by server: {reason:?}: {message}")]
    Refused {
        /// Why.
        reason: RefuseReason,
        /// Server-provided text, safe to show.
        message: String,
        /// Server's protocol version, if it said.
        server_version: Option<ProtocolVersion>,
    },
    /// Malformed input rejected by `hx-proto`.
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtoError),
    /// Well-formed input that breaks a protocol rule (wrong role, order, feature).
    #[error("protocol violation: {0}")]
    Violation(String),
    /// Version negotiation failed.
    #[error("version negotiation failed: {0}")]
    Version(#[from] NegotiateError),
    /// The operation is not allowed for this side of the connection.
    #[error("{0} is not allowed for this role")]
    WrongRole(&'static str),
    /// The feature behind the operation was not negotiated.
    #[error("feature {0} was not negotiated")]
    FeatureDisabled(&'static str),
    /// A bounded wait expired.
    #[error("timed out: {0}")]
    Timeout(&'static str),
    /// A datagram does not fit in one QUIC datagram.
    #[error("datagram of {len} bytes exceeds the maximum {max}")]
    DatagramTooLarge {
        /// Datagram size.
        len: usize,
        /// Current maximum.
        max: usize,
    },
    /// Invalid configuration passed by the caller.
    #[error("invalid configuration: {0}")]
    Config(String),
    /// Transfer body length differs from the announced size.
    #[error("transfer size does not match its header")]
    TransferSize,
}

/// Result alias.
pub type Result<T, E = Error> = std::result::Result<T, E>;

pub(crate) fn transport<E: fmt::Display>(e: E) -> Error {
    Error::Transport(e.to_string())
}
