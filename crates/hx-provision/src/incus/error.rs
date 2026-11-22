//! Errors of the Incus client.

use std::time::Duration;

/// Everything that can go wrong talking to Incus.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum IncusError {
    /// The socket could not be reached (not running, permission denied, wrong path).
    #[error("cannot reach Incus at `{path}`: {message}")]
    Connect {
        /// Socket path.
        path: String,
        /// OS error text.
        message: String,
    },
    /// The HTTP exchange failed after connecting.
    #[error("Incus HTTP error: {0}")]
    Http(String),
    /// A request or a background operation took too long.
    #[error("timed out after {after:?} waiting for {what}")]
    Timeout {
        /// What was awaited.
        what: String,
        /// How long we waited.
        after: Duration,
    },
    /// Incus answered with an error.
    #[error("Incus API error {code}: {message}")]
    Api {
        /// HTTP / API error code (404 = not found).
        code: u16,
        /// Message from Incus.
        message: String,
    },
    /// A response body exceeded the limit set for the request.
    #[error("response larger than {limit} bytes")]
    TooLarge {
        /// The limit.
        limit: usize,
    },
    /// The response did not have the documented shape.
    #[error("unexpected Incus response: {0}")]
    Protocol(String),
    /// A background operation finished unsuccessfully.
    #[error("Incus operation failed: {0}")]
    Operation(String),
    /// The daemon had already purged the operation when its result was asked for, so whether it
    /// succeeded is unknown. Mutating calls re-read the state and only report this when the
    /// intended result is not there.
    #[error(
        "the result of {0} is unknown (the operation was purged) and the intended state is not in place"
    )]
    Purged(String),
    /// A name that would not be a valid single path segment or Incus name.
    #[error("invalid {what} name `{name}`")]
    InvalidName {
        /// What kind of object.
        what: &'static str,
        /// The rejected name.
        name: String,
    },
    /// The transport cannot do this (a scripted fake without streaming upload).
    #[error("not supported by this transport: {0}")]
    Unsupported(String),
    /// A value passed by the caller is not acceptable.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}

impl IncusError {
    /// Incus said the object does not exist.
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::Api { code: 404, .. })
    }
}
