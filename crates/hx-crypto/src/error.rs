//! Errors of the crypto and pairing layer. None of them carries secret material.

use hx_proto::pb::RefuseReason;

/// Result alias.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Why a key, secret, registry or protocol operation failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Bytes are not a valid Ed25519 public key (or are a weak one).
    #[error("invalid public key")]
    InvalidKey,
    /// The system random source failed.
    #[error("random source failure")]
    Random,
    /// TLS configuration could not be built.
    #[error("TLS configuration: {0}")]
    Tls(String),
    /// A token, code or PIN was not in the accepted format.
    #[error("invalid secret format: {0}")]
    InvalidSecret(&'static str),
    /// A stored value (registry file, PIN hash) is malformed.
    #[error("corrupt stored data: {0}")]
    Corrupt(String),
    /// The registry file has permissions that expose it to other users.
    #[error("registry file permissions are too open (need 0600)")]
    InsecurePermissions,
    /// Another registry instance already holds the single-writer lock.
    #[error("the device registry is locked by another instance")]
    Locked,
    /// Reading or writing the registry failed.
    #[error("registry I/O: {0}")]
    Io(#[from] std::io::Error),
    /// The device is not in the registry.
    #[error("unknown device")]
    UnknownDevice,
    /// Pairing failed. The client cannot tell a wrong code, an expired token and an
    /// interception apart (and must not try to).
    #[error("pairing failed: wrong or expired code, or the connection is being intercepted")]
    PairingFailed,
    /// The server has no pairing window open.
    #[error("pairing is closed on this server")]
    PairingClosed,
    /// The peer broke the pairing or authentication protocol.
    #[error("protocol violation: {0}")]
    Protocol(&'static str),
    /// The device was revoked (by the server, or by too many wrong PINs).
    #[error("this device has been revoked")]
    Revoked,
    /// The server refused the connection.
    #[error("refused by server ({reason:?}): {message}")]
    Refused {
        /// Reason code.
        reason: RefuseReason,
        /// Server text (untrusted, may be shown).
        message: String,
    },
    /// The PIN was wrong.
    #[error("wrong PIN ({attempts_left} attempts left before this device is revoked)")]
    WrongPin {
        /// Wrong PINs still allowed.
        attempts_left: u32,
        /// How long to wait before the next attempt.
        retry_after: std::time::Duration,
    },
    /// Too soon after a wrong PIN.
    #[error("too many attempts; retry in {retry_after:?}")]
    Backoff {
        /// Remaining wait.
        retry_after: std::time::Duration,
    },
    /// The server cannot verify a PIN (none configured).
    #[error("the server has no PIN configured")]
    PinNotAvailable,
    /// The server closed the setup connection with `SETUP_CLOSED` (protocol 1.3 §5.10): setup
    /// is not open for this device (finished, window closed, binding moved). Go to the normal
    /// PIN login.
    #[error("setup is closed on this server")]
    SetupClosed,
    /// The server is older than protocol 1.3 (or was never confirmed to be newer): the
    /// feature cannot be used. The user must update the server.
    #[error("the server must be updated to protocol 1.3 or newer")]
    UpdateRequired,
    /// The server rate-limited the request (for example pairing codes: 3 per hour).
    #[error("rate limited; retry in {retry_after:?}")]
    RateLimited {
        /// How long to wait, as told by the server (zero if it did not say).
        retry_after: std::time::Duration,
    },
    /// The server reported a fault of its own for the request.
    #[error("the server could not complete the request")]
    ServerFailed,
    /// The operation did not finish in time.
    #[error("timed out: {0}")]
    Timeout(&'static str),
    /// Transport failure.
    #[error("transport: {0}")]
    Transport(#[from] hx_transport::Error),
    /// Message could not be encoded or decoded.
    #[error("message: {0}")]
    Message(#[from] hx_proto::ProtoError),
}
