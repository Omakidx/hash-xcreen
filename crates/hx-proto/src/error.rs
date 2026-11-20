//! The single error type of this crate.

use thiserror::Error;

/// Why a piece of network input was rejected. Never carries attacker-controlled bulk data.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProtoError {
    /// Fewer bytes than the format needs.
    #[error("truncated input: need {need} bytes, have {have}")]
    Truncated {
        /// Bytes required.
        need: usize,
        /// Bytes available.
        have: usize,
    },
    /// More bytes than the format allows.
    #[error("{extra} unexpected trailing bytes")]
    TrailingBytes {
        /// Number of surplus bytes.
        extra: usize,
    },
    /// Channel id byte that this protocol version does not define.
    #[error("unknown channel id {0:#04x}")]
    UnknownChannel(u8),
    /// Media header layout version other than 1.
    #[error("unsupported media header version {0}")]
    UnsupportedVersion(u8),
    /// Codec byte that is not a defined codec.
    #[error("unknown codec {0}")]
    UnknownCodec(u8),
    /// Flag bits that this version reserves as zero are set.
    #[error("reserved flag bits set: {0:#06x}")]
    ReservedFlags(u16),
    /// A length above the documented limit.
    #[error("{what} too large: {len} > {max}")]
    TooLarge {
        /// What was measured.
        what: &'static str,
        /// Offending length.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// A zero length where at least one byte is required.
    #[error("{what} must not be empty")]
    Empty {
        /// What was empty.
        what: &'static str,
    },
    /// Protobuf wire-format error.
    #[error("protobuf decode error: {0}")]
    Decode(String),
    /// Well-formed protobuf whose content violates the protocol's rules.
    #[error("invalid {field}: {reason}")]
    Invalid {
        /// Field or message at fault.
        field: &'static str,
        /// What is wrong with it.
        reason: &'static str,
    },
}
