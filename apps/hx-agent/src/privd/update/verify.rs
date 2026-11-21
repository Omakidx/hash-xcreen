//! Signature and digest checks over bytes privd holds in memory or in its own staging file.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Why a verification failed. None of these carry attacker-controlled text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// This build embeds no release key.
    #[error("this build embeds no release signing key")]
    NoKeys,
    /// The signature file is not a minisign signature.
    #[error("the signature file is not a minisign signature")]
    BadSignatureFile,
    /// No embedded key validates the signature (wrong key, altered data, legacy signature).
    #[error("no embedded release key validates the signature")]
    SignatureMismatch,
    /// A key could not be parsed (tests).
    #[error("malformed public key")]
    BadKey,
}

/// Lowercase hex of a byte string.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// SHA-256 of `data` as lowercase hex.
pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// Whether two hex digests are equal, compared in constant time.
pub fn digest_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_answer_and_comparison() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(digest_eq("ab", "ab"));
        assert!(!digest_eq("ab", "ac"));
        assert!(!digest_eq("ab", "abc"));
    }
}
