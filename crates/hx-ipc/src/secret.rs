//! Secrets and the raw secret frame (`docs/ipc.md` section 5.2).
//!
//! A secret never passes through `prost`: it travels in a kind-2 frame whose body is
//! `request_id` (u64 LE) + `slot` (u8) + the raw bytes. [`Secret`] holds those bytes.

use bytes::BytesMut;
use zeroize::{Zeroize, Zeroizing};

use crate::error::FrameError;

/// Bytes of the secret frame body before the secret: `request_id` and `slot`.
pub const SECRET_HEADER_LEN: usize = 9;

/// Bytes that are secret material, zeroized on drop.
///
/// Deliberately **not** `Clone`, not `Display`, not comparable with `==`, and its `Debug` shows
/// only the length. Read the bytes with [`Secret::expose`] for as short a time as possible.
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    /// Takes ownership of `bytes`.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The secret bytes. Do not log, format or copy them into long-lived storage.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True if there are no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Constant-time comparison with `other` for equal lengths (the lengths themselves are not
    /// secret). Not for use as a MAC check: use `PepperVerify` for that.
    pub fn ct_eq(&self, other: &[u8]) -> bool {
        if self.0.len() != other.len() {
            return false;
        }
        let mut diff = 0u8;
        for (a, b) in self.0.iter().zip(other) {
            diff |= a ^ b;
        }
        std::hint::black_box(diff) == 0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret(<redacted, {} bytes>)", self.0.len())
    }
}

/// A decoded kind-2 frame.
#[derive(Debug)]
pub struct SecretFrame {
    /// The request this secret belongs to.
    pub request_id: u64,
    /// Which declared slot it fills.
    pub slot: u8,
    /// The raw secret.
    pub secret: Secret,
}

impl SecretFrame {
    /// Parses the body of a kind-2 frame and **zeroizes the input buffer** (the one read from
    /// the socket), so no second long-lived copy remains.
    pub fn from_body(mut body: BytesMut) -> Result<Self, FrameError> {
        let result = (|| {
            if body.len() <= SECRET_HEADER_LEN {
                // Empty secrets do not exist: a slot declares length >= 1.
                return Err(FrameError::BadBody("secret"));
            }
            let mut id = [0u8; 8];
            id.copy_from_slice(&body[..8]);
            Ok(Self {
                request_id: u64::from_le_bytes(id),
                slot: body[8],
                secret: Secret::new(body[SECRET_HEADER_LEN..].to_vec()),
            })
        })();
        body.as_mut().zeroize();
        result
    }

    /// Encodes the body (without the frame prefix) into a zeroizing buffer.
    pub fn encode_body(request_id: u64, slot: u8, secret: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(SECRET_HEADER_LEN + secret.len()));
        out.extend_from_slice(&request_id.to_le_bytes());
        out.push(slot);
        out.extend_from_slice(secret);
        out
    }
}
