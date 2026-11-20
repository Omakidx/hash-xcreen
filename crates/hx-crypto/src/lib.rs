//! Identity and device keys, pinned-key mutual TLS, SPAKE2 pairing, PIN verification with
//! lockout, and the device registry (protocol 1.0 §11, architecture §8).
//!
//! * [`keys`]: Ed25519 [`IdentityKey`] / [`PublicKey`], fingerprints, [`DeviceId`].
//! * [`tls`]: rustls configurations that authenticate with raw public keys and pin them.
//! * [`secrets`]: pairing tokens, short codes and PINs (redacted, zeroized).
//! * [`wire`]: the messages inside the pairing and auth envelopes.
//!
//! Everything that can be driven by a peer returns an error instead of panicking, and no
//! secret ever reaches `Debug`, logs or error text.

#![forbid(unsafe_code)]

pub mod clock;
mod encoding;
pub mod error;
pub mod keys;
pub mod secrets;
pub mod tls;
pub mod wire;

pub use clock::{Clock, ManualClock, SystemClock};
pub use error::{Error, Result};
pub use keys::{DeviceId, Fingerprint, IdentityKey, PublicKey};
pub use secrets::{PairingCode, PairingCredential, PairingToken, Pin};
