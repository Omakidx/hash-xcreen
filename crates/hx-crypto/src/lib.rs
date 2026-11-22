//! Identity and device keys, pinned-key mutual TLS, SPAKE2 pairing, PIN verification with
//! lockout, and the device registry (protocol 1.0 §11, architecture §8).
//!
//! * [`keys`]: Ed25519 [`IdentityKey`] / [`PublicKey`], fingerprints, [`DeviceId`].
//! * [`tls`]: rustls configurations that authenticate with raw public keys and pin them.
//! * [`secrets`]: pairing tokens, short codes and PINs (redacted, zeroized).
//! * [`pairing`]: the pairing window and both sides of the SPAKE2 exchange
//!   ([`pair_device`] for clients).
//! * [`pin`]: Argon2id PIN hashes and the backoff schedule.
//! * [`registry`]: the [`DeviceRegistry`] trait with file and memory implementations.
//! * [`auth`]: the server-side [`Authenticator`] that turns a `PendingSession` into a paired
//!   device or an authorized session.
//! * [`session`]: the client side of a session ([`connect_session`], PIN submission).
//! * [`wire`]: the messages inside the pairing and auth envelopes.
//! * [`setup`]: the client side of the post-pairing setup connection (protocol 1.3).
//!
//! Everything that can be driven by a peer returns an error instead of panicking, and no
//! secret ever reaches `Debug`, logs or error text.

#![forbid(unsafe_code)]

pub mod auth;
pub mod clock;
mod encoding;
pub mod error;
#[cfg(feature = "fuzzing")]
pub mod fuzz;
pub mod keys;
pub mod pairing;
pub mod pin;
pub mod registry;
pub mod secrets;
pub mod session;
pub mod setup;
pub mod text;
pub mod tls;
pub mod wire;

pub use auth::{
    Authenticator, AuthenticatorConfig, BoxFuture, DEFAULT_LOCKED_WAIT, MAX_LOCKED_WAIT, Outcome,
    PasswordVerdict, PinVerdict, PinVerifier, RegistryView, ReinstateGate, RevocationGuard,
    RevocationPermit, SetupAdmission, SetupGate,
};
pub use clock::{Clock, ManualClock, SystemClock};
pub use error::{Error, Result};
pub use keys::{DeviceId, Fingerprint, IdentityKey, PublicKey};
pub use pairing::{
    PairClientOptions, PairedServer, PairedWith, PairingLimits, PairingWindow, pair_device,
};
pub use pin::{MAX_PIN_FAILURES, PinHash, PinParams};
pub use registry::{
    DeviceRecord, DeviceRegistry, FileRegistry, MemoryRegistry, Revocation, RevokeReason, RevokedBy,
};
pub use secrets::{PairingCode, PairingCredential, PairingToken, Pin};
pub use session::{AwaitingPin, PinReply, SessionOptions, connect_session, connect_with_pin};
