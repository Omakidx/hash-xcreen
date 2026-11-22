//! Redacting `Debug` for the generated message types that carry secrets.
//!
//! `build.rs` turns off prost's derived `Debug` for these types (`skip_debug`) and the impls
//! here replace it, so a stray `{:?}` or a `tracing` field can never print a PIN, a password,
//! a pairing code or the opaque pairing/auth payload. No length is printed either: the length
//! of a PIN is information too.

use std::fmt;

use crate::pb;

/// Stands in for a secret value in a `Debug` dump.
struct Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl fmt::Debug for pb::SetupSetPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetupSetPin")
            .field("pin", &Redacted)
            .finish()
    }
}

impl fmt::Debug for pb::SetupStart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The options hold no secret; the password does.
        f.debug_struct("SetupStart")
            .field("options", &self.options)
            .field("password", &Redacted)
            .finish()
    }
}

impl fmt::Debug for pb::Opaque {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Opaque").field("data", &Redacted).finish()
    }
}

impl fmt::Debug for pb::PairingCodeIssued {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingCodeIssued")
            .field("code", &Redacted)
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}
