//! The pepper of the PIN and password verifiers (ipc.md 5.3).
//!
//! A verifier is `HMAC-SHA256(HKDF(pepper, purpose), Argon2id(secret))`. The Argon2id step runs in
//! gatewayd; this module is the second step, which only privd can run. The pepper is 32 random
//! bytes generated at the first start and kept in a root-only file; it is never sent over the
//! socket, logged or put in an error. The key for each purpose is derived with HKDF-SHA256 and
//! zeroized after use.

use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use super::limiter::Purpose;

/// Length of the pepper and of every MAC.
pub const LEN: usize = 32;
/// Version of the scheme, returned by `PepperEnrol` next to the MAC.
pub const VERSION: u8 = 1;

/// The loaded pepper. `Debug` shows nothing; the bytes are zeroized on drop.
pub struct Pepper(Zeroizing<[u8; LEN]>);

impl std::fmt::Debug for Pepper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Pepper(<redacted>)")
    }
}

impl Pepper {
    /// Loads the pepper from `path`, creating it (mode 0600, 32 bytes from the OS random source)
    /// if it does not exist. A file of the wrong length or with group or world permissions is an
    /// error: privd refuses to run with a pepper it cannot vouch for.
    pub fn load_or_create(path: &Path) -> io::Result<Self> {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
        {
            Ok(mut f) => {
                let mut key = Zeroizing::new([0u8; LEN]);
                getrandom::fill(&mut key[..]).map_err(io::Error::other)?;
                f.write_all(&key[..])?;
                f.sync_all()?;
                if let Some(dir) = path.parent() {
                    std::fs::File::open(dir)?.sync_all()?;
                }
                Ok(Self(key))
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                let meta = std::fs::metadata(path)?;
                if meta.permissions().mode() & 0o077 != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "the pepper file is readable by group or others",
                    ));
                }
                let mut buf = Zeroizing::new(Vec::with_capacity(LEN + 1));
                std::fs::File::open(path)?
                    .take(LEN as u64 + 1)
                    .read_to_end(&mut buf)?;
                if buf.len() != LEN {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "the pepper file has the wrong length",
                    ));
                }
                let mut key = Zeroizing::new([0u8; LEN]);
                key.copy_from_slice(&buf);
                Ok(Self(key))
            }
            Err(e) => Err(e),
        }
    }

    /// A pepper with fixed bytes (tests).
    #[cfg(any(test, feature = "test-support"))]
    pub fn from_bytes(bytes: [u8; LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn purpose_key(&self, purpose: Purpose) -> Zeroizing<[u8; LEN]> {
        let hk = Hkdf::<Sha256>::new(None, &self.0[..]);
        let mut info = b"hx-privd-pepper/v1/".to_vec();
        info.extend_from_slice(purpose.label().as_bytes());
        let mut out = Zeroizing::new([0u8; LEN]);
        // 32 bytes is far below the HKDF-SHA256 output limit; expand cannot fail.
        let _ = hk.expand(&info, &mut out[..]);
        out
    }

    /// `HMAC-SHA256(HKDF(pepper, purpose), input)`.
    ///
    /// Only `PepperEnrol` hands this value to a caller. `verify` never does.
    pub fn mac(&self, purpose: Purpose, input: &[u8]) -> [u8; LEN] {
        let key = self.purpose_key(purpose);
        // HMAC accepts keys of any length; new_from_slice cannot fail.
        let mut m = Hmac::<Sha256>::new_from_slice(&key[..]).expect("HMAC takes any key length");
        m.update(input);
        let mut out = [0u8; LEN];
        out.copy_from_slice(&m.finalize().into_bytes());
        out
    }

    /// Whether `expected` equals the MAC of `input`, in constant time. Returns only the verdict.
    pub fn verify(&self, purpose: Purpose, input: &[u8], expected: &[u8]) -> bool {
        let mut mac = self.mac(purpose, input);
        let ok = expected.len() == LEN && bool::from(mac.ct_eq(expected));
        mac.zeroize();
        ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_is_deterministic_and_separated_by_purpose_and_pepper() {
        let p = Pepper::from_bytes([7; LEN]);
        let q = Pepper::from_bytes([8; LEN]);
        let input = [1u8; 32];
        let a = p.mac(Purpose::Pin, &input);
        assert_eq!(a, p.mac(Purpose::Pin, &input));
        assert_ne!(a, p.mac(Purpose::Password, &input));
        assert_ne!(a, q.mac(Purpose::Pin, &input));
        assert_ne!(a, p.mac(Purpose::Pin, &[2u8; 32]));
    }

    #[test]
    fn verify_accepts_only_the_exact_mac() {
        let p = Pepper::from_bytes([7; LEN]);
        let input = [1u8; 32];
        let mac = p.mac(Purpose::Pin, &input);
        assert!(p.verify(Purpose::Pin, &input, &mac));
        assert!(!p.verify(Purpose::Password, &input, &mac));
        let mut bad = mac;
        bad[31] ^= 1;
        assert!(!p.verify(Purpose::Pin, &input, &bad));
        assert!(!p.verify(Purpose::Pin, &input, &mac[..31]));
    }

    #[test]
    fn the_file_is_created_0600_reloaded_and_checked() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("pepper.key");
        let p = Pepper::load_or_create(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let q = Pepper::load_or_create(&path).unwrap();
        assert_eq!(p.mac(Purpose::Pin, &[0; 32]), q.mac(Purpose::Pin, &[0; 32]));
        // Wrong length and wrong mode are refused.
        std::fs::write(&path, b"short").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(Pepper::load_or_create(&path).is_err());
        std::fs::write(&path, [0u8; LEN]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Pepper::load_or_create(&path).is_err());
    }

    #[test]
    fn debug_never_shows_bytes() {
        let p = Pepper::from_bytes([0x41; LEN]);
        let s = format!("{p:?}");
        assert!(!s.contains("41") && !s.contains("65"));
    }
}
