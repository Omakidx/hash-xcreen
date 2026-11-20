//! Ed25519 identity and device keys (protocol §11.1).

use std::fmt;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    encoding::{hex_decode, hex_encode},
    error::{Error, Result},
};

/// DER prefix of an Ed25519 `SubjectPublicKeyInfo` (RFC 8410); the 32 key bytes follow.
const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Length of an Ed25519 `SubjectPublicKeyInfo`: the raw-public-key "certificate" in TLS.
pub const SPKI_LEN: usize = 44;

/// Fill `N` bytes from the operating system's random source.
pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|_| Error::Random)?;
    Ok(b)
}

/// An Ed25519 public key that decodes to a valid, non-weak point.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// Validate and wrap raw key bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let vk = VerifyingKey::from_bytes(bytes).map_err(|_| Error::InvalidKey)?;
        if vk.is_weak() {
            return Err(Error::InvalidKey);
        }
        Ok(Self(*bytes))
    }

    /// Parse the 44-byte `SubjectPublicKeyInfo` exactly: any other length, algorithm or
    /// trailing byte is an error.
    pub fn from_spki(der: &[u8]) -> Result<Self> {
        if der.len() != SPKI_LEN || der[..SPKI_PREFIX.len()] != SPKI_PREFIX {
            return Err(Error::InvalidKey);
        }
        let raw: [u8; 32] = der[SPKI_PREFIX.len()..]
            .try_into()
            .map_err(|_| Error::InvalidKey)?;
        Self::from_bytes(&raw)
    }

    /// The raw 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The 44-byte `SubjectPublicKeyInfo` DER that TLS presents for this key.
    pub fn spki(&self) -> [u8; SPKI_LEN] {
        let mut out = [0u8; SPKI_LEN];
        out[..SPKI_PREFIX.len()].copy_from_slice(&SPKI_PREFIX);
        out[SPKI_PREFIX.len()..].copy_from_slice(&self.0);
        out
    }

    /// SHA-256 of the raw key.
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint(Sha256::digest(self.0).into())
    }

    /// The registry identifier of this key.
    pub fn device_id(&self) -> DeviceId {
        let fp = self.fingerprint();
        let mut id = [0u8; 16];
        id.copy_from_slice(&fp.0[..16]);
        DeviceId(id)
    }
}

/// Public keys are not secret, but the short fingerprint is what logs should show.
impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.fingerprint().short())
    }
}

/// SHA-256 of a public key: what users compare when they verify a key by eye.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// Full lowercase hex (64 characters).
    pub fn to_hex(&self) -> String {
        hex_encode(&self.0)
    }

    /// First 12 hex characters, for logs and lists.
    pub fn short(&self) -> String {
        hex_encode(&self.0[..6])
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", self.short())
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Stable identifier of a paired device: the first 16 bytes of its key fingerprint.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceId(pub(crate) [u8; 16]);

impl DeviceId {
    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Parse the 32-character hex form.
    pub fn parse(s: &str) -> Result<Self> {
        let b = hex_decode(s).ok_or(Error::InvalidSecret("device id"))?;
        let id: [u8; 16] = b
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidSecret("device id"))?;
        Ok(Self(id))
    }

    pub(crate) fn from_slice(b: &[u8]) -> Option<Self> {
        <[u8; 16]>::try_from(b).ok().map(Self)
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex_encode(&self.0))
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({self})")
    }
}

/// A long-term Ed25519 key pair: the agent identity or one device key.
///
/// The secret half is zeroized on drop, never printed, and not clonable (share it with `Arc`).
pub struct IdentityKey {
    secret: SigningKey,
    public: PublicKey,
}

impl IdentityKey {
    /// A fresh key from the operating system's random source.
    pub fn generate() -> Result<Self> {
        let seed = Zeroizing::new(random_bytes::<32>()?);
        Self::from_seed(&seed)
    }

    /// Rebuild a key from its 32-byte seed (what [`seed`](Self::seed) returned).
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        let secret = SigningKey::from_bytes(seed);
        let public = PublicKey::from_bytes(secret.verifying_key().as_bytes())?;
        Ok(Self { secret, public })
    }

    /// The 32-byte secret seed, for storage by the caller (root-only file on the server, system
    /// keyring on the client). The returned buffer is zeroized on drop.
    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret.to_bytes())
    }

    /// The public half.
    pub fn public(&self) -> PublicKey {
        self.public
    }

    pub(crate) fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.secret.sign(message).to_bytes()
    }
}

impl fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IdentityKey({}, [redacted])",
            self.public.fingerprint().short()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spki_round_trip_and_strictness() {
        let k = IdentityKey::generate().unwrap();
        let spki = k.public().spki();
        assert_eq!(PublicKey::from_spki(&spki).unwrap(), k.public());
        let mut longer = spki.to_vec();
        longer.push(0);
        assert!(PublicKey::from_spki(&longer).is_err());
        assert!(PublicKey::from_spki(&spki[..43]).is_err());
        let mut wrong_alg = spki;
        wrong_alg[8] ^= 1;
        assert!(PublicKey::from_spki(&wrong_alg).is_err());
    }

    #[test]
    fn weak_and_invalid_points_are_rejected() {
        // The identity point (small order).
        let mut id = [0u8; 32];
        id[0] = 1;
        assert!(PublicKey::from_bytes(&id).is_err());
        // y = 2 does not lie on the curve.
        let mut off = [0u8; 32];
        off[0] = 2;
        let _ = PublicKey::from_bytes(&off); // must not panic either way
    }

    #[test]
    fn seed_round_trip_and_redacted_debug() {
        let k = IdentityKey::generate().unwrap();
        let again = IdentityKey::from_seed(&k.seed()).unwrap();
        assert_eq!(k.public(), again.public());
        let dbg = format!("{k:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains(&hex_encode(&k.seed()[..])));
    }

    #[test]
    fn device_id_is_stable_and_parses() {
        let k = IdentityKey::generate().unwrap().public();
        let id = k.device_id();
        assert_eq!(DeviceId::parse(&id.to_string()).unwrap(), id);
        assert_eq!(k.device_id(), id);
        assert!(DeviceId::parse("00").is_err());
    }
}
