//! The device key in the system keyring (Secret Service on Linux).
//!
//! The 32-byte Ed25519 seed is stored as hex under service `hash-xcreen`, user `device-key`.
//! If the Secret Service is not available the app says so and does not fall back to a file:
//! [`KeyError::Unavailable`] carries the text the UI shows.

use std::sync::{Arc, Mutex};

use hx_crypto::IdentityKey;
use zeroize::Zeroizing;

const SERVICE: &str = "hash-xcreen";
const USER: &str = "device-key";

/// Why the key could not be read or stored.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// No Secret Service (no keyring daemon, locked and not unlockable, no D-Bus session).
    #[error("the system keyring (Secret Service) is not available: {0}")]
    Unavailable(String),
    /// The stored value is not a key.
    #[error("the stored device key is damaged")]
    Corrupt,
    /// Key generation failed.
    #[error("could not create a device key")]
    Generate,
}

/// Where the seed lives. The real one is [`KeyringStore`]; tests and demo mode use
/// [`MemoryKeyStore`].
pub trait SecretStore: Send + Sync {
    /// The stored hex seed, if any.
    fn load(&self) -> Result<Option<Zeroizing<String>>, KeyError>;
    /// Stores the hex seed.
    fn store(&self, hex: &str) -> Result<(), KeyError>;
}

/// The Secret Service through the `keyring` crate.
#[derive(Debug, Default)]
pub struct KeyringStore;

impl KeyringStore {
    fn entry() -> Result<keyring::Entry, KeyError> {
        keyring::Entry::new(SERVICE, USER).map_err(|e| KeyError::Unavailable(e.to_string()))
    }
}

impl SecretStore for KeyringStore {
    fn load(&self) -> Result<Option<Zeroizing<String>>, KeyError> {
        match Self::entry()?.get_password() {
            Ok(p) => Ok(Some(Zeroizing::new(p))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(KeyError::Unavailable(e.to_string())),
        }
    }

    fn store(&self, hex: &str) -> Result<(), KeyError> {
        Self::entry()?
            .set_password(hex)
            .map_err(|e| KeyError::Unavailable(e.to_string()))
    }
}

/// In-memory store for demo mode and tests.
#[derive(Default)]
pub struct MemoryKeyStore {
    value: Mutex<Option<String>>,
    /// When set, every call fails as if the Secret Service were missing.
    pub unavailable: bool,
}

impl MemoryKeyStore {
    /// A store that behaves like a machine without a Secret Service.
    pub fn broken() -> Self {
        Self {
            value: Mutex::new(None),
            unavailable: true,
        }
    }
}

impl SecretStore for MemoryKeyStore {
    fn load(&self) -> Result<Option<Zeroizing<String>>, KeyError> {
        if self.unavailable {
            return Err(KeyError::Unavailable("no Secret Service".into()));
        }
        Ok(self
            .value
            .lock()
            .ok()
            .and_then(|g| g.clone())
            .map(Zeroizing::new))
    }

    fn store(&self, hex: &str) -> Result<(), KeyError> {
        if self.unavailable {
            return Err(KeyError::Unavailable("no Secret Service".into()));
        }
        if let Ok(mut g) = self.value.lock() {
            *g = Some(hex.to_owned());
        }
        Ok(())
    }
}

fn hex_encode(b: &[u8]) -> Zeroizing<String> {
    Zeroizing::new(b.iter().map(|x| format!("{x:02x}")).collect())
}

fn hex_decode(s: &str) -> Option<Zeroizing<[u8; 32]>> {
    if s.len() != 64 || !s.is_ascii() {
        return None;
    }
    let mut out = Zeroizing::new([0u8; 32]);
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Loads the device key, or creates and stores a new one on first launch.
pub fn load_or_create(store: &dyn SecretStore) -> Result<Arc<IdentityKey>, KeyError> {
    if let Some(hex) = store.load()? {
        let seed = hex_decode(hex.trim()).ok_or(KeyError::Corrupt)?;
        return IdentityKey::from_seed(&seed)
            .map(Arc::new)
            .map_err(|_| KeyError::Corrupt);
    }
    let key = IdentityKey::generate().map_err(|_| KeyError::Generate)?;
    store.store(&hex_encode(&key.seed()[..]))?;
    Ok(Arc::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_once_then_reloads_the_same_key() {
        let s = MemoryKeyStore::default();
        let a = load_or_create(&s).unwrap();
        let b = load_or_create(&s).unwrap();
        assert_eq!(a.public(), b.public());
    }

    #[test]
    fn missing_secret_service_is_a_clear_error() {
        let e = load_or_create(&MemoryKeyStore::broken()).unwrap_err();
        assert!(matches!(e, KeyError::Unavailable(_)));
        assert!(e.to_string().contains("Secret Service"));
    }

    #[test]
    fn a_damaged_value_is_refused_not_replaced() {
        let s = MemoryKeyStore::default();
        s.store("zz").unwrap();
        assert!(matches!(load_or_create(&s), Err(KeyError::Corrupt)));
    }
}
