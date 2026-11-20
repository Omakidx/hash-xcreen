//! PIN hashing (Argon2id) and the lockout schedule (protocol §11.4).

use std::{fmt, time::Duration};

use argon2::{Algorithm, Argon2, Params, Version};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    encoding::{hex_decode, hex_encode},
    error::{Error, Result},
    keys::random_bytes,
    secrets::Pin,
};

const SALT_LEN: usize = 16;
const OUT_LEN: usize = 32;
const PREFIX: &str = "hx-pin1";

/// Consecutive wrong PINs that revoke a device.
pub const MAX_PIN_FAILURES: u32 = 5;

/// Longest wait between attempts.
pub const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Wait required after the `failures`-th consecutive wrong PIN: 1 s, 2 s, 4 s, ... capped at
/// [`MAX_BACKOFF`]. Zero failures need no wait.
pub fn backoff_after(failures: u32) -> Duration {
    if failures == 0 {
        return Duration::ZERO;
    }
    let secs = 1u64.checked_shl(failures - 1).unwrap_or(u64::MAX);
    Duration::from_secs(secs).min(MAX_BACKOFF)
}

/// Argon2id cost parameters, stored with every hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinParams {
    /// Memory in KiB.
    pub memory_kib: u32,
    /// Iterations.
    pub iterations: u32,
    /// Lanes.
    pub parallelism: u32,
}

impl PinParams {
    /// 64 MiB, 3 passes, 1 lane: well above the OWASP minimum (19 MiB, 2, 1), about 100 to
    /// 250 ms on a small VPS core. Only paired devices reach it, one verification at a time per
    /// device.
    pub const DEFAULT: Self = Self {
        memory_kib: 64 * 1024,
        iterations: 3,
        parallelism: 1,
    };

    /// Upper bounds applied to parameters read from storage, so a corrupted file cannot force
    /// an arbitrary cost.
    const MAX_MEMORY_KIB: u32 = 1024 * 1024;
    const MAX_ITERATIONS: u32 = 16;
    const MAX_PARALLELISM: u32 = 16;

    fn validate(self) -> Result<Params> {
        if self.memory_kib > Self::MAX_MEMORY_KIB
            || self.iterations > Self::MAX_ITERATIONS
            || self.parallelism > Self::MAX_PARALLELISM
        {
            return Err(Error::Corrupt("PIN hash parameters out of range".into()));
        }
        Params::new(
            self.memory_kib,
            self.iterations,
            self.parallelism,
            Some(OUT_LEN),
        )
        .map_err(|_| Error::Corrupt("PIN hash parameters invalid".into()))
    }
}

/// A stored PIN verifier: Argon2id output with its salt and parameters.
#[derive(Clone, PartialEq, Eq)]
pub struct PinHash {
    params: PinParams,
    salt: [u8; SALT_LEN],
    hash: [u8; OUT_LEN],
}

fn derive(params: PinParams, salt: &[u8], pin: &[u8]) -> Result<Zeroizing<[u8; OUT_LEN]>> {
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.validate()?);
    let mut out = Zeroizing::new([0u8; OUT_LEN]);
    argon
        .hash_password_into(pin, salt, &mut *out)
        .map_err(|_| Error::Corrupt("PIN hashing failed".into()))?;
    Ok(out)
}

impl PinHash {
    /// Hash a new PIN with the default parameters and a fresh random salt.
    pub fn new(pin: &Pin) -> Result<Self> {
        Self::with_params(pin, PinParams::DEFAULT)
    }

    /// Hash with explicit parameters (tests use small ones).
    pub fn with_params(pin: &Pin, params: PinParams) -> Result<Self> {
        let salt = random_bytes::<SALT_LEN>()?;
        let hash = derive(params, &salt, pin.as_bytes())?;
        Ok(Self {
            params,
            salt,
            hash: *hash,
        })
    }

    /// Constant-time check of a candidate PIN. CPU and memory heavy: run on a blocking thread.
    pub fn verify(&self, pin: &[u8]) -> bool {
        match derive(self.params, &self.salt, pin) {
            Ok(candidate) => candidate.ct_eq(&self.hash).into(),
            Err(_) => false,
        }
    }

    /// The parameters it was made with.
    pub fn params(&self) -> PinParams {
        self.params
    }

    /// Storage form: `hx-pin1$m=<KiB>,t=<n>,p=<n>$<salt hex>$<hash hex>`.
    pub fn to_storage_string(&self) -> String {
        format!(
            "{PREFIX}$m={},t={},p={}${}${}",
            self.params.memory_kib,
            self.params.iterations,
            self.params.parallelism,
            hex_encode(&self.salt),
            hex_encode(&self.hash)
        )
    }

    /// Parse the storage form; any deviation or out-of-range parameter is an error.
    pub fn from_storage_string(s: &str) -> Result<Self> {
        let bad = || Error::Corrupt("PIN hash".into());
        let mut parts = s.split('$');
        if parts.next() != Some(PREFIX) {
            return Err(bad());
        }
        let params_s = parts.next().ok_or_else(bad)?;
        let salt_s = parts.next().ok_or_else(bad)?;
        let hash_s = parts.next().ok_or_else(bad)?;
        if parts.next().is_some() {
            return Err(bad());
        }
        let mut kv = params_s.split(',');
        let mut take = |name: &str| -> Result<u32> {
            kv.next()
                .and_then(|p| p.strip_prefix(name))
                .and_then(|p| p.strip_prefix('='))
                .and_then(|n| n.parse().ok())
                .ok_or_else(bad)
        };
        let params = PinParams {
            memory_kib: take("m")?,
            iterations: take("t")?,
            parallelism: take("p")?,
        };
        if kv.next().is_some() {
            return Err(bad());
        }
        params.validate()?;
        let salt: [u8; SALT_LEN] = hex_decode(salt_s)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(bad)?;
        let hash: [u8; OUT_LEN] = hex_decode(hash_s)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(bad)?;
        Ok(Self { params, salt, hash })
    }
}

impl fmt::Debug for PinHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PinHash({:?}, [redacted])", self.params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHEAP: PinParams = PinParams {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    };

    #[test]
    fn verifies_right_and_rejects_wrong() {
        let h = PinHash::with_params(&Pin::new("123456").unwrap(), CHEAP).unwrap();
        assert!(h.verify(b"123456"));
        assert!(!h.verify(b"123457"));
        assert!(!h.verify(b""));
    }

    #[test]
    fn salts_differ_and_storage_round_trips() {
        let pin = Pin::new("654321").unwrap();
        let a = PinHash::with_params(&pin, CHEAP).unwrap();
        let b = PinHash::with_params(&pin, CHEAP).unwrap();
        assert_ne!(a.to_storage_string(), b.to_storage_string());
        let back = PinHash::from_storage_string(&a.to_storage_string()).unwrap();
        assert_eq!(back, a);
        assert!(back.verify(b"654321"));
        assert!(!format!("{a:?}").contains(&hex_encode(&a.hash)));
    }

    #[test]
    fn default_parameters_are_documented_ones() {
        assert_eq!(
            PinParams::DEFAULT,
            PinParams {
                memory_kib: 65536,
                iterations: 3,
                parallelism: 1
            }
        );
    }

    #[test]
    fn corrupt_or_expensive_storage_is_rejected() {
        let h = PinHash::with_params(&Pin::new("123456").unwrap(), CHEAP).unwrap();
        let ok = h.to_storage_string();
        assert!(PinHash::from_storage_string(&ok.replace("hx-pin1", "x")).is_err());
        assert!(PinHash::from_storage_string(&ok.replace("m=64", "m=4294967295")).is_err());
        assert!(PinHash::from_storage_string(&ok.replace("t=1", "t=999")).is_err());
        assert!(PinHash::from_storage_string(&format!("{ok}$extra")).is_err());
        assert!(PinHash::from_storage_string("hx-pin1$m=64,t=1,p=1$00$00").is_err());
        assert!(PinHash::from_storage_string("").is_err());
    }

    #[test]
    fn backoff_schedule() {
        let s: Vec<u64> = (0..8).map(|n| backoff_after(n).as_secs()).collect();
        assert_eq!(s, [0, 1, 2, 4, 8, 16, 30, 30]);
        assert_eq!(backoff_after(u32::MAX), MAX_BACKOFF);
    }
}
