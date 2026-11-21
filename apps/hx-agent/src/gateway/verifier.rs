//! PIN and Linux-password verifiers: `HMAC(pepper, Argon2id(secret))` (`docs/ipc.md` section 5.3,
//! decision 1).
//!
//! # The split with hx-crypto and privd
//!
//! * The **Argon2id** half runs here, in the gateway, with the cost parameters of protocol 11.4
//!   (`hx_crypto::PinParams`, default 64 MiB, 3 passes, 1 lane) and a random 16-byte salt.
//! * The **pepper** half runs in privd, which alone holds the key. A login calls `PepperVerify`
//!   (yes or no, failures counted globally and capped, section 5.3); a verifier is created with
//!   `PepperEnrol`. **The gateway never sees the pepper, and never sees a MAC except the one
//!   `PepperEnrol` returns for a verifier it is creating** (it stores that value, nothing else).
//! * hx-crypto's `PinHash` compares the Argon2id output locally, so it cannot carry a peppered
//!   verifier, and `Authenticator::set_pin` has no hook for a remote check. The gateway therefore
//!   runs the session login itself ([`super::login`]) with hx-crypto's registry for the
//!   per-device failure counter and revocation, and uses this module for the secret. The exact
//!   hx-crypto change that would let `Authenticator` do it is in the round report.
//!
//! # Record format
//!
//! ASCII, at most 128 bytes (the admin socket's `MAX_VERIFIER_BYTES`):
//!
//! ```text
//! hx-pv1$m=<KiB>,t=<n>,p=<n>$<salt: 32 hex>$<mac: 64 hex>
//! ```
//!
//! The same record serves both purposes (the purpose is the pepper key privd derives, not part
//! of the record). Parameters read back are bounded like hx-crypto's (m up to 1 GiB, t and p up
//! to 16) so a corrupted file cannot force an arbitrary cost.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use argon2::{Algorithm, Argon2, Params, Version};
use hx_crypto::{DeviceId, PinParams};
use hx_ipc::privd::pb::LockoutPurpose;
use zeroize::Zeroizing;

use super::privd_client::{PrivdClient, PrivdError};
use super::util::{hex, unhex};

/// Record prefix.
pub const PREFIX: &str = "hx-pv1";
/// Longest record (the admin socket accepts at most this many bytes).
pub const MAX_RECORD_LEN: usize = hx_ipc::admin::MAX_VERIFIER_BYTES;
const SALT_LEN: usize = 16;
const OUT_LEN: usize = 32;
const MAX_MEMORY_KIB: u32 = 1024 * 1024;
const MAX_ITERATIONS: u32 = 16;
const MAX_PARALLELISM: u32 = 16;
/// OWASP's minimum Argon2id memory (19 MiB): the default floor for a verifier set by an
/// operator, so a typo cannot install a trivially cheap hash.
pub const DEFAULT_MIN_MEMORY_KIB: u32 = 19 * 1024;

/// Why a verifier or its storage was refused.
#[derive(Debug, thiserror::Error)]
pub enum VerifierError {
    /// The record is not in the documented format or its parameters are out of range.
    #[error("malformed verifier: {0}")]
    Malformed(&'static str),
    /// The Argon2id memory is below the configured floor.
    #[error("verifier cost parameters are below the minimum")]
    TooCheap,
    /// The secret is not acceptable (a PIN is 6 to 16 digits).
    #[error("invalid secret format")]
    InvalidSecret,
    /// Argon2id failed (parameters rejected by the implementation).
    #[error("hashing failed")]
    Hash,
    /// privd failed (including `PepperEnrol`'s daily cap).
    #[error(transparent)]
    Privd(#[from] PrivdError),
    /// The verifier file could not be read or written, or is not private to this user.
    #[error("verifier storage: {0}")]
    Storage(String),
}

fn params_ok(p: PinParams) -> Result<Params, VerifierError> {
    if p.memory_kib > MAX_MEMORY_KIB
        || p.iterations == 0
        || p.iterations > MAX_ITERATIONS
        || p.parallelism == 0
        || p.parallelism > MAX_PARALLELISM
        || p.memory_kib < 8 * p.parallelism
    {
        return Err(VerifierError::Malformed("cost parameters out of range"));
    }
    Params::new(p.memory_kib, p.iterations, p.parallelism, Some(OUT_LEN))
        .map_err(|_| VerifierError::Malformed("cost parameters rejected"))
}

/// A stored verifier: Argon2id parameters and salt, and the peppered MAC of the output.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifierRecord {
    params: PinParams,
    salt: [u8; SALT_LEN],
    mac: [u8; OUT_LEN],
}

impl std::fmt::Debug for VerifierRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VerifierRecord({:?}, [redacted])", self.params)
    }
}

impl VerifierRecord {
    /// Parses the ASCII record. Any deviation is an error.
    pub fn parse(bytes: &[u8]) -> Result<Self, VerifierError> {
        let bad = VerifierError::Malformed;
        if bytes.len() > MAX_RECORD_LEN {
            return Err(bad("too long"));
        }
        let s = std::str::from_utf8(bytes).map_err(|_| bad("not ASCII"))?;
        let mut parts = s.split('$');
        if parts.next() != Some(PREFIX) {
            return Err(bad("prefix"));
        }
        let (Some(params_s), Some(salt_s), Some(mac_s), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(bad("field count"));
        };
        let mut kv = params_s.split(',');
        let mut take = |name: &str| -> Result<u32, VerifierError> {
            kv.next()
                .and_then(|p| p.strip_prefix(name))
                .and_then(|p| p.strip_prefix('='))
                .and_then(|n| n.parse().ok())
                .ok_or(bad("parameters"))
        };
        let params = PinParams {
            memory_kib: take("m")?,
            iterations: take("t")?,
            parallelism: take("p")?,
        };
        if kv.next().is_some() {
            return Err(bad("parameters"));
        }
        params_ok(params)?;
        let salt: [u8; SALT_LEN] = unhex(salt_s)
            .and_then(|b| b.as_slice().try_into().ok())
            .ok_or(bad("salt"))?;
        let mac: [u8; OUT_LEN] = unhex(mac_s)
            .and_then(|b| b.as_slice().try_into().ok())
            .ok_or(bad("mac"))?;
        Ok(Self { params, salt, mac })
    }

    /// The ASCII record.
    pub fn to_bytes(&self) -> Vec<u8> {
        format!(
            "{PREFIX}$m={},t={},p={}${}${}",
            self.params.memory_kib,
            self.params.iterations,
            self.params.parallelism,
            hex(&self.salt),
            hex(&self.mac)
        )
        .into_bytes()
    }

    /// The Argon2id cost parameters.
    pub fn params(&self) -> PinParams {
        self.params
    }

    /// Fails if the memory cost is below `min_memory_kib` (the operator's floor).
    pub fn check_cost(&self, min_memory_kib: u32) -> Result<(), VerifierError> {
        if self.params.memory_kib < min_memory_kib {
            return Err(VerifierError::TooCheap);
        }
        Ok(())
    }

    /// The stored MAC, for `PepperVerify`'s `expected_verifier`.
    pub fn expected_mac(&self) -> &[u8; OUT_LEN] {
        &self.mac
    }

    /// Argon2id of `secret` with this record's salt and parameters. CPU and memory heavy: call
    /// it from a blocking thread. The output is the `MAC_INPUT` secret for privd.
    pub fn derive(&self, secret: &[u8]) -> Result<Zeroizing<[u8; OUT_LEN]>, VerifierError> {
        derive(self.params, &self.salt, secret)
    }
}

fn derive(
    params: PinParams,
    salt: &[u8],
    secret: &[u8],
) -> Result<Zeroizing<[u8; OUT_LEN]>, VerifierError> {
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params_ok(params)?);
    let mut out = Zeroizing::new([0u8; OUT_LEN]);
    argon
        .hash_password_into(secret, salt, &mut *out)
        .map_err(|_| VerifierError::Hash)?;
    Ok(out)
}

/// Creates a verifier for `secret`: a fresh salt, Argon2id here, then privd's `PepperEnrol` for
/// the MAC. Used when an operator or the client sets a PIN or password. Counts against
/// `PepperEnrol`'s caps in privd.
pub async fn enrol(
    privd: &PrivdClient,
    purpose: LockoutPurpose,
    secret: &[u8],
    params: PinParams,
) -> Result<VerifierRecord, VerifierError> {
    if purpose == LockoutPurpose::Pin && hx_crypto::Pin::from_bytes(secret).is_err() {
        return Err(VerifierError::InvalidSecret);
    }
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|_| VerifierError::Hash)?;
    let owned = Zeroizing::new(secret.to_vec());
    let output = tokio::task::spawn_blocking(move || derive(params, &salt, &owned))
        .await
        .map_err(|_| VerifierError::Hash)??;
    let enrolled = privd.pepper_enrol(purpose, &*output).await?;
    Ok(VerifierRecord {
        params,
        salt,
        mac: enrolled.mac,
    })
}

/// Which verifier a login uses: the device's own if the operator set one, else the shared one.
#[derive(Default, Clone)]
struct State {
    pin_all: Option<VerifierRecord>,
    pin_devices: BTreeMap<DeviceId, VerifierRecord>,
    password: Option<VerifierRecord>,
}

/// The verifiers of the gateway, persisted next to the device registry (`docs/ipc.md` section 2:
/// the gateway's state directory, 0700, owned by `hx-gatewayd`). One text file, rewritten
/// atomically (temporary file, `fsync`, `rename`, directory `fsync`), 0600.
pub struct VerifierStore {
    path: PathBuf,
    state: RwLock<State>,
    write_lock: std::sync::Mutex<()>,
}

impl VerifierStore {
    /// Opens (or starts) the store at `path`. Fails closed: the parent directory must not be
    /// writable by group or others, and an existing file must be a regular file owned by this
    /// user with mode 0600 (opened without following symlinks) that parses.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, VerifierError> {
        let path = path.into();
        let storage = |m: &str| VerifierError::Storage(m.to_owned());
        let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
        let dir = dir.unwrap_or(Path::new("."));
        let mode = fs::metadata(dir)
            .map_err(|e| VerifierError::Storage(e.kind().to_string()))?
            .permissions()
            .mode();
        if mode & 0o022 != 0 {
            return Err(storage("directory is writable by group or others"));
        }
        let state = match fs::OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&path)
        {
            Ok(mut f) => {
                let meta = f
                    .metadata()
                    .map_err(|e| VerifierError::Storage(e.kind().to_string()))?;
                if !meta.is_file()
                    || meta.uid() != rustix::process::geteuid().as_raw()
                    || meta.permissions().mode() & 0o077 != 0
                {
                    return Err(storage("file is not a private regular file"));
                }
                let mut text = String::new();
                f.read_to_string(&mut text)
                    .map_err(|_| storage("unreadable"))?;
                parse_file(&text)?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(e) => return Err(VerifierError::Storage(e.kind().to_string())),
        };
        Ok(Self {
            path,
            state: RwLock::new(state),
            write_lock: std::sync::Mutex::new(()),
        })
    }

    fn read(&self) -> State {
        self.state.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// The PIN verifier for `id`: its own, else the shared one. `None` if no PIN is set.
    pub fn pin_for(&self, id: &DeviceId) -> Option<VerifierRecord> {
        let s = self.state.read().unwrap_or_else(|p| p.into_inner());
        s.pin_devices.get(id).or(s.pin_all.as_ref()).cloned()
    }

    /// True if any PIN verifier exists (a server without one refuses sessions).
    pub fn has_pin(&self) -> bool {
        let s = self.state.read().unwrap_or_else(|p| p.into_inner());
        s.pin_all.is_some() || !s.pin_devices.is_empty()
    }

    /// The Linux-password verifier, if set.
    pub fn password(&self) -> Option<VerifierRecord> {
        self.state
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .password
            .clone()
    }

    /// Sets the shared PIN verifier (`all`) or one device's. Persisted before it takes effect.
    pub fn set_pin(
        &self,
        target: Option<DeviceId>,
        record: VerifierRecord,
    ) -> Result<(), VerifierError> {
        self.mutate(|s| match target {
            Some(id) => {
                s.pin_devices.insert(id, record);
            }
            None => {
                s.pin_all = Some(record);
                // A shared PIN set by the operator replaces every per-device override.
                s.pin_devices.clear();
            }
        })
    }

    /// Sets the Linux-password verifier.
    pub fn set_password(&self, record: VerifierRecord) -> Result<(), VerifierError> {
        self.mutate(|s| s.password = Some(record))
    }

    fn mutate(&self, f: impl FnOnce(&mut State)) -> Result<(), VerifierError> {
        let _w = self.write_lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut next = self.read();
        f(&mut next);
        persist(&self.path, &next)?;
        *self.state.write().unwrap_or_else(|p| p.into_inner()) = next;
        Ok(())
    }
}

fn render(s: &State) -> String {
    let line = |label: &str, r: &VerifierRecord| {
        format!("{label} {}\n", String::from_utf8_lossy(&r.to_bytes()))
    };
    let mut out = String::from("# hx-gatewayd verifiers (peppered; useless without hx-privd)\n");
    if let Some(r) = &s.pin_all {
        out.push_str(&line("pin all", r));
    }
    for (id, r) in &s.pin_devices {
        out.push_str(&line(&format!("pin {id}"), r));
    }
    if let Some(r) = &s.password {
        out.push_str(&line("password", r));
    }
    out
}

fn parse_file(text: &str) -> Result<State, VerifierError> {
    let bad = VerifierError::Malformed("verifier file");
    let mut state = State::default();
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut words = line.split(' ');
        match (words.next(), words.next(), words.next(), words.next()) {
            (Some("pin"), Some("all"), Some(rec), None) => {
                state.pin_all = Some(VerifierRecord::parse(rec.as_bytes())?);
            }
            (Some("pin"), Some(id), Some(rec), None) => {
                let id = DeviceId::parse(id).map_err(|_| VerifierError::Malformed("device id"))?;
                state
                    .pin_devices
                    .insert(id, VerifierRecord::parse(rec.as_bytes())?);
            }
            (Some("password"), Some(rec), None, None) => {
                state.password = Some(VerifierRecord::parse(rec.as_bytes())?);
            }
            _ => return Err(bad),
        }
    }
    Ok(state)
}

fn persist(path: &Path, state: &State) -> Result<(), VerifierError> {
    let io = |e: std::io::Error| VerifierError::Storage(e.kind().to_string());
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let tmp = path.with_extension("tmp");
    // A stale temporary file from a crash is ours to replace; never follow a link.
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&tmp)
        .map_err(io)?;
    f.write_all(render(state).as_bytes()).map_err(io)?;
    f.sync_all().map_err(io)?;
    fs::rename(&tmp, path).map_err(io)?;
    fs::File::open(dir).and_then(|d| d.sync_all()).map_err(io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::util::device_id;

    const CHEAP: PinParams = PinParams {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    };

    fn record() -> VerifierRecord {
        VerifierRecord {
            params: CHEAP,
            salt: [7; 16],
            mac: [9; 32],
        }
    }

    #[test]
    fn records_round_trip_and_fit_the_admin_limit() {
        let r = record();
        let bytes = r.to_bytes();
        assert!(bytes.len() <= MAX_RECORD_LEN, "{} bytes", bytes.len());
        assert_eq!(VerifierRecord::parse(&bytes).unwrap(), r);
        // The default 64 MiB parameters are the longest realistic record.
        let big = VerifierRecord {
            params: PinParams::DEFAULT,
            ..r
        };
        assert!(big.to_bytes().len() <= MAX_RECORD_LEN);
    }

    #[test]
    fn malformed_and_expensive_records_are_rejected() {
        let ok = String::from_utf8(record().to_bytes()).unwrap();
        for bad in [
            ok.replace("hx-pv1", "hx-pin1"),
            ok.replace("m=64", "m=4294967295"),
            ok.replace("t=1", "t=999"),
            ok.replace("t=1", "t=0"),
            ok.replace("m=64", "m=4"),
            format!("{ok}$extra"),
            ok.replace("070707", "zz0707"),
            String::new(),
            "x".repeat(MAX_RECORD_LEN + 1),
        ] {
            assert!(VerifierRecord::parse(bad.as_bytes()).is_err(), "{bad}");
        }
        assert!(record().check_cost(DEFAULT_MIN_MEMORY_KIB).is_err());
        assert!(record().check_cost(64).is_ok());
    }

    #[test]
    fn derive_depends_on_salt_params_and_secret() {
        let r = record();
        let a = r.derive(b"123456").unwrap();
        assert_eq!(*a, *r.derive(b"123456").unwrap());
        assert_ne!(*a, *r.derive(b"123457").unwrap());
        let other = VerifierRecord {
            salt: [8; 16],
            ..record()
        };
        assert_ne!(*a, *other.derive(b"123456").unwrap());
        assert!(!format!("{r:?}").contains("0909"));
    }

    #[test]
    fn the_store_persists_atomically_with_private_modes() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("verifiers");
        let store = VerifierStore::open(&path).unwrap();
        assert!(!store.has_pin());
        let id = device_id(&[3; 16]).unwrap();
        store.set_pin(None, record()).unwrap();
        let mut own = record();
        own.mac = [1; 32];
        store.set_pin(Some(id), own.clone()).unwrap();
        store.set_password(record()).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let again = VerifierStore::open(&path).unwrap();
        assert_eq!(again.pin_for(&id), Some(own));
        assert_eq!(again.pin_for(&device_id(&[4; 16]).unwrap()), Some(record()));
        assert_eq!(again.password(), Some(record()));
        // Setting the shared PIN drops per-device overrides.
        again.set_pin(None, record()).unwrap();
        assert_eq!(again.pin_for(&id), Some(record()));
    }

    #[test]
    fn the_store_refuses_loose_modes() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("verifiers");
        VerifierStore::open(&path)
            .unwrap()
            .set_pin(None, record())
            .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(VerifierStore::open(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o770)).unwrap();
        assert!(VerifierStore::open(&path).is_err());
    }
}
