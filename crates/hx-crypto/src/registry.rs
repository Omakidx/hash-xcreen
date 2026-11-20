//! The server's registry of paired devices (architecture §8.2, protocol §11).
//!
//! [`DeviceRegistry`] is the interface the authenticator uses; [`FileRegistry`] persists it
//! atomically in a single file (0600, written to a temporary file, flushed, renamed over the
//! old one, directory flushed) and [`MemoryRegistry`] keeps it in memory for tests. Where the
//! file lives is decided by the agent (1C).
//!
//! Every mutation is **all or nothing**: it is applied to a copy, persisted, and only then
//! becomes visible, so a failed write never leaves memory and disk disagreeing and a failure
//! counter is never lost.

use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
};

use prost::Message;

use crate::{
    error::{Error, Result},
    keys::{DeviceId, PublicKey},
};

/// Why a device was revoked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevokeReason {
    /// An operator or another device revoked it.
    User,
    /// The PIN was wrong too many times.
    TooManyPinFailures,
}

impl RevokeReason {
    fn code(self) -> u32 {
        match self {
            Self::User => 1,
            Self::TooManyPinFailures => 2,
        }
    }

    fn from_code(c: u32) -> Option<Self> {
        match c {
            1 => Some(Self::User),
            2 => Some(Self::TooManyPinFailures),
            _ => None,
        }
    }
}

/// When and why a device lost access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Revocation {
    /// Seconds since the Unix epoch.
    pub at_unix: u64,
    /// Why.
    pub reason: RevokeReason,
}

/// One paired device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRecord {
    /// Identifier (derived from the key).
    pub id: DeviceId,
    /// Label chosen at pairing (sanitised; informational only, never used for authorisation).
    pub name: String,
    /// The pinned device key.
    pub public_key: PublicKey,
    /// When it was paired (Unix seconds).
    pub created_unix: u64,
    /// Last successful session (Unix seconds), 0 if never.
    pub last_seen_unix: u64,
    /// Consecutive wrong PINs.
    pub failed_pins: u32,
    /// Set once revoked.
    pub revoked: Option<Revocation>,
}

impl DeviceRecord {
    /// True if the device may not connect.
    pub fn is_revoked(&self) -> bool {
        self.revoked.is_some()
    }
}

/// Result of recording a wrong PIN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinFailure {
    /// Consecutive failures now.
    pub failed_pins: u32,
    /// True if this failure revoked the device.
    pub revoked: bool,
}

/// Storage of paired devices. Implementations must make each method atomic and durable (a
/// `Ok` return means the change survives a crash).
pub trait DeviceRegistry: Send + Sync + 'static {
    /// Look a device up by id.
    fn get(&self, id: &DeviceId) -> Result<Option<DeviceRecord>>;

    /// Look a device up by its key (the id is derived from the key, and the stored key must
    /// match exactly).
    fn find_by_key(&self, key: &PublicKey) -> Result<Option<DeviceRecord>> {
        Ok(self.get(&key.device_id())?.filter(|r| r.public_key == *key))
    }

    /// All devices, ordered by id.
    fn list(&self) -> Result<Vec<DeviceRecord>>;

    /// Add a device, or (if the key is already paired) update its name. An existing record
    /// keeps its failure counter and revocation state.
    fn upsert_paired(&self, key: &PublicKey, name: &str, now_unix: u64) -> Result<DeviceRecord>;

    /// Count a wrong PIN; the `max_failures`-th consecutive one revokes the device, in the
    /// same atomic write.
    fn record_pin_failure(
        &self,
        id: &DeviceId,
        max_failures: u32,
        now_unix: u64,
    ) -> Result<PinFailure>;

    /// A correct PIN: reset the counter and stamp `last_seen`.
    fn record_pin_success(&self, id: &DeviceId, now_unix: u64) -> Result<()>;

    /// Revoke. Returns false if the device is unknown or already revoked.
    fn revoke(&self, id: &DeviceId, reason: RevokeReason, now_unix: u64) -> Result<bool>;

    /// Lift a revocation and reset the counter. The caller must have verified the Linux
    /// password first (architecture §8.3). Returns false if unknown or not revoked.
    fn reinstate(&self, id: &DeviceId) -> Result<bool>;

    /// Forget a device entirely. Returns false if unknown.
    fn remove(&self, id: &DeviceId) -> Result<bool>;
}

// ------------------------------------------------------------------ shared store

type State = BTreeMap<DeviceId, DeviceRecord>;

/// State plus an optional file to persist to.
struct Store {
    state: Mutex<State>,
    file: Option<PathBuf>,
}

impl Store {
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, State>> {
        // A poisoned lock means a panic while a copy was being edited; the committed state is
        // intact (mutations work on a copy), so continue with it.
        Ok(self.state.lock().unwrap_or_else(|p| p.into_inner()))
    }

    fn read<R>(&self, f: impl FnOnce(&State) -> R) -> Result<R> {
        Ok(f(&*self.lock()?))
    }

    /// Apply `f` to a copy; persist the copy; publish it only if persisting worked and `f`
    /// asked for the change to be kept.
    fn mutate<R>(&self, f: impl FnOnce(&mut State) -> (R, bool)) -> Result<R> {
        let mut guard = self.lock()?;
        let mut next = guard.clone();
        let (out, changed) = f(&mut next);
        if changed {
            if let Some(path) = &self.file {
                persist(path, &next)?;
            }
            *guard = next;
        }
        Ok(out)
    }

    fn get(&self, id: &DeviceId) -> Result<Option<DeviceRecord>> {
        self.read(|s| s.get(id).cloned())
    }

    fn list(&self) -> Result<Vec<DeviceRecord>> {
        self.read(|s| s.values().cloned().collect())
    }

    fn upsert_paired(&self, key: &PublicKey, name: &str, now: u64) -> Result<DeviceRecord> {
        self.mutate(|s| {
            let id = key.device_id();
            let rec = s.entry(id).or_insert_with(|| DeviceRecord {
                id,
                name: name.to_owned(),
                public_key: *key,
                created_unix: now,
                last_seen_unix: 0,
                failed_pins: 0,
                revoked: None,
            });
            rec.name = name.to_owned();
            (rec.clone(), true)
        })
    }

    fn record_pin_failure(&self, id: &DeviceId, max: u32, now: u64) -> Result<PinFailure> {
        self.mutate(|s| match s.get_mut(id) {
            None => (Err(Error::UnknownDevice), false),
            Some(rec) => {
                rec.failed_pins = rec.failed_pins.saturating_add(1);
                if rec.failed_pins >= max && rec.revoked.is_none() {
                    rec.revoked = Some(Revocation {
                        at_unix: now,
                        reason: RevokeReason::TooManyPinFailures,
                    });
                }
                (
                    Ok(PinFailure {
                        failed_pins: rec.failed_pins,
                        revoked: rec.revoked.is_some(),
                    }),
                    true,
                )
            }
        })?
    }

    fn record_pin_success(&self, id: &DeviceId, now: u64) -> Result<()> {
        self.mutate(|s| match s.get_mut(id) {
            None => (Err(Error::UnknownDevice), false),
            Some(rec) => {
                rec.failed_pins = 0;
                rec.last_seen_unix = now;
                (Ok(()), true)
            }
        })?
    }

    fn revoke(&self, id: &DeviceId, reason: RevokeReason, now: u64) -> Result<bool> {
        self.mutate(|s| match s.get_mut(id) {
            Some(rec) if rec.revoked.is_none() => {
                rec.revoked = Some(Revocation {
                    at_unix: now,
                    reason,
                });
                (true, true)
            }
            _ => (false, false),
        })
    }

    fn reinstate(&self, id: &DeviceId) -> Result<bool> {
        self.mutate(|s| match s.get_mut(id) {
            Some(rec) if rec.revoked.is_some() => {
                rec.revoked = None;
                rec.failed_pins = 0;
                (true, true)
            }
            _ => (false, false),
        })
    }

    fn remove(&self, id: &DeviceId) -> Result<bool> {
        self.mutate(|s| {
            let had = s.remove(id).is_some();
            (had, had)
        })
    }
}

macro_rules! delegate_registry {
    ($ty:ty) => {
        impl DeviceRegistry for $ty {
            fn get(&self, id: &DeviceId) -> Result<Option<DeviceRecord>> {
                self.0.get(id)
            }
            fn list(&self) -> Result<Vec<DeviceRecord>> {
                self.0.list()
            }
            fn upsert_paired(
                &self,
                key: &PublicKey,
                name: &str,
                now_unix: u64,
            ) -> Result<DeviceRecord> {
                self.0.upsert_paired(key, name, now_unix)
            }
            fn record_pin_failure(
                &self,
                id: &DeviceId,
                max_failures: u32,
                now_unix: u64,
            ) -> Result<PinFailure> {
                self.0.record_pin_failure(id, max_failures, now_unix)
            }
            fn record_pin_success(&self, id: &DeviceId, now_unix: u64) -> Result<()> {
                self.0.record_pin_success(id, now_unix)
            }
            fn revoke(&self, id: &DeviceId, reason: RevokeReason, now_unix: u64) -> Result<bool> {
                self.0.revoke(id, reason, now_unix)
            }
            fn reinstate(&self, id: &DeviceId) -> Result<bool> {
                self.0.reinstate(id)
            }
            fn remove(&self, id: &DeviceId) -> Result<bool> {
                self.0.remove(id)
            }
        }
    };
}

// ------------------------------------------------------------------ memory

/// Registry that lives in memory only (tests, ephemeral setups).
pub struct MemoryRegistry(Store);

impl MemoryRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self(Store {
            state: Mutex::new(State::new()),
            file: None,
        })
    }
}

impl Default for MemoryRegistry {
    fn default() -> Self {
        Self::new()
    }
}

delegate_registry!(MemoryRegistry);

// ------------------------------------------------------------------ file

/// Registry persisted in one file, replaced atomically on every change.
pub struct FileRegistry(Store);

const FILE_VERSION: u32 = 1;

#[derive(Clone, PartialEq, Message)]
struct FileDoc {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(message, repeated, tag = "2")]
    devices: Vec<FileDevice>,
}

#[derive(Clone, PartialEq, Message)]
struct FileDevice {
    #[prost(bytes = "vec", tag = "1")]
    id: Vec<u8>,
    #[prost(string, tag = "2")]
    name: String,
    #[prost(bytes = "vec", tag = "3")]
    public_key: Vec<u8>,
    #[prost(uint64, tag = "4")]
    created: u64,
    #[prost(uint64, tag = "5")]
    last_seen: u64,
    #[prost(uint32, tag = "6")]
    failed_pins: u32,
    #[prost(uint64, tag = "7")]
    revoked_at: u64,
    /// 0 = not revoked, otherwise a [`RevokeReason`] code.
    #[prost(uint32, tag = "8")]
    revoke_reason: u32,
}

impl FileRegistry {
    /// Open (or start) the registry at `path`. A missing file is an empty registry. A file that
    /// other users can read or write, that is not a regular file, or that does not parse is an
    /// error: the registry fails closed rather than start from nothing.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let state = match fs::symlink_metadata(&path) {
            Ok(meta) => {
                if !meta.is_file() {
                    return Err(Error::Corrupt("registry path is not a regular file".into()));
                }
                if meta.permissions().mode() & 0o077 != 0 {
                    return Err(Error::InsecurePermissions);
                }
                decode_file(&fs::read(&path)?)?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self(Store {
            state: Mutex::new(state),
            file: Some(path),
        }))
    }
}

delegate_registry!(FileRegistry);

fn decode_file(bytes: &[u8]) -> Result<State> {
    let doc =
        FileDoc::decode(bytes).map_err(|_| Error::Corrupt("registry does not parse".into()))?;
    if doc.version != FILE_VERSION {
        return Err(Error::Corrupt(format!(
            "unsupported registry version {}",
            doc.version
        )));
    }
    let mut state = State::new();
    for d in doc.devices {
        let key_bytes: [u8; 32] = d
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::Corrupt("device key length".into()))?;
        let key = PublicKey::from_bytes(&key_bytes)
            .map_err(|_| Error::Corrupt("device key invalid".into()))?;
        let id = DeviceId::from_slice(&d.id).ok_or_else(|| Error::Corrupt("device id".into()))?;
        if id != key.device_id() {
            return Err(Error::Corrupt("device id does not match its key".into()));
        }
        let revoked = match (d.revoke_reason, RevokeReason::from_code(d.revoke_reason)) {
            (0, _) => None,
            (_, Some(reason)) => Some(Revocation {
                at_unix: d.revoked_at,
                reason,
            }),
            _ => return Err(Error::Corrupt("revocation reason".into())),
        };
        let rec = DeviceRecord {
            id,
            name: d.name,
            public_key: key,
            created_unix: d.created,
            last_seen_unix: d.last_seen,
            failed_pins: d.failed_pins,
            revoked,
        };
        if state.insert(id, rec).is_some() {
            return Err(Error::Corrupt("duplicate device".into()));
        }
    }
    Ok(state)
}

fn encode_file(state: &State) -> Vec<u8> {
    FileDoc {
        version: FILE_VERSION,
        devices: state
            .values()
            .map(|r| FileDevice {
                id: r.id.as_bytes().to_vec(),
                name: r.name.clone(),
                public_key: r.public_key.as_bytes().to_vec(),
                created: r.created_unix,
                last_seen: r.last_seen_unix,
                failed_pins: r.failed_pins,
                revoked_at: r.revoked.map_or(0, |v| v.at_unix),
                revoke_reason: r.revoked.map_or(0, |v| v.reason.code()),
            })
            .collect(),
    }
    .encode_to_vec()
}

/// Write `state` to `path` atomically: temporary file (0600, exclusive) in the same
/// directory, flushed, renamed over `path`, directory flushed.
fn persist(path: &Path, state: &State) -> Result<()> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .ok_or_else(|| Error::Corrupt("registry path has no file name".into()))?;
    let mut tmp_name = name.to_os_string();
    tmp_name.push(format!(".{}.tmp", std::process::id()));
    let tmp = dir.join(tmp_name);
    // A leftover from a crash of an earlier process with the same pid.
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let result = (|| -> std::io::Result<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(&encode_file(state))?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)?;
        fs::File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::IdentityKey;

    fn key() -> PublicKey {
        IdentityKey::generate().expect("key").public()
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "hx-crypto-{tag}-{}-{}",
            std::process::id(),
            crate::keys::random_bytes::<4>()
                .map(|b| u32::from_le_bytes(b))
                .unwrap_or(0)
        ));
        fs::create_dir_all(&d).expect("tmp dir");
        d
    }

    #[test]
    fn lifecycle_in_memory() {
        let r = MemoryRegistry::new();
        let k = key();
        let rec = r.upsert_paired(&k, "laptop", 10).unwrap();
        assert_eq!(r.find_by_key(&k).unwrap().unwrap(), rec);
        assert!(r.find_by_key(&key()).unwrap().is_none());
        // Failures count and the 5th revokes, in one step.
        for n in 1..5 {
            let f = r.record_pin_failure(&rec.id, 5, 20).unwrap();
            assert_eq!((f.failed_pins, f.revoked), (n, false));
        }
        let f = r.record_pin_failure(&rec.id, 5, 21).unwrap();
        assert!(f.revoked);
        let got = r.get(&rec.id).unwrap().unwrap();
        assert_eq!(
            got.revoked.unwrap().reason,
            RevokeReason::TooManyPinFailures
        );
        assert!(!r.revoke(&rec.id, RevokeReason::User, 22).unwrap());
        // Re-pairing keeps the counter and revocation.
        let again = r.upsert_paired(&k, "renamed", 30).unwrap();
        assert_eq!(again.name, "renamed");
        assert!(again.is_revoked());
        assert_eq!(again.created_unix, 10);
        assert!(r.reinstate(&rec.id).unwrap());
        let ok = r.get(&rec.id).unwrap().unwrap();
        assert!(!ok.is_revoked() && ok.failed_pins == 0);
        r.record_pin_failure(&rec.id, 5, 40).unwrap();
        r.record_pin_success(&rec.id, 50).unwrap();
        let ok = r.get(&rec.id).unwrap().unwrap();
        assert_eq!((ok.failed_pins, ok.last_seen_unix), (0, 50));
        assert!(r.remove(&rec.id).unwrap());
        assert!(matches!(
            r.record_pin_success(&rec.id, 1),
            Err(Error::UnknownDevice)
        ));
    }

    #[test]
    fn file_registry_persists_atomically_with_0600() {
        let dir = tmp_dir("file");
        let path = dir.join("devices.pb");
        let k = key();
        {
            let r = FileRegistry::open(&path).unwrap();
            r.upsert_paired(&k, "phone", 5).unwrap();
            r.record_pin_failure(&k.device_id(), 5, 6).unwrap();
            r.revoke(&k.device_id(), RevokeReason::User, 7).unwrap();
        }
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let r = FileRegistry::open(&path).unwrap();
        let rec = r.find_by_key(&k).unwrap().unwrap();
        assert_eq!(rec.name, "phone");
        assert_eq!(rec.failed_pins, 1);
        assert_eq!(rec.revoked.unwrap().reason, RevokeReason::User);
        // No temporary file is left behind.
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn open_fails_closed_on_bad_files() {
        let dir = tmp_dir("bad");
        let path = dir.join("devices.pb");
        fs::write(&path, b"\xff\xff garbage").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(FileRegistry::open(&path), Err(Error::Corrupt(_))));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            FileRegistry::open(&path),
            Err(Error::InsecurePermissions)
        ));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_failed_write_changes_nothing() {
        let dir = tmp_dir("ro");
        let path = dir.join("devices.pb");
        let r = FileRegistry::open(&path).unwrap();
        let k = key();
        r.upsert_paired(&k, "a", 1).unwrap();
        // Make the directory unwritable (skipped when running as root, who can still write).
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
        let denied = fs::File::create(dir.join("probe")).is_err();
        if denied {
            assert!(r.record_pin_failure(&k.device_id(), 5, 2).is_err());
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
            assert_eq!(r.get(&k.device_id()).unwrap().unwrap().failed_pins, 0);
        } else {
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn tampered_id_is_rejected() {
        let k = key();
        let mut state = State::new();
        state.insert(
            k.device_id(),
            DeviceRecord {
                id: k.device_id(),
                name: "x".into(),
                public_key: k,
                created_unix: 1,
                last_seen_unix: 0,
                failed_pins: 0,
                revoked: None,
            },
        );
        let mut doc = FileDoc::decode(encode_file(&state).as_slice()).unwrap();
        doc.devices[0].id[0] ^= 1;
        assert!(matches!(
            decode_file(&doc.encode_to_vec()),
            Err(Error::Corrupt(_))
        ));
    }
}
