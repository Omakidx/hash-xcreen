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
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
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
    /// keeps its failure counter. A **revoked** device is not touched and the call fails with
    /// [`Error::Revoked`], decided inside the same atomic step as the write.
    fn upsert_paired(&self, key: &PublicKey, name: &str, now_unix: u64) -> Result<DeviceRecord>;

    /// Count a PIN attempt **before** it is checked (so an attempt that is cut off still
    /// counts) and return the failure counter after counting. A correct PIN resets it with
    /// [`record_pin_success`](Self::record_pin_success).
    fn begin_pin_attempt(&self, id: &DeviceId) -> Result<u32>;

    /// Undo one [`begin_pin_attempt`](Self::begin_pin_attempt) because the attempt was never
    /// judged (the verifier could not answer): a saturating decrement of the failure counter,
    /// which never goes below 0. Returns the counter afterwards. It does not touch
    /// `last_seen` or a revocation.
    ///
    /// The default fails, so an implementation written before this method existed keeps
    /// compiling and, when a refund is needed, leaves the attempt counted (the safe side).
    fn refund_pin_attempt(&self, _id: &DeviceId) -> Result<u32> {
        Err(Error::Protocol("this registry cannot refund a PIN attempt"))
    }

    /// Reset the failure counter to 0 without stamping `last_seen` (an operator's lockout
    /// reset; a revocation is left as it is, use [`reinstate`](Self::reinstate) for that).
    /// Fails with [`Error::UnknownDevice`] for an unknown id. The default fails like
    /// [`refund_pin_attempt`](Self::refund_pin_attempt).
    fn reset_pin_failures(&self, _id: &DeviceId) -> Result<()> {
        Err(Error::Protocol("this registry cannot reset PIN failures"))
    }

    /// After a wrong verdict: revoke the device if its counter reached `max_failures`.
    /// Returns true if the device is revoked afterwards.
    fn revoke_if_failed(&self, id: &DeviceId, max_failures: u32, now_unix: u64) -> Result<bool>;

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
    /// Exclusive lock on `<file>.lock`, held for the lifetime of the registry (file-backed only).
    _lock: Option<fs::File>,
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
            if s.get(&id).is_some_and(DeviceRecord::is_revoked) {
                return (Err(Error::Revoked), false);
            }
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
            (Ok(rec.clone()), true)
        })?
    }

    fn begin_pin_attempt(&self, id: &DeviceId) -> Result<u32> {
        self.mutate(|s| match s.get_mut(id) {
            None => (Err(Error::UnknownDevice), false),
            Some(rec) => {
                rec.failed_pins = rec.failed_pins.saturating_add(1);
                (Ok(rec.failed_pins), true)
            }
        })?
    }

    fn refund_pin_attempt(&self, id: &DeviceId) -> Result<u32> {
        self.mutate(|s| match s.get_mut(id) {
            None => (Err(Error::UnknownDevice), false),
            Some(rec) => {
                let changed = rec.failed_pins > 0;
                rec.failed_pins = rec.failed_pins.saturating_sub(1);
                (Ok(rec.failed_pins), changed)
            }
        })?
    }

    fn reset_pin_failures(&self, id: &DeviceId) -> Result<()> {
        self.mutate(|s| match s.get_mut(id) {
            None => (Err(Error::UnknownDevice), false),
            Some(rec) => {
                let changed = rec.failed_pins != 0;
                rec.failed_pins = 0;
                (Ok(()), changed)
            }
        })?
    }

    fn revoke_if_failed(&self, id: &DeviceId, max: u32, now: u64) -> Result<bool> {
        self.mutate(|s| match s.get_mut(id) {
            None => (Err(Error::UnknownDevice), false),
            Some(rec) => {
                let mut changed = false;
                if rec.failed_pins >= max && rec.revoked.is_none() {
                    rec.revoked = Some(Revocation {
                        at_unix: now,
                        reason: RevokeReason::TooManyPinFailures,
                    });
                    changed = true;
                }
                (Ok(rec.revoked.is_some()), changed)
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
            fn begin_pin_attempt(&self, id: &DeviceId) -> Result<u32> {
                self.0.begin_pin_attempt(id)
            }
            fn refund_pin_attempt(&self, id: &DeviceId) -> Result<u32> {
                self.0.refund_pin_attempt(id)
            }
            fn reset_pin_failures(&self, id: &DeviceId) -> Result<()> {
                self.0.reset_pin_failures(id)
            }
            fn revoke_if_failed(
                &self,
                id: &DeviceId,
                max_failures: u32,
                now_unix: u64,
            ) -> Result<bool> {
                self.0.revoke_if_failed(id, max_failures, now_unix)
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
            _lock: None,
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
    /// Open (or start) the registry at `path`, as its **only** writer: an exclusive `flock` on
    /// `<path>.lock` is taken here and held until the value is dropped; if another instance
    /// (in this or another process) holds it the call fails with [`Error::Locked`]. Other tools
    /// (CLI) must therefore revoke and reinstate through the agent, never by opening the file.
    ///
    /// Fails closed: the directory must not be writable by group or others; the file is opened
    /// without following symlinks and must be a regular file owned by the effective user with
    /// mode 0600; it must parse. A missing file is an empty registry.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let dir = parent_dir(&path);
        let dir_mode = fs::metadata(dir)?.permissions().mode();
        if dir_mode & 0o022 != 0 {
            return Err(Error::InsecurePermissions);
        }
        let lock = take_lock(&path)?;
        let state = match open_nofollow(&path) {
            Ok(mut f) => {
                let meta = f.metadata()?;
                if !meta.is_file() {
                    return Err(Error::Corrupt("registry path is not a regular file".into()));
                }
                if meta.uid() != rustix::process::geteuid().as_raw()
                    || meta.permissions().mode() & 0o077 != 0
                {
                    return Err(Error::InsecurePermissions);
                }
                let mut bytes = Vec::new();
                f.read_to_end(&mut bytes)?;
                decode_file(&bytes)?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self(Store {
            state: Mutex::new(state),
            file: Some(path),
            _lock: Some(lock),
        }))
    }
}

fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

fn open_nofollow(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
}

fn take_lock(path: &Path) -> Result<fs::File> {
    let mut name = path
        .file_name()
        .ok_or_else(|| Error::Corrupt("registry path has no file name".into()))?
        .to_os_string();
    name.push(".lock");
    let lock = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(parent_dir(path).join(name))?;
    match rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(lock),
        Err(e) if e == rustix::io::Errno::WOULDBLOCK => Err(Error::Locked),
        Err(e) => Err(std::io::Error::from(e).into()),
    }
}

delegate_registry!(FileRegistry);

pub(crate) fn decode_file(bytes: &[u8]) -> Result<State> {
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
    let dir = parent_dir(path);
    let name = path
        .file_name()
        .ok_or_else(|| Error::Corrupt("registry path has no file name".into()))?;
    let mut tmp_name = name.to_os_string();
    tmp_name.push(format!(
        ".{}.tmp",
        crate::encoding::hex_encode(&crate::keys::random_bytes::<8>()?)
    ));
    let tmp = dir.join(tmp_name);
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
                .map(u32::from_le_bytes)
                .unwrap_or(0)
        ));
        fs::create_dir_all(&d).expect("tmp dir");
        fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).expect("chmod");
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
            assert_eq!(r.begin_pin_attempt(&rec.id).unwrap(), n);
            assert!(!r.revoke_if_failed(&rec.id, 5, 20).unwrap());
        }
        assert_eq!(r.begin_pin_attempt(&rec.id).unwrap(), 5);
        assert!(r.revoke_if_failed(&rec.id, 5, 21).unwrap());
        let got = r.get(&rec.id).unwrap().unwrap();
        assert_eq!(
            got.revoked.unwrap().reason,
            RevokeReason::TooManyPinFailures
        );
        assert!(!r.revoke(&rec.id, RevokeReason::User, 22).unwrap());
        // A revoked device cannot be re-paired, and the record is left alone.
        assert!(matches!(
            r.upsert_paired(&k, "renamed", 30),
            Err(Error::Revoked)
        ));
        assert_eq!(r.get(&rec.id).unwrap().unwrap().name, "laptop");
        assert!(r.reinstate(&rec.id).unwrap());
        let again = r.upsert_paired(&k, "renamed", 31).unwrap();
        assert_eq!((again.name.as_str(), again.created_unix), ("renamed", 10));
        let ok = r.get(&rec.id).unwrap().unwrap();
        assert!(!ok.is_revoked() && ok.failed_pins == 0);
        r.begin_pin_attempt(&rec.id).unwrap();
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
            r.begin_pin_attempt(&k.device_id()).unwrap();
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
    fn refund_undoes_one_attempt_and_never_goes_below_zero() {
        let r = MemoryRegistry::new();
        let k = key();
        let id = r.upsert_paired(&k, "laptop", 10).unwrap().id;
        assert_eq!(r.refund_pin_attempt(&id).unwrap(), 0, "saturates at 0");
        assert_eq!(r.get(&id).unwrap().unwrap().failed_pins, 0);
        assert_eq!(r.begin_pin_attempt(&id).unwrap(), 1);
        assert_eq!(r.begin_pin_attempt(&id).unwrap(), 2);
        assert_eq!(r.refund_pin_attempt(&id).unwrap(), 1);
        assert_eq!(
            r.begin_pin_attempt(&id).unwrap(),
            2,
            "counts again from there"
        );
        assert_eq!(r.refund_pin_attempt(&id).unwrap(), 1);
        assert_eq!(r.refund_pin_attempt(&id).unwrap(), 0);
        assert_eq!(r.refund_pin_attempt(&id).unwrap(), 0);
        // It leaves last_seen and a revocation alone.
        r.record_pin_success(&id, 77).unwrap();
        r.begin_pin_attempt(&id).unwrap();
        r.revoke(&id, RevokeReason::User, 80).unwrap();
        r.refund_pin_attempt(&id).unwrap();
        let rec = r.get(&id).unwrap().unwrap();
        assert_eq!((rec.failed_pins, rec.last_seen_unix), (0, 77));
        assert!(rec.is_revoked());
        assert!(matches!(
            r.refund_pin_attempt(&key().device_id()),
            Err(Error::UnknownDevice)
        ));
    }

    #[test]
    fn reset_zeroes_the_counter_without_stamping_last_seen() {
        let r = MemoryRegistry::new();
        let id = r.upsert_paired(&key(), "laptop", 10).unwrap().id;
        r.record_pin_success(&id, 55).unwrap();
        for _ in 0..3 {
            r.begin_pin_attempt(&id).unwrap();
        }
        r.reset_pin_failures(&id).unwrap();
        let rec = r.get(&id).unwrap().unwrap();
        assert_eq!((rec.failed_pins, rec.last_seen_unix), (0, 55));
        // Idempotent, and a revocation stays.
        r.reset_pin_failures(&id).unwrap();
        r.revoke(&id, RevokeReason::User, 60).unwrap();
        r.reset_pin_failures(&id).unwrap();
        assert!(r.get(&id).unwrap().unwrap().is_revoked());
        assert!(matches!(
            r.reset_pin_failures(&key().device_id()),
            Err(Error::UnknownDevice)
        ));
    }

    #[test]
    fn refund_and_reset_persist_through_the_file_registry() {
        let dir = tmp_dir("refund");
        let path = dir.join("devices.pb");
        let k = key();
        let id = k.device_id();
        {
            let r = FileRegistry::open(&path).unwrap();
            r.upsert_paired(&k, "phone", 5).unwrap();
            for _ in 0..3 {
                r.begin_pin_attempt(&id).unwrap();
            }
            assert_eq!(r.refund_pin_attempt(&id).unwrap(), 2);
        }
        {
            let r = FileRegistry::open(&path).unwrap();
            assert_eq!(r.get(&id).unwrap().unwrap().failed_pins, 2);
            r.reset_pin_failures(&id).unwrap();
        }
        let r = FileRegistry::open(&path).unwrap();
        let rec = r.get(&id).unwrap().unwrap();
        assert_eq!((rec.failed_pins, rec.last_seen_unix), (0, 0));
        // At 0 a refund writes nothing and stays at 0.
        assert_eq!(r.refund_pin_attempt(&id).unwrap(), 0);
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
            assert!(r.begin_pin_attempt(&k.device_id()).is_err());
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

    #[test]
    fn a_second_instance_on_the_same_file_is_refused_until_the_first_is_dropped() {
        let dir = tmp_dir("lock");
        let path = dir.join("devices.pb");
        let first = FileRegistry::open(&path).unwrap();
        assert!(matches!(FileRegistry::open(&path), Err(Error::Locked)));
        // Writes by the holder still work, and nobody else can undo them.
        let k = key();
        first.upsert_paired(&k, "a", 1).unwrap();
        first.revoke(&k.device_id(), RevokeReason::User, 2).unwrap();
        assert!(matches!(FileRegistry::open(&path), Err(Error::Locked)));
        drop(first);
        let second = FileRegistry::open(&path).unwrap();
        assert!(second.get(&k.device_id()).unwrap().unwrap().is_revoked());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn concurrent_openers_get_exactly_one_winner() {
        let dir = tmp_dir("race");
        let path = dir.join("devices.pb");
        let wins: usize = (0..8)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || {
                    // Keep the winner alive until every thread has tried.
                    let r = FileRegistry::open(&path);
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    usize::from(r.is_ok())
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .sum();
        assert_eq!(wins, 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn open_refuses_symlinks_foreign_modes_and_open_directories() {
        let dir = tmp_dir("hard");
        let real = dir.join("real.pb");
        {
            let r = FileRegistry::open(&real).unwrap();
            r.upsert_paired(&key(), "x", 1).unwrap();
        }
        // A symlink at the registry path is not followed.
        let link = dir.join("link.pb");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(FileRegistry::open(&link).is_err());
        // A group-writable directory is refused.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(matches!(
            FileRegistry::open(&real),
            Err(Error::InsecurePermissions)
        ));
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(FileRegistry::open(&real).is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn temporary_files_use_random_names() {
        let dir = tmp_dir("tmpname");
        let path = dir.join("devices.pb");
        // A stale temporary file with a guessable name does not get in the way.
        fs::write(
            dir.join(format!("devices.pb.{}.tmp", std::process::id())),
            b"x",
        )
        .unwrap();
        let r = FileRegistry::open(&path).unwrap();
        r.upsert_paired(&key(), "a", 1).unwrap();
        assert!(FileRegistry::open(&path).is_err());
        drop(r);
        assert_eq!(FileRegistry::open(&path).unwrap().list().unwrap().len(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }
}
