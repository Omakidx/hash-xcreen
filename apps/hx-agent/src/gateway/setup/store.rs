//! The persisted part of the setup state: the window mirror and the setup binding
//! (`docs/ipc.md` 2 and 5.5). `/var/lib/hx-gatewayd/setup`, 0600, rewritten atomically
//! (temporary file, `fsync`, `rename`, directory `fsync`) exactly like the verifier file, so
//! gatewayd's seccomp allowlist (`openat fsync renameat unlinkat ...`) already covers it.
//!
//! The file holds nothing secret: the window times, the **public** 8-byte id of the installer's
//! token, and the id of the bound device.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use hx_crypto::DeviceId;

use crate::gateway::util::{device_id, hex, unhex};

/// What survives a gatewayd restart.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Persisted {
    /// When the window was opened (Unix seconds); 0 when there is none.
    pub window_opened: u64,
    /// When it ends (Unix seconds); 0 when closed.
    pub window_expires: u64,
    /// The public id of the token the installer created while the window was open.
    pub token_id: Option<[u8; 8]>,
    /// The bound setup device.
    pub device: Option<DeviceId>,
}

/// Why the store could not be opened or written.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// A file system problem, or a file that is not private to this user.
    #[error("setup store: {0}")]
    Storage(String),
    /// The file is not in the documented format.
    #[error("setup store: malformed file")]
    Malformed,
}

/// The file and its in-memory copy.
pub struct SetupStore {
    path: PathBuf,
    write_lock: Mutex<()>,
}

impl SetupStore {
    /// Opens the store at `path` and returns it with what was stored. Fails closed like the
    /// verifier store: the parent directory must not be writable by group or others, and an
    /// existing file must be a private regular file of this user that parses.
    pub fn open(path: impl Into<PathBuf>) -> Result<(Self, Persisted), StoreError> {
        let path = path.into();
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mode = fs::metadata(dir)
            .map_err(|e| StoreError::Storage(e.kind().to_string()))?
            .permissions()
            .mode();
        if mode & 0o022 != 0 {
            return Err(StoreError::Storage(
                "directory is writable by group or others".into(),
            ));
        }
        let state = match fs::OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&path)
        {
            Ok(mut f) => {
                let meta = f
                    .metadata()
                    .map_err(|e| StoreError::Storage(e.kind().to_string()))?;
                if !meta.is_file()
                    || meta.uid() != rustix::process::geteuid().as_raw()
                    || meta.permissions().mode() & 0o077 != 0
                {
                    return Err(StoreError::Storage(
                        "file is not a private regular file".into(),
                    ));
                }
                let mut text = String::new();
                Read::by_ref(&mut f)
                    .take(4096)
                    .read_to_string(&mut text)
                    .map_err(|_| StoreError::Storage("unreadable".into()))?;
                parse(&text)?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Persisted::default(),
            Err(e) => return Err(StoreError::Storage(e.kind().to_string())),
        };
        Ok((
            Self {
                path,
                write_lock: Mutex::new(()),
            },
            state,
        ))
    }

    /// Writes `state` atomically. `Ok` means it survives a crash.
    pub fn save(&self, state: &Persisted) -> Result<(), StoreError> {
        let _w = self.write_lock.lock().unwrap_or_else(|p| p.into_inner());
        let io = |e: std::io::Error| StoreError::Storage(e.kind().to_string());
        let dir = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let tmp = self.path.with_extension("tmp");
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
        fs::rename(&tmp, &self.path).map_err(io)?;
        fs::File::open(dir).and_then(|d| d.sync_all()).map_err(io)?;
        Ok(())
    }
}

fn render(s: &Persisted) -> String {
    let mut out = String::from("# hx-gatewayd setup window and binding (no secrets)\n");
    out.push_str(&format!("window_opened {}\n", s.window_opened));
    out.push_str(&format!("window_expires {}\n", s.window_expires));
    if let Some(t) = &s.token_id {
        out.push_str(&format!("token_id {}\n", hex(t)));
    }
    if let Some(d) = &s.device {
        out.push_str(&format!("device {}\n", hex(d.as_bytes())));
    }
    out
}

fn parse(text: &str) -> Result<Persisted, StoreError> {
    let mut p = Persisted::default();
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut w = line.split(' ');
        match (w.next(), w.next(), w.next()) {
            (Some("window_opened"), Some(v), None) => {
                p.window_opened = v.parse().map_err(|_| StoreError::Malformed)?;
            }
            (Some("window_expires"), Some(v), None) => {
                p.window_expires = v.parse().map_err(|_| StoreError::Malformed)?;
            }
            (Some("token_id"), Some(v), None) => {
                let b = unhex(v).ok_or(StoreError::Malformed)?;
                p.token_id = Some(b.as_slice().try_into().map_err(|_| StoreError::Malformed)?);
            }
            (Some("device"), Some(v), None) => {
                let b = unhex(v).ok_or(StoreError::Malformed)?;
                p.device = Some(device_id(&b).ok_or(StoreError::Malformed)?);
            }
            _ => return Err(StoreError::Malformed),
        }
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        d
    }

    #[test]
    fn persists_atomically_with_private_modes_and_reads_back() {
        let d = dir();
        let path = d.path().join("setup");
        let (store, empty) = SetupStore::open(&path).unwrap();
        assert_eq!(empty, Persisted::default());
        let state = Persisted {
            window_opened: 100,
            window_expires: 7300,
            token_id: Some([1, 2, 3, 4, 5, 6, 7, 8]),
            device: device_id(&[9; 16]),
        };
        store.save(&state).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(!path.with_extension("tmp").exists(), "no temporary file is left");
        let (_, again) = SetupStore::open(&path).unwrap();
        assert_eq!(again, state);
        // Overwriting and clearing.
        store.save(&Persisted::default()).unwrap();
        assert_eq!(SetupStore::open(&path).unwrap().1, Persisted::default());
    }

    #[test]
    fn refuses_loose_modes_symlinks_and_garbage() {
        let d = dir();
        let path = d.path().join("setup");
        let (store, _) = SetupStore::open(&path).unwrap();
        store.save(&Persisted::default()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(SetupStore::open(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, "window_opened nope\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(SetupStore::open(&path), Err(StoreError::Malformed)));
        fs::remove_file(&path).unwrap();
        let target = d.path().join("t");
        fs::write(&target, "").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(SetupStore::open(&path).is_err(), "NOFOLLOW");
        fs::remove_file(&path).unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o770)).unwrap();
        assert!(SetupStore::open(&path).is_err());
    }
}
