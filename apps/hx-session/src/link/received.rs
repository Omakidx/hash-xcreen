//! The received-files directory (`docs/ipc.md` section 16): where files from the client land.
//!
//! * The directory is opened **once** as a descriptor (`O_DIRECTORY | O_NOFOLLOW`); every file is
//!   created and, if the transfer fails, removed through that descriptor (`openat`, `unlinkat`),
//!   so renaming the directory or planting a symlink where it was cannot redirect either.
//! * Files are created `O_CREAT | O_EXCL | O_NOFOLLOW` with mode `0600` and never overwrite:
//!   `name`, `name.1`, `name.2`, ... A name that would pass 255 bytes with its suffix is
//!   shortened, not refused.
//! * An aggregate **quota** bounds the whole directory (configurable, 8 GiB by default): the
//!   bytes already on disk plus the announced size of every transfer in flight must fit, and the
//!   free space of the filesystem must exceed the announced size by a safety margin. A transfer
//!   that does not fit is refused before any byte is written.

use rustix::fs::{AtFlags, Mode, OFlags, openat, unlinkat};
use std::fs::File;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};

/// Free space that must remain beyond an announced file.
const FREE_SPACE_MARGIN: u64 = 256 * 1024 * 1024;
/// Names are at most this many bytes.
const NAME_MAX: usize = 255;

/// Why a file could not be created.
#[derive(Debug)]
pub(crate) enum ReceivedError {
    /// The quota or the free space does not allow it: refuse the transfer (`REJECTED`).
    NoRoom,
    /// The directory or the file could not be opened: `TRANSFER_ERROR`.
    Io(std::io::Error),
}

struct Dir {
    fd: OwnedFd,
}

/// The received-files directory of a daemon: lazily opened, shared by every link.
pub(crate) struct ReceivedStore {
    path: PathBuf,
    quota: u64,
    margin: u64,
    dir: Mutex<Option<Arc<Dir>>>,
    /// Announced bytes of the transfers in flight.
    inflight: Arc<AtomicU64>,
}

/// A file being received. `discard` removes it through the directory descriptor; dropping it
/// without `discard` or `finish` leaves it (the caller always does one of the two).
pub(crate) struct ReceivedFile {
    pub file: File,
    pub name: String,
    dir: Arc<Dir>,
    reserved: u64,
    inflight: Arc<AtomicU64>,
}

impl ReceivedStore {
    pub(crate) fn new(path: PathBuf, quota: u64) -> Self {
        Self::with_margin(path, quota, FREE_SPACE_MARGIN)
    }

    pub(crate) fn with_margin(path: PathBuf, quota: u64, margin: u64) -> Self {
        Self {
            path,
            quota,
            margin,
            dir: Mutex::new(None),
            inflight: Arc::new(AtomicU64::new(0)),
        }
    }

    fn open_dir(&self) -> std::io::Result<Arc<Dir>> {
        use std::os::unix::fs::DirBuilderExt;
        let mut g = self.dir.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(d) = &*g {
            return Ok(d.clone());
        }
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.path)?;
        let fd = rustix::fs::open(
            &self.path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let d = Arc::new(Dir { fd });
        *g = Some(d.clone());
        Ok(d)
    }

    /// Bytes of regular files in the directory now (a read-only scan; stale entries the user
    /// deleted do not count).
    fn on_disk(&self) -> u64 {
        std::fs::read_dir(&self.path)
            .map(|rd| {
                rd.flatten()
                    .filter_map(|e| e.metadata().ok())
                    .filter(|m| m.is_file())
                    .map(|m| std::os::unix::fs::MetadataExt::size(&m))
                    .sum()
            })
            .unwrap_or(0)
    }

    /// Creates the file for a transfer announcing `size` bytes under a name derived from `hint`.
    pub(crate) fn create(&self, hint: &str, size: u64) -> Result<ReceivedFile, ReceivedError> {
        let dir = self.open_dir().map_err(ReceivedError::Io)?;
        // Quota: what is on disk, plus every announced transfer in flight, plus this one.
        let reserved_before = self.inflight.fetch_add(size, Relaxed);
        let release = |n: u64| {
            self.inflight.fetch_sub(n, Relaxed);
        };
        if self
            .on_disk()
            .saturating_add(reserved_before)
            .saturating_add(size)
            > self.quota
        {
            release(size);
            return Err(ReceivedError::NoRoom);
        }
        if let Ok(st) = rustix::fs::fstatvfs(&dir.fd) {
            let free = st.f_bavail.saturating_mul(st.f_frsize);
            if free < size.saturating_add(self.margin) {
                release(size);
                return Err(ReceivedError::NoRoom);
            }
        }
        let name = plain_name(hint);
        for n in 0..1000u32 {
            let candidate = candidate_name(&name, n);
            match openat(
                &dir.fd,
                candidate.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            ) {
                Ok(fd) => {
                    return Ok(ReceivedFile {
                        file: File::from(fd),
                        name: candidate,
                        dir,
                        reserved: size,
                        inflight: self.inflight.clone(),
                    });
                }
                Err(rustix::io::Errno::EXIST) => continue,
                Err(e) => {
                    release(size);
                    return Err(ReceivedError::Io(e.into()));
                }
            }
        }
        release(size);
        Err(ReceivedError::Io(std::io::Error::other(
            "no free file name",
        )))
    }

    /// The directory's path (for the clipboard offer of received files; every write still goes
    /// through the descriptor).
    pub(crate) fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Announced bytes of transfers in flight (tests).
    #[cfg(test)]
    pub(crate) fn inflight(&self) -> u64 {
        self.inflight.load(Relaxed)
    }
}

impl ReceivedFile {
    /// The transfer failed or was aborted: remove the partial file through the directory
    /// descriptor and release its reservation.
    pub(crate) fn discard(self) {
        let _ = unlinkat(&self.dir.fd, self.name.as_str(), AtFlags::empty());
        self.inflight.fetch_sub(self.reserved, Relaxed);
    }

    /// The transfer completed: the file stays and counts as on-disk bytes from now on. Returns
    /// the name it was given in the directory.
    pub(crate) fn finish(self) -> String {
        self.inflight.fetch_sub(self.reserved, Relaxed);
        self.name
    }
}

/// A file name this session will create: the announced name when it is a plain component, else
/// `file`. Never a path.
pub(crate) fn plain_name(hint: &str) -> String {
    let ok = !hint.is_empty()
        && hint.len() <= NAME_MAX
        && hint != "."
        && hint != ".."
        && !hint.contains(['/', '\\', '\0'])
        && !hint.starts_with('-');
    if ok {
        hint.to_owned()
    } else {
        "file".to_owned()
    }
}

/// `name` for `n == 0`, else `name.n`, with the base cut (on a character boundary) so the whole
/// stays within 255 bytes.
fn candidate_name(name: &str, n: u32) -> String {
    if n == 0 {
        return name.to_owned();
    }
    let suffix = format!(".{n}");
    let mut end = name.len().min(NAME_MAX - suffix.len());
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{suffix}", &name[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("hx-received-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn names_are_hints_and_never_paths() {
        assert_eq!(plain_name("report.pdf"), "report.pdf");
        for bad in ["", ".", "..", "a/b", "a\\b", "-rf", "nul\0byte"] {
            assert_eq!(plain_name(bad), "file", "{bad:?}");
        }
        assert_eq!(plain_name(&"x".repeat(256)), "file");
    }

    #[test]
    fn files_are_exclusive_private_and_do_not_follow_symlinks() {
        let dir = tmp("excl");
        let store = ReceivedStore::with_margin(dir.clone(), 1 << 30, 0);
        let mut f1 = store.create("a.txt", 1).unwrap();
        let f2 = store.create("a.txt", 1).unwrap();
        let f3 = store.create("a.txt", 1).unwrap();
        assert_eq!(
            (f1.name.as_str(), f2.name.as_str(), f3.name.as_str()),
            ("a.txt", "a.txt.1", "a.txt.2")
        );
        f1.file.write_all(b"x").unwrap();
        assert_eq!(
            std::fs::metadata(dir.join("a.txt"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        // A symlink planted at the target name is never followed: the next name is used.
        std::os::unix::fs::symlink("/etc/passwd", dir.join("b.txt")).unwrap();
        let f4 = store.create("b.txt", 1).unwrap();
        assert_eq!(f4.name, "b.txt.1");
        assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"x");
        f1.finish();
        f2.discard();
        f3.discard();
        f4.discard();
        assert_eq!(store.inflight(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn discard_goes_through_the_directory_descriptor_not_the_path() {
        // Review: after the directory was renamed and a symlink planted in its place, a path
        // based remove would delete a file of the same name elsewhere.
        let base = tmp("fd");
        std::fs::create_dir_all(&base).unwrap();
        let dir = base.join("received");
        let store = ReceivedStore::with_margin(dir.clone(), 1 << 30, 0);
        let f = store.create("victim.txt", 1).unwrap();
        let moved = base.join("moved");
        std::fs::rename(&dir, &moved).unwrap();
        let elsewhere = base.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("victim.txt"), b"keep me").unwrap();
        std::os::unix::fs::symlink(&elsewhere, &dir).unwrap();
        f.discard();
        assert_eq!(
            std::fs::read(elsewhere.join("victim.txt")).unwrap(),
            b"keep me",
            "the file behind the planted symlink is untouched"
        );
        assert!(
            !moved.join("victim.txt").exists(),
            "the partial file is gone"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn the_aggregate_quota_refuses_what_does_not_fit() {
        let dir = tmp("quota");
        let store = ReceivedStore::with_margin(dir.clone(), 3_000, 0);
        // Announced bytes of transfers in flight count before anything is written.
        let a = store.create("a", 1_500).unwrap();
        let b = store.create("b", 1_500).unwrap();
        assert!(matches!(store.create("c", 1), Err(ReceivedError::NoRoom)));
        assert_eq!(store.inflight(), 3_000);
        b.discard();
        assert_eq!(store.inflight(), 1_500);
        // Bytes on disk count too: finish `a` with real content, then fill the rest.
        let mut a = a;
        a.file.write_all(&[1u8; 1_500]).unwrap();
        a.finish();
        let c = store.create("c", 1_500).unwrap();
        assert!(matches!(store.create("d", 1), Err(ReceivedError::NoRoom)));
        c.discard();
        // The free-space margin applies as well.
        let tight = ReceivedStore::with_margin(tmp("margin"), 1 << 40, u64::MAX / 2);
        assert!(matches!(tight.create("e", 1), Err(ReceivedError::NoRoom)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn long_names_are_shortened_for_the_collision_suffix() {
        // Review: a 255-byte name plus ".1" used to fail with ENAMETOOLONG.
        let dir = tmp("long");
        let store = ReceivedStore::with_margin(dir.clone(), 1 << 30, 0);
        let long = "x".repeat(255);
        let files: Vec<_> = (0..12).map(|_| store.create(&long, 1).unwrap()).collect();
        assert_eq!(files[0].name.len(), 255);
        for f in &files {
            assert!(f.name.len() <= 255, "{}", f.name.len());
        }
        let names: std::collections::HashSet<_> = files.iter().map(|f| f.name.clone()).collect();
        assert_eq!(names.len(), 12, "all distinct");
        // Multi-byte names are cut on a character boundary.
        let wide = "é".repeat(127) + "z"; // 255 bytes
        assert_eq!(wide.len(), 255);
        let a = store.create(&wide, 1).unwrap();
        let b = store.create(&wide, 1).unwrap();
        assert!(b.name.len() <= 255 && b.name != a.name);
        assert!(std::str::from_utf8(b.name.as_bytes()).is_ok());
        for f in files {
            f.discard();
        }
        a.discard();
        b.discard();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
