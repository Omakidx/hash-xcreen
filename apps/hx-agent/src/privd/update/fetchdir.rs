//! Reading what the fetcher left (ipc.md 6.12 rule 2, and 7 rule 15).
//!
//! The fetcher's directory is **hostile**: a compromised fetcher can plant symlinks, hard links,
//! fifos and mounts-in-waiting, and can rewrite a file at any moment. privd therefore:
//!
//! * opens the directory once, `O_DIRECTORY|O_NOFOLLOW`, and keeps the descriptor; every later
//!   operation is relative to that descriptor;
//! * opens each file with `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS)`,
//!   `O_NOFOLLOW|O_NONBLOCK|O_NOCTTY` (a fifo cannot block the daemon, a symlink is refused);
//! * checks the **open descriptor** (`fstat`): a regular file, link count 1, size within quota;
//! * copies the bytes from that descriptor, once, into memory (the manifest) or into an
//!   `O_TMPFILE` of the root-only staging directory (the artifact), hashing the bytes as they are
//!   copied. Everything verified afterwards is that copy; the fetcher's file is never reopened.
//!
//! The directory is created by privd (root, mode 1733: the fetcher's dynamic user reaches it only
//! through the unit's bind mount, because the state directory above it is 0700) and swept before
//! every fetch with `unlinkat` relative to the descriptor, never by path.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;

use rustix::fs::{AtFlags, FileType, Mode, OFlags, ResolveFlags};
use sha2::{Digest, Sha256};

use super::verify::hex;

/// Why a file of the fetcher's directory was not accepted.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// No such file.
    #[error("the fetcher left no `{0}`")]
    Missing(String),
    /// A symlink, a special file or a directory where a regular file was expected.
    #[error("`{0}` is not a regular file")]
    NotRegular(String),
    /// Hard-linked elsewhere.
    #[error("`{0}` has more than one link")]
    Linked(String),
    /// Larger than its quota (or than the size the signed manifest announced).
    #[error("`{0}` exceeds its size quota")]
    TooBig(String),
    /// Smaller than the size the signed manifest announced.
    #[error("`{0}` is shorter than announced")]
    Short(String),
    /// Anything else the kernel said.
    #[error("cannot read `{name}`: {source}")]
    Io {
        /// The file.
        name: String,
        /// The error.
        source: io::Error,
    },
}

/// The open fetch directory.
pub struct FetchDir {
    fd: OwnedFd,
}

fn dir_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

/// Creates a root-only directory (`mode`) if missing, then checks it is a directory (not a
/// symlink) owned by the effective uid. Returns nothing; callers open it afterwards.
pub fn ensure_dir(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new().mode(mode).create(path)?;
        }
        Err(e) => return Err(e),
    }
    let m = std::fs::symlink_metadata(path)?;
    if !m.is_dir() || m.uid() != rustix::process::geteuid().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "not a directory owned by privd",
        ));
    }
    if m.permissions().mode() & 0o7777 != mode {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

impl FetchDir {
    /// Opens the directory without following a symlink at its last component.
    pub fn open(path: &Path) -> io::Result<Self> {
        let fd = rustix::fs::open(path, dir_flags(), Mode::empty())?;
        Ok(Self { fd })
    }

    /// Removes every entry privd can remove, relative to the directory descriptor, then checks
    /// that the names privd reads are gone. A subdirectory the fetcher made (and that privd,
    /// holding no `CAP_DAC_OVERRIDE`, cannot empty) is left alone: privd never reads anything but
    /// the three fixed names.
    pub fn sweep(&self, known: &[&str]) -> io::Result<()> {
        let names: Vec<String> = rustix::fs::Dir::read_from(&self.fd)?
            .filter_map(Result::ok)
            .filter_map(|e| e.file_name().to_str().ok().map(str::to_string))
            .filter(|n| n != "." && n != "..")
            .collect();
        for n in names {
            if rustix::fs::unlinkat(&self.fd, n.as_str(), AtFlags::empty()).is_err() {
                let _ = rustix::fs::unlinkat(&self.fd, n.as_str(), AtFlags::REMOVEDIR);
            }
        }
        for k in known {
            match rustix::fs::statat(&self.fd, *k, AtFlags::SYMLINK_NOFOLLOW) {
                Err(rustix::io::Errno::NOENT) => {}
                _ => {
                    return Err(io::Error::other(format!(
                        "cannot clear `{k}` from the fetch directory"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Opens `name` as the rules above require and returns the descriptor and its length.
    fn open_checked(&self, name: &str, max: u64) -> Result<(File, u64), ReadError> {
        let io_err = |source| ReadError::Io {
            name: name.to_string(),
            source,
        };
        let fd = rustix::fs::openat2(
            &self.fd,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|e| match e {
            rustix::io::Errno::NOENT => ReadError::Missing(name.to_string()),
            // ELOOP (a symlink), ENXIO (a socket or a fifo with no writer), EISDIR and friends.
            rustix::io::Errno::LOOP
            | rustix::io::Errno::NXIO
            | rustix::io::Errno::ISDIR
            | rustix::io::Errno::MLINK => ReadError::NotRegular(name.to_string()),
            other => io_err(other.into()),
        })?;
        let st = rustix::fs::fstat(&fd).map_err(|e| io_err(e.into()))?;
        if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
            return Err(ReadError::NotRegular(name.to_string()));
        }
        if st.st_nlink != 1 {
            return Err(ReadError::Linked(name.to_string()));
        }
        let len = u64::try_from(st.st_size).unwrap_or(u64::MAX);
        if len > max {
            return Err(ReadError::TooBig(name.to_string()));
        }
        Ok((File::from(fd), len))
    }

    /// Reads a small file once into memory (at most `max` bytes).
    pub fn read_small(&self, name: &str, max: u64) -> Result<Vec<u8>, ReadError> {
        let (file, len) = self.open_checked(name, max)?;
        let mut buf = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
        // The file may grow after the fstat: read at most `max + 1` and refuse the excess.
        let n = file
            .take(max + 1)
            .read_to_end(&mut buf)
            .map_err(|source| ReadError::Io {
                name: name.to_string(),
                source,
            })?;
        if n as u64 > max {
            return Err(ReadError::TooBig(name.to_string()));
        }
        Ok(buf)
    }

    /// Copies a large file once into an anonymous file of the staging directory, hashing exactly
    /// the bytes copied. `expected_len` is the size the signed manifest announced: a file of any
    /// other length is refused.
    pub fn stage_large(
        &self,
        name: &str,
        expected_len: u64,
        staging: &Path,
    ) -> Result<Staged, ReadError> {
        let (mut src, _len) = self.open_checked(name, expected_len)?;
        let io_err = |source| ReadError::Io {
            name: name.to_string(),
            source,
        };
        let mut dst = anonymous_file(staging).map_err(io_err)?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            // Never read past the announced size: a growing file is over quota, not a longer
            // artifact.
            let want = usize::try_from((expected_len + 1 - total).min(buf.len() as u64))
                .unwrap_or(buf.len());
            let n = loop {
                match src.read(&mut buf[..want]) {
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        return Err(ReadError::Short(name.to_string()));
                    }
                    r => break r.map_err(io_err)?,
                }
            };
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > expected_len {
                return Err(ReadError::TooBig(name.to_string()));
            }
            hasher.update(&buf[..n]);
            dst.write_all(&buf[..n]).map_err(io_err)?;
        }
        if total < expected_len {
            return Err(ReadError::Short(name.to_string()));
        }
        dst.flush().map_err(io_err)?;
        dst.seek(SeekFrom::Start(0)).map_err(io_err)?;
        Ok(Staged {
            file: dst,
            len: total,
            sha256: hex(&hasher.finalize()),
        })
    }

    /// The directory descriptor (tests plant hostile entries relative to it).
    pub fn fd(&self) -> impl AsFd + '_ {
        &self.fd
    }
}

/// An artifact copy in privd's own staging directory, already hashed.
pub struct Staged {
    /// Positioned at the start; anonymous (no name, so nobody can reopen or replace it).
    pub file: File,
    /// Its length.
    pub len: u64,
    /// SHA-256 of exactly the bytes in `file`, lowercase hex.
    pub sha256: String,
}

/// An unnamed read-write file in `dir` (`O_TMPFILE`), or, where the file system has no
/// `O_TMPFILE`, a file created exclusively and unlinked at once.
fn anonymous_file(dir: &Path) -> io::Result<File> {
    match rustix::fs::open(
        dir,
        OFlags::RDWR | OFlags::TMPFILE | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    ) {
        Ok(fd) => Ok(File::from(fd)),
        Err(rustix::io::Errno::OPNOTSUPP | rustix::io::Errno::ISDIR | rustix::io::Errno::INVAL) => {
            use std::os::unix::fs::OpenOptionsExt;
            let mut b = [0u8; 8];
            getrandom::fill(&mut b).map_err(io::Error::other)?;
            let p = dir.join(format!(".anon-{}", hex(&b)));
            let f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(OFlags::NOFOLLOW.bits() as i32)
                .open(&p)?;
            std::fs::remove_file(&p)?;
            Ok(f)
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{OpenOptionsExt, symlink};

    fn setup() -> (tempfile::TempDir, FetchDir, std::path::PathBuf, std::path::PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let fetch = t.path().join("updates");
        let staging = t.path().join("staging");
        ensure_dir(&fetch, 0o700).unwrap();
        ensure_dir(&staging, 0o700).unwrap();
        (t, FetchDir::open(&fetch).unwrap(), fetch, staging)
    }

    #[test]
    fn a_regular_file_is_read_once_and_hashed() {
        let (_t, d, fetch, staging) = setup();
        std::fs::write(fetch.join("artifact.tar.gz"), b"hello artifact").unwrap();
        let s = d.stage_large("artifact.tar.gz", 14, &staging).unwrap();
        assert_eq!(s.len, 14);
        assert_eq!(s.sha256, super::super::verify::sha256_hex(b"hello artifact"));
        // The fetcher rewrites its file after the copy: the staged bytes do not change.
        std::fs::write(fetch.join("artifact.tar.gz"), b"EVIL EVIL EVIL").unwrap();
        let mut got = String::new();
        let mut f = s.file;
        f.read_to_string(&mut got).unwrap();
        assert_eq!(got, "hello artifact");
        // And the staging directory holds no named file.
        assert_eq!(std::fs::read_dir(&staging).unwrap().count(), 0);
    }

    #[test]
    fn symlinks_fifos_links_and_directories_are_refused() {
        let (t, d, fetch, _s) = setup();
        let secret = t.path().join("secret");
        std::fs::write(&secret, b"root only").unwrap();
        symlink(&secret, fetch.join("manifest.json")).unwrap();
        assert!(matches!(
            d.read_small("manifest.json", 100),
            Err(ReadError::NotRegular(_))
        ));
        std::fs::hard_link(&secret, fetch.join("hard")).unwrap();
        assert!(matches!(d.read_small("hard", 100), Err(ReadError::Linked(_))));
        rustix::fs::mknodat(
            rustix::fs::CWD,
            fetch.join("fifo"),
            FileType::Fifo,
            Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        assert!(matches!(d.read_small("fifo", 100), Err(ReadError::NotRegular(_))));
        std::fs::create_dir(fetch.join("dir")).unwrap();
        assert!(matches!(d.read_small("dir", 100), Err(ReadError::NotRegular(_))));
        assert!(matches!(d.read_small("nope", 100), Err(ReadError::Missing(_))));
        // A name that tries to leave the directory is not a name at all.
        assert!(d.read_small("../secret", 100).is_err());
        assert!(d.read_small("/etc/passwd", 100).is_err());
    }

    #[test]
    fn a_symlinked_directory_is_not_opened_and_a_swap_is_not_followed() {
        let (t, d, fetch, _s) = setup();
        std::fs::write(fetch.join("manifest.json"), b"good").unwrap();
        assert_eq!(d.read_small("manifest.json", 100).unwrap(), b"good");
        // The directory is replaced by a symlink after privd opened it: privd keeps reading the
        // directory it opened.
        let moved = t.path().join("moved");
        std::fs::rename(&fetch, &moved).unwrap();
        let other = t.path().join("other");
        std::fs::create_dir(&other).unwrap();
        std::fs::write(other.join("manifest.json"), b"planted").unwrap();
        symlink(&other, &fetch).unwrap();
        assert_eq!(d.read_small("manifest.json", 100).unwrap(), b"good");
        // And a fresh open of the symlink is refused.
        assert!(FetchDir::open(&fetch).is_err());
        assert!(ensure_dir(&fetch, 0o700).is_err());
    }

    #[test]
    fn quotas_and_announced_sizes_are_enforced() {
        let (_t, d, fetch, staging) = setup();
        std::fs::write(fetch.join("big"), vec![7u8; 1000]).unwrap();
        assert!(matches!(d.read_small("big", 999), Err(ReadError::TooBig(_))));
        assert!(matches!(
            d.stage_large("big", 999, &staging),
            Err(ReadError::TooBig(_))
        ));
        assert!(matches!(
            d.stage_large("big", 1001, &staging),
            Err(ReadError::Short(_))
        ));
        assert!(d.stage_large("big", 1000, &staging).is_ok());
    }

    #[test]
    fn sweep_removes_planted_entries_without_following_them() {
        let (t, d, fetch, _s) = setup();
        let victim = t.path().join("victim");
        std::fs::create_dir(&victim).unwrap();
        std::fs::write(victim.join("keep"), b"x").unwrap();
        symlink(&victim, fetch.join("manifest.json")).unwrap();
        std::fs::write(fetch.join("artifact.tar.gz"), b"x").unwrap();
        std::fs::create_dir(fetch.join("sub")).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(fetch.join("extra"))
            .unwrap();
        d.sweep(&["manifest.json", "artifact.tar.gz"]).unwrap();
        assert_eq!(std::fs::read_dir(&fetch).unwrap().count(), 0);
        assert!(victim.join("keep").exists(), "the symlink target survived");
    }
}
