//! The lock shared by `install` and `uninstall` (design D3, C4).
//!
//! `install.sh` takes `flock -n 9` on `/run/hx-install.lock` and hands descriptor 9 over with
//! `--lock-fd 9`. The agent checks that the descriptor really is that file (a regular file, ours,
//! the same device and inode as the path) before it trusts it, then locks it (a no-op for the
//! description that already holds the lock). Without `--lock-fd` it opens the file itself.
//!
//! This is the one place of the installer that needs `unsafe`: adopting an inherited descriptor
//! number has no safe wrapper. The block is one call after the descriptor was shown to be open.
#![allow(unsafe_code)]

use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use rustix::fs::{FlockOperation, OFlags};

use super::error::InstallError;

/// A held lock. Dropping it releases the lock.
#[derive(Debug)]
pub struct Lock {
    _fd: OwnedFd,
}

fn locked() -> InstallError {
    InstallError::locked("another hx-agent install or uninstall is running (the lock is held)")
}

/// Takes the lock at `path`, or adopts and verifies the inherited `lock_fd`.
pub fn acquire(path: &Path, lock_fd: Option<i32>) -> Result<Lock, InstallError> {
    let adopted = lock_fd.is_some();
    let fd = match lock_fd {
        Some(n) => adopt(n, path)?,
        None => {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .custom_flags((OFlags::NOFOLLOW | OFlags::CLOEXEC).bits() as i32)
                .open(path)
                .map_err(|e| {
                    InstallError::internal(format!("cannot open the lock file: {}", e.kind()))
                })?;
            OwnedFd::from(f)
        }
    };
    match rustix::fs::flock(&fd, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(Lock { _fd: fd }),
        Err(e) => {
            // An inherited descriptor is not closed on failure (the caller's shell owns the lock).
            if adopted {
                let _ = fd.into_raw_fd();
            }
            if e == rustix::io::Errno::WOULDBLOCK {
                Err(locked())
            } else {
                Err(InstallError::internal(format!("cannot take the lock: {e}")))
            }
        }
    }
}

fn adopt(n: i32, path: &Path) -> Result<OwnedFd, InstallError> {
    if n < 3 {
        return Err(InstallError::usage(
            "--lock-fd must be a descriptor number of 3 or more",
        ));
    }
    // SAFETY: `fcntl(F_GETFD)` only queries the descriptor and has no effect on it.
    if unsafe { libc::fcntl(n, libc::F_GETFD) } == -1 {
        return Err(InstallError::usage("--lock-fd is not an open descriptor"));
    }
    // SAFETY: the descriptor is open (checked above) and was handed to this process for exactly
    // this purpose by `install.sh` (`exec ... --lock-fd 9`); nothing else in the process owns it.
    let fd = unsafe { OwnedFd::from_raw_fd(n) };
    // Until the descriptor is shown to be the lock file it is not ours to close: on every error
    // path it is leaked (`into_raw_fd`), never dropped.
    let refuse = |fd: OwnedFd, e: InstallError| {
        let _ = fd.into_raw_fd();
        e
    };
    let st = match rustix::fs::fstat(&fd) {
        Ok(st) => st,
        Err(e) => return Err(refuse(fd, InstallError::internal(format!("--lock-fd: {e}")))),
    };
    let Ok(on_disk) = rustix::fs::lstat(path) else {
        return Err(refuse(
            fd,
            InstallError::usage("--lock-fd does not match the lock file (it does not exist)"),
        ));
    };
    let regular =
        rustix::fs::FileType::from_raw_mode(st.st_mode) == rustix::fs::FileType::RegularFile;
    if !regular
        || st.st_uid != rustix::process::geteuid().as_raw()
        || (st.st_dev, st.st_ino) != (on_disk.st_dev, on_disk.st_ino)
    {
        return Err(refuse(
            fd,
            InstallError::usage(
                "--lock-fd is not the lock file (a regular file of ours, the same file as the lock path)",
            ),
        ));
    }
    // The tools the installer runs must not inherit the descriptor.
    let flags = rustix::io::fcntl_getfd(&fd).unwrap_or(rustix::io::FdFlags::empty());
    let _ = rustix::io::fcntl_setfd(&fd, flags | rustix::io::FdFlags::CLOEXEC);
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_second_holder_gets_exit_11() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("run/hx-install.lock");
        let first = acquire(&p, None).unwrap();
        let e = acquire(&p, None).unwrap_err();
        assert_eq!(e.exit, 11);
        drop(first);
        assert!(acquire(&p, None).is_ok(), "released on drop");
    }

    #[test]
    fn an_inherited_descriptor_is_verified_and_reused() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("hx-install.lock");
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .read(true)
            .open(&p)
            .unwrap();
        // As install.sh did: lock first, then hand the descriptor over.
        rustix::fs::flock(&f, FlockOperation::NonBlockingLockExclusive).unwrap();
        let n = f.into_raw_fd();
        let held = acquire(&p, Some(n)).expect("the holder itself may re-lock");
        // Someone else still cannot take it.
        assert_eq!(acquire(&p, None).unwrap_err().exit, 11);
        drop(held);
    }

    #[test]
    fn a_descriptor_that_is_not_the_lock_file_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("hx-install.lock");
        std::fs::write(&p, b"").unwrap();
        let other = std::fs::File::create(d.path().join("other")).unwrap();
        let n = other.into_raw_fd();
        let e = acquire(&p, Some(n)).unwrap_err();
        assert_eq!(e.exit, 2, "{}", e.message);
        // N3: a descriptor that is not the lock file is not ours to close.
        assert!(
            std::path::Path::new(&format!("/proc/self/fd/{n}")).exists(),
            "the refused descriptor is still open"
        );
        // Not open, or too small.
        assert!(acquire(&p, Some(1_000_000)).is_err());
        assert!(acquire(&p, Some(1)).is_err());
    }
}
