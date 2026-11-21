//! Socket activation (`sd_listen_fds(3)` by hand) and a path-binding fallback for tests.
//!
//! privd inherits `/run/hx/privd.sock` from `hx-privd.socket` (ipc.md 3), so it needs no
//! permission to create it and the socket survives a privd restart.
//!
//! # The one `unsafe` block of the crate
//!
//! Adopting descriptor 3 as an owned socket needs `OwnedFd::from_raw_fd`, which `std` (and
//! `rustix`) mark `unsafe`: the compiler cannot know that nobody else owns the number. The block
//! is in [`adopt_listen_fd`], runs at most once per process (a flag refuses a second call), only
//! after `LISTEN_PID` matched our pid and `LISTEN_FDS` is exactly 1, and the result is checked
//! straight away to be a listening stream unix socket bound to the path we expect.
#![allow(unsafe_code)]

use std::io;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use rustix::io::{FdFlags, fcntl_setfd};
use rustix::net::{SocketAddrUnix, SocketType, getsockname, sockopt};

/// First descriptor systemd passes (`SD_LISTEN_FDS_START`).
pub const LISTEN_FDS_START: i32 = 3;

/// Why socket activation failed.
#[derive(Debug, thiserror::Error)]
pub enum ActivationError {
    /// The environment does not describe an activated socket for this process.
    #[error("not socket-activated: {0}")]
    NotActivated(&'static str),
    /// The inherited descriptor is not the socket this daemon serves.
    #[error("the inherited descriptor is not the expected socket: {0}")]
    WrongSocket(&'static str),
    /// `adopt_listen_fd` was already called in this process.
    #[error("the activation descriptor was already adopted")]
    AlreadyAdopted,
    /// A system call failed.
    #[error("io: {0}")]
    Io(#[from] io::Error),
    /// A system call failed (`rustix`).
    #[error("system call: {0}")]
    Errno(#[from] rustix::io::Errno),
}

/// Number of descriptors systemd passed to this process, from the two environment variables.
///
/// `LISTEN_PID` must equal `my_pid` (the variables are inherited by children, which must not take
/// the descriptors) and `LISTEN_FDS` must be exactly 1: `hx-privd.socket` has one `ListenStream`.
pub fn parse_listen_env(
    listen_pid: Option<&str>,
    listen_fds: Option<&str>,
    my_pid: u32,
) -> Result<usize, ActivationError> {
    let pid: u32 = listen_pid
        .ok_or(ActivationError::NotActivated("LISTEN_PID is not set"))?
        .parse()
        .map_err(|_| ActivationError::NotActivated("LISTEN_PID is not a number"))?;
    if pid != my_pid {
        return Err(ActivationError::NotActivated(
            "LISTEN_PID is not this process",
        ));
    }
    let n: usize = listen_fds
        .ok_or(ActivationError::NotActivated("LISTEN_FDS is not set"))?
        .parse()
        .map_err(|_| ActivationError::NotActivated("LISTEN_FDS is not a number"))?;
    if n != 1 {
        return Err(ActivationError::NotActivated(
            "LISTEN_FDS must be exactly 1",
        ));
    }
    Ok(n)
}

static ADOPTED: AtomicBool = AtomicBool::new(false);

/// Takes ownership of descriptor 3. See the module docs for why this is the only `unsafe` code.
fn adopt_listen_fd() -> Result<OwnedFd, ActivationError> {
    if ADOPTED.swap(true, Ordering::SeqCst) {
        return Err(ActivationError::AlreadyAdopted);
    }
    // SAFETY: systemd opened descriptor `LISTEN_FDS_START` for this process and told us so with
    // `LISTEN_PID` equal to our pid (checked by the caller); no other object in this process owns
    // it, because this function runs once (the flag above) at start before any other code opens
    // descriptors by number. `OwnedFd` takes unique ownership and closes it on drop.
    Ok(unsafe { OwnedFd::from_raw_fd(LISTEN_FDS_START) })
}

/// The listener systemd passed, checked to be a listening `SOCK_STREAM` unix socket bound to
/// `expected_path`. Close-on-exec is set so that no child ever inherits it.
pub fn from_env(expected_path: &Path) -> Result<UnixListener, ActivationError> {
    let my_pid = rustix::process::getpid().as_raw_nonzero().get() as u32;
    parse_listen_env(
        std::env::var("LISTEN_PID").ok().as_deref(),
        std::env::var("LISTEN_FDS").ok().as_deref(),
        my_pid,
    )?;
    let fd = adopt_listen_fd()?;
    fcntl_setfd(&fd, FdFlags::CLOEXEC)?;
    if sockopt::socket_type(&fd)? != SocketType::STREAM {
        return Err(ActivationError::WrongSocket("not a stream socket"));
    }
    if !sockopt::socket_acceptconn(&fd)? {
        return Err(ActivationError::WrongSocket("not a listening socket"));
    }
    let bound = SocketAddrUnix::try_from(getsockname(&fd)?)
        .map_err(|_| ActivationError::WrongSocket("not a unix socket"))?;
    let bound_path = bound.path().map(|p| p.to_bytes().to_vec());
    if bound_path.as_deref() != Some(expected_path.as_os_str().as_bytes()) {
        return Err(ActivationError::WrongSocket("bound to another path"));
    }
    let listener = UnixListener::from(fd);
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Binds `path` (tests and the in-process integration harness only: the daemon binary never calls
/// this, it has no option that reaches it). A stale socket file at the path is replaced; any other
/// kind of file is refused.
pub fn bind_path(path: &Path) -> io::Result<UnixListener> {
    use std::os::unix::fs::FileTypeExt;
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "the path exists and is not a socket",
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let l = UnixListener::bind(path)?;
    l.set_nonblocking(true)?;
    Ok(l)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_env_rules() {
        assert_eq!(parse_listen_env(Some("42"), Some("1"), 42).unwrap(), 1);
        for (pid, fds) in [
            (None, Some("1")),
            (Some("42"), None),
            (Some("41"), Some("1")),
            (Some("x"), Some("1")),
            (Some("42"), Some("2")),
            (Some("42"), Some("0")),
            (Some("42"), Some("x")),
        ] {
            assert!(parse_listen_env(pid, fds, 42).is_err(), "{pid:?} {fds:?}");
        }
    }

    #[test]
    fn bind_path_replaces_a_stale_socket_but_not_a_file() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("s.sock");
        drop(bind_path(&p).unwrap());
        drop(bind_path(&p).unwrap());
        let f = d.path().join("plain");
        std::fs::write(&f, b"x").unwrap();
        assert!(bind_path(&f).is_err());
    }

    #[test]
    fn this_process_was_not_activated() {
        // The test runner is not started by systemd with LISTEN_PID set to its pid.
        assert!(from_env(Path::new("/nonexistent")).is_err());
    }
}
