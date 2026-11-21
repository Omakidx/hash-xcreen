//! systemd socket activation (`sd_listen_fds`), implemented here instead of through a crate.
//!
//! `hx-session.socket` creates `/run/hx-session/link.sock` in a root-owned directory and hands the
//! listening descriptor to `hx-session.service` as fd 3 (`docs/ipc.md` section 11). The daemon
//! never creates or binds the path itself.
//!
//! This module holds the **only** `unsafe` in the crate: taking ownership of fd 3
//! (`OwnedFd::from_raw_fd`). It is sound because the descriptor is checked first: `LISTEN_PID`
//! must be our own pid (so the variables were meant for this process and not inherited), exactly
//! one descriptor must be passed, `/proc/self/fd/3` must be an open socket, and the socket must
//! be a listening unix stream socket. After this call nothing else owns fd 3.

#![allow(unsafe_code)]

use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::net::UnixListener;
use thiserror::Error;

/// The first descriptor systemd passes (`SD_LISTEN_FDS_START`).
const FIRST_FD: i32 = 3;

/// Why socket activation was not usable.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ActivationError {
    /// `LISTEN_PID`/`LISTEN_FDS` are absent: the daemon was not started by a socket unit.
    #[error("not started by socket activation (LISTEN_PID and LISTEN_FDS are not set)")]
    NotActivated,
    /// The variables are for another process, or malformed.
    #[error("socket activation variables are invalid: {0}")]
    Invalid(&'static str),
    /// Zero or more than one descriptor was passed.
    #[error("expected exactly one activated socket, got {0}")]
    WrongCount(u32),
    /// fd 3 is not a listening unix stream socket.
    #[error("the activated descriptor is not a listening unix stream socket")]
    NotAListener,
}

/// The activation environment, separated from the process environment for tests.
#[derive(Debug, Clone, Default)]
pub struct ListenEnv {
    /// `LISTEN_PID`.
    pub pid: Option<String>,
    /// `LISTEN_FDS`.
    pub fds: Option<String>,
}

impl ListenEnv {
    /// Reads the process environment.
    pub fn from_process() -> Self {
        Self {
            pid: std::env::var("LISTEN_PID").ok(),
            fds: std::env::var("LISTEN_FDS").ok(),
        }
    }

    /// Checks the variables against `our_pid` and returns the number of descriptors.
    pub fn check(&self, our_pid: u32) -> Result<u32, ActivationError> {
        let (Some(pid), Some(fds)) = (&self.pid, &self.fds) else {
            return Err(ActivationError::NotActivated);
        };
        let pid: u32 = pid
            .parse()
            .map_err(|_| ActivationError::Invalid("LISTEN_PID is not a number"))?;
        if pid != our_pid {
            return Err(ActivationError::Invalid("LISTEN_PID is not this process"));
        }
        let n: u32 = fds
            .parse()
            .map_err(|_| ActivationError::Invalid("LISTEN_FDS is not a number"))?;
        if n != 1 {
            return Err(ActivationError::WrongCount(n));
        }
        Ok(n)
    }
}

/// Takes the activated listening socket (fd 3) from the environment systemd set up.
pub fn listener_from_env() -> Result<UnixListener, ActivationError> {
    ListenEnv::from_process().check(rustix::process::getpid().as_raw_nonzero().get() as u32)?;
    // The descriptor must be an open socket before anything takes ownership of it.
    let target = std::fs::read_link(format!("/proc/self/fd/{FIRST_FD}"))
        .map_err(|_| ActivationError::NotAListener)?;
    if !target.to_string_lossy().starts_with("socket:") {
        return Err(ActivationError::NotAListener);
    }
    // SAFETY: LISTEN_PID names this process, exactly one descriptor was passed, and
    // /proc/self/fd/3 is an open socket, so fd 3 is valid and owned by nobody else in this
    // process. This is the single place the descriptor is adopted.
    let fd = unsafe { OwnedFd::from_raw_fd(FIRST_FD) };
    let ty = rustix::net::sockopt::socket_type(&fd).map_err(|_| ActivationError::NotAListener)?;
    let listening =
        rustix::net::sockopt::socket_acceptconn(&fd).map_err(|_| ActivationError::NotAListener)?;
    let unix = rustix::net::getsockname(&fd)
        .is_ok_and(|a| a.address_family() == rustix::net::AddressFamily::UNIX);
    if ty != rustix::net::SocketType::STREAM || !listening || !unix {
        return Err(ActivationError::NotAListener);
    }
    rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC)
        .map_err(|_| ActivationError::NotAListener)?;
    Ok(UnixListener::from(fd))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pid: &str, fds: &str) -> ListenEnv {
        ListenEnv {
            pid: Some(pid.into()),
            fds: Some(fds.into()),
        }
    }

    #[test]
    fn variables_are_checked() {
        assert_eq!(env("42", "1").check(42), Ok(1));
        assert_eq!(
            ListenEnv::default().check(42),
            Err(ActivationError::NotActivated)
        );
        assert!(matches!(
            env("41", "1").check(42),
            Err(ActivationError::Invalid(_))
        ));
        assert!(matches!(
            env("x", "1").check(42),
            Err(ActivationError::Invalid(_))
        ));
        assert!(matches!(
            env("42", "y").check(42),
            Err(ActivationError::Invalid(_))
        ));
        assert_eq!(
            env("42", "0").check(42),
            Err(ActivationError::WrongCount(0))
        );
        assert_eq!(
            env("42", "2").check(42),
            Err(ActivationError::WrongCount(2))
        );
    }
}
