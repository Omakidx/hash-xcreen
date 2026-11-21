//! systemd socket activation (`sd_listen_fds`), implemented here instead of through a crate.
//!
//! `hx-session.socket` creates `/run/hx-session/link.sock` in a root-owned directory and hands the
//! listening descriptor to `hx-session.service` as fd 3 (`docs/ipc.md` section 11). The daemon
//! never creates or binds the path itself.
//!
//! This module holds the **only** `unsafe` in the crate: taking ownership of fd 3
//! (`OwnedFd::from_raw_fd`) and removing the activation variables from the environment once
//! it is adopted. It is sound because the descriptor is checked first: `LISTEN_PID`
//! must be our own pid (so the variables were meant for this process and not inherited), exactly
//! one descriptor must be passed, `/proc/self/fd/3` must be an open socket, and the socket must
//! be a listening unix stream socket. After this call nothing else owns fd 3.

#![allow(unsafe_code)]

use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, Ordering};
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
    /// The descriptor was already adopted by an earlier call (a second adoption of fd 3 would
    /// double-close it).
    #[error("the activated socket was already taken")]
    AlreadyTaken,
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
///
/// **Once per process**: a second call returns [`ActivationError::AlreadyTaken`] instead of
/// adopting fd 3 again. After a successful adoption `LISTEN_PID`, `LISTEN_FDS` and
/// `LISTEN_FDNAMES` are removed from the environment (as `sd_listen_fds(1)` does), so nothing the
/// daemon spawns could mistake the descriptor for its own. Call it at startup, before any other
/// thread exists (removing environment variables is not thread-safe).
pub fn listener_from_env() -> Result<UnixListener, ActivationError> {
    static TAKEN: AtomicBool = AtomicBool::new(false);
    claim(&TAKEN)?;
    let result = adopt();
    if result.is_err() {
        // Nothing was adopted: a later, corrected attempt may try again.
        TAKEN.store(false, Ordering::SeqCst);
    }
    result
}

/// The once-guard: the first caller wins.
fn claim(flag: &AtomicBool) -> Result<(), ActivationError> {
    if flag.swap(true, Ordering::SeqCst) {
        Err(ActivationError::AlreadyTaken)
    } else {
        Ok(())
    }
}

/// Removes the variables systemd set so that they are not inherited or read again.
pub(crate) fn scrub_listen_env() {
    for v in ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"] {
        // SAFETY: documented precondition of `listener_from_env`: called at startup before other
        // threads exist, so nothing reads or writes the environment concurrently.
        unsafe { std::env::remove_var(v) };
    }
}

fn adopt() -> Result<UnixListener, ActivationError> {
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
    scrub_listen_env();
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
    fn the_descriptor_can_only_be_taken_once() {
        // Review: a second adoption of fd 3 would double-close it.
        let flag = AtomicBool::new(false);
        assert_eq!(claim(&flag), Ok(()));
        assert_eq!(claim(&flag), Err(ActivationError::AlreadyTaken));
        assert_eq!(claim(&flag), Err(ActivationError::AlreadyTaken));
    }

    #[test]
    fn the_activation_variables_are_removed_after_adoption() {
        // SAFETY: the only test that touches these variables; no thread of this test binary reads
        // them.
        unsafe {
            std::env::set_var("LISTEN_PID", "1");
            std::env::set_var("LISTEN_FDS", "1");
            std::env::set_var("LISTEN_FDNAMES", "link");
        }
        scrub_listen_env();
        for v in ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"] {
            assert!(std::env::var_os(v).is_none(), "{v}");
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
