//! Blocking termination signals while a hidden prompt has the terminal in no-echo mode.
//!
//! If the process died of `SIGTERM`, `SIGHUP`, `SIGQUIT` or `SIGINT` in that window, the operator's
//! terminal would stay without echo. With the signals **blocked** they wait until the prompt has
//! restored the terminal settings and the block is lifted; then they are delivered with their
//! default action, so the process still ends, only after the terminal is in order. No handler is
//! installed and no state is shared. (`SIGKILL` and `SIGSTOP` cannot be blocked; a killed process
//! leaves the terminal as it was, which the operator can restore with `stty sane`.)
//!
//! This is the one place besides `privd` that needs `unsafe`: `pthread_sigmask` has no safe wrapper
//! in the crates the project uses. The unsafe is two calls on plain stack values.
#![allow(unsafe_code)]

/// The signals that end a process and that a terminal or a supervisor can send.
const BLOCKED: [libc::c_int; 5] = [
    libc::SIGTERM,
    libc::SIGHUP,
    libc::SIGQUIT,
    libc::SIGINT,
    libc::SIGTSTP,
];

/// While alive, the calling thread has [`BLOCKED`] blocked; dropping it restores the old mask
/// (and delivers anything that arrived meanwhile).
pub struct Blocked {
    old: libc::sigset_t,
}

impl Blocked {
    /// Blocks the signals for the calling thread. `None` if the mask cannot be changed (the
    /// prompt then runs unprotected, as it would have before).
    pub fn new() -> Option<Self> {
        // SAFETY: `set` and `old` are valid, writable `sigset_t` values on this stack frame;
        // `sigemptyset` initialises `set`, `sigaddset` is given valid signal numbers, and
        // `pthread_sigmask` writes the previous mask into `old`. Nothing is retained.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            if libc::sigemptyset(&mut set) != 0 {
                return None;
            }
            for s in BLOCKED {
                if libc::sigaddset(&mut set, s) != 0 {
                    return None;
                }
            }
            let mut old: libc::sigset_t = std::mem::zeroed();
            if libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old) != 0 {
                return None;
            }
            Some(Self { old })
        }
    }
}

impl Drop for Blocked {
    fn drop(&mut self) {
        // SAFETY: `old` is the mask `pthread_sigmask` returned in `new`; the output pointer may be
        // null.
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.old, std::ptr::null_mut());
        }
    }
}
