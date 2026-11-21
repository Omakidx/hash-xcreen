//! `SO_PEERGROUPS`: the supplementary groups of the process on the other end of a unix socket, as
//! the kernel recorded them at `connect`.
//!
//! privd checks them at every Gateway accept (ipc.md 3): a connecting process that holds a
//! forbidden group (`docker`, `incus-admin`, ...) is refused, whatever the static account files say.
//! `rustix` has no wrapper for this option, so this module holds the second audited `unsafe` block
//! of the crate (the first is in `activation`); a test lists the files that may contain `unsafe`.
#![allow(unsafe_code)]

use std::io;
use std::os::fd::{AsFd, AsRawFd};

/// Largest group list accepted (the kernel's `NGROUPS_MAX` is 65 536; far fewer is normal).
const MAX_GROUPS: usize = 4096;

/// Supplementary gids of the peer of `fd`. The primary gid is not included (it is in
/// `SO_PEERCRED`).
pub fn peer_groups<Fd: AsFd>(fd: Fd) -> io::Result<Vec<u32>> {
    let raw = fd.as_fd().as_raw_fd();
    let mut buf = vec![0u32; 64];
    loop {
        let mut len = (buf.len() * std::mem::size_of::<u32>()) as libc::socklen_t;
        // SAFETY: `raw` is a valid socket descriptor, borrowed from `fd` for the whole call;
        // `buf` is a live allocation of `len` bytes that the kernel may write; `len` is a valid
        // in/out pointer to a `socklen_t`. The kernel writes at most `len` bytes.
        let r = unsafe {
            libc::getsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_PEERGROUPS,
                buf.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if r == 0 {
            buf.truncate(len as usize / std::mem::size_of::<u32>());
            return Ok(buf);
        }
        let e = io::Error::last_os_error();
        let need = len as usize / std::mem::size_of::<u32>();
        if e.raw_os_error() == Some(libc::ERANGE) && need > buf.len() && need <= MAX_GROUPS {
            buf.resize(need, 0);
            continue;
        }
        return Err(e);
    }
}

/// The first of `groups` or `primary` that is in `forbidden`.
pub fn forbidden_peer_group(groups: &[u32], primary: u32, forbidden: &[u32]) -> Option<u32> {
    std::iter::once(primary)
        .chain(groups.iter().copied())
        .find(|g| forbidden.contains(g))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_socketpair_reports_our_own_groups() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let g = peer_groups(&a).unwrap();
        // The test process's supplementary groups, as the kernel sees them.
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let want: Vec<u32> = status
            .lines()
            .find_map(|l| l.strip_prefix("Groups:"))
            .unwrap()
            .split_whitespace()
            .filter_map(|x| x.parse().ok())
            .collect();
        assert_eq!(g, want);
    }

    #[test]
    fn the_forbidden_check_covers_primary_and_supplementary() {
        assert_eq!(forbidden_peer_group(&[5, 27], 1000, &[27, 999]), Some(27));
        assert_eq!(forbidden_peer_group(&[5], 999, &[27, 999]), Some(999));
        assert_eq!(forbidden_peer_group(&[5, 6], 1000, &[27, 999]), None);
        assert_eq!(forbidden_peer_group(&[], 1000, &[]), None);
    }
}
