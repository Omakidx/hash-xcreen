//! Peer authentication on a unix socket (`docs/ipc.md` section 3).
//!
//! On every accept privd calls `getsockopt(SO_PEERCRED)`; the peer's uid selects the role for the
//! life of the connection. The allowlist is `{0, uid(hx-gatewayd)}`, the gateway uid being
//! resolved by privd itself at start, never taken from the socket.

use std::io;
use std::os::fd::AsFd;

use rustix::net::sockopt::socket_peercred;

use crate::privd::pb::Role;

/// Credentials of the process that connected, as recorded by the kernel at `connect` time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    /// Process id, for the audit log only (never for decisions, `docs/ipc.md` section 3). It is
    /// relative to the pid namespace of the reader and can be 0 for a peer in another one.
    pub pid: u32,
    /// Effective uid of the peer at `connect`.
    pub uid: u32,
    /// Effective gid of the peer at `connect`.
    pub gid: u32,
}

/// `SO_PEERCRED` of a connected unix stream socket.
pub fn peer_credentials<Fd: AsFd>(fd: Fd) -> io::Result<PeerCred> {
    let c = socket_peercred(fd)?;
    Ok(PeerCred {
        pid: u32::try_from(c.pid.as_raw_nonzero().get()).unwrap_or(0),
        uid: c.uid.as_raw(),
        gid: c.gid.as_raw(),
    })
}

/// The role for a peer uid, or `None` if the peer must be closed without a reply.
///
/// `gateway_uid` is the uid of the `hx-gatewayd` system user as resolved by privd. Root is
/// `Admin`; a gateway uid of 0 is refused here because it would make the roles ambiguous.
pub fn role_for_uid(peer_uid: u32, gateway_uid: u32) -> Option<Role> {
    if gateway_uid == 0 {
        return None;
    }
    match peer_uid {
        0 => Some(Role::Admin),
        u if u == gateway_uid => Some(Role::Gateway),
        _ => None,
    }
}

/// The admin socket allows uid 0 only (`docs/ipc.md` section 9).
pub fn admin_socket_allows(peer_uid: u32) -> bool {
    peer_uid == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles() {
        assert_eq!(role_for_uid(0, 999), Some(Role::Admin));
        assert_eq!(role_for_uid(999, 999), Some(Role::Gateway));
        assert_eq!(role_for_uid(1000, 999), None);
        assert_eq!(role_for_uid(0, 0), None);
        assert!(admin_socket_allows(0));
        assert!(!admin_socket_allows(999));
    }

    #[test]
    fn own_credentials_over_a_socketpair() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let c = peer_credentials(&a).unwrap();
        use std::os::unix::fs::MetadataExt;
        let me = std::fs::metadata("/proc/self").unwrap();
        assert_eq!(c.uid, me.uid());
        assert_eq!(c.gid, me.gid());
    }
}
