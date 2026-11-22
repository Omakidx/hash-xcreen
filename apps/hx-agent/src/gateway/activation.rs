//! Socket activation of `hx-gatewayd` (systemd's `LISTEN_FDS` protocol, `sd_listen_fds(3)`).
//!
//! `hx-gatewayd.service` is started with `Sockets=hx-gatewayd-admin.socket
//! hx-gatewayd-public.socket`, so systemd passes descriptors **by name** (`LISTEN_FDNAMES`):
//!
//! | Name | Socket unit | Descriptors |
//! |---|---|---|
//! | `admin` | `hx-gatewayd-admin.socket` | one `AF_UNIX` stream socket (root-only admin socket) |
//! | `public` | `hx-gatewayd-public.socket` | two: a listening TCP socket and a bound UDP socket on the same port (WebSocket and QUIC) |
//!
//! The public sockets exist so that the unprivileged gateway (empty capability bounding set)
//! is reached on port 443: root's systemd binds the port. Descriptors are selected by name,
//! never by index (the order depends on the unit load order), and the type of a `public`
//! descriptor comes from `SO_TYPE`, never from its position.
//!
//! The process is **activated** when `LISTEN_FDS` is set and non-zero. Then everything is
//! checked strictly and a mismatch is a start-up error (never a silent fallback to binding):
//!
//! * `LISTEN_PID` must be this process, `LISTEN_FDNAMES` must name every descriptor;
//! * only the names `admin` (at most once) and `public` (none, or exactly one TCP and one UDP
//!   descriptor) are accepted, anything else is refused;
//! * each descriptor must be what it claims (family, type, listening or bound);
//! * the port of the public sockets must equal the port of `listen` in the configuration
//!   (`/etc/hx/gatewayd.toml`), so that the installer's socket drop-in and the configuration
//!   cannot drift apart unnoticed.
//!
//! Without activation (a development run, tests) the gateway binds `listen` and the admin
//! socket itself.
//!
//! This module is safe code: the descriptors are adopted by the `listenfd` crate, which
//! validates family and type before it wraps them.

use std::net::{TcpListener, UdpSocket};
use std::os::unix::net::UnixListener;

/// The two names this gateway understands.
const ADMIN: &str = "admin";
const PUBLIC: &str = "public";

/// Why activation was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ActivationError {
    /// A `LISTEN_*` variable is malformed or does not belong to this process.
    #[error("socket activation: {0}")]
    Invalid(&'static str),
    /// A descriptor name this gateway does not use.
    #[error(
        "socket activation: unexpected descriptor name {0:?} (expected \"admin\" and \"public\")"
    )]
    UnexpectedName(String),
    /// A name that may appear once appears more than once.
    #[error("socket activation: the descriptor name {0:?} appears more than once")]
    Duplicate(&'static str),
    /// The `public` descriptors are not exactly one TCP and one UDP socket.
    #[error("socket activation: \"public\" must be exactly one TCP and one UDP socket")]
    PublicPair,
    /// A descriptor is not the kind of socket its name promises.
    #[error("socket activation: the {0:?} descriptor is not a suitable listening socket")]
    NotAListener(&'static str),
    /// The activated port differs from `listen`.
    #[error(
        "socket activation: the public sockets listen on port {socket} but gatewayd.toml has \
         listen port {config}; make the socket drop-in (hx-gatewayd-public.socket.d) and \
         `listen` agree"
    )]
    PortMismatch {
        /// Port of the sockets systemd passed.
        socket: u16,
        /// Port of `listen`.
        config: u16,
    },
    /// The TCP and UDP sockets listen on different ports.
    #[error("socket activation: the TCP socket is on port {tcp} but the UDP socket on {udp}")]
    SplitPorts {
        /// TCP port.
        tcp: u16,
        /// UDP port.
        udp: u16,
    },
}

/// What systemd handed over.
#[derive(Debug)]
pub struct Activated {
    /// The admin socket (`admin`), if passed, already non-blocking.
    pub admin: Option<UnixListener>,
    /// The public sockets (`public`): the UDP socket and the TCP listener, if passed.
    pub public: Option<(UdpSocket, TcpListener)>,
}

/// The `LISTEN_*` variables as text (so the checks are testable without the process
/// environment).
#[derive(Debug, Default, Clone)]
pub struct ListenEnv {
    /// `LISTEN_PID`.
    pub pid: Option<String>,
    /// `LISTEN_FDS`.
    pub fds: Option<String>,
    /// `LISTEN_FDNAMES`.
    pub names: Option<String>,
}

impl ListenEnv {
    /// Reads the process environment.
    pub fn from_process() -> Self {
        let get = |k| std::env::var(k).ok();
        Self {
            pid: get("LISTEN_PID"),
            fds: get("LISTEN_FDS"),
            names: get("LISTEN_FDNAMES"),
        }
    }
}

/// Which descriptor index (0 is fd 3) holds what.
#[derive(Debug, PartialEq, Eq)]
pub struct Plan {
    /// Index of `admin`.
    pub admin: Option<usize>,
    /// Indexes of the `public` descriptors (empty, or two).
    pub public: Vec<usize>,
}

/// Checks the variables against `our_pid` and maps names to descriptor indexes. `Ok(None)`
/// means "not activated".
pub fn plan(env: &ListenEnv, our_pid: u32) -> Result<Option<Plan>, ActivationError> {
    let Some(fds) = env.fds.as_deref() else {
        return Ok(None);
    };
    let n: usize = fds
        .parse()
        .map_err(|_| ActivationError::Invalid("LISTEN_FDS is not a number"))?;
    if n == 0 {
        return Ok(None);
    }
    let pid: u32 = env
        .pid
        .as_deref()
        .ok_or(ActivationError::Invalid("LISTEN_PID is not set"))?
        .parse()
        .map_err(|_| ActivationError::Invalid("LISTEN_PID is not a number"))?;
    if pid != our_pid {
        return Err(ActivationError::Invalid("LISTEN_PID is not this process"));
    }
    let names = env
        .names
        .as_deref()
        .ok_or(ActivationError::Invalid("LISTEN_FDNAMES is not set"))?;
    let names: Vec<&str> = names.split(':').collect();
    if names.len() != n {
        return Err(ActivationError::Invalid(
            "LISTEN_FDNAMES does not name every descriptor",
        ));
    }
    let mut plan = Plan {
        admin: None,
        public: Vec::new(),
    };
    for (i, name) in names.iter().enumerate() {
        match *name {
            ADMIN => {
                if plan.admin.replace(i).is_some() {
                    return Err(ActivationError::Duplicate(ADMIN));
                }
            }
            PUBLIC => plan.public.push(i),
            other => return Err(ActivationError::UnexpectedName(other.to_owned())),
        }
    }
    if !(plan.public.is_empty() || plan.public.len() == 2) {
        return Err(ActivationError::PublicPair);
    }
    Ok(Some(plan))
}

/// The port rule: both public sockets on one port, the port `listen` names.
pub fn check_ports(config_port: u16, tcp: u16, udp: u16) -> Result<(), ActivationError> {
    if tcp != udp {
        return Err(ActivationError::SplitPorts { tcp, udp });
    }
    if tcp != config_port {
        return Err(ActivationError::PortMismatch {
            socket: tcp,
            config: config_port,
        });
    }
    Ok(())
}

/// Adopts what systemd passed. `listen_port` is the port of `listen` in the configuration.
///
/// `LISTEN_PID` and `LISTEN_FDS` are removed from the environment by `listenfd` once the
/// descriptors are taken. Returns an empty [`Activated`] when the process is not activated.
pub fn from_process(listen_port: u16) -> Result<Activated, ActivationError> {
    let env = ListenEnv::from_process();
    let our_pid = rustix::process::getpid().as_raw_nonzero().get() as u32;
    let Some(plan) = plan(&env, our_pid)? else {
        return Ok(Activated {
            admin: None,
            public: None,
        });
    };
    // `listenfd` would honour a non-systemd override of the first descriptor.
    if std::env::var_os("LISTEN_FDS_FIRST_FD").is_some() {
        return Err(ActivationError::Invalid(
            "LISTEN_FDS_FIRST_FD is not a systemd variable",
        ));
    }
    let mut fds = listenfd::ListenFd::from_env();
    if fds.len() != plan.admin.iter().count() + plan.public.len() {
        return Err(ActivationError::Invalid(
            "LISTEN_FDNAMES does not name every descriptor",
        ));
    }
    let admin = match plan.admin {
        Some(i) => Some(take_admin(&mut fds, i)?),
        None => None,
    };
    let public = if plan.public.is_empty() {
        None
    } else {
        let (udp, tcp) = take_public(&mut fds, &plan.public)?;
        let port = |a: std::io::Result<std::net::SocketAddr>| {
            a.map(|a| a.port())
                .map_err(|_| ActivationError::NotAListener(PUBLIC))
        };
        check_ports(
            listen_port,
            port(tcp.local_addr())?,
            port(udp.local_addr())?,
        )?;
        Some((udp, tcp))
    };
    Ok(Activated { admin, public })
}

fn take_admin(fds: &mut listenfd::ListenFd, i: usize) -> Result<UnixListener, ActivationError> {
    let bad = || ActivationError::NotAListener(ADMIN);
    let l = fds
        .take_unix_listener(i)
        .map_err(|_| bad())?
        .ok_or_else(bad)?;
    if !rustix::net::sockopt::socket_acceptconn(&l).map_err(|_| bad())? {
        return Err(bad());
    }
    l.set_nonblocking(true).map_err(|_| bad())?;
    Ok(l)
}

/// Sorts the two `public` descriptors into (UDP, TCP) by `SO_TYPE` (`listenfd` checks the
/// type and family before it wraps a descriptor; a failed attempt takes nothing).
fn take_public(
    fds: &mut listenfd::ListenFd,
    idx: &[usize],
) -> Result<(UdpSocket, TcpListener), ActivationError> {
    let bad = || ActivationError::NotAListener(PUBLIC);
    let (mut udp, mut tcp) = (None, None);
    for &i in idx {
        if let Ok(Some(l)) = fds.take_tcp_listener(i) {
            if tcp.replace(l).is_some() {
                return Err(ActivationError::PublicPair);
            }
        } else if let Ok(Some(s)) = fds.take_udp_socket(i) {
            if udp.replace(s).is_some() {
                return Err(ActivationError::PublicPair);
            }
        } else {
            return Err(bad());
        }
    }
    let (Some(udp), Some(tcp)) = (udp, tcp) else {
        return Err(ActivationError::PublicPair);
    };
    // The TCP socket must be listening, the UDP socket bound to a port.
    if !rustix::net::sockopt::socket_acceptconn(&tcp).map_err(|_| bad())? {
        return Err(bad());
    }
    if udp.local_addr().map_err(|_| bad())?.port() == 0 {
        return Err(bad());
    }
    Ok((udp, tcp))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pid: &str, fds: &str, names: &str) -> ListenEnv {
        ListenEnv {
            pid: Some(pid.into()),
            fds: Some(fds.into()),
            names: Some(names.into()),
        }
    }

    #[test]
    fn not_activated_without_listen_fds_or_with_zero() {
        assert_eq!(plan(&ListenEnv::default(), 7), Ok(None));
        assert_eq!(plan(&env("7", "0", ""), 7), Ok(None));
    }

    #[test]
    fn names_select_the_descriptors_whatever_the_order() {
        let p = plan(&env("7", "3", "public:admin:public"), 7)
            .unwrap()
            .unwrap();
        assert_eq!(
            p,
            Plan {
                admin: Some(1),
                public: vec![0, 2]
            }
        );
        let p = plan(&env("7", "3", "admin:public:public"), 7)
            .unwrap()
            .unwrap();
        assert_eq!(p.admin, Some(0));
        let p = plan(&env("7", "1", "admin"), 7).unwrap().unwrap();
        assert_eq!(p.public, Vec::<usize>::new());
    }

    #[test]
    fn malformed_or_foreign_variables_are_refused() {
        for e in [
            env("8", "1", "admin"),
            env("x", "1", "admin"),
            env("7", "y", "admin"),
            env("7", "2", "admin"),
            env("7", "1", "admin:public"),
            ListenEnv {
                pid: None,
                fds: Some("1".into()),
                names: Some("admin".into()),
            },
            ListenEnv {
                pid: Some("7".into()),
                fds: Some("1".into()),
                names: None,
            },
        ] {
            assert!(
                matches!(plan(&e, 7), Err(ActivationError::Invalid(_))),
                "{e:?}"
            );
        }
    }

    #[test]
    fn extra_duplicate_and_incomplete_descriptors_are_refused() {
        assert_eq!(
            plan(&env("7", "2", "admin:admin"), 7),
            Err(ActivationError::Duplicate("admin"))
        );
        assert!(matches!(
            plan(&env("7", "2", "admin:other"), 7),
            Err(ActivationError::UnexpectedName(n)) if n == "other"
        ));
        // systemd's default name for an unnamed socket is the unit name.
        assert!(matches!(
            plan(&env("7", "1", "hx-gatewayd-public.socket"), 7),
            Err(ActivationError::UnexpectedName(_))
        ));
        assert_eq!(
            plan(&env("7", "2", "admin:public"), 7),
            Err(ActivationError::PublicPair)
        );
        assert_eq!(
            plan(&env("7", "4", "admin:public:public:public"), 7),
            Err(ActivationError::PublicPair)
        );
    }

    #[test]
    fn the_port_must_match_the_configuration() {
        assert_eq!(check_ports(443, 443, 443), Ok(()));
        assert_eq!(
            check_ports(443, 8443, 8443),
            Err(ActivationError::PortMismatch {
                socket: 8443,
                config: 443
            })
        );
        assert_eq!(
            check_ports(443, 443, 444),
            Err(ActivationError::SplitPorts { tcp: 443, udp: 444 })
        );
        let msg = check_ports(443, 8443, 8443).unwrap_err().to_string();
        assert!(msg.contains("8443") && msg.contains("443") && msg.contains("drop-in"));
    }
}
