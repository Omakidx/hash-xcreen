//! The Drive role's process loop (ipc.md §24): the activated socket, one connection at a time,
//! `SO_PEERCRED`, the idle exit and the exit codes.

use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use hx_ipc::repo::{DRIVE_IDLE_EXIT, WORKER_SILENCE_TIMEOUT};
use rustix::event::{PollFd, PollFlags, poll};
use rustix::fs::Timespec;

use super::DriveConfig;
use super::creds::{CLIENT_FILE, ClientConfig, credentials_directory_from_env};
use super::retry::Timing;
use super::server::{self, End};
use super::transport::HttpConfig;
use crate::role::{EXIT_DRIVE_CLIENT, EXIT_INTERNAL, EXIT_LISTEN, EXIT_OK, EXIT_SANDBOX};
use crate::sandbox;

/// Where the listener comes from.
#[derive(Debug, Clone)]
pub enum Listen {
    /// `LISTEN_FDS` / `LISTEN_PID` and descriptor 3 (production).
    Activated,
    /// Bind this path (tests only, `HX_WORKER_DRIVE_SOCKET`).
    #[cfg(feature = "test-hooks")]
    Path(PathBuf),
}

/// What differs between production and a test.
#[derive(Debug, Clone)]
pub struct RoleConfig {
    /// The OAuth client file.
    pub client_file: PathBuf,
    /// The uid `SO_PEERCRED` must show (0).
    pub peer_uid: u32,
    /// Exit this long after the last connection closed (60 s).
    pub idle_exit: Duration,
    /// The listener.
    pub listen: Listen,
    /// The HTTP client.
    pub http: HttpConfig,
    /// Retry timing.
    pub timing: Timing,
    /// Silence timeout of a connection.
    pub silence: Duration,
    /// Run the early hardening (off for in-process tests).
    pub harden: bool,
}

impl RoleConfig {
    /// Production: the fixed paths and times. With the `test-hooks` feature (never in a release
    /// build) the environment may override them: `HX_WORKER_DRIVE_SOCKET`,
    /// `HX_WORKER_DRIVE_API_ADDR`, `HX_WORKER_DRIVE_CA`, `HX_WORKER_DRIVE_CLIENT`,
    /// `HX_WORKER_DRIVE_PEER_UID` and `HX_WORKER_DRIVE_IDLE_MS` (ipc.md §29 d).
    #[must_use]
    #[allow(unused_mut)]
    pub fn production() -> Self {
        let mut cfg = Self {
            client_file: PathBuf::from(CLIENT_FILE),
            peer_uid: 0,
            idle_exit: DRIVE_IDLE_EXIT,
            listen: Listen::Activated,
            http: HttpConfig::default(),
            timing: Timing::production(),
            silence: WORKER_SILENCE_TIMEOUT,
            harden: true,
        };
        #[cfg(feature = "test-hooks")]
        {
            let var = |n: &str| std::env::var_os(n);
            if let Some(v) = var("HX_WORKER_DRIVE_SOCKET") {
                cfg.listen = Listen::Path(v.into());
            }
            if let Some(v) = var("HX_WORKER_DRIVE_API_ADDR") {
                cfg.http.api_addr = Some(v.to_string_lossy().into_owned());
            }
            if let Some(v) = var("HX_WORKER_DRIVE_CA") {
                cfg.http.extra_roots_pem = std::fs::read(v).ok();
            }
            if let Some(v) = var("HX_WORKER_DRIVE_CLIENT") {
                cfg.client_file = v.into();
            }
            if let Some(v) = var("HX_WORKER_DRIVE_PEER_UID") {
                cfg.peer_uid = v.to_string_lossy().parse().unwrap_or(u32::MAX);
            }
            if let Some(v) = var("HX_WORKER_DRIVE_IDLE_MS") {
                cfg.idle_exit =
                    Duration::from_millis(v.to_string_lossy().parse().unwrap_or(60_000));
            }
        }
        cfg
    }
}

/// Why there is no listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ActivationError {
    /// `LISTEN_PID` is absent or not this process.
    #[error("LISTEN_PID is not this process")]
    Pid,
    /// `LISTEN_FDS` is not exactly 1.
    #[error("LISTEN_FDS is not 1")]
    Count,
    /// Descriptor 3 is not a listening `AF_UNIX` `SOCK_STREAM` socket.
    #[error("descriptor 3 is not a listening unix stream socket")]
    NotAListener,
}

/// Checks the activation variables (systemd's `sd_listen_fds` rules) against `pid`.
///
/// # Errors
/// [`ActivationError`].
pub fn check_activation_env(
    listen_pid: Option<&str>,
    listen_fds: Option<&str>,
    pid: u32,
) -> Result<(), ActivationError> {
    if listen_pid.and_then(|p| p.parse::<u32>().ok()) != Some(pid) {
        return Err(ActivationError::Pid);
    }
    if listen_fds != Some("1") {
        return Err(ActivationError::Count);
    }
    Ok(())
}

fn activated_listener() -> Result<UnixListener, ActivationError> {
    use rustix::net::{AddressFamily, SocketType, sockopt};
    let var = |n: &str| std::env::var(n).ok();
    check_activation_env(
        var("LISTEN_PID").as_deref(),
        var("LISTEN_FDS").as_deref(),
        std::process::id(),
    )?;
    let fd = sandbox::take_activated_fd(3).map_err(|_| ActivationError::NotAListener)?;
    let ok = sockopt::socket_type(&fd).is_ok_and(|t| t == SocketType::STREAM)
        && sockopt::socket_domain(&fd).is_ok_and(|d| d == AddressFamily::UNIX)
        && sockopt::socket_acceptconn(&fd).unwrap_or(false);
    if !ok {
        return Err(ActivationError::NotAListener);
    }
    // `LISTEN_PID` and `LISTEN_FDS` stay in the environment: the helper starts no process, so
    // nothing can inherit them.
    Ok(UnixListener::from(fd))
}

fn make_listener(listen: &Listen) -> io::Result<UnixListener> {
    match listen {
        Listen::Activated => activated_listener().map_err(|e| io::Error::other(e.to_string())),
        #[cfg(feature = "test-hooks")]
        Listen::Path(p) => {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::remove_file(p);
            let l = UnixListener::bind(p)?;
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600))?;
            Ok(l)
        }
    }
}

fn peer_uid(stream: &UnixStream) -> Option<u32> {
    rustix::net::sockopt::socket_peercred(stream)
        .ok()
        .map(|c| c.uid.as_raw())
}

/// Errors of `accept` that mean "try again": an interrupted call, a connection that was reset or
/// aborted before it was accepted (`ECONNABORTED`, `EPROTO`), and a lack of buffers (`ENOBUFS`,
/// `ENOMEM`). Everything else (a closed descriptor, `EMFILE`) ends the helper with 71.
#[must_use]
pub fn accept_error_is_transient(e: &io::Error) -> bool {
    use io::ErrorKind as K;
    matches!(
        e.kind(),
        K::Interrupted | K::ConnectionAborted | K::ConnectionReset
    ) || matches!(
        e.raw_os_error(),
        Some(libc::EPROTO | libc::ENOBUFS | libc::ENOMEM | libc::ECONNABORTED)
    )
}

/// Serves connections from `listener` until `idle_exit` has passed with none open. Returns the
/// exit code.
pub fn serve_listener(listener: &UnixListener, cfg: &RoleConfig, drive: &DriveConfig) -> i32 {
    if listener.set_nonblocking(true).is_err() {
        return EXIT_LISTEN;
    }
    let mut idle_since = Instant::now();
    loop {
        let remaining = cfg.idle_exit.saturating_sub(idle_since.elapsed());
        if remaining.is_zero() {
            return EXIT_OK;
        }
        let ts = Timespec {
            tv_sec: i64::try_from(remaining.as_secs()).unwrap_or(i64::MAX),
            tv_nsec: i64::from(remaining.subsec_nanos()),
        };
        let mut fds = [PollFd::new(listener, PollFlags::IN)];
        match poll(&mut fds, Some(&ts)) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => {
                eprintln!("hx-backup-worker: poll: {e}");
                return EXIT_LISTEN;
            }
        }
        let stream = match listener.accept() {
            Ok((s, _)) => s,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) if accept_error_is_transient(&e) => {
                // A client that left before it was accepted, or a moment without buffers: not a
                // reason to stop serving.
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(e) => {
                eprintln!("hx-backup-worker: accept: {e}");
                return EXIT_LISTEN;
            }
        };
        if stream.set_nonblocking(false).is_err() {
            continue;
        }
        if peer_uid(&stream) != Some(cfg.peer_uid) {
            // Not privd: closed without a byte read or written.
            eprintln!(
                "hx-backup-worker: connection refused: peer is not uid {}",
                cfg.peer_uid
            );
            drop(stream);
            idle_since = Instant::now();
            continue;
        }
        let end = server::serve_connection(stream, drive);
        match end {
            End::Bye => {}
            other => eprintln!("hx-backup-worker: drive session ended: {other:?}"),
        }
        idle_since = Instant::now();
    }
}

/// The Drive role (ipc.md §24, §29). Returns the exit code.
pub fn run(cfg: &RoleConfig) -> i32 {
    crate::session::install_panic_hook();
    if cfg.harden {
        if let Err(e) = sandbox::install_signal_handlers() {
            eprintln!("hx-backup-worker: signal handlers: {e}");
            return EXIT_SANDBOX;
        }
        if let Err(e) = sandbox::early_hardening() {
            eprintln!("hx-backup-worker: {e}");
            return EXIT_SANDBOX;
        }
    }
    let client = match ClientConfig::load(&cfg.client_file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "hx-backup-worker: the Drive OAuth client file {} is unusable: {e}",
                cfg.client_file.display()
            );
            return EXIT_DRIVE_CLIENT;
        }
    };
    let listener = match make_listener(&cfg.listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("hx-backup-worker: no listener: {e}");
            return EXIT_LISTEN;
        }
    };
    let drive = DriveConfig {
        client,
        credentials_dir: credentials_directory_from_env(),
        http: cfg.http.clone(),
        timing: cfg.timing,
        silence: cfg.silence,
        hostname: rustix::system::uname().nodename().to_bytes().to_vec(),
    };
    match panic::catch_unwind(AssertUnwindSafe(|| serve_listener(&listener, cfg, &drive))) {
        Ok(code) => code,
        Err(_) => EXIT_INTERNAL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_accept_errors_do_not_end_the_helper() {
        for raw in [
            libc::ECONNABORTED,
            libc::EPROTO,
            libc::ENOBUFS,
            libc::ENOMEM,
            libc::EINTR,
        ] {
            assert!(
                accept_error_is_transient(&io::Error::from_raw_os_error(raw)),
                "{raw}"
            );
        }
        for raw in [libc::EBADF, libc::EMFILE, libc::EINVAL] {
            assert!(
                !accept_error_is_transient(&io::Error::from_raw_os_error(raw)),
                "{raw}"
            );
        }
    }

    #[test]
    fn activation_follows_the_sd_listen_fds_rules() {
        assert_eq!(check_activation_env(Some("42"), Some("1"), 42), Ok(()));
        assert_eq!(
            check_activation_env(None, Some("1"), 42),
            Err(ActivationError::Pid)
        );
        assert_eq!(
            check_activation_env(Some("41"), Some("1"), 42),
            Err(ActivationError::Pid)
        );
        assert_eq!(
            check_activation_env(Some("x"), Some("1"), 42),
            Err(ActivationError::Pid)
        );
        assert_eq!(
            check_activation_env(Some("42"), None, 42),
            Err(ActivationError::Count)
        );
        assert_eq!(
            check_activation_env(Some("42"), Some("2"), 42),
            Err(ActivationError::Count)
        );
        assert_eq!(
            check_activation_env(Some("42"), Some("0"), 42),
            Err(ActivationError::Count)
        );
    }
}
