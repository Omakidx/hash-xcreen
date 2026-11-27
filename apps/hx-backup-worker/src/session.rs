//! The worker's session (ipc.md §24 and §26): start-up, the one connection, the handshake, the job,
//! the end.
//!
//! ```text
//! signals -> listen on /run/hx-worker/repo.sock -> accept ONE connection, close and unlink the listener
//!         -> NO_NEW_PRIVS, DUMPABLE=0, RLIMIT_CORE=0
//!         -> Hello / HelloAck / Job / secrets        (main thread alone, no filter yet)
//!         -> drop capabilities for the job kind, install the seccomp allowlist
//!         -> start the link threads and the progress thread
//!         -> run the job -> one JobResult -> Bye -> exit
//! ```

use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hx_backup::engine::{Link, LinkFailure, LinkOptions};
use hx_ipc::repo::{WORKER_SILENCE_TIMEOUT, pb};

use crate::job::{self, JobOptions};
use crate::progress::Reporter;
use crate::role::{EXIT_INTERNAL, EXIT_LINK_LOST, EXIT_LISTEN, EXIT_PROTOCOL, EXIT_SANDBOX};
use crate::sandbox::{self, Mode};
use crate::{SOFTWARE, role};

/// The listener's socket file inside the run directory.
pub const SOCKET_NAME: &str = "repo.sock";

/// Whether the second hardening step runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sandbox {
    /// Drop capabilities and install the seccomp allowlist in `Mode`.
    Full(Mode),
    /// Neither. For in-process tests of the session, which share a process with the test harness.
    Off,
}

/// Everything that differs between production and a test.
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// `/run/hx-worker`: the directory (0700) of the listener.
    pub run_dir: PathBuf,
    /// How long to wait for privd to connect (ipc.md §24: 60 s).
    pub accept_timeout: Duration,
    /// The link's timing.
    pub link: LinkOptions,
    /// The job runner's paths and ownership handling.
    pub job: JobOptions,
    /// The sandbox.
    pub sandbox: Sandbox,
}

impl WorkerConfig {
    /// The production configuration: `/run/hx-worker`, 60 s, `/src`, `/dst`, numeric ownership and
    /// the enforcing sandbox. With the `test-hooks` feature (never in a release build) the
    /// environment may override the directories (`HX_WORKER_RUN_DIR`, `HX_WORKER_SRC`,
    /// `HX_WORKER_DST`) and turn ownership off (`HX_WORKER_NO_OWNERSHIP`).
    #[must_use]
    #[allow(unused_mut)]
    pub fn production() -> Self {
        let mut cfg = Self {
            run_dir: PathBuf::from("/run/hx-worker"),
            accept_timeout: WORKER_SILENCE_TIMEOUT,
            link: LinkOptions::default(),
            job: JobOptions::production(),
            sandbox: Sandbox::Full(Mode::Enforce),
        };
        #[cfg(feature = "test-hooks")]
        {
            if let Some(v) = std::env::var_os("HX_WORKER_RUN_DIR") {
                cfg.run_dir = v.into();
            }
            if let Some(v) = std::env::var_os("HX_WORKER_SRC") {
                cfg.job.src = v.into();
            }
            if let Some(v) = std::env::var_os("HX_WORKER_DST") {
                cfg.job.dst = v.into();
            }
            if std::env::var_os("HX_WORKER_NO_OWNERSHIP").is_some() {
                cfg.job.ownership = hx_backup::engine::Ownership::Skip;
            }
        }
        cfg
    }
}

/// Creates `run_dir` (0700) and the listener, accepts **exactly one** connection within `timeout`,
/// closes the listener and unlinks its socket (ipc.md §24).
///
/// # Errors
/// An I/O error, or `TimedOut` when nobody connected.
pub fn listen_once(run_dir: &Path, timeout: Duration) -> io::Result<UnixStream> {
    match fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(run_dir)
    {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    fs::set_permissions(run_dir, fs::Permissions::from_mode(0o700))?;
    let path = run_dir.join(SOCKET_NAME);
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + timeout;
    let stream = loop {
        match listener.accept() {
            Ok((s, _)) => break s,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    let _ = fs::remove_file(&path);
                    return Err(io::ErrorKind::TimedOut.into());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(e),
        }
    };
    // One connection only: nobody else can ever connect.
    drop(listener);
    let _ = fs::remove_file(&path);
    stream.set_nonblocking(false)?;
    Ok(stream)
}

/// The worker role: start-up, then [`serve`]. Returns the exit code (ipc.md §24).
pub fn run_worker(cfg: &WorkerConfig) -> i32 {
    install_panic_hook();
    if let Err(e) = sandbox::install_signal_handlers() {
        eprintln!("hx-backup-worker: signal handlers: {e}");
        return EXIT_SANDBOX;
    }
    let stream = match listen_once(&cfg.run_dir, cfg.accept_timeout) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("hx-backup-worker: no connection: {e}");
            return EXIT_LISTEN;
        }
    };
    if let Err(e) = sandbox::early_hardening() {
        eprintln!("hx-backup-worker: {e}");
        return EXIT_SANDBOX;
    }
    match panic::catch_unwind(AssertUnwindSafe(|| serve(stream, cfg))) {
        Ok(code) => code,
        Err(_) => EXIT_INTERNAL,
    }
}

/// A panic prints where it happened and nothing else: its payload may hold text built from a
/// secret.
pub(crate) fn install_panic_hook() {
    panic::set_hook(Box::new(|info| {
        let loc = info.location().map_or_else(
            || "unknown".to_owned(),
            |l| format!("{}:{}", l.file(), l.line()),
        );
        eprintln!("hx-backup-worker: panic at {loc} (message withheld)");
    }));
}

fn exit_for(f: LinkFailure) -> i32 {
    eprintln!("hx-backup-worker: {f}");
    match f {
        LinkFailure::Violation(_) => EXIT_PROTOCOL,
        LinkFailure::Lost | LinkFailure::Silent => EXIT_LINK_LOST,
    }
}

/// Everything after the connection: handshake, sandbox, job, result. Returns the exit code.
///
/// Used by [`run_worker`], and directly by tests with [`Sandbox::Off`] and one end of a socket
/// pair standing in for privd.
pub fn serve(stream: UnixStream, cfg: &WorkerConfig) -> i32 {
    let (link, start) = match Link::accept(stream, SOFTWARE, cfg.link) {
        Ok(x) => x,
        Err(f) => return exit_for(f),
    };
    let kind = pb::JobKind::try_from(start.job.kind).unwrap_or(pb::JobKind::Unspecified);
    if let Sandbox::Full(mode) = cfg.sandbox
        && let Err(e) = sandbox::harden(kind, mode)
    {
        eprintln!("hx-backup-worker: {e}");
        return EXIT_SANDBOX;
    }
    if let Err(e) = link.start() {
        eprintln!("hx-backup-worker: cannot start the link threads: {e}");
        return EXIT_INTERNAL;
    }
    let link = Arc::new(link);
    let reporter = match Reporter::start(Arc::clone(&link), kind) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("hx-backup-worker: cannot start the progress thread: {e}");
            return EXIT_INTERNAL;
        }
    };
    let result = job::run(&link, start, &cfg.job, reporter.clone());
    reporter.stop();
    match link.finish(result) {
        Ok(()) => role::EXIT_OK,
        Err(f) => exit_for(f),
    }
}
