//! The backup worker of `docs/ipc.md` Part 3, and the dispatch of the `hx-backup-worker` binary.
//!
//! One binary, two roles (ipc.md §6.12, §36): the **worker** runs as PID 1 of a network-less helper
//! container, speaks the repository link to `hx-privd` and runs `rustic_core` for one job; the
//! **Drive helper** (workstream W4, not built yet) is the only process that speaks to Google.
//!
//! This package exists apart from `hx-agent` so that `rustic_core` is never linked into
//! `hx-privd` or `hx-gatewayd` (ipc.md §36): Cargo unifies the features of one package across all
//! of its binaries. `tests/layout.rs` guards that.
//!
//! | Module | What it does |
//! |---|---|
//! | [`role`] | Picks the role from the environment and the arguments; the exit codes. |
//! | [`session`] | Start-up (the one listener), the handshake, the job, the end of the session. |
//! | [`sandbox`] | `NO_NEW_PRIVS`, capabilities by job kind, the seccomp allowlist, signals. The only `unsafe`. |
//! | [`job`] | The job runner of ipc.md §28 and the choice of a `WorkerError`. |
//! | [`progress`] | `Progress` frames, at most two a second, numbers only. |
//!
//! The link itself (framing state, the reader and writer threads, the `rustic_core` backend) is
//! `hx_backup::engine::link`.

pub mod job;
pub mod progress;
pub mod role;
pub mod sandbox;
pub mod session;

/// `HelloAck.software`: 1 to 64 bytes of `[A-Za-z0-9._+-]`.
pub const SOFTWARE: &str = concat!("hx-backup-worker-", env!("CARGO_PKG_VERSION"));

/// Runs the binary: picks the role, runs it, returns the process exit code (ipc.md §24).
pub fn run(args: &[std::ffi::OsString], env_role: Option<&std::ffi::OsStr>) -> i32 {
    init_logging();
    // A release binary honours no test override: any HX_WORKER_* variable fails closed.
    #[cfg(not(feature = "test-hooks"))]
    if std::env::vars_os().any(|(k, _)| k.to_string_lossy().starts_with("HX_WORKER_")) {
        eprintln!("hx-backup-worker: unexpected HX_WORKER_* variable");
        return role::EXIT_ROLE;
    }
    match role::select(args, env_role) {
        Ok(role::Role::Worker) => session::run_worker(&session::WorkerConfig::production()),
        Ok(role::Role::Drive) => {
            eprintln!("hx-backup-worker: the drive role is not implemented");
            role::EXIT_DRIVE_NOT_IMPLEMENTED
        }
        Err(e) => {
            eprintln!("hx-backup-worker: {e}");
            role::EXIT_ROLE
        }
    }
}

/// Logs go to stderr, which is the helper's console log; privd never parses it. Never a secret, a
/// path of the user's or a repository id at a level above `debug`.
fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_target(false)
        .try_init();
}
