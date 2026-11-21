//! `hx-agent`: the root-run administration CLI (status, devices, pairing, logs, uninstall).
//!
//! Everything lives in `hx_agent::cli`; this is the process shell. It takes its configuration
//! from constants (no flag or environment variable moves a socket path or the program that is
//! run), hardens the process before anything holds a secret, and refuses to act unless the
//! effective uid is 0.

#![forbid(unsafe_code)]

use std::io;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use hx_agent::cli::{self, Config, Env, TtyPrompter, exit, system_now};
use hx_agent::privd::hardening;

fn main() -> ExitCode {
    // A crash must not write a core file holding a password, and nobody may read this process's
    // memory. Both are safe calls.
    if let Err(e) = hardening::disable_dumps() {
        eprintln!("hx-agent: error: cannot disable core dumps: {e}");
        return ExitCode::from(exit::FAILED);
    }
    let euid = rustix::process::geteuid().as_raw();
    if euid == 0 {
        // Best effort: keep a typed secret out of swap. The sockets and Argon2 need no more.
        let _ = hardening::lock_memory();
    }
    // Files this process creates (none today) are private.
    rustix::process::umask(rustix::fs::Mode::from_bits_truncate(0o077));
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let mut out = io::stdout();
    let mut err = io::stderr();
    let mut prompt = TtyPrompter::controlling();
    let mut env = Env {
        config: Config::production(),
        euid,
        out: &mut out,
        err: &mut err,
        prompt: &mut prompt,
        stop: Arc::new(AtomicBool::new(false)),
        now: system_now,
        json: false,
    };
    ExitCode::from(cli::run(&args, &mut env))
}
