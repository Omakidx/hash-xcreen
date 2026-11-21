//! hx-privd: the root daemon that serves the fixed command set of docs/ipc.md Part 1.
//!
//! Started by `hx-privd.service` with the socket from `hx-privd.socket` passed in (socket
//! activation). It takes **no arguments and reads no environment** that changes its behaviour: every
//! path and the gateway user are compiled in (ipc.md 3).
//!
//! Startup order: process hardening (no core dumps, not dumpable, `mlockall`; a failure is fatal),
//! the configuration (the gateway uid from the `hx-gatewayd` passwd entry), the inherited socket,
//! the daemon (state, pepper, audit log), and the account-policy self-checks, which must pass.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use hx_agent::privd::activation;
use hx_agent::privd::config::PrivdConfig;
use hx_agent::privd::daemon::Daemon;
use hx_agent::privd::server::{ServeOptions, serve};
use hx_agent::privd::{hardening, log};

fn fail(msg: &str) -> ExitCode {
    log::error(msg);
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    if std::env::args_os().len() > 1 {
        return fail("hx-privd takes no arguments");
    }
    // Files are created by privd for privd only.
    rustix::process::umask(rustix::fs::Mode::from_bits_truncate(0o077));
    if let Err(e) = hardening::apply() {
        return fail(&format!(
            "cannot apply process hardening (dumpable, core, mlockall): {e}"
        ));
    }
    let cfg = match PrivdConfig::production() {
        Ok(c) => c,
        Err(e) => return fail(&format!("configuration: {e}")),
    };
    // Adopt the activation descriptor before any runtime thread exists, so that nothing else can
    // have opened descriptor 3 (see `activation`).
    let listener = match activation::from_env(&cfg.socket_path) {
        Ok(l) => l,
        Err(e) => return fail(&format!("socket activation: {e}")),
    };
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return fail(&format!("cannot start the runtime: {e}")),
    };
    rt.block_on(async move {
        let daemon = match Daemon::system(cfg) {
            Ok(d) => d,
            Err(e) => return fail(&format!("cannot start: {e}")),
        };
        let violations = daemon.run_self_checks();
        if !violations.is_empty() {
            return fail("the host account policy self-checks failed; refusing to start");
        }
        // logrotate sends SIGHUP after moving the audit log: reopen it.
        {
            use tokio::signal::unix::{SignalKind, signal};
            if let Ok(mut hup) = signal(SignalKind::hangup()) {
                let d = daemon.clone();
                tokio::spawn(async move {
                    while hup.recv().await.is_some() {
                        d.reopen_audit();
                        log::info("audit log reopened");
                    }
                });
            }
        }
        let shutdown = async {
            use tokio::signal::unix::{SignalKind, signal};
            let (Ok(mut term), Ok(mut int)) = (
                signal(SignalKind::terminate()),
                signal(SignalKind::interrupt()),
            ) else {
                return std::future::pending::<()>().await;
            };
            tokio::select! {
                _ = term.recv() => {},
                _ = int.recv() => {},
            }
        };
        log::info("serving");
        match serve(daemon, listener, ServeOptions::default(), shutdown).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&format!("serve: {e}")),
        }
    })
}
