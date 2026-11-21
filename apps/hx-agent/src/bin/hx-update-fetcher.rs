//! hx-update-fetcher: the sandboxed downloader of the self-update path (docs/ipc.md 6.12).
//!
//! Started by `hx-update-fetcher@<job>.service` (dynamic user, no capabilities, no `AF_UNIX`).
//! The one argument is the job, the unit's instance name: `manifest-stable`, `manifest-beta` or
//! `artifact-<version>`. It downloads bytes into the unit's bind-mounted directory and exits 0;
//! it verifies nothing. Everything else is `hx_agent::fetcher`.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use hx_agent::fetcher::{Config, Job, run};

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let (Some(arg), None) = (args.next(), args.next()) else {
        eprintln!("hx-update-fetcher: expected exactly one job argument");
        return ExitCode::from(2);
    };
    let Some(job) = arg.to_str().and_then(Job::parse) else {
        eprintln!("hx-update-fetcher: not a valid job");
        return ExitCode::from(2);
    };
    let cfg = match Config::production() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("hx-update-fetcher: {e}");
            return ExitCode::FAILURE;
        }
    };
    match run(&job, &cfg) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hx-update-fetcher: {} failed: {e}", job.instance());
            ExitCode::FAILURE
        }
    }
}
