//! hx-privd-rescue: the rollback helper of `hx-privd.service` (`OnFailure=`), installed at
//! `/usr/lib/hx-rescue/hx-privd-rescue`, outside the release directory.
//!
//! It takes **no arguments and reads no environment**. If an update is pending it restores
//! `current` to the recorded previous version and restarts privd; otherwise it does nothing. It
//! never writes `updates-state`. The logic and its checks are in `hx_agent::privd::rescue`.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use hx_agent::privd::rescue::{Outcome, Paths, SystemCtl, run};

fn say(level: &str, msg: &str) {
    // One sanitized line for the journal (a version string is validated, an error text is ours).
    let line = hx_ipc::text::sanitize_text(msg, 500);
    eprintln!("hx-privd-rescue {level}: {line}");
}

fn main() -> ExitCode {
    if std::env::args_os().len() > 1 {
        say("error", "takes no arguments");
        return ExitCode::FAILURE;
    }
    // Nothing this helper creates is readable by others.
    rustix::process::umask(rustix::fs::Mode::from_bits_truncate(0o077));
    match run(&Paths::production(), &SystemCtl) {
        Ok(Outcome::NoPending) => {
            say("info", "no update is pending; nothing to do");
            ExitCode::SUCCESS
        }
        Ok(Outcome::Restarted {
            restored,
            links_untouched,
        }) => {
            say(
                "info",
                &format!(
                    "restarted hx-privd (current restored: {restored}, links left alone: {links_untouched})"
                ),
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            say("error", &e.to_string());
            ExitCode::FAILURE
        }
    }
}
