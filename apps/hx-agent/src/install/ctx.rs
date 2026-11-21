//! Everything a stage may touch, in one place: the root and paths, the tool runner, the daemons,
//! the host probe, the terminal, the clock, the state, the secrets. Production fills it from the
//! CLI's `Env`; tests fill it with fakes.

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use hx_crypto::PinParams;
use zeroize::Zeroizing;

use super::daemons::Daemons;
use super::error::{InstallError, Result};
use super::log::InstallLog;
use super::options::{Mode, Options};
use super::paths::{self, Paths};
use super::probe::Probe;
use super::progress::{DesktopOut, PairingOut, Progress};
use super::runner::{Call, Output, Runner};
use super::state::InstallState;
use crate::cli::Prompter;
use crate::privd::update::keys::UpdateKeys;

/// The secrets of one run. Held only here, in `Zeroizing` buffers, never persisted.
#[derive(Default)]
pub struct Secrets {
    /// The Linux password of the desktop user.
    pub password: Option<Zeroizing<Vec<u8>>>,
    /// The PIN.
    pub pin: Option<Zeroizing<Vec<u8>>>,
    /// The pairing token.
    pub token: Option<Zeroizing<Vec<u8>>>,
    /// The owner public key (32 bytes, not secret, but handled the same way).
    pub owner_key: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secrets(<redacted>)")
    }
}

/// The test hooks (compiled in only with `install-test-hooks`, otherwise always off).
#[derive(Debug, Clone, Default)]
pub struct Hooks {
    /// Do not refuse a container host.
    pub allow_container: bool,
    /// Stop with an error after this stage has finished.
    pub fail_after: Option<String>,
}

/// Waits that tests shorten.
#[derive(Debug, Clone)]
pub struct Timing {
    /// How long to wait for Incus's socket after enabling it.
    pub socket_wait: Duration,
    /// Timeout of one apt call.
    pub apt_secs: u64,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            socket_wait: Duration::from_secs(60),
            apt_secs: 1800,
        }
    }
}

/// What the run found out, for the final result.
#[derive(Debug, Clone)]
pub struct Report {
    /// The pairing credential installed.
    pub pairing: PairingOut,
    /// The desktop.
    pub desktop: Option<DesktopOut>,
    /// Global addresses of the host.
    pub addresses: Vec<String>,
}

impl Default for Report {
    fn default() -> Self {
        Self {
            pairing: PairingOut {
                kind: "none",
                expires_at_unix_s: 0,
            },
            desktop: None,
            addresses: Vec::new(),
        }
    }
}

/// The context of one install run.
pub struct Ctx<'a> {
    /// The root and the path table.
    pub paths: Paths,
    /// Runs tools.
    pub runner: &'a mut dyn Runner,
    /// privd and gatewayd.
    pub daemons: &'a mut dyn Daemons,
    /// Facts about the host.
    pub probe: &'a dyn Probe,
    /// The terminal.
    pub prompt: &'a mut dyn Prompter,
    /// Progress output.
    pub progress: Progress<'a>,
    /// The Unix clock.
    pub now: fn() -> u64,
    /// The log file.
    pub log: InstallLog,
    /// The embedded release keys.
    pub keys: UpdateKeys,
    /// Argon2id cost of the verifiers.
    pub verifier_params: PinParams,
    /// The mode.
    pub mode: Mode,
    /// The normalized options.
    pub opts: Options,
    /// The state (saved after every stage).
    pub state: InstallState,
    /// The secrets.
    pub secrets: Secrets,
    /// The bootstrap directory, when `install.sh` handed one over.
    pub bootstrap_dir: Option<PathBuf>,
    /// `--image-file`, refused at preflight.
    pub image_file: Option<String>,
    /// Test hooks.
    pub hooks: Hooks,
    /// Waits.
    pub timing: Timing,
    /// The interactive prompts have run.
    pub gathered: bool,
    /// What the run found out.
    pub report: Report,
}

impl Ctx<'_> {
    /// Runs a tool, logging its argv and exit status. An `Err` is a tool that could not run.
    pub fn run(&mut self, call: Call) -> Result<Output> {
        let line = call.line();
        let now = (self.now)();
        match self.runner.run(&call) {
            Ok(out) => {
                self.log.line(now, &format!("run {line} -> {}", out.status));
                Ok(out)
            }
            Err(e) => {
                self.log
                    .line(now, &format!("run {line} -> error: {}", e.kind()));
                Err(InstallError::tool(format!("{}: {e}", call.tool.name())))
            }
        }
    }

    /// Runs a tool and requires exit status 0.
    pub fn run_ok(&mut self, call: Call) -> Result<Output> {
        let name = call.tool.name();
        let line = call.line();
        let out = self.run(call)?;
        if out.ok() {
            Ok(out)
        } else {
            let tail = out.err_tail();
            Err(InstallError::tool(format!(
                "`{line}` failed with status {}{}{}",
                out.status,
                if tail.is_empty() { "" } else { ": " },
                if tail.is_empty() {
                    name.to_owned()
                } else {
                    tail
                }
            )))
        }
    }

    /// Writes the state file.
    pub fn save_state(&mut self) -> Result<()> {
        // The options may have changed since the state was made (interactive answers).
        self.state.options = self.opts.clone();
        let path = self.paths.at(paths::STATE_FILE);
        super::state::save(&path, &self.state)?;
        Ok(())
    }

    /// A warning on the progress channel and in the log.
    pub fn warn(&mut self, stage: &str, message: &str) {
        let now = (self.now)();
        self.log.line(now, &format!("warn {stage}: {message}"));
        self.progress.warn(stage, message);
    }

    /// Writes a human line to stderr.
    pub fn say(&mut self, text: &str) {
        self.progress.human(text);
    }
}

/// A writer that discards (tests that do not look at the output).
pub struct Sink;

impl Write for Sink {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
