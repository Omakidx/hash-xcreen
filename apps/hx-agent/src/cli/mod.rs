//! The `hx-agent` administration CLI: the root-run local tool of the operator.
//!
//! It talks to two daemons and nothing else:
//!
//! * the **gatewayd admin socket** (`/run/hx/gatewayd-admin.sock`, `docs/ipc.md` section 9):
//!   devices, pairing credentials, verifiers, the gateway's mirror of the setup window;
//! * **`hx-privd`** (`/run/hx/privd.sock`, ipc.md Part 1) as the `Admin` role (uid 0): host and
//!   desktop facts and operations, lockout reset, updates, uninstall.
//!
//! # Rules the code keeps
//!
//! * **Root only.** [`run`] refuses every command but `help` and `--version` unless the effective
//!   uid is 0. (The sockets refuse anyone else too; the check gives a clear message first.)
//! * **Secrets only from the terminal or a secret frame.** A Linux password, a PIN or a pairing
//!   token is read from `/dev/tty` with echo off ([`tty`]) into a `Zeroizing` buffer and sent as a
//!   kind-2 secret frame. No flag, environment variable, file or stdin carries one (the only
//!   exception, `pairing token --token`, is refused to be silent about being weaker). The CLI
//!   reads **no environment variable at all** and logs nothing.
//! * **Peer text is untrusted.** Everything that came from gatewayd, privd, Incus (through
//!   privd) or journald goes through [`text::peer`] on entry and through [`text::scrub_output`] /
//!   [`text::scrub_json`] on exit, so no escape sequence, bidi control or forged line reaches the
//!   terminal.
//! * **Frames are read only with `Decoder::read_from` over a `NoCmsgReader`** ([`wire`]).
//! * **Fixed argv.** The one program the CLI runs is `journalctl`, with an argv built from
//!   constants (no operator text, no shell, a cleared environment).
//! * **Destructive and wide-reaching actions need a typed confirmation or `--yes`**:
//!   `pin reset-lockout`, `docker enable`, `update apply|rollback`, `uninstall`.
//!
//! The usage, exit codes and `--json` envelope are documented in `README.md` next to this file.

use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use serde_json::{Value, json};

pub mod args;
mod commands;
pub mod error;
pub mod gatewayd;
mod help;
pub mod privd;
pub mod text;
pub mod tty;
mod verifier;
pub mod wire;

pub use args::{Cmd, Parsed};
pub use error::{CliError, exit};
pub use tty::{Prompter, TtyPrompter};

use std::path::PathBuf;

use hx_crypto::PinParams;

/// Where the CLI finds things. [`Config::production`] has the fixed paths; tests build their own.
/// The binary reads no flag or environment variable that changes any of this.
#[derive(Debug, Clone)]
pub struct Config {
    /// `/run/hx/privd.sock`.
    pub privd_socket: PathBuf,
    /// `/run/hx/gatewayd-admin.sock`.
    pub admin_socket: PathBuf,
    /// `/var/log/hx/audit.log`.
    pub audit_log: PathBuf,
    /// The uid that must own the audit log and its directory (0).
    pub audit_owner_uid: u32,
    /// `/usr/bin/journalctl`.
    pub journalctl: PathBuf,
    /// The uid the daemons run their sockets as, and that must own the socket files and their
    /// directory: 0 in production (a test points it at its own uid). The CLI sends a secret only
    /// to a socket that passes this check.
    pub expected_peer_uid: u32,
    /// Argon2id cost of the verifiers `pin set` and `desktop password` create.
    pub verifier_params: PinParams,
}

impl Config {
    /// The production paths.
    pub fn production() -> Self {
        Self {
            privd_socket: "/run/hx/privd.sock".into(),
            admin_socket: "/run/hx/gatewayd-admin.sock".into(),
            audit_log: crate::privd::config::AUDIT_LOG.into(),
            audit_owner_uid: 0,
            journalctl: "/usr/bin/journalctl".into(),
            expected_peer_uid: 0,
            verifier_params: PinParams::DEFAULT,
        }
    }
}

/// Everything a command may touch: configuration, the effective uid, the output streams, the
/// terminal prompter, the clock. The binary fills it in; tests substitute each part.
pub struct Env<'a> {
    /// Paths and parameters.
    pub config: Config,
    /// The effective uid of the process (the binary passes the real one).
    pub euid: u32,
    /// Standard output.
    pub out: &'a mut dyn Write,
    /// Standard error.
    pub err: &'a mut dyn Write,
    /// Asks the operator (hidden secrets, confirmations).
    pub prompt: &'a mut dyn Prompter,
    /// Set to end `logs --follow` (the binary never sets it: Ctrl-C ends the process).
    pub stop: Arc<AtomicBool>,
    /// The current Unix time in seconds.
    pub now: fn() -> u64,
    /// `--json` was given (set by [`run`]).
    pub json: bool,
}

/// The uid the CLI acts as: 0 only if **both** the real and the effective uid are 0. A setuid-root
/// copy of the binary run by an ordinary user has an effective uid of 0 and a real uid of that
/// user; it must not become an administration tool for them, so such a process counts as the
/// real (non-root) user and is refused.
pub fn admin_uid(real: u32, effective: u32) -> u32 {
    if real == 0 && effective == 0 {
        0
    } else if effective != 0 {
        effective
    } else {
        real
    }
}

/// Locks all memory (so a typed secret is never swapped out) with `lock`, and says so on `err` if
/// that fails. Called at start, before any prompt can run: the command continues, but the
/// operator knows a secret could reach swap.
pub fn lock_memory_or_warn(err: &mut dyn Write, lock: impl FnOnce() -> io::Result<()>) -> bool {
    match lock() {
        Ok(()) => true,
        Err(e) => {
            write_out(
                err,
                &format!(
                    "hx-agent: warning: cannot lock memory ({e}); a password or PIN typed now could be written to swap\n"
                ),
            );
            false
        }
    }
}

/// The current Unix time.
pub fn system_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// What a command produced.
pub struct Outcome {
    /// The human text (no trailing newline needed).
    pub text: String,
    /// The `data` member of the `--json` envelope.
    pub data: Value,
    /// The exit code (0 unless the command succeeded only in part, such as `status` with a
    /// daemon down).
    pub exit: u8,
}

impl Outcome {
    /// A fully successful outcome.
    pub fn ok(text: impl Into<String>, data: Value) -> Self {
        Self {
            text: text.into(),
            data,
            exit: exit::OK,
        }
    }
}

fn command_name(c: &Cmd) -> &'static str {
    match c {
        Cmd::Help(_) => "help",
        Cmd::Version => "version",
        Cmd::Status => "status",
        Cmd::DevicesList => "devices list",
        Cmd::DevicesRevoke { .. } => "devices revoke",
        Cmd::DevicesReinstate { .. } => "devices reinstate",
        Cmd::PairingCode { .. } => "pairing code",
        Cmd::PairingToken { .. } => "pairing token",
        Cmd::PinSet { .. } => "pin set",
        Cmd::PinResetLockout { .. } => "pin reset-lockout",
        Cmd::SetupBegin { .. } => "setup begin",
        Cmd::SetupExtend { .. } => "setup extend",
        Cmd::SetupFinish { .. } => "setup finish",
        Cmd::DesktopPower { action, .. } => match action {
            args::Power::Start => "desktop start",
            args::Power::Stop => "desktop stop",
            args::Power::Restart => "desktop restart",
        },
        Cmd::DesktopLimits { .. } => "desktop limits",
        Cmd::DesktopPassword { .. } => "desktop password",
        Cmd::DockerEnable { .. } => "docker enable",
        Cmd::DockerDisable { .. } => "docker disable",
        Cmd::SnapshotsList { .. } => "snapshots list",
        Cmd::SnapshotsCreate { .. } => "snapshots create",
        Cmd::SnapshotsDelete { .. } => "snapshots delete",
        Cmd::Logs { .. } => "logs",
        Cmd::UpdateCheck => "update check",
        Cmd::UpdateApply { .. } => "update apply",
        Cmd::UpdateRollback { .. } => "update rollback",
        Cmd::Uninstall { .. } => "uninstall",
    }
}

fn write_out(w: &mut dyn Write, s: &str) {
    // A closed pipe (`hx-agent logs | head`) is not an error worth a message.
    let _ = w.write_all(s.as_bytes());
    let _ = w.flush();
}

fn print_json(env: &mut Env<'_>, mut v: Value) {
    text::scrub_json(&mut v);
    let mut s = serde_json::to_string(&v).unwrap_or_else(|_| "{}".into());
    s.push('\n');
    write_out(env.out, &s);
}

fn report_error(env: &mut Env<'_>, json_mode: bool, name: &str, e: &CliError) -> u8 {
    if json_mode {
        let mut err = json!({"code": e.code_name(), "message": e.message()});
        if let Some(d) = e.detail_name() {
            err["detail"] = json!(d);
        }
        print_json(env, json!({"ok": false, "command": name, "error": err}));
    } else {
        let line = format!("hx-agent: error: {}\n", e.message());
        write_out(env.err, &text::scrub_output(&line));
    }
    e.exit_code()
}

/// Runs one command line (the arguments after the program name) and returns the exit code.
pub fn run(args: &[String], env: &mut Env<'_>) -> u8 {
    let json_mode = args.iter().any(|a| a == "--json");
    env.json = json_mode;
    let parsed = match args::parse(args) {
        Ok(p) => p,
        Err(e) => return report_error(env, json_mode, "", &e),
    };
    let name = command_name(&parsed.cmd);
    match &parsed.cmd {
        Cmd::Help(topic) => {
            write_out(env.out, &help::text(topic.as_deref()));
            return exit::OK;
        }
        Cmd::Version => {
            let line = format!("hx-agent {}\n", env!("CARGO_PKG_VERSION"));
            write_out(env.out, &line);
            return exit::OK;
        }
        _ => {}
    }
    if env.euid != 0 {
        return report_error(env, json_mode, name, &CliError::NotRoot);
    }
    match commands::dispatch(env, parsed.cmd) {
        Ok(Some(outcome)) => {
            if json_mode {
                let ok = outcome.exit == exit::OK;
                print_json(
                    env,
                    json!({"ok": ok, "command": name, "data": outcome.data}),
                );
            } else {
                let mut t = outcome.text;
                if !t.ends_with('\n') {
                    t.push('\n');
                }
                write_out(env.out, &text::scrub_output(&t));
            }
            outcome.exit
        }
        // A streaming command already wrote its output.
        Ok(None) => exit::OK,
        Err(e) => report_error(env, json_mode, name, &e),
    }
}
