//! `hx-agent install` and `hx-agent uninstall`: the installer engine (design 1E, WS-2).
//!
//! `install.sh` verifies and downloads the release and hands over to this module
//! (`hx-agent install --bootstrap-dir <dir> --lock-fd 9 ...`). From there:
//!
//! ```text
//! lock (--lock-fd verified) -> state + options (re-run classification, exit 12)
//!   -> secrets (C2 stdin / prompts / --token) -> the 19 stages ([`stages::TABLE`])
//!   -> JSON Lines progress (C3) -> result
//! ```
//!
//! # Rules the code keeps
//!
//! * **A closed tool set** ([`runner::Tool`]) with fixed paths, run with a **cleared environment**,
//!   a fixed `PATH`, fixed argv and no shell. Tests use a fake runner.
//! * **No secret in an argv, an environment, a log, the state or a message.** Secrets live in
//!   `Zeroizing` buffers ([`ctx::Secrets`]); a secret reaches a tool only as its standard input
//!   (`systemd-creds`), and reaches the daemons only as kind-2 secret frames.
//! * **Resumable and convergent**: every stage has a done-check; a stage is skipped only when it
//!   is recorded as done and the check still passes. `pairing-token`, `pairing` and `finish` are
//!   never skipped on resume (a token or code must be fresh).
//! * **Nothing outside the root**: every path goes through [`paths::Paths`], so tests and a
//!   non-production configuration work in a temporary directory and never touch the host.
//!
//! Contracts: C1 (CLI and exit codes), C2 ([`stdin`]), C3 ([`progress`]), C4 ([`stages::release`]),
//! C7 ([`state`]); the units are embedded from one table ([`units`]).

pub mod ctx;
pub mod daemons;
pub mod engine;
pub mod error;
pub mod fsx;
pub mod interactive;
pub mod lock;
pub mod log;
pub mod options;
pub mod paths;
pub mod preflight;
pub mod probe;
pub mod progress;
pub mod runner;
pub mod stages;
pub mod state;
pub mod stdin;
#[cfg(any(test, feature = "install-test-hooks"))]
pub mod testing;
pub mod uninstall;
pub mod units;
pub mod zabbly;

use std::io::Write;
use std::path::Path;

use hx_crypto::PinParams;
use zeroize::Zeroizing;

use crate::cli::{Env, Prompter};
use crate::privd::update::keys::UpdateKeys;
use ctx::{Ctx, Hooks, Secrets, Timing};
use daemons::{Daemons, SocketDaemons};
use error::InstallError;
use options::{HostFacts, Mode, Options, RawOptions, SecretString};
use paths::Paths;
use probe::{Probe, SystemProbe};
use progress::Progress;
use runner::{DenyRunner, RealRunner, Runner};
use state::InstallState;

/// The warning printed when the token comes from argv (the CLI's text for `pairing token --token`).
pub const TOKEN_WARNING: &str = "warning: --token is the WEAKER way to give a token. It is visible in the process list \
(/proc/<pid>/cmdline) while this runs, it stays in your shell history, and under sudo it is written to the \
auth log and the journal. A token is single use and expires, which limits that exposure but does not remove \
it. Use --pair to type it at a hidden prompt instead.";

/// A parsed `hx-agent install` command line.
#[derive(Debug, PartialEq, Eq, Default)]
pub struct InstallArgs {
    /// The mode given (none: resume with the recorded one).
    pub mode: Option<Mode>,
    /// The value of `--token`.
    pub token: Option<SecretString>,
    /// The options.
    pub raw: RawOptions,
    /// `--bootstrap-dir`.
    pub bootstrap_dir: Option<String>,
    /// `--lock-fd`.
    pub lock_fd: Option<i32>,
    /// `--test-allow-container` (feature `install-test-hooks` only).
    pub test_allow_container: bool,
    /// `--test-fail-after` (feature `install-test-hooks` only).
    pub test_fail_after: Option<String>,
}

/// Where the `--ssh` secrets come from.
pub enum StdinSource {
    /// File descriptor 0, under the 30 second limit.
    Real,
    /// Frames read already (tests).
    Frames(Option<stdin::Frames>),
}

/// Everything [`run`] needs from outside.
pub struct Deps<'a> {
    /// The root.
    pub paths: Paths,
    /// Runs tools.
    pub runner: &'a mut dyn Runner,
    /// privd and gatewayd.
    pub daemons: &'a mut dyn Daemons,
    /// Facts about the host.
    pub probe: &'a dyn Probe,
    /// The terminal.
    pub prompt: &'a mut dyn Prompter,
    /// Standard output.
    pub out: &'a mut dyn Write,
    /// Standard error.
    pub err: &'a mut dyn Write,
    /// `--json`.
    pub json: bool,
    /// The Unix clock.
    pub now: fn() -> u64,
    /// The release keys.
    pub keys: UpdateKeys,
    /// Argon2id cost of the verifiers.
    pub verifier_params: PinParams,
    /// The effective uid (must be 0).
    pub euid: u32,
    /// Waits.
    pub timing: Timing,
    /// The `--ssh` input.
    pub stdin: StdinSource,
}

fn random_id() -> Result<String, InstallError> {
    let mut b = [0u8; 16];
    rustix::rand::getrandom(&mut b, rustix::rand::GetRandomFlags::empty())
        .map_err(|e| InstallError::internal(format!("no randomness: {e}")))?;
    Ok(crate::cli::text::hex(&b))
}

fn mem_mib(paths: &Paths) -> u64 {
    fsx::read_text(&paths.at("/proc/meminfo"))
        .and_then(|t| preflight::parse_mem_total_mib(&t))
        .unwrap_or(0)
}

/// The secrets of `--ssh` as the context holds them.
fn secrets_from(f: stdin::Frames) -> Secrets {
    Secrets {
        password: f.password,
        pin: f.pin,
        token: f.token,
        owner_key: f.owner_key,
    }
}

/// Whether the recorded install still needs the password and PIN.
fn needs_secrets(prior: Option<&InstallState>) -> bool {
    prior.is_none_or(|s| !(s.finished("desktop") && s.finished("verifiers")))
}

/// Runs `hx-agent install`. Returns the process exit code; everything is reported through
/// `deps.out` and `deps.err`.
pub fn run(args: InstallArgs, deps: Deps<'_>) -> u8 {
    let Deps {
        paths,
        runner,
        daemons,
        probe,
        prompt,
        out,
        err,
        json,
        now,
        keys,
        verifier_params,
        euid,
        timing,
        stdin: stdin_source,
    } = deps;
    let mut progress = Progress::new(json, out, err, Box::new(move || probe.mono_ms()));
    let early = |p: &mut Progress<'_>, e: &InstallError| -> u8 {
        p.human(&format!("hx-agent: error: {}\n", e.message));
        p.result_err(e.exit, "preflight", e.code.name(), &e.message, e.retryable);
        e.exit
    };
    if euid != 0 {
        return early(&mut progress, &InstallError::not_root());
    }
    let _lock = match lock::acquire(&paths.at(paths::LOCK_FILE), args.lock_fd) {
        Ok(l) => l,
        Err(e) => return early(&mut progress, &e),
    };
    let prior = match state::load(&paths.at(paths::STATE_FILE)) {
        Ok(p) => p,
        Err(e) => return early(&mut progress, &InstallError::internal(e.to_string())),
    };
    // The mode: given, or the recorded one.
    let mode = match (args.mode, prior.as_ref().and_then(|s| Mode::parse(&s.mode))) {
        (Some(m), _) | (None, Some(m)) => m,
        (None, None) => {
            return early(
                &mut progress,
                &InstallError::usage(
                    "a fresh host needs a mode: --interactive, --pair, --token <t> or --ssh (see: hx-agent help install)",
                ),
            );
        }
    };
    // Options: validated, merged over the recorded ones, classified.
    let zone = paths.at(paths::ZONEINFO);
    let facts = HostFacts {
        cpus: probe.cpus(),
        mem_mib: mem_mib(&paths),
        zoneinfo: &zone,
    };
    let (opts, explicit) =
        match Options::resolve(&args.raw, prior.as_ref().map(|s| &s.options), &facts) {
            Ok(x) => x,
            Err(e) => return early(&mut progress, &e),
        };
    if let Some(p) = &prior {
        let c = options::conflicts(p, &opts, &explicit);
        if !c.is_empty() {
            return early(
                &mut progress,
                &InstallError::conflict(options::conflict_message(&c)),
            );
        }
    }
    // Secrets.
    let mut secrets = Secrets::default();
    let mut gathered = false;
    match mode {
        Mode::Ssh if args.mode.is_some() => {
            let frames = match stdin_source {
                StdinSource::Real => stdin::read_stdin(true),
                StdinSource::Frames(f) => {
                    f.ok_or_else(|| InstallError::usage("no secrets on stdin"))
                }
            };
            match frames {
                Ok(f) => secrets = secrets_from(f),
                Err(e) => return early(&mut progress, &e),
            }
        }
        Mode::Ssh => {
            if needs_secrets(prior.as_ref()) {
                return early(
                    &mut progress,
                    &InstallError::usage(
                        "this install still needs the password and the PIN: run again with --ssh and send them on stdin",
                    ),
                );
            }
        }
        Mode::Token => match &args.token {
            Some(t) => {
                secrets.token = Some(Zeroizing::new(t.0.as_bytes().to_vec()));
                progress.human(&format!("{TOKEN_WARNING}\n"));
            }
            None => {
                return early(
                    &mut progress,
                    &InstallError::usage(
                        "--token needs the token: run again with --token <t>, or use --pair",
                    ),
                );
            }
        },
        Mode::Interactive => {
            // A re-run without the flag does not ask again once there is nothing left to build.
            gathered = args.mode.is_none() && !needs_secrets(prior.as_ref());
        }
        Mode::Pair => {}
    }
    let mut state = prior.unwrap_or_else(|| {
        InstallState::new(
            random_id().unwrap_or_else(|_| "0".repeat(32)),
            mode.as_str(),
            opts.clone(),
            now(),
        )
    });
    state.mode = mode.as_str().to_owned();
    state.options = opts.clone();
    let hooks = Hooks {
        allow_container: args.test_allow_container,
        fail_after: args.test_fail_after.clone(),
    };
    let log = log::InstallLog::open(&paths.at(paths::LOG_FILE));
    let mut ctx = Ctx {
        paths,
        runner,
        daemons,
        probe,
        prompt,
        progress,
        now,
        log,
        keys,
        verifier_params,
        mode,
        opts,
        state,
        secrets,
        bootstrap_dir: args.bootstrap_dir.as_ref().map(std::path::PathBuf::from),
        image_file: args.raw.image_file().map(str::to_owned),
        hooks,
        timing,
        gathered,
        report: ctx::Report::default(),
    };
    engine::execute(&mut ctx)
}

/// The directory a non-production configuration works in: `root/` next to its sockets.
pub(crate) fn dev_root(config: &crate::cli::Config) -> std::path::PathBuf {
    config
        .privd_socket
        .parent()
        .unwrap_or_else(|| Path::new("/"))
        .join("root")
}

/// Production when the configuration names the real privd socket.
pub fn is_production(config: &crate::cli::Config) -> bool {
    config.privd_socket == Path::new(paths::PRIVD_SOCKET)
}

/// The CLI entry of `hx-agent install`: production or a tree under the test configuration.
pub fn run_cli(args: InstallArgs, env: &mut Env<'_>) -> u8 {
    let production = is_production(&env.config);
    let paths = if production {
        Paths::system()
    } else {
        Paths::under(dev_root(&env.config))
    };
    let mut real = RealRunner;
    let mut deny = DenyRunner;
    let runner: &mut dyn Runner = if production { &mut real } else { &mut deny };
    let mut daemons = SocketDaemons {
        privd_socket: env.config.privd_socket.clone(),
        admin_socket: env.config.admin_socket.clone(),
        expected_uid: env.config.expected_peer_uid,
    };
    let probe = SystemProbe;
    let deps = Deps {
        paths,
        runner,
        daemons: &mut daemons,
        probe: &probe,
        prompt: &mut *env.prompt,
        out: &mut *env.out,
        err: &mut *env.err,
        json: env.json,
        now: env.now,
        keys: UpdateKeys::embedded(),
        verifier_params: env.config.verifier_params,
        euid: env.euid,
        timing: Timing::default(),
        stdin: StdinSource::Real,
    };
    run(args, deps)
}
