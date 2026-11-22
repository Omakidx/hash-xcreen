//! The engine behind "Add server, SSH path" (no UI): connect over SSH with host-key
//! confirmation, check the server, run `install.sh --ssh`, stream its progress, pair.
//!
//! ```text
//! probe_host_key        fingerprint for the user to confirm (no credential sent)
//! Connection::connect   host key pinned to what the user confirmed, then key or password auth
//! preflight             the server's real values against the minimums (requirement screen)
//! install               upload, sudo, C2 secrets on stdin, C3 events out, typed result or error
//! pair::*               pair with the app's token, cross-check the server key, PIN login
//! ```
//!
//! Secrets are `Zeroizing`, never in argv, the environment or a log line; nothing is persisted.
//! Retry after a lost connection means connecting again and calling [`install`] again with the
//! secrets supplied again (see [`install`]'s module for the exact semantics).

pub mod error;
pub mod frames;
pub mod install;
pub mod pair;
pub mod preflight;
pub mod progress;
pub mod ssh;
pub mod text;

pub use error::{ErrorKind, InstallerFailure, Result, SshSetupError};
pub use frames::Secrets;
pub use install::{InstallOptions, InstallRequest, InstallScript, install};
pub use preflight::{Check, PreflightReport, ServerFacts, Status, SudoMode, preflight};
pub use progress::{
    DesktopInfo, GROUPS, InstallEvent, InstallResult, LogStream, PairingKind, Phase, StageState,
    group_of,
};
pub use ssh::{
    Auth, ConnectOptions, Connection, Credentials, HostKey, KeySource, SshTarget, probe_host_key,
};
