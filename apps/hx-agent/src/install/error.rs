//! What can go wrong in the installer, and the exit code and JSON `code` each failure maps to
//! (design C1, C3).
//!
//! Every message is built from our own text or from peer text that went through
//! [`crate::cli::text::peer`]; nothing here is raw tool output, and nothing can hold a secret.

use crate::cli::error::{CliError, exit};
use crate::cli::text::peer;

/// Exit codes 9 to 12 of the installer (0 to 8 are those of the CLI, [`exit`]).
pub mod codes {
    /// Preflight failed: nothing was changed.
    pub const PREFLIGHT: u8 = 9;
    /// A signature, digest or version check failed.
    pub const VERIFY: u8 = 10;
    /// Another install or uninstall is running.
    pub const LOCKED: u8 = 11;
    /// The options conflict with the existing install.
    pub const CONFLICT: u8 = 12;
}

/// The machine-readable class of a failure (`code` of the C3 `result` line).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    /// A daemon cannot be reached.
    Unavailable,
    /// A tool failed or could not be run.
    Tool,
    /// Signature, digest or version verification failed.
    Verify,
    /// A preflight check failed.
    Preflight,
    /// privd or gatewayd refused.
    Refused,
    /// Not in this release.
    Unimplemented,
    /// Bad arguments or missing secrets.
    Usage,
    /// Options conflict with the recorded install.
    Conflict,
    /// The lock is held.
    Locked,
    /// Not root.
    NotRoot,
    /// The operator declined.
    Declined,
    /// An unexpected local failure (file system, state).
    Internal,
    /// The `--test-fail-after` hook.
    TestHook,
}

impl Code {
    /// The `code` string.
    pub fn name(self) -> &'static str {
        match self {
            Self::Unavailable => "UNAVAILABLE",
            Self::Tool => "TOOL",
            Self::Verify => "VERIFY",
            Self::Preflight => "PREFLIGHT",
            Self::Refused => "REFUSED",
            Self::Unimplemented => "UNIMPLEMENTED",
            Self::Usage => "USAGE",
            Self::Conflict => "CONFLICT",
            Self::Locked => "LOCKED",
            Self::NotRoot => "NOT_ROOT",
            Self::Declined => "DECLINED",
            Self::Internal => "INTERNAL",
            Self::TestHook => "TEST_HOOK",
        }
    }
}

/// A failure of the installer or of one of its stages.
#[derive(Debug, Clone)]
pub struct InstallError {
    /// The class.
    pub code: Code,
    /// Sanitized text for the operator.
    pub message: String,
    /// Running the same command again may help.
    pub retryable: bool,
    /// The process exit code.
    pub exit: u8,
}

/// Longest message kept in state and JSON.
pub const MAX_MESSAGE: usize = 400;

impl InstallError {
    fn new(code: Code, exit: u8, retryable: bool, message: impl AsRef<str>) -> Self {
        Self {
            code,
            message: peer(message.as_ref(), MAX_MESSAGE),
            retryable,
            exit,
        }
    }

    /// A tool failed (exit 1, retryable).
    pub fn tool(message: impl AsRef<str>) -> Self {
        Self::new(Code::Tool, exit::FAILED, true, message)
    }

    /// An unexpected local failure (exit 1, retryable).
    pub fn internal(message: impl AsRef<str>) -> Self {
        Self::new(Code::Internal, exit::FAILED, true, message)
    }

    /// A daemon cannot be reached (exit 3, retryable).
    pub fn unavailable(message: impl AsRef<str>) -> Self {
        Self::new(Code::Unavailable, exit::UNAVAILABLE, true, message)
    }

    /// A preflight check failed (exit 9, not retryable without a change).
    pub fn preflight(message: impl AsRef<str>) -> Self {
        Self::new(Code::Preflight, codes::PREFLIGHT, false, message)
    }

    /// A verification failed (exit 10).
    pub fn verify(message: impl AsRef<str>) -> Self {
        Self::new(Code::Verify, codes::VERIFY, false, message)
    }

    /// Bad arguments or missing secrets (exit 2).
    pub fn usage(message: impl AsRef<str>) -> Self {
        Self::new(Code::Usage, exit::USAGE, false, message)
    }

    /// Not in this release (exit 6).
    pub fn unimplemented(message: impl AsRef<str>) -> Self {
        Self::new(Code::Unimplemented, exit::UNIMPLEMENTED, false, message)
    }

    /// The options conflict with the existing install (exit 12).
    pub fn conflict(message: impl AsRef<str>) -> Self {
        Self::new(Code::Conflict, codes::CONFLICT, false, message)
    }

    /// The lock is held (exit 11).
    pub fn locked(message: impl AsRef<str>) -> Self {
        Self::new(Code::Locked, codes::LOCKED, true, message)
    }

    /// Not root (exit 7).
    pub fn not_root() -> Self {
        Self::new(
            Code::NotRoot,
            exit::NOT_ROOT,
            false,
            "hx-agent must run as root (try: sudo hx-agent ...)",
        )
    }

    /// The `--test-fail-after` hook fired (exit 1, retryable).
    pub fn test_hook(stage: &str) -> Self {
        Self::new(
            Code::TestHook,
            exit::FAILED,
            true,
            format!("test hook: stopped after stage '{stage}'"),
        )
    }
}

impl From<CliError> for InstallError {
    fn from(e: CliError) -> Self {
        let exit = e.exit_code();
        let (code, retryable) = match &e {
            CliError::Usage(_) => (Code::Usage, false),
            CliError::Unavailable(_) => (Code::Unavailable, true),
            CliError::Remote(r) => match exit {
                exit::UNAVAILABLE => (Code::Unavailable, true),
                exit::UNIMPLEMENTED => (Code::Unimplemented, false),
                exit::REFUSED | exit::NOT_FOUND => (Code::Refused, r.retryable),
                _ => (Code::Internal, r.retryable),
            },
            CliError::Unimplemented(_) => (Code::Unimplemented, false),
            CliError::Declined(_) => (Code::Declined, false),
            CliError::NotRoot => (Code::NotRoot, false),
            CliError::NotFound(_) => (Code::Refused, false),
            CliError::Failed(_) => (Code::Internal, true),
        };
        Self::new(code, exit, retryable, e.message())
    }
}

impl From<std::io::Error> for InstallError {
    fn from(e: std::io::Error) -> Self {
        Self::internal(format!("file system error: {}", e.kind()))
    }
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for InstallError {}

/// Result alias of the installer.
pub type Result<T> = std::result::Result<T, InstallError>;
