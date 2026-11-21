//! What can go wrong in the CLI, and the exit code each failure maps to.
//!
//! Every message here is built from our own text or from peer text that went through
//! [`super::text::peer`]; nothing in a `CliError` is raw peer bytes.

use hx_ipc::privd::pb::{ErrorCode, ErrorDetail};

use super::text::peer;

/// Exit codes (documented in `README.md`).
pub mod exit {
    /// Success.
    pub const OK: u8 = 0;
    /// Any other failure: an internal error, a protocol violation, a half-finished operation.
    pub const FAILED: u8 = 1;
    /// Bad command line.
    pub const USAGE: u8 = 2;
    /// A daemon cannot be reached, timed out, or answered `UNAVAILABLE`.
    pub const UNAVAILABLE: u8 = 3;
    /// The server refused: `PERMISSION_DENIED`, `FAILED_PRECONDITION`, `RESOURCE_EXHAUSTED`,
    /// `INVALID_ARGUMENT`.
    pub const REFUSED: u8 = 4;
    /// A device, desktop or snapshot does not exist, or an id prefix is ambiguous.
    pub const NOT_FOUND: u8 = 5;
    /// The command exists but this release does not implement it (`UNIMPLEMENTED`).
    pub const UNIMPLEMENTED: u8 = 6;
    /// Not running as root.
    pub const NOT_ROOT: u8 = 7;
    /// The operator declined, or there was no terminal to ask on.
    pub const DECLINED: u8 = 8;
}

/// An error answer from privd or gatewayd, with its text sanitized.
#[derive(Debug, Clone)]
pub struct Remote {
    /// The code.
    pub code: ErrorCode,
    /// The refinement.
    pub detail: ErrorDetail,
    /// Sanitized message.
    pub message: String,
    /// The server says a retry may help.
    pub retryable: bool,
    /// Suggested wait in milliseconds.
    pub retry_after_ms: u32,
}

/// A failure of one CLI command.
#[derive(Debug)]
pub enum CliError {
    /// Bad arguments.
    Usage(String),
    /// A socket cannot be reached or the call timed out.
    Unavailable(String),
    /// An error answer from a daemon.
    Remote(Remote),
    /// No such device, desktop or snapshot; or an ambiguous prefix.
    NotFound(String),
    /// The server does not implement the command in this release.
    Unimplemented(String),
    /// The operator said no, or no terminal was available.
    Declined(String),
    /// The peer broke the contract, or something else went wrong.
    Failed(String),
    /// euid is not 0.
    NotRoot,
}

impl CliError {
    /// Shorthand for [`CliError::Failed`].
    pub fn failed(m: impl Into<String>) -> Self {
        Self::Failed(m.into())
    }

    /// The process exit code.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Usage(_) => exit::USAGE,
            Self::Unavailable(_) => exit::UNAVAILABLE,
            Self::NotFound(_) => exit::NOT_FOUND,
            Self::Unimplemented(_) => exit::UNIMPLEMENTED,
            Self::Declined(_) => exit::DECLINED,
            Self::NotRoot => exit::NOT_ROOT,
            Self::Failed(_) => exit::FAILED,
            Self::Remote(r) => match r.code {
                ErrorCode::Unavailable | ErrorCode::DeadlineExceeded => exit::UNAVAILABLE,
                ErrorCode::NotFound => exit::NOT_FOUND,
                ErrorCode::Unimplemented => exit::UNIMPLEMENTED,
                ErrorCode::PermissionDenied
                | ErrorCode::FailedPrecondition
                | ErrorCode::ResourceExhausted
                | ErrorCode::InvalidArgument => exit::REFUSED,
                _ => exit::FAILED,
            },
        }
    }

    /// A stable, machine-readable name (the `error.code` of `--json`).
    pub fn code_name(&self) -> String {
        match self {
            Self::Usage(_) => "USAGE".into(),
            Self::Unavailable(_) => "UNAVAILABLE".into(),
            Self::NotFound(_) => "NOT_FOUND".into(),
            Self::Unimplemented(_) => "UNIMPLEMENTED".into(),
            Self::Declined(_) => "DECLINED".into(),
            Self::NotRoot => "NOT_ROOT".into(),
            Self::Failed(_) => "FAILED".into(),
            Self::Remote(r) => r
                .code
                .as_str_name()
                .strip_prefix("ERROR_CODE_")
                .unwrap_or("UNKNOWN")
                .to_owned(),
        }
    }

    /// The `detail` refinement of a remote error, if any.
    pub fn detail_name(&self) -> Option<String> {
        match self {
            Self::Remote(r) if r.detail != ErrorDetail::Unspecified => Some(
                r.detail
                    .as_str_name()
                    .strip_prefix("ERROR_DETAIL_")
                    .unwrap_or("UNKNOWN")
                    .to_owned(),
            ),
            _ => None,
        }
    }

    /// The text for the operator.
    pub fn message(&self) -> String {
        match self {
            Self::Usage(m)
            | Self::Unavailable(m)
            | Self::NotFound(m)
            | Self::Failed(m)
            | Self::Unimplemented(m)
            | Self::Declined(m) => m.clone(),
            Self::NotRoot => "hx-agent must run as root (try: sudo hx-agent ...)".into(),
            Self::Remote(r) => {
                let mut s = format!("the server answered {}", self.code_name());
                if let Some(d) = self.detail_name() {
                    s.push_str(&format!(" ({d})"));
                }
                if !r.message.is_empty() {
                    s.push_str(&format!(": {}", r.message));
                }
                if r.retryable || r.retry_after_ms > 0 {
                    s.push_str(&format!(
                        " (retry in about {} s)",
                        u64::from(r.retry_after_ms).div_ceil(1000).max(1)
                    ));
                }
                s
            }
        }
    }
}

/// Converts the `Error` message of a daemon into a [`CliError`], sanitizing its text.
pub fn remote(e: &hx_ipc::privd::pb::Error) -> CliError {
    CliError::Remote(Remote {
        code: ErrorCode::try_from(e.code).unwrap_or(ErrorCode::Internal),
        detail: ErrorDetail::try_from(e.detail).unwrap_or(ErrorDetail::Unspecified),
        message: peer(&e.message, hx_ipc::privd::MAX_ERROR_MESSAGE_LEN),
        retryable: e.retryable,
        retry_after_ms: e.retry_after_ms,
    })
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for CliError {}
