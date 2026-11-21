//! The error a command answers with, and the mapping from the layers below.

use hx_ipc::privd::{MAX_ERROR_MESSAGE_LEN, pb};
use hx_ipc::text::sanitize_text;
use hx_provision::incus::IncusError;
use hx_provision::orchestrate::{ProvisionError, ReadyError};

use pb::{ErrorCode, ErrorDetail, ProgressStage};

/// A failed command: becomes `Response { error }` (ipc.md 4, "Error model").
///
/// The message is built here from constants and sanitized daemon text. It never takes a secret:
/// no constructor accepts anything but a `&str` chosen by privd or an error text of `hx-provision`
/// or Incus, and [`CmdError::to_pb`] strips control characters and truncates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmdError {
    /// Error class.
    pub code: ErrorCode,
    /// Command-specific refinement.
    pub detail: ErrorDetail,
    /// Human-readable, at most 256 bytes after [`CmdError::to_pb`].
    pub message: String,
    /// Whether the caller may retry the same request later.
    pub retryable: bool,
    /// Suggested wait before a retry, 0 when unknown.
    pub retry_after_ms: u32,
    /// The failing stage of a long command.
    pub stage: Option<ProgressStage>,
}

impl CmdError {
    fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            detail: ErrorDetail::Unspecified,
            message: message.into(),
            retryable: false,
            retry_after_ms: 0,
            stage: None,
        }
    }

    /// `INVALID_ARGUMENT` naming the field.
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidArgument, message)
    }

    /// `PERMISSION_DENIED`.
    pub fn denied(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::PermissionDenied, message)
    }

    /// `FAILED_PRECONDITION` with a detail.
    pub fn precondition(detail: ErrorDetail, message: impl Into<String>) -> Self {
        let mut e = Self::new(ErrorCode::FailedPrecondition, message);
        e.detail = detail;
        e
    }

    /// `NOT_FOUND`.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }

    /// `RESOURCE_EXHAUSTED`, retryable when `retry_after_ms` is known.
    pub fn exhausted(message: impl Into<String>, retry_after_ms: u32) -> Self {
        let mut e = Self::new(ErrorCode::ResourceExhausted, message);
        e.retry_after_ms = retry_after_ms;
        e.retryable = retry_after_ms > 0;
        e
    }

    /// `RESOURCE_EXHAUSTED` with detail `LOCKED`: not retryable until an Admin resets it.
    pub fn locked(message: impl Into<String>) -> Self {
        let mut e = Self::new(ErrorCode::ResourceExhausted, message);
        e.detail = ErrorDetail::Locked;
        e
    }

    /// `UNAVAILABLE` (retryable).
    pub fn unavailable(message: impl Into<String>) -> Self {
        let mut e = Self::new(ErrorCode::Unavailable, message);
        e.retryable = true;
        e
    }

    /// `UNIMPLEMENTED`.
    pub fn unimplemented(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unimplemented, message)
    }

    /// `INTERNAL`. The caller's message must already be generic; details go to the journal.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, message)
    }

    /// `CANCELLED`.
    pub fn cancelled() -> Self {
        Self::new(ErrorCode::Cancelled, "cancelled")
    }

    /// `DEADLINE_EXCEEDED`.
    pub fn deadline() -> Self {
        let mut e = Self::new(ErrorCode::DeadlineExceeded, "deadline exceeded");
        e.retryable = true;
        e
    }

    /// Sets the failing stage.
    pub fn at_stage(mut self, stage: ProgressStage) -> Self {
        self.stage = Some(stage);
        self
    }

    /// Sets the detail.
    pub fn with_detail(mut self, detail: ErrorDetail) -> Self {
        self.detail = detail;
        self
    }

    /// The wire form: message sanitized and cut to 256 bytes.
    pub fn to_pb(&self) -> pb::Error {
        pb::Error {
            code: self.code as i32,
            detail: self.detail as i32,
            message: sanitize_text(&self.message, MAX_ERROR_MESSAGE_LEN),
            retryable: self.retryable,
            retry_after_ms: self.retry_after_ms,
            stage: self.stage.map(|s| s as i32),
        }
    }
}

impl std::fmt::Display for CmdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for CmdError {}

fn daemon_text(e: &impl std::fmt::Display) -> String {
    sanitize_text(&e.to_string(), 200)
}

impl From<IncusError> for CmdError {
    fn from(e: IncusError) -> Self {
        match &e {
            IncusError::Connect { .. } => CmdError::unavailable("Incus cannot be reached"),
            IncusError::Http(_) | IncusError::Timeout { .. } => {
                CmdError::unavailable(format!("Incus: {}", daemon_text(&e)))
            }
            IncusError::Api { code: 404, .. } => CmdError::not_found(daemon_text(&e)),
            IncusError::InvalidArgument(_) | IncusError::InvalidName { .. } => {
                CmdError::invalid(daemon_text(&e))
            }
            IncusError::Purged(_) => CmdError::internal(daemon_text(&e)),
            _ => CmdError::internal(format!("Incus: {}", daemon_text(&e))),
        }
    }
}

impl From<ProvisionError> for CmdError {
    fn from(e: ProvisionError) -> Self {
        match e {
            ProvisionError::Incus(i) => i.into(),
            ProvisionError::NotReady(ReadyError::Incus(i)) => i.into(),
            ProvisionError::NotReady(r) => {
                CmdError::precondition(ErrorDetail::DesktopNotReady, daemon_text(&r))
            }
            ProvisionError::Apply(a) => CmdError::internal(daemon_text(&a)),
            ProvisionError::Invalid(m) => CmdError::invalid(sanitize_text(&m, 200)),
            ProvisionError::NotOurs(_) => {
                CmdError::denied("the object does not carry the hash-xcreen marker")
            }
            ProvisionError::Unimplemented(m) => CmdError::unimplemented(sanitize_text(&m, 200)),
            ProvisionError::NotRunning => {
                CmdError::precondition(ErrorDetail::DesktopNotReady, "the desktop is not running")
            }
            ProvisionError::Task(m) => CmdError::internal(sanitize_text(&m, 200)),
        }
    }
}

impl From<std::io::Error> for CmdError {
    fn from(e: std::io::Error) -> Self {
        crate::privd::log::warn(&format!("io error: {e}"));
        CmdError::internal("an I/O operation on the host failed")
    }
}
