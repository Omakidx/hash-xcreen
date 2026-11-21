//! Running a plan inside a container: the executor abstraction and the stage runner.
//!
//! [`lower`] turns each plan [`Step`] into a few [`Action`]s (commands and file writes). The
//! runner feeds them to an [`Executor`]. `hx-provision`'s Incus executor is
//! [`crate::orchestrate::IncusExecutor`]; tests use a recording executor.
//!
//! # Secrets
//!
//! The only secret is the desktop user's password. It lives in [`Secrets`], reaches the container
//! only as the *stdin* of `chpasswd`, and is never part of an argv, an environment, a plan, a
//! log line or an error message. [`ExecRequest`]'s `Debug` output redacts stdin.

use std::future::Future;
use std::time::{Duration, Instant};

use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::lower::lower;
use crate::plan::{Plan, Stage, Step};

/// A secret byte string. Redacted in `Debug`, **not `Clone`**, and zeroized on drop (the whole
/// allocation, spare capacity included, through the `zeroize` crate's volatile writes).
///
/// There is deliberately no way to copy one: a secret that is handed over is moved. The types that
/// hold secrets ([`Secrets`], [`ExecRequest`], [`Action`]) are therefore not `Clone` either.
#[derive(PartialEq, Eq)]
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// A secret holding a copy of `bytes`. The caller remains responsible for zeroizing its own
    /// buffer.
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }

    /// The secret bytes. Callers must not log them.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret(<redacted, {} bytes>)", self.0.len())
    }
}

impl ZeroizeOnDrop for Secret {}

/// Longest accepted password, in bytes.
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// Why a password was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SecretError {
    /// Empty.
    #[error("the password is empty")]
    Empty,
    /// Longer than [`MAX_PASSWORD_BYTES`].
    #[error("the password is longer than 1024 bytes")]
    TooLong,
    /// Contains a newline, carriage return or NUL, which `chpasswd` input cannot represent.
    #[error("the password contains a newline or NUL byte")]
    BadCharacter,
}

/// Run-time secrets handed over by the caller. None of it is ever written to a recipe. Not
/// `Clone`; the secrets inside are zeroized when this is dropped.
#[derive(Debug, Default)]
pub struct Secrets {
    user_password: Option<Secret>,
    current_password: Option<Secret>,
}

impl Secrets {
    /// No secrets (enough for the build stage).
    pub fn none() -> Self {
        Self::default()
    }

    /// The Linux password of the desktop user, needed by the post stage.
    pub fn with_user_password(mut self, password: &str) -> Result<Self, SecretError> {
        self.user_password = Some(check_password(password)?);
        Ok(self)
    }

    /// The password the desktop user has *now*, for
    /// [`crate::password::change_user_password`] to check before it sets a new one (ipc.md 6.9).
    /// Same rules as [`Secrets::with_user_password`].
    pub fn with_current_password(mut self, password: &str) -> Result<Self, SecretError> {
        self.current_password = Some(check_password(password)?);
        Ok(self)
    }

    pub(crate) fn user_password(&self) -> Option<&Secret> {
        self.user_password.as_ref()
    }

    pub(crate) fn current_password(&self) -> Option<&Secret> {
        self.current_password.as_ref()
    }
}

fn check_password(password: &str) -> Result<Secret, SecretError> {
    if password.is_empty() {
        return Err(SecretError::Empty);
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(SecretError::TooLong);
    }
    if password.contains(['\n', '\r', '\0']) {
        return Err(SecretError::BadCharacter);
    }
    Ok(Secret::new(password.as_bytes().to_vec()))
}

impl ZeroizeOnDrop for Secrets {}

/// One command to run in the container. Not `Clone` (it may carry a [`Secret`]).
#[derive(PartialEq, Eq)]
pub struct ExecRequest {
    /// Short label for progress and errors (never contains secrets).
    pub label: String,
    /// Program and arguments. Never contains secrets.
    pub argv: Vec<String>,
    /// Extra environment. Never contains secrets.
    pub env: Vec<(String, String)>,
    /// Working directory.
    pub cwd: Option<String>,
    /// Bytes delivered on the process's standard input. The executor must deliver them on stdin
    /// (or an equivalent 0600 file redirected to stdin), never through argv or environment.
    pub stdin: Option<Secret>,
    /// Wall-clock limit; the executor must stop waiting and clean up when it expires.
    pub timeout: Duration,
}

impl std::fmt::Debug for ExecRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecRequest")
            .field("label", &self.label)
            .field("argv", &self.argv)
            .field("env", &self.env)
            .field("cwd", &self.cwd)
            .field(
                "stdin",
                &self
                    .stdin
                    .as_ref()
                    .map(|s| format!("<{} bytes>", s.expose().len())),
            )
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// A file to write into the container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePush {
    /// Absolute path inside the container. The parent directory exists.
    pub path: String,
    /// Content.
    pub content: Vec<u8>,
    /// Permission bits.
    pub mode: u32,
}

/// What the runner asks the executor to do.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Run a command.
    Exec(ExecRequest),
    /// Write a file.
    Push(FilePush),
}

/// Result of a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutput {
    /// Process exit status.
    pub exit_code: i32,
    /// Captured standard output (possibly truncated by the executor).
    pub stdout: String,
    /// Captured standard error (possibly truncated by the executor).
    pub stderr: String,
}

/// Failure to run a command at all (as opposed to the command failing).
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum ExecError {
    /// The command did not finish in time and was abandoned.
    #[error("timed out after {0:?}")]
    Timeout(Duration),
    /// The backend failed.
    #[error("{0}")]
    Backend(String),
}

/// Something that can run commands and write files inside one container.
pub trait Executor {
    /// Run a command and capture its output.
    fn exec(
        &self,
        request: &ExecRequest,
    ) -> impl Future<Output = Result<ExecOutput, ExecError>> + Send;
    /// Write a file.
    fn push_file(&self, file: &FilePush) -> impl Future<Output = Result<(), ExecError>> + Send;
}

/// Progress notifications; contain step descriptions only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    /// A step is about to run.
    Started {
        /// Stage being run.
        stage: Stage,
        /// 1-based position.
        index: usize,
        /// Steps in the stage.
        total: usize,
        /// [`Step::describe`] of the step.
        step: String,
    },
    /// A step finished.
    Finished {
        /// Stage being run.
        stage: Stage,
        /// 1-based position.
        index: usize,
        /// Step description.
        step: String,
        /// How long it took.
        elapsed: Duration,
        /// `false` when an optional command failed and was downgraded to a warning.
        ok: bool,
    },
}

/// An optional command failed; the stage went on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepWarning {
    /// Step description.
    pub step: String,
    /// Tail of the command's error output.
    pub message: String,
}

/// What a finished stage reports.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StageReport {
    /// Downgraded failures.
    pub warnings: Vec<StepWarning>,
    /// Per-step wall-clock time.
    pub timings: Vec<(String, Duration)>,
}

/// Why a command step failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StepFailure {
    /// The command exited non-zero.
    #[error("exit status {code}: {tail}")]
    ExitCode {
        /// Exit status.
        code: i32,
        /// Tail of stderr (or stdout when stderr is empty).
        tail: String,
    },
    /// The executor could not run it.
    #[error("{0}")]
    Exec(ExecError),
}

/// A stage stopped at a failed step.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApplyError {
    /// A step failed.
    #[error("{stage:?} stage, step {index} ({step}): {failure}")]
    Step {
        /// Stage that was running.
        stage: Stage,
        /// 1-based position of the step.
        index: usize,
        /// Step description.
        step: String,
        /// What went wrong.
        failure: StepFailure,
    },
    /// The stage needs a secret that the caller did not supply.
    #[error("{stage:?} stage, step ({step}) needs the user password, which was not provided")]
    MissingSecret {
        /// Stage that was running.
        stage: Stage,
        /// Step description.
        step: String,
    },
}

/// Make text that came from inside a container safe to show or log: ANSI/OSC escape sequences
/// and control characters (except newline and tab) are removed, and only the last `max` bytes are
/// kept (on a character boundary).
pub fn sanitize(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max + 8));
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => match chars.peek() {
                // CSI: ESC [ params... final byte 0x40-0x7e
                Some('[') => {
                    chars.next();
                    for n in chars.by_ref() {
                        if ('\u{40}'..='\u{7e}').contains(&n) {
                            break;
                        }
                    }
                }
                // OSC: ESC ] ... BEL or ESC \
                Some(']') => {
                    chars.next();
                    while let Some(n) = chars.next() {
                        if n == '\u{7}' {
                            break;
                        }
                        if n == '\u{1b}' {
                            chars.next();
                            break;
                        }
                    }
                }
                _ => {
                    chars.next();
                }
            },
            '\n' | '\t' => out.push(c),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    let t = out.trim_end();
    if t.len() <= max {
        return t.to_string();
    }
    let mut start = t.len() - max;
    while !t.is_char_boundary(start) {
        start += 1;
    }
    format!("...{}", &t[start..])
}

fn tail(s: &str, max: usize) -> String {
    sanitize(s, max)
}

/// Run one stage of `plan` in order, stopping at the first failure.
///
/// An `optional` command that fails is reported in [`StageReport::warnings`] and the stage
/// continues. `on_progress` receives step descriptions only.
pub async fn apply_stage<E: Executor>(
    executor: &E,
    plan: &Plan,
    stage: Stage,
    secrets: &Secrets,
    on_progress: &mut (dyn FnMut(&Progress) + Send),
) -> Result<StageReport, ApplyError> {
    let steps = plan.stage(stage);
    let total = steps.len();
    let mut report = StageReport::default();
    for (i, step) in steps.iter().enumerate() {
        let index = i + 1;
        let desc = step.describe();
        let started = Instant::now();
        on_progress(&Progress::Started {
            stage,
            index,
            total,
            step: desc.clone(),
        });
        let actions = lower(step, secrets).map_err(|_| ApplyError::MissingSecret {
            stage,
            step: desc.clone(),
        })?;
        let optional = matches!(step, Step::Command(c) if c.optional);
        let mut failure = None;
        for action in &actions {
            let r = match action {
                Action::Exec(req) => match executor.exec(req).await {
                    Ok(out) if out.exit_code == 0 => Ok(()),
                    Ok(out) => Err(StepFailure::ExitCode {
                        code: out.exit_code,
                        tail: tail(
                            if out.stderr.trim().is_empty() {
                                &out.stdout
                            } else {
                                &out.stderr
                            },
                            2000,
                        ),
                    }),
                    Err(e) => Err(StepFailure::Exec(e)),
                },
                Action::Push(f) => executor.push_file(f).await.map_err(StepFailure::Exec),
            };
            if let Err(e) = r {
                failure = Some(e);
                break;
            }
        }
        let elapsed = started.elapsed();
        report.timings.push((desc.clone(), elapsed));
        match failure {
            None => on_progress(&Progress::Finished {
                stage,
                index,
                step: desc,
                elapsed,
                ok: true,
            }),
            Some(f) if optional => {
                report.warnings.push(StepWarning {
                    step: desc.clone(),
                    message: f.to_string(),
                });
                on_progress(&Progress::Finished {
                    stage,
                    index,
                    step: desc,
                    elapsed,
                    ok: false,
                });
            }
            Some(failure) => {
                return Err(ApplyError::Step {
                    stage,
                    index,
                    step: desc,
                    failure,
                });
            }
        }
    }
    Ok(report)
}
