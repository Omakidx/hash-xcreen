//! Typed errors: one variant per failure the "Add server" mockups show.

use crate::preflight::Check;

/// What the installer reported when it stopped (the failing `result` line of design C3, or, when
/// there was none, the exit code and the last stderr line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallerFailure {
    /// The stage that failed (`incus`, `desktop`, `bootstrap-verify`, ...), `unknown` if none ran.
    pub stage: String,
    /// The machine-readable class (`UNAVAILABLE`, `TOOL`, `VERIFY`, `PREFLIGHT`, `LOCKED`, ...).
    pub code: String,
    /// Sanitized message for the user.
    pub message: String,
    /// Whether running the same command again can help. The installer's own flag, plus `LOCKED`
    /// (another install is still finishing), which the shell bootstrap cannot mark itself.
    pub retryable: bool,
    /// The installer's exit status.
    pub exit: u32,
}

/// Everything this crate can fail with.
#[derive(Debug, thiserror::Error)]
pub enum SshSetupError {
    /// The TCP connection or the SSH handshake failed (unreachable, refused, timed out).
    #[error("cannot connect to the server: {0}")]
    Connect(String),
    /// The server rejected the credentials.
    #[error("the server rejected the SSH credentials")]
    AuthFailed,
    /// The private key is encrypted and no (or a wrong) passphrase was given.
    #[error("the SSH key is protected by a passphrase")]
    KeyPassphraseRequired,
    /// The private key cannot be read or used.
    #[error("cannot use the SSH key: {0}")]
    KeyUnusable(String),
    /// The server presented another host key than the one the user trusted.
    #[error("the server's host key changed (trusted {expected}, server offered {actual})")]
    HostKeyChanged {
        /// The fingerprint the caller expected.
        expected: String,
        /// The fingerprint the server offered.
        actual: String,
    },
    /// `sudo` needs a password and none was given.
    #[error("sudo needs the account password")]
    SudoPasswordRequired,
    /// The sudo password was refused. Nothing secret was sent to the installer.
    #[error("the sudo password was not accepted")]
    SudoPasswordWrong,
    /// The account is not root and cannot use sudo.
    #[error("this account is not root and cannot use sudo")]
    SudoUnavailable,
    /// The server does not meet the minimum.
    #[error("the server does not meet the requirements")]
    RequirementFailed(Vec<Check>),
    /// The SSH connection closed while the installer was running. Finished stages are kept on
    /// the server; connect again and call `install` again (secrets must be supplied again).
    #[error("the SSH connection was lost during the install")]
    ConnectionLost {
        /// The stage that was running, when known.
        last_stage: Option<String>,
    },
    /// The installer ran and failed.
    #[error("the installer failed at stage {}: {} ({})", .0.stage, .0.message, .0.code)]
    InstallerFailed(InstallerFailure),
    /// A value the caller gave is not acceptable (checked before anything is sent).
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// A step took longer than its bound.
    #[error("timed out: {0}")]
    Timeout(&'static str),
    /// The server's answer is not what the contract says.
    #[error("unexpected answer from the server: {0}")]
    Protocol(String),
    /// The key the server reported over SSH is not the key it presented while pairing.
    #[error("the server key seen while pairing is not the one the installer reported")]
    ServerKeyMismatch,
    /// Pairing or the PIN login failed.
    #[error("pairing failed: {0}")]
    Pairing(#[from] hx_crypto::Error),
}

/// The coarse class of an error, for the UI to pick a screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Back to the connection step.
    Connection,
    /// Ask for the credentials again.
    Credentials,
    /// Warn loudly: possible interception.
    HostKey,
    /// Ask for the sudo password again.
    Sudo,
    /// Show the requirement list.
    Requirements,
    /// Offer "Reconnect and resume".
    ConnectionLost,
    /// Show the stage, the reason and (if retryable) Retry.
    Installer,
    /// Pairing, PIN login, key cross-check.
    Pairing,
    /// A bug or an unexpected answer.
    Internal,
}

impl SshSetupError {
    /// The coarse class.
    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::Connect(_) | Self::Timeout(_) => ErrorKind::Connection,
            Self::AuthFailed | Self::KeyPassphraseRequired | Self::KeyUnusable(_) => {
                ErrorKind::Credentials
            }
            Self::HostKeyChanged { .. } => ErrorKind::HostKey,
            Self::SudoPasswordRequired | Self::SudoPasswordWrong | Self::SudoUnavailable => {
                ErrorKind::Sudo
            }
            Self::RequirementFailed(_) => ErrorKind::Requirements,
            Self::ConnectionLost { .. } => ErrorKind::ConnectionLost,
            Self::InstallerFailed(_) => ErrorKind::Installer,
            Self::ServerKeyMismatch | Self::Pairing(_) => ErrorKind::Pairing,
            Self::InvalidInput(_) | Self::Protocol(_) => ErrorKind::Internal,
        }
    }

    /// Whether the same action can be tried again. For `ConnectionLost` and a retryable
    /// installer failure, the caller must supply the secrets again.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Connect(_)
            | Self::Timeout(_)
            | Self::ConnectionLost { .. }
            | Self::SudoPasswordWrong
            | Self::SudoPasswordRequired
            | Self::KeyPassphraseRequired
            | Self::AuthFailed => true,
            Self::InstallerFailed(f) => f.retryable,
            _ => false,
        }
    }
}

/// Result alias.
pub type Result<T, E = SshSetupError> = std::result::Result<T, E>;
