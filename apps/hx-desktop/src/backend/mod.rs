//! The seams to the parts that are built elsewhere, as small traits with working fakes
//! ([`demo`]).
//!
//! * [`InstallEngine`]: the SSH install (`crates/hx-sshsetup`).
//! * [`SetupClient`]: the one-liner path after pairing (`hx_crypto::setup`, protocol 1.3).
//! * [`DeviceAdmin`]: pairing codes and reinstate (protocol 1.3).
//! * [`ServerControl`]: what Server details needs beyond devices (overview numbers, PIN and
//!   password change, Docker, limits, restart, agent update). No protocol message exists for
//!   these yet; the trait is the contract the app needs.
//!
//! Listing and revoking devices, pairing with a token or code and the PIN login use the 1.2
//! APIs directly (`crate::session`), not these traits.

pub mod demo;
pub mod demo_desk;
pub mod real;
pub mod setup_real;
pub mod ssh;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use hx_crypto::IdentityKey;
use zeroize::Zeroizing;

/// A boxed future, as the traits are used through `dyn`.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A secret string: zeroized on drop, redacted in `Debug`, not `Clone`.
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// Wraps a secret.
    pub fn new(s: impl Into<String>) -> Self {
        Self(Zeroizing::new(s.into()))
    }
    /// The text. Use it only to hand it to the engine.
    pub fn expose(&self) -> &str {
        &self.0
    }
    /// Length in characters (for "6 digits" hints).
    pub fn len(&self) -> usize {
        self.0.chars().count()
    }
    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

// ------------------------------------------------------------------------------------ SSH

/// Where to connect over SSH.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshTarget {
    /// Host or IP.
    pub host: String,
    /// SSH port.
    pub port: u16,
}

/// How to authenticate over SSH. Never stored.
#[derive(Debug)]
pub enum SshAuth {
    /// The keys the app finds in `~/.ssh` and the agent.
    DefaultKeys {
        /// SSH user.
        user: String,
    },
    /// One key file.
    KeyFile {
        /// SSH user.
        user: String,
        /// Path of the private key.
        path: String,
        /// Passphrase, if the key has one.
        passphrase: Option<Secret>,
    },
    /// A password.
    Password {
        /// SSH user.
        user: String,
        /// The password.
        password: Secret,
    },
}

impl SshAuth {
    /// The SSH user.
    pub fn user(&self) -> &str {
        match self {
            Self::DefaultKeys { user }
            | Self::KeyFile { user, .. }
            | Self::Password { user, .. } => user,
        }
    }
}

/// The host key the server presented.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostKey {
    /// `ED25519`, `RSA`, ...
    pub algorithm: String,
    /// `SHA256:...`
    pub fingerprint: String,
}

/// Status of one requirement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckStatus {
    /// Met.
    Pass,
    /// Not met.
    Fail,
    /// Could not be determined.
    Unknown,
}

/// One row of the "Server checks" screen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckRow {
    /// Short key: `os`, `memory`, `cpus`, `disk`, `port`, `sudo`, ...
    pub key: String,
    /// What the server has ("7.8 GB memory").
    pub title: String,
    /// What is needed or what is missing ("At least 4 GB needed").
    pub detail: String,
    /// Result.
    pub status: CheckStatus,
}

/// Result of the requirement checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preflight {
    /// "Connected over SSH as root".
    pub connected_as: String,
    /// The rows in display order.
    pub rows: Vec<CheckRow>,
    /// Cores the server has (limit of the CPU slider).
    pub cpus: u32,
    /// Memory in MiB (limit of the memory slider).
    pub memory_mib: u64,
    /// Free disk in GiB (limit of the disk slider).
    pub disk_free_gib: u64,
}

impl Preflight {
    /// True when no row failed.
    pub fn ok(&self) -> bool {
        self.rows.iter().all(|r| r.status != CheckStatus::Fail)
    }
    /// Number of failed rows.
    pub fn failures(&self) -> usize {
        self.rows
            .iter()
            .filter(|r| r.status == CheckStatus::Fail)
            .count()
    }
}

/// Why an engine call failed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EngineError {
    /// No answer (off, wrong address, firewall).
    #[error("cannot reach the server: {0}")]
    Unreachable(String),
    /// The host key differs from the trusted one.
    #[error("the server's host key changed")]
    HostKeyChanged {
        /// Trusted fingerprint.
        expected: String,
        /// Presented fingerprint.
        actual: String,
    },
    /// Wrong password or key.
    #[error("the server refused these credentials")]
    AuthFailed,
    /// The key needs a passphrase.
    #[error("the key needs a passphrase")]
    KeyPassphraseRequired,
    /// `sudo` needs a password the app does not have.
    #[error("{0}")]
    Other(String),
}

/// What the wizard collected for the desktop (the installer's non-secret options).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallOptions {
    /// `ubuntu-24.04`, `ubuntu-26.04`, `debian-12`, `debian-13`.
    pub distro: String,
    /// `xfce`.
    pub desktop: String,
    /// `basic` or `developer`.
    pub apps: String,
    /// Docker in the desktop.
    pub docker: bool,
    /// Linux username.
    pub username: String,
    /// CPU cores for the desktop.
    pub cpu: u32,
    /// Memory in GiB.
    pub memory_gb: u32,
    /// Disk in GiB.
    pub disk_gb: u32,
    /// Agent port.
    pub port: u16,
    /// Optional domain (recorded only).
    pub domain: String,
    /// Backup schedule: `off` in Phase 1.
    pub backup: String,
}

/// An SSH install request. The secrets are used for this call only.
pub struct InstallRequest {
    /// Server.
    pub target: SshTarget,
    /// SSH credentials.
    pub auth: SshAuth,
    /// The host key the user confirmed.
    pub host_key: HostKey,
    /// Non-secret options.
    pub options: InstallOptions,
    /// The Linux account password.
    pub password: Secret,
    /// The PIN.
    pub pin: Secret,
    /// The app's own one-time pairing token (`hxt1-...`): the installer installs it as its last
    /// step (stage `pairing`), and the app pairs with it when the install finishes.
    pub pairing_token: Secret,
}

impl SshAuth {
    /// A copy, for a retry in the same session (secrets stay in memory only).
    pub fn duplicate(&self) -> Self {
        match self {
            Self::DefaultKeys { user } => Self::DefaultKeys { user: user.clone() },
            Self::KeyFile {
                user,
                path,
                passphrase,
            } => Self::KeyFile {
                user: user.clone(),
                path: path.clone(),
                passphrase: passphrase.as_ref().map(|p| Secret::new(p.expose())),
            },
            Self::Password { user, password } => Self::Password {
                user: user.clone(),
                password: Secret::new(password.expose()),
            },
        }
    }
}

impl InstallRequest {
    /// A copy, for "Retry from this stage" while the progress screen is open.
    pub fn duplicate(&self) -> Self {
        Self {
            target: self.target.clone(),
            auth: self.auth.duplicate(),
            host_key: self.host_key.clone(),
            options: self.options.clone(),
            password: Secret::new(self.password.expose()),
            pin: Secret::new(self.pin.expose()),
            pairing_token: Secret::new(self.pairing_token.expose()),
        }
    }
}

/// State of one installer stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StageState {
    /// Started.
    Start,
    /// Finished.
    Done,
    /// Skipped because it was already done.
    Skipped,
    /// Deferred (backups in Phase 1).
    Deferred,
}

/// A failure reported by the installer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallFailure {
    /// Stage id.
    pub stage: String,
    /// Machine code, for example `UNAVAILABLE`.
    pub code: String,
    /// Sanitized message.
    pub message: String,
    /// Retry is safe.
    pub retryable: bool,
}

/// What a finished install tells the app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallOutcome {
    /// The server's identity key, 64 hex digits.
    pub server_key_hex: String,
    /// Addresses the server reports.
    pub addresses: Vec<String>,
    /// Agent port.
    pub port: u16,
    /// Agent version.
    pub agent_version: String,
    /// "Built on the server" or "Prebuilt image".
    pub image_path: String,
    /// Whole run in seconds.
    pub elapsed_secs: u64,
}

/// One event of a running install (SSH or one-liner).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstallEvent {
    /// A stage changed state; `ms` is its duration when done.
    Stage {
        /// Stage id (`preflight`, `packages`, ...).
        id: String,
        /// New state.
        state: StageState,
        /// Duration in milliseconds.
        ms: Option<u64>,
    },
    /// A step inside a stage; `percent` is `None` when the installer cannot measure it.
    Step {
        /// Stage id.
        stage: String,
        /// 1-based index.
        index: u32,
        /// Total steps.
        total: u32,
        /// Text.
        text: String,
        /// 0..=100 or unknown.
        percent: Option<u8>,
    },
    /// A warning line.
    Warn(String),
    /// A log line.
    Log(String),
    /// Which image path was chosen and why.
    ImagePath {
        /// A prebuilt image is used.
        prebuilt: bool,
        /// Reason for building locally, or empty.
        reason: String,
    },
    /// The connection to the server was lost during `stage`.
    ConnectionLost {
        /// The last stage seen.
        stage: String,
    },
    /// The install failed.
    Failed(InstallFailure),
    /// The install finished.
    Finished(InstallOutcome),
}

/// A running install: read events until `None`.
pub trait InstallRun: Send {
    /// The next event, or `None` after the final one.
    fn next_event(&mut self) -> BoxFuture<'_, Option<InstallEvent>>;
    /// Stop (closes the SSH session; the install resumes on the next run).
    fn cancel(&mut self);
}

/// Uninstall request (over SSH, as root).
pub struct UninstallRequest {
    /// Server.
    pub target: SshTarget,
    /// Credentials.
    pub auth: SshAuth,
    /// Trusted host key.
    pub host_key: HostKey,
    /// Keep the desktop on the server.
    pub keep_desktop: bool,
}

/// The SSH install engine.
pub trait InstallEngine: Send + Sync {
    /// Connects far enough to read the host key; nothing is authenticated yet.
    fn probe_host_key(&self, target: &SshTarget) -> BoxFuture<'_, Result<HostKey, EngineError>>;
    /// Authenticates against the trusted key and runs the requirement checks.
    fn preflight(
        &self,
        target: &SshTarget,
        auth: &SshAuth,
        trusted: &HostKey,
    ) -> BoxFuture<'_, Result<Preflight, EngineError>>;
    /// Starts an install and returns its event stream.
    fn install(
        &self,
        req: InstallRequest,
    ) -> BoxFuture<'_, Result<Box<dyn InstallRun>, EngineError>>;
    /// Uninstalls the agent.
    fn uninstall(&self, req: UninstallRequest) -> BoxFuture<'_, Result<(), EngineError>>;
}

// ------------------------------------------------------------------------------------ one-liner

/// A server address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerAddr {
    /// Host or IP.
    pub host: String,
    /// Agent port.
    pub port: u16,
}

/// A paired server, from a token or a code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairedInfo {
    /// Server identity key, 64 hex digits.
    pub server_key_hex: String,
    /// Label the server reported.
    pub server_name: String,
    /// The protocol version the server showed on this pairing (`major`, `minor`); `None` when
    /// it was never confirmed. Setup, reinstate and pairing codes need 1.3.
    pub server_version: Option<(u32, u32)>,
}

/// Why pairing or setup failed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SetupError {
    /// Nothing answers at the address yet.
    #[error("cannot reach the agent")]
    Unreachable,
    /// Wrong, expired or used token or code (the server never says which).
    #[error("the token or code did not work")]
    PairingFailed,
    /// Pairing is closed on the server.
    #[error("pairing is closed on the server")]
    PairingClosed,
    /// The server is older than protocol 1.3: it must be updated first.
    #[error("the server must be updated")]
    UpdateRequired,
    /// Setup is no longer open for this device (it was finished or the window closed): go to
    /// the normal PIN login.
    #[error("setup is no longer open on this server; connect with your PIN")]
    Closed,
    /// Anything else.
    #[error("{0}")]
    Other(String),
}

/// Request for the post-pairing setup (password, PIN, desktop options).
pub struct SetupRequest {
    /// Non-secret options.
    pub options: InstallOptions,
    /// Account password.
    pub password: Secret,
    /// PIN.
    pub pin: Secret,
}

impl SetupRequest {
    /// A copy, for "Retry" while the progress screen is open (memory only).
    pub fn duplicate(&self) -> Self {
        Self {
            options: self.options.clone(),
            password: Secret::new(self.password.expose()),
            pin: Secret::new(self.pin.expose()),
        }
    }
}

/// The one-liner path: pairing, then the setup protocol of 1.3.
pub trait SetupClient: Send + Sync {
    /// Pairs with the agent the one-liner installer started, using the token shown to the user.
    /// `Err(Unreachable)` until the agent listens: the caller polls.
    fn pair(
        &self,
        addr: &ServerAddr,
        device: Arc<IdentityKey>,
        token: &Secret,
    ) -> BoxFuture<'_, Result<PairedInfo, SetupError>>;
    /// Sends the password and PIN and creates the desktop; progress arrives as install events.
    fn start_setup(
        &self,
        addr: &ServerAddr,
        device: Arc<IdentityKey>,
        paired: &PairedInfo,
        req: SetupRequest,
    ) -> BoxFuture<'_, Result<Box<dyn InstallRun>, SetupError>>;
}

// ------------------------------------------------------------------------------------ admin

/// A saved server plus this device's key: what an admin call needs.
#[derive(Clone)]
pub struct AdminContext {
    /// Host.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Pinned server key, hex.
    pub server_key_hex: String,
    /// This device's key.
    pub device: Arc<IdentityKey>,
    /// The protocol version the server last showed (`major`, `minor`).
    pub server_version: Option<(u32, u32)>,
    /// A PIN-authenticated management connection, when the user unlocked one (the real
    /// implementations send their requests over it).
    pub session: Option<Arc<dyn crate::session::Desk>>,
}

/// A pairing code issued by an already paired device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedCode {
    /// `K7QM-4XD2`.
    pub code: String,
    /// Seconds until it expires.
    pub expires_in_secs: u64,
    /// Failed tries allowed.
    pub tries: u32,
}

/// Why an admin call failed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AdminError {
    /// Wrong current PIN or password; attempts left when the server says.
    #[error("incorrect")]
    Incorrect {
        /// Attempts left, if known.
        attempts_left: Option<u32>,
    },
    /// Rate limited.
    #[error("too many requests, try again later")]
    RateLimited,
    /// The server could not do it right now.
    #[error("{0}")]
    Failed(String),
    /// No answer.
    #[error("cannot reach the server")]
    Unreachable,
    /// The server is older than protocol 1.3: it must be updated first.
    #[error("the server must be updated")]
    UpdateRequired,
}

/// Pairing codes and reinstate (protocol 1.3).
pub trait DeviceAdmin: Send + Sync {
    /// Asks the server for a short-lived pairing code (rate-limited and audited server-side).
    fn create_pairing_code(
        &self,
        ctx: &AdminContext,
    ) -> BoxFuture<'_, Result<IssuedCode, AdminError>>;
    /// Re-enables this device after a revoke, proving the account password.
    fn reinstate(
        &self,
        ctx: &AdminContext,
        password: &Secret,
    ) -> BoxFuture<'_, Result<(), AdminError>>;
}

// ------------------------------------------------------------------------------------ server control

/// The numbers of Server details, Overview.
#[derive(Clone, Debug, PartialEq)]
pub struct Overview {
    /// The desktop answers.
    pub desktop_running: bool,
    /// Uptime in seconds.
    pub uptime_secs: u64,
    /// Who is connected, if anyone.
    pub session_with: Option<String>,
    /// "Ubuntu 24.04 · XFCE · Developer · Docker on".
    pub setup: String,
    /// Agent version.
    pub agent_version: String,
    /// Channel.
    pub channel: String,
    /// A newer version, if one exists.
    pub update_available: Option<String>,
    /// Protocol version text.
    pub protocol: String,
    /// CPU use in percent.
    pub cpu_pct: u32,
    /// Cores of the desktop.
    pub cpu_cores: u32,
    /// Memory used, GiB.
    pub mem_used_gb: f32,
    /// Memory limit, GiB.
    pub mem_total_gb: f32,
    /// Disk used, GiB.
    pub disk_used_gb: u32,
    /// Disk limit, GiB.
    pub disk_total_gb: u32,
    /// Host OS line.
    pub host_os: String,
    /// Paired devices.
    pub devices: u32,
    /// Docker is on.
    pub docker: bool,
    /// Cores of the host (limit of the CPU slider).
    pub host_cpus: u32,
    /// GiB the desktop may use at most (host memory minus the reserve).
    pub host_mem_gb: u32,
    /// GiB of disk the desktop may use at most.
    pub host_disk_gb: u32,
}

/// Resource limits of the desktop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Cores.
    pub cpu: u32,
    /// GiB.
    pub memory_gb: u32,
    /// GiB.
    pub disk_gb: u32,
}

/// Server management beyond devices.
pub trait ServerControl: Send + Sync {
    /// Overview numbers.
    fn overview(&self, ctx: &AdminContext) -> BoxFuture<'_, Result<Overview, AdminError>>;
    /// Changes the PIN (the current one counts as an attempt).
    fn change_pin(
        &self,
        ctx: &AdminContext,
        current: &Secret,
        new: &Secret,
    ) -> BoxFuture<'_, Result<(), AdminError>>;
    /// Changes the Linux account password.
    fn change_password(
        &self,
        ctx: &AdminContext,
        current: &Secret,
        new: &Secret,
    ) -> BoxFuture<'_, Result<(), AdminError>>;
    /// Restarts the desktop.
    fn restart_desktop(&self, ctx: &AdminContext) -> BoxFuture<'_, Result<(), AdminError>>;
    /// Turns Docker on or off (restarts the desktop).
    fn set_docker(&self, ctx: &AdminContext, on: bool) -> BoxFuture<'_, Result<(), AdminError>>;
    /// Applies resource limits without a restart.
    fn set_limits(
        &self,
        ctx: &AdminContext,
        limits: Limits,
    ) -> BoxFuture<'_, Result<(), AdminError>>;
    /// Updates the agent now.
    fn update_agent(&self, ctx: &AdminContext) -> BoxFuture<'_, Result<String, AdminError>>;
}

/// Everything the app needs from outside, in one place. `demo::Backends::new()` fills it with
/// the fakes; the integrator replaces the fields it has real implementations for.
#[derive(Clone)]
pub struct Backends {
    /// SSH install.
    pub install: Arc<dyn InstallEngine>,
    /// One-liner setup.
    pub setup: Arc<dyn SetupClient>,
    /// Pairing codes and reinstate.
    pub admin: Arc<dyn DeviceAdmin>,
    /// Server management.
    pub control: Arc<dyn ServerControl>,
    /// Opens the PIN-authenticated desktop connection (real: `session::RealConnector`).
    pub connector: Arc<dyn crate::session::Connector>,
}

// ------------------------------------------------------------------------------------ stage rows

/// One of the ten grouped rows of the progress screen.
#[derive(Clone, Copy, Debug)]
pub struct StageGroup {
    /// Row title.
    pub title: &'static str,
    /// The installer stage ids it covers, shown in small grey text.
    pub stages: &'static [&'static str],
}

/// The ten rows (architecture 5.3 stages grouped, design/mockups/progress.html).
pub const GROUPS: [StageGroup; 10] = [
    StageGroup {
        title: "Check the server",
        stages: &["preflight"],
    },
    StageGroup {
        title: "Install system packages",
        stages: &["packages"],
    },
    StageGroup {
        title: "Install Incus (the container manager)",
        stages: &["incus"],
    },
    StageGroup {
        title: "Install the agent",
        stages: &["release", "system-files", "credentials", "config", "units"],
    },
    StageGroup {
        title: "Prepare the host",
        stages: &["setup-window", "host", "firewall-port"],
    },
    StageGroup {
        title: "Build the desktop",
        stages: &["desktop"],
    },
    StageGroup {
        title: "Secure access: password and PIN",
        stages: &["verifiers", "owner-key"],
    },
    StageGroup {
        title: "Backups",
        stages: &["backup"],
    },
    StageGroup {
        title: "Pair this device",
        stages: &["pairing-token", "pairing"],
    },
    StageGroup {
        title: "Finish",
        stages: &["finish", "done"],
    },
];

/// The row a stage id belongs to.
pub fn group_of(stage: &str) -> Option<usize> {
    // The engine's table also knows the `bootstrap-*` ids of `install.sh`.
    hx_sshsetup::group_of(stage)
}
