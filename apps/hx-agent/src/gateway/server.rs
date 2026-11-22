//! The gateway as a whole: the public endpoint, the admin socket and the parts between them.
//!
//! [`Gateway::start`] wires everything:
//!
//! ```text
//!  client ── QUIC / WebSocket ──► hx_transport::Server ──► PendingSession
//!                                      │ INTENT_PAIR     │ INTENT_SESSION
//!                                      ▼                 ▼
//!                       Authenticator::authenticate   Login (pinned key, PIN via privd)
//!                       (SPAKE2 pairing)                 │ authorized
//!                                      │                 ▼
//!                           DeviceService::announce  SessionManager::serve ──► DesktopLink (seam)
//!                                      │ INTENT_SETUP / INTENT_REINSTATE
//!                                      ▼
//!                  SetupCoordinator::serve   ReinstateGate (password via privd)
//!  hx-agent CLI (root) ── admin socket ──► admin::serve ──► DeviceService / Login / VerifierStore
//! ```
//!
//! Every `PendingSession` is looked up in the **current** registry (protocol 11.5); an unknown,
//! revoked or not-yet-set-up peer gets the same `Refuse{UNAUTHORIZED, "not authorized"}`.
//! `Hello.software` and `Hello.device_name` are sanitized before they are logged.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use hx_crypto::{
    Authenticator, AuthenticatorConfig, Clock, DeviceRegistry, FileRegistry, IdentityKey, Outcome,
    PairingLimits, SystemClock, tls,
};
use hx_proto::VideoCodec;
use hx_proto::channel::CloseCode;
use hx_proto::version::{Features, PROTOCOL_MINOR, capabilities_with_file_limit};
use hx_transport::{PendingSession, Server, ServerOptions};
use tokio::net::UnixListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::admin::{self, AdminPolicy, AdminState};
use super::config::GatewayConfig;
use super::desktop::DesktopLink;
use super::devices::DeviceService;
use super::live::LiveSessions;
use super::privd_client::PrivdClient;
use super::session::{SessionManager, SessionSettings};
use super::setup::store::{SetupStore, StoreError};
use super::setup::{SetupCoordinator, SetupSettings};
use super::util::log_text;
use super::verifier::{PrivdPinVerifier, PrivdReinstateGate, VerifierError, VerifierStore};

/// The software string sent in `HelloAck` (at most 128 bytes).
pub const SOFTWARE: &str = concat!("hx-gatewayd ", env!("CARGO_PKG_VERSION"));
/// Video codecs the gateway offers (v1 encodes H.264 only).
pub const OFFERED_CODECS: [VideoCodec; 1] = [VideoCodec::H264];

/// Why the gateway could not start.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    /// The registry could not be opened (permissions, lock held, corrupt).
    #[error("device registry: {0}")]
    Registry(#[from] hx_crypto::Error),
    /// The verifier store could not be opened.
    #[error("verifier store: {0}")]
    Verifiers(#[from] VerifierError),
    /// Binding the public endpoint failed.
    #[error("transport: {0}")]
    Transport(#[from] hx_transport::Error),
    /// The setup store could not be opened.
    #[error("setup store: {0}")]
    Setup(#[from] StoreError),
    /// Another I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Everything [`Gateway::start`] needs.
pub struct StartOptions {
    /// The configuration.
    pub config: GatewayConfig,
    /// The agent identity key (what clients pin).
    pub identity: Arc<IdentityKey>,
    /// The desktop link (the seam; [`super::desktop::UnavailableLink`] until it exists).
    pub link: Arc<dyn DesktopLink>,
    /// The admin socket, already bound (by systemd's socket activation or [`admin::bind`]).
    pub admin_listener: Option<UnixListener>,
    /// The public sockets, already bound by systemd's socket activation (UDP for QUIC, TCP for
    /// the WebSocket fallback). `None` binds `config.listen` itself.
    pub public_listeners: Option<(std::net::UdpSocket, std::net::TcpListener)>,
    /// Who may use the admin socket.
    pub admin_policy: AdminPolicy,
    /// The clock (tests move time).
    pub clock: Arc<dyn Clock>,
    /// Transport options (pre-authentication limits and so on).
    pub server_options: ServerOptions,
    /// The setup coordinator's tunables; `None` is the production values for
    /// `config.desktop_id` (tests lower the Argon2id cost and the retry wait).
    pub setup: Option<SetupSettings>,
}

impl StartOptions {
    /// Production defaults around `config`, `identity` and `link`.
    pub fn new(
        config: GatewayConfig,
        identity: Arc<IdentityKey>,
        link: Arc<dyn DesktopLink>,
    ) -> Self {
        Self {
            config,
            identity,
            link,
            admin_listener: None,
            public_listeners: None,
            admin_policy: AdminPolicy::RootOnly,
            clock: Arc::new(SystemClock),
            server_options: ServerOptions::default(),
            setup: None,
        }
    }
}

struct Shared {
    auth: Authenticator,
    verifiers: Arc<VerifierStore>,
    devices: Arc<DeviceService>,
    sessions: Arc<SessionManager>,
    live: Arc<LiveSessions>,
    setup: SetupCoordinator,
}

/// A running gateway.
pub struct Gateway {
    server: Arc<Server>,
    shared: Arc<Shared>,
    privd: PrivdClient,
    admin_state: Arc<AdminState>,
    shutdown: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
    /// Held until [`Gateway::begin`]: the admin listener and its shutdown receiver.
    pending_admin: Option<(UnixListener, AdminPolicy, watch::Receiver<bool>)>,
    begun: bool,
}

impl Gateway {
    /// [`Gateway::bind`] then [`Gateway::begin`]: the usual in-process start.
    pub async fn start(opts: StartOptions) -> Result<Self, GatewayError> {
        let mut g = Self::bind(opts).await?;
        g.begin();
        Ok(g)
    }

    /// Opens the registry and verifiers under `config.state_dir` and binds the public
    /// endpoint, **without accepting anything yet**. The binary applies the process hardening
    /// ([`super::harden`]) between `bind` and [`Gateway::begin`], so that the seccomp filter is
    /// in force before the first connection is looked at.
    pub async fn bind(opts: StartOptions) -> Result<Self, GatewayError> {
        let StartOptions {
            config,
            identity,
            link,
            admin_listener,
            public_listeners,
            admin_policy,
            clock,
            server_options,
            setup: setup_settings,
        } = opts;

        // State: the registry (hx-crypto's single-writer file) and the verifiers, side by side
        // in the gateway's own 0700 directory.
        let registry: Arc<dyn DeviceRegistry> =
            Arc::new(FileRegistry::open(config.state_dir.join("registry"))?);
        let verifiers = Arc::new(VerifierStore::open(config.state_dir.join("verifiers"))?);

        let ttl = Duration::from_secs(config.pairing_ttl_s);
        let auth = Authenticator::with_clock(
            identity.clone(),
            registry.clone(),
            AuthenticatorConfig {
                server_name: config.server_name.clone(),
                software: SOFTWARE.into(),
                // What a session is offered and gets when its PIN is accepted. `SETUP` is
                // offered only on `INTENT_SETUP` connections (protocol 4.7).
                capabilities: capabilities_with_file_limit(
                    &OFFERED_CODECS,
                    Features::defined_up_to(PROTOCOL_MINOR).without(Features::SETUP),
                    config.max_file_bytes,
                ),
                session_features: Features::defined_up_to(PROTOCOL_MINOR)
                    .without(Features::SETUP),
                pairing: PairingLimits {
                    token_ttl: ttl,
                    code_ttl: ttl,
                    ..PairingLimits::default()
                },
                ..AuthenticatorConfig::default()
            },
            clock.clone(),
        );
        let privd = PrivdClient::new(&config.privd_socket, Default::default());
        // The PIN check: Argon2id here, the yes/no from privd's pepper (docs/ipc.md 5.3).
        auth.set_pin_verifier(Arc::new(PrivdPinVerifier::new(
            verifiers.clone(),
            privd.clone(),
        )));
        // The account password check of a device locked out by its PIN (protocol 11.7).
        auth.set_reinstate_gate(Arc::new(PrivdReinstateGate::new(
            verifiers.clone(),
            privd.clone(),
        )));
        let live = LiveSessions::new();
        let devices = DeviceService::new(auth.clone(), privd.clone(), live.clone(), clock.clone());
        devices.set_pairing_ttl_s(config.pairing_ttl_s);
        // The post-pairing setup: its own persisted state next to the registry.
        let (setup_store, persisted) = SetupStore::open(config.state_dir.join("setup"))?;
        let setup = SetupCoordinator::new(
            setup_store,
            persisted,
            privd.clone(),
            verifiers.clone(),
            devices.clone(),
            &auth,
            clock.clone(),
            setup_settings.unwrap_or_else(|| SetupSettings::new(config.desktop_id.clone())),
        );
        auth.set_setup_gate(Arc::new(setup.clone()));
        let sessions = SessionManager::new(
            SessionSettings {
                desktop_id: config.desktop_id.clone(),
                takeover: config.takeover,
                manage_idle: Duration::from_secs(config.manage_idle_s),
                watch_interval: Duration::from_secs(5),
            },
            link,
            privd.clone(),
            devices.clone(),
            live.clone(),
            clock,
        );
        let tls = tls::server_config(&identity)?;
        let server = Arc::new(match public_listeners {
            Some((udp, tcp)) => Server::from_listeners_paused(udp, tcp, tls, server_options)?,
            None => Server::bind_paused(config.listen, tls, server_options).await?,
        });
        let shared = Arc::new(Shared {
            auth: auth.clone(),
            verifiers: verifiers.clone(),
            devices: devices.clone(),
            sessions: sessions.clone(),
            live: live.clone(),
            setup: setup.clone(),
        });
        let admin_state = AdminState::new(
            devices,
            verifiers,
            auth,
            sessions,
            live,
            config.argon2_min_memory_kib,
            config.pairing_ttl_s,
            setup,
        );
        let (shutdown, shutdown_rx) = watch::channel(false);
        Ok(Self {
            server,
            shared,
            privd,
            admin_state,
            shutdown,
            tasks: Vec::new(),
            pending_admin: admin_listener.map(|l| (l, admin_policy, shutdown_rx)),
            begun: false,
        })
    }

    /// Starts accepting public connections and admin requests. Call it once.
    pub fn begin(&mut self) {
        if std::mem::replace(&mut self.begun, true) {
            return;
        }
        // Only now does the transport read its sockets: the binary hardened itself between
        // `bind` and `begin`.
        self.server.start();
        // The public accept loop: every pending session gets its own task, so a slow peer
        // never blocks the loop.
        let (srv, sh) = (self.server.clone(), self.shared.clone());
        self.tasks.push(tokio::spawn(async move {
            while let Some(pending) = srv.accept().await {
                let sh = sh.clone();
                tokio::spawn(async move { handle_pending(sh, pending).await });
            }
        }));
        if let Some((listener, policy, rx)) = self.pending_admin.take() {
            self.tasks.push(tokio::spawn(admin::serve(
                listener,
                policy,
                self.admin_state.clone(),
                rx,
            )));
        }
    }

    /// The bound QUIC address.
    pub fn quic_addr(&self) -> Option<SocketAddr> {
        self.server.quic_addr()
    }

    /// The bound WebSocket (TCP) address.
    pub fn websocket_addr(&self) -> Option<SocketAddr> {
        self.server.websocket_addr()
    }

    /// The authenticator (tests issue pairing tokens through it; the admin socket issues codes).
    pub fn authenticator(&self) -> &Authenticator {
        &self.shared.auth
    }

    /// The verifier store.
    pub fn verifiers(&self) -> &Arc<VerifierStore> {
        &self.shared.verifiers
    }

    /// The device service.
    pub fn devices(&self) -> &Arc<DeviceService> {
        &self.shared.devices
    }

    /// The session manager.
    pub fn sessions(&self) -> &Arc<SessionManager> {
        &self.shared.sessions
    }

    /// Live sessions.
    pub fn live(&self) -> &Arc<LiveSessions> {
        &self.shared.live
    }

    /// The setup coordinator.
    pub fn setup(&self) -> &SetupCoordinator {
        &self.shared.setup
    }

    /// The privd client (tests and tools create verifiers with it).
    pub fn privd(&self) -> &PrivdClient {
        &self.privd
    }

    /// The admin state.
    pub fn admin_state(&self) -> &Arc<AdminState> {
        &self.admin_state
    }

    /// Stops accepting, tells live clients (`SHUTDOWN`) and ends the background tasks.
    pub async fn shutdown(mut self) {
        let _ = self.shutdown.send(true);
        self.server.close();
        self.shared
            .live
            .close_all(CloseCode::Shutdown, "server is stopping")
            .await;
        for t in self.tasks.drain(..) {
            t.abort();
        }
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        for t in &self.tasks {
            t.abort();
        }
    }
}

async fn handle_pending(sh: Arc<Shared>, pending: PendingSession) {
    let hello = pending.hello();
    // Peer-supplied text is cleaned before it reaches a log line (protocol 11.5).
    let software = log_text(&hello.software, 128);
    let name = log_text(&hello.device_name, 64);
    let remote = pending.remote_addr();
    tracing::debug!(%remote, %software, device = %name, intent = hello.intent, "pending session");
    // Subscribed before the authentication runs, so a revocation during it is never missed.
    let revocations = sh.auth.subscribe_revocations();
    // Pairing and the PIN login are both `Authenticator::authenticate`: the current registry
    // is read for every session, the PIN is checked by `PrivdPinVerifier`.
    match sh.auth.authenticate(pending).await {
        Ok(Outcome::Paired {
            connection,
            device,
            with,
        }) => {
            tracing::info!(device = %device.id, "device paired");
            // The device that pairs with the installer's token while the setup window is open
            // becomes the setup device (a code never binds).
            sh.setup.on_paired(&device, with);
            sh.devices.announce_added(&device);
            // The pairing connection carries nothing else (protocol 11.2): it is closed once
            // the client has had a moment to read the end of the exchange, and the device
            // reconnects with `INTENT_SETUP` or `INTENT_SESSION`.
            let _ = tokio::time::timeout(Duration::from_secs(2), connection.closed()).await;
            connection.close(CloseCode::NoError, "paired").await;
        }
        Ok(Outcome::Authorized { connection, device }) => {
            tracing::info!(device = %device.id, "session authorized");
            sh.sessions.serve(connection, device, revocations).await;
        }
        Ok(Outcome::Setup {
            connection,
            device,
            pin_verified,
        }) => {
            tracing::info!(device = %device.id, pin_verified, "setup connection authorized");
            sh.setup.serve(connection, device, pin_verified).await;
        }
        // The password was proven and the registry already holds the device as active again;
        // announce it and audit it (cause `password`, never the password). No session exists.
        Ok(Outcome::Reinstated { device }) => {
            tracing::info!(device = %device.id, "device reinstated with the account password");
            sh.devices.announce_reinstated_with_password(&device);
        }
        Ok(Outcome::Refused(_)) => {}
        Err(e) => tracing::debug!(error = %e, "authentication ended without success"),
    }
}

/// Where systemd places the credentials of system services (`$CREDENTIALS_DIRECTORY` is
/// `/run/credentials/<unit>`).
const CREDENTIALS_ROOT: &str = "/run/credentials/";

/// Is `path` lexically under systemd's credentials tree (no `..`)?
fn in_credentials_dir(path: &Path) -> bool {
    // `Path::starts_with` compares whole components, so `/run/credentialsX` does not match.
    path.starts_with(CREDENTIALS_ROOT)
        && path != Path::new(CREDENTIALS_ROOT)
        && path
            .components()
            .all(|c| !matches!(c, std::path::Component::ParentDir))
}

/// Is `meta` an acceptable identity-key file?
///
/// Everywhere: a regular file with no group or other access (0600 or stricter).
///
/// Under `/run/credentials/` only, as systemd creates it: a unit with `User=` or
/// `DynamicUser=` gets its credential as mode 0400 **owned by root with an ACL entry** for the
/// service user (systemd falls back to `chown` to the user when the file system has no ACLs).
/// `stat` then reports the ACL *mask* in the group bits, so the file looks like 0440. That is
/// accepted: owner read, group read (the mask), nothing else, and the owner must be root or
/// the process's own user. Write or execute bits, and any "other" access, are refused as
/// everywhere else.
fn identity_file_acceptable(meta: &std::fs::Metadata, credentials_dir: bool, euid: u32) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !meta.is_file() {
        return false;
    }
    let mode = meta.permissions().mode() & 0o7777;
    if !credentials_dir {
        return mode & 0o077 == 0;
    }
    mode & !0o440 == 0 && (meta.uid() == 0 || meta.uid() == euid)
}

/// Loads the identity key from a credential file: 32 raw bytes, or 64 hex characters.
/// The file must be a private regular file (see [`identity_file_acceptable`]: a systemd
/// credential is 0400, or 0440 as `stat` shows it with the service user's ACL) and is opened
/// without following symlinks.
pub fn load_identity(path: &Path) -> Result<IdentityKey, String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|e| format!("cannot open the identity credential: {}", e.kind()))?;
    let meta = f.metadata().map_err(|e| e.kind().to_string())?;
    if !identity_file_acceptable(
        &meta,
        in_credentials_dir(path),
        rustix::process::geteuid().as_raw(),
    ) {
        return Err("the identity credential must be a private regular file".into());
    }
    // Allocated once (the read is capped at 256 bytes): reading never regrows, so no copy of
    // the key is left behind in an abandoned buffer.
    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(256));
    f.by_ref()
        .take(256)
        .read_to_end(&mut bytes)
        .map_err(|e| e.kind().to_string())?;
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    if bytes.len() == 32 {
        seed.copy_from_slice(&bytes);
    } else {
        let text =
            std::str::from_utf8(&bytes).map_err(|_| "the identity credential is not a key")?;
        let raw = super::util::unhex(text.trim()).ok_or("the identity credential is not a key")?;
        if raw.len() != 32 {
            return Err("the identity credential is not a 32-byte key".into());
        }
        seed.copy_from_slice(&raw);
    }
    IdentityKey::from_seed(&seed).map_err(|_| "the identity credential is not a valid key".into())
}

#[cfg(test)]
mod identity_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn meta_with_mode(mode: u32) -> (tempfile::TempDir, std::fs::Metadata) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("identity");
        std::fs::write(&p, [0u8; 32]).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        let m = std::fs::metadata(&p).unwrap();
        (dir, m)
    }

    #[test]
    fn the_credentials_tree_is_recognised_lexically() {
        assert!(in_credentials_dir(Path::new(
            "/run/credentials/hx-gatewayd.service/identity"
        )));
        for p in [
            "/run/credentials",
            "/run/credentials/../etc/identity",
            "/run/credentials/x/../../etc/identity",
            "/tmp/run/credentials/x/identity",
            "/var/run/credentials/x/identity",
            "identity",
        ] {
            assert!(!in_credentials_dir(Path::new(p)), "{p}");
        }
    }

    #[test]
    fn strict_outside_the_credentials_tree() {
        let me = rustix::process::geteuid().as_raw();
        for (mode, ok) in [
            (0o400, true),
            (0o600, true),
            (0o440, false),
            (0o640, false),
            (0o604, false),
            (0o644, false),
        ] {
            let (_d, m) = meta_with_mode(mode);
            assert_eq!(identity_file_acceptable(&m, false, me), ok, "{mode:o}");
        }
    }

    #[test]
    fn systemds_acl_mask_is_accepted_under_the_credentials_tree_only() {
        let me = rustix::process::geteuid().as_raw();
        for (mode, ok) in [
            (0o400, true),
            (0o440, true), // owner r, ACL mask r
            (0o640, false),
            (0o460, false),
            (0o444, false),
            (0o404, false),
            (0o500, false),
            (0o410, false),
            (0o2440, false),
        ] {
            let (_d, m) = meta_with_mode(mode);
            assert_eq!(identity_file_acceptable(&m, true, me), ok, "{mode:o}");
        }
        // The same 0440 is refused anywhere else.
        let (_d, m) = meta_with_mode(0o440);
        assert!(!identity_file_acceptable(&m, false, me));
    }

    #[test]
    fn a_credential_owned_by_somebody_else_is_refused() {
        let (_d, m) = meta_with_mode(0o400);
        let owner = std::os::unix::fs::MetadataExt::uid(&m);
        // Neither root nor the process's user (unless the test runs as root).
        if owner != 0 {
            assert!(!identity_file_acceptable(&m, true, owner + 1));
        }
        assert!(identity_file_acceptable(&m, true, owner));
    }

    #[test]
    fn directories_and_symlinks_are_not_identity_files() {
        let dir = tempfile::tempdir().unwrap();
        let m = std::fs::metadata(dir.path()).unwrap();
        assert!(!identity_file_acceptable(&m, false, 0));
        assert!(!identity_file_acceptable(&m, true, 0));
        let target = dir.path().join("t");
        std::fs::write(&target, [0u8; 32]).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o400)).unwrap();
        let link = dir.path().join("l");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(load_identity(&link).is_err(), "NOFOLLOW");
    }
}
