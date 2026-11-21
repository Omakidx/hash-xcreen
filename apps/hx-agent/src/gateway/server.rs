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
use hx_proto::pb::{Intent, RefuseReason};
use hx_proto::version::{Features, PROTOCOL_MINOR, capabilities_with_file_limit};
use hx_transport::{PendingSession, Server, ServerHello, ServerOptions};
use tokio::net::UnixListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::admin::{self, AdminPolicy, AdminState};
use super::config::GatewayConfig;
use super::desktop::DesktopLink;
use super::devices::DeviceService;
use super::live::LiveSessions;
use super::login::{Login, LoginConfig};
use super::privd_client::PrivdClient;
use super::session::{SessionManager, SessionSettings};
use super::util::log_text;
use super::verifier::{VerifierError, VerifierStore};

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
    /// Who may use the admin socket.
    pub admin_policy: AdminPolicy,
    /// The clock (tests move time).
    pub clock: Arc<dyn Clock>,
    /// Transport options (pre-authentication limits and so on).
    pub server_options: ServerOptions,
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
            admin_policy: AdminPolicy::RootOnly,
            clock: Arc::new(SystemClock),
            server_options: ServerOptions::default(),
        }
    }
}

struct Shared {
    config: GatewayConfig,
    auth: Authenticator,
    registry: Arc<dyn DeviceRegistry>,
    login: Login,
    verifiers: Arc<VerifierStore>,
    devices: Arc<DeviceService>,
    sessions: Arc<SessionManager>,
    live: Arc<LiveSessions>,
    features: Features,
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
            admin_policy,
            clock,
            server_options,
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
        let live = LiveSessions::new();
        let devices = DeviceService::new(auth.clone(), privd.clone(), live.clone());
        let login = Login::new(
            registry.clone(),
            auth.clone(),
            verifiers.clone(),
            privd.clone(),
            clock.clone(),
            LoginConfig::default(),
            devices.revoke_gate(),
        );
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
            auth.clone(),
            clock,
        );
        let server = Arc::new(
            Server::bind_paused(
                config.listen,
                tls::server_config(&identity)?,
                server_options,
            )
            .await?,
        );
        let shared = Arc::new(Shared {
            auth: auth.clone(),
            registry,
            login: login.clone(),
            verifiers: verifiers.clone(),
            devices: devices.clone(),
            sessions: sessions.clone(),
            live: live.clone(),
            features: Features::defined_up_to(PROTOCOL_MINOR),
            config: config.clone(),
        });
        let admin_state = AdminState::new(
            devices,
            login,
            verifiers,
            auth,
            sessions,
            live,
            config.argon2_min_memory_kib,
            config.pairing_ttl_s,
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
    let intent = Intent::try_from(hello.intent).unwrap_or(Intent::Unspecified);
    tracing::debug!(%remote, %software, device = %name, ?intent, "pending session");
    match intent {
        Intent::Pair => pair(&sh, pending).await,
        Intent::Session => session(&sh, pending).await,
        Intent::Unspecified => {
            let _ = pending
                .refuse(RefuseReason::Unauthorized, "not authorized")
                .await;
        }
    }
}

async fn pair(sh: &Shared, pending: PendingSession) {
    match sh.auth.authenticate(pending).await {
        Ok(Outcome::Paired { connection, device }) => {
            tracing::info!(device = %device.id, "device paired");
            sh.devices.announce_added(&device);
            // Post-pairing setup messages (password, PIN) are specified by 1G; until then the
            // pairing connection is closed once the client has had a moment to read the end of
            // the exchange (protocol 11.2).
            let _ = tokio::time::timeout(Duration::from_secs(2), connection.closed()).await;
            connection.close(CloseCode::NoError, "paired").await;
        }
        Ok(Outcome::Authorized { connection, .. }) => {
            // `authenticate` never authorizes: its PIN is unset and sessions are handled below.
            connection
                .close(CloseCode::InternalError, "unexpected")
                .await;
        }
        Ok(Outcome::Refused(_)) => {}
        Err(e) => tracing::debug!(error = %e, "pairing ended without success"),
    }
}

async fn session(sh: &Shared, pending: PendingSession) {
    let refuse = |p: PendingSession| async move {
        let _ = p.refuse(RefuseReason::Unauthorized, "not authorized").await;
    };
    let Ok(key) = tls::peer_key(pending.peer_certificates()) else {
        return refuse(pending).await;
    };
    // The current registry, never a cached answer.
    let device = match sh.registry.find_by_key(&key) {
        Ok(Some(d)) if !d.is_revoked() => d,
        Ok(_) => return refuse(pending).await,
        Err(e) => {
            tracing::error!(error = %e, "registry lookup failed; refusing");
            return refuse(pending).await;
        }
    };
    // No PIN anywhere: the server is not set up yet. The text is the same as for an unknown
    // peer (protocol 11.6).
    if !sh.verifiers.has_pin() {
        return refuse(pending).await;
    }
    // Subscribed before the login runs, so a revocation during it is never missed.
    let revocations = sh.auth.subscribe_revocations();
    let caps = capabilities_with_file_limit(&OFFERED_CODECS, sh.features, sh.config.max_file_bytes);
    let conn = match pending
        .accept(ServerHello {
            capabilities: caps,
            software: SOFTWARE.into(),
        })
        .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(error = %e, "accepting the session failed");
            return;
        }
    };
    if let Err(e) = sh.login.pin_exchange(&conn, &device).await {
        tracing::debug!(device = %device.id, error = %e, "login failed");
        Login::close_failed(&conn, "authentication failed").await;
        return;
    }
    let device = match sh.login.complete(&conn, &device, sh.features).await {
        Ok(d) => d,
        Err(e) => {
            tracing::debug!(device = %device.id, error = %e, "login could not be completed");
            Login::close_failed(&conn, "authentication failed").await;
            return;
        }
    };
    tracing::info!(device = %device.id, "session authorized");
    sh.sessions.serve(conn, device, revocations).await;
}

/// Loads the identity key from a credential file: 32 raw bytes, or 64 hex characters.
/// The file must be a private regular file (a systemd credential is 0400) and is opened
/// without following symlinks.
pub fn load_identity(path: &Path) -> Result<IdentityKey, String> {
    use std::io::Read;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|e| format!("cannot open the identity credential: {}", e.kind()))?;
    let meta = f.metadata().map_err(|e| e.kind().to_string())?;
    if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
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
