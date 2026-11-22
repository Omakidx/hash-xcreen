//! Harness of the setup, pairing-code and reinstate tests: a real [`Gateway`] in front of a
//! **real privd daemon** (`Harness` on `FakeIncus`), the admin socket, and the real client
//! library (`hx_crypto::setup`, `reinstate_client`, `device_admin`).
//!
//! Not every test file uses every helper.
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hx_agent::gateway::admin::{self, AdminPolicy};
use hx_agent::gateway::config::GatewayConfig;
use hx_agent::gateway::desktop::recording::RecordingLink;
use hx_agent::gateway::server::{Gateway, StartOptions};
use hx_agent::gateway::setup::SetupSettings;
use hx_agent::privd::daemon::Ctx;
use hx_agent::privd::testing::{Harness, request};
use hx_crypto::setup::{Password, SetupAuth, SetupConnectOptions, SetupSession, connect_setup};
use hx_crypto::{
    IdentityKey, ManualClock, PairClientOptions, PairingCredential, PairingToken, Pin, PublicKey,
    pair_device,
};
use hx_ipc::admin::pb as apb;
use hx_ipc::privd::pb::{self, Role, request::Command, response::Result as R};
use hx_proto::pb as wire;
use hx_proto::version::ProtocolVersion;
use hx_transport::{Connection, Target, TransportPreference};
use rustls::pki_types::ServerName;

use super::{AdminClient, CHEAP, PIN, new_key, within};

pub const PASSWORD: &str = "Correct-Horse-Battery-9";

/// A gateway over a real privd, with a window opened the way the installer does it.
pub struct SetupEnv {
    pub h: Harness,
    pub gw: Option<Gateway>,
    pub dir: tempfile::TempDir,
    pub clock: Arc<ManualClock>,
    pub server_key: Arc<IdentityKey>,
    pub admin_path: PathBuf,
    /// The app's device key.
    pub app: Arc<IdentityKey>,
    pub link: Arc<RecordingLink>,
    /// The transport the setup client uses.
    pub pref: TransportPreference,
}

fn uid() -> u32 {
    rustix::process::getuid().as_raw()
}

pub fn options() -> wire::SetupOptions {
    wire::SetupOptions {
        distro: wire::SetupDistro::Ubuntu2404 as i32,
        preset: wire::SetupPreset::Basic as i32,
        username: "alice".into(),
        ..Default::default()
    }
}

impl SetupEnv {
    pub async fn start() -> Self {
        capture_logs();
        let h = Harness::start(uid());
        let dir = tempfile::tempdir().expect("tempdir");
        let state = dir.path().join("state");
        std::fs::create_dir(&state).unwrap();
        std::fs::set_permissions(&state, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .unwrap();
        let admin_path = dir.path().join("admin.sock");
        let mut env = Self {
            h,
            gw: None,
            dir,
            clock: Arc::new(ManualClock::new()),
            server_key: new_key(),
            admin_path,
            app: new_key(),
            link: Arc::new(RecordingLink::default()),
            pref: TransportPreference::Quic,
        };
        env.start_gateway().await;
        env
    }

    /// (Re)starts the gateway over the same state directory, identity and privd.
    pub async fn start_gateway(&mut self) {
        let state = self.dir.path().join("state");
        let mut config = GatewayConfig::with_listen("127.0.0.1:0".parse().unwrap(), state);
        config.privd_socket = self.h.socket.clone();
        config.argon2_min_memory_kib = 32;
        config.admin_socket = self.admin_path.clone();
        // After a stop, the previous gateway's tasks release the registry lock as they end.
        for attempt in 0..100 {
            let mut opts =
                StartOptions::new(config.clone(), self.server_key.clone(), self.link.clone());
            opts.admin_listener = Some(admin::bind(&self.admin_path).expect("admin socket"));
            opts.admin_policy = AdminPolicy::OnlyUid(uid());
            opts.clock = self.clock.clone();
            let mut s = SetupSettings::new("main");
            s.params = CHEAP;
            s.finish_retry_wait = Duration::from_millis(20);
            opts.setup = Some(s);
            opts.server_mgmt = Some(hx_agent::gateway::server_mgmt::ServerMgmtSettings {
                desktop_id: "main".into(),
                params: CHEAP,
            });
            match Gateway::start(opts).await {
                Ok(gw) => {
                    self.gw = Some(gw);
                    return;
                }
                Err(hx_agent::gateway::server::GatewayError::Registry(
                    hx_crypto::Error::Locked,
                )) if attempt < 99 => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(e) => panic!("gateway: {e}"),
            }
        }
    }

    /// Stops the gateway (a crash, as far as privd can tell: its connections just close).
    pub async fn stop_gateway(&mut self) {
        if let Some(gw) = self.gw.take() {
            gw.shutdown().await;
        }
    }

    pub fn gw(&self) -> &Gateway {
        self.gw.as_ref().expect("gateway is running")
    }

    pub fn server_public(&self) -> PublicKey {
        self.server_key.public()
    }

    pub fn target(&self, pref: TransportPreference) -> Target {
        let addr = if pref == TransportPreference::WebSocket {
            self.gw().websocket_addr().expect("ws")
        } else {
            self.gw().quic_addr().expect("quic")
        };
        Target {
            addr,
            server_name: ServerName::try_from("hx.invalid").expect("name"),
        }
    }

    pub async fn admin(&self) -> AdminClient {
        AdminClient::connect(&self.admin_path).await.expect("admin")
    }

    /// privd's Admin, in process (the installer calls privd as Admin).
    pub async fn privd_admin(&self, command: Command) -> pb::Response {
        self.h
            .daemon
            .handle(request(1, command), Ctx::new(Role::Admin))
            .await
    }

    /// What the installer does: `BeginSetup` in privd, then the gateway's `SetupWindow`.
    pub async fn open_window(&self, secs: u32) {
        let r = self
            .privd_admin(Command::BeginSetup(pb::BeginSetupRequest {
                expires_in_s: secs,
            }))
            .await;
        assert!(matches!(r.result, Some(R::BeginSetup(_))), "{r:?}");
        let mut a = self.admin().await;
        a.call(
            apb::request::Command::SetupWindow(apb::SetupWindowRequest {
                action: apb::SetupWindowAction::Open as i32,
                expires_in_s: secs,
            }),
            None,
        )
        .await
        .expect("SetupWindow");
    }

    /// privd `READY` without a setup (BeginSetup, then Admin `FinishSetup` with `force`), for
    /// the tests that are about devices, not about setup.
    pub async fn make_ready(&self) {
        let r = self
            .privd_admin(Command::BeginSetup(pb::BeginSetupRequest {
                expires_in_s: 0,
            }))
            .await;
        assert!(matches!(r.result, Some(R::BeginSetup(_))), "{r:?}");
        let r = self
            .privd_admin(Command::FinishSetup(pb::FinishSetupRequest {
                force: Some(true),
            }))
            .await;
        assert!(matches!(r.result, Some(R::FinishSetup(_))), "{r:?}");
    }

    /// Sets the shared PIN and the password verifier directly (privd's `PepperEnrol`, then the
    /// store), the way the SSH path leaves them. Needs privd to allow class A.
    pub async fn set_verifiers(&self) {
        for (purpose, secret) in [
            (pb::LockoutPurpose::Pin, PIN),
            (pb::LockoutPurpose::Password, PASSWORD),
        ] {
            let record = hx_agent::gateway::verifier::enrol(
                self.gw().privd(),
                purpose,
                secret.as_bytes(),
                CHEAP,
            )
            .await
            .expect("enrol");
            match purpose {
                pb::LockoutPurpose::Pin => self.gw().verifiers().set_pin(None, record).unwrap(),
                _ => self.gw().verifiers().set_password(record).unwrap(),
            }
        }
    }

    /// Pairs `device` with a fresh token from the authenticator (an ordinary, non-setup device).
    pub async fn pair_plain(&self, device: &Arc<IdentityKey>, name: &str) {
        let token = self
            .gw()
            .authenticator()
            .pairing()
            .issue_token()
            .expect("token");
        let cred = PairingCredential::parse(&token.to_text()).expect("parse");
        self.pair_with(device, name, &cred).await;
    }

    /// The gateway clock's wall time.
    pub fn unix_now(&self) -> u64 {
        hx_crypto::Clock::unix_secs(&*self.clock)
    }

    pub async fn status(&self) -> apb::StatusResult {
        let mut a = self.admin().await;
        match a
            .call(apb::request::Command::Status(apb::StatusRequest {}), None)
            .await
            .expect("status")
        {
            apb::response::Result::Status(s) => s,
            other => panic!("{other:?}"),
        }
    }

    /// privd's phase, as the gateway's own admission sees it.
    pub async fn phase(&self) -> pb::Phase {
        match self
            .privd_admin(Command::GetHostInfo(pb::GetHostInfoRequest {}))
            .await
            .result
        {
            Some(R::GetHostInfo(i)) => pb::Phase::try_from(i.phase).unwrap(),
            other => panic!("{other:?}"),
        }
    }

    /// Installs an installer token through the admin socket (a secret frame, as the installer
    /// does) and returns its text.
    pub async fn install_token(&self) -> PairingCredential {
        let token = PairingToken::generate().expect("token");
        let text = token.to_text();
        let mut a = self.admin().await;
        let r = a
            .call(
                apb::request::Command::CreatePairingToken(apb::CreatePairingTokenRequest {
                    expires_in_s: 900,
                }),
                Some(text.as_bytes()),
            )
            .await
            .expect("CreatePairingToken");
        assert!(
            matches!(r, apb::response::Result::CreatePairingToken(_)),
            "{r:?}"
        );
        PairingCredential::parse(&text).expect("parse")
    }

    /// Pairs `device` with `cred`; returns the confirmed server version.
    pub async fn pair_with(
        &self,
        device: &Arc<IdentityKey>,
        name: &str,
        cred: &PairingCredential,
    ) -> ProtocolVersion {
        let paired = within(pair_device(
            &self.target(TransportPreference::Quic),
            device,
            cred,
            &PairClientOptions {
                preference: TransportPreference::Quic,
                device_name: name.into(),
                ..Default::default()
            },
        ))
        .await
        .expect("pairing");
        assert_eq!(paired.server_key, self.server_public());
        let v = paired.server_version();
        paired.finish().await;
        v
    }

    /// The one-liner's pairing: an installer token while the window is open, and the app.
    pub async fn pair_app(&self) -> ProtocolVersion {
        let cred = self.install_token().await;
        self.pair_with(&self.app, "app", &cred).await
    }

    pub fn setup_opts(
        &self,
        version: ProtocolVersion,
        pref: TransportPreference,
    ) -> SetupConnectOptions {
        SetupConnectOptions {
            confirmed_server_version: Some(version),
            preference: pref,
            device_name: "app".into(),
            ..Default::default()
        }
    }

    /// Connects `device` for setup.
    pub async fn connect_setup_as(
        &self,
        device: &Arc<IdentityKey>,
        version: ProtocolVersion,
    ) -> hx_crypto::Result<SetupAuth> {
        within(connect_setup(
            &self.target(self.pref),
            device,
            self.server_public(),
            &self.setup_opts(version, self.pref),
        ))
        .await
    }

    /// Connects the app for setup and expects a key-only session (no PIN exists yet).
    pub async fn key_only(&self, version: ProtocolVersion) -> SetupSession {
        match self
            .connect_setup_as(&self.app, version)
            .await
            .expect("connect_setup")
        {
            SetupAuth::Ready(s) => s,
            SetupAuth::NeedsPin(_) => panic!("expected KeyOnly"),
        }
    }

    /// Connects the app for setup, proves `PIN`, and returns the session.
    pub async fn with_pin(&self, version: ProtocolVersion) -> SetupSession {
        let auth = match self.connect_setup_as(&self.app, version).await {
            Ok(a) => a,
            Err(e) => {
                let why: Vec<String> = captured_logs()
                    .lines()
                    .filter(|l| l.contains("admission"))
                    .map(str::to_owned)
                    .collect();
                panic!("connect_setup: {e:?} {why:?}");
            }
        };
        match auth {
            SetupAuth::NeedsPin(mut a) => {
                within(a.submit_pin(&Pin::new(PIN).unwrap()))
                    .await
                    .expect("pin");
                within(async { a.into_session() }).await.expect("session")
            }
            SetupAuth::Ready(_) => panic!("expected NeedsPin"),
        }
    }

    /// A normal PIN login of `device`.
    pub async fn login(
        &self,
        device: &Arc<IdentityKey>,
        pin: &str,
    ) -> hx_crypto::Result<Connection> {
        within(hx_crypto::connect_with_pin(
            &self.target(TransportPreference::Quic),
            device,
            self.server_public(),
            &Pin::new(pin).unwrap(),
            &hx_crypto::SessionOptions {
                preference: TransportPreference::Quic,
                device_name: "app".into(),
                capabilities: hx_proto::version::capabilities(
                    &[hx_proto::VideoCodec::H264],
                    hx_proto::version::Features::defined_up_to(hx_proto::version::PROTOCOL_MINOR)
                        .without(hx_proto::version::Features::SETUP),
                ),
                ..Default::default()
            },
        ))
        .await
    }

    /// Makes every command inside the build take `ms` (so a job can be observed mid-flight).
    pub fn slow_build(&self, ms: u64) {
        self.h.incus.with(|s| {
            s.exec_rules.push(hx_agent::privd::testing::ExecRule {
                needle: String::new(),
                exit: 0,
                stdout: String::new(),
                delay: Some(Duration::from_millis(ms)),
            });
        });
    }

    /// Makes the build hang until the instance is stopped (cancel and restart tests).
    pub fn hang_build(&self) {
        self.h.incus.with(|s| {
            s.exec_rules.push(hx_agent::privd::testing::ExecRule {
                needle: String::new(),
                exit: 0,
                stdout: String::new(),
                delay: None,
            });
        });
    }

    /// Makes `chpasswd` (the build's last step) fail.
    pub fn fail_build(&self) {
        self.h.incus.with(|s| {
            s.exec_rules.push(hx_agent::privd::testing::ExecRule {
                needle: "chpasswd".into(),
                exit: 1,
                stdout: String::new(),
                delay: None,
            });
        });
    }

    pub fn clear_build_rules(&self) {
        // Only the rule the test pushed last (the fake's own defaults stay).
        self.h.incus.with(|s| {
            s.exec_rules.pop();
        });
    }

    /// Waits until the fake Incus has the instance and executes inside it.
    pub async fn wait_building(&self) {
        for _ in 0..400 {
            if self
                .h
                .incus
                .with(|s| s.execs.len() > 1 && s.instances.contains_key("hx-main"))
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("the build never started");
    }
}

/// Reads setup events until a `Result`; returns it with the stages seen.
pub async fn until_result(
    s: &mut SetupSession,
) -> (
    wire::SetupResult,
    Vec<i32>,
    Option<hx_transport::error::CloseInfo>,
) {
    use hx_crypto::setup::SetupEvent;
    let mut stages = Vec::new();
    let mut result = None;
    loop {
        let ev = match tokio::time::timeout(super::WAIT, s.next_event()).await {
            Ok(r) => r.expect("event"),
            Err(_) => panic!("no event in time; logs:\n{}", captured_logs()),
        };
        match ev {
            SetupEvent::Progress(p) => stages.push(p.stage),
            SetupEvent::Result(r) => result = Some(r),
            SetupEvent::State(_) => {}
            SetupEvent::Closed(c) => {
                return (result.expect("a result before the close"), stages, Some(c));
            }
        }
        // A result that is not final (the connection stays open) is returned at once.
        if let Some(r) = &result
            && !r.finished
        {
            return (result.unwrap(), stages, None);
        }
    }
}

pub fn password() -> Password {
    Password::new(PASSWORD).unwrap()
}

pub fn pin() -> Pin {
    Pin::new(PIN).unwrap()
}

/// Everything gatewayd logged (DEBUG and up) in this test binary, for the "no secret in any
/// log line" checks. The subscriber is global, installed once.
pub fn captured_logs() -> String {
    String::from_utf8_lossy(&LOG.lock().unwrap_or_else(|p| p.into_inner())).into_owned()
}

static LOG: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());

#[derive(Clone, Copy)]
struct LogWriter;

impl std::io::Write for LogWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        LOG.lock()
            .unwrap_or_else(|p| p.into_inner())
            .extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogWriter {
    type Writer = LogWriter;
    fn make_writer(&'a self) -> LogWriter {
        LogWriter
    }
}

/// Installs the capturing subscriber (once per process).
pub fn capture_logs() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = tracing::subscriber::set_global_default(
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_ansi(false)
                .with_writer(LogWriter)
                .finish(),
        );
    });
}
