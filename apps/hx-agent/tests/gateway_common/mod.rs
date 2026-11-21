//! Shared test harness for the gateway tests: an in-process gateway over a fake privd, real
//! clients (hx-crypto + hx-transport), a raw minor-0 client and an admin-socket client.
//!
//! Not every test file uses every helper.
#![allow(dead_code)]

pub mod fake_privd;

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hx_agent::gateway::admin::{self, AdminPolicy};
use hx_agent::gateway::config::GatewayConfig;
use hx_agent::gateway::desktop::recording::RecordingLink;
use hx_agent::gateway::server::{Gateway, StartOptions};
use hx_agent::gateway::verifier;
use hx_crypto::{
    DeviceId, IdentityKey, ManualClock, PairClientOptions, PairingCredential, Pin, PinParams,
    PublicKey, SessionOptions, connect_session, pair_device, tls,
};
use hx_ipc::admin::{self as ipc_admin, Incoming, pb as apb};
use hx_ipc::frame::Decoder;
use hx_ipc::privd::{self, PrivdPolicy, Side};
use hx_proto::VideoCodec;
use hx_proto::pb::{ControlMessage, control_message::Message as Ctl};
use hx_proto::version::{Features, PROTOCOL_MINOR, capabilities};
use hx_transport::{Connection, Target, TransportPreference};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

pub use fake_privd::FakePrivd;

pub const WAIT: Duration = Duration::from_secs(20);
pub const PIN: &str = "482913";
/// Cheap Argon2id parameters so that tests are fast; the production floor is a config value.
pub const CHEAP: PinParams = PinParams {
    memory_kib: 64,
    iterations: 1,
    parallelism: 1,
};

pub async fn within<T>(f: impl Future<Output = T>) -> T {
    tokio::time::timeout(WAIT, f).await.expect("timed out")
}

/// Polls `f` until it returns true (a few seconds at most).
pub async fn eventually<F: Future<Output = bool>>(mut f: impl FnMut() -> F) -> bool {
    for _ in 0..200 {
        if f().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    false
}

pub fn new_key() -> Arc<IdentityKey> {
    Arc::new(IdentityKey::generate().expect("key"))
}

pub fn my_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

/// What a test environment is made of.
pub struct Env {
    pub dir: tempfile::TempDir,
    pub privd: FakePrivd,
    pub gw: Gateway,
    pub clock: Arc<ManualClock>,
    pub link: Arc<RecordingLink>,
    pub server_key: Arc<IdentityKey>,
    pub admin_path: PathBuf,
}

pub struct EnvOptions {
    pub takeover_deny: bool,
    pub admin_policy: AdminPolicy,
    pub manage_idle_s: u64,
}

impl Default for EnvOptions {
    fn default() -> Self {
        Self {
            takeover_deny: false,
            admin_policy: AdminPolicy::OnlyUid(my_uid()),
            manage_idle_s: 300,
        }
    }
}

impl Env {
    pub async fn start() -> Self {
        Self::start_with(EnvOptions::default()).await
    }

    pub async fn start_with(o: EnvOptions) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = dir.path().join("state");
        std::fs::create_dir(&state).unwrap();
        std::fs::set_permissions(&state, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .unwrap();
        let privd = FakePrivd::start(dir.path());
        let mut config = GatewayConfig::with_listen("127.0.0.1:0".parse().unwrap(), state);
        config.privd_socket = privd.path.clone();
        config.argon2_min_memory_kib = 8;
        config.manage_idle_s = o.manage_idle_s;
        if o.takeover_deny {
            config.takeover = hx_agent::gateway::takeover::TakeoverPolicy::Deny;
        }
        let admin_path = dir.path().join("admin.sock");
        config.admin_socket = admin_path.clone();
        let server_key = new_key();
        let clock = Arc::new(ManualClock::new());
        let link = Arc::new(RecordingLink::default());
        let mut opts = StartOptions::new(config, server_key.clone(), link.clone());
        opts.admin_listener = Some(admin::bind(&admin_path).expect("admin socket"));
        opts.admin_policy = o.admin_policy;
        opts.clock = clock.clone();
        let gw = Gateway::start(opts).await.expect("gateway");
        Self {
            dir,
            privd,
            gw,
            clock,
            link,
            server_key,
            admin_path,
        }
    }

    pub fn server_public(&self) -> PublicKey {
        self.server_key.public()
    }

    pub fn target(&self, pref: TransportPreference) -> Target {
        let addr = if pref == TransportPreference::WebSocket {
            self.gw.websocket_addr().expect("ws")
        } else {
            self.gw.quic_addr().expect("quic")
        };
        Target {
            addr,
            server_name: ServerName::try_from("hx.invalid").expect("name"),
        }
    }

    /// Pairs `device` using a fresh token from the authenticator.
    pub async fn pair(&self, device: &Arc<IdentityKey>, name: &str) {
        self.pair_with(device, name, TransportPreference::Quic).await
    }

    pub async fn pair_with(&self, device: &Arc<IdentityKey>, name: &str, pref: TransportPreference) {
        let token = self.gw.authenticator().pairing().issue_token().expect("token");
        let cred = PairingCredential::parse(&token.to_text()).expect("parse");
        let paired = within(pair_device(
            &self.target(pref),
            device,
            &cred,
            &PairClientOptions {
                preference: pref,
                device_name: name.into(),
                ..Default::default()
            },
        ))
        .await
        .expect("pairing");
        assert_eq!(paired.server_key, self.server_public());
        paired.finish().await;
    }

    /// Sets the shared PIN through privd's `PepperEnrol` (the gateway never sees the pepper).
    pub async fn set_pin(&self, pin: &str) {
        let record = verifier::enrol(
            self.gw.privd(),
            hx_ipc::privd::pb::LockoutPurpose::Pin,
            pin.as_bytes(),
            CHEAP,
        )
        .await
        .expect("enrol");
        self.gw.verifiers().set_pin(None, record).expect("store");
    }

    pub fn session_opts(&self, pref: TransportPreference, name: &str) -> SessionOptions {
        SessionOptions {
            preference: pref,
            device_name: name.into(),
            capabilities: capabilities(
                &[VideoCodec::H264],
                Features::defined_up_to(PROTOCOL_MINOR),
            ),
            ..Default::default()
        }
    }

    /// Connects `device` and submits `pin`: the authorized connection.
    pub async fn login(&self, device: &Arc<IdentityKey>, name: &str, pin: &str) -> Connection {
        self.login_with(device, name, pin, TransportPreference::Quic).await
    }

    pub async fn login_with(
        &self,
        device: &Arc<IdentityKey>,
        name: &str,
        pin: &str,
        pref: TransportPreference,
    ) -> Connection {
        within(hx_crypto::connect_with_pin(
            &self.target(pref),
            device,
            self.server_public(),
            &Pin::new(pin).unwrap(),
            &self.session_opts(pref, name),
        ))
        .await
        .expect("login")
    }

    /// Connects and returns the connection waiting for the PIN.
    pub async fn connect_unauth(
        &self,
        device: &Arc<IdentityKey>,
        name: &str,
    ) -> hx_crypto::AwaitingPin {
        within(connect_session(
            &self.target(TransportPreference::Quic),
            device,
            self.server_public(),
            &self.session_opts(TransportPreference::Quic, name),
        ))
        .await
        .expect("connect")
    }

    pub fn id_of(device: &Arc<IdentityKey>) -> DeviceId {
        device.public().device_id()
    }
}

/// A `ViewConfig` that is valid for a client that offers H.264 and nothing optional.
pub fn view_config() -> ControlMessage {
    ControlMessage::new(Ctl::ViewConfig(hx_proto::pb::ViewConfig {
        codec: VideoCodec::H264 as i32,
        ..Default::default()
    }))
}

pub fn ctl(m: Ctl) -> ControlMessage {
    ControlMessage::new(m)
}

/// Receives control messages until one matches `pick`, within the global wait.
pub async fn recv_until<T>(
    conn: &Connection,
    mut pick: impl FnMut(&Ctl) -> Option<T>,
) -> T {
    within(async {
        loop {
            let m = conn.recv_control().await.expect("control message");
            if let Some(v) = m.message.as_ref().and_then(&mut pick) {
                return v;
            }
        }
    })
    .await
}

// ------------------------------------------------------------------ admin client

/// A client of the admin socket (tests only).
pub struct AdminClient {
    stream: UnixStream,
    decoder: Decoder<PrivdPolicy>,
    next_id: u64,
}

impl AdminClient {
    pub async fn connect(path: &std::path::Path) -> Result<Self, String> {
        let stream = UnixStream::connect(path).await.map_err(|e| e.to_string())?;
        let mut c = Self {
            stream,
            decoder: Decoder::new(PrivdPolicy::new(Side::Client)),
            next_id: 1,
        };
        let hello = apb::Frame {
            frame: Some(apb::frame::Frame::Hello(hx_ipc::privd::pb::Hello {
                major: 1,
                minor: 0,
                software: "test".into(),
            })),
        };
        c.write(&hello).await?;
        match c.read().await? {
            Incoming::Message(apb::Frame {
                frame: Some(apb::frame::Frame::HelloAck(_)),
            }) => Ok(c),
            other => Err(format!("unexpected {other:?}")),
        }
    }

    async fn write(&mut self, f: &apb::Frame) -> Result<(), String> {
        let bytes = ipc_admin::encode_message(f, Side::Server).map_err(|e| e.to_string())?;
        self.stream.write_all(&bytes).await.map_err(|e| e.to_string())
    }

    async fn read(&mut self) -> Result<Incoming, String> {
        let mut buf = [0u8; 4096];
        loop {
            let n = tokio::time::timeout(WAIT, self.stream.read(&mut buf))
                .await
                .map_err(|_| "timed out".to_string())?
                .map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("closed".into());
            }
            let mut data = &buf[..n];
            while !data.is_empty() {
                let (used, frame) = self.decoder.feed(data).map_err(|e| e.to_string())?;
                data = &data[used..];
                if let Some(raw) = frame {
                    return ipc_admin::decode(raw, Side::Client).map_err(|e| e.to_string());
                }
            }
        }
    }

    /// Sends a command (with an optional secret in a kind-2 frame) and returns the result.
    pub async fn call(
        &mut self,
        command: apb::request::Command,
        secret: Option<&[u8]>,
    ) -> Result<apb::response::Result, String> {
        let id = self.next_id;
        self.next_id += 1;
        let slots = secret
            .map(|s| {
                vec![apb::AdminSecretSlot {
                    slot: 0,
                    kind: apb::AdminSecretKind::PairingToken as i32,
                    length: s.len() as u32,
                }]
            })
            .unwrap_or_default();
        let req = apb::Frame {
            frame: Some(apb::frame::Frame::Request(apb::Request {
                request_id: id,
                deadline_ms: 0,
                secret_slots: slots,
                command: Some(command),
            })),
        };
        self.write(&req).await?;
        if let Some(s) = secret {
            let framed = privd::encode_secret(id, 0, s).map_err(|e| e.to_string())?;
            self.stream.write_all(&framed).await.map_err(|e| e.to_string())?;
        }
        match self.read().await? {
            Incoming::Message(apb::Frame {
                frame: Some(apb::frame::Frame::Response(r)),
            }) if r.request_id == id => r.result.ok_or_else(|| "empty response".into()),
            other => Err(format!("unexpected {other:?}")),
        }
    }
}

// ------------------------------------------------------------------ raw QUIC client (minor 0)

/// A bare-bones QUIC client that can say "protocol 1.0": hx-transport's own client always
/// announces the current minor, and the takeover fallback for a 1.0 peer must be tested.
pub struct RawClient {
    _endpoint: quinn::Endpoint,
    pub conn: quinn::Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    started: bool,
}

impl RawClient {
    pub async fn connect(addr: std::net::SocketAddr, device: &Arc<IdentityKey>, server: PublicKey) -> Self {
        let mut tls = (*tls::client_config_session(device, server).expect("tls")).clone();
        tls.alpn_protocols = vec![b"hx/1".to_vec()];
        let q = quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("quic tls");
        let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("endpoint");
        ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(q)));
        let conn = ep.connect(addr, "hx.invalid").expect("connect").await.expect("handshake");
        let (send, recv) = conn.open_bi().await.expect("control stream");
        Self {
            _endpoint: ep,
            conn,
            send,
            recv,
            started: false,
        }
    }

    pub async fn send_ctl(&mut self, m: &ControlMessage) {
        if !self.started {
            self.send.write_all(&[0x01]).await.unwrap();
            self.started = true;
        }
        let body = hx_proto::message::encode_framed(m).expect("encode");
        self.send.write_all(&body).await.unwrap();
    }

    pub async fn recv_ctl(&mut self) -> Option<ControlMessage> {
        let mut prefix = [0u8; 4];
        self.recv.read_exact(&mut prefix).await.ok()?;
        let len = hx_proto::message::parse_frame_len(prefix, 65536).ok()?;
        let mut body = vec![0u8; len];
        self.recv.read_exact(&mut body).await.ok()?;
        hx_proto::message::decode::<ControlMessage>(&body).ok()
    }

    /// Announces protocol 1.0, with the 1.0 feature set, as a session.
    pub async fn hello_v10(&mut self) -> hx_proto::pb::HelloAck {
        let hello = ControlMessage::new(Ctl::Hello(hx_proto::pb::Hello {
            version: Some(hx_proto::pb::Version { major: 1, minor: 0 }),
            capabilities: Some(capabilities(
                &[VideoCodec::H264],
                Features::defined_up_to(0),
            )),
            intent: hx_proto::pb::Intent::Session as i32,
            software: "raw 1.0 client".into(),
            device_name: "old phone".into(),
        }));
        self.send_ctl(&hello).await;
        match self.recv_ctl().await.and_then(|m| m.message) {
            Some(Ctl::HelloAck(a)) => a,
            other => panic!("expected HelloAck, got {other:?}"),
        }
    }

    /// Submits the PIN and returns the auth status.
    pub async fn submit_pin(&mut self, pin: &str) -> hx_crypto::wire::AuthStatus {
        use hx_crypto::wire::{AuthMessage, AuthStatus, auth_message::Body};
        let m = AuthMessage::new(Body::Pin(hx_crypto::wire::PinAttempt {
            pin: pin.as_bytes().to_vec(),
        }))
        .into_control()
        .unwrap();
        self.send_ctl(&m).await;
        let reply = self.recv_ctl().await.expect("auth result");
        let Some(Body::Result(r)) = AuthMessage::from_control(&reply).unwrap().body else {
            panic!("not a result")
        };
        AuthStatus::try_from(r.status).unwrap()
    }
}
