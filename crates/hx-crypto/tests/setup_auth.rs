//! The authenticator's `INTENT_SETUP` path (protocol 1.3, design D2): the admission matrix,
//! the re-checks right before authorization, the PIN path that reuses the §11.4 exchange
//! unchanged, `PairedWith`, and a 1.2 client.

use std::{
    collections::VecDeque,
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use hx_crypto::{
    Authenticator, AuthenticatorConfig, BoxFuture, DeviceId, DeviceRegistry, Error, IdentityKey,
    ManualClock, MemoryRegistry, Outcome, PairClientOptions, PairedWith, PairingCredential, Pin,
    PinVerdict, PinVerifier, RevokeReason, SetupAdmission, SetupGate, pair_device, tls,
    wire::{AuthMessage, AuthResult, AuthStatus, PinAttempt, auth_message::Body},
};
use hx_proto::{
    channel::CloseCode,
    message,
    pb::{self, ControlMessage, Intent, RefuseReason, control_message::Message as Ctl},
    version::{Features, capabilities},
};
use hx_transport::{
    Client, ClientHello, ClientOptions, Connection, Server, ServerOptions, Target,
    TransportPreference,
};
use rustls::pki_types::ServerName;
use tokio::{sync::mpsc, task::JoinHandle};
use zeroize::Zeroizing;

const PREF: TransportPreference = TransportPreference::Quic;
const WAIT: Duration = Duration::from_secs(20);
const NOT_AUTHORIZED: &str = "not authorized";

async fn within<T>(f: impl Future<Output = T>) -> T {
    tokio::time::timeout(WAIT, f).await.expect("timed out")
}

fn new_key() -> Arc<IdentityKey> {
    Arc::new(IdentityKey::generate().expect("key"))
}

fn pin(s: &str) -> Pin {
    Pin::new(s).expect("pin")
}

// ------------------------------------------------------------------ scripted gate

/// Answers `admit` from a script, then `fallback`; records every call.
struct Gate {
    script: Mutex<VecDeque<SetupAdmission>>,
    fallback: Mutex<SetupAdmission>,
    delay: Duration,
    calls: AtomicUsize,
    asked: Mutex<Vec<DeviceId>>,
}

impl Gate {
    fn new(fallback: SetupAdmission) -> Arc<Self> {
        Self::scripted(&[], fallback, Duration::ZERO)
    }

    fn scripted(script: &[SetupAdmission], fallback: SetupAdmission, delay: Duration) -> Arc<Self> {
        Arc::new(Self {
            script: Mutex::new(script.iter().copied().collect()),
            fallback: Mutex::new(fallback),
            delay,
            calls: AtomicUsize::new(0),
            asked: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl SetupGate for Gate {
    fn admit<'a>(&'a self, device: &'a DeviceId) -> BoxFuture<'a, SetupAdmission> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.asked.lock().expect("lock").push(*device);
            tokio::time::sleep(self.delay).await;
            let next = self.script.lock().expect("lock").pop_front();
            next.unwrap_or(*self.fallback.lock().expect("lock"))
        })
    }
}

// ------------------------------------------------------------------ scripted PIN verifier

struct Verifier {
    script: Mutex<VecDeque<PinVerdict>>,
    fallback: PinVerdict,
    delay: Duration,
    has_pin: bool,
    calls: AtomicUsize,
    /// What `failed_pins` was when the verifier was asked (counted before the check).
    counted_when_asked: Mutex<Vec<u32>>,
    registry: Arc<MemoryRegistry>,
}

impl Verifier {
    fn new(env_registry: &Arc<MemoryRegistry>, fallback: PinVerdict, delay: Duration) -> Arc<Self> {
        Arc::new(Self {
            script: Mutex::new(VecDeque::new()),
            fallback,
            delay,
            has_pin: true,
            calls: AtomicUsize::new(0),
            counted_when_asked: Mutex::new(Vec::new()),
            registry: env_registry.clone(),
        })
    }

    fn without_pin(env_registry: &Arc<MemoryRegistry>) -> Arc<Self> {
        let mut v = Arc::try_unwrap(Self::new(env_registry, PinVerdict::Wrong, Duration::ZERO))
            .unwrap_or_else(|_| unreachable!());
        v.has_pin = false;
        Arc::new(v)
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl PinVerifier for Verifier {
    fn has_pin(&self, _device: &DeviceId) -> bool {
        self.has_pin
    }

    fn verify<'a>(
        &'a self,
        device: &'a DeviceId,
        _pin: Zeroizing<Vec<u8>>,
    ) -> BoxFuture<'a, PinVerdict> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let failed = self
                .registry
                .get(device)
                .expect("reg")
                .expect("device")
                .failed_pins;
            self.counted_when_asked.lock().expect("lock").push(failed);
            tokio::time::sleep(self.delay).await;
            self.script
                .lock()
                .expect("lock")
                .pop_front()
                .unwrap_or(self.fallback)
        })
    }
}

// ------------------------------------------------------------------ environment

struct Env {
    auth: Authenticator,
    server: Arc<Server>,
    registry: Arc<MemoryRegistry>,
    clock: Arc<ManualClock>,
    server_key: Arc<IdentityKey>,
    outcomes: mpsc::UnboundedReceiver<hx_crypto::Result<Outcome>>,
    device: Arc<IdentityKey>,
    _accept: JoinHandle<()>,
}

fn config() -> AuthenticatorConfig {
    AuthenticatorConfig {
        // What a gateway offers: every feature of 1.3 except SETUP.
        capabilities: capabilities(&[], Features::defined_up_to(3).without(Features::SETUP)),
        session_features: Features::defined_up_to(3).without(Features::SETUP),
        max_pin_messages: 10,
        ..Default::default()
    }
}

/// A server with one paired device. No gate and no PIN verifier are installed yet.
async fn env(config: AuthenticatorConfig) -> Env {
    let server_key = new_key();
    let registry = Arc::new(MemoryRegistry::new());
    let clock = Arc::new(ManualClock::new());
    let auth =
        Authenticator::with_clock(server_key.clone(), registry.clone(), config, clock.clone());
    let server = Arc::new(
        Server::bind(
            "127.0.0.1:0".parse().expect("addr"),
            tls::server_config(&server_key).expect("tls"),
            ServerOptions::default(),
        )
        .await
        .expect("bind"),
    );
    let (tx, outcomes) = mpsc::unbounded_channel();
    let (s2, a2) = (server.clone(), auth.clone());
    let accept = tokio::spawn(async move {
        while let Some(p) = s2.accept().await {
            let (a, tx) = (a2.clone(), tx.clone());
            tokio::spawn(async move {
                let _ = tx.send(a.authenticate(p).await);
            });
        }
    });
    let mut e = Env {
        auth,
        server,
        registry,
        clock,
        server_key,
        outcomes,
        device: new_key(),
        _accept: accept,
    };
    let device = e.device.clone();
    e.pair_with_token(&device).await;
    e
}

impl Env {
    fn target(&self) -> Target {
        Target {
            addr: self.server.quic_addr().expect("quic addr"),
            server_name: ServerName::try_from("hx.invalid").expect("name"),
        }
    }

    async fn next(&mut self) -> hx_crypto::Result<Outcome> {
        within(self.outcomes.recv()).await.expect("an outcome")
    }

    async fn pair_with_token(&mut self, device: &Arc<IdentityKey>) -> PairedWith {
        let token = self.auth.pairing().issue_token().expect("token");
        let cred = PairingCredential::parse(&token.to_text()).expect("parse");
        self.pair_with(device, &cred).await
    }

    async fn pair_with(
        &mut self,
        device: &Arc<IdentityKey>,
        cred: &PairingCredential,
    ) -> PairedWith {
        let paired = within(pair_device(
            &self.target(),
            device,
            cred,
            &PairClientOptions {
                preference: PREF,
                device_name: "laptop".into(),
                ..Default::default()
            },
        ))
        .await
        .expect("pairing succeeds");
        let Outcome::Paired {
            connection, with, ..
        } = self.next().await.expect("outcome")
        else {
            panic!("expected Paired");
        };
        paired.finish().await;
        connection.close(CloseCode::NoError, "done").await;
        with
    }

    fn id(&self) -> DeviceId {
        self.device.public().device_id()
    }

    fn failed(&self) -> u32 {
        self.registry
            .get(&self.id())
            .expect("reg")
            .expect("dev")
            .failed_pins
    }

    fn setup_hello(features: Features) -> ClientHello {
        ClientHello {
            capabilities: capabilities(&[], features),
            intent: Intent::Setup,
            software: "setup-test".into(),
            device_name: "laptop".into(),
        }
    }

    /// Connect with `INTENT_SETUP` as `device`.
    async fn connect_as(
        &self,
        device: &Arc<IdentityKey>,
        hello: &ClientHello,
    ) -> hx_transport::Result<Connection> {
        let client = Client::new(
            tls::client_config_session(device, self.server_key.public()).expect("tls"),
            ClientOptions {
                preference: PREF,
                ..Default::default()
            },
        );
        within(client.connect(&self.target(), hello)).await
    }

    async fn connect_setup(&self) -> hx_transport::Result<Connection> {
        self.connect_as(&self.device, &Self::setup_hello(Features::SETUP))
            .await
    }

    /// The refusal text and reason of a refused connect.
    async fn refused(&self, r: hx_transport::Result<Connection>) -> (RefuseReason, String) {
        match r {
            Err(hx_transport::Error::Refused {
                reason, message, ..
            }) => (reason, message),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// A raw QUIC peer that sends `Hello` with its own version and features, for clients the
    /// high-level API cannot imitate (an older minor). Returns the first reply.
    async fn raw_hello(
        &self,
        minor: u32,
        features: Features,
        intent: Intent,
    ) -> (RawPeer, ControlMessage) {
        let mut tls = (*tls::client_config_session(&self.device, self.server_key.public())
            .expect("tls"))
        .clone();
        tls.alpn_protocols = vec![hx_proto::version::ALPN.to_vec()];
        let q = quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("quic tls");
        let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().expect("addr")).expect("ep");
        ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(q)));
        let conn = ep
            .connect(self.target().addr, "hx.invalid")
            .expect("connect")
            .await
            .expect("handshake");
        let hello = ControlMessage::new(Ctl::Hello(pb::Hello {
            version: Some(pb::Version { major: 1, minor }),
            capabilities: Some(capabilities(&[], features)),
            intent: intent as i32,
            software: "raw".into(),
            device_name: "raw peer".into(),
        }));
        let body = message::encode(&hello).expect("encode");
        let (mut send, recv) = conn.open_bi().await.expect("control stream");
        send.write_all(&[0x01]).await.expect("channel");
        send.write_all(&(body.len() as u32).to_le_bytes())
            .await
            .expect("len");
        send.write_all(&body).await.expect("body");
        let mut peer = RawPeer {
            _ep: ep,
            conn,
            send,
            recv,
        };
        let first = peer.read().await;
        (peer, first)
    }
}

struct RawPeer {
    _ep: quinn::Endpoint,
    conn: quinn::Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl RawPeer {
    async fn read(&mut self) -> ControlMessage {
        let mut len = [0u8; 4];
        within(self.recv.read_exact(&mut len))
            .await
            .expect("reply length");
        let mut body = vec![0u8; u32::from_le_bytes(len) as usize];
        within(self.recv.read_exact(&mut body))
            .await
            .expect("reply body");
        message::decode(&body).expect("valid reply")
    }

    async fn write(&mut self, m: &ControlMessage) {
        let body = message::encode(m).expect("encode");
        self.send
            .write_all(&(body.len() as u32).to_le_bytes())
            .await
            .expect("len");
        self.send.write_all(&body).await.expect("body");
    }

    async fn closed_code(&self) -> CloseCode {
        match within(self.conn.closed()).await {
            quinn::ConnectionError::ApplicationClosed(ac) => {
                CloseCode::from_code(ac.error_code.into_inner())
            }
            other => panic!("unexpected close: {other}"),
        }
    }
}

fn pin_message(p: &str) -> ControlMessage {
    AuthMessage::new(Body::Pin(PinAttempt {
        pin: p.as_bytes().to_vec(),
    }))
    .into_control()
    .expect("encode")
}

fn auth_result(m: &ControlMessage) -> AuthResult {
    match AuthMessage::from_control(m).expect("auth message").body {
        Some(Body::Result(r)) => r,
        other => panic!("expected an auth result, got {other:?}"),
    }
}

async fn recv_result(c: &Connection) -> AuthResult {
    auth_result(&within(c.recv_control()).await.expect("control"))
}

async fn send_pin(c: &Connection, p: &str) -> AuthResult {
    c.send_control(&pin_message(p)).await.expect("send PIN");
    recv_result(c).await
}

fn status(r: &AuthResult) -> AuthStatus {
    AuthStatus::try_from(r.status).expect("status")
}

fn cancel_request() -> ControlMessage {
    ControlMessage::new(Ctl::Setup(pb::SetupMessage {
        request_id: 1,
        body: Some(pb::setup_message::Body::Cancel(pb::SetupCancel {})),
    }))
}

// ------------------------------------------------------------------ the admission matrix

#[tokio::test]
async fn unknown_and_revoked_devices_get_the_same_uniform_refusal() {
    let mut e = env(config()).await;
    let gate = Gate::new(SetupAdmission::KeyOnly);
    e.auth.set_setup_gate(gate.clone());
    e.auth.set_pin_verifier(Verifier::new(
        &e.registry,
        PinVerdict::Right,
        Duration::ZERO,
    ));

    // Unknown key.
    let stranger = new_key();
    let r = e
        .connect_as(&stranger, &Env::setup_hello(Features::SETUP))
        .await;
    let unknown = e.refused(r).await;
    assert!(matches!(
        e.next().await,
        Ok(Outcome::Refused(RefuseReason::Unauthorized))
    ));

    // Revoked key.
    e.auth
        .revoke(&e.id(), RevokeReason::User)
        .await
        .expect("revoke");
    let r = e.connect_setup().await;
    let revoked = e.refused(r).await;
    assert!(matches!(
        e.next().await,
        Ok(Outcome::Refused(RefuseReason::Unauthorized))
    ));

    assert_eq!(unknown, (RefuseReason::Unauthorized, NOT_AUTHORIZED.into()));
    assert_eq!(unknown, revoked, "the same text for both");
    assert_eq!(gate.calls(), 0, "the gate is never asked about them");
}

#[tokio::test]
async fn an_old_minor_or_a_missing_setup_feature_is_unauthorized_and_never_reaches_the_gate() {
    let mut e = env(config()).await;
    let gate = Gate::new(SetupAdmission::KeyOnly);
    e.auth.set_setup_gate(gate.clone());
    e.auth.set_pin_verifier(Verifier::new(
        &e.registry,
        PinVerdict::Right,
        Duration::ZERO,
    ));

    // The same refusal as for an unknown device, for each of:
    //  - client minor 2 (a 1.2 peer cannot know the intent) with the SETUP bit set,
    //  - client minor 3 without offering SETUP,
    //  - client minor 0.
    for (minor, features) in [
        (2, Features::SETUP),
        (3, Features::NONE),
        (3, Features::defined_up_to(2)),
        (0, Features::SETUP),
    ] {
        let (peer, first) = e.raw_hello(minor, features, Intent::Setup).await;
        let Some(Ctl::Refuse(r)) = first.message else {
            panic!("minor {minor}: expected Refuse, got {first:?}");
        };
        assert_eq!(r.reason, RefuseReason::Unauthorized as i32, "minor {minor}");
        assert_eq!(r.message, NOT_AUTHORIZED, "minor {minor}");
        assert_eq!(peer.closed_code().await, CloseCode::Unauthorized);
        assert!(matches!(
            e.next().await,
            Ok(Outcome::Refused(RefuseReason::Unauthorized))
        ));
    }
    // High-level client that does not offer SETUP.
    let r = e
        .connect_as(&e.device, &Env::setup_hello(Features::NONE))
        .await;
    assert_eq!(e.refused(r).await.0, RefuseReason::Unauthorized);
    assert!(matches!(
        e.next().await,
        Ok(Outcome::Refused(RefuseReason::Unauthorized))
    ));
    assert_eq!(gate.calls(), 0);
}

#[tokio::test]
async fn without_a_gate_setup_is_unauthorized() {
    let mut e = env(config()).await;
    e.auth.set_pin_verifier(Verifier::new(
        &e.registry,
        PinVerdict::Right,
        Duration::ZERO,
    ));
    let r = e.connect_setup().await;
    assert_eq!(
        e.refused(r).await,
        (RefuseReason::Unauthorized, NOT_AUTHORIZED.into())
    );
    assert!(matches!(
        e.next().await,
        Ok(Outcome::Refused(RefuseReason::Unauthorized))
    ));
}

#[tokio::test]
async fn a_closed_gate_refuses_setup_closed_with_close_code_10() {
    let mut e = env(config()).await;
    e.auth.set_setup_gate(Gate::new(SetupAdmission::Closed));
    let (peer, first) = e.raw_hello(3, Features::SETUP, Intent::Setup).await;
    let Some(Ctl::Refuse(r)) = first.message else {
        panic!("expected Refuse, got {first:?}");
    };
    assert_eq!(r.reason, RefuseReason::SetupClosed as i32);
    assert_eq!(peer.closed_code().await, CloseCode::SetupClosed);
    assert!(matches!(
        e.next().await,
        Ok(Outcome::Refused(RefuseReason::SetupClosed))
    ));
    // Through the client API too.
    let r = e.connect_setup().await;
    assert_eq!(e.refused(r).await.0, RefuseReason::SetupClosed);
    assert!(matches!(
        e.next().await,
        Ok(Outcome::Refused(RefuseReason::SetupClosed))
    ));
}

#[tokio::test]
async fn an_unavailable_or_hanging_gate_refuses_busy() {
    let mut e = env(AuthenticatorConfig {
        setup_gate_timeout: Duration::from_millis(300),
        ..config()
    })
    .await;
    e.auth
        .set_setup_gate(Gate::new(SetupAdmission::Unavailable));
    let r = e.connect_setup().await;
    assert_eq!(e.refused(r).await.0, RefuseReason::Busy);
    assert!(matches!(
        e.next().await,
        Ok(Outcome::Refused(RefuseReason::Busy))
    ));

    // A gate that never answers in time counts as unavailable.
    let slow = Gate::scripted(&[], SetupAdmission::KeyOnly, Duration::from_secs(30));
    e.auth.set_setup_gate(slow.clone());
    let started = std::time::Instant::now();
    let r = e.connect_setup().await;
    assert_eq!(e.refused(r).await.0, RefuseReason::Busy);
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(matches!(
        e.next().await,
        Ok(Outcome::Refused(RefuseReason::Busy))
    ));
    assert_eq!(slow.calls(), 1);
}

#[tokio::test]
async fn needs_pin_without_a_verifier_is_unauthorized() {
    let mut e = env(config()).await;
    e.auth.set_setup_gate(Gate::new(SetupAdmission::NeedsPin));
    // No verifier at all, and a verifier that has no PIN for the device.
    let r = e.connect_setup().await;
    assert_eq!(e.refused(r).await.0, RefuseReason::Unauthorized);
    assert!(matches!(
        e.next().await,
        Ok(Outcome::Refused(RefuseReason::Unauthorized))
    ));
    e.auth.set_pin_verifier(Verifier::without_pin(&e.registry));
    let r = e.connect_setup().await;
    assert_eq!(e.refused(r).await.0, RefuseReason::Unauthorized);
    assert!(matches!(
        e.next().await,
        Ok(Outcome::Refused(RefuseReason::Unauthorized))
    ));
}

// ------------------------------------------------------------------ KeyOnly

#[tokio::test]
async fn key_only_is_authorized_control_only_without_a_pin() {
    let mut e = env(config()).await;
    let gate = Gate::new(SetupAdmission::KeyOnly);
    e.auth.set_setup_gate(gate.clone());
    // No PIN verifier exists at all (the device has no PIN yet): it is not consulted.
    let c = e.connect_setup().await.expect("connects");
    let r = recv_result(&c).await;
    assert_eq!(status(&r), AuthStatus::Ok);
    let Outcome::Setup {
        connection,
        device,
        pin_verified,
    } = e.next().await.expect("outcome")
    else {
        panic!("expected Setup");
    };
    assert!(!pin_verified);
    assert_eq!(device.id, e.id());
    assert!(connection.is_control_only() && connection.is_authorized());
    assert_eq!(connection.enabled_features(), Features::SETUP);
    assert_eq!(c.negotiated().features, Features::SETUP);
    assert_eq!(connection.negotiated().version.minor, 3);
    // The gate was asked twice: before HelloAck and right before authorization.
    assert_eq!(gate.calls(), 2);
    assert_eq!(*gate.asked.lock().expect("lock"), vec![e.id(), e.id()]);

    // Setup messages flow; nothing else does.
    c.send_control(&cancel_request()).await.expect("send");
    assert_eq!(
        within(connection.recv_control()).await.expect("recv"),
        cancel_request()
    );
    assert!(matches!(
        connection
            .send_cursor(&pb::CursorEvent {
                event: Some(pb::cursor_event::Event::Position(
                    pb::CursorPosition::default()
                ))
            })
            .await,
        Err(hx_transport::Error::NotAuthorized)
    ));
}

#[tokio::test]
async fn a_key_only_connection_is_closed_when_its_device_is_revoked() {
    let mut e = env(config()).await;
    e.auth.set_setup_gate(Gate::new(SetupAdmission::KeyOnly));
    let c = e.connect_setup().await.expect("connects");
    let _ = recv_result(&c).await;
    let Outcome::Setup { connection, .. } = e.next().await.expect("outcome") else {
        panic!("expected Setup");
    };
    e.auth
        .revoke(&e.id(), RevokeReason::User)
        .await
        .expect("revoke");
    let info = within(connection.closed()).await;
    assert_eq!(info.code, CloseCode::Unauthorized);
    assert_eq!(within(c.closed()).await.code, CloseCode::Unauthorized);
}

// ------------------------------------------------------------------ NeedsPin

#[tokio::test]
async fn needs_pin_asks_for_the_pin_then_authorizes_control_only() {
    let mut e = env(config()).await;
    let gate = Gate::new(SetupAdmission::NeedsPin);
    e.auth.set_setup_gate(gate.clone());
    let v = Verifier::new(&e.registry, PinVerdict::Right, Duration::ZERO);
    e.auth.set_pin_verifier(v.clone());
    let c = e.connect_setup().await.expect("connects");
    let first = recv_result(&c).await;
    assert_eq!(status(&first), AuthStatus::PinRequired);
    assert_eq!(first.attempts_left, 5);
    assert_eq!(first.retry_after_ms, 0);
    // Not authorized before the PIN: a setup message is a protocol violation.
    assert_eq!(v.calls(), 0);
    let ok = send_pin(&c, "482913").await;
    assert_eq!(status(&ok), AuthStatus::Ok);
    let Outcome::Setup {
        connection,
        pin_verified,
        ..
    } = e.next().await.expect("outcome")
    else {
        panic!("expected Setup");
    };
    assert!(pin_verified);
    assert!(connection.is_control_only());
    assert_eq!(connection.enabled_features(), Features::SETUP);
    assert_eq!(gate.calls(), 2, "asked again right before authorization");
    assert_eq!(v.calls(), 1);
    assert_eq!(e.failed(), 0, "a right PIN clears the counter");
}

#[tokio::test]
async fn setup_before_the_pin_is_a_protocol_violation() {
    let mut e = env(config()).await;
    e.auth.set_setup_gate(Gate::new(SetupAdmission::NeedsPin));
    e.auth.set_pin_verifier(Verifier::new(
        &e.registry,
        PinVerdict::Right,
        Duration::ZERO,
    ));
    let c = e.connect_setup().await.expect("connects");
    assert_eq!(status(&recv_result(&c).await), AuthStatus::PinRequired);
    c.send_control(&cancel_request()).await.expect("sent");
    assert_eq!(within(c.closed()).await.code, CloseCode::ProtocolError);
    assert!(e.next().await.is_err(), "the exchange fails");
}

#[tokio::test]
async fn pin_rules_are_the_session_rules_counted_backoff_and_five_revoke() {
    let mut e = env(config()).await;
    e.auth.set_setup_gate(Gate::new(SetupAdmission::NeedsPin));
    let v = Verifier::new(&e.registry, PinVerdict::Wrong, Duration::ZERO);
    e.auth.set_pin_verifier(v.clone());
    let c = e.connect_setup().await.expect("connects");
    assert_eq!(status(&recv_result(&c).await), AuthStatus::PinRequired);

    let r = send_pin(&c, "000000").await;
    assert_eq!(status(&r), AuthStatus::WrongPin);
    assert_eq!((r.attempts_left, r.retry_after_ms), (4, 1000));
    // The attempt was counted before the verifier was asked.
    assert_eq!(*v.counted_when_asked.lock().expect("lock"), vec![1]);
    // Too soon: not verified, not counted.
    let r = send_pin(&c, "000000").await;
    assert_eq!(status(&r), AuthStatus::Backoff);
    assert_eq!((v.calls(), e.failed()), (1, 1));
    for (n, wait) in [(2u32, 2u64), (3, 4), (4, 8)] {
        e.clock.advance(Duration::from_secs(wait));
        let r = send_pin(&c, "000000").await;
        assert_eq!(status(&r), AuthStatus::WrongPin, "{n}");
        assert_eq!(r.attempts_left, 5 - n);
    }
    e.clock.advance(Duration::from_secs(60));
    let r = send_pin(&c, "000000").await;
    assert_eq!(status(&r), AuthStatus::Revoked);
    assert!(matches!(e.next().await, Err(Error::Revoked)));
    let rec = e.registry.get(&e.id()).expect("reg").expect("dev");
    assert_eq!(
        rec.revoked.expect("revoked").reason,
        RevokeReason::TooManyPinFailures
    );
    assert_eq!(v.calls(), 5);
}

#[tokio::test]
async fn a_malformed_pin_counts_as_wrong_without_reaching_the_verifier() {
    let e = env(config()).await;
    e.auth.set_setup_gate(Gate::new(SetupAdmission::NeedsPin));
    let v = Verifier::new(&e.registry, PinVerdict::Right, Duration::ZERO);
    e.auth.set_pin_verifier(v.clone());
    let c = e.connect_setup().await.expect("connects");
    assert_eq!(status(&recv_result(&c).await), AuthStatus::PinRequired);
    let r = send_pin(&c, "12ab").await;
    assert_eq!(status(&r), AuthStatus::WrongPin);
    assert_eq!((v.calls(), e.failed()), (0, 1));
}

#[tokio::test]
async fn an_unavailable_verifier_is_refunded_and_a_locked_one_ends_the_connection() {
    let mut e = env(config()).await;
    e.auth.set_setup_gate(Gate::new(SetupAdmission::NeedsPin));
    let v = Verifier::new(&e.registry, PinVerdict::Unavailable, Duration::ZERO);
    e.auth.set_pin_verifier(v.clone());
    let c = e.connect_setup().await.expect("connects");
    assert_eq!(status(&recv_result(&c).await), AuthStatus::PinRequired);
    let r = send_pin(&c, "482913").await;
    assert_eq!(status(&r), AuthStatus::Backoff);
    assert_eq!(e.failed(), 0, "refunded");
    drop(c);
    let _ = e.next().await;

    e.clock.advance(Duration::from_secs(10));
    e.auth.set_pin_verifier(Verifier::new(
        &e.registry,
        PinVerdict::Locked { retry_after: None },
        Duration::ZERO,
    ));
    let c = e.connect_setup().await.expect("connects");
    assert_eq!(status(&recv_result(&c).await), AuthStatus::PinRequired);
    let r = send_pin(&c, "482913").await;
    assert_eq!(status(&r), AuthStatus::NotAvailable);
    assert!(matches!(e.next().await, Err(Error::PinNotAvailable)));
    assert_eq!(e.failed(), 0);
}

#[tokio::test]
async fn too_many_messages_on_one_setup_connection_end_it() {
    let mut e = env(AuthenticatorConfig {
        max_pin_messages: 3,
        ..config()
    })
    .await;
    e.auth.set_setup_gate(Gate::new(SetupAdmission::NeedsPin));
    e.auth.set_pin_verifier(Verifier::new(
        &e.registry,
        PinVerdict::Wrong,
        Duration::ZERO,
    ));
    let c = e.connect_setup().await.expect("connects");
    assert_eq!(status(&recv_result(&c).await), AuthStatus::PinRequired);
    for _ in 0..3 {
        e.clock.advance(Duration::from_secs(60));
        let _ = send_pin(&c, "000000").await;
    }
    assert!(matches!(e.next().await, Err(Error::Protocol(_))));
    assert_eq!(within(c.closed()).await.code, CloseCode::Unauthorized);
    assert_eq!(e.failed(), 3);
}

// ------------------------------------------------------------------ re-checks before authorize

#[tokio::test]
async fn the_gate_is_rechecked_after_the_pin_and_a_closed_window_ends_the_connection() {
    let mut e = env(config()).await;
    // Open at the door, closed by the time the PIN has been checked.
    let gate = Gate::scripted(
        &[SetupAdmission::NeedsPin, SetupAdmission::Closed],
        SetupAdmission::Closed,
        Duration::ZERO,
    );
    e.auth.set_setup_gate(gate.clone());
    e.auth.set_pin_verifier(Verifier::new(
        &e.registry,
        PinVerdict::Right,
        Duration::ZERO,
    ));
    let c = e.connect_setup().await.expect("connects");
    assert_eq!(status(&recv_result(&c).await), AuthStatus::PinRequired);
    c.send_control(&pin_message("482913")).await.expect("PIN");
    // No AuthResult{OK}: the connection is closed SETUP_CLOSED instead.
    let info = within(c.closed()).await;
    assert_eq!(info.code, CloseCode::SetupClosed);
    assert!(matches!(
        e.next().await,
        Ok(Outcome::Refused(RefuseReason::SetupClosed))
    ));
    assert_eq!(gate.calls(), 2);
}

#[tokio::test]
async fn key_only_is_rechecked_too_and_a_changed_admission_is_never_authorized() {
    for (second, code, reason) in [
        (
            SetupAdmission::Closed,
            CloseCode::SetupClosed,
            RefuseReason::SetupClosed,
        ),
        // A PIN appeared meanwhile: the key alone is no longer enough.
        (
            SetupAdmission::NeedsPin,
            CloseCode::Busy,
            RefuseReason::Busy,
        ),
        (
            SetupAdmission::Unavailable,
            CloseCode::Busy,
            RefuseReason::Busy,
        ),
    ] {
        let mut e = env(config()).await;
        e.auth.set_setup_gate(Gate::scripted(
            &[SetupAdmission::KeyOnly, second],
            second,
            Duration::ZERO,
        ));
        let c = e.connect_setup().await.expect("connects");
        let info = within(c.closed()).await;
        assert_eq!(info.code, code, "{second:?}");
        assert!(
            matches!(e.next().await, Ok(Outcome::Refused(r)) if r == reason),
            "{second:?}"
        );
    }
}

#[tokio::test]
async fn a_revocation_while_the_pin_is_checked_is_noticed_before_authorization() {
    let mut e = env(config()).await;
    e.auth.set_setup_gate(Gate::new(SetupAdmission::NeedsPin));
    // The verifier takes a while; the device is revoked during it.
    e.auth.set_pin_verifier(Verifier::new(
        &e.registry,
        PinVerdict::Right,
        Duration::from_millis(400),
    ));
    let c = e.connect_setup().await.expect("connects");
    assert_eq!(status(&recv_result(&c).await), AuthStatus::PinRequired);
    c.send_control(&pin_message("482913")).await.expect("PIN");
    tokio::time::sleep(Duration::from_millis(100)).await;
    e.auth
        .revoke(&e.id(), RevokeReason::User)
        .await
        .expect("revoke");
    assert!(matches!(e.next().await, Err(Error::Revoked)));
    assert_eq!(within(c.closed()).await.code, CloseCode::Unauthorized);
}

// ------------------------------------------------------------------ PairedWith

#[tokio::test]
async fn paired_with_names_the_token_id_or_the_code() {
    let mut e = env(config()).await;
    // A second device, with a token: the id is the token's public id, never its secret.
    let token = e.auth.pairing().issue_token().expect("token");
    let cred = PairingCredential::parse(&token.to_text()).expect("parse");
    let second = new_key();
    let with = e.pair_with(&second, &cred).await;
    assert_eq!(with, PairedWith::Token { id: token.id() });
    assert!(!format!("{with:?}").contains(&*token.to_text()));

    // A third, with the short code.
    let code = e.auth.pairing().issue_code().expect("code");
    let cred = PairingCredential::parse(&code.to_text()).expect("parse");
    let third = new_key();
    assert_eq!(e.pair_with(&third, &cred).await, PairedWith::Code);
}

// ------------------------------------------------------------------ normal sessions and 1.2

#[tokio::test]
async fn a_normal_session_never_asks_the_gate_and_never_sees_pin_required() {
    let mut e = env(config()).await;
    let gate = Gate::new(SetupAdmission::KeyOnly);
    e.auth.set_setup_gate(gate.clone());
    e.auth.set_pin_verifier(Verifier::new(
        &e.registry,
        PinVerdict::Right,
        Duration::ZERO,
    ));
    let mut a = within(hx_crypto::connect_session(
        &e.target(),
        &e.device,
        e.server_key.public(),
        &hx_crypto::SessionOptions {
            preference: PREF,
            capabilities: capabilities(&[], Features::defined_up_to(3)),
            ..Default::default()
        },
    ))
    .await
    .expect("connect");
    let r = within(a.submit(&pin("482913"))).await.expect("reply");
    assert_eq!(r, hx_crypto::PinReply::Accepted);
    let Outcome::Authorized { connection, .. } = e.next().await.expect("outcome") else {
        panic!("expected Authorized");
    };
    assert!(!connection.is_control_only());
    // SETUP is not part of a normal session: it was not offered, so it is not negotiated.
    assert!(!connection.negotiated().features.contains(Features::SETUP));
    assert!(!connection.enabled_features().contains(Features::SETUP));
    assert!(
        connection
            .enabled_features()
            .contains(Features::DEVICE_MANAGEMENT)
    );
    assert_eq!(gate.calls(), 0);
    // A setup message on it is refused by the transport.
    assert!(matches!(
        connection.send_control(&cancel_request()).await,
        Err(hx_transport::Error::FeatureDisabled(_))
    ));
}

#[tokio::test]
async fn a_1_2_client_still_logs_in_and_never_gets_setup() {
    let mut e = env(config()).await;
    e.auth.set_setup_gate(Gate::new(SetupAdmission::KeyOnly));
    e.auth.set_pin_verifier(Verifier::new(
        &e.registry,
        PinVerdict::Right,
        Duration::ZERO,
    ));
    // A 1.2 client: its own minor and only the bits it knows.
    let (mut peer, first) = e
        .raw_hello(2, Features::defined_up_to(2), Intent::Session)
        .await;
    let Some(Ctl::HelloAck(ack)) = first.message else {
        panic!("expected HelloAck, got {first:?}");
    };
    // The server says 1.3 and advertises no SETUP bit on a session.
    assert_eq!(ack.version, Some(pb::Version { major: 1, minor: 3 }));
    let offered = ack.capabilities.expect("caps").features;
    assert_eq!(offered & Features::SETUP.0, 0);
    assert_ne!(offered & Features::DEVICE_MANAGEMENT.0, 0);
    peer.write(&pin_message("482913")).await;
    let ok = auth_result(&peer.read().await);
    assert_eq!(status(&ok), AuthStatus::Ok);
    let Outcome::Authorized { connection, .. } = e.next().await.expect("outcome") else {
        panic!("expected Authorized");
    };
    assert_eq!(connection.negotiated().version.minor, 2);
    assert!(!connection.negotiated().features.contains(Features::SETUP));
    assert!(
        connection
            .negotiated()
            .features
            .contains(Features::DEVICE_MANAGEMENT)
    );
    // A device-management request from the 1.2 client is delivered as before.
    let list = ControlMessage::new(Ctl::DeviceMgmt(pb::DeviceMgmt {
        request_id: 1,
        body: Some(pb::device_mgmt::Body::List(pb::ListDevices {})),
    }));
    peer.write(&list).await;
    assert_eq!(within(connection.recv_control()).await.expect("recv"), list);
    // PIN_REQUIRED and the setup intent do not exist for it: INTENT_SETUP is refused.
    drop((peer, connection));
    let (peer, first) = e
        .raw_hello(2, Features::defined_up_to(2), Intent::Setup)
        .await;
    assert!(matches!(first.message, Some(Ctl::Refuse(_))));
    assert_eq!(peer.closed_code().await, CloseCode::Unauthorized);
}
