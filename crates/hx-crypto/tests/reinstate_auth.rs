//! `INTENT_REINSTATE` (protocol 1.3, §11.7): the admission matrix, the attempt limits, each
//! password verdict, and the redaction of the password message.

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
    Authenticator, AuthenticatorConfig, BoxFuture, Clock, DeviceId, DeviceRegistry, Error,
    IdentityKey, ManualClock, MemoryRegistry, Outcome, PairClientOptions, PairingCredential,
    PasswordVerdict, ReinstateGate, RevokeReason, RevokedBy, pair_device, tls,
    wire::{AuthMessage, AuthResult, AuthStatus, PasswordAttempt, auth_message::Body},
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
use prost::Message as _;
use rustls::pki_types::ServerName;
use tokio::{sync::mpsc, task::JoinHandle};
use zeroize::Zeroizing;

const PREF: TransportPreference = TransportPreference::Quic;
const WAIT: Duration = Duration::from_secs(20);
const NOT_AUTHORIZED: &str = "not authorized";
const DAY: u64 = 86_400;

async fn within<T>(f: impl Future<Output = T>) -> T {
    tokio::time::timeout(WAIT, f).await.expect("timed out")
}

fn new_key() -> Arc<IdentityKey> {
    Arc::new(IdentityKey::generate().expect("key"))
}

// ------------------------------------------------------------------ scripted gate

struct Gate {
    script: Mutex<VecDeque<PasswordVerdict>>,
    fallback: PasswordVerdict,
    has_password: bool,
    calls: AtomicUsize,
    seen: Mutex<Vec<Vec<u8>>>,
}

impl Gate {
    fn new(fallback: PasswordVerdict) -> Arc<Self> {
        Arc::new(Self {
            script: Mutex::new(VecDeque::new()),
            fallback,
            has_password: true,
            calls: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
        })
    }

    fn without_password() -> Arc<Self> {
        let mut g =
            Arc::try_unwrap(Self::new(PasswordVerdict::Wrong)).unwrap_or_else(|_| unreachable!());
        g.has_password = false;
        Arc::new(g)
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl ReinstateGate for Gate {
    fn has_password(&self, _device: &DeviceId) -> bool {
        self.has_password
    }

    fn verify<'a>(
        &'a self,
        _device: &'a DeviceId,
        password: Zeroizing<Vec<u8>>,
    ) -> BoxFuture<'a, PasswordVerdict> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.seen.lock().expect("lock").push(password.to_vec());
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

async fn env() -> Env {
    env_with(|r| r, AuthenticatorConfig::default()).await
}

async fn env_with(
    wrap: impl FnOnce(Arc<MemoryRegistry>) -> Arc<dyn DeviceRegistry>,
    config: AuthenticatorConfig,
) -> Env {
    let server_key = new_key();
    let registry = Arc::new(MemoryRegistry::new());
    let clock = Arc::new(ManualClock::new());
    let auth = Authenticator::with_clock(
        server_key.clone(),
        wrap(registry.clone()),
        config,
        clock.clone(),
    );
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
    e.pair().await;
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

    async fn pair(&mut self) {
        let token = self.auth.pairing().issue_token().expect("token");
        let cred = PairingCredential::parse(&token.to_text()).expect("parse");
        let paired = within(pair_device(
            &self.target(),
            &self.device,
            &cred,
            &PairClientOptions {
                preference: PREF,
                ..Default::default()
            },
        ))
        .await
        .expect("pairing");
        let Outcome::Paired { connection, .. } = self.next().await.expect("outcome") else {
            panic!("expected Paired");
        };
        paired.finish().await;
        connection.close(CloseCode::NoError, "done").await;
    }

    fn id(&self) -> DeviceId {
        self.device.public().device_id()
    }

    /// Revoke the paired device as `by`, now.
    fn revoke(&self, by: RevokedBy) {
        assert!(
            self.registry
                .revoke(&self.id(), RevokeReason::User, by, self.clock.unix_secs())
                .expect("revoke")
        );
    }

    /// The real lockout path: five counted PINs and the lockout revocation.
    fn lock_out(&self) {
        for _ in 0..5 {
            self.registry.begin_pin_attempt(&self.id()).expect("count");
        }
        assert!(
            self.registry
                .revoke_if_failed(&self.id(), 5, self.clock.unix_secs())
                .expect("revoke")
        );
    }

    fn hello(features: Features) -> ClientHello {
        ClientHello {
            capabilities: capabilities(&[], features),
            intent: Intent::Reinstate,
            software: "reinstate-test".into(),
            device_name: "laptop".into(),
        }
    }

    async fn connect_as(&self, device: &Arc<IdentityKey>) -> hx_transport::Result<Connection> {
        let client = Client::new(
            tls::client_config_session(device, self.server_key.public()).expect("tls"),
            ClientOptions {
                preference: PREF,
                ..Default::default()
            },
        );
        within(client.connect(&self.target(), &Self::hello(Features::NONE))).await
    }

    async fn connect(&self) -> hx_transport::Result<Connection> {
        self.connect_as(&self.device).await
    }

    async fn refused(&self, r: hx_transport::Result<Connection>) -> (RefuseReason, String) {
        match r {
            Err(hx_transport::Error::Refused {
                reason, message, ..
            }) => (reason, message),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// Connect and read `PASSWORD_REQUIRED`.
    async fn open(&self) -> Connection {
        let c = self.connect().await.expect("connects");
        let first = recv_result(&c).await;
        assert_eq!(status(&first), AuthStatus::PasswordRequired);
        c
    }

    async fn raw_hello(&self, minor: u32, intent: Intent) -> (RawPeer, ControlMessage) {
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
            capabilities: Some(capabilities(&[], Features::NONE)),
            intent: intent as i32,
            software: "raw".into(),
            device_name: "raw peer".into(),
        }));
        let body = message::encode(&hello).expect("encode");
        let (mut send, mut recv) = conn.open_bi().await.expect("control stream");
        send.write_all(&[0x01]).await.expect("channel");
        send.write_all(&(body.len() as u32).to_le_bytes())
            .await
            .expect("len");
        send.write_all(&body).await.expect("body");
        let mut len = [0u8; 4];
        within(recv.read_exact(&mut len)).await.expect("len");
        let mut buf = vec![0u8; u32::from_le_bytes(len) as usize];
        within(recv.read_exact(&mut buf)).await.expect("body");
        let first = message::decode(&buf).expect("valid reply");
        (
            RawPeer {
                _ep: ep,
                _send: send,
                conn,
            },
            first,
        )
    }
}

struct RawPeer {
    _ep: quinn::Endpoint,
    _send: quinn::SendStream,
    conn: quinn::Connection,
}

impl RawPeer {
    async fn closed_code(&self) -> CloseCode {
        match within(self.conn.closed()).await {
            quinn::ConnectionError::ApplicationClosed(ac) => {
                CloseCode::from_code(ac.error_code.into_inner())
            }
            other => panic!("unexpected close: {other}"),
        }
    }
}

fn password_message(p: &[u8]) -> ControlMessage {
    AuthMessage::new(Body::Password(PasswordAttempt {
        password: p.to_vec(),
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

async fn send_password(c: &Connection, p: &[u8]) -> AuthResult {
    c.send_control(&password_message(p))
        .await
        .expect("send password");
    recv_result(c).await
}

fn status(r: &AuthResult) -> AuthStatus {
    AuthStatus::try_from(r.status).expect("status")
}

const GOOD: &[u8] = b"correct horse battery staple";

// ------------------------------------------------------------------ admission matrix

#[tokio::test]
async fn only_a_fresh_lockout_revocation_may_reinstate_and_everything_else_is_uniform() {
    let mut e = env().await;
    let gate = Gate::new(PasswordVerdict::Right);
    e.auth.set_reinstate_gate(gate.clone());

    // An active (not revoked) device.
    let r = e.connect().await;
    let active = e.refused(r).await;
    assert!(matches!(
        e.next().await,
        Ok(Outcome::Refused(RefuseReason::Unauthorized))
    ));
    assert_eq!(active, (RefuseReason::Unauthorized, NOT_AUTHORIZED.into()));

    // An unknown key.
    let r = e.connect_as(&new_key()).await;
    assert_eq!(e.refused(r).await, active);
    assert!(matches!(
        e.next().await,
        Ok(Outcome::Refused(RefuseReason::Unauthorized))
    ));

    // Every cause but the lockout.
    for by in [
        RevokedBy::Device,
        RevokedBy::Operator,
        RevokedBy::SelfRevoke,
    ] {
        let mut e2 = env().await;
        e2.auth.set_reinstate_gate(gate.clone());
        e2.revoke(by);
        let r = e2.connect().await;
        assert_eq!(e2.refused(r).await, active, "{by:?}");
        assert!(
            matches!(
                e2.next().await,
                Ok(Outcome::Refused(RefuseReason::Unauthorized))
            ),
            "{by:?}"
        );
        // And it stays revoked.
        assert!(e2.registry.get(&e2.id()).unwrap().unwrap().is_revoked());
    }

    // A lockout revocation older than 30 days.
    let mut e3 = env().await;
    e3.auth.set_reinstate_gate(gate.clone());
    e3.lock_out();
    e3.clock.advance(Duration::from_secs(30 * DAY));
    let r = e3.connect().await;
    assert_eq!(e3.refused(r).await, active);
    assert!(matches!(
        e3.next().await,
        Ok(Outcome::Refused(RefuseReason::Unauthorized))
    ));

    assert_eq!(gate.calls(), 0, "no password was ever checked");
}

#[tokio::test]
async fn a_lockout_just_under_30_days_old_is_admitted() {
    let mut e = env().await;
    e.auth.set_reinstate_gate(Gate::new(PasswordVerdict::Right));
    e.lock_out();
    e.clock.advance(Duration::from_secs(30 * DAY - 5));
    let c = e.open().await;
    let r = send_password(&c, GOOD).await;
    assert_eq!(status(&r), AuthStatus::Ok);
    assert!(matches!(e.next().await, Ok(Outcome::Reinstated { .. })));
}

#[tokio::test]
async fn an_old_minor_a_missing_gate_and_a_1_2_client_get_the_uniform_refusal() {
    let mut e = env().await;
    e.lock_out();
    // No gate installed.
    let r = e.connect().await;
    assert_eq!(
        e.refused(r).await,
        (RefuseReason::Unauthorized, NOT_AUTHORIZED.into())
    );
    assert!(matches!(
        e.next().await,
        Ok(Outcome::Refused(RefuseReason::Unauthorized))
    ));
    // A 1.2 client that nevertheless sends the intent (no real 1.2 client can).
    let gate = Gate::new(PasswordVerdict::Right);
    e.auth.set_reinstate_gate(gate.clone());
    for minor in [2, 0] {
        let (peer, first) = e.raw_hello(minor, Intent::Reinstate).await;
        let Some(Ctl::Refuse(r)) = first.message else {
            panic!("minor {minor}: expected Refuse, got {first:?}");
        };
        assert_eq!(r.reason, RefuseReason::Unauthorized as i32);
        assert_eq!(r.message, NOT_AUTHORIZED);
        assert_eq!(peer.closed_code().await, CloseCode::Unauthorized);
        assert!(matches!(
            e.next().await,
            Ok(Outcome::Refused(RefuseReason::Unauthorized))
        ));
    }
    assert!(e.registry.get(&e.id()).unwrap().unwrap().is_revoked());
    assert_eq!(gate.calls(), 0);
}

// ------------------------------------------------------------------ verdicts

#[tokio::test]
async fn right_reinstates_resets_the_counter_confirms_and_closes_without_a_session() {
    let mut e = env().await;
    let gate = Gate::new(PasswordVerdict::Right);
    e.auth.set_reinstate_gate(gate.clone());
    e.lock_out();
    let c = e.open().await;
    let ok = send_password(&c, GOOD).await;
    assert_eq!(status(&ok), AuthStatus::Ok);
    let Outcome::Reinstated { device } = e.next().await.expect("outcome") else {
        panic!("expected Reinstated");
    };
    assert_eq!(device.id, e.id());
    assert!(!device.is_revoked());
    assert_eq!(device.failed_pins, 0);
    let rec = e.registry.get(&e.id()).unwrap().unwrap();
    assert!(rec.revoked.is_none());
    assert_eq!(rec.failed_pins, 0);
    // Closed with NO_ERROR, not authorized, no features.
    assert_eq!(within(c.closed()).await.code, CloseCode::NoError);
    assert!(c.negotiated().features == Features::NONE);
    assert_eq!(*gate.seen.lock().expect("lock"), vec![GOOD.to_vec()]);
    // The gate cannot be reused: the device is no longer revoked.
    let r = e.connect().await;
    assert_eq!(e.refused(r).await.0, RefuseReason::Unauthorized);
    assert!(matches!(
        e.next().await,
        Ok(Outcome::Refused(RefuseReason::Unauthorized))
    ));
}

#[tokio::test]
async fn wrong_is_counted_and_answered_wrong_password() {
    let e = env().await;
    let gate = Gate::new(PasswordVerdict::Wrong);
    e.auth.set_reinstate_gate(gate.clone());
    e.lock_out();
    let first = {
        let c = e.connect().await.expect("connects");
        let r = recv_result(&c).await;
        assert_eq!(
            (status(&r), r.attempts_left),
            (AuthStatus::PasswordRequired, 3)
        );
        c
    };
    let r = send_password(&first, b"nope").await;
    assert_eq!(
        (status(&r), r.attempts_left),
        (AuthStatus::WrongPassword, 2)
    );
    let r = send_password(&first, b"nope").await;
    assert_eq!(
        (status(&r), r.attempts_left),
        (AuthStatus::WrongPassword, 1)
    );
    assert_eq!(gate.calls(), 2);
    assert!(e.registry.get(&e.id()).unwrap().unwrap().is_revoked());
}

#[tokio::test]
async fn malformed_passwords_are_wrong_without_reaching_the_gate() {
    let mut e = env().await;
    let gate = Gate::new(PasswordVerdict::Right);
    e.auth.set_reinstate_gate(gate.clone());
    e.lock_out();
    // Each counts against the hourly budget of 3, so three kinds are tried.
    let c = e.open().await;
    for bad in [&b""[..], b"a\0b", &[0xff, 0xfe]] {
        let r = send_password(&c, bad).await;
        assert_eq!(status(&r), AuthStatus::WrongPassword);
    }
    assert_eq!(gate.calls(), 0);
    let _ = e.next().await; // the connection used its three messages
    // A valid one is over the hourly budget now, and still not checked.
    let c2 = e.connect().await.expect("connects");
    let first = recv_result(&c2).await;
    assert_eq!(
        (status(&first), first.attempts_left),
        (AuthStatus::PasswordRequired, 0)
    );
    assert_eq!(status(&send_password(&c2, GOOD).await), AuthStatus::Backoff);
    assert_eq!(gate.calls(), 0);
}

#[tokio::test]
async fn unavailable_and_locked_are_not_available_and_refunded() {
    for verdict in [
        PasswordVerdict::Unavailable,
        PasswordVerdict::Locked {
            retry_after: Some(Duration::from_secs(60)),
        },
    ] {
        let mut e = env().await;
        let gate = Gate::new(verdict);
        e.auth.set_reinstate_gate(gate.clone());
        e.lock_out();
        // Many rounds: the per-device budget (3 per hour) is never used up, because each
        // attempt is refunded.
        for round in 0..6 {
            let c = e.open().await;
            let r = send_password(&c, GOOD).await;
            assert_eq!(status(&r), AuthStatus::NotAvailable, "{verdict:?} {round}");
            assert!(matches!(e.next().await, Err(Error::PinNotAvailable)));
            assert_eq!(within(c.closed()).await.code, CloseCode::Unauthorized);
        }
        assert_eq!(gate.calls(), 6);
        assert!(e.registry.get(&e.id()).unwrap().unwrap().is_revoked());
    }
}

#[tokio::test]
async fn no_password_verifier_is_not_available() {
    let mut e = env().await;
    e.auth.set_reinstate_gate(Gate::without_password());
    e.lock_out();
    let c = e.open().await;
    let r = send_password(&c, GOOD).await;
    assert_eq!(status(&r), AuthStatus::NotAvailable);
    assert!(matches!(e.next().await, Err(Error::PinNotAvailable)));
}

// ------------------------------------------------------------------ limits

#[tokio::test]
async fn a_connection_takes_at_most_three_password_messages() {
    let mut e = env().await;
    // Lift the hourly budget out of the way to isolate the per-connection limit.
    e.auth = Authenticator::with_clock(
        e.server_key.clone(),
        e.registry.clone(),
        AuthenticatorConfig {
            reinstate_attempts_per_hour: 100,
            ..Default::default()
        },
        e.clock.clone(),
    );
    // A fresh accept loop with the new authenticator.
    let (tx, rx) = mpsc::unbounded_channel();
    let (s2, a2) = (e.server.clone(), e.auth.clone());
    e._accept.abort();
    e._accept = tokio::spawn(async move {
        while let Some(p) = s2.accept().await {
            let (a, tx) = (a2.clone(), tx.clone());
            tokio::spawn(async move {
                let _ = tx.send(a.authenticate(p).await);
            });
        }
    });
    e.outcomes = rx;
    e.auth.set_reinstate_gate(Gate::new(PasswordVerdict::Wrong));
    e.lock_out();
    let c = e.open().await;
    for _ in 0..3 {
        assert_eq!(
            status(&send_password(&c, b"nope").await),
            AuthStatus::WrongPassword
        );
    }
    assert!(matches!(e.next().await, Err(Error::Protocol(_))));
    assert_eq!(within(c.closed()).await.code, CloseCode::Unauthorized);
}

#[tokio::test]
async fn a_device_gets_three_attempts_an_hour_across_connections() {
    let mut e = env().await;
    let gate = Gate::new(PasswordVerdict::Wrong);
    e.auth.set_reinstate_gate(gate.clone());
    e.lock_out();
    // Two attempts on one connection, one on the next.
    let c1 = e.open().await;
    send_password(&c1, b"x").await;
    send_password(&c1, b"x").await;
    drop(c1);
    let _ = e.next().await;
    let c2 = e.open().await;
    let r = send_password(&c2, b"x").await;
    assert_eq!(
        (status(&r), r.attempts_left),
        (AuthStatus::WrongPassword, 0)
    );
    // The budget is spent: BACKOFF with the wait, not verified, not counted.
    e.clock.advance(Duration::from_secs(600));
    let r = send_password(&c2, b"x").await;
    assert_eq!(status(&r), AuthStatus::Backoff);
    assert!(
        (2_990_000..=3_000_000).contains(&r.retry_after_ms),
        "{}",
        r.retry_after_ms
    );
    assert_eq!(gate.calls(), 3);
    // A new connection is told the same, and the first message is already over budget.
    let c3 = e.connect().await.expect("connects");
    let first = recv_result(&c3).await;
    assert_eq!(
        (status(&first), first.attempts_left),
        (AuthStatus::PasswordRequired, 0)
    );
    assert_eq!(status(&send_password(&c3, b"x").await), AuthStatus::Backoff);
    assert_eq!(gate.calls(), 3);
    // After the hour the budget is back (the oldest attempts have aged out).
    e.clock.advance(Duration::from_secs(3_000));
    let c4 = e.open().await;
    assert_eq!(
        status(&send_password(&c4, b"x").await),
        AuthStatus::WrongPassword
    );
    assert_eq!(gate.calls(), 4);
    assert!(e.registry.get(&e.id()).unwrap().unwrap().is_revoked());
}

#[tokio::test]
async fn the_budget_is_per_device() {
    let mut e = env().await;
    let gate = Gate::new(PasswordVerdict::Wrong);
    e.auth.set_reinstate_gate(gate.clone());
    e.lock_out();
    let c = e.open().await;
    for _ in 0..3 {
        send_password(&c, b"x").await;
    }
    let _ = e.next().await;
    // A second device, also locked out, still has its own three.
    let second = new_key();
    let token = e.auth.pairing().issue_token().expect("token");
    let cred = PairingCredential::parse(&token.to_text()).expect("parse");
    let paired = within(pair_device(
        &e.target(),
        &second,
        &cred,
        &PairClientOptions {
            preference: PREF,
            ..Default::default()
        },
    ))
    .await
    .expect("pairing");
    let Outcome::Paired { connection, .. } = e.next().await.expect("outcome") else {
        panic!("expected Paired");
    };
    paired.finish().await;
    connection.close(CloseCode::NoError, "done").await;
    let id2 = second.public().device_id();
    for _ in 0..5 {
        e.registry.begin_pin_attempt(&id2).expect("count");
    }
    assert!(
        e.registry
            .revoke_if_failed(&id2, 5, e.clock.unix_secs())
            .expect("revoke")
    );
    let c2 = e.connect_as(&second).await.expect("connects");
    let r = recv_result(&c2).await;
    assert_eq!(
        (status(&r), r.attempts_left),
        (AuthStatus::PasswordRequired, 3)
    );
}

// ------------------------------------------------------------------ redaction and wire

#[test]
fn the_password_message_is_redacted_and_round_trips() {
    let secret = "tr0ub4dor&3-secret";
    let p = PasswordAttempt {
        password: secret.as_bytes().to_vec(),
    };
    assert!(!format!("{p:?}").contains(secret));
    assert!(!format!("{p:#?}").contains(secret));
    assert!(format!("{p:?}").contains("redacted"));
    let m = AuthMessage::new(Body::Password(p.clone()));
    assert!(!format!("{m:?}").contains(secret));
    let wire = m.encode_to_vec();
    assert!(!wire.is_empty());
    let back = AuthMessage::decode(wire.as_slice()).expect("decode");
    match back.body {
        Some(Body::Password(b)) => assert_eq!(b.password, secret.as_bytes()),
        other => panic!("expected a password, got {other:?}"),
    }
    // Field 3 of AuthMessage, field 1 of the attempt: `1a 14 0a 12 <18 bytes>`.
    assert_eq!(&wire[..4], &[0x1a, 0x14, 0x0a, 0x12]);
    // The new statuses.
    assert_eq!(AuthStatus::PasswordRequired as i32, 7);
    assert_eq!(AuthStatus::WrongPassword as i32, 8);
    // Wrapped in the opaque control message it prints no secret either.
    let c = m.into_control().expect("control");
    assert!(!format!("{c:?}").contains(secret));
    // A client that does not know field 3 skips it: an old AuthMessage-shaped decode still works.
    assert!(matches!(
        AuthMessage::from_control(&c).expect("auth").body,
        Some(Body::Password(_))
    ));
}

// ------------------------------------------------------------------ the commit is announced

/// A registry whose reads become slow once a reinstatement was committed, so that the
/// exchange's deadline fires between the registry write and the end of the exchange.
struct SlowAfterReinstate {
    inner: Arc<MemoryRegistry>,
    armed: std::sync::atomic::AtomicBool,
    delay: Duration,
}

impl DeviceRegistry for SlowAfterReinstate {
    fn get(&self, id: &DeviceId) -> hx_crypto::Result<Option<hx_crypto::DeviceRecord>> {
        if self.armed.load(Ordering::SeqCst) {
            std::thread::sleep(self.delay);
        }
        self.inner.get(id)
    }
    fn list(&self) -> hx_crypto::Result<Vec<hx_crypto::DeviceRecord>> {
        self.inner.list()
    }
    fn upsert_paired(
        &self,
        key: &hx_crypto::PublicKey,
        name: &str,
        now_unix: u64,
    ) -> hx_crypto::Result<hx_crypto::DeviceRecord> {
        self.inner.upsert_paired(key, name, now_unix)
    }
    fn begin_pin_attempt(&self, id: &DeviceId) -> hx_crypto::Result<u32> {
        self.inner.begin_pin_attempt(id)
    }
    fn refund_pin_attempt(&self, id: &DeviceId) -> hx_crypto::Result<u32> {
        self.inner.refund_pin_attempt(id)
    }
    fn reset_pin_failures(&self, id: &DeviceId) -> hx_crypto::Result<()> {
        self.inner.reset_pin_failures(id)
    }
    fn revoke_if_failed(&self, id: &DeviceId, max: u32, now: u64) -> hx_crypto::Result<bool> {
        self.inner.revoke_if_failed(id, max, now)
    }
    fn record_pin_success(&self, id: &DeviceId, now: u64) -> hx_crypto::Result<()> {
        self.inner.record_pin_success(id, now)
    }
    fn revoke(
        &self,
        id: &DeviceId,
        reason: RevokeReason,
        by: RevokedBy,
        now: u64,
    ) -> hx_crypto::Result<bool> {
        self.inner.revoke(id, reason, by, now)
    }
    fn reinstate_after_lockout(
        &self,
        id: &DeviceId,
        now: u64,
        max_age: u64,
    ) -> hx_crypto::Result<bool> {
        let done = self.inner.reinstate_after_lockout(id, now, max_age)?;
        self.armed.store(true, Ordering::SeqCst);
        Ok(done)
    }
    fn reinstate(&self, id: &DeviceId) -> hx_crypto::Result<bool> {
        self.inner.reinstate(id)
    }
    fn remove(&self, id: &DeviceId) -> hx_crypto::Result<bool> {
        self.inner.remove(id)
    }
}

/// Security review F3: if the exchange's deadline fires after the registry already holds the
/// device as active, `Outcome::Reinstated` is lost, but the reinstatement is still announced
/// (from the commit itself), so the application can audit it.
#[tokio::test]
async fn a_reinstatement_that_commits_just_before_the_deadline_is_still_announced() {
    let mut e = env_with(
        |inner| {
            Arc::new(SlowAfterReinstate {
                inner,
                armed: false.into(),
                delay: Duration::from_millis(1500),
            })
        },
        AuthenticatorConfig {
            pin_timeout: Duration::from_millis(500),
            ..AuthenticatorConfig::default()
        },
    )
    .await;
    e.auth.set_reinstate_gate(Gate::new(PasswordVerdict::Right));
    let mut announced = e.auth.subscribe_reinstatements();
    e.lock_out();
    let c = e.open().await;
    let _ = c.send_control(&password_message(GOOD)).await;
    // The exchange ran out of time after the commit ...
    assert!(matches!(e.next().await, Err(Error::Timeout(_))));
    // ... the device is active in the registry ...
    assert!(!e.registry.get(&e.id()).unwrap().unwrap().is_revoked());
    // ... and the commit announced it.
    assert_eq!(within(announced.recv()).await.unwrap(), e.id());
}
