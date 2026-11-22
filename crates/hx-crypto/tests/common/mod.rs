//! Shared harness of the client-library tests: a real `Authenticator` behind a real QUIC
//! `Server`, one paired device, scripted gates (setup, PIN, password).
#![allow(dead_code)]

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
    Authenticator, AuthenticatorConfig, BoxFuture, DeviceId, DeviceRegistry, IdentityKey,
    ManualClock, MemoryRegistry, Outcome, PairClientOptions, PairingCredential, PasswordVerdict,
    PinVerdict, PinVerifier, ReinstateGate, RevokeReason, RevokedBy, SetupAdmission, SetupGate,
    pair_device, tls,
};
use hx_proto::{
    channel::CloseCode,
    version::{Features, ProtocolVersion, capabilities},
};
use hx_transport::{Server, ServerOptions, Target, TransportPreference};
use rustls::pki_types::ServerName;
use tokio::{sync::mpsc, task::JoinHandle};
use zeroize::Zeroizing;

pub const PREF: TransportPreference = TransportPreference::Quic;
pub const WAIT: Duration = Duration::from_secs(20);

pub async fn within<T>(f: impl Future<Output = T>) -> T {
    tokio::time::timeout(WAIT, f).await.expect("timed out")
}

pub fn new_key() -> Arc<IdentityKey> {
    Arc::new(IdentityKey::generate().expect("key"))
}

// ------------------------------------------------------------------ gates

/// A setup gate whose answer the test can change.
pub struct Gate {
    answer: Mutex<SetupAdmission>,
    calls: AtomicUsize,
}

impl Gate {
    pub fn new(a: SetupAdmission) -> Arc<Self> {
        Arc::new(Self {
            answer: Mutex::new(a),
            calls: AtomicUsize::new(0),
        })
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl SetupGate for Gate {
    fn admit<'a>(&'a self, _device: &'a DeviceId) -> BoxFuture<'a, SetupAdmission> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.answer.lock().expect("lock")
        })
    }
}

/// A PIN verifier that answers from a script, then a fallback.
pub struct Verifier {
    script: Mutex<VecDeque<PinVerdict>>,
    fallback: PinVerdict,
    pub seen: Mutex<Vec<Vec<u8>>>,
}

impl Verifier {
    pub fn new(script: &[PinVerdict], fallback: PinVerdict) -> Arc<Self> {
        Arc::new(Self {
            script: Mutex::new(script.iter().copied().collect()),
            fallback,
            seen: Mutex::new(Vec::new()),
        })
    }
}

impl PinVerifier for Verifier {
    fn has_pin(&self, _device: &DeviceId) -> bool {
        true
    }

    fn verify<'a>(
        &'a self,
        _device: &'a DeviceId,
        pin: Zeroizing<Vec<u8>>,
    ) -> BoxFuture<'a, PinVerdict> {
        Box::pin(async move {
            self.seen.lock().expect("lock").push(pin.to_vec());
            self.script
                .lock()
                .expect("lock")
                .pop_front()
                .unwrap_or(self.fallback)
        })
    }
}

/// A password gate that answers from a script, then a fallback.
pub struct PwGate {
    script: Mutex<VecDeque<PasswordVerdict>>,
    fallback: PasswordVerdict,
    has_password: bool,
    pub seen: Mutex<Vec<Vec<u8>>>,
}

impl PwGate {
    pub fn new(script: &[PasswordVerdict], fallback: PasswordVerdict) -> Arc<Self> {
        Arc::new(Self {
            script: Mutex::new(script.iter().copied().collect()),
            fallback,
            has_password: true,
            seen: Mutex::new(Vec::new()),
        })
    }

    pub fn without_password() -> Arc<Self> {
        Arc::new(Self {
            script: Mutex::new(VecDeque::new()),
            fallback: PasswordVerdict::Wrong,
            has_password: false,
            seen: Mutex::new(Vec::new()),
        })
    }
}

impl ReinstateGate for PwGate {
    fn has_password(&self, _device: &DeviceId) -> bool {
        self.has_password
    }

    fn verify<'a>(
        &'a self,
        _device: &'a DeviceId,
        password: Zeroizing<Vec<u8>>,
    ) -> BoxFuture<'a, PasswordVerdict> {
        Box::pin(async move {
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

pub struct Env {
    pub auth: Authenticator,
    pub server: Arc<Server>,
    pub registry: Arc<MemoryRegistry>,
    pub clock: Arc<ManualClock>,
    pub server_key: Arc<IdentityKey>,
    pub outcomes: mpsc::UnboundedReceiver<hx_crypto::Result<Outcome>>,
    pub device: Arc<IdentityKey>,
    /// The version the server showed on the confirmed pairing of `device`.
    pub paired_version: ProtocolVersion,
    _accept: JoinHandle<()>,
}

/// What a gateway offers: every 1.3 feature except `SETUP` (offered on setup connections only).
pub fn config() -> AuthenticatorConfig {
    AuthenticatorConfig {
        capabilities: capabilities(&[], Features::defined_up_to(3).without(Features::SETUP)),
        session_features: Features::defined_up_to(3).without(Features::SETUP),
        max_pin_messages: 10,
        ..Default::default()
    }
}

impl Env {
    /// A server with one device, paired with a token.
    pub async fn new(config: AuthenticatorConfig) -> Env {
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
            paired_version: ProtocolVersion { major: 0, minor: 0 },
            _accept: accept,
        };
        e.pair().await;
        e
    }

    pub fn target(&self) -> Target {
        Target {
            addr: self.server.quic_addr().expect("quic addr"),
            server_name: ServerName::try_from("hx.invalid").expect("name"),
        }
    }

    pub async fn next(&mut self) -> hx_crypto::Result<Outcome> {
        within(self.outcomes.recv()).await.expect("an outcome")
    }

    /// No outcome is pending: nothing connected to the server.
    pub fn no_outcome(&mut self) -> bool {
        self.outcomes.try_recv().is_err()
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
                device_name: "laptop".into(),
                ..Default::default()
            },
        ))
        .await
        .expect("pairing succeeds");
        self.paired_version = paired.server_version();
        let Outcome::Paired { connection, .. } = self.next().await.expect("outcome") else {
            panic!("expected Paired");
        };
        paired.finish().await;
        connection.close(CloseCode::NoError, "done").await;
    }

    pub fn id(&self) -> DeviceId {
        self.device.public().device_id()
    }

    /// The real lockout path: five counted PINs and the lockout revocation.
    pub fn lock_out(&self) {
        for _ in 0..5 {
            self.registry.begin_pin_attempt(&self.id()).expect("count");
        }
        assert!(
            self.registry
                .revoke_if_failed(&self.id(), 5, self.clock.unix_secs_for_tests())
                .expect("revoke")
        );
    }

    pub fn registry_record(&self) -> hx_crypto::DeviceRecord {
        self.registry
            .get(&self.id())
            .expect("registry")
            .expect("device")
    }

    pub fn revoke(&self, by: RevokedBy) {
        assert!(
            self.registry
                .revoke(
                    &self.id(),
                    RevokeReason::User,
                    by,
                    self.clock.unix_secs_for_tests()
                )
                .expect("revoke")
        );
    }
}

/// `ManualClock::unix_secs` comes from the `Clock` trait; a tiny shim keeps the tests tidy.
pub trait UnixSecs {
    fn unix_secs_for_tests(&self) -> u64;
}

impl UnixSecs for ManualClock {
    fn unix_secs_for_tests(&self) -> u64 {
        use hx_crypto::Clock;
        self.unix_secs()
    }
}
