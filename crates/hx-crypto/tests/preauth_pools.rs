//! Pre-authentication pools and the per-device share of the PIN failure budget
//! (docs/protocol.md section 1 and 11.4 rule 4a, docs/ipc.md section 5.3).
//!
//! * A flood of connections that never send a `Hello`, from many addresses, fills the general
//!   pending pool; a paired device still logs in through its reserved slot.
//! * Two device keys that each fail five times charge a shared failure budget at most eight
//!   times, so it does not lock and a third device still logs in.
//! * An unknown key while no pairing secret is live gets the uniform answers at once.

use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use hx_crypto::{
    Authenticator, AuthenticatorConfig, BoxFuture, DeviceId, DeviceRegistry, Error, IdentityKey,
    ManualClock, MemoryRegistry, Outcome, PairClientOptions, PairingCredential, Pin, PinVerdict,
    PinVerifier, SessionOptions, connect_session, connect_with_pin, pair_device, tls,
};
use hx_proto::{
    channel::CloseCode,
    pb::RefuseReason,
    version::{Features, capabilities},
};
use hx_transport::{Server, ServerOptions, Target, TransportPreference};
use rustls::pki_types::ServerName;
use tokio::{sync::mpsc, task::JoinHandle};
use zeroize::Zeroizing;

const PIN: &str = "482913";
const WAIT: Duration = Duration::from_secs(20);
const PREF: TransportPreference = TransportPreference::Quic;

async fn within<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(WAIT, f).await.expect("timed out")
}

fn new_key() -> Arc<IdentityKey> {
    Arc::new(IdentityKey::generate().expect("key"))
}

/// Stands in for privd: a correct PIN is free, a wrong one counts against one budget shared by
/// every device, and past `cap` failures it is locked for everybody.
struct SharedBudget {
    cap: usize,
    failures: AtomicUsize,
    calls: AtomicUsize,
}

impl SharedBudget {
    fn new(cap: usize) -> Arc<Self> {
        Arc::new(Self {
            cap,
            failures: AtomicUsize::new(0),
            calls: AtomicUsize::new(0),
        })
    }

    fn failures(&self) -> usize {
        self.failures.load(Ordering::SeqCst)
    }

    fn locked(&self) -> bool {
        self.failures() >= self.cap
    }
}

impl PinVerifier for SharedBudget {
    fn shares_failure_budget(&self) -> bool {
        true
    }

    fn verify<'a>(
        &'a self,
        _device: &'a DeviceId,
        pin: Zeroizing<Vec<u8>>,
    ) -> BoxFuture<'a, PinVerdict> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.locked() {
                return PinVerdict::Locked { retry_after: None };
            }
            if pin.as_slice() == PIN.as_bytes() {
                return PinVerdict::Right;
            }
            self.failures.fetch_add(1, Ordering::SeqCst);
            PinVerdict::Wrong
        })
    }
}

struct Env {
    auth: Authenticator,
    server: Arc<Server>,
    registry: Arc<MemoryRegistry>,
    clock: Arc<ManualClock>,
    server_key: Arc<IdentityKey>,
    outcomes: mpsc::UnboundedReceiver<hx_crypto::Result<Outcome>>,
    _accept: JoinHandle<()>,
}

impl Env {
    async fn new(verifier: Arc<dyn PinVerifier>) -> Env {
        let server_key = new_key();
        let registry = Arc::new(MemoryRegistry::new());
        let clock = Arc::new(ManualClock::new());
        let auth = Authenticator::with_clock(
            server_key.clone(),
            registry.clone(),
            AuthenticatorConfig {
                capabilities: capabilities(
                    &[],
                    Features::defined_up_to(3).without(Features::SETUP),
                ),
                session_features: Features::defined_up_to(3).without(Features::SETUP),
                max_pin_messages: 10,
                ..Default::default()
            },
            clock.clone(),
        );
        auth.set_pin_verifier(verifier);
        let server = Arc::new(
            Server::bind(
                "127.0.0.1:0".parse().expect("addr"),
                tls::server_config(&server_key).expect("tls"),
                ServerOptions {
                    // The flood test opens a hundred connections one after the other.
                    handshake_timeout: Duration::from_secs(30),
                    classifier: Some(auth.pre_auth_classifier()),
                    ..Default::default()
                },
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
        Env {
            auth,
            server,
            registry,
            clock,
            server_key,
            outcomes,
            _accept: accept,
        }
    }

    fn target(&self) -> Target {
        Target {
            addr: self.server.quic_addr().expect("quic addr"),
            server_name: ServerName::try_from("hx.invalid").expect("name"),
        }
    }

    /// A device that is already paired (written to the registry directly).
    fn paired_device(&self, name: &str) -> Arc<IdentityKey> {
        let k = new_key();
        self.registry
            .upsert_paired(&k.public(), name, 1)
            .expect("paired");
        k
    }

    fn session_opts() -> SessionOptions {
        SessionOptions {
            preference: PREF,
            capabilities: capabilities(&[], Features::defined_up_to(0)),
            ..Default::default()
        }
    }
}

// ------------------------------------------------------------------ N2: the shared budget

#[tokio::test]
async fn two_devices_without_the_pin_cannot_lock_the_shared_budget() {
    // privd's global cap: 10 PIN failures.
    let privd = SharedBudget::new(10);
    let env = Env::new(privd.clone()).await;
    let (a, b, c) = (
        env.paired_device("a"),
        env.paired_device("b"),
        env.paired_device("c"),
    );
    let wrong = Pin::new("000000").expect("pin");
    let opts = Env::session_opts();

    for (name, dev) in [("a", &a), ("b", &b)] {
        for n in 1..=5u32 {
            // Wait out the backoff of the previous failure.
            env.clock.advance(Duration::from_secs(60));
            let mut conn = within(connect_session(
                &env.target(),
                dev,
                env.server_key.public(),
                &opts,
            ))
            .await
            .expect("connects");
            let r = within(conn.submit(&wrong)).await;
            if n < 5 {
                assert!(r.is_ok(), "{name} attempt {n}: {r:?}");
            } else {
                // The 5th attempt revokes the device, without asking privd.
                assert!(
                    matches!(r, Err(Error::Revoked)),
                    "{name} attempt {n}: {r:?}"
                );
            }
        }
        let rec = env
            .registry
            .get(&dev.public().device_id())
            .expect("reg")
            .expect("device");
        assert!(rec.is_revoked(), "{name} is revoked");
    }
    // Each device charged 4 failures, not 5: 8 of 10, and the budget is not locked.
    assert_eq!(privd.failures(), 8);
    assert_eq!(privd.calls.load(Ordering::SeqCst), 8);
    assert!(!privd.locked());

    // A third device with the right PIN gets in.
    env.clock.advance(Duration::from_secs(60));
    let conn = within(connect_with_pin(
        &env.target(),
        &c,
        env.server_key.public(),
        &Pin::new(PIN).expect("pin"),
        &opts,
    ))
    .await
    .expect("the third device logs in");
    drop(conn);
    assert_eq!(privd.failures(), 8);
}

#[tokio::test]
async fn a_local_verifier_still_checks_the_fifth_attempt() {
    // Without a shared budget (a local PIN hash) every attempt is verified, so a correct
    // PIN as the 5th attempt works.
    struct Local(Mutex<usize>);
    impl PinVerifier for Local {
        fn verify<'a>(
            &'a self,
            _device: &'a DeviceId,
            pin: Zeroizing<Vec<u8>>,
        ) -> BoxFuture<'a, PinVerdict> {
            Box::pin(async move {
                *self.0.lock().expect("lock") += 1;
                if pin.as_slice() == PIN.as_bytes() {
                    PinVerdict::Right
                } else {
                    PinVerdict::Wrong
                }
            })
        }
    }
    let local = Arc::new(Local(Mutex::new(0)));
    let env = Env::new(local.clone()).await;
    let dev = env.paired_device("a");
    let opts = Env::session_opts();
    let wrong = Pin::new("000000").expect("pin");
    for _ in 0..4 {
        env.clock.advance(Duration::from_secs(60));
        let mut c = within(connect_session(
            &env.target(),
            &dev,
            env.server_key.public(),
            &opts,
        ))
        .await
        .expect("connects");
        within(c.submit(&wrong)).await.expect("reply");
    }
    env.clock.advance(Duration::from_secs(60));
    within(connect_with_pin(
        &env.target(),
        &dev,
        env.server_key.public(),
        &Pin::new(PIN).expect("pin"),
        &opts,
    ))
    .await
    .expect("the 5th attempt is checked and right");
    assert_eq!(*local.0.lock().expect("lock"), 5);
}

// ------------------------------------------------------------------ N1: the pools

/// A raw QUIC peer that completes TLS with `key` from `local` and then says nothing.
async fn silent_peer(
    server: SocketAddr,
    local: SocketAddr,
    key: &Arc<IdentityKey>,
) -> Option<(quinn::Endpoint, quinn::Connection)> {
    let mut cfg = (*tls::client_config_pairing(key).expect("tls")).clone();
    cfg.alpn_protocols = vec![hx_proto::version::ALPN.to_vec()];
    let q = quinn::crypto::rustls::QuicClientConfig::try_from(cfg).expect("quic tls");
    let mut ep = quinn::Endpoint::client(local).expect("endpoint");
    ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(q)));
    let conn = ep.connect(server, "hx.invalid").ok()?.await.ok()?;
    Some((ep, conn))
}

#[tokio::test]
async fn a_flood_of_silent_peers_cannot_stop_a_paired_device_logging_in() {
    let env = Env::new(SharedBudget::new(10)).await;
    let device = env.paired_device("laptop");
    // A pairing secret is live (otherwise unknown keys are refused at once), so unknown keys
    // may take general slots and the flood can fill them.
    let _token = env.auth.pairing().issue_token().expect("token");

    let server = env.server.quic_addr().expect("quic");
    // 6 networks (/24), 4 addresses each, 4 connections per address: more than the 64 slots.
    let mut flood = Vec::new();
    for net in 1..=6u8 {
        for host in 1..=4u8 {
            for _ in 0..4 {
                let local: SocketAddr = format!("127.{net}.0.{host}:0").parse().expect("addr");
                if let Some(p) = silent_peer(server, local, &new_key()).await {
                    flood.push(p);
                }
            }
        }
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let alive = flood
        .iter()
        .filter(|(_, c)| c.close_reason().is_none())
        .count();
    assert_eq!(alive, 64, "the general pool is exactly full");

    // One more unknown key is closed with BUSY: the pool really is full.
    let (_ep, extra) = silent_peer(server, "127.9.0.1:0".parse().expect("addr"), &new_key())
        .await
        .expect("TLS completes");
    match within(extra.closed()).await {
        quinn::ConnectionError::ApplicationClosed(ac) => {
            assert_eq!(
                ac.error_code.into_inner(),
                u64::from(CloseCode::Busy.code())
            );
        }
        other => panic!("unexpected close: {other}"),
    }

    // The paired device still completes its PIN login, from the same /24 as no flooder.
    let conn = within(connect_with_pin(
        &env.target(),
        &device,
        env.server_key.public(),
        &Pin::new(PIN).expect("pin"),
        &Env::session_opts(),
    ))
    .await
    .expect("a paired device logs in during the flood");
    drop(conn);
    drop(flood);
}

#[tokio::test]
async fn an_unknown_key_without_a_live_pairing_secret_gets_the_uniform_answers() {
    let mut env = Env::new(SharedBudget::new(10)).await;
    let stranger = new_key();
    let opts = Env::session_opts();

    // A session hello: uniform UNAUTHORIZED.
    let r = within(connect_session(
        &env.target(),
        &stranger,
        env.server_key.public(),
        &opts,
    ))
    .await;
    assert!(
        matches!(
            &r,
            Err(Error::Refused {
                reason: RefuseReason::Unauthorized,
                ..
            })
        ),
        "{r:?}"
    );

    // A pairing hello while pairing is closed: PAIRING_CLOSED, as before.
    let token = env.auth.pairing().issue_token().expect("token");
    let cred = PairingCredential::parse(&token.to_text()).expect("parse");
    env.auth.pairing().close();
    let r = within(pair_device(
        &env.target(),
        &stranger,
        &cred,
        &PairClientOptions {
            preference: PREF,
            device_name: "stranger".into(),
            ..Default::default()
        },
    ))
    .await;
    assert!(matches!(r, Err(Error::PairingClosed)), "{:?}", r.err());

    // Neither reached the application: no pending session was ever yielded.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(env.outcomes.try_recv().is_err());
}
