//! The `PinVerifier` hook: one test per verdict, and the race properties of the PIN login with
//! a slow asynchronous verifier (the shape of the gateway's check against `hx-privd`).

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
    Authenticator, AuthenticatorConfig, AwaitingPin, BoxFuture, Clock, DeviceId, DeviceRegistry,
    Error, IdentityKey, ManualClock, MemoryRegistry, Outcome, PairClientOptions, PairingCredential,
    Pin, PinReply, PinVerdict, PinVerifier, RevokeReason, SessionOptions, connect_session,
    connect_with_pin, pair_device, tls,
};
use hx_proto::{channel::CloseCode, pb::RefuseReason};
use hx_transport::{Server, ServerOptions, Target, TransportPreference};
use rustls::pki_types::ServerName;
use tokio::{sync::mpsc, task::JoinHandle};
use zeroize::Zeroizing;

const PREF: TransportPreference = TransportPreference::Quic;
const PIN: &str = "482913";
const LOCKED: PinVerdict = PinVerdict::Locked { retry_after: None };
const WAIT: Duration = Duration::from_secs(20);

async fn within<T>(f: impl Future<Output = T>) -> T {
    tokio::time::timeout(WAIT, f).await.expect("timed out")
}

fn new_key() -> Arc<IdentityKey> {
    Arc::new(IdentityKey::generate().expect("key"))
}

// ------------------------------------------------------------------ the scripted verifier

/// Answers from a script (then `fallback`) after an asynchronous delay, and records how many
/// checks ran, how many ran at the same time, and what it was given.
struct Scripted {
    script: Mutex<VecDeque<PinVerdict>>,
    fallback: PinVerdict,
    delay: Duration,
    has_pin: bool,
    calls: AtomicUsize,
    running: AtomicUsize,
    max_running: AtomicUsize,
    seen: Mutex<Vec<Vec<u8>>>,
}

impl Scripted {
    fn new(fallback: PinVerdict, delay: Duration) -> Arc<Self> {
        Arc::new(Self {
            script: Mutex::new(VecDeque::new()),
            fallback,
            delay,
            has_pin: true,
            calls: AtomicUsize::new(0),
            running: AtomicUsize::new(0),
            max_running: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
        })
    }

    fn without_pin() -> Arc<Self> {
        let mut s = Arc::try_unwrap(Self::new(PinVerdict::Wrong, Duration::ZERO))
            .unwrap_or_else(|_| unreachable!());
        s.has_pin = false;
        Arc::new(s)
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn max_running(&self) -> usize {
        self.max_running.load(Ordering::SeqCst)
    }
}

impl PinVerifier for Scripted {
    fn has_pin(&self, _device: &DeviceId) -> bool {
        self.has_pin
    }

    fn verify<'a>(
        &'a self,
        _device: &'a DeviceId,
        pin: Zeroizing<Vec<u8>>,
    ) -> BoxFuture<'a, PinVerdict> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.seen.lock().expect("lock").push(pin.to_vec());
            let now = self.running.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_running.fetch_max(now, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            self.running.fetch_sub(1, Ordering::SeqCst);
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

/// A server with a paired device and `v` installed as the PIN check.
async fn env(config: AuthenticatorConfig, v: &Arc<Scripted>) -> Env {
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
    e.pair().await;
    e.auth.set_pin_verifier(v.clone());
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
                device_name: "laptop".into(),
                ..Default::default()
            },
        ))
        .await
        .expect("pairing succeeds");
        let Outcome::Paired { connection, .. } = self.next().await.expect("outcome") else {
            panic!("expected Paired");
        };
        paired.finish().await;
        connection.close(CloseCode::NoError, "done").await;
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

    async fn open(&self) -> AwaitingPin {
        within(connect_session(
            &self.target(),
            &self.device,
            self.server_key.public(),
            &SessionOptions {
                preference: PREF,
                ..Default::default()
            },
        ))
        .await
        .expect("connect")
    }

    /// Every connection keeps guessing (up to its message budget), moving the clock a minute
    /// ahead before each attempt, so an attempt is held back only by the per-device guard and
    /// the failure limit, never by the backoff of an attempt that finished earlier. Stops on
    /// the first error (revoked, closed).
    async fn hammer(&self, conns: &mut [AwaitingPin], guess: &Pin) {
        let guess = &guess;
        within(join_all(
            conns
                .iter_mut()
                .map(|c| async move {
                    for _ in 0..5 {
                        self.clock.advance(Duration::from_secs(60));
                        if c.submit(guess).await.is_err() {
                            break;
                        }
                    }
                })
                .collect(),
        ))
        .await;
    }
}

fn pin(s: &str) -> Pin {
    Pin::new(s).expect("pin")
}

/// Poll futures to completion together (no extra dependency).
async fn join_all<T, F: Future<Output = T>>(fs: Vec<F>) -> Vec<T> {
    let mut set: Vec<_> = fs.into_iter().map(Box::pin).collect();
    let mut out: Vec<Option<T>> = set.iter().map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut pending = false;
        for (i, f) in set.iter_mut().enumerate() {
            if out[i].is_none() {
                match f.as_mut().poll(cx) {
                    std::task::Poll::Ready(v) => out[i] = Some(v),
                    std::task::Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(())
        }
    })
    .await;
    out.into_iter().flatten().collect()
}

// ------------------------------------------------------------------ one test per verdict

#[tokio::test]
async fn right_authorizes_clears_the_counter_and_hands_over_the_digits() {
    let v = Scripted::new(PinVerdict::Right, Duration::from_millis(20));
    let mut e = env(AuthenticatorConfig::default(), &v).await;
    e.registry.begin_pin_attempt(&e.id()).expect("count");
    e.clock.advance(Duration::from_secs(5));
    let mut c = e.open().await;
    let r = within(c.submit(&pin(PIN))).await;
    assert_eq!(r.expect("reply"), PinReply::Accepted);
    assert!(matches!(
        e.next().await.expect("outcome"),
        Outcome::Authorized { .. }
    ));
    let rec = e.registry.get(&e.id()).expect("reg").expect("dev");
    assert_eq!(rec.failed_pins, 0);
    assert_eq!(rec.last_seen_unix, e.clock.unix_secs());
    assert_eq!(*v.seen.lock().expect("lock"), vec![PIN.as_bytes().to_vec()]);
}

#[tokio::test]
async fn wrong_counts_backs_off_and_the_fifth_revokes() {
    let v = Scripted::new(PinVerdict::Wrong, Duration::from_millis(10));
    let e = env(
        AuthenticatorConfig {
            max_pin_messages: 10,
            ..Default::default()
        },
        &v,
    )
    .await;
    let mut c = e.open().await;
    let r = within(c.submit(&pin("000000"))).await.expect("reply");
    assert_eq!(
        r,
        PinReply::Wrong {
            attempts_left: 4,
            retry_after: Duration::from_secs(1)
        }
    );
    // Too soon: neither verified nor counted.
    let r = within(c.submit(&pin("000000"))).await.expect("reply");
    assert!(matches!(r, PinReply::Backoff { .. }), "{r:?}");
    assert_eq!((v.calls(), e.failed()), (1, 1));
    for (n, wait) in [(2u32, 2u64), (3, 4), (4, 8)] {
        e.clock.advance(Duration::from_secs(wait));
        let r = within(c.submit(&pin("000000"))).await.expect("reply");
        assert!(
            matches!(r, PinReply::Wrong { attempts_left, .. } if attempts_left == 5 - n),
            "{n}: {r:?}"
        );
    }
    e.clock.advance(Duration::from_secs(60));
    let r = within(c.submit(&pin("000000"))).await;
    assert!(matches!(r, Err(Error::Revoked)), "{r:?}");
    assert_eq!(v.calls(), 5);
    let rec = e.registry.get(&e.id()).expect("reg").expect("dev");
    assert_eq!(
        rec.revoked.expect("revoked").reason,
        RevokeReason::TooManyPinFailures
    );
}

#[tokio::test]
async fn unavailable_is_refunded_exactly_once_never_revokes_and_holds_the_device() {
    let v = Scripted::new(PinVerdict::Unavailable, Duration::from_millis(10));
    let e = env(
        AuthenticatorConfig {
            max_pin_messages: 40,
            ..Default::default()
        },
        &v,
    )
    .await;
    // Four earlier failures on record: one more *counted* failure would revoke.
    for _ in 0..4 {
        e.registry.begin_pin_attempt(&e.id()).expect("count");
    }
    let mut revocations = e.auth.subscribe_revocations();
    let mut c = e.open().await;
    for round in 1..=12usize {
        let r = within(c.submit(&pin("000000"))).await.expect("reply");
        assert_eq!(
            r,
            PinReply::Backoff {
                retry_after: Duration::from_secs(2)
            },
            "round {round}"
        );
        // Counted before the check and refunded once after it: back exactly where it was
        // (a double refund would show as 3).
        assert_eq!(e.failed(), 4, "round {round}");
        assert_eq!(v.calls(), round);
        // The hold told to the client is enforced: no new check, nothing counted.
        let r = within(c.submit(&pin("000000"))).await.expect("reply");
        assert!(matches!(r, PinReply::Backoff { .. }), "{r:?}");
        assert_eq!(v.calls(), round);
        assert_eq!(e.failed(), 4);
        e.clock.advance(Duration::from_secs(3));
        if round % 2 == 0 {
            // A fresh connection (a connection has a message budget).
            c = e.open().await;
        }
    }
    let rec = e.registry.get(&e.id()).expect("reg").expect("dev");
    assert!(!rec.is_revoked());
    assert_eq!(rec.last_seen_unix, 0);
    assert!(revocations.try_recv().is_err(), "nothing was announced");

    // A later definite "no" counts from where it was: the 5th failure revokes.
    e.auth
        .set_pin_verifier(Scripted::new(PinVerdict::Wrong, Duration::ZERO));
    let r = within(c.submit(&pin("000000"))).await;
    assert!(matches!(r, Err(Error::Revoked)), "{r:?}");
}

#[tokio::test]
async fn locked_refuses_with_not_available_and_refunds() {
    let v = Scripted::new(LOCKED, Duration::from_millis(10));
    let e = env(AuthenticatorConfig::default(), &v).await;
    e.registry.begin_pin_attempt(&e.id()).expect("count");
    let mut c = e.open().await;
    let r = within(c.submit(&pin("000000"))).await;
    assert!(matches!(r, Err(Error::PinNotAvailable)), "{r:?}");
    let rec = e.registry.get(&e.id()).expect("reg").expect("dev");
    assert_eq!(rec.failed_pins, 1, "back to the earlier count");
    assert!(!rec.is_revoked());
    assert_eq!(v.calls(), 1);
}

#[tokio::test]
async fn locked_sets_the_verifiers_wait_and_attempts_during_it_are_not_counted() {
    let v = Scripted::new(
        PinVerdict::Locked {
            retry_after: Some(Duration::from_secs(7)),
        },
        Duration::from_millis(10),
    );
    let e = env(AuthenticatorConfig::default(), &v).await;
    e.registry.begin_pin_attempt(&e.id()).expect("count");
    let r = within(e.open().await.submit(&pin("000000"))).await;
    assert!(matches!(r, Err(Error::PinNotAvailable)), "{r:?}");
    assert_eq!((v.calls(), e.failed()), (1, 1));

    // Parallel attempts during the wait: BACKOFF with what is left, never verified, never
    // counted, never revoking.
    e.clock.advance(Duration::from_secs(2));
    let mut conns = vec![e.open().await, e.open().await, e.open().await];
    let replies = within(join_all(
        conns
            .iter_mut()
            .map(|c| async move { c.submit(&pin("000000")).await })
            .collect(),
    ))
    .await;
    for r in replies {
        assert_eq!(
            r.expect("reply"),
            PinReply::Backoff {
                retry_after: Duration::from_secs(5)
            }
        );
    }
    assert_eq!((v.calls(), e.failed()), (1, 1));
    assert!(
        !e.registry
            .get(&e.id())
            .expect("reg")
            .expect("dev")
            .is_revoked()
    );

    // After the wait the verifier is asked again (and is still locked).
    e.clock.advance(Duration::from_secs(5));
    let r = within(e.open().await.submit(&pin("000000"))).await;
    assert!(matches!(r, Err(Error::PinNotAvailable)), "{r:?}");
    assert_eq!((v.calls(), e.failed()), (2, 1));
}

#[tokio::test]
async fn is_backing_off_covers_wrong_pin_backoff_locked_and_unavailable_holds() {
    // Wrong PIN: 1 s after the first failure.
    let v = Scripted::new(PinVerdict::Wrong, Duration::ZERO);
    let e = env(AuthenticatorConfig::default(), &v).await;
    assert!(!e.auth.is_backing_off(&e.id()));
    let r = within(e.open().await.submit(&pin("000000"))).await;
    assert!(matches!(r, Ok(PinReply::Wrong { .. })), "{r:?}");
    assert!(e.auth.is_backing_off(&e.id()));
    assert_eq!(e.auth.backoff_remaining(&e.id()), Duration::from_secs(1));
    e.clock.advance(Duration::from_millis(999));
    assert!(e.auth.is_backing_off(&e.id()));
    e.clock.advance(Duration::from_millis(1));
    assert!(!e.auth.is_backing_off(&e.id()));
    // Other devices are unaffected.
    assert!(
        !e.auth
            .is_backing_off(&IdentityKey::generate().expect("k").public().device_id())
    );

    // Locked: the verifier's wait.
    e.auth.set_pin_verifier(Scripted::new(
        PinVerdict::Locked {
            retry_after: Some(Duration::from_secs(9)),
        },
        Duration::ZERO,
    ));
    let r = within(e.open().await.submit(&pin("000000"))).await;
    assert!(matches!(r, Err(Error::PinNotAvailable)), "{r:?}");
    assert_eq!(e.auth.backoff_remaining(&e.id()), Duration::from_secs(9));
    e.clock.advance(Duration::from_secs(9));
    assert!(!e.auth.is_backing_off(&e.id()));

    // Unavailable: the 2 s hold; an operator reset drops it.
    e.auth
        .set_pin_verifier(Scripted::new(PinVerdict::Unavailable, Duration::ZERO));
    let r = within(e.open().await.submit(&pin("000000"))).await;
    assert!(matches!(r, Ok(PinReply::Backoff { .. })), "{r:?}");
    assert!(e.auth.is_backing_off(&e.id()));
    e.auth.reset_lockout(&e.id()).await.expect("reset");
    assert!(!e.auth.is_backing_off(&e.id()));
}

#[tokio::test]
async fn locked_without_a_wait_holds_the_device_for_the_default() {
    let v = Scripted::new(LOCKED, Duration::ZERO);
    let e = env(AuthenticatorConfig::default(), &v).await;
    let r = within(e.open().await.submit(&pin("000000"))).await;
    assert!(matches!(r, Err(Error::PinNotAvailable)), "{r:?}");
    let r = within(e.open().await.submit(&pin("000000"))).await;
    assert_eq!(
        r.expect("reply"),
        PinReply::Backoff {
            retry_after: hx_crypto::DEFAULT_LOCKED_WAIT
        }
    );
    assert_eq!(v.calls(), 1);
    assert_eq!(e.failed(), 0);
}

#[tokio::test]
async fn a_device_the_verifier_has_no_pin_for_is_refused_before_anything_is_asked() {
    let v = Scripted::without_pin();
    let mut e = env(AuthenticatorConfig::default(), &v).await;
    let r = within(connect_with_pin(
        &e.target(),
        &e.device,
        e.server_key.public(),
        &pin(PIN),
        &SessionOptions {
            preference: PREF,
            ..Default::default()
        },
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
    assert!(matches!(
        e.next().await,
        Ok(Outcome::Refused(RefuseReason::Unauthorized))
    ));
    assert_eq!((v.calls(), e.failed()), (0, 0));
}

#[tokio::test]
async fn a_local_pin_hash_is_a_verifier_and_set_pin_is_unchanged() {
    use hx_crypto::{PinHash, PinParams};
    let cheap = PinParams {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    };
    let v = Scripted::new(PinVerdict::Wrong, Duration::ZERO);
    let mut e = env(AuthenticatorConfig::default(), &v).await;
    // Through set_pin_verifier with the hash itself ...
    e.auth.set_pin_verifier(Arc::new(
        PinHash::with_params(&pin(PIN), cheap).expect("hash"),
    ));
    let mut c = e.open().await;
    assert!(matches!(
        within(c.submit(&pin("000000"))).await,
        Ok(PinReply::Wrong { .. })
    ));
    e.clock.advance(Duration::from_secs(5));
    assert_eq!(
        within(c.submit(&pin(PIN))).await.expect("reply"),
        PinReply::Accepted
    );
    assert!(matches!(
        e.next().await.expect("outcome"),
        Outcome::Authorized { .. }
    ));
    // ... and the custom verifier was never consulted.
    assert_eq!(v.calls(), 0);
}

#[tokio::test]
async fn reset_lockout_clears_the_counter_and_the_wait_without_stamping_last_seen() {
    let v = Scripted::new(PinVerdict::Wrong, Duration::ZERO);
    let e = env(AuthenticatorConfig::default(), &v).await;
    let mut c = e.open().await;
    assert!(matches!(
        within(c.submit(&pin("000000"))).await,
        Ok(PinReply::Wrong { .. })
    ));
    assert!(matches!(
        within(c.submit(&pin("000000"))).await,
        Ok(PinReply::Backoff { .. })
    ));
    assert_eq!(e.failed(), 1);
    assert!(e.auth.reset_lockout(&e.id()).await.expect("reset"));
    assert_eq!(e.failed(), 0);
    let rec = e.registry.get(&e.id()).expect("reg").expect("dev");
    assert_eq!(rec.last_seen_unix, 0);
    // The wait is gone: the next attempt is verified at once.
    assert!(matches!(
        within(c.submit(&pin("000000"))).await,
        Ok(PinReply::Wrong { .. })
    ));
    assert_eq!(v.calls(), 2);
    assert!(
        !e.auth
            .reset_lockout(&new_key().public().device_id())
            .await
            .expect("unknown")
    );
}

// ------------------------------------------------------------------ races with a slow verifier

#[tokio::test]
async fn parallel_guessing_with_a_slow_async_verifier_is_serialised_and_backed_off() {
    let v = Scripted::new(PinVerdict::Wrong, Duration::from_millis(300));
    let e = env(AuthenticatorConfig::default(), &v).await;
    let wrong = pin("111111");
    let mut conns = Vec::new();
    for _ in 0..4 {
        conns.push(e.open().await);
    }
    // All four guess at once while the first verification is still pending.
    let replies = within(join_all(
        conns.iter_mut().map(|c| c.submit(&wrong)).collect(),
    ))
    .await;
    let evaluated = replies
        .iter()
        .filter(|r| matches!(r, Ok(PinReply::Wrong { .. })))
        .count();
    let backed_off = replies
        .iter()
        .filter(|r| matches!(r, Ok(PinReply::Backoff { .. })))
        .count();
    assert_eq!((evaluated, backed_off), (1, 3), "{replies:?}");
    assert_eq!(v.calls(), 1, "no extra guess reached the verifier");
    assert_eq!(v.max_running(), 1);
    assert_eq!(e.failed(), 1);
}

#[tokio::test]
async fn parallel_attempts_during_a_pending_unavailable_get_no_extra_checks() {
    let v = Scripted::new(PinVerdict::Unavailable, Duration::from_millis(300));
    let e = env(AuthenticatorConfig::default(), &v).await;
    let wrong = pin("111111");
    let mut conns = Vec::new();
    for _ in 0..4 {
        conns.push(e.open().await);
    }
    let replies = within(join_all(
        conns.iter_mut().map(|c| c.submit(&wrong)).collect(),
    ))
    .await;
    assert!(
        replies
            .iter()
            .all(|r| matches!(r, Ok(PinReply::Backoff { .. }))),
        "{replies:?}"
    );
    assert_eq!(v.calls(), 1, "the others were held, not verified");
    assert_eq!(v.max_running(), 1);
    assert_eq!(e.failed(), 0);
}

#[tokio::test]
async fn parallel_connections_never_verify_two_pins_at_once() {
    // The backoff never decides anything here, so only the per-device guard is under test.
    let v = Scripted::new(PinVerdict::Wrong, Duration::from_millis(40));
    let e = env(
        AuthenticatorConfig {
            max_pin_failures: 50,
            ..Default::default()
        },
        &v,
    )
    .await;
    let wrong = pin("111111");
    let mut conns = Vec::new();
    for _ in 0..4 {
        conns.push(e.open().await);
    }
    e.hammer(&mut conns, &wrong).await;
    assert!(v.calls() >= 4, "the verifier was really exercised");
    assert_eq!(v.max_running(), 1, "one verification at a time per device");
    // Every check that ran was counted, none twice and none lost.
    assert_eq!(e.failed() as usize, v.calls());
}

#[tokio::test]
async fn parallel_connections_cannot_beat_the_failure_limit_with_a_slow_verifier() {
    // 4 connections guess at once, failure limit 2, no waiting between attempts: exactly 2
    // checks may run before the device is revoked, never more.
    let v = Scripted::new(PinVerdict::Wrong, Duration::from_millis(100));
    let e = env(
        AuthenticatorConfig {
            max_pin_failures: 2,
            ..Default::default()
        },
        &v,
    )
    .await;
    let wrong = pin("111111");
    let mut conns = Vec::new();
    for _ in 0..4 {
        conns.push(e.open().await);
    }
    e.hammer(&mut conns, &wrong).await;
    assert_eq!(v.calls(), 2, "exactly the limit, never more");
    assert_eq!(v.max_running(), 1);
    assert!(
        e.registry
            .get(&e.id())
            .expect("reg")
            .expect("dev")
            .is_revoked()
    );
}

// ------------------------------------------------------------------ the deadline

fn short_deadline() -> AuthenticatorConfig {
    AuthenticatorConfig {
        pin_timeout: Duration::from_millis(400),
        min_hash_budget: Duration::from_millis(10),
        ..Default::default()
    }
}

async fn settle_failed(e: &Env, at_least: u32) -> u32 {
    let mut last = 0;
    for _ in 0..300 {
        last = e.failed();
        if last >= at_least {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    last
}

#[tokio::test]
async fn a_deadline_cut_during_a_slow_verification_still_counts() {
    let v = Scripted::new(PinVerdict::Wrong, Duration::from_millis(1500));
    let e = env(short_deadline(), &v).await;
    let mut c = e.open().await;
    let r = within(c.submit(&pin("000000"))).await;
    assert!(r.is_err(), "the exchange was cut off: {r:?}");
    // Counted before the verifier started, although the caller is gone ...
    assert_eq!(settle_failed(&e, 1).await, 1);
    // ... and the detached unit still finishes and sets the backoff when it does.
    tokio::time::sleep(Duration::from_millis(1700)).await;
    assert_eq!(e.failed(), 1);
    let mut c = e.open().await;
    let r = within(c.submit(&pin(PIN))).await;
    assert!(matches!(r, Ok(PinReply::Backoff { .. })), "{r:?}");
    assert_eq!(v.calls(), 1);
}

#[tokio::test]
async fn a_cut_off_unavailable_attempt_is_still_refunded() {
    let v = Scripted::new(PinVerdict::Unavailable, Duration::from_millis(1200));
    let e = env(short_deadline(), &v).await;
    let mut c = e.open().await;
    let r = within(c.submit(&pin("000000"))).await;
    assert!(r.is_err(), "the exchange was cut off: {r:?}");
    assert_eq!(settle_failed(&e, 1).await, 1, "counted while pending");
    for _ in 0..100 {
        if e.failed() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(e.failed(), 0, "refunded when the verifier gave up");
}
