//! End-to-end pairing and authentication over loopback, on both QUIC and WebSocket.

use std::{future::Future, sync::Arc, time::Duration};

use hx_crypto::{
    Authenticator, AuthenticatorConfig, DeviceRegistry, Error, IdentityKey, ManualClock,
    MemoryRegistry, Outcome, PairClientOptions, PairingCredential, PairingLimits, PairingToken,
    Pin, PinHash, PinParams, PinReply, RevokeReason, SessionOptions, connect_session,
    connect_with_pin, pair_device, tls,
};
use hx_proto::{
    channel::CloseCode,
    pb::{Intent, RefuseReason},
    version::{Features, capabilities},
};
use hx_transport::{
    Client, ClientHello, ClientOptions, Server, ServerHello, ServerOptions, Target,
    TransportPreference,
};
use rustls::pki_types::ServerName;
use tokio::{sync::mpsc, task::JoinHandle};

const WAIT: Duration = Duration::from_secs(15);
const BOTH: [TransportPreference; 2] = [TransportPreference::Quic, TransportPreference::WebSocket];
const PIN: &str = "482913";
const CHEAP: PinParams = PinParams {
    memory_kib: 64,
    iterations: 1,
    parallelism: 1,
};

async fn within<T>(f: impl Future<Output = T>) -> T {
    tokio::time::timeout(WAIT, f).await.expect("timed out")
}

fn new_key() -> Arc<IdentityKey> {
    Arc::new(IdentityKey::generate().expect("key"))
}

fn target(s: &Server, pref: TransportPreference) -> Target {
    let addr = if pref == TransportPreference::WebSocket {
        s.websocket_addr().expect("ws addr")
    } else {
        s.quic_addr().expect("quic addr")
    };
    Target {
        addr,
        server_name: ServerName::try_from("hx.invalid").expect("name"),
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

async fn env_with(config: AuthenticatorConfig) -> Env {
    let server_key = new_key();
    let registry = Arc::new(MemoryRegistry::new());
    let clock = Arc::new(ManualClock::new());
    let auth =
        Authenticator::with_clock(server_key.clone(), registry.clone(), config, clock.clone());
    auth.set_pin(PinHash::with_params(&Pin::new(PIN).expect("pin"), CHEAP).expect("hash"));
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

async fn env() -> Env {
    env_with(AuthenticatorConfig {
        session_features: Features::defined_up_to(0),
        capabilities: capabilities(&[hx_proto::VideoCodec::H264], Features::defined_up_to(0)),
        ..Default::default()
    })
    .await
}

fn pair_opts(pref: TransportPreference, name: &str) -> PairClientOptions {
    PairClientOptions {
        preference: pref,
        device_name: name.into(),
        ..Default::default()
    }
}

fn session_opts(pref: TransportPreference) -> SessionOptions {
    SessionOptions {
        preference: pref,
        capabilities: capabilities(&[hx_proto::VideoCodec::H264], Features::defined_up_to(0)),
        ..Default::default()
    }
}

impl Env {
    async fn next(&mut self) -> hx_crypto::Result<Outcome> {
        within(self.outcomes.recv()).await.expect("an outcome")
    }

    /// Pair `device` with a fresh token and finish both sides.
    async fn pair(&mut self, device: &Arc<IdentityKey>, pref: TransportPreference) {
        let token = self.auth.pairing().issue_token().expect("token");
        let cred = PairingCredential::parse(&token.to_text()).expect("parse");
        let t = target(&self.server, pref);
        let paired = within(pair_device(
            &t,
            device,
            &cred,
            &pair_opts(pref, "my laptop"),
        ))
        .await
        .expect("pairing succeeds");
        assert_eq!(paired.server_key, self.server_key.public());
        let Outcome::Paired { connection, .. } = self.next().await.expect("server outcome") else {
            panic!("expected Paired");
        };
        paired.finish().await;
        connection.close(CloseCode::NoError, "done").await;
    }
}

// ------------------------------------------------------------------ pairing

#[tokio::test]
async fn pairing_with_a_long_token_pins_both_keys_and_is_single_use() {
    for pref in BOTH {
        let mut e = env().await;
        let device = new_key();
        let token = e.auth.pairing().issue_token().expect("token");
        let cred = PairingCredential::parse(&token.to_text()).expect("parse");
        let t = target(&e.server, pref);

        let paired = within(pair_device(
            &t,
            &device,
            &cred,
            &pair_opts(pref, "my laptop"),
        ))
        .await
        .unwrap_or_else(|e| panic!("{pref:?}: {e}"));
        assert_eq!(paired.server_key, e.server_key.public(), "{pref:?}");
        let Outcome::Paired {
            connection,
            device: rec,
        } = e.next().await.expect("outcome")
        else {
            panic!("expected Paired");
        };
        assert_eq!(rec.public_key, device.public());
        assert_eq!(rec.name, "my laptop");
        assert_eq!(
            e.registry
                .find_by_key(&device.public())
                .expect("reg")
                .expect("stored")
                .id,
            device.public().device_id()
        );
        paired.finish().await;
        connection.close(CloseCode::NoError, "done").await;

        // Single use: the same token cannot pair another device.
        let other = new_key();
        let again = within(pair_device(&t, &other, &cred, &pair_opts(pref, "second"))).await;
        assert!(
            matches!(again, Err(Error::PairingClosed)),
            "{pref:?}: {again:?}"
        );
        assert!(matches!(
            e.next().await,
            Ok(Outcome::Refused(RefuseReason::PairingClosed))
        ));
        assert!(
            e.registry
                .find_by_key(&other.public())
                .expect("reg")
                .is_none()
        );
    }
}

#[tokio::test]
async fn a_used_token_fails_while_the_window_is_still_open() {
    for pref in BOTH {
        let mut e = env().await;
        let token = e.auth.pairing().issue_token().expect("token");
        let cred = PairingCredential::parse(&token.to_text()).expect("parse");
        let _keep_open = e.auth.pairing().issue_token().expect("second token");
        let t = target(&e.server, pref);
        let first = new_key();
        within(pair_device(&t, &first, &cred, &pair_opts(pref, "a")))
            .await
            .expect("first use");
        let _ = e.next().await;
        let second = new_key();
        let r = within(pair_device(&t, &second, &cred, &pair_opts(pref, "b"))).await;
        assert!(matches!(r, Err(Error::PairingFailed)), "{pref:?}: {r:?}");
        assert!(matches!(e.next().await, Err(Error::PairingFailed)));
        assert!(
            e.registry
                .find_by_key(&second.public())
                .expect("reg")
                .is_none()
        );
    }
}

#[tokio::test]
async fn pairing_with_a_short_code() {
    for pref in BOTH {
        let mut e = env().await;
        let device = new_key();
        let code = e.auth.pairing().issue_code().expect("code");
        // What a person types: lower case, a space instead of the dash.
        let typed = code.to_text().to_lowercase().replace('-', " ");
        let cred = PairingCredential::parse(&typed).expect("parse");
        let t = target(&e.server, pref);
        let paired = within(pair_device(&t, &device, &cred, &pair_opts(pref, "phone")))
            .await
            .unwrap_or_else(|e| panic!("{pref:?}: {e}"));
        assert_eq!(paired.server_key, e.server_key.public());
        let Outcome::Paired { connection, .. } = e.next().await.expect("outcome") else {
            panic!("expected Paired");
        };
        paired.finish().await;
        connection.close(CloseCode::NoError, "done").await;
        // The code is spent.
        assert!(!e.auth.pairing().is_open());
    }
}

#[tokio::test]
async fn a_short_code_survives_only_three_wrong_guesses() {
    for pref in BOTH {
        let mut e = env().await;
        let code = e.auth.pairing().issue_code().expect("code");
        let right = PairingCredential::parse(&code.to_text()).expect("parse");
        let wrong_text = if code.to_text().starts_with('A') {
            "B234-5678"
        } else {
            "A234-5678"
        };
        let wrong = PairingCredential::parse(wrong_text).expect("parse");
        let t = target(&e.server, pref);
        for n in 1..=3 {
            let r = within(pair_device(&t, &new_key(), &wrong, &pair_opts(pref, "x"))).await;
            assert!(
                matches!(r, Err(Error::PairingFailed)),
                "{pref:?} guess {n}: {r:?}"
            );
            assert!(matches!(e.next().await, Err(Error::PairingFailed)));
        }
        // The code is now invalid: even the right code is refused.
        assert!(!e.auth.pairing().is_open(), "{pref:?}");
        let device = new_key();
        let r = within(pair_device(&t, &device, &right, &pair_opts(pref, "x"))).await;
        assert!(matches!(r, Err(Error::PairingClosed)), "{pref:?}: {r:?}");
        assert!(e.registry.list().expect("list").is_empty());
    }
}

#[tokio::test]
async fn the_right_code_after_two_wrong_guesses_still_works() {
    let pref = TransportPreference::Quic;
    let mut e = env().await;
    let code = e.auth.pairing().issue_code().expect("code");
    let right = PairingCredential::parse(&code.to_text()).expect("parse");
    let wrong_text = if code.to_text().starts_with('A') {
        "B234-5678"
    } else {
        "A234-5678"
    };
    let wrong = PairingCredential::parse(wrong_text).expect("parse");
    let t = target(&e.server, pref);
    for _ in 0..2 {
        let _ = within(pair_device(&t, &new_key(), &wrong, &pair_opts(pref, "x"))).await;
        let _ = e.next().await;
    }
    let p = within(pair_device(&t, &new_key(), &right, &pair_opts(pref, "x")))
        .await
        .expect("third attempt with the right code");
    let _ = e.next().await;
    p.finish().await;
}

#[tokio::test]
async fn expired_tokens_and_codes_are_refused() {
    for pref in BOTH {
        let mut e = env().await;
        let token = e.auth.pairing().issue_token().expect("token");
        let code = e.auth.pairing().issue_code().expect("code");
        let t = target(&e.server, pref);
        e.clock.advance(Duration::from_secs(15 * 60 + 1));
        for text in [token.to_text().to_string(), code.to_text().to_string()] {
            let cred = PairingCredential::parse(&text).expect("parse");
            let r = within(pair_device(&t, &new_key(), &cred, &pair_opts(pref, "x"))).await;
            assert!(matches!(r, Err(Error::PairingClosed)), "{pref:?}: {r:?}");
            assert!(matches!(
                e.next().await,
                Ok(Outcome::Refused(RefuseReason::PairingClosed))
            ));
        }
        assert!(e.registry.list().expect("list").is_empty());
    }
}

#[tokio::test]
async fn an_installed_token_pairs_once_and_a_wrong_one_fails_the_same_way() {
    for pref in BOTH {
        let mut e = env().await;
        // The installer created this token; the server only installs it.
        let token = PairingToken::generate().expect("token");
        e.auth
            .pairing()
            .install_token(&token, Duration::from_secs(10 * 60))
            .expect("install");
        let cred = PairingCredential::parse(&token.to_text()).expect("parse");
        let t = target(&e.server, pref);

        // A different secret under the same id fails like any wrong token.
        let mut forged = token.to_text().to_string();
        forged.pop();
        forged.push(if forged.ends_with('0') { '1' } else { '0' });
        if let Ok(forged) = PairingCredential::parse(&forged) {
            let r = within(pair_device(&t, &new_key(), &forged, &pair_opts(pref, "x"))).await;
            assert!(matches!(r, Err(Error::PairingFailed)), "{pref:?}: {r:?}");
            assert!(matches!(e.next().await, Err(Error::PairingFailed)));
        }

        let device = new_key();
        let paired = within(pair_device(&t, &device, &cred, &pair_opts(pref, "laptop")))
            .await
            .unwrap_or_else(|e| panic!("{pref:?}: {e}"));
        assert_eq!(paired.server_key, e.server_key.public());
        let Outcome::Paired { connection, .. } = e.next().await.expect("outcome") else {
            panic!("expected Paired");
        };
        paired.finish().await;
        connection.close(CloseCode::NoError, "done").await;

        // Single use.
        let r = within(pair_device(
            &t,
            &new_key(),
            &cred,
            &pair_opts(pref, "again"),
        ))
        .await;
        assert!(matches!(r, Err(Error::PairingClosed)), "{pref:?}: {r:?}");
        let _ = e.next().await;
        assert_eq!(e.registry.list().expect("list").len(), 1);
    }
}

#[tokio::test]
async fn an_installed_token_expires_at_its_ttl() {
    let pref = TransportPreference::Quic;
    let mut e = env().await;
    let token = PairingToken::generate().expect("token");
    e.auth
        .pairing()
        .install_token(&token, Duration::from_secs(60))
        .expect("install");
    let cred = PairingCredential::parse(&token.to_text()).expect("parse");
    e.clock.advance(Duration::from_secs(61));
    let t = target(&e.server, pref);
    let r = within(pair_device(&t, &new_key(), &cred, &pair_opts(pref, "x"))).await;
    assert!(matches!(r, Err(Error::PairingClosed)), "{r:?}");
    assert!(matches!(
        e.next().await,
        Ok(Outcome::Refused(RefuseReason::PairingClosed))
    ));
}

#[tokio::test]
async fn expiry_applies_while_another_secret_keeps_the_window_open() {
    let pref = TransportPreference::Quic;
    let mut e = env().await;
    let old = e.auth.pairing().issue_token().expect("old");
    e.clock.advance(Duration::from_secs(14 * 60));
    let _fresh = e.auth.pairing().issue_token().expect("fresh");
    e.clock.advance(Duration::from_secs(2 * 60));
    let cred = PairingCredential::parse(&old.to_text()).expect("parse");
    let t = target(&e.server, pref);
    let r = within(pair_device(&t, &new_key(), &cred, &pair_opts(pref, "x"))).await;
    assert!(matches!(r, Err(Error::PairingFailed)), "{r:?}");
    assert!(matches!(e.next().await, Err(Error::PairingFailed)));
}

// ------------------------------------------------------------------ man in the middle

/// An attacker with his own server key and his own device key relays the pairing messages
/// between the victim and the real server.
async fn start_mitm(real: Target, pref: TransportPreference) -> (Arc<Server>, JoinHandle<()>) {
    let (attacker_server_key, attacker_device_key) = (new_key(), new_key());
    let srv = Arc::new(
        Server::bind(
            "127.0.0.1:0".parse().expect("addr"),
            tls::server_config(&attacker_server_key).expect("tls"),
            ServerOptions::default(),
        )
        .await
        .expect("bind"),
    );
    let s2 = srv.clone();
    let task = tokio::spawn(async move {
        while let Some(p) = s2.accept().await {
            let (real, key) = (real.clone(), attacker_device_key.clone());
            tokio::spawn(async move {
                let Ok(down) = p
                    .accept(ServerHello {
                        capabilities: capabilities(&[], Features::NONE),
                        software: "mitm".into(),
                    })
                    .await
                else {
                    return;
                };
                let client = Client::new(
                    tls::client_config_pairing(&key).expect("cfg"),
                    ClientOptions {
                        preference: pref,
                        ..Default::default()
                    },
                );
                let Ok(up) = client
                    .connect(
                        &real,
                        &ClientHello {
                            capabilities: capabilities(&[], Features::NONE),
                            intent: Intent::Pair,
                            software: "mitm".into(),
                            device_name: "attacker".into(),
                        },
                    )
                    .await
                else {
                    return;
                };
                loop {
                    tokio::select! {
                        m = down.recv_control() => match m {
                            Ok(m) => if up.send_control(&m).await.is_err() { break },
                            Err(_) => break,
                        },
                        m = up.recv_control() => match m {
                            Ok(m) => if down.send_control(&m).await.is_err() { break },
                            Err(_) => break,
                        },
                    }
                }
                up.close(CloseCode::NoError, "done").await;
                down.close(CloseCode::NoError, "done").await;
            });
        }
    });
    (srv, task)
}

#[tokio::test]
async fn a_man_in_the_middle_is_detected_and_pairs_nothing() {
    for pref in BOTH {
        let mut e = env().await;
        let token = e.auth.pairing().issue_token().expect("token");
        let cred = PairingCredential::parse(&token.to_text()).expect("parse");
        let (mitm, _task) = start_mitm(target(&e.server, pref), pref).await;

        let victim = new_key();
        let r = within(pair_device(
            &target(&mitm, pref),
            &victim,
            &cred,
            &pair_opts(pref, "victim"),
        ))
        .await;
        assert!(
            matches!(
                r,
                Err(Error::PairingFailed | Error::Transport(_) | Error::Protocol(_))
            ),
            "{pref:?}: the victim must not accept the relayed pairing: {r:?}"
        );
        // The real server did not register the attacker's key or the victim's.
        assert!(
            matches!(e.next().await, Err(Error::PairingFailed)),
            "{pref:?}"
        );
        assert!(e.registry.list().expect("list").is_empty(), "{pref:?}");

        // The token was not consumed (only an attempt was): the real user still pairs.
        let t = target(&e.server, pref);
        let ok = within(pair_device(&t, &victim, &cred, &pair_opts(pref, "victim")))
            .await
            .expect("direct pairing still works");
        assert_eq!(ok.server_key, e.server_key.public());
        let _ = e.next().await;
        ok.finish().await;
    }
}

// ------------------------------------------------------------------ sessions and PIN

#[tokio::test]
async fn a_session_with_the_right_pin_is_authorized_and_usable() {
    for pref in BOTH {
        let mut e = env().await;
        let device = new_key();
        e.pair(&device, pref).await;

        let t = target(&e.server, pref);
        let pin = Pin::new(PIN).expect("pin");
        let conn = within(connect_with_pin(
            &t,
            &device,
            e.server_key.public(),
            &pin,
            &session_opts(pref),
        ))
        .await
        .unwrap_or_else(|e| panic!("{pref:?}: {e}"));
        let Outcome::Authorized {
            connection: srv,
            device: rec,
        } = e.next().await.expect("outcome")
        else {
            panic!("expected Authorized");
        };
        assert!(srv.is_authorized(), "{pref:?}");
        assert_eq!(rec.public_key, device.public());
        // The authorized channel works: input travels client to server.
        within(conn.send_input(&hx_proto::pb::InputEvent::default()))
            .await
            .ok();
        within(conn.ping(WAIT)).await.expect("ping");
        let stored = e.registry.get(&rec.id).expect("reg").expect("device");
        assert_eq!(stored.failed_pins, 0);
        assert!(stored.last_seen_unix > 0);
    }
}

#[tokio::test]
async fn wrong_pins_back_off_and_the_fifth_revokes_the_device() {
    for pref in BOTH {
        let mut e = env().await;
        let device = new_key();
        e.pair(&device, pref).await;
        let t = target(&e.server, pref);
        let wrong = Pin::new("000000").expect("pin");
        let right = Pin::new(PIN).expect("pin");
        let opts = session_opts(pref);
        let id = device.public().device_id();

        let mut c1 = within(connect_session(&t, &device, e.server_key.public(), &opts))
            .await
            .expect("connect");
        // 1st wrong PIN.
        let r = within(c1.submit(&wrong)).await.expect("reply");
        assert_eq!(
            r,
            PinReply::Wrong {
                attempts_left: 4,
                retry_after: Duration::from_secs(1)
            },
            "{pref:?}"
        );
        // An immediate retry is not evaluated, even with the right PIN, and not counted.
        let r = within(c1.submit(&right)).await.expect("reply");
        assert!(matches!(r, PinReply::Backoff { .. }), "{pref:?}: {r:?}");
        assert_eq!(
            e.registry.get(&id).expect("reg").expect("dev").failed_pins,
            1
        );
        // 2nd, 3rd, 4th wrong PINs (after waiting) on the same connection.
        for (n, wait) in [(2u32, 2u64), (3, 4), (4, 8)] {
            e.clock.advance(Duration::from_secs(wait));
            let r = within(c1.submit(&wrong)).await.expect("reply");
            assert!(
                matches!(r, PinReply::Wrong { attempts_left, .. } if attempts_left == 5 - n),
                "{pref:?} failure {n}: {r:?}"
            );
        }
        assert_eq!(
            e.registry.get(&id).expect("reg").expect("dev").failed_pins,
            4
        );
        // The connection has used its message budget; the counter is on disk and survives it.
        drop(c1);
        for _ in 0..4 {
            if e.outcomes.try_recv().is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // 5th wrong PIN on a new connection revokes.
        e.clock.advance(Duration::from_secs(60));
        let mut c2 = within(connect_session(&t, &device, e.server_key.public(), &opts))
            .await
            .expect("connect");
        let r = within(c2.submit(&wrong)).await;
        assert!(matches!(r, Err(Error::Revoked)), "{pref:?}: {r:?}");
        let rec = e.registry.get(&id).expect("reg").expect("dev");
        assert_eq!(
            rec.revoked.expect("revoked").reason,
            RevokeReason::TooManyPinFailures
        );

        // A revoked device cannot connect any more, even with the right PIN.
        let r = within(connect_with_pin(
            &t,
            &device,
            e.server_key.public(),
            &right,
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
            "{pref:?}: {r:?}"
        );
    }
}

#[tokio::test]
async fn revoked_devices_are_refused_for_sessions_and_for_pairing() {
    for pref in BOTH {
        let mut e = env().await;
        let device = new_key();
        e.pair(&device, pref).await;
        let id = device.public().device_id();
        assert!(
            e.auth
                .revoke(&id, RevokeReason::User)
                .await
                .expect("revoke")
        );
        assert!(!e.auth.revoke(&id, RevokeReason::User).await.expect("again"));

        let t = target(&e.server, pref);
        let pin = Pin::new(PIN).expect("pin");
        let r = within(connect_with_pin(
            &t,
            &device,
            e.server_key.public(),
            &pin,
            &session_opts(pref),
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
            "{pref:?}: {r:?}"
        );
        assert!(matches!(
            e.next().await,
            Ok(Outcome::Refused(RefuseReason::Unauthorized))
        ));

        // It cannot re-pair either, even with a valid token.
        let token = e.auth.pairing().issue_token().expect("token");
        let cred = PairingCredential::parse(&token.to_text()).expect("parse");
        let r = within(pair_device(&t, &device, &cred, &pair_opts(pref, "again"))).await;
        assert!(
            matches!(
                &r,
                Err(Error::Refused {
                    reason: RefuseReason::Unauthorized,
                    ..
                })
            ),
            "{pref:?}: {r:?}"
        );
        assert!(matches!(
            e.next().await,
            Ok(Outcome::Refused(RefuseReason::Unauthorized))
        ));
        // The registry confirms the old record is still revoked and nothing else was added.
        assert!(e.registry.get(&id).expect("reg").expect("dev").is_revoked());
        assert_eq!(e.registry.list().expect("list").len(), 1);
    }
}

#[tokio::test]
async fn revoking_closes_a_live_session() {
    for pref in BOTH {
        let mut e = env().await;
        let device = new_key();
        e.pair(&device, pref).await;
        let t = target(&e.server, pref);
        let pin = Pin::new(PIN).expect("pin");
        let conn = within(connect_with_pin(
            &t,
            &device,
            e.server_key.public(),
            &pin,
            &session_opts(pref),
        ))
        .await
        .expect("session");
        let Outcome::Authorized {
            connection: srv, ..
        } = e.next().await.expect("outcome")
        else {
            panic!("expected Authorized");
        };
        let mut seen = e.auth.subscribe_revocations();
        e.auth
            .revoke(&device.public().device_id(), RevokeReason::User)
            .await
            .expect("revoke");
        assert_eq!(
            seen.recv().await.expect("announced"),
            device.public().device_id()
        );
        let closed = within(conn.closed()).await;
        assert_eq!(closed.code, CloseCode::Unauthorized, "{pref:?}");
        let _ = within(srv.closed()).await;
    }
}

#[tokio::test]
async fn unknown_keys_are_refused_without_a_pairing_window() {
    for pref in BOTH {
        let mut e = env().await;
        let stranger = new_key();
        let t = target(&e.server, pref);
        let pin = Pin::new(PIN).expect("pin");

        // Session with a key that was never paired.
        let r = within(connect_with_pin(
            &t,
            &stranger,
            e.server_key.public(),
            &pin,
            &session_opts(pref),
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
            "{pref:?}: {r:?}"
        );
        assert!(matches!(
            e.next().await,
            Ok(Outcome::Refused(RefuseReason::Unauthorized))
        ));

        // Pairing while nothing is valid.
        let cred = PairingCredential::parse("ABCD-EFGH").expect("parse");
        let r = within(pair_device(&t, &stranger, &cred, &pair_opts(pref, "x"))).await;
        assert!(matches!(r, Err(Error::PairingClosed)), "{pref:?}: {r:?}");
        assert!(matches!(
            e.next().await,
            Ok(Outcome::Refused(RefuseReason::PairingClosed))
        ));
        assert!(e.registry.list().expect("list").is_empty());
    }
}

#[tokio::test]
async fn a_server_without_a_pin_refuses_sessions() {
    let pref = TransportPreference::Quic;
    let mut e = env().await;
    let device = new_key();
    e.pair(&device, pref).await;
    // A fresh authenticator over the same registry has no PIN configured.
    let server_key = e.server_key.clone();
    let bare = Authenticator::new(
        server_key.clone(),
        e.registry.clone(),
        AuthenticatorConfig::default(),
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
    let t = target(&server, pref);
    let s2 = server.clone();
    let handle = tokio::spawn(async move {
        let p = s2.accept().await.expect("pending");
        bare.authenticate(p).await
    });
    let pin = Pin::new(PIN).expect("pin");
    let r = within(connect_with_pin(
        &t,
        &device,
        server_key.public(),
        &pin,
        &session_opts(pref),
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
        within(handle).await.expect("join"),
        Ok(Outcome::Refused(RefuseReason::Unauthorized))
    ));
}

#[tokio::test]
async fn names_from_peers_are_sanitised_before_they_are_stored() {
    let pref = TransportPreference::Quic;
    let mut e = env().await;
    let token = e.auth.pairing().issue_token().expect("token");
    let cred = PairingCredential::parse(&token.to_text()).expect("parse");
    let t = target(&e.server, pref);
    let device = new_key();
    let p = within(pair_device(
        &t,
        &device,
        &cred,
        &pair_opts(pref, "evil\u{1b}[2J\u{202E}name\n"),
    ))
    .await
    .expect("pairs");
    let _ = e.next().await;
    p.finish().await;
    let rec = e
        .registry
        .find_by_key(&device.public())
        .expect("reg")
        .expect("dev");
    assert_eq!(rec.name, "evil[2Jname");
}

#[tokio::test]
async fn pairing_pin_and_key_types_never_print_secrets() {
    let token = hx_crypto::PairingToken::generate().expect("token");
    let code = hx_crypto::PairingCode::generate().expect("code");
    let pin = Pin::new(PIN).expect("pin");
    let key = IdentityKey::generate().expect("key");
    let hash = PinHash::with_params(&pin, CHEAP).expect("hash");
    let cred = PairingCredential::parse(&token.to_text()).expect("cred");
    let attempt = hx_crypto::wire::PinAttempt {
        pin: PIN.as_bytes().to_vec(),
    };
    let msg = hx_crypto::wire::AuthMessage::new(hx_crypto::wire::auth_message::Body::Pin(
        attempt.clone(),
    ));
    let all = format!("{token:?} {code:?} {pin:?} {key:?} {hash:?} {cred:?} {attempt:?} {msg:?}");
    assert!(!all.contains(PIN));
    assert!(!all.contains(&token.to_text()[5..]));
    assert!(!all.contains(&code.to_text()[..4]));
    let seed = key.seed();
    let seed_hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
    assert!(!all.contains(&seed_hex));
    assert!(all.contains("redacted"));
}

#[tokio::test]
async fn pairing_limits_can_be_tightened() {
    let mut e = env_with(AuthenticatorConfig {
        pairing: PairingLimits {
            code_attempts: 1,
            ..Default::default()
        },
        ..Default::default()
    })
    .await;
    let pref = TransportPreference::Quic;
    let code = e.auth.pairing().issue_code().expect("code");
    let wrong_text = if code.to_text().starts_with('A') {
        "B234-5678"
    } else {
        "A234-5678"
    };
    let t = target(&e.server, pref);
    let r = within(pair_device(
        &t,
        &new_key(),
        &PairingCredential::parse(wrong_text).expect("parse"),
        &pair_opts(pref, "x"),
    ))
    .await;
    assert!(matches!(r, Err(Error::PairingFailed)));
    let _ = e.next().await;
    assert!(!e.auth.pairing().is_open());
}

#[tokio::test]
async fn parallel_pin_guessing_is_serialised_and_backed_off() {
    let pref = TransportPreference::Quic;
    let mut e = env().await;
    let device = new_key();
    e.pair(&device, pref).await;
    let t = target(&e.server, pref);
    let opts = session_opts(pref);
    let wrong = Pin::new("111111").expect("pin");

    let mut conns = Vec::new();
    for _ in 0..4 {
        conns.push(
            within(connect_session(&t, &device, e.server_key.public(), &opts))
                .await
                .expect("connect"),
        );
    }
    // All four guess at once: only the first is evaluated, the rest hit the backoff.
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
    let id = device.public().device_id();
    assert_eq!(
        e.registry.get(&id).expect("reg").expect("dev").failed_pins,
        1
    );
}

#[tokio::test]
async fn a_connection_gets_a_bounded_number_of_pin_messages() {
    let pref = TransportPreference::Quic;
    let mut e = env_with(AuthenticatorConfig {
        max_pin_messages: 2,
        ..Default::default()
    })
    .await;
    let device = new_key();
    e.pair(&device, pref).await;
    let t = target(&e.server, pref);
    let wrong = Pin::new("222222").expect("pin");
    let mut c = within(connect_session(
        &t,
        &device,
        e.server_key.public(),
        &session_opts(pref),
    ))
    .await
    .expect("connect");
    assert!(matches!(
        within(c.submit(&wrong)).await,
        Ok(PinReply::Wrong { .. })
    ));
    assert!(matches!(
        within(c.submit(&wrong)).await,
        Ok(PinReply::Backoff { .. })
    ));
    // The third message finds the connection closed.
    assert!(within(c.submit(&wrong)).await.is_err());
    assert!(matches!(e.next().await, Err(Error::Protocol(_))));
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

// ------------------------------------------------------------------ review fixes

/// An authorized session for a freshly paired device.
async fn live_session(
    e: &mut Env,
    pref: TransportPreference,
) -> (Arc<IdentityKey>, hx_transport::Connection) {
    let device = new_key();
    e.pair(&device, pref).await;
    let t = target(&e.server, pref);
    let pin = Pin::new(PIN).expect("pin");
    let conn = within(connect_with_pin(
        &t,
        &device,
        e.server_key.public(),
        &pin,
        &session_opts(pref),
    ))
    .await
    .expect("session");
    let Outcome::Authorized { .. } = e.next().await.expect("outcome") else {
        panic!("expected Authorized");
    };
    (device, conn)
}

fn fast_watch() -> AuthenticatorConfig {
    AuthenticatorConfig {
        watch_interval: Duration::from_millis(100),
        ..Default::default()
    }
}

#[tokio::test]
async fn every_revocation_path_closes_the_live_session() {
    for pref in BOTH {
        // Authenticator::revoke
        let mut e = env_with(fast_watch()).await;
        let (d, conn) = live_session(&mut e, pref).await;
        assert!(
            e.auth
                .revoke(&d.public().device_id(), RevokeReason::User)
                .await
                .expect("revoke")
        );
        assert_eq!(
            within(conn.closed()).await.code,
            CloseCode::Unauthorized,
            "{pref:?} revoke"
        );

        // Authenticator::remove
        let mut e = env_with(fast_watch()).await;
        let (d, conn) = live_session(&mut e, pref).await;
        assert!(
            e.auth
                .remove(&d.public().device_id())
                .await
                .expect("remove")
        );
        assert_eq!(
            within(conn.closed()).await.code,
            CloseCode::Unauthorized,
            "{pref:?} remove"
        );

        // A change made behind the authenticator's back (backstop re-check).
        let mut e = env_with(fast_watch()).await;
        let (d, conn) = live_session(&mut e, pref).await;
        e.registry
            .revoke(&d.public().device_id(), RevokeReason::User, 1)
            .expect("direct revoke");
        assert_eq!(
            within(conn.closed()).await.code,
            CloseCode::Unauthorized,
            "{pref:?} direct revoke"
        );
        let mut e = env_with(fast_watch()).await;
        let (d, conn) = live_session(&mut e, pref).await;
        e.registry
            .remove(&d.public().device_id())
            .expect("direct remove");
        assert_eq!(
            within(conn.closed()).await.code,
            CloseCode::Unauthorized,
            "{pref:?} direct remove"
        );
    }
}

#[tokio::test]
async fn a_dropped_revoke_call_still_announces() {
    let pref = TransportPreference::Quic;
    let mut e = env().await;
    let (d, conn) = live_session(&mut e, pref).await;
    let id = d.public().device_id();
    // Start the revoke and cancel the future at once.
    {
        let fut = e.auth.revoke(&id, RevokeReason::User);
        let _ = tokio::time::timeout(Duration::ZERO, fut).await;
    }
    assert_eq!(within(conn.closed()).await.code, CloseCode::Unauthorized);
    assert!(e.registry.get(&id).expect("reg").expect("dev").is_revoked());
}

#[tokio::test]
async fn reinstate_goes_through_the_authenticator_and_clears_state() {
    let pref = TransportPreference::Quic;
    let mut e = env().await;
    let (d, _conn) = live_session(&mut e, pref).await;
    let id = d.public().device_id();
    e.auth
        .revoke(&id, RevokeReason::User)
        .await
        .expect("revoke");
    assert!(e.auth.reinstate(&id).await.expect("reinstate"));
    assert!(
        !e.auth
            .registry()
            .get(&id)
            .expect("reg")
            .expect("dev")
            .is_revoked()
    );
    assert!(!e.auth.reinstate(&id).await.expect("again"));
}

/// Revokes the device right after it has been looked up, as a concurrent operator would.
struct RevokeOnLookup(Arc<MemoryRegistry>);

impl DeviceRegistry for RevokeOnLookup {
    fn get(&self, id: &hx_crypto::DeviceId) -> hx_crypto::Result<Option<hx_crypto::DeviceRecord>> {
        self.0.get(id)
    }
    fn find_by_key(
        &self,
        key: &hx_crypto::PublicKey,
    ) -> hx_crypto::Result<Option<hx_crypto::DeviceRecord>> {
        let found = self.0.find_by_key(key)?;
        if found.is_some() {
            self.0.revoke(&key.device_id(), RevokeReason::User, 1)?;
        }
        Ok(found)
    }
    fn list(&self) -> hx_crypto::Result<Vec<hx_crypto::DeviceRecord>> {
        self.0.list()
    }
    fn upsert_paired(
        &self,
        key: &hx_crypto::PublicKey,
        name: &str,
        now: u64,
    ) -> hx_crypto::Result<hx_crypto::DeviceRecord> {
        self.0.upsert_paired(key, name, now)
    }
    fn begin_pin_attempt(&self, id: &hx_crypto::DeviceId) -> hx_crypto::Result<u32> {
        self.0.begin_pin_attempt(id)
    }
    fn revoke_if_failed(
        &self,
        id: &hx_crypto::DeviceId,
        max: u32,
        now: u64,
    ) -> hx_crypto::Result<bool> {
        self.0.revoke_if_failed(id, max, now)
    }
    fn record_pin_success(&self, id: &hx_crypto::DeviceId, now: u64) -> hx_crypto::Result<()> {
        self.0.record_pin_success(id, now)
    }
    fn revoke(
        &self,
        id: &hx_crypto::DeviceId,
        r: RevokeReason,
        now: u64,
    ) -> hx_crypto::Result<bool> {
        self.0.revoke(id, r, now)
    }
    fn reinstate(&self, id: &hx_crypto::DeviceId) -> hx_crypto::Result<bool> {
        self.0.reinstate(id)
    }
    fn remove(&self, id: &hx_crypto::DeviceId) -> hx_crypto::Result<bool> {
        self.0.remove(id)
    }
}

#[tokio::test]
async fn a_key_revoked_during_pairing_does_not_pair() {
    let pref = TransportPreference::Quic;
    let inner = Arc::new(MemoryRegistry::new());
    let device = new_key();
    inner
        .upsert_paired(&device.public(), "old name", 1)
        .expect("pre-register");
    let server_key = new_key();
    let auth = Authenticator::new(
        server_key.clone(),
        Arc::new(RevokeOnLookup(inner.clone())),
        AuthenticatorConfig::default(),
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
    let token = auth.pairing().issue_token().expect("token");
    let cred = PairingCredential::parse(&token.to_text()).expect("parse");
    let t = target(&server, pref);
    let (s2, a2) = (server.clone(), auth.clone());
    let handle = tokio::spawn(async move {
        let p = s2.accept().await.expect("pending");
        a2.authenticate(p).await
    });
    let r = within(pair_device(
        &t,
        &device,
        &cred,
        &pair_opts(pref, "new name"),
    ))
    .await;
    assert!(
        r.is_err(),
        "the client must not be told pairing worked: {r:?}"
    );
    assert!(within(handle).await.expect("join").is_err());
    let rec = inner
        .get(&device.public().device_id())
        .expect("reg")
        .expect("dev");
    assert!(rec.is_revoked());
    assert_eq!(rec.name, "old name");
}

#[tokio::test]
async fn refusals_do_not_say_whether_a_key_was_revoked() {
    let pref = TransportPreference::Quic;
    let mut e = env().await;
    let device = new_key();
    e.pair(&device, pref).await;
    e.auth
        .revoke(&device.public().device_id(), RevokeReason::User)
        .await
        .expect("revoke");
    let t = target(&e.server, pref);
    let pin = Pin::new(PIN).expect("pin");
    let msg = |r: hx_crypto::Result<hx_transport::Connection>| match r {
        Err(Error::Refused { reason, message }) => (reason, message),
        other => panic!("expected a refusal: {other:?}"),
    };
    let revoked = msg(within(connect_with_pin(
        &t,
        &device,
        e.server_key.public(),
        &pin,
        &session_opts(pref),
    ))
    .await);
    let _ = e.next().await;
    let stranger = msg(within(connect_with_pin(
        &t,
        &new_key(),
        e.server_key.public(),
        &pin,
        &session_opts(pref),
    ))
    .await);
    assert_eq!(revoked, stranger);
}

fn slow_pin_config(pin_timeout: Duration, min_budget: Duration) -> AuthenticatorConfig {
    AuthenticatorConfig {
        pin_timeout,
        min_hash_budget: min_budget,
        ..Default::default()
    }
}

async fn failed_pins_settle(e: &Env, id: &hx_crypto::DeviceId) -> u32 {
    let mut last = 0;
    for _ in 0..300 {
        last = e.registry.get(id).expect("reg").expect("dev").failed_pins;
        if last > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    last
}

#[tokio::test]
async fn a_pin_attempt_cut_off_by_the_deadline_still_counts() {
    let pref = TransportPreference::Quic;
    let mut e = env_with(slow_pin_config(
        Duration::from_millis(400),
        Duration::from_millis(10),
    ))
    .await;
    let device = new_key();
    e.pair(&device, pref).await;
    // A hash that takes much longer than the exchange deadline.
    e.auth.set_pin(
        PinHash::with_params(
            &Pin::new(PIN).expect("pin"),
            PinParams {
                memory_kib: 128 * 1024,
                iterations: 4,
                parallelism: 1,
            },
        )
        .expect("hash"),
    );
    let t = target(&e.server, pref);
    let mut c = within(connect_session(
        &t,
        &device,
        e.server_key.public(),
        &session_opts(pref),
    ))
    .await
    .expect("connect");
    let r = within(c.submit(&Pin::new("000000").expect("pin"))).await;
    assert!(r.is_err(), "the exchange was cut off: {r:?}");
    let id = device.public().device_id();
    assert_eq!(
        failed_pins_settle(&e, &id).await,
        1,
        "the cut-off attempt must count"
    );
}

#[tokio::test]
async fn no_attempt_is_started_without_time_to_finish_it() {
    let pref = TransportPreference::Quic;
    let mut e = env_with(slow_pin_config(
        Duration::from_millis(400),
        Duration::from_secs(5),
    ))
    .await;
    let device = new_key();
    e.pair(&device, pref).await;
    let t = target(&e.server, pref);
    let mut c = within(connect_session(
        &t,
        &device,
        e.server_key.public(),
        &session_opts(pref),
    ))
    .await
    .expect("connect");
    let r = within(c.submit(&Pin::new("000000").expect("pin"))).await;
    assert!(r.is_err());
    tokio::time::sleep(Duration::from_millis(800)).await;
    let id = device.public().device_id();
    assert_eq!(
        e.registry.get(&id).expect("reg").expect("dev").failed_pins,
        0
    );
}

#[tokio::test]
async fn names_a_sanitiser_would_change_still_pair() {
    let pref = TransportPreference::Quic;
    let mut e = env().await;
    let token = e.auth.pairing().issue_token().expect("token");
    let cred = PairingCredential::parse(&token.to_text()).expect("parse");
    let t = target(&e.server, pref);
    let device = new_key();
    let raw = "tab\there\u{200B}\u{7}";
    let p = within(pair_device(&t, &device, &cred, &pair_opts(pref, raw)))
        .await
        .expect("a name with control characters must still pair");
    let _ = e.next().await;
    p.finish().await;
    let rec = e
        .registry
        .find_by_key(&device.public())
        .expect("reg")
        .expect("dev");
    assert_eq!(rec.name, "tabhere");
}
