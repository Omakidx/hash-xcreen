//! `DeviceAdmin::create_pairing_code` (protocol §5.9, 1.3) on an authorized session whose
//! server side is scripted.

mod common;

use std::time::Duration;

use common::{Env, PREF, Verifier, config, within};
use hx_crypto::{
    Error, Outcome, PinVerdict,
    device_admin::DeviceAdmin,
    secrets::Pin,
    session::{PinReply, SessionOptions, connect_session},
};
use hx_proto::{
    pb::{self, control_message::Message as Ctl, device_mgmt::Body as Dm},
    version::{Features, capabilities},
};
use hx_transport::{Client, ClientHello, ClientOptions, Connection};
use tokio::task::JoinHandle;

/// An authorized `INTENT_SESSION` pair of connections (client, server side).
async fn authorized(e: &mut Env, features: Features) -> (Connection, Connection) {
    e.auth
        .set_pin_verifier(Verifier::new(&[], PinVerdict::Right));
    let o = SessionOptions {
        preference: PREF,
        capabilities: capabilities(&[], features),
        ..Default::default()
    };
    let mut a = connect_session(&e.target(), &e.device, e.server_key.public(), &o)
        .await
        .expect("connects");
    assert_eq!(
        a.submit(&Pin::new("482913").expect("pin"))
            .await
            .expect("reply"),
        PinReply::Accepted
    );
    let Outcome::Authorized { connection, .. } = e.next().await.expect("outcome") else {
        panic!("expected Authorized");
    };
    (a.into_connection().expect("authorized"), connection)
}

fn reply(id: u32, p: pb::PairingCodeIssued) -> pb::ControlMessage {
    pb::ControlMessage::new(Ctl::DeviceMgmt(pb::DeviceMgmt {
        request_id: id,
        body: Some(Dm::PairingCodeIssued(p)),
    }))
}

fn issued(code: &str, expires: u64) -> pb::PairingCodeIssued {
    pb::PairingCodeIssued {
        code: code.into(),
        expires_at_unix: expires,
        status: pb::PairingCodeStatus::Ok as i32,
        retry_after_s: 0,
    }
}

fn status_only(s: pb::PairingCodeStatus, retry: u32) -> pb::PairingCodeIssued {
    pb::PairingCodeIssued {
        code: String::new(),
        expires_at_unix: 0,
        status: s as i32,
        retry_after_s: retry,
    }
}

fn event(kind: pb::DeviceEventKind) -> pb::ControlMessage {
    pb::ControlMessage::new(Ctl::DeviceMgmt(pb::DeviceMgmt {
        request_id: 0,
        body: Some(Dm::Event(pb::DeviceEvent {
            kind: kind as i32,
            device: Some(pb::DeviceInfo {
                device_id: vec![7; 16].into(),
                name: "phone".into(),
                created_unix: 1,
                status: pb::DeviceStatus::Active as i32,
                ..Default::default()
            }),
            by_device_id: Default::default(),
        })),
    }))
}

/// The server's side: answer each `create_pairing_code` with the next scripted reply (built
/// from the request id), recording the requested lifetimes.
fn serve(
    c: Connection,
    mut script: Vec<Box<dyn FnOnce(u32) -> Vec<pb::ControlMessage> + Send>>,
) -> JoinHandle<Vec<u32>> {
    script.reverse();
    tokio::spawn(async move {
        let mut asked = Vec::new();
        while let Some(next) = script.pop() {
            let Ok(m) = c.recv_control().await else {
                break;
            };
            let Some(Ctl::DeviceMgmt(d)) = m.message else {
                break;
            };
            let Some(Dm::CreatePairingCode(req)) = d.body else {
                break;
            };
            asked.push(req.expires_in_s);
            for out in next(d.request_id) {
                c.send_control(&out).await.expect("send");
            }
        }
        asked
    })
}

#[tokio::test]
async fn a_code_is_issued_with_its_expiry_and_stays_redacted() {
    let mut e = Env::new(config()).await;
    let (client, server) = authorized(&mut e, Features::DEVICE_MANAGEMENT).await;
    let h = serve(
        server,
        vec![Box::new(|id| {
            vec![reply(id, issued("AB12-CD34", 1_900_000_000))]
        })],
    );
    let mut admin = DeviceAdmin::new(client).expect("admin");
    let code = within(admin.create_pairing_code(600)).await.expect("code");
    assert_eq!(code.code(), "AB12-CD34");
    assert_eq!(code.expires_at_unix, 1_900_000_000);
    let dbg = format!("{code:?} {code:#?}");
    assert!(!dbg.contains("AB12") && dbg.contains("redacted"), "{dbg}");
    assert_eq!(h.await.expect("server"), [600]);
}

#[tokio::test]
async fn rate_limited_carries_retry_after_and_a_later_call_works() {
    let mut e = Env::new(config()).await;
    let (client, server) = authorized(&mut e, Features::DEVICE_MANAGEMENT).await;
    let h = serve(
        server,
        vec![
            Box::new(|id| {
                vec![reply(
                    id,
                    status_only(pb::PairingCodeStatus::RateLimited, 1800),
                )]
            }),
            Box::new(|id| vec![reply(id, issued("ZZZZ-1111", 5))]),
        ],
    );
    let mut admin = DeviceAdmin::new(client).expect("admin");
    let r = within(admin.create_pairing_code(300)).await;
    let Err(Error::RateLimited { retry_after }) = r else {
        panic!("expected RateLimited, got {r:?}");
    };
    assert_eq!(retry_after, Duration::from_secs(1800));
    let code = within(admin.create_pairing_code(300)).await.expect("code");
    assert_eq!(code.code(), "ZZZZ-1111");
    assert_eq!(h.await.expect("server"), [300, 300]);
}

#[tokio::test]
async fn invalid_argument_and_a_server_fault_are_distinct_errors() {
    let mut e = Env::new(config()).await;
    let (client, server) = authorized(&mut e, Features::DEVICE_MANAGEMENT).await;
    let _h = serve(
        server,
        vec![
            Box::new(|id| {
                vec![reply(
                    id,
                    status_only(pb::PairingCodeStatus::InvalidArgument, 0),
                )]
            }),
            Box::new(|id| vec![reply(id, status_only(pb::PairingCodeStatus::Failed, 0))]),
        ],
    );
    let mut admin = DeviceAdmin::new(client).expect("admin");
    assert!(matches!(
        within(admin.create_pairing_code(300)).await,
        Err(Error::InvalidSecret(_))
    ));
    assert!(matches!(
        within(admin.create_pairing_code(300)).await,
        Err(Error::ServerFailed)
    ));
}

#[tokio::test]
async fn the_lifetime_is_checked_before_anything_is_sent() {
    let mut e = Env::new(config()).await;
    let (client, server) = authorized(&mut e, Features::DEVICE_MANAGEMENT).await;
    let h = serve(server, vec![]);
    let mut admin = DeviceAdmin::new(client).expect("admin");
    for bad in [0, 59, 901, u32::MAX] {
        assert!(
            matches!(
                admin.create_pairing_code(bad).await,
                Err(Error::InvalidSecret(_))
            ),
            "{bad}"
        );
    }
    assert!(h.await.expect("server").is_empty());
}

#[tokio::test]
async fn notices_and_a_mismatched_answer_are_handled_by_request_id() {
    let mut e = Env::new(config()).await;
    let (client, server) = authorized(&mut e, Features::DEVICE_MANAGEMENT).await;
    // A change notice arrives before the answer; the answer is matched by id.
    let _h = serve(
        server,
        vec![
            Box::new(|id| {
                vec![
                    event(pb::DeviceEventKind::Added),
                    reply(id, issued("AAAA-BBBB", 9)),
                ]
            }),
            // An answer to a request that was never made.
            Box::new(|id| vec![reply(id + 50, issued("CCCC-DDDD", 9))]),
        ],
    );
    let mut admin = DeviceAdmin::new(client).expect("admin");
    let code = within(admin.create_pairing_code(300)).await.expect("code");
    assert_eq!(code.code(), "AAAA-BBBB");
    let events = admin.take_events();
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0].body, Some(Dm::Event(_))));
    assert!(admin.take_events().is_empty());
    let r = within(admin.create_pairing_code(300)).await;
    assert!(matches!(r, Err(Error::Protocol(_))), "{r:?}");
}

#[tokio::test]
async fn a_server_that_never_answers_times_out() {
    let mut e = Env::new(config()).await;
    let (client, server) = authorized(&mut e, Features::DEVICE_MANAGEMENT).await;
    let _h = serve(server, vec![Box::new(|_| vec![])]);
    let mut admin = DeviceAdmin::new(client)
        .expect("admin")
        .with_timeout(Duration::from_millis(300));
    let r = admin.create_pairing_code(300).await;
    assert!(matches!(r, Err(Error::Timeout(_))), "{r:?}");
}

#[tokio::test]
async fn without_the_feature_the_call_is_not_offered() {
    let mut e = Env::new(config()).await;
    // The client did not offer DEVICE_MANAGEMENT: not negotiated.
    let (client, _server) = authorized(&mut e, Features::NONE).await;
    let r = DeviceAdmin::new(client);
    assert!(matches!(r, Err(Error::UpdateRequired)), "{r:?}");
}

#[tokio::test]
async fn a_connection_that_has_not_passed_the_pin_cannot_be_used() {
    // Refused without a PIN: a restricted connection (key checked, PIN not) is never wrapped,
    // and the server would treat the message as a protocol error anyway.
    let e = Env::new(config()).await;
    e.auth
        .set_pin_verifier(Verifier::new(&[], PinVerdict::Right));
    let client = Client::new(
        hx_crypto::tls::client_config_session(&e.device, e.server_key.public()).expect("tls"),
        ClientOptions {
            preference: PREF,
            ..Default::default()
        },
    );
    let hello = ClientHello {
        capabilities: capabilities(&[], Features::DEVICE_MANAGEMENT),
        intent: pb::Intent::Session,
        software: "test".into(),
        device_name: "laptop".into(),
    };
    let restricted = within(client.connect(&e.target(), &hello))
        .await
        .expect("connects");
    // The client library hands out a session connection only after the PIN was accepted.
    let a = connect_session(
        &e.target(),
        &e.device,
        e.server_key.public(),
        &SessionOptions {
            preference: PREF,
            ..Default::default()
        },
    )
    .await
    .expect("connects");
    assert!(matches!(a.into_connection(), Err(Error::Protocol(_))));
    // Forcing the call on a restricted connection anyway: the server ends the connection and
    // no code exists (nothing was issued, so nothing could be answered).
    let mut admin = DeviceAdmin::new(restricted).expect("negotiated");
    let r = within(admin.create_pairing_code(300)).await;
    assert!(matches!(r, Err(Error::Transport(_))), "{r:?}");
}
