//! `CreatePairingCode` (protocol 5.9, 1.3): a PIN-authenticated session of an active device asks
//! for a short code for a new device. Real gateway, real privd, real client library.

mod gateway_common;

use std::time::Duration;

use gateway_common::setup::*;
use gateway_common::{PIN, new_key, within};
use hx_crypto::device_admin::DeviceAdmin;
use hx_crypto::{Error, PairingCredential};
use hx_proto::pb::{self, control_message::Message as Ctl};

async fn env_with_a_device() -> (SetupEnv, std::sync::Arc<hx_crypto::IdentityKey>) {
    let e = SetupEnv::start().await;
    e.make_ready().await;
    let phone = new_key();
    e.pair_plain(&phone, "phone").await;
    e.set_verifiers().await;
    (e, phone)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_logged_in_device_gets_a_code_that_pairs_an_ordinary_device_and_is_audited() {
    capture_logs();
    let (e, phone) = env_with_a_device().await;
    let conn = e.login(&phone, PIN).await.expect("login");
    let mut admin = DeviceAdmin::new(conn).unwrap();
    let before = e.unix_now();
    let issued = within(admin.create_pairing_code(300))
        .await
        .expect("a code");
    let code = issued.code().to_owned();
    assert_eq!(code.len(), 9, "XXXX-XXXX");
    assert!(issued.expires_at_unix >= before + 299 && issued.expires_at_unix <= before + 302);

    // The new device pairs with it, as with an interactive install: an ordinary device.
    let laptop = new_key();
    e.pair_with(&laptop, "laptop", &PairingCredential::parse(&code).unwrap())
        .await;
    // It needs the PIN, and it can never open setup.
    assert!(e.login(&laptop, PIN).await.unwrap().is_authorized());
    assert!(matches!(
        e.connect_setup_as(
            &laptop,
            hx_proto::version::ProtocolVersion { major: 1, minor: 3 }
        )
        .await,
        Err(Error::SetupClosed)
    ));
    // The code is single use.
    let again = new_key();
    let r = hx_crypto::pair_device(
        &e.target(hx_transport::TransportPreference::Quic),
        &again,
        &PairingCredential::parse(&code).unwrap(),
        &hx_crypto::PairClientOptions::default(),
    )
    .await;
    assert!(r.is_err(), "a code works once");

    // Audited with the requesting device's id, never the code.
    let id_hex = hex(phone.public().device_id().as_bytes());
    let lines = e.h.audit.lines();
    let line = lines
        .iter()
        .find(|l| l.contains("DEVICE_PAIRING_CODE_ISSUED"))
        .unwrap_or_else(|| panic!("no audit line: {lines:?}"));
    assert!(line.contains(&id_hex), "{line}");
    assert!(lines.iter().all(|l| !l.contains(&code)));
    assert!(
        !captured_logs().contains(&code),
        "the code reached a log line"
    );
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn at_most_three_codes_an_hour_and_a_new_code_replaces_the_old() {
    let (e, phone) = env_with_a_device().await;
    let conn = e.login(&phone, PIN).await.unwrap();
    let mut admin = DeviceAdmin::new(conn).unwrap();
    let first = within(admin.create_pairing_code(600))
        .await
        .unwrap()
        .code()
        .to_owned();
    let second = within(admin.create_pairing_code(600))
        .await
        .unwrap()
        .code()
        .to_owned();
    assert_ne!(first, second);
    // One live code: the first stopped working when the second was issued.
    let a = new_key();
    let r = hx_crypto::pair_device(
        &e.target(hx_transport::TransportPreference::Quic),
        &a,
        &PairingCredential::parse(&first).unwrap(),
        &hx_crypto::PairClientOptions::default(),
    )
    .await;
    assert!(r.is_err(), "the replaced code is dead");
    let _third = within(admin.create_pairing_code(600)).await.unwrap();
    // The fourth in the hour is refused with a wait, and changes nothing.
    match within(admin.create_pairing_code(600)).await {
        Err(Error::RateLimited { retry_after }) => {
            assert!(retry_after > Duration::ZERO && retry_after <= Duration::from_secs(3600));
        }
        other => panic!("{other:?}"),
    }
    let lines = e.h.audit.lines();
    assert_eq!(
        lines
            .iter()
            .filter(|l| l.contains("DEVICE_PAIRING_CODE_ISSUED"))
            .count(),
        3,
        "a refusal is not audited as an issue"
    );
    // The limit counts all connections of the server: another session is refused too.
    let other = new_key();
    e.pair_plain(&other, "tablet").await;
    let mut admin2 = DeviceAdmin::new(e.login(&other, PIN).await.unwrap()).unwrap();
    assert!(matches!(
        within(admin2.create_pairing_code(600)).await,
        Err(Error::RateLimited { .. })
    ));
    // An hour later it works again.
    e.clock.advance(Duration::from_secs(3601));
    assert!(within(admin2.create_pairing_code(600)).await.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_lifetime_is_validated_and_capped_by_the_configured_pairing_ttl() {
    let (e, phone) = env_with_a_device().await;
    let conn = e.login(&phone, PIN).await.unwrap();
    // 59 and 901 are protocol errors on the wire (the message validates before the server acts).
    for bad in [59u32, 901] {
        let c = e.login(&phone, PIN).await.unwrap();
        let m = pb::ControlMessage::new(Ctl::DeviceMgmt(pb::DeviceMgmt {
            request_id: 1,
            body: Some(pb::device_mgmt::Body::CreatePairingCode(
                pb::CreatePairingCode { expires_in_s: bad },
            )),
        }));
        // The message validates on the way out; if it is sent anyway, the server closes.
        if c.send_control(&m).await.is_ok() {
            within(async {
                while let Ok(m) = c.recv_control().await {
                    if let Some(Ctl::DeviceMgmt(d)) = m.message {
                        assert!(
                            !matches!(d.body, Some(pb::device_mgmt::Body::PairingCodeIssued(_))),
                            "a code was issued for {bad}"
                        );
                    }
                }
            })
            .await;
        }
    }
    assert_eq!(
        e.h.audit
            .lines()
            .iter()
            .filter(|l| l.contains("DEVICE_PAIRING_CODE_ISSUED"))
            .count(),
        0
    );
    // The default pairing lifetime is 900 s: 900 is honoured, and the expiry says so.
    let mut admin = DeviceAdmin::new(conn).unwrap();
    let now = e.unix_now();
    let issued = within(admin.create_pairing_code(900)).await.unwrap();
    assert!(issued.expires_at_unix <= now + 902);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pairing_connection_cannot_ask() {
    let (e, _phone) = env_with_a_device().await;
    // A freshly paired connection is restricted: the variant is not processed there.
    let token = e.gw().authenticator().pairing().issue_token().unwrap();
    let cred = PairingCredential::parse(&token.to_text()).unwrap();
    let newcomer = new_key();
    let paired = within(hx_crypto::pair_device(
        &e.target(hx_transport::TransportPreference::Quic),
        &newcomer,
        &cred,
        &hx_crypto::PairClientOptions::default(),
    ))
    .await
    .unwrap();
    let m = pb::ControlMessage::new(Ctl::DeviceMgmt(pb::DeviceMgmt {
        request_id: 1,
        body: Some(pb::device_mgmt::Body::CreatePairingCode(
            pb::CreatePairingCode { expires_in_s: 300 },
        )),
    }));
    let _ = paired.connection.send_control(&m).await;
    within(async {
        while let Ok(m) = paired.connection.recv_control().await {
            if let Some(Ctl::DeviceMgmt(_)) = m.message {
                panic!("a DeviceMgmt answer on a pairing connection");
            }
        }
    })
    .await;
    assert_eq!(
        e.h.audit
            .lines()
            .iter()
            .filter(|l| l.contains("DEVICE_PAIRING_CODE_ISSUED"))
            .count(),
        0
    );
}
