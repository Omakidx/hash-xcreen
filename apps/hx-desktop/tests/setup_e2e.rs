//! The app's real `SetupClient` (`backend::setup_real::RealSetupClient`) against a real
//! gatewayd in front of a real privd daemon on a fake Incus (the harness of
//! `apps/hx-agent/tests/gateway_common/setup.rs`): the one-liner path after pairing.
//!
//! `#[ignore]`d with the other end-to-end tests: `cargo nextest run -p hx-desktop --run-ignored only`.

#[path = "../../hx-agent/tests/gateway_common/mod.rs"]
mod gateway_common;

use gateway_common::setup::{PASSWORD, SetupEnv};
use gateway_common::{PIN, within};
use hx_desktop::backend::setup_real::RealSetupClient;
use hx_desktop::backend::{
    InstallEvent, InstallOptions, PairedInfo, Secret, ServerAddr, SetupClient, SetupError,
    SetupRequest, StageState,
};
use hx_transport::TransportPreference;

fn options() -> InstallOptions {
    InstallOptions {
        distro: "ubuntu-24.04".into(),
        desktop: "xfce".into(),
        apps: "basic".into(),
        docker: false,
        username: "alice".into(),
        // 0 = the server's defaults (the fake host is small)
        cpu: 0,
        memory_gb: 0,
        disk_gb: 0,
        port: 443,
        domain: String::new(),
        backup: "off".into(),
    }
}

fn request() -> SetupRequest {
    SetupRequest {
        options: options(),
        password: Secret::new(PASSWORD),
        pin: Secret::new(PIN),
    }
}

fn key_hex(k: &hx_crypto::PublicKey) -> String {
    k.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "end to end against a real gatewayd and privd; run with --run-ignored only"]
async fn the_app_creates_the_desktop_after_a_one_liner_pairing() {
    let e = SetupEnv::start().await;
    e.open_window(7200).await;
    let version = e.pair_app().await;
    let addr = e.target(TransportPreference::Quic).addr;
    let server = ServerAddr {
        host: addr.ip().to_string(),
        port: addr.port(),
    };
    let paired = PairedInfo {
        server_key_hex: key_hex(&e.server_public()),
        server_name: String::new(),
        server_version: Some((version.major, version.minor)),
    };
    let client = RealSetupClient {
        device_name: "app".into(),
    };
    let mut run = within(client.start_setup(&server, e.app.clone(), &paired, request()))
        .await
        .expect("setup starts");
    let mut events = Vec::new();
    while let Some(ev) = tokio::time::timeout(std::time::Duration::from_secs(60), run.next_event())
        .await
        .expect("an event in time")
    {
        events.push(ev);
    }
    assert!(
        !events.iter().any(|x| matches!(
            x,
            InstallEvent::Failed(_) | InstallEvent::ConnectionLost { .. }
        )),
        "{events:?}"
    );
    assert!(events.iter().any(|x| matches!(x, InstallEvent::Stage { id, state: StageState::Done, .. } if id == "desktop")), "{events:?}");
    assert!(
        matches!(events.last(), Some(InstallEvent::Finished(o)) if o.server_key_hex == key_hex(&e.server_public())),
        "{events:?}"
    );
    // The PIN the app chose now works for an ordinary login.
    let _conn = e.login(&e.app, PIN).await.expect("PIN login");
}

#[tokio::test]
async fn a_server_that_was_never_confirmed_as_1_3_must_be_updated_before_any_connection() {
    let client = RealSetupClient {
        device_name: "app".into(),
    };
    let key = hx_crypto::IdentityKey::generate().unwrap();
    let paired = PairedInfo {
        server_key_hex: key_hex(&key.public()),
        server_name: String::new(),
        server_version: Some((1, 2)),
    };
    // Port 9 on the loopback: nothing listens, and the gate answers before any socket is tried.
    let r = client
        .start_setup(
            &ServerAddr {
                host: "127.0.0.1".into(),
                port: 9,
            },
            std::sync::Arc::new(key),
            &paired,
            request(),
        )
        .await;
    assert!(
        matches!(r, Err(SetupError::UpdateRequired)),
        "the 1.3 gate must answer first"
    );
}
