//! The app's real `ServerControl` and pairing-code path against a real gatewayd in front of a
//! real privd on a fake Incus (the setup of `apps/hx-agent/tests/gateway_server_mgmt.rs`), over
//! the app's own session task.
//!
//! `#[ignore]`d with the other end-to-end tests: `cargo nextest run -p hx-desktop --run-ignored only`.

#[path = "../../hx-agent/tests/gateway_common/mod.rs"]
mod gateway_common;

use std::sync::Arc;

use gateway_common::setup::SetupEnv;
use gateway_common::{PIN, new_key};
use hx_desktop::backend::control_real::RealControl;
use hx_desktop::backend::real::RealAdmin;
use hx_desktop::backend::{
    AdminContext, AdminError, DesktopStatus, DeviceAdmin, Limits, Secret, ServerControl,
};
use hx_desktop::session::net::{Link, Session, login};
use hx_desktop::video::Stats;
use hx_transport::TransportPreference;

struct Rig {
    e: SetupEnv,
    ctx: AdminContext,
}

async fn rig() -> Rig {
    let e = SetupEnv::start().await;
    e.make_ready().await;
    e.h.incus
        .add_desktop("hx-main", "ubuntu-24.04-xfce-basic", "alice", true);
    e.h.daemon.register_desktop("main").unwrap();
    let phone = new_key();
    e.pair_plain(&phone, "phone").await;
    e.set_verifiers().await;
    let addr = e.target(TransportPreference::Quic).addr;
    let link = Link {
        host: addr.ip().to_string(),
        port: addr.port(),
        server_key: e.server_public(),
        device: phone.clone(),
        device_name: "phone".into(),
    };
    let conn = login(&link, PIN).await.expect("PIN login");
    let (session, _events) = Session::start(
        conn,
        None,
        std::env::temp_dir(),
        Arc::new(Stats::default()),
        tokio::runtime::Handle::current(),
    );
    let ctx = AdminContext {
        host: link.host.clone(),
        port: link.port,
        server_key_hex: hx_desktop::session::net::key_hex(&link.server_key),
        device: phone,
        server_version: Some((1, 3)),
        session: Some(Arc::new(session)),
    };
    Rig { e, ctx }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "end to end against a real gatewayd and privd; run with --run-ignored only"]
async fn overview_pin_limits_docker_and_pairing_code_over_the_apps_session() {
    let r = rig().await;
    let control = RealControl;

    // The overview shows what the server reports, and nothing it does not.
    let o = control.overview(&r.ctx).await.expect("overview");
    assert_eq!(o.desktop, DesktopStatus::Running);
    assert!(
        o.setup.starts_with("Ubuntu 24.04 · XFCE · Basic"),
        "{}",
        o.setup
    );
    assert!(o.host_cpus > 0 && o.host_disk_gb > 0);
    assert_eq!(o.agent_version, env!("CARGO_PKG_VERSION"));

    // A wrong current PIN counts on the server and reports the attempts left.
    let wrong = control
        .change_pin(&r.ctx, &Secret::new("000000"), &Secret::new("135790"))
        .await;
    assert_eq!(
        wrong,
        Err(AdminError::Incorrect {
            attempts_left: Some(4)
        })
    );
    // The gateway runs on a manual clock: let the one-second wait pass.
    r.e.clock.advance(std::time::Duration::from_secs(5));
    // The right one changes it.
    control
        .change_pin(&r.ctx, &Secret::new(PIN), &Secret::new("135790"))
        .await
        .expect("change PIN");

    // Docker on is a server-side command; the app shows it.
    let docker = control.set_docker(&r.ctx, true).await;
    assert!(
        matches!(&docker, Err(AdminError::Failed(m)) if m.contains("sudo hx-agent docker enable")),
        "{docker:?}"
    );

    // Limits the server accepts.
    let _ = control
        .set_limits(
            &r.ctx,
            Limits {
                cpu: 1,
                memory_gb: 1,
                disk_gb: 8,
            },
        )
        .await;

    // A pairing code over the same session task (the single reader of control answers).
    let admin = RealAdmin {
        device_name: "phone".into(),
    };
    let code = admin
        .create_pairing_code(&r.ctx)
        .await
        .expect("pairing code");
    assert_eq!(code.code.len(), 9, "XXXX-XXXX");
    assert!(code.expires_in_secs > 0 && code.expires_in_secs <= 900);

    // And the paired list still answers on the same session afterwards.
    let desk = r.ctx.session.clone().unwrap();
    assert!(!desk.list_devices().await.expect("device list").is_empty());
    let _ = &r.e;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_a_signed_in_session_the_calls_ask_for_the_pin() {
    let key = hx_crypto::IdentityKey::generate().unwrap();
    let ctx = AdminContext {
        host: "127.0.0.1".into(),
        port: 9,
        server_key_hex: String::new(),
        device: Arc::new(key),
        server_version: Some((1, 3)),
        session: None,
    };
    assert_eq!(
        RealControl.overview(&ctx).await.err(),
        Some(AdminError::SessionRequired)
    );
    assert_eq!(
        RealAdmin {
            device_name: "x".into()
        }
        .create_pairing_code(&ctx)
        .await
        .err(),
        Some(AdminError::Failed("Sign in with your PIN first.".into()))
    );
}
