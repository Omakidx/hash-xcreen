//! What the gateway does around `DesktopLink::attach` that no desktop is needed for: a
//! revocation during a slow dial, and the bound on making the desktop ready.

mod gateway_common;

use std::time::Duration;

use gateway_common::*;
use hx_agent::gateway::desktop::DetachReason;
use hx_agent::gateway::desktop::recording::Event;
use hx_proto::channel::CloseCode;
use hx_proto::pb::control_message::Message as Ctl;

async fn closed_with(conn: &hx_transport::Connection) -> CloseCode {
    tokio::time::timeout(Duration::from_secs(20), conn.closed())
        .await
        .expect("the connection closes")
        .code
}

/// A device revoked while the desktop is being dialled is cut off before it is given anything:
/// the claim looks at the device again after the link attached it, and detaches it.
#[tokio::test]
async fn a_revocation_during_a_slow_attach_detaches_the_client_again() {
    let env = Env::start().await;
    *env.link.attach_delay.lock().unwrap() = Duration::from_secs(2);
    let a = new_key();
    env.pair(&a, "alice").await;
    env.set_pin(PIN).await;
    let ca = env.login(&a, "alice", PIN).await;
    ca.send_control(&view_config()).await.unwrap();
    // The claim is now inside `attach` (2 s). Revoke the device.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(env.link.log().is_empty(), "still dialling");
    env.gw
        .devices()
        .revoke_by_operator(Env::id_of(&a))
        .await
        .unwrap();
    assert_eq!(closed_with(&ca).await, CloseCode::Unauthorized);
    // The attach finishes, finds the device gone and gives the desktop back.
    assert!(
        eventually(|| async {
            env.link.log()
                == vec![
                    Event::Attach("alice".into()),
                    Event::Detach("alice".into(), DetachReason::Left),
                ]
        })
        .await,
        "{:?}",
        env.link.log()
    );
    assert!(!env.gw.sessions().has_active_client().await);
}

/// Making the desktop ready is bounded: a privd that hangs on `StartDesktop` costs the client
/// "desktop unavailable" after 10 s, never a hang, and the next client is not blocked behind it.
#[tokio::test]
async fn a_hung_start_of_the_desktop_is_bounded() {
    let env = Env::start().await;
    env.privd.with(|s| {
        s.desktop_state = hx_ipc::privd::pb::DesktopState::Stopped as i32;
        s.start_delay_ms = 14_000;
    });
    let a = new_key();
    env.pair(&a, "alice").await;
    env.set_pin(PIN).await;
    let ca = env.login(&a, "alice", PIN).await;
    let started = std::time::Instant::now();
    ca.send_control(&view_config()).await.unwrap();
    let said = recv_until(&ca, |m| match m {
        Ctl::Goodbye(g) => Some(g.clone()),
        _ => None,
    })
    .await;
    assert_eq!(said.code, CloseCode::Busy.code());
    assert_eq!(said.message, "desktop unavailable", "a fixed text");
    assert!(
        started.elapsed() < Duration::from_secs(13),
        "answered after {:?}",
        started.elapsed()
    );
    assert!(env.link.log().is_empty(), "nothing was attached");
}
