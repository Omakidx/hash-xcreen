//! What the relay does when the desktop's session is the wrong version: `InstallSession` is
//! asked for once and then rate limited, the desktop ends up "session unavailable", and a client
//! only ever hears a fixed text. No desktop is needed: the "session" is a socket that answers the
//! preamble with another link major.

mod gateway_common;

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::sync::Arc;
use std::time::Duration;

use gateway_common::*;
use hx_agent::gateway::desktop::DesktopLink;
use hx_agent::gateway::privd_client::PrivdClient;
use hx_agent::gateway::relay::{RelayConfig, RelayLink};
use hx_ipc::admin::pb::LinkState;
use hx_proto::channel::CloseCode;
use hx_proto::pb::control_message::Message as Ctl;

/// A fake `hx-session` of another link major: it answers every preamble with major 9 and hangs
/// up, as an honest older or newer session does (ipc.md 12.2).
fn outdated_session(path: &std::path::Path) -> std::thread::JoinHandle<()> {
    let l = UnixListener::bind(path).unwrap();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { return };
            let mut offer = [0u8; 24];
            if s.read_exact(&mut offer).is_ok() {
                let mut a = [0u8; 8];
                a[..4].copy_from_slice(b"HXLK");
                a[4] = 9;
                a[6] = offer[6];
                let _ = s.write_all(&a);
            }
        }
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn an_outdated_session_asks_for_one_install_then_the_desktop_is_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("link.sock");
    let _fake = outdated_session(&sock);
    let slot: Arc<std::sync::Mutex<Option<Arc<RelayLink>>>> = Default::default();
    let (s2, sock2) = (slot.clone(), sock.clone());
    let env = Env::start_with(EnvOptions {
        custom_link: Some(Box::new(move |privd| {
            let relay = RelayLink::new(
                RelayConfig::new(sock2),
                Some(PrivdClient::new(&privd.path, Default::default())),
            );
            *s2.lock().unwrap() = Some(relay.clone());
            relay as Arc<dyn DesktopLink>
        })),
        ..EnvOptions::default()
    })
    .await;
    let relay = slot.lock().unwrap().take().unwrap();
    let a = new_key();
    env.pair(&a, "alice").await;
    env.set_pin(PIN).await;

    for round in 0..5 {
        if round > 0 {
            // Forget the backoff (as if privd had reported the session restarted), so that this
            // round dials at once and fails the same way.
            relay.keeper().session_restarted();
        }
        let c = env.login(&a, "alice", PIN).await;
        c.send_control(&view_config()).await.unwrap();
        let said = recv_until(&c, |m| match m {
            Ctl::Goodbye(g) => Some(g.clone()),
            _ => None,
        })
        .await;
        assert_eq!(said.code, CloseCode::Busy.code(), "round {round}");
        assert_eq!(
            said.message, "desktop unavailable",
            "a fixed text, round {round}"
        );
        c.close(CloseCode::NoError, "bye").await;
        // Let the background InstallSession finish.
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    // One install was asked for in all that time: the next ones are rate limited here (and the
    // policy's own budget of three ends in "session unavailable").
    assert_eq!(env.privd.with(|s| s.install_session_calls), 1);
    assert_eq!(env.privd.with(|s| s.restart_session_calls), 0);
    assert_eq!(relay.state(), LinkState::SessionUnavailable);
    assert!(!relay.keeper().is_up());
    assert!(!env.gw.sessions().has_active_client().await);
}
