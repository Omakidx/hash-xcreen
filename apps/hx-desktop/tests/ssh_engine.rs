//! The app's real `InstallEngine` adapter (`backend::ssh::SshInstallEngine`) driven against
//! `hx-sshsetup`'s in-process SSH server. The fake speaks over a duplex pipe, so a small TCP
//! proxy bridges each accepted connection to a fresh fake server: the engine dials a real
//! socket as it does in production.

#[path = "../../../crates/hx-sshsetup/tests/support/mod.rs"]
mod support;

use std::sync::Arc;

use hx_desktop::backend::ssh::SshInstallEngine;
use hx_desktop::backend::{
    CheckStatus, EngineError, HostKey, InstallEngine, InstallEvent, InstallOptions, InstallRequest,
    Secret, SshAuth, SshTarget, StageState,
};
use support::*;

/// Listens on 127.0.0.1 and bridges every connection to a new fake server.
async fn proxy(f: Fake) -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = l.accept().await {
            let mut pipe = f.connect();
            tokio::spawn(async move {
                let _ = tokio::io::copy_bidirectional(&mut tcp, &mut pipe).await;
            });
        }
    });
    port
}

fn engine() -> SshInstallEngine {
    SshInstallEngine::with_script(b"#!/bin/sh\nexit 0\n".to_vec())
}

fn auth() -> SshAuth {
    SshAuth::Password {
        user: "alice".into(),
        password: Secret::new("right-pw"),
    }
}

fn options() -> InstallOptions {
    {
        let mut w = hx_desktop::wizard::Wizard::new();
        w.username = "alex".into();
        w.options()
    }
}

fn request(port: u16, host_key: HostKey) -> InstallRequest {
    let token = hx_crypto::PairingToken::generate()
        .unwrap()
        .to_text()
        .to_string();
    InstallRequest {
        target: SshTarget {
            host: "127.0.0.1".into(),
            port,
        },
        auth: auth(),
        host_key,
        options: options(),
        password: Secret::new("desktop-pw"),
        pin: Secret::new("482915"),
        pairing_token: Secret::new(token),
    }
}

async fn events(mut run: Box<dyn hx_desktop::backend::InstallRun>) -> Vec<InstallEvent> {
    let mut v = Vec::new();
    while let Some(e) = tokio::time::timeout(std::time::Duration::from_secs(30), run.next_event())
        .await
        .expect("an event in time")
    {
        v.push(e);
    }
    v
}

async fn confirmed(e: &SshInstallEngine, port: u16, f: &Fake) -> HostKey {
    let hk = e
        .probe_host_key(&SshTarget {
            host: "127.0.0.1".into(),
            port,
        })
        .await
        .expect("probe");
    assert_eq!(hk.fingerprint, f.fingerprint());
    hk
}

#[tokio::test]
async fn host_key_then_requirement_checks() {
    let f = Fake::new(shell(
        Sudo::Root,
        HEALTHY_PREFLIGHT.to_owned(),
        Arc::new(|_| vec![out(&ok_lines(KEY_HEX)), Action::Exit(0)]),
    ));
    let port = proxy(f.clone()).await;
    let e = engine();
    let hk = confirmed(&e, port, &f).await;
    assert_eq!(hk.algorithm, "ED25519");
    assert_eq!(
        f.auth_attempts(),
        0,
        "nothing is authenticated before the user trusts the key"
    );
    let p = e
        .preflight(
            &SshTarget {
                host: "127.0.0.1".into(),
                port,
            },
            &auth(),
            &hk,
        )
        .await
        .expect("preflight");
    assert!(p.ok());
    assert_eq!(p.cpus, 4);
    assert!(
        p.rows
            .iter()
            .any(|r| r.title == "Ubuntu 24.04.1 LTS is supported"),
        "{:?}",
        p.rows
    );
    assert!(p.rows.iter().all(|r| r.status != CheckStatus::Fail));
}

#[tokio::test]
async fn a_changed_host_key_stops_before_any_credential() {
    let f = Fake::new(shell(
        Sudo::Root,
        HEALTHY_PREFLIGHT.to_owned(),
        Arc::new(|_| vec![Action::Exit(0)]),
    ));
    let port = proxy(f.clone()).await;
    let e = engine();
    let wrong = HostKey {
        algorithm: "ED25519".into(),
        fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
    };
    let r = e
        .preflight(
            &SshTarget {
                host: "127.0.0.1".into(),
                port,
            },
            &auth(),
            &wrong,
        )
        .await;
    assert!(
        matches!(r, Err(EngineError::HostKeyChanged { .. })),
        "{r:?}"
    );
    assert_eq!(f.auth_attempts(), 0);
}

#[tokio::test]
async fn bad_credentials_are_reported() {
    let f = Fake::new(shell(
        Sudo::Root,
        HEALTHY_PREFLIGHT.to_owned(),
        Arc::new(|_| vec![Action::Exit(0)]),
    ));
    let port = proxy(f.clone()).await;
    let e = engine();
    let hk = confirmed(&e, port, &f).await;
    let bad = SshAuth::Password {
        user: "alice".into(),
        password: Secret::new("wrong"),
    };
    let r = e
        .preflight(
            &SshTarget {
                host: "127.0.0.1".into(),
                port,
            },
            &bad,
            &hk,
        )
        .await;
    assert_eq!(r.err(), Some(EngineError::AuthFailed));
}

#[tokio::test]
async fn an_install_streams_events_and_ends_with_the_result() {
    let f = Fake::new(shell(
        Sudo::Root,
        HEALTHY_PREFLIGHT.to_owned(),
        Arc::new(|_| vec![out(&ok_lines(KEY_HEX)), Action::Exit(0)]),
    ));
    let port = proxy(f.clone()).await;
    let e = engine();
    let hk = confirmed(&e, port, &f).await;
    let run = e.install(request(port, hk)).await.expect("install starts");
    let ev = events(run).await;
    assert!(ev.iter().any(|x| matches!(x, InstallEvent::Stage { id, state: StageState::Done, ms: Some(120) } if id == "preflight")), "{ev:?}");
    assert!(
        ev.iter().any(|x| matches!(
            x,
            InstallEvent::Step {
                percent: None,
                index: 3,
                total: 12,
                ..
            }
        )),
        "an unmeasured step has no percentage"
    );
    assert!(ev.iter().any(|x| matches!(
        x,
        InstallEvent::ImagePath {
            prebuilt: false,
            ..
        }
    )));
    match ev.last() {
        Some(InstallEvent::Finished(o)) => {
            assert_eq!(o.port, 443);
            assert_eq!(o.image_path, "Built on the server");
            assert_eq!(o.server_key_hex, KEY_HEX);
        }
        other => panic!("last event {other:?}"),
    }
    // The secrets went on stdin of the installer, never into a command line.
    let execs = f.execs();
    let run_cmd = execs
        .iter()
        .find(|x| x.command.contains("--ssh"))
        .expect("the installer ran");
    assert!(
        !run_cmd.command.contains("desktop-pw")
            && !run_cmd.command.contains("482915")
            && !run_cmd.command.contains("hxt1-")
    );
}

#[tokio::test]
async fn an_installer_failure_is_a_failed_event_with_retry_info() {
    let fail = "{\"v\":1,\"t\":\"result\",\"ok\":false,\"exit\":1,\"stage\":\"incus\",\"code\":\"UNAVAILABLE\",\"message\":\"package source unreachable\",\"retryable\":true}\n";
    let f = Fake::new(shell(
        Sudo::Root,
        HEALTHY_PREFLIGHT.to_owned(),
        Arc::new(move |_| vec![out(fail), Action::Exit(1)]),
    ));
    let port = proxy(f.clone()).await;
    let e = engine();
    let hk = confirmed(&e, port, &f).await;
    let ev = events(e.install(request(port, hk)).await.unwrap()).await;
    match ev.last() {
        Some(InstallEvent::Failed(x)) => {
            assert_eq!(
                (x.stage.as_str(), x.code.as_str(), x.retryable),
                ("incus", "UNAVAILABLE", true)
            );
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_lost_connection_is_reported_with_the_last_stage() {
    let lost =
        "{\"v\":1,\"t\":\"stage\",\"id\":\"desktop\",\"n\":13,\"of\":19,\"state\":\"start\"}\n";
    let f = Fake::new(shell(
        Sudo::Root,
        HEALTHY_PREFLIGHT.to_owned(),
        Arc::new(move |_| vec![out(lost), Action::Disconnect]),
    ));
    let port = proxy(f.clone()).await;
    let e = engine();
    let hk = confirmed(&e, port, &f).await;
    let ev = events(e.install(request(port, hk)).await.unwrap()).await;
    assert!(
        matches!(ev.last(), Some(InstallEvent::ConnectionLost { stage }) if stage == "desktop"),
        "{ev:?}"
    );
}
