//! The real implementations behind the two update seams (docs/ipc.md 6.12): `SystemdCtl` builds
//! fixed `systemctl` argument vectors (checked here through the fake runner, so nothing is
//! started), and `SocketProbe` speaks the real framing to privd's socket and to a stand-in for
//! gatewayd's admin socket.

mod privd_update_common;

use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;

use hx_agent::fetcher::{Channel, Job};
use hx_agent::privd::runner::{RunOutput, Tool};
use hx_agent::privd::testing::{FakeRunner, Harness};
use hx_agent::privd::update::system::{HealthProbe, SocketProbe, Systemd, SystemdCtl, Unit};
use hx_ipc::admin::{self, Incoming, pb as apb};
use hx_ipc::privd::{PrivdPolicy, Side};
use hx_ipc::{Decoder, NoCmsgReader};

fn ctl_with(
    out: impl FnMut(&hx_agent::privd::runner::Program) -> RunOutput + Send + 'static,
) -> (SystemdCtl, Arc<FakeRunner>) {
    let r = FakeRunner::with(out);
    (SystemdCtl::new(r.clone()), r)
}

fn argv(r: &FakeRunner) -> Vec<Vec<String>> {
    r.calls()
        .into_iter()
        .map(|p| {
            assert_eq!(p.tool, Tool::Systemctl);
            assert!(p.stdin.is_none());
            p.args
        })
        .collect()
}

fn success() -> RunOutput {
    RunOutput {
        code: Some(0),
        ..RunOutput::default()
    }
}

#[tokio::test]
async fn the_fetcher_unit_is_started_by_a_fixed_argument_vector() {
    let (ctl, r) = ctl_with(|_| success());
    ctl.fetch(&Job::Manifest(Channel::Beta)).await.unwrap();
    ctl.fetch(&Job::Artifact("1.4.2-rc.1".into()))
        .await
        .unwrap();
    assert_eq!(
        argv(&r),
        [
            vec!["reset-failed", "hx-update-fetcher@manifest-beta.service"],
            vec!["start", "hx-update-fetcher@manifest-beta.service"],
            vec![
                "reset-failed",
                "hx-update-fetcher@artifact-1.4.2-rc.1.service"
            ],
            vec!["start", "hx-update-fetcher@artifact-1.4.2-rc.1.service"],
        ]
    );
    // Every call has a timeout and a cleared environment (the runner's rule); the artifact job
    // may run for its ten minutes plus a little, the manifest job for under a minute.
    let calls = r.calls();
    assert!(calls[1].timeout <= std::time::Duration::from_secs(60));
    assert!(calls[3].timeout > std::time::Duration::from_secs(600));
}

#[tokio::test]
async fn a_failed_or_slow_fetcher_is_stopped_and_reported_without_its_output() {
    let (ctl, r) = ctl_with(|p| {
        if p.args.first().map(String::as_str) == Some("start") {
            RunOutput {
                code: Some(1),
                stderr: "secret-looking stderr \u{1b}[31m".into(),
                ..RunOutput::default()
            }
        } else {
            success()
        }
    });
    let e = ctl
        .fetch(&Job::Manifest(Channel::Stable))
        .await
        .unwrap_err();
    assert!(e.contains("fetcher failed") && !e.contains("secret"), "{e}");
    let a = argv(&r);
    assert_eq!(
        a.last().unwrap(),
        &["stop", "hx-update-fetcher@manifest-stable.service"]
    );

    let (ctl, _r) = ctl_with(|p| {
        if p.args.first().map(String::as_str) == Some("start") {
            RunOutput {
                code: None,
                timed_out: true,
                ..RunOutput::default()
            }
        } else {
            success()
        }
    });
    let e = ctl.fetch(&Job::Artifact("1.0.1".into())).await.unwrap_err();
    assert!(e.contains("in time"), "{e}");
}

#[tokio::test]
async fn restarts_name_only_the_two_units_and_privd_does_not_wait() {
    let (ctl, r) = ctl_with(|_| success());
    ctl.restart(Unit::Gatewayd).await.unwrap();
    ctl.restart(Unit::Privd).await.unwrap();
    assert_eq!(
        argv(&r),
        [
            vec!["restart", "hx-gatewayd.service"],
            vec!["restart", "--no-block", "hx-privd.service"],
        ]
    );
    let (ctl, _) = ctl_with(|_| RunOutput {
        code: Some(5),
        ..RunOutput::default()
    });
    assert!(ctl.restart(Unit::Gatewayd).await.is_err());
}

#[tokio::test]
async fn unit_state_is_read_from_systemctl_show() {
    let (ctl, r) = ctl_with(|_| RunOutput {
        code: Some(0),
        stdout: "ActiveState=active\nMainPID=4711\n".into(),
        ..RunOutput::default()
    });
    let s = ctl.state(Unit::Gatewayd).await.unwrap();
    assert!(s.active);
    assert_eq!(s.main_pid, 4711);
    assert_eq!(
        argv(&r)[0],
        [
            "show",
            "--property=ActiveState",
            "--property=MainPID",
            "hx-gatewayd.service"
        ]
    );
    for (text, active, pid) in [
        ("ActiveState=activating\nMainPID=0\n", false, 0),
        ("ActiveState=failed\nMainPID=12\n", false, 12),
        ("MainPID=garbage\nActiveState=active\n", true, 0),
        ("", false, 0),
    ] {
        let (ctl, _) = ctl_with(move |_| RunOutput {
            code: Some(0),
            stdout: text.into(),
            ..RunOutput::default()
        });
        let s = ctl.state(Unit::Gatewayd).await.unwrap();
        assert_eq!((s.active, s.main_pid), (active, pid), "{text:?}");
    }
}

// ----- the socket probes ----------------------------------------------------------------------------

#[tokio::test]
async fn the_privd_probe_gets_hello_and_pong_from_the_real_server() {
    let h = Harness::start(rustix::process::getuid().as_raw());
    let probe = SocketProbe {
        privd_socket: h.socket.clone(),
        admin_socket: h.dir.path().join("none.sock"),
    };
    // The version of privd's own HelloAck, so an old process is told from a new one.
    assert!(probe.privd_answers().await.is_some_and(|v| !v.is_empty()));
    // Nothing listening: no.
    let probe = SocketProbe {
        privd_socket: h.dir.path().join("none.sock"),
        admin_socket: h.dir.path().join("none.sock"),
    };
    assert!(probe.privd_answers().await.is_none());
    assert!(probe.gatewayd_status().await.is_none());
}

/// A stand-in for gatewayd's admin socket: answers `Hello`, then `Status` with `reply`.
fn fake_admin(path: &std::path::Path, reply: fn(u64) -> apb::response::Result) {
    let l = UnixListener::bind(path).unwrap();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || serve(s, reply));
        }
    });
}

fn serve(s: UnixStream, reply: fn(u64) -> apb::response::Result) {
    use std::io::Write;
    let mut dec = Decoder::new(PrivdPolicy::new(Side::Server));
    let mut out = s.try_clone().unwrap();
    loop {
        let Ok(Some(raw)) = dec.read_from(&mut NoCmsgReader(&s)) else {
            return;
        };
        let Ok(Incoming::Message(f)) = admin::decode(raw, Side::Server) else {
            return;
        };
        let answer = match f.frame {
            Some(apb::frame::Frame::Hello(_)) => apb::frame::Frame::HelloAck(apb::HelloAck {
                major: 1,
                minor: 0,
                gatewayd_version: "test".into(),
            }),
            Some(apb::frame::Frame::Request(r)) => apb::frame::Frame::Response(apb::Response {
                request_id: r.request_id,
                result: Some(reply(r.request_id)),
            }),
            _ => return,
        };
        let bytes = admin::encode_message(
            &apb::Frame {
                frame: Some(answer),
            },
            Side::Client,
        )
        .unwrap();
        if out.write_all(&bytes).is_err() {
            return;
        }
    }
}

#[tokio::test]
async fn the_admin_probe_wants_a_status_result_and_nothing_else() {
    let d = tempfile::tempdir().unwrap();
    let probe_for = |name: &str| SocketProbe {
        privd_socket: d.path().join("unused"),
        admin_socket: d.path().join(name),
    };
    fake_admin(&d.path().join("ok.sock"), |_| {
        apb::response::Result::Status(apb::StatusResult {
            gatewayd_version: "fake-1.2.3".into(),
            ..Default::default()
        })
    });
    assert_eq!(
        probe_for("ok.sock").gatewayd_status().await.as_deref(),
        Some("fake-1.2.3")
    );

    // An error answer to Status (gatewayd up but unhealthy), or the answer to another command.
    fake_admin(&d.path().join("err.sock"), |_| {
        apb::response::Result::Error(hx_ipc::privd::pb::Error {
            code: hx_ipc::privd::pb::ErrorCode::Internal as i32,
            message: "bad".into(),
            ..Default::default()
        })
    });
    assert!(probe_for("err.sock").gatewayd_status().await.is_none());
    fake_admin(&d.path().join("wrong.sock"), |_| {
        apb::response::Result::ListDevices(apb::ListDevicesResult::default())
    });
    assert!(probe_for("wrong.sock").gatewayd_status().await.is_none());

    // A listener that accepts and says nothing: the probe gives up after its own timeout.
    let silent = UnixListener::bind(d.path().join("silent.sock")).unwrap();
    std::thread::spawn(move || {
        let _held: Vec<_> = silent.incoming().flatten().collect();
    });
    let started = std::time::Instant::now();
    assert!(probe_for("silent.sock").gatewayd_status().await.is_none());
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    assert!(probe_for("missing.sock").gatewayd_status().await.is_none());
}

#[tokio::test]
async fn stopping_a_fetch_stops_its_unit() {
    let (ctl, r) = ctl_with(|_| success());
    ctl.stop_fetch(&Job::Artifact("1.4.2".into())).await;
    assert_eq!(
        argv(&r),
        [vec!["stop", "hx-update-fetcher@artifact-1.4.2.service"]]
    );
}
