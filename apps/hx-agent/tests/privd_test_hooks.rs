//! The `privd-test-hooks` feature (design C12): a sysctl failure such as EPERM (a nested VM or an
//! unprivileged container, where `/proc/sys` is read-only) is a warning instead of a failure of
//! `SetupHost`. In a normal build the same failure is an error, which is what a release build
//! does. Run the hook half with
//! `cargo nextest run -p hx-agent --features privd-test-hooks --test privd_test_hooks`.

use std::sync::Arc;

use hx_agent::privd::daemon::Ctx;
use hx_agent::privd::runner::{RunOutput, Tool};
use hx_agent::privd::testing::{FakeIncus, FakeProbe, FakeRunner, Harness, error_of, request};
use hx_ipc::privd::pb::{self, ErrorDetail, Role, request::Command};

const GW: u32 = 4_242;

/// Everything succeeds except `sysctl -p`, which fails the way a read-only `/proc/sys` does.
fn eperm_runner() -> Arc<FakeRunner> {
    FakeRunner::with(|p| match p.tool {
        Tool::Sysctl => RunOutput {
            code: Some(255),
            stderr: "sysctl: permission denied on key \"fs.inotify.max_user_instances\"\n".into(),
            ..Default::default()
        },
        Tool::Ip => RunOutput {
            code: Some(0),
            stdout: r#"[{"ifname":"eth0","addr_info":[{"family":"inet","local":"203.0.113.9"}]}]"#
                .into(),
            ..Default::default()
        },
        Tool::Iptables if p.args.first().map(String::as_str) == Some("-C") => RunOutput {
            code: Some(1),
            ..Default::default()
        },
        _ => RunOutput {
            code: Some(0),
            ..Default::default()
        },
    })
}

async fn setup_host(h: &Harness) -> pb::Response {
    h.daemon
        .handle(
            request(1, Command::SetupHost(pb::SetupHostRequest::default())),
            Ctx::new(Role::Admin),
        )
        .await
}

fn harness(probe: FakeProbe) -> Harness {
    let h = Harness::start_with(GW, probe, FakeIncus::new(), eperm_runner());
    h.incus.with(|s| s.pool_exists = false);
    h
}

#[cfg(feature = "privd-test-hooks")]
mod with_hooks {
    use super::*;
    use hx_ipc::privd::pb::response::Result as R;

    #[tokio::test]
    async fn a_sysctl_eperm_is_a_warning_and_setup_host_still_succeeds() {
        let h = harness(FakeProbe::default());
        let r = setup_host(&h).await;
        let Some(R::SetupHost(r)) = r.result else {
            panic!("{r:?}");
        };
        assert!(!r.sysctl_applied, "the answer says the values are not in effect");
        assert!(r.firewall_loaded, "the rest of the host setup is unaffected");
        // The drop-in is still written: it applies at the next boot of a real host.
        assert!(h.daemon.cfg.sysctl_file.exists());
        assert!(
            h.audit
                .lines()
                .iter()
                .any(|l| l.contains("warning (privd-test-hooks)") && l.contains("sysctl")),
            "the warning is audited: {:?}",
            h.audit.lines()
        );
    }

    #[tokio::test]
    async fn values_that_did_not_take_effect_are_a_warning_too() {
        let probe = FakeProbe {
            sysctl_ok: false,
            ..FakeProbe::default()
        };
        let h = Harness::start_with(GW, probe, FakeIncus::new(), FakeRunner::new());
        assert!(!h.daemon.apply_sysctl().await.unwrap());
    }

    #[tokio::test]
    async fn only_the_sysctl_step_is_softened() {
        // A failing nft load is still an error with the hook on.
        let runner = FakeRunner::with(|p| RunOutput {
            code: Some(i32::from(p.tool == Tool::Nft)),
            stdout: if p.tool == Tool::Ip {
                r#"[{"ifname":"eth0","addr_info":[{"family":"inet","local":"203.0.113.9"}]}]"#
                    .into()
            } else {
                String::new()
            },
            ..Default::default()
        });
        let h = Harness::start_with(GW, FakeProbe::default(), FakeIncus::new(), runner);
        h.incus.with(|s| s.pool_exists = false);
        let r = setup_host(&h).await;
        let e = error_of(&r).expect("an error");
        assert_eq!(e.detail(), ErrorDetail::Nft);
    }
}

#[cfg(not(feature = "privd-test-hooks"))]
mod without_hooks {
    use super::*;
    use hx_ipc::privd::pb::ErrorCode;

    #[tokio::test]
    async fn a_sysctl_eperm_fails_setup_host_in_a_normal_build() {
        let h = harness(FakeProbe::default());
        let r = setup_host(&h).await;
        let e = error_of(&r).expect("SetupHost must fail");
        assert_eq!((e.code(), e.detail()), (ErrorCode::Internal, ErrorDetail::Sysctl));
    }
}
