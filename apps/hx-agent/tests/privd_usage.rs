//! `GetDesktop` usage numbers (docs/ipc.md 6.6) against the fake Incus.

use hx_agent::privd::daemon::Ctx;
use hx_agent::privd::testing::{Harness, request};
use hx_agent::privd::timefmt::rfc3339;
use hx_ipc::privd::pb::{self, Role, request::Command, response::Result as R};
use serde_json::{Value, json};

const GW: u32 = 4_242;
const NOW: u64 = 1_800_000_000;

fn harness() -> Harness {
    let h = Harness::start(GW);
    h.incus
        .add_desktop("hx-main", "ubuntu-24.04-xfce-basic", "alice", true);
    h.daemon.register_desktop("main").unwrap();
    h
}

fn set(h: &Harness, running: bool, state_extra: Value, last_used: Option<u64>) {
    h.incus.with(|s| {
        let i = s.instances.get_mut("hx-main").unwrap();
        i.status = if running { "Running" } else { "Stopped" }.into();
        i.state_extra = state_extra;
        i.last_used_at = last_used.map(rfc3339).unwrap_or_default();
    });
}

async fn usage(h: &Harness) -> Option<pb::DesktopUsage> {
    let r = h
        .daemon
        .handle(
            request(
                1,
                Command::GetDesktop(pb::GetDesktopRequest {
                    desktop_id: "main".into(),
                }),
            ),
            Ctx::new(Role::Gateway),
        )
        .await;
    let Some(R::GetDesktop(g)) = r.result else {
        panic!("{r:?}")
    };
    g.desktop.unwrap().usage
}

fn state(cpu_s: u64, disk: Option<i64>) -> Value {
    let mut v = json!({"cpu": {"usage": cpu_s * 1_000_000_000}, "memory": {"usage": 512u64 << 20}});
    if let Some(d) = disk {
        v["disk"] = json!({"root": {"usage": d}});
    }
    v
}

#[tokio::test]
async fn running_desktop_reports_memory_disk_uptime_and_cpu_from_two_samples() {
    let h = harness();
    set(&h, true, state(100, Some(3 << 30)), Some(NOW - 7200));
    let first = usage(&h).await.unwrap();
    assert_eq!(first.cpu_percent, None, "one sample is not a rate");
    assert_eq!(first.memory_used_mib, Some(512));
    assert_eq!(first.disk_used_mib, Some(3072));
    assert_eq!(first.uptime_s, Some(7200));

    // limits.cpu is 2: 2 CPU-seconds busy over 4 s is 25 %.
    h.clock.advance_secs(4);
    set(&h, true, state(102, Some(3 << 30)), Some(NOW - 7200));
    let second = usage(&h).await.unwrap();
    assert_eq!(second.cpu_percent, Some(25));
    assert_eq!(second.uptime_s, Some(7204));
}

#[tokio::test]
async fn disk_is_absent_without_driver_accounting_and_uptime_without_a_start_time() {
    let h = harness();
    for disk in [None, Some(-1), Some(0)] {
        set(&h, true, state(1, disk), None);
        let u = usage(&h).await.unwrap();
        assert_eq!(u.disk_used_mib, None, "{disk:?}");
        assert_eq!(u.uptime_s, None);
        assert_eq!(u.memory_used_mib, Some(512));
    }
}

#[tokio::test]
async fn stopped_desktop_has_no_usage_and_the_cpu_series_restarts() {
    let h = harness();
    set(&h, true, state(10, None), Some(NOW));
    usage(&h).await;
    set(&h, false, Value::Null, Some(NOW));
    assert_eq!(usage(&h).await, None);
    h.clock.advance_secs(5);
    set(&h, true, state(11, None), Some(NOW + 5));
    assert_eq!(usage(&h).await.unwrap().cpu_percent, None, "new series");
}

#[tokio::test]
async fn usage_costs_no_extra_incus_requests() {
    let h = harness();
    set(&h, true, state(1, None), Some(NOW));
    usage(&h).await;
    let before = h.incus.log().len();
    usage(&h).await;
    let per_call = h.incus.log().len() - before;
    // GetDesktop's own reads: instance, state, snapshots.
    assert_eq!(per_call, 3, "{:?}", h.incus.log());
}
