//! Live usage numbers of a desktop for `GetDesktop` (ipc.md 6.6, `DesktopUsage`).
//!
//! Read-only and free of extra Incus calls: everything comes from the instance state and instance
//! record that `GetDesktop` already fetches. CPU percent needs two samples of the cumulative CPU
//! time, so the daemon keeps the last one per desktop in memory ([`CpuTracker`]); no request ever
//! sleeps for a second sample.

use std::collections::BTreeMap;

use hx_ipc::privd::pb;
use hx_provision::incus::{Instance, InstanceState};

use super::timefmt::parse_rfc3339;

/// A sample closer than this to the previous one repeats the previous value.
const MIN_SPACING_MS: u64 = 1_000;
/// A previous sample older than this is not a meaningful baseline (the average would hide the
/// present): the series restarts and the percentage is absent once.
const MAX_AGE_MS: u64 = 10 * 60 * 1_000;

#[derive(Debug, Clone, Copy)]
struct CpuSample {
    unix_ms: u64,
    cpu_ns: u64,
    percent: Option<u32>,
}

/// The last CPU sample of each desktop. Bounded by the number of registered desktops (the id is
/// only ever one privd loaded).
#[derive(Debug, Default)]
pub struct CpuTracker(BTreeMap<String, CpuSample>);

impl CpuTracker {
    /// Records a sample for `id` and returns the CPU percent (0 to 100 of `cores` CPUs) since the
    /// previous accepted sample, or `None` when there is no usable baseline.
    pub fn observe(
        &mut self,
        id: &str,
        now_ms: u64,
        cpu_ns: Option<u64>,
        cores: u32,
    ) -> Option<u32> {
        let Some(ns) = cpu_ns else {
            self.0.remove(id);
            return None;
        };
        let fresh = CpuSample {
            unix_ms: now_ms,
            cpu_ns: ns,
            percent: None,
        };
        let Some(prev) = self.0.get(id).copied() else {
            self.0.insert(id.to_string(), fresh);
            return None;
        };
        if now_ms < prev.unix_ms || now_ms - prev.unix_ms > MAX_AGE_MS || ns < prev.cpu_ns {
            // Clock stepped back, stale baseline or counter reset (the instance restarted).
            self.0.insert(id.to_string(), fresh);
            return None;
        }
        let dt_ms = now_ms - prev.unix_ms;
        if dt_ms < MIN_SPACING_MS {
            return prev.percent;
        }
        let capacity_ns = dt_ms as f64 * 1e6 * f64::from(cores.max(1));
        let pct = (((ns - prev.cpu_ns) as f64 / capacity_ns) * 100.0)
            .round()
            .clamp(0.0, 100.0) as u32;
        self.0.insert(
            id.to_string(),
            CpuSample {
                percent: Some(pct),
                ..fresh
            },
        );
        Some(pct)
    }

    /// Drops the series of `id` (a stopped desktop starts a new one).
    pub fn forget(&mut self, id: &str) {
        self.0.remove(id);
    }
}

/// Seconds since the instance's last start; `None` when Incus has no start time (epoch zero or
/// empty), it cannot be parsed or it lies in the future.
pub fn uptime_s(instance: &Instance, now_s: u64) -> Option<u64> {
    let started = parse_rfc3339(&instance.last_used_at)?;
    // Incus reports 1970-01-01 for an instance that never ran.
    if started == 0 || started > now_s {
        return None;
    }
    Some(now_s - started)
}

/// The usage of a running desktop; `None` when it is not running. `cpu_percent` comes from
/// [`CpuTracker::observe`].
pub fn desktop_usage(
    st: &InstanceState,
    instance: &Instance,
    now_s: u64,
    cpu_percent: Option<u32>,
) -> Option<pb::DesktopUsage> {
    if !st.is_running() {
        return None;
    }
    const MIB: u64 = 1024 * 1024;
    Some(pb::DesktopUsage {
        cpu_percent,
        memory_used_mib: st.memory_usage_bytes.map(|b| b / MIB),
        // Drivers without accounting (`dir`) report nothing or 0; an installed OS never uses 0.
        disk_used_mib: st.disk_root_usage_bytes.filter(|b| *b > 0).map(|b| b / MIB),
        uptime_s: uptime_s(instance, now_s),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000_000;

    #[test]
    fn cpu_percent_from_two_samples() {
        let mut t = CpuTracker::default();
        assert_eq!(t.observe("a", 10_000, Some(5 * S), 2), None, "first sample");
        // 1 CPU-second busy over 2 s on 2 cores = 25 %.
        assert_eq!(t.observe("a", 12_000, Some(6 * S), 2), Some(25));
        // Too soon: repeats.
        assert_eq!(t.observe("a", 12_300, Some(9 * S), 2), Some(25));
        // Saturated and over-reported counters clamp to 100.
        assert_eq!(t.observe("a", 13_000, Some(20 * S), 2), Some(100));
    }

    #[test]
    fn cpu_series_restarts_on_reset_staleness_and_stop() {
        let mut t = CpuTracker::default();
        t.observe("a", 1_000, Some(10 * S), 1);
        assert_eq!(t.observe("a", 3_000, Some(S), 1), None, "counter went back");
        assert_eq!(t.observe("a", 5_000, Some(2 * S), 1), Some(50));
        assert_eq!(t.observe("a", 5_000 + MAX_AGE_MS + 1, Some(3 * S), 1), None);
        assert_eq!(
            t.observe("a", 1, Some(3 * S), 1),
            None,
            "clock stepped back"
        );
        assert_eq!(t.observe("a", 5_000, None, 1), None, "stopped");
        assert_eq!(t.observe("a", 7_000, Some(4 * S), 1), None, "new series");
        assert_eq!(t.observe("b", 7_000, Some(4 * S), 1), None, "per desktop");
    }

    fn running(cpu: Option<u64>, mem: Option<u64>, disk: Option<u64>) -> InstanceState {
        InstanceState {
            status: "Running".into(),
            cpu_usage_ns: cpu,
            memory_usage_bytes: mem,
            disk_root_usage_bytes: disk,
            ..Default::default()
        }
    }

    #[test]
    fn usage_fields_are_absent_when_unknown() {
        let inst = Instance {
            last_used_at: "2026-11-21T09:15:00Z".into(),
            ..Default::default()
        };
        let now = parse_rfc3339("2026-11-21T10:15:00Z").unwrap();
        let u = desktop_usage(
            &running(None, Some(3 << 20), Some(7 << 20)),
            &inst,
            now,
            Some(9),
        )
        .unwrap();
        assert_eq!(
            (
                u.cpu_percent,
                u.memory_used_mib,
                u.disk_used_mib,
                u.uptime_s
            ),
            (Some(9), Some(3), Some(7), Some(3600))
        );
        let none = desktop_usage(
            &running(None, None, Some(0)),
            &Instance::default(),
            now,
            None,
        )
        .unwrap();
        assert_eq!(none, pb::DesktopUsage::default());
        let stopped = InstanceState {
            status: "Stopped".into(),
            ..Default::default()
        };
        assert_eq!(desktop_usage(&stopped, &inst, now, None), None);
    }

    #[test]
    fn uptime_rejects_unset_and_future_start_times() {
        let at = |t: &str| Instance {
            last_used_at: t.into(),
            ..Default::default()
        };
        let now = parse_rfc3339("2026-11-21T10:15:00Z").unwrap();
        assert_eq!(uptime_s(&at("1970-01-01T00:00:00Z"), now), None);
        assert_eq!(uptime_s(&at("garbage"), now), None);
        assert_eq!(uptime_s(&at("2027-01-01T00:00:00Z"), now), None);
    }
}
