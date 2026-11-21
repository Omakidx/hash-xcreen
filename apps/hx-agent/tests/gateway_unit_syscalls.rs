//! `hx-gatewayd.service` filters system calls (`SystemCallFilter=`, answering `EPERM`), and the
//! binary then installs its own seccomp allowlist with the `seccomp` system call. `seccomp` is in
//! systemd's `@sandbox` group, not in `@system-service`, so the unit has to allow it by name or
//! the daemon cannot start under real systemd.
//!
//! Found by the nested-Incus installer run (docs/spikes/1e-installer-nested-incus.md): with the
//! unit as first merged, `hx-gatewayd` failed at start with
//! `seccomp: Error calling seccomp: Operation not permitted`.

/// The words the unit's `SystemCallFilter=` lines allow (lines starting with `~` deny).
fn allowed_syscalls(unit: &str) -> Vec<String> {
    unit.lines()
        .filter_map(|l| l.trim().strip_prefix("SystemCallFilter="))
        .filter(|v| !v.starts_with('~'))
        .flat_map(|v| v.split_whitespace().map(str::to_owned).collect::<Vec<_>>())
        .collect()
}

#[test]
fn the_unit_allows_the_seccomp_call_the_binary_makes_to_confine_itself() {
    let unit = include_str!("../systemd/hx-gatewayd.service");
    let allowed = allowed_syscalls(unit);
    assert!(
        allowed.iter().any(|w| w == "seccomp"),
        "SystemCallFilter= must list `seccomp` (it is not in @system-service); allowed: {allowed:?}"
    );
}

#[test]
fn the_unit_still_allows_what_the_hardening_code_needs_before_the_filter() {
    let unit = include_str!("../systemd/hx-gatewayd.service");
    let allowed = allowed_syscalls(unit);
    for w in ["@system-service", "setrlimit", "prlimit64", "mlockall"] {
        assert!(allowed.iter().any(|x| x == w), "missing {w}: {allowed:?}");
    }
}
