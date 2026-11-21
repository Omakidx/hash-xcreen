//! The hardening of `hx-update-fetcher@.service` and the unit changes the update path needs
//! (docs/ipc.md 6.12): a dynamic user, no capabilities, no `AF_UNIX`, bounded in size and time,
//! writing only to privd's directory; and that every unit runs its binary through the
//! `/usr/lib/hx/current` link that privd switches.

use std::collections::BTreeMap;

use hx_agent::fetcher;
use hx_agent::privd::config::STATE_DIR;
use hx_agent::privd::update::{UpdateConfig, VERSIONS_DIR};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/systemd");

type Unit = BTreeMap<String, BTreeMap<String, Vec<String>>>;

fn read(name: &str) -> String {
    std::fs::read_to_string(format!("{DIR}/{name}")).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn parse(text: &str) -> Unit {
    let mut u = Unit::new();
    let mut section = String::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(s) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = s.to_string();
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("bad line: {line}"));
        u.entry(section.clone())
            .or_default()
            .entry(k.trim().to_string())
            .or_default()
            .push(v.trim().to_string());
    }
    u
}

fn one<'a>(u: &'a Unit, key: &str) -> &'a str {
    let v = u
        .get("Service")
        .and_then(|s| s.get(key))
        .unwrap_or_else(|| panic!("[Service] {key} is missing"));
    assert_eq!(v.len(), 1, "{key} must appear once");
    &v[0]
}

fn words(u: &Unit, key: &str) -> Vec<String> {
    u.get("Service")
        .and_then(|s| s.get(key))
        .map(|vs| {
            vs.iter()
                .flat_map(|v| v.split_whitespace().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn fetcher_unit() -> Unit {
    parse(&read("hx-update-fetcher@.service"))
}

#[test]
fn the_fetcher_runs_as_a_dynamic_user_with_no_capabilities() {
    let u = fetcher_unit();
    assert_eq!(one(&u, "DynamicUser"), "yes");
    assert_eq!(one(&u, "Type"), "oneshot");
    // An empty bounding set and no ambient capabilities.
    assert_eq!(one(&u, "CapabilityBoundingSet"), "");
    assert_eq!(one(&u, "AmbientCapabilities"), "");
    assert_eq!(one(&u, "NoNewPrivileges"), "yes");
    assert_eq!(one(&u, "RestrictSUIDSGID"), "yes");
    assert!(words(&u, "SupplementaryGroups").is_empty());
    assert!(
        !u["Service"].contains_key("Restart"),
        "a failed fetch is reported, not retried"
    );
    assert!(
        !u["Service"].contains_key("User") || one(&u, "User") != "root",
        "never root"
    );
}

#[test]
fn the_fetcher_can_reach_the_internet_and_no_unix_socket() {
    let u = fetcher_unit();
    let fam = words(&u, "RestrictAddressFamilies");
    assert_eq!(fam, ["AF_INET", "AF_INET6"], "exactly the two IP families");
    assert!(!fam.iter().any(|f| f == "AF_UNIX" || f == "AF_NETLINK"));
    assert!(
        !fam.iter().any(|f| f.starts_with('~')),
        "an allow list, not a deny list"
    );
    // Not a private network (it has to reach the release hosts), and no wide-open exceptions.
    assert!(!u["Service"].contains_key("PrivateNetwork"));
    assert!(!u["Service"].contains_key("IPAddressAllow"));
}

#[test]
fn the_fetcher_cannot_write_anywhere_but_privds_directory() {
    let u = fetcher_unit();
    assert_eq!(one(&u, "ProtectSystem"), "strict");
    assert_eq!(one(&u, "ProtectHome"), "yes");
    assert_eq!(one(&u, "PrivateTmp"), "yes");
    assert_eq!(one(&u, "PrivateDevices"), "yes");
    assert!(
        !u["Service"].contains_key("ReadWritePaths"),
        "the only writable path is the bind mount"
    );
    // The bind mount: privd's update directory onto the path the binary writes to.
    let want = format!(
        "{}:{}",
        UpdateConfig::production(std::path::Path::new(STATE_DIR))
            .fetch_dir
            .display(),
        fetcher::OUT_DIR
    );
    assert_eq!(one(&u, "BindPaths"), want);
    for k in [
        "ProtectKernelTunables",
        "ProtectKernelModules",
        "ProtectKernelLogs",
        "ProtectControlGroups",
        "ProtectClock",
        "ProtectHostname",
        "LockPersonality",
        "MemoryDenyWriteExecute",
        "RestrictRealtime",
        "RestrictNamespaces",
        "RemoveIPC",
    ] {
        assert_eq!(one(&u, k), "yes", "{k}");
    }
    assert_eq!(one(&u, "ProtectProc"), "invisible");
}

#[test]
fn the_fetcher_is_bounded_in_size_time_and_system_calls() {
    let u = fetcher_unit();
    // LimitFSIZE is the artifact quota the binary enforces itself.
    let fsize: u64 = one(&u, "LimitFSIZE").parse().unwrap();
    assert_eq!(fsize, fetcher::MAX_ARTIFACT_BYTES);
    assert_eq!(one(&u, "LimitCORE"), "0");
    assert!(one(&u, "LimitNOFILE").parse::<u32>().unwrap() <= 256);
    assert!(one(&u, "TasksMax").parse::<u32>().unwrap() <= 64);
    assert!(one(&u, "MemoryMax").ends_with('M'));
    // The unit's hard stop is a little after the binary's own 10 minute artifact timeout.
    let stop: u64 = one(&u, "RuntimeMaxSec").parse().unwrap();
    let own = fetcher::ARTIFACT_TIMEOUT.as_secs();
    assert!(stop > own && stop <= own + 120, "{stop} vs {own}");
    assert_eq!(one(&u, "TimeoutStartSec").parse::<u64>().unwrap(), stop);
    // The system-call filter: the service set minus everything privileged or resource-changing.
    let filters = &u["Service"]["SystemCallFilter"];
    assert!(filters.iter().any(|f| f == "@system-service"));
    let denied: Vec<&str> = filters
        .iter()
        .filter_map(|f| f.strip_prefix('~'))
        .flat_map(str::split_whitespace)
        .collect();
    for g in [
        "@privileged",
        "@resources",
        "@mount",
        "@module",
        "@reboot",
        "@raw-io",
        "@debug",
    ] {
        assert!(denied.contains(&g), "{g} is denied");
    }
    assert_eq!(one(&u, "SystemCallArchitectures"), "native");
    // 0644 files, so that privd (which has no CAP_DAC_OVERRIDE) can read them.
    assert_eq!(one(&u, "UMask"), "0022");
}

#[test]
fn the_instance_is_the_only_argument_and_the_binary_is_the_current_release() {
    let u = fetcher_unit();
    let exec = one(&u, "ExecStart");
    assert_eq!(exec, format!("{VERSIONS_DIR}/current/hx-update-fetcher %i"));
    // Nothing else is passed: no shell, no environment.
    assert!(!exec.contains(';') && !exec.contains("sh -c"));
    assert!(!u["Service"].contains_key("Environment"));
    assert!(!u["Service"].contains_key("EnvironmentFile"));
}

#[test]
fn every_unit_runs_its_binary_through_the_current_link() {
    for unit in [
        "hx-privd.service",
        "hx-gatewayd.service",
        "hx-update-fetcher@.service",
    ] {
        let u = parse(&read(unit));
        let exec = one(&u, "ExecStart");
        assert!(
            exec.starts_with(&format!("{VERSIONS_DIR}/current/")),
            "{unit}: {exec}"
        );
    }
}

#[test]
fn privd_may_write_the_release_directory_and_nothing_else_under_usr() {
    let u = parse(&read("hx-privd.service"));
    let rw = words(&u, "ReadWritePaths");
    assert!(
        rw.iter().any(|p| p.trim_start_matches('-') == VERSIONS_DIR),
        "{rw:?}"
    );
    assert!(rw.iter().all(|p| {
        let p = p.trim_start_matches('-');
        !p.starts_with("/usr") || p == VERSIONS_DIR
    }));
    // privd itself still speaks no IP: the fetcher is the only networked part.
    assert_eq!(one(&u, "IPAddressDeny"), "any");
}

#[test]
fn the_fetchers_mount_point_exists_before_it_starts() {
    let t = read("tmpfiles.d/hx.conf");
    assert!(
        t.lines().any(|l| {
            let f: Vec<_> = l.split_whitespace().collect();
            f.len() >= 4 && f[0] == "d" && f[1] == fetcher::OUT_DIR && f[3] == "root"
        }),
        "{t}"
    );
}
