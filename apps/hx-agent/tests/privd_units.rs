//! The shipped systemd units and tmpfiles match docs/ipc.md section 3 and the daemon's constants.

use std::collections::BTreeMap;

use hx_agent::privd::cmd::hostsetup::docker_user_rules;
use hx_agent::privd::config::{AUDIT_LOG, FIREWALL_FILE, SOCKET_PATH, STATE_DIR, SYSCTL_FILE};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/systemd");

fn read(name: &str) -> String {
    std::fs::read_to_string(format!("{DIR}/{name}")).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// `section -> key -> every value, in order` (a unit file may repeat a key).
type Unit = BTreeMap<String, BTreeMap<String, Vec<String>>>;

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
            .unwrap_or_else(|| panic!("not a key=value line: {line}"));
        u.entry(section.clone())
            .or_default()
            .entry(k.trim().to_string())
            .or_default()
            .push(v.trim().to_string());
    }
    u
}

fn one<'a>(u: &'a Unit, section: &str, key: &str) -> &'a str {
    let v = u
        .get(section)
        .and_then(|s| s.get(key))
        .unwrap_or_else(|| panic!("[{section}] {key} is missing"));
    assert_eq!(v.len(), 1, "[{section}] {key} must appear once");
    &v[0]
}

fn words(u: &Unit, section: &str, key: &str) -> Vec<String> {
    u.get(section)
        .and_then(|s| s.get(key))
        .map(|vs| {
            vs.iter()
                .flat_map(|v| v.split_whitespace().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn the_socket_unit_is_exactly_ipc_md_section_3() {
    let u = parse(&read("hx-privd.socket"));
    assert_eq!(one(&u, "Socket", "ListenStream"), SOCKET_PATH);
    assert_eq!(one(&u, "Socket", "ListenStream"), "/run/hx/privd.sock");
    assert_eq!(one(&u, "Socket", "SocketUser"), "root");
    assert_eq!(one(&u, "Socket", "SocketGroup"), "hx-gatewayd");
    assert_eq!(one(&u, "Socket", "SocketMode"), "0660");
    assert_eq!(one(&u, "Socket", "Accept"), "no");
    // It orders itself after systemd-tmpfiles-setup.service, which creates /run/hx.
    assert!(words(&u, "Unit", "After").contains(&"systemd-tmpfiles-setup.service".to_string()));
    // Nothing else is listened on, and nothing widens the access.
    let socket = &u["Socket"];
    for k in socket.keys() {
        assert!(
            [
                "ListenStream",
                "SocketUser",
                "SocketGroup",
                "SocketMode",
                "Accept",
                "Service"
            ]
            .contains(&k.as_str()),
            "unexpected [Socket] key {k}"
        );
    }
}

#[test]
fn tmpfiles_creates_the_runtime_directories_of_section_3() {
    let text = read("tmpfiles.d/hx.conf");
    let lines: Vec<Vec<&str>> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split_whitespace().collect())
        .collect();
    assert!(lines.contains(&vec!["d", "/run/hx", "0755", "root", "root", "-"]));
    assert!(lines.contains(&vec![
        "d",
        "/run/hx/link",
        "0750",
        "root",
        "hx-gatewayd",
        "-"
    ]));
    // No other path is created under /run/hx, and nothing is removed.
    for l in &lines {
        assert!(matches!(l[0], "d" | "f"), "unexpected tmpfiles type {l:?}");
        if l[1].starts_with("/run/hx") {
            assert!(matches!(l[1], "/run/hx" | "/run/hx/link"), "{l:?}");
        }
    }
}

#[test]
fn the_service_is_root_hardened_and_matches_the_daemons_paths() {
    let u = parse(&read("hx-privd.service"));
    assert_eq!(one(&u, "Service", "User"), "root");
    assert_eq!(one(&u, "Unit", "Requires"), "hx-privd.socket");
    assert!(words(&u, "Unit", "After").contains(&"hx-privd.socket".to_string()));
    // ipc.md 5.2: mlockall must succeed and no core file.
    assert_eq!(one(&u, "Service", "LimitMEMLOCK"), "infinity");
    assert_eq!(one(&u, "Service", "LimitCORE"), "0");
    // State and audit log directories are the daemon's constants.
    assert_eq!(STATE_DIR, "/var/lib/hx");
    assert_eq!(one(&u, "Service", "StateDirectory"), "hx");
    assert_eq!(one(&u, "Service", "StateDirectoryMode"), "0700");
    assert_eq!(AUDIT_LOG, "/var/log/hx/audit.log");
    assert_eq!(one(&u, "Service", "LogsDirectory"), "hx");
    // The unit must not own /run/hx (RuntimeDirectory would delete it at stop, with the socket).
    assert!(!u["Service"].contains_key("RuntimeDirectory"));
    // Files the daemon writes outside its own directories are in ReadWritePaths.
    assert_eq!(one(&u, "Service", "ProtectSystem"), "strict");
    let rw = words(&u, "Service", "ReadWritePaths");
    for path in [FIREWALL_FILE, SYSCTL_FILE] {
        let dir = std::path::Path::new(path)
            .parent()
            .unwrap()
            .to_str()
            .unwrap();
        assert!(rw.iter().any(|p| p == dir), "{dir} must be writable");
    }
    // Hardening that must stay on.
    for (k, v) in [
        ("NoNewPrivileges", "yes"),
        ("MemoryDenyWriteExecute", "yes"),
        ("LockPersonality", "yes"),
        ("RestrictSUIDSGID", "yes"),
        ("RestrictRealtime", "yes"),
        ("RestrictNamespaces", "yes"),
        ("ProtectHome", "yes"),
        ("PrivateTmp", "yes"),
    ] {
        assert_eq!(one(&u, "Service", k), v, "{k}");
    }
    // Hardening that would break sysctl, blkid or nft stays off.
    for k in [
        "ProtectKernelTunables",
        "PrivateDevices",
        "PrivateNetwork",
        "ProcSubset",
    ] {
        assert!(
            !u["Service"].contains_key(k),
            "{k} would break the daemon's work"
        );
    }
    // Capabilities: only what nft, iptables, blkid and mlockall need.
    let caps = words(&u, "Service", "CapabilityBoundingSet");
    assert!(!caps.is_empty());
    for c in &caps {
        assert!(
            [
                "CAP_NET_ADMIN",
                "CAP_NET_RAW",
                "CAP_DAC_OVERRIDE",
                "CAP_IPC_LOCK"
            ]
            .contains(&c.as_str()),
            "{c}"
        );
    }
    // No environment is passed and the command is not a shell line (ipc.md 5.2, 7 rule 3).
    assert!(!u["Service"].contains_key("Environment"));
    assert!(!u["Service"].contains_key("EnvironmentFile"));
    let exec = one(&u, "Service", "ExecStart");
    assert_eq!(exec, "/usr/lib/hx/current/hx-privd");
}

#[test]
fn the_host_firewall_unit_loads_the_file_privd_writes_before_incus() {
    let u = parse(&read("hx-host-firewall.service"));
    let exec = one(&u, "Service", "ExecStart");
    assert_eq!(exec, format!("/usr/sbin/nft -f {FIREWALL_FILE}"));
    assert!(words(&u, "Unit", "Before").contains(&"incus.service".to_string()));
    assert_eq!(one(&u, "Service", "Type"), "oneshot");
}

#[test]
fn the_docker_user_unit_applies_the_rules_privd_applies() {
    let u = parse(&read("hx-docker-user.service"));
    let exec = one(&u, "Service", "ExecStart").to_string();
    for rule in docker_user_rules("hxbr0") {
        let joined = rule.join(" ");
        assert!(
            exec.contains(&format!("-C DOCKER-USER {joined}")),
            "check of `{joined}` missing"
        );
        assert!(
            exec.contains(&format!("-I DOCKER-USER 1 {joined}")),
            "insert of `{joined}` missing"
        );
    }
    assert!(words(&u, "Unit", "After").contains(&"docker.service".to_string()));
}

#[test]
fn m2_the_audit_log_is_rotated_with_a_sighup_to_privd() {
    let text = read("logrotate.d/hx-audit");
    assert!(text.contains(AUDIT_LOG));
    assert!(text.contains("create 0640 root root"));
    assert!(text.contains("postrotate"));
    assert!(text.contains("--signal=HUP hx-privd.service"));
}
