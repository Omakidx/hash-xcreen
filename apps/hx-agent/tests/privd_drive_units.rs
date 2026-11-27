//! The hardening of `hx-drive.socket` and `hx-drive.service` (docs/ipc.md section 24, "Drive
//! link"): socket-activated, root-only socket, a dynamic user with no capabilities, only IP
//! sockets with the fetcher's egress limits, the fetcher's system-call filter, the sealed token
//! credential, bounded memory, and installed with the other units but not enabled.

use std::collections::BTreeMap;

use hx_agent::install::units::{self, Dest, Enable};
use hx_agent::privd::update::VERSIONS_DIR;

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

fn one<'a>(u: &'a Unit, section: &str, key: &str) -> &'a str {
    let v = u
        .get(section)
        .and_then(|s| s.get(key))
        .unwrap_or_else(|| panic!("[{section}] {key} is missing"));
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

fn service() -> Unit {
    parse(&read("hx-drive.service"))
}

#[test]
fn the_socket_is_root_only_and_activates_the_service() {
    let u = parse(&read("hx-drive.socket"));
    assert_eq!(one(&u, "Socket", "ListenStream"), "/run/hx/drive.sock");
    assert_eq!(one(&u, "Socket", "SocketUser"), "root");
    assert_eq!(one(&u, "Socket", "SocketMode"), "0600");
    assert_eq!(one(&u, "Socket", "Accept"), "no");
    assert_eq!(one(&u, "Socket", "Service"), "hx-drive.service");
    assert!(
        !u["Socket"].contains_key("SocketGroup"),
        "no group may connect"
    );
    // /run/hx exists before the socket is bound
    assert_eq!(one(&u, "Unit", "After"), "systemd-tmpfiles-setup.service");
    let t = read("tmpfiles.d/hx.conf");
    assert!(t.lines().any(|l| l.starts_with("d /run/hx ")), "{t}");
}

#[test]
fn the_service_runs_the_drive_role_of_the_current_worker_binary() {
    let u = service();
    assert_eq!(
        one(&u, "Service", "ExecStart"),
        format!("{VERSIONS_DIR}/current/hx-backup-worker"),
        "no argument: the role comes from the environment alone"
    );
    assert_eq!(one(&u, "Service", "Environment"), "HX_BACKUP_ROLE=drive");
    assert!(!u["Service"].contains_key("EnvironmentFile"));
    assert_eq!(one(&u, "Service", "Type"), "simple");
    // the binary exits itself when idle; a failure (75: no OAuth client) must not be retried in a loop
    assert!(!u["Service"].contains_key("Restart"));
    assert!(!u["Service"].contains_key("RuntimeMaxSec"));
    // it is started by its socket only
    assert!(!u.contains_key("Install"));
}

#[test]
fn the_token_credential_is_sealed_and_loaded_by_the_service_manager() {
    let u = service();
    assert_eq!(
        one(&u, "Service", "LoadCredentialEncrypted"),
        "drive-token:/etc/hx/creds/drive-token.cred"
    );
    // the unit cannot read the credential's source itself
    let hidden = words(&u, "InaccessiblePaths");
    for p in ["/etc/hx", "/var/lib/hx", "/var/lib/hx-gatewayd", "/run/hx"] {
        assert!(hidden.iter().any(|h| h == p), "{p} is hidden: {hidden:?}");
    }
}

#[test]
fn the_service_is_a_dynamic_user_with_no_capabilities_and_no_privilege() {
    let u = service();
    assert_eq!(one(&u, "Service", "DynamicUser"), "yes");
    assert_ne!(one(&u, "Service", "User"), "root");
    assert!(words(&u, "SupplementaryGroups").is_empty());
    assert_eq!(one(&u, "Service", "CapabilityBoundingSet"), "");
    assert_eq!(one(&u, "Service", "AmbientCapabilities"), "");
    for k in [
        "NoNewPrivileges",
        "RestrictSUIDSGID",
        "LockPersonality",
        "MemoryDenyWriteExecute",
        "RestrictRealtime",
        "RestrictNamespaces",
        "ProtectKernelTunables",
        "ProtectKernelModules",
        "ProtectKernelLogs",
        "ProtectControlGroups",
        "ProtectClock",
        "ProtectHostname",
        "RemoveIPC",
        "ProtectHome",
        "PrivateTmp",
        "PrivateDevices",
    ] {
        assert_eq!(one(&u, "Service", k), "yes", "{k}");
    }
    assert_eq!(one(&u, "Service", "ProtectSystem"), "strict");
    assert_eq!(one(&u, "Service", "ProtectProc"), "invisible");
    assert!(
        !u["Service"].contains_key("ReadWritePaths") && !u["Service"].contains_key("BindPaths"),
        "it writes nowhere"
    );
    assert_eq!(one(&u, "Service", "LimitFSIZE"), "0");
    assert_eq!(one(&u, "Service", "UMask"), "0077");
}

#[test]
fn the_network_and_system_call_rules_are_the_fetchers() {
    let u = service();
    let f = parse(&read("hx-update-fetcher@.service"));
    // IP only: no AF_UNIX of its own (the activated descriptor is inherited), no netlink
    let fam = words(&u, "RestrictAddressFamilies");
    assert_eq!(fam, ["AF_INET", "AF_INET6"]);
    for key in [
        "RestrictAddressFamilies",
        "IPAddressDeny",
        "IPAddressAllow",
        "SystemCallFilter",
        "SystemCallArchitectures",
        "SystemCallErrorNumber",
    ] {
        assert_eq!(
            words(&u, key),
            words(&f, key),
            "{key} differs from the update fetcher's"
        );
    }
    assert!(!u["Service"].contains_key("PrivateNetwork"));
    let deny = words(&u, "IPAddressDeny");
    for r in [
        "localhost",
        "link-local",
        "multicast",
        "10.0.0.0/8",
        "192.168.0.0/16",
        "fc00::/7",
    ] {
        assert!(deny.iter().any(|d| d == r), "{r} is denied");
    }
    assert_eq!(
        words(&u, "IPAddressAllow"),
        ["127.0.0.53/32", "127.0.0.54/32"]
    );
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
        "mkdir",
        "rename",
        "chmod",
    ] {
        assert!(denied.contains(&g), "{g} is denied");
    }
}

#[test]
fn memory_tasks_and_descriptors_are_bounded() {
    let u = service();
    assert_eq!(one(&u, "Service", "MemoryMax"), "512M", "ipc.md section 24");
    assert_eq!(one(&u, "Service", "LimitCORE"), "0");
    assert!(one(&u, "Service", "LimitNOFILE").parse::<u32>().unwrap() <= 256);
    assert!(one(&u, "Service", "TasksMax").parse::<u32>().unwrap() <= 64);
}

#[test]
fn the_units_are_installed_with_the_others_but_not_enabled() {
    for name in ["hx-drive.socket", "hx-drive.service"] {
        let row = units::find(name).unwrap_or_else(|| panic!("{name} is not in units::FILES"));
        assert_eq!(row.dest, Dest::Unit);
        assert_eq!(
            row.enable,
            Enable::No,
            "{name}: the Drive-connect flow enables it"
        );
        assert_eq!(row.text, read(name), "the embedded text is the file");
    }
}
