//! The "requirement checks" screen: the server's real values against the thresholds.
//!
//! One read-only probe script is piped to `sh -s` (constant text, nothing interpolated; the port
//! is only used to read the answer). It changes nothing on the server. The minimums are those of architecture
//! 4.1 and 5.2: `MemTotal` 3584 MiB, 2 CPUs, 30 GiB free, an x86_64 host with systemd 250+, one
//! of Ubuntu 24.04 / 26.04 and Debian 12 / 13, not inside a container, the port free.

use std::time::Duration;

use crate::error::{Result, SshSetupError};
use crate::ssh::Connection;
use crate::text::sanitize;

/// Minimum `MemTotal` in MiB.
pub const MIN_MEM_MIB: u64 = 3584;
/// Minimum CPUs.
pub const MIN_CPUS: u64 = 2;
/// Minimum free disk in GiB.
pub const MIN_DISK_GIB: u64 = 30;
/// Minimum systemd version.
pub const MIN_SYSTEMD: u32 = 250;
/// Supported `(ID, VERSION_ID)` pairs.
pub const SUPPORTED_OS: [(&str, &str); 4] = [
    ("ubuntu", "24.04"),
    ("ubuntu", "26.04"),
    ("debian", "12"),
    ("debian", "13"),
];

const SCRIPT: &str = r#"LC_ALL=C; export LC_ALL
echo "@uid"; id -u
echo "@os"; cat /etc/os-release 2>/dev/null
echo "@arch"; uname -m
echo "@systemd"; if [ -d /run/systemd/system ]; then echo yes; else echo no; fi
echo "@systemd-version"; systemctl --version 2>/dev/null | head -n 1
echo "@virt"; systemd-detect-virt -c 2>/dev/null | head -n 1
echo "@mem"; grep -m1 MemTotal /proc/meminfo
echo "@cpus"; nproc 2>/dev/null
echo "@disk"; df -Pk /var/lib/incus 2>/dev/null || df -Pk /var/lib 2>/dev/null
echo "@ss"; if command -v ss >/dev/null 2>&1; then echo yes; ss -H -ltun 2>/dev/null; else echo no; fi
echo "@sudo"; if command -v sudo >/dev/null 2>&1; then echo present; else echo absent; fi
echo "@sudo-n"; if [ "$(id -u)" = 0 ]; then echo root; elif sudo -n true >/dev/null 2>&1; then echo yes; else echo no; fi
echo "@end"
"#;

/// How commands get root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SudoMode {
    /// The SSH account is root.
    Root,
    /// `sudo` works without a password.
    Passwordless,
    /// `sudo` is installed and (probably) needs the account password.
    NeedsPassword,
    /// Not root and no `sudo`.
    Unavailable,
}

/// The outcome of one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Meets the minimum.
    Pass,
    /// Does not.
    Fail,
    /// Could not be measured; not blocking.
    Unknown,
}

/// One row of the requirement screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// Stable id: `os`, `arch`, `systemd`, `container`, `memory`, `cpus`, `disk`, `port`, `sudo`.
    pub id: &'static str,
    /// What is checked.
    pub label: &'static str,
    /// The result.
    pub status: Status,
    /// What the server has.
    pub actual: String,
    /// What is needed.
    pub required: String,
}

/// The raw facts read from the server.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServerFacts {
    /// `ID` of os-release.
    pub os_id: String,
    /// `VERSION_ID`.
    pub os_version: String,
    /// `PRETTY_NAME`.
    pub os_pretty: String,
    /// `uname -m`.
    pub arch: String,
    /// Whether systemd is the init system.
    pub systemd: bool,
    /// systemd's major version.
    pub systemd_version: Option<u32>,
    /// The container type when the host is itself a container (`lxc`, `docker`, ...).
    pub container: Option<String>,
    /// `MemTotal` in MiB.
    pub mem_mib: Option<u64>,
    /// Logical CPUs.
    pub cpus: Option<u64>,
    /// Free space in GiB where the Incus pool will live.
    pub disk_free_gib: Option<u64>,
    /// Whether something already listens on the port (TCP or UDP); `None` when `ss` is absent.
    pub port_in_use: Option<bool>,
    /// The port checked.
    pub port: u16,
    /// How commands will get root.
    pub sudo: Option<SudoMode>,
}

/// The facts and the verdict on each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightReport {
    /// What the server has.
    pub facts: ServerFacts,
    /// One row per requirement, in screen order.
    pub checks: Vec<Check>,
}

impl PreflightReport {
    /// The failed checks.
    pub fn failures(&self) -> Vec<&Check> {
        self.checks
            .iter()
            .filter(|c| c.status == Status::Fail)
            .collect()
    }

    /// True when nothing failed.
    pub fn passed(&self) -> bool {
        self.failures().is_empty()
    }

    /// `Ok` when nothing failed, else [`SshSetupError::RequirementFailed`] with the failed rows.
    pub fn require_ok(&self) -> Result<()> {
        let failed: Vec<Check> = self.failures().into_iter().cloned().collect();
        if failed.is_empty() {
            Ok(())
        } else {
            Err(SshSetupError::RequirementFailed(failed))
        }
    }
}

/// Reads the server's facts over `conn` and judges them. `port` is the public port the
/// installer will use (443 by default).
pub async fn preflight(conn: &Connection, port: u16) -> Result<PreflightReport> {
    let out = conn
        .exec("sh -s", Some(SCRIPT.as_bytes()), Duration::from_secs(30))
        .await?;
    if !out.success() {
        return Err(SshSetupError::Protocol(
            "the server's shell could not run the check script".into(),
        ));
    }
    Ok(evaluate(&parse_facts(&out.stdout_text(), port)))
}

fn sections(text: &str) -> std::collections::HashMap<&str, Vec<&str>> {
    let mut map: std::collections::HashMap<&str, Vec<&str>> = Default::default();
    let mut cur: Option<&str> = None;
    for line in text.lines() {
        if let Some(name) = line.strip_prefix('@') {
            cur = Some(name.trim());
            map.entry(name.trim()).or_default();
        } else if let Some(c) = cur {
            map.entry(c).or_default().push(line);
        }
    }
    map
}

fn os_release_value(lines: &[&str], key: &str) -> String {
    for l in lines {
        if let Some(v) = l.strip_prefix(key).and_then(|r| r.strip_prefix('=')) {
            return sanitize(v.trim().trim_matches('"').trim_matches('\''), 80);
        }
    }
    String::new()
}

/// Parses the output of the probe script (exposed for tests and for callers that run it over
/// another transport).
pub fn parse_facts(text: &str, port: u16) -> ServerFacts {
    let sec = sections(text);
    let first = |k: &str| {
        sec.get(k)
            .and_then(|v| v.iter().find(|l| !l.trim().is_empty()))
            .map(|l| l.trim())
            .unwrap_or("")
    };
    let os = sec.get("os").cloned().unwrap_or_default();
    let uid_root = first("uid") == "0";
    let sudo = if uid_root {
        Some(SudoMode::Root)
    } else if first("sudo") == "absent" {
        Some(SudoMode::Unavailable)
    } else if first("sudo-n") == "yes" {
        Some(SudoMode::Passwordless)
    } else if first("sudo") == "present" {
        Some(SudoMode::NeedsPassword)
    } else {
        None
    };
    let virt = first("virt");
    let ss = sec.get("ss").cloned().unwrap_or_default();
    let port_in_use = if ss.first().map(|l| l.trim()) == Some("yes") {
        let needle = format!(":{port}");
        Some(ss.iter().skip(1).any(|l| {
            l.split_whitespace()
                .nth(4)
                .is_some_and(|local| local.ends_with(&needle))
        }))
    } else {
        None
    };
    let mem_mib = first("mem")
        .split_whitespace()
        .nth(1)
        .and_then(|k| k.parse::<u64>().ok())
        .map(|kib| kib / 1024);
    let disk_free_gib = sec
        .get("disk")
        .and_then(|v| v.iter().rev().find(|l| !l.trim().is_empty()))
        .and_then(|l| l.split_whitespace().nth(3))
        .and_then(|k| k.parse::<u64>().ok())
        .map(|kib| kib / (1024 * 1024));
    ServerFacts {
        os_id: os_release_value(&os, "ID"),
        os_version: os_release_value(&os, "VERSION_ID"),
        os_pretty: os_release_value(&os, "PRETTY_NAME"),
        arch: sanitize(first("arch"), 32),
        systemd: first("systemd") == "yes",
        systemd_version: first("systemd-version")
            .split_whitespace()
            .nth(1)
            .and_then(|v| v.parse().ok()),
        container: (!virt.is_empty() && virt != "none").then(|| sanitize(virt, 32)),
        mem_mib,
        cpus: first("cpus").parse().ok(),
        disk_free_gib,
        port_in_use,
        port,
        sudo,
    }
}

/// Judges the facts against the thresholds.
pub fn evaluate(f: &ServerFacts) -> PreflightReport {
    let mut checks = Vec::new();
    let supported = SUPPORTED_OS
        .iter()
        .any(|(i, v)| *i == f.os_id && *v == f.os_version);
    checks.push(Check {
        id: "os",
        label: "Operating system",
        status: if supported {
            Status::Pass
        } else {
            Status::Fail
        },
        actual: if f.os_pretty.is_empty() {
            format!("{} {}", f.os_id, f.os_version).trim().to_owned()
        } else {
            f.os_pretty.clone()
        },
        required: "Ubuntu 24.04 or 26.04, Debian 12 or 13".into(),
    });
    checks.push(Check {
        id: "arch",
        label: "Architecture",
        status: if f.arch == "x86_64" {
            Status::Pass
        } else {
            Status::Fail
        },
        actual: f.arch.clone(),
        required: "x86_64".into(),
    });
    let sysd_ok = f.systemd && f.systemd_version.is_none_or(|v| v >= MIN_SYSTEMD);
    checks.push(Check {
        id: "systemd",
        label: "systemd",
        status: if sysd_ok { Status::Pass } else { Status::Fail },
        actual: match (f.systemd, f.systemd_version) {
            (false, _) => "not the init system".into(),
            (true, Some(v)) => format!("systemd {v}"),
            (true, None) => "systemd".into(),
        },
        required: format!("systemd {MIN_SYSTEMD} or newer"),
    });
    checks.push(Check {
        id: "container",
        label: "Bare host or VM",
        status: if f.container.is_none() {
            Status::Pass
        } else {
            Status::Fail
        },
        actual: f.container.as_ref().map_or_else(
            || "not a container".into(),
            |c| format!("inside a {c} container"),
        ),
        required: "not inside a container".into(),
    });
    checks.push(num(
        "memory",
        "Memory",
        f.mem_mib,
        MIN_MEM_MIB,
        "MiB",
        format!("{MIN_MEM_MIB} MiB (4 GB class)"),
    ));
    checks.push(num(
        "cpus",
        "CPUs",
        f.cpus,
        MIN_CPUS,
        "",
        format!("{MIN_CPUS}"),
    ));
    checks.push(num(
        "disk",
        "Free disk",
        f.disk_free_gib,
        MIN_DISK_GIB,
        "GiB",
        format!("{MIN_DISK_GIB} GiB"),
    ));
    checks.push(Check {
        id: "port",
        label: "Port",
        status: match f.port_in_use {
            Some(false) => Status::Pass,
            Some(true) => Status::Fail,
            None => Status::Unknown,
        },
        actual: match f.port_in_use {
            Some(false) => format!("{} is free", f.port),
            Some(true) => format!("{} is in use", f.port),
            None => format!("{} could not be checked", f.port),
        },
        required: format!("{} free (TCP and UDP)", f.port),
    });
    checks.push(Check {
        id: "sudo",
        label: "Administrator access",
        status: match f.sudo {
            Some(SudoMode::Unavailable) => Status::Fail,
            Some(_) => Status::Pass,
            None => Status::Unknown,
        },
        actual: match f.sudo {
            Some(SudoMode::Root) => "root".into(),
            Some(SudoMode::Passwordless) => "sudo without a password".into(),
            Some(SudoMode::NeedsPassword) => "sudo with the account password".into(),
            Some(SudoMode::Unavailable) => "not root, no sudo".into(),
            None => "unknown".into(),
        },
        required: "root, or an account that can use sudo".into(),
    });
    PreflightReport {
        facts: f.clone(),
        checks,
    }
}

fn num(
    id: &'static str,
    label: &'static str,
    have: Option<u64>,
    min: u64,
    unit: &str,
    required: String,
) -> Check {
    Check {
        id,
        label,
        status: match have {
            Some(v) if v >= min => Status::Pass,
            Some(_) => Status::Fail,
            None => Status::Unknown,
        },
        actual: have.map_or_else(
            || "could not be read".into(),
            |v| format!("{v} {unit}").trim().to_owned(),
        ),
        required,
    }
}

/// Finds out how this account gets root: the same probe as the preflight's `sudo` row, alone.
pub(crate) async fn detect_sudo(conn: &Connection) -> Result<SudoMode> {
    let script = "if [ \"$(id -u)\" = 0 ]; then echo root; \
                  elif ! command -v sudo >/dev/null 2>&1; then echo none; \
                  elif sudo -n true >/dev/null 2>&1; then echo passwordless; \
                  else echo password; fi\n";
    let out = conn
        .exec("sh -s", Some(script.as_bytes()), Duration::from_secs(20))
        .await?;
    match out.stdout_text().trim() {
        "root" => Ok(SudoMode::Root),
        "passwordless" => Ok(SudoMode::Passwordless),
        "password" => Ok(SudoMode::NeedsPassword),
        "none" => Ok(SudoMode::Unavailable),
        _ => Err(SshSetupError::Protocol(
            "cannot tell how this account gets root".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "@uid\n1000\n@os\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n\
@arch\nx86_64\n@systemd\nyes\n@systemd-version\nsystemd 255 (255.4-1ubuntu8)\n@virt\nnone\n\
@mem\nMemTotal:        8123456 kB\n@cpus\n4\n@disk\nFilesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 100000000 1000 62914560 2% /\n\
@ss\nyes\ntcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nudp UNCONN 0 0 127.0.0.53:53 0.0.0.0:*\n\
@sudo\npresent\n@sudo-n\nno\n@end\n@port\n443\n";

    #[test]
    fn parses_a_healthy_server() {
        let f = parse_facts(GOOD, 443);
        assert_eq!(f.os_id, "ubuntu");
        assert_eq!(f.os_version, "24.04");
        assert_eq!(f.arch, "x86_64");
        assert!(f.systemd);
        assert_eq!(f.systemd_version, Some(255));
        assert_eq!(f.container, None);
        assert_eq!(f.mem_mib, Some(7933));
        assert_eq!(f.cpus, Some(4));
        assert_eq!(f.disk_free_gib, Some(60));
        assert_eq!(f.port_in_use, Some(false));
        assert_eq!(f.sudo, Some(SudoMode::NeedsPassword));
        let r = evaluate(&f);
        assert!(r.passed(), "{:?}", r.failures());
        assert!(r.require_ok().is_ok());
        assert_eq!(r.checks.len(), 9);
    }

    #[test]
    fn every_threshold_fails_exactly_where_it_should() {
        let mut f = parse_facts(GOOD, 443);
        f.mem_mib = Some(3583);
        f.cpus = Some(1);
        f.disk_free_gib = Some(29);
        f.arch = "aarch64".into();
        f.os_version = "22.04".into();
        f.systemd_version = Some(249);
        f.container = Some("lxc".into());
        f.port_in_use = Some(true);
        f.sudo = Some(SudoMode::Unavailable);
        let r = evaluate(&f);
        let ids: Vec<_> = r.failures().iter().map(|c| c.id).collect();
        assert_eq!(
            ids,
            [
                "os",
                "arch",
                "systemd",
                "container",
                "memory",
                "cpus",
                "disk",
                "port",
                "sudo"
            ]
        );
        match r.require_ok() {
            Err(SshSetupError::RequirementFailed(v)) => assert_eq!(v.len(), 9),
            other => panic!("{other:?}"),
        }
        // The boundary values pass.
        f = parse_facts(GOOD, 443);
        f.mem_mib = Some(3584);
        f.cpus = Some(2);
        f.disk_free_gib = Some(30);
        f.systemd_version = Some(250);
        assert!(evaluate(&f).passed());
    }

    #[test]
    fn missing_tools_are_unknown_not_failures() {
        let f = parse_facts(
            "@uid\n0\n@os\nID=debian\nVERSION_ID=\"12\"\n@arch\nx86_64\n@systemd\nyes\n@ss\nno\n@sudo\nabsent\n",
            443,
        );
        assert_eq!(f.sudo, Some(SudoMode::Root));
        assert_eq!(f.port_in_use, None);
        let r = evaluate(&f);
        let unknown: Vec<_> = r
            .checks
            .iter()
            .filter(|c| c.status == Status::Unknown)
            .map(|c| c.id)
            .collect();
        assert_eq!(unknown, ["memory", "cpus", "disk", "port"]);
        assert!(r.passed());
    }

    #[test]
    fn hostile_output_is_sanitized() {
        let f = parse_facts("@os\nPRETTY_NAME=\"Evil\u{202E}OS\u{1b}[2J\"\nID=x\n", 443);
        assert_eq!(f.os_pretty, "EvilOS[2J");
    }

    #[test]
    fn a_listener_on_another_port_does_not_count() {
        let f = parse_facts(
            "@ss\nyes\ntcp LISTEN 0 1 [::]:4430 [::]:*\ntcp LISTEN 0 1 *:443 *:*\n",
            443,
        );
        assert_eq!(f.port_in_use, Some(true));
        let f = parse_facts("@ss\nyes\ntcp LISTEN 0 1 [::]:4430 [::]:*\n", 443);
        assert_eq!(f.port_in_use, Some(false));
    }
}
