//! Facts about the host that commands need (CPU, memory, pool space, OS), behind a trait so that
//! the bounds of ipc.md 6.8 and 8 are tested with chosen numbers.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Sysctl keys and the minimum values `SetupHost` writes (ipc.md 6.4 step 4).
pub const SYSCTLS: [(&str, u64); 4] = [
    ("fs.inotify.max_queued_events", 1_048_576),
    ("fs.inotify.max_user_instances", 1_048_576),
    ("fs.inotify.max_user_watches", 1_048_576),
    ("vm.max_map_count", 262_144),
];

/// Free space for a prebuilt image (ipc.md 6.5 step 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageSpace {
    /// Free bytes on the file system of privd's state directory (the staging copy).
    pub state_free: u64,
    /// Free bytes on the file system of Incus's data directory (Incus's copy).
    pub incus_free: u64,
    /// Both directories are on one device, so the two copies add up.
    pub same_device: bool,
}

/// Reads the free space and device of two directories with `statvfs` and `stat`.
pub fn read_image_space(state_dir: &Path, incus_dir: &Path) -> Option<ImageSpace> {
    use std::os::unix::fs::MetadataExt;
    let (_, state_free) = fs_space(state_dir)?;
    let (_, incus_free) = fs_space(incus_dir)?;
    let same_device =
        std::fs::metadata(state_dir).ok()?.dev() == std::fs::metadata(incus_dir).ok()?.dev();
    Some(ImageSpace {
        state_free,
        incus_free,
        same_device,
    })
}

/// Host facts.
pub trait HostProbe: Send + Sync {
    /// CPUs available to this process.
    fn cpu_count(&self) -> u32;
    /// `(total, available)` memory in MiB.
    fn memory_mib(&self) -> (u64, u64);
    /// `(ID, VERSION_ID)` of `/etc/os-release`.
    fn os_release(&self) -> (String, String);
    /// `(total, free)` bytes of the filesystem of the storage pool `pool`, if it can be read.
    fn pool_space(&self, pool: &str) -> Option<(u64, u64)>;
    /// Free bytes of the filesystem that holds Incus's data (where a loop-file pool is created).
    fn incus_dir_free(&self) -> Option<u64>;
    /// Whether every sysctl of [`SYSCTLS`] is at least its configured value.
    fn sysctl_ok(&self) -> bool;
    /// Free space for the staging and Incus copies of a prebuilt image; `None` when a directory
    /// cannot be read (the disk rule then fails closed). The default reads the real file systems.
    fn image_space(&self, state_dir: &Path, incus_dir: &Path) -> Option<ImageSpace> {
        read_image_space(state_dir, incus_dir)
    }
}

/// Reads the real host.
#[derive(Debug, Clone)]
pub struct SystemProbe {
    incus_dir: PathBuf,
}

impl SystemProbe {
    /// A probe that finds pools under `incus_dir/storage-pools/<name>`.
    pub fn new(incus_dir: &Path) -> Self {
        Self {
            incus_dir: incus_dir.to_path_buf(),
        }
    }
}

fn fs_space(path: &Path) -> Option<(u64, u64)> {
    let s = rustix::fs::statvfs(path).ok()?;
    Some((
        s.f_blocks.saturating_mul(s.f_frsize),
        s.f_bavail.saturating_mul(s.f_frsize),
    ))
}

/// `(MemTotal, MemAvailable)` in MiB from `/proc/meminfo` text.
pub fn parse_meminfo(text: &str) -> (u64, u64) {
    let field = |name: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(name)?.strip_prefix(':'))
            .and_then(|v| v.trim().strip_suffix("kB")?.trim().parse::<u64>().ok())
            .map_or(0, |kb| kb / 1024)
    };
    (field("MemTotal"), field("MemAvailable"))
}

/// `(ID, VERSION_ID)` from `/etc/os-release` text; quotes are stripped.
pub fn parse_os_release(text: &str) -> (String, String) {
    let get = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
            .map(|v| v.trim().trim_matches('"').to_string())
            .unwrap_or_default()
    };
    (get("ID"), get("VERSION_ID"))
}

/// Every address of every interface except `skip_iface`, from `ip -j address show` output.
///
/// An error when the text is not a JSON array (truncated or garbled output) or lists no address at
/// all (a host always has at least a loopback): the ACL's host drops must never be built from a
/// partial or empty list.
pub fn parse_ip_addresses(json: &str, skip_iface: &str) -> Result<Vec<IpAddr>, &'static str> {
    let Ok(serde_json::Value::Array(ifaces)) = serde_json::from_str(json) else {
        return Err("the address list is not valid JSON (truncated?)");
    };
    let mut out: Vec<IpAddr> = Vec::new();
    for i in &ifaces {
        if i.get("ifname").and_then(|v| v.as_str()) == Some(skip_iface) {
            continue;
        }
        for a in i
            .get("addr_info")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            if let Some(ip) = a
                .get("local")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<IpAddr>().ok())
                && !out.contains(&ip)
            {
                out.push(ip);
            }
        }
    }
    if out.is_empty() {
        return Err("the address list is empty");
    }
    Ok(out)
}

impl HostProbe for SystemProbe {
    fn cpu_count(&self) -> u32 {
        std::thread::available_parallelism()
            .map(|n| u32::try_from(n.get()).unwrap_or(u32::MAX))
            .unwrap_or(1)
    }

    fn memory_mib(&self) -> (u64, u64) {
        std::fs::read_to_string("/proc/meminfo")
            .map(|t| parse_meminfo(&t))
            .unwrap_or((0, 0))
    }

    fn os_release(&self) -> (String, String) {
        std::fs::read_to_string("/etc/os-release")
            .or_else(|_| std::fs::read_to_string("/usr/lib/os-release"))
            .map(|t| parse_os_release(&t))
            .unwrap_or_default()
    }

    fn pool_space(&self, pool: &str) -> Option<(u64, u64)> {
        fs_space(&self.incus_dir.join("storage-pools").join(pool))
    }

    fn incus_dir_free(&self) -> Option<u64> {
        fs_space(&self.incus_dir).map(|(_, free)| free)
    }

    fn sysctl_ok(&self) -> bool {
        SYSCTLS.iter().all(|(k, want)| {
            let path = format!("/proc/sys/{}", k.replace('.', "/"));
            std::fs::read_to_string(path)
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .is_some_and(|v| v >= *want)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meminfo_and_os_release() {
        let m = "MemTotal:       65839104 kB\nMemFree: 1 kB\nMemAvailable:   34516992 kB\n";
        assert_eq!(parse_meminfo(m), (64296, 33708));
        assert_eq!(parse_meminfo("garbage"), (0, 0));
        let o = "NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n";
        assert_eq!(parse_os_release(o), ("ubuntu".into(), "24.04".into()));
        assert_eq!(parse_os_release(""), (String::new(), String::new()));
    }

    #[test]
    fn addresses_skip_our_bridge_and_duplicates() {
        let j = r#"[
          {"ifname":"lo","addr_info":[{"family":"inet","local":"127.0.0.1"},{"family":"inet6","local":"::1"}]},
          {"ifname":"eth0","addr_info":[{"family":"inet","local":"203.0.113.5"},{"family":"inet6","local":"fe80::1"}]},
          {"ifname":"docker0","addr_info":[{"family":"inet","local":"172.17.0.1"}]},
          {"ifname":"hx-br0","addr_info":[{"family":"inet","local":"10.99.0.1"}]},
          {"ifname":"dup","addr_info":[{"family":"inet","local":"203.0.113.5"},{"family":"inet","local":"not-an-ip"}]}
        ]"#;
        let ips: Vec<String> = parse_ip_addresses(j, "hx-br0")
            .unwrap()
            .into_iter()
            .map(|i| i.to_string())
            .collect();
        assert_eq!(
            ips,
            ["127.0.0.1", "::1", "203.0.113.5", "fe80::1", "172.17.0.1"]
        );
        assert!(parse_ip_addresses("not json", "x").is_err());
        assert!(parse_ip_addresses("[]", "x").is_err());
        // Truncated output is an error, never a shorter list.
        assert!(parse_ip_addresses(&j[..j.len() - 40], "hx-br0").is_err());
        // A host with many interfaces: well over 64 KiB of JSON parses.
        let mut big = String::from("[");
        for n in 0..400 {
            big.push_str(&format!(
                "{{\"ifname\":\"veth{n}\",\"flags\":[\"BROADCAST\"],\"pad\":\"{}\",\"addr_info\":[{{\"family\":\"inet\",\"local\":\"10.{}.{}.1\"}}]}},",
                "x".repeat(150),
                n / 250,
                n % 250
            ));
        }
        big.push_str(
            "{\"ifname\":\"lo\",\"addr_info\":[{\"family\":\"inet\",\"local\":\"127.0.0.1\"}]}]",
        );
        assert!(big.len() > 64 * 1024);
        assert_eq!(parse_ip_addresses(&big, "none").unwrap().len(), 401);
    }

    #[test]
    fn the_system_probe_reads_this_host() {
        let p = SystemProbe::new(Path::new("/"));
        assert!(p.cpu_count() >= 1);
        assert!(p.memory_mib().0 > 0);
        assert!(p.incus_dir_free().is_some());
    }
}
