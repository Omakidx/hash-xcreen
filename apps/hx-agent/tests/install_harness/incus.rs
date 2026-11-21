//! The host side of the nested harness: every Incus object the run creates is named `hx1e-...`,
//! carries `user.hx1e-test=1`, and is removed again. The harness only talks to the Incus daemon
//! (it never runs `nft`, `iptables` or `sysctl`, and never touches the `default` profile, the
//! `incusbr0` bridge, the `default` pool or any Docker object).

use std::process::{Command, Stdio};

pub const PREFIX: &str = "hx1e-";
pub const POOL: &str = "hx1e-pool";
pub const BRIDGE: &str = "hx1e-br0";
pub const PROFILE: &str = "hx1e-l1";
/// The gateway address of the test bridge (also where the CONNECT proxy listens).
pub const BRIDGE_ADDR: &str = "10.77.0.1";
pub const BRIDGE_CIDR: &str = "10.77.0.1/24";

#[derive(Debug)]
pub struct Out {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Out {
    pub fn ok(&self) -> bool {
        self.code == 0
    }
}

/// `incus <args>` with stdin closed.
pub fn incus(args: &[&str]) -> Out {
    let o = Command::new("incus")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("spawn incus");
    Out {
        code: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

/// `incus <args>`, panicking with the output when it fails.
pub fn incus_ok(args: &[&str]) -> String {
    let o = incus(args);
    assert!(
        o.ok(),
        "incus {args:?} failed ({}): {} {}",
        o.code,
        o.stdout,
        o.stderr
    );
    o.stdout
}

/// `sh -c script` in `inst` as root (no stdin).
pub fn exec(inst: &str, script: &str) -> Out {
    incus(&[
        "exec",
        inst,
        "--force-noninteractive",
        "--",
        "sh",
        "-c",
        script,
    ])
}

/// `exec`, panicking when the script fails.
pub fn exec_ok(inst: &str, script: &str) -> String {
    let o = exec(inst, script);
    assert!(
        o.ok(),
        "`{script}` in {inst} failed ({}): {} {}",
        o.code,
        o.stdout,
        o.stderr
    );
    o.stdout
}

/// Pushes a file as root:root with `mode`.
pub fn push(inst: &str, local: &std::path::Path, remote: &str, mode: &str) {
    incus_ok(&[
        "file",
        "push",
        "--uid",
        "0",
        "--gid",
        "0",
        "--mode",
        mode,
        "--create-dirs",
        &local.to_string_lossy(),
        &format!("{inst}{remote}"),
    ]);
}

/// Pushes the bytes of `data` to `remote` as root:root with `mode`.
pub fn push_bytes(inst: &str, data: &[u8], remote: &str, mode: &str) {
    let t = tempfile::NamedTempFile::new().expect("tempfile");
    std::fs::write(t.path(), data).expect("write");
    push(inst, t.path(), remote, mode);
}

/// Pulls a file's bytes (None when it is missing).
pub fn pull(inst: &str, remote: &str) -> Option<Vec<u8>> {
    let t = tempfile::NamedTempFile::new().expect("tempfile");
    let o = incus(&[
        "file",
        "pull",
        &format!("{inst}{remote}"),
        &t.path().to_string_lossy(),
    ]);
    o.ok().then(|| std::fs::read(t.path()).expect("read"))
}

/// Pushes a directory tree to `remote_parent/<name>`, root-owned (install.sh insists on that).
pub fn push_dir(inst: &str, local: &std::path::Path, remote_parent: &str) {
    incus_ok(&[
        "file",
        "push",
        "-r",
        "--uid",
        "0",
        "--gid",
        "0",
        &local.to_string_lossy(),
        &format!("{inst}{remote_parent}"),
    ]);
}

/// The names of every `hx1e-` object, per kind. Empty means clean.
pub fn leftovers() -> Vec<String> {
    let mut v = Vec::new();
    for (kind, args) in [
        ("instance", vec!["list", "--format", "csv", "-c", "n"]),
        (
            "profile",
            vec!["profile", "list", "--format", "csv", "-c", "n"],
        ),
        (
            "network",
            vec!["network", "list", "--format", "csv", "-c", "n"],
        ),
        (
            "storage",
            vec!["storage", "list", "--format", "csv", "-c", "n"],
        ),
        (
            "network-acl",
            vec!["network", "acl", "list", "--format", "csv", "-c", "n"],
        ),
    ] {
        let o = incus(&args);
        for l in o.stdout.lines().map(str::trim) {
            if l.starts_with(PREFIX) {
                v.push(format!("{kind}:{l}"));
            }
        }
    }
    v
}

/// Removes every `hx1e-` object this harness could have made. Best effort, in dependency order;
/// returns what is still there.
pub fn cleanup() -> Vec<String> {
    let o = incus(&["list", "--format", "csv", "-c", "n"]);
    for n in o
        .stdout
        .lines()
        .map(str::trim)
        .filter(|n| n.starts_with(PREFIX))
    {
        let _ = incus(&["delete", "--force", n]);
    }
    let _ = incus(&["profile", "delete", PROFILE]);
    let _ = incus(&["network", "delete", BRIDGE]);
    // The image volume Incus keeps in the pool after launching from an image.
    let vols = incus(&[
        "storage", "volume", "list", POOL, "--format", "csv", "-c", "tn",
    ]);
    for l in vols.stdout.lines() {
        if let Some(name) = l.strip_prefix("image,") {
            let _ = incus(&[
                "storage",
                "volume",
                "delete",
                POOL,
                &format!("image/{name}"),
            ]);
        }
    }
    let _ = incus(&["storage", "delete", POOL]);
    leftovers()
}

/// `incus <show>` of the three objects the harness must not change, with the `used_by` lists
/// removed: other sessions on this shared machine start and stop instances all the time, and a
/// list of users is not configuration. The harness separately asserts that no `hx1e-` object is
/// among the users.
pub fn default_objects() -> Vec<(String, String)> {
    let mut v = Vec::new();
    for (name, args) in [
        ("profile default", vec!["profile", "show", "default"]),
        ("network incusbr0", vec!["network", "show", "incusbr0"]),
        ("storage default", vec!["storage", "show", "default"]),
    ] {
        let raw = incus_ok(&args);
        assert!(
            !raw.contains(PREFIX),
            "{name} is used by an hx1e- object: {raw}"
        );
        let mut keep = String::new();
        let mut skipping = false;
        for l in raw.lines() {
            if l.starts_with("used_by:") {
                skipping = true;
                continue;
            }
            if skipping && l.starts_with("- ") {
                continue;
            }
            skipping = false;
            keep.push_str(l);
            keep.push('\n');
        }
        v.push((name.to_owned(), keep));
    }
    v
}

/// Creates pool, bridge and profile (see the module docs of the test for why each key is set).
pub fn create_host_objects() {
    // The bridge: no NAT, no firewall rules, no routing, no IPv6, no ACL. With these keys
    // incusd's bridge driver builds no firewall options at all (FeaturesV4 needs ipv4.firewall,
    // SNATV4 needs ipv4.nat, ACL needs security.acls) and writes no ip_forward sysctl (needs
    // ipv4.routing), so NetworkSetup has nothing to apply. Incus 6.0.0, driver_bridge.go.
    incus_ok(&[
        "network",
        "create",
        BRIDGE,
        &format!("ipv4.address={BRIDGE_CIDR}"),
        "ipv4.nat=false",
        "ipv4.firewall=false",
        "ipv4.routing=false",
        "ipv6.address=none",
        "ipv6.nat=false",
        "ipv6.firewall=false",
        "ipv6.routing=false",
        "dns.mode=none",
        "user.hx1e-test=1",
    ]);
    incus_ok(&[
        "storage",
        "create",
        POOL,
        "btrfs",
        "size=60GiB",
        "user.hx1e-test=1",
    ]);
    incus_ok(&["profile", "create", PROFILE]);
    incus_ok(&[
        "profile",
        "device",
        "add",
        PROFILE,
        "root",
        "disk",
        "path=/",
        &format!("pool={POOL}"),
        "size=50GiB",
    ]);
    incus_ok(&[
        "profile",
        "device",
        "add",
        PROFILE,
        "eth0",
        "nic",
        &format!("network={BRIDGE}"),
        "name=eth0",
    ]);
}

/// Sets the L1 profile's container keys. `apparmor_signal` is the Debian 13 L1's test-only
/// `raw.apparmor`.
pub fn configure_profile(apparmor_signal: bool) {
    let mut a: Vec<&str> = vec![
        "profile",
        "set",
        PROFILE,
        "security.nesting=true",
        "security.syscalls.intercept.mknod=true",
        "security.syscalls.intercept.setxattr=true",
        "security.idmap.isolated=true",
        "security.idmap.size=1000000",
        "limits.kernel.memlock=unlimited",
        "limits.cpu=4",
        "limits.memory=8GiB",
        "user.hx1e-test=1",
    ];
    if apparmor_signal {
        a.push("raw.apparmor=signal,");
    }
    incus_ok(&a);
}
