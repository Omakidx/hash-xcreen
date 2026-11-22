//! Stage `preflight`: read-only checks (design C1). Nothing is changed; a failure is exit 9 with
//! every failed check listed, except `--image prebuilt` and `--image-file`, which are exit 6
//! ("not in this release": privd answers `UNIMPLEMENTED` for both).
//!
//! The checks are split in two because `--interactive` asks its questions between them: first
//! what depends only on the host ([`host_checks`]), then what depends on the options the operator
//! chose ([`option_checks`]).

use super::ctx::Ctx;
use super::error::{InstallError, Result};
use super::fsx::read_text;
use super::paths;
use super::runner::{Call, Tool};
use super::stages::incus;

/// Least RAM, MiB.
pub const MIN_MEM_MIB: u64 = 3584;
/// Fewest CPUs.
pub const MIN_CPUS: u32 = 2;
/// Least free space for the Incus storage, GiB.
pub const MIN_FREE_GIB: u64 = 30;
/// Least free space on `/` when the pool is a block device, GiB.
pub const MIN_ROOT_FREE_GIB: u64 = 5;
/// Oldest systemd (`systemd-creds` and `LoadCredentialEncrypted=` arrived in 250).
pub const MIN_SYSTEMD: u32 = 250;

/// The supported hosts (design Q2): Ubuntu 22.04 is dropped.
pub const SUPPORTED: &[(&str, &str)] = &[
    ("ubuntu", "24.04"),
    ("ubuntu", "26.04"),
    ("debian", "12"),
    ("debian", "13"),
];

/// `ID` and `VERSION_ID` and `VERSION_CODENAME` of an os-release text.
pub fn parse_os_release(text: &str) -> (String, String, String) {
    let get = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix('=')))
            .map(|v| v.trim().trim_matches('"').trim_matches('\'').to_owned())
            .unwrap_or_default()
    };
    (get("ID"), get("VERSION_ID"), get("VERSION_CODENAME"))
}

/// The number of `systemd 255 (255.4-1ubuntu8)`.
pub fn parse_systemd_version(text: &str) -> Option<u32> {
    text.lines().next()?.split_whitespace().nth(1)?.parse().ok()
}

/// MemTotal of /proc/meminfo in MiB.
pub fn parse_mem_total_mib(text: &str) -> Option<u64> {
    let kb: u64 = text
        .lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    Some(kb / 1024)
}

/// The host-only checks. Returns the list of failures.
fn host_failures(ctx: &mut Ctx<'_>) -> Vec<String> {
    let mut bad: Vec<String> = Vec::new();

    let os = read_text(&ctx.paths.at(paths::OS_RELEASE)).unwrap_or_default();
    let (id, ver, _) = parse_os_release(&os);
    if id == "ubuntu" && ver == "22.04" {
        bad.push(
            "Ubuntu 22.04 is not supported (its systemd 249 has no systemd-creds); use Ubuntu 24.04 or 26.04, or Debian 12 or 13"
                .into(),
        );
    } else if !SUPPORTED.iter().any(|(i, v)| *i == id && *v == ver) {
        bad.push(format!(
            "this host ({} {}) is not supported; supported: Ubuntu 24.04, 26.04, Debian 12, 13",
            crate::cli::text::peer(&id, 32),
            crate::cli::text::peer(&ver, 32)
        ));
    }

    let machine = ctx.probe.machine();
    if machine != "x86_64" {
        bad.push(format!(
            "the architecture is {}, only x86_64 is supported",
            crate::cli::text::peer(&machine, 32)
        ));
    }

    if !ctx.paths.at("/run/systemd/system").is_dir() {
        bad.push(
            "systemd is not the init system of this host (/run/systemd/system is missing)".into(),
        );
    } else {
        match ctx.run(Call::new(Tool::Systemctl, &["--version"])) {
            Ok(o) if o.ok() => match parse_systemd_version(&o.out_text()) {
                Some(v) if v >= MIN_SYSTEMD => {}
                Some(v) => bad.push(format!(
                    "systemd {v} is too old; {MIN_SYSTEMD} or newer is required (systemd-creds)"
                )),
                None => bad.push("cannot read the systemd version".into()),
            },
            _ => bad.push("cannot run systemctl --version".into()),
        }
    }

    if !ctx.paths.at("/sys/fs/cgroup/cgroup.controllers").exists() {
        bad.push("cgroup v2 is not mounted at /sys/fs/cgroup".into());
    }

    let userns = read_text(&ctx.paths.at("/proc/sys/user/max_user_namespaces"))
        .and_then(|t| t.trim().parse::<u64>().ok())
        .unwrap_or(0);
    if userns == 0 {
        bad.push("user namespaces are disabled (user.max_user_namespaces is 0)".into());
    }

    if !ctx.hooks.allow_container {
        match ctx.run(Call::new(Tool::SystemdDetectVirt, &["-c"])) {
            Ok(o) => {
                let t = o.out_text();
                let kind = t.trim();
                if o.ok() && kind != "none" && !kind.is_empty() {
                    bad.push(format!(
                        "this host is a container ({}); install on a virtual machine or a physical host",
                        crate::cli::text::peer(kind, 32)
                    ));
                }
            }
            Err(_) => bad.push("cannot determine whether this host is a container".into()),
        }
    }

    let mem = read_text(&ctx.paths.at("/proc/meminfo"))
        .and_then(|t| parse_mem_total_mib(&t))
        .unwrap_or(0);
    if mem < MIN_MEM_MIB {
        bad.push(format!(
            "{mem} MiB of RAM; at least {MIN_MEM_MIB} MiB are required"
        ));
    }
    let cpus = ctx.probe.cpus();
    if cpus < MIN_CPUS {
        bad.push(format!("{cpus} CPU; at least {MIN_CPUS} are required"));
    }

    // Free space: where Incus keeps its data (or would), unless the pool is a whole device.
    if ctx.opts.storage_device.is_none() {
        let probe_path = {
            let p = ctx.paths.at(paths::VAR_LIB_HX);
            let inc = ctx.paths.at("/var/lib/incus");
            if inc.exists() {
                inc
            } else if let Some(parent) = p.parent().filter(|d| d.exists()) {
                parent.to_path_buf()
            } else {
                ctx.paths.root().to_path_buf()
            }
        };
        match ctx.probe.free_gib(&probe_path) {
            Ok(g) if g >= MIN_FREE_GIB => {}
            Ok(g) => bad.push(format!(
                "{g} GiB free for the desktop's storage; at least {MIN_FREE_GIB} GiB are required (or use --storage-device)"
            )),
            Err(_) => bad.push("cannot read the free disk space".into()),
        }
    }

    // A release must be there to install, or already installed.
    let release_ok =
        ctx.bootstrap_dir.is_some() || super::stages::release::installed_current(ctx).is_some();
    if !release_ok {
        bad.push(
            "there is no release to install: run hx-agent install through install.sh (it downloads and verifies one)"
                .into(),
        );
    }

    // Incus rules (design D4): adopted and never upgraded; --docker needs 6.0.5.
    match incus::existing_version(ctx) {
        Ok(Some(v)) => {
            if !incus::at_least(&v, incus::MIN_VERSION) {
                bad.push(format!(
                    "the installed Incus {v} is older than 6.0.0 and is never upgraded by hash-xcreen; upgrade or remove it first"
                ));
            } else if ctx.opts.docker && !incus::at_least(&v, incus::DOCKER_MIN_VERSION) {
                bad.push(format!(
                    "--docker needs Incus 6.0.5 or newer and the installed Incus {v} is never upgraded by hash-xcreen; upgrade it, or install without --docker"
                ));
            }
        }
        Ok(None) => {}
        Err(e) => bad.push(e.message),
    }
    bad
}

/// The checks that depend only on the host. Prints the Docker note.
pub fn host_checks(ctx: &mut Ctx<'_>) -> Result<()> {
    let bad = host_failures(ctx);
    if ctx.paths.at("/run/docker.sock").exists() || ctx.paths.at("/var/run/docker.sock").exists() {
        ctx.warn(
            "preflight",
            "Docker is running on this host; hash-xcreen keeps the desktop isolated from it (information only)",
        );
    }
    finish(bad)
}

fn finish(bad: Vec<String>) -> Result<()> {
    if bad.is_empty() {
        return Ok(());
    }
    let mut m = String::from("preflight failed, nothing was changed:");
    for b in &bad {
        m.push_str("\n  - ");
        m.push_str(b);
    }
    Err(InstallError::preflight(m))
}

/// The checks that depend on the options.
pub fn option_checks(ctx: &mut Ctx<'_>) -> Result<()> {
    if ctx.opts.image == "prebuilt" || ctx.image_file.is_some() {
        return Err(InstallError::unimplemented(
            "--image prebuilt and --image-file are not in this release (privd answers UNIMPLEMENTED); use --image build or auto. Nothing was changed",
        ));
    }
    let mut bad: Vec<String> = Vec::new();
    let port = ctx.opts.port;
    let ours = ctx.state.created.socket_port == port && socket_active(ctx);
    if !ours && !ctx.probe.port_free(port) {
        bad.push(format!(
            "port {port} is in use for TCP or UDP (choose another with --port)"
        ));
    }
    if let Some(dev) = ctx.opts.storage_device.clone() {
        match ctx.probe.block_device(&dev) {
            Err(_) => bad.push(format!("{dev} cannot be read")),
            Ok(i) => {
                if !i.is_block {
                    bad.push(format!("{dev} is not a block device"));
                }
                if i.is_block && !i.whole_disk {
                    bad.push(format!("{dev} is a partition; a whole disk is required"));
                }
                if i.mounted {
                    bad.push(format!("{dev} (or a partition of it) is mounted"));
                }
                if i.signature {
                    bad.push(format!(
                        "{dev} has a filesystem, RAID, LVM or LUKS signature; wipe it first if you are sure"
                    ));
                }
                if i.is_block && i.size_gib < MIN_FREE_GIB {
                    bad.push(format!(
                        "{dev} is {} GiB; at least {MIN_FREE_GIB} GiB are required",
                        i.size_gib
                    ));
                }
            }
        }
        match ctx.probe.free_gib(ctx.paths.root()) {
            Ok(g) if g >= MIN_ROOT_FREE_GIB => {}
            Ok(g) => bad.push(format!(
                "{g} GiB free on the root file system; at least {MIN_ROOT_FREE_GIB} GiB are required with --storage-device"
            )),
            Err(_) => bad.push("cannot read the free disk space of /".into()),
        }
    }
    if ctx.mode.builds_desktop() && ctx.opts.user.is_none() {
        bad.push("--user is required (the desktop's Linux user)".into());
    }
    if bad.is_empty() {
        return Ok(());
    }
    finish(bad)
}

fn socket_active(ctx: &mut Ctx<'_>) -> bool {
    ctx.run(Call::new(
        Tool::Systemctl,
        &["is-active", "--quiet", "hx-gatewayd-public.socket"],
    ))
    .is_ok_and(|o| o.ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_release_is_parsed() {
        let t = "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\nVERSION_CODENAME=noble\n";
        assert_eq!(
            parse_os_release(t),
            ("ubuntu".into(), "24.04".into(), "noble".into())
        );
        let d = "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n";
        assert_eq!(parse_os_release(d).0, "debian");
        assert_eq!(parse_os_release("").0, "");
    }

    #[test]
    fn systemd_and_meminfo_are_parsed() {
        assert_eq!(
            parse_systemd_version("systemd 255 (255.4-1ubuntu8)\n+PAM"),
            Some(255)
        );
        assert_eq!(
            parse_systemd_version("systemd 249 (249.11-0ubuntu3)\n"),
            Some(249)
        );
        assert_eq!(parse_systemd_version("nonsense"), None);
        assert_eq!(
            parse_mem_total_mib("MemTotal:       16384000 kB\nMemFree: 1 kB\n"),
            Some(16_000)
        );
        assert_eq!(parse_mem_total_mib(""), None);
    }
}
