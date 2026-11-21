//! The options of `hx-agent install` (design D4): parsing support, validation at the boundary,
//! merging with a recorded install, and the re-run classification.
//!
//! [`RawOptions`] is what the command line said (every value optional, text). [`Options`] is the
//! normalized, validated, serializable form that goes into the state file: **no secret is in
//! either** (the `--token` value travels separately in [`SecretString`], which redacts its
//! `Debug` and is wiped on drop).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use super::error::InstallError;
use super::state::InstallState;

/// The longest Linux password the installer accepts. libxcrypt (`crypt_rn`), and so `hx-pwcheck`
/// that checks the password later, reads at most 511 bytes: a longer one could be set but never
/// be checked.
pub const MAX_PASSWORD_BYTES: usize = 511;

/// Why `pw` cannot be the desktop user's password, or `None` when it can (1 to 511 bytes, no
/// newline, carriage return or NUL).
pub fn password_problem(pw: &[u8]) -> Option<String> {
    if pw.is_empty() || pw.iter().any(|b| matches!(b, 0 | b'\n' | b'\r')) {
        return Some(
            "a password is 1 to 511 bytes with no newline, carriage return or NUL".to_owned(),
        );
    }
    (pw.len() > MAX_PASSWORD_BYTES).then(|| {
        format!(
            "the password is {} bytes; at most {MAX_PASSWORD_BYTES} are accepted, because the password checker (libxcrypt) reads no more and a longer one could never be checked",
            pw.len()
        )
    })
}

/// A string secret: redacting `Debug`, wiped on drop.
pub struct SecretString(pub Zeroizing<String>);

impl SecretString {
    /// Wraps `s`.
    pub fn new(s: String) -> Self {
        Self(Zeroizing::new(s))
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        *self.0 == *other.0
    }
}
impl Eq for SecretString {}

/// How the install gets its secrets and what it finishes (design C1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Prompts on `/dev/tty`; ends with a pairing code.
    Interactive,
    /// The one-liner: the token is typed at a hidden prompt; stops after `pairing-token`.
    Pair,
    /// Unattended: the token comes from argv (weaker); stops after `pairing-token`.
    Token,
    /// Secrets on stdin (C2); installs its token at the end.
    Ssh,
}

impl Mode {
    /// The name recorded in the state.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Interactive => "interactive",
            Self::Pair => "pair",
            Self::Token => "token",
            Self::Ssh => "ssh",
        }
    }

    /// Parses a recorded name.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "interactive" => Some(Self::Interactive),
            "pair" => Some(Self::Pair),
            "token" => Some(Self::Token),
            "ssh" => Some(Self::Ssh),
            _ => None,
        }
    }

    /// The mode builds the desktop itself (the others stop after `pairing-token`).
    pub fn builds_desktop(self) -> bool {
        matches!(self, Self::Interactive | Self::Ssh)
    }
}

/// Valued options, in the order the help lists them.
pub const VALUED: &[&str] = &[
    "--distro",
    "--desktop",
    "--user",
    "--hostname",
    "--timezone",
    "--locale",
    "--keyboard",
    "--apps",
    "--backup",
    "--backup-keep",
    "--cpu",
    "--memory",
    "--disk",
    "--storage-device",
    "--image",
    "--image-file",
    "--port",
    "--domain",
    "--channel",
];

/// Boolean options.
pub const FLAGS: &[&str] = &["--docker", "--allow-private-networks"];

/// What the command line said: option name (with `--`) to text, and the flags that were given.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RawOptions {
    /// Valued options.
    pub values: BTreeMap<&'static str, String>,
    /// Flags.
    pub flags: BTreeSet<&'static str>,
}

impl Drop for RawOptions {
    fn drop(&mut self) {
        self.values.values_mut().for_each(Zeroize::zeroize);
    }
}

impl RawOptions {
    fn get(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    /// `--image-file` was given.
    pub fn image_file(&self) -> Option<&str> {
        self.get("--image-file")
    }
}

/// The normalized options (no secrets).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Options {
    /// `ubuntu-24.04`, `ubuntu-26.04`, `debian-12` or `debian-13`.
    pub distro: String,
    /// `xfce`.
    pub desktop: String,
    /// The desktop user.
    #[serde(default)]
    pub user: Option<String>,
    /// RFC 1123 label.
    #[serde(default)]
    pub hostname: Option<String>,
    /// A zoneinfo name.
    #[serde(default)]
    pub timezone: Option<String>,
    /// A locale with `.UTF-8`.
    #[serde(default)]
    pub locale: Option<String>,
    /// A keyboard layout.
    #[serde(default)]
    pub keyboard: Option<String>,
    /// `basic` or `developer`.
    pub apps: String,
    /// Docker in the desktop (counts as the isolation acknowledgement).
    pub docker: bool,
    /// `off`, `12h` or `24h` (recorded only: Phase 2).
    pub backup: String,
    /// Backups kept (recorded only).
    #[serde(default)]
    pub backup_keep: Option<u32>,
    /// CPUs.
    #[serde(default)]
    pub cpu: Option<u32>,
    /// Memory, MiB.
    #[serde(default)]
    pub memory_mib: Option<u64>,
    /// Disk, GiB.
    #[serde(default)]
    pub disk_gib: Option<u64>,
    /// A whole block device for the pool.
    #[serde(default)]
    pub storage_device: Option<String>,
    /// `auto`, `build` or `prebuilt`.
    pub image: String,
    /// The public port.
    pub port: u16,
    /// Recorded only (Phase 3).
    #[serde(default)]
    pub domain: Option<String>,
    /// `stable` or `beta`.
    pub channel: String,
    /// Admin-only `SetupHost` opt-in.
    pub allow_private_networks: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            distro: "ubuntu-24.04".into(),
            desktop: "xfce".into(),
            user: None,
            hostname: None,
            timezone: None,
            locale: None,
            keyboard: None,
            apps: "basic".into(),
            docker: false,
            backup: "off".into(),
            backup_keep: None,
            cpu: None,
            memory_mib: None,
            disk_gib: None,
            storage_device: None,
            image: "auto".into(),
            port: 443,
            domain: None,
            channel: "stable".into(),
            allow_private_networks: false,
        }
    }
}

/// The distros privd knows (`ipc.md` section 6).
pub const DISTROS: &[&str] = &["ubuntu-24.04", "ubuntu-26.04", "debian-12", "debian-13"];

/// Host facts the limits are checked against.
#[derive(Debug, Clone)]
pub struct HostFacts<'a> {
    /// CPUs.
    pub cpus: u32,
    /// RAM in MiB.
    pub mem_mib: u64,
    /// The zoneinfo directory.
    pub zoneinfo: &'a Path,
}

fn usage(m: impl AsRef<str>) -> InstallError {
    InstallError::usage(m)
}

/// `8192`, `8192M` or `8G` to MiB.
pub fn parse_memory_mib(s: &str) -> Result<u64, InstallError> {
    let bad = || usage("--memory must look like 8192, 8192M or 8G");
    let lower = s.to_ascii_lowercase();
    let (num, mult) = if let Some(n) = lower.strip_suffix('g') {
        (n, 1024u64)
    } else if let Some(n) = lower.strip_suffix('m') {
        (n, 1)
    } else {
        (lower.as_str(), 1)
    };
    let n: u64 = num.parse().map_err(|_| bad())?;
    n.checked_mul(mult).ok_or_else(bad)
}

fn is_fqdn(s: &str) -> bool {
    let labels: Vec<&str> = s.split('.').collect();
    s.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| {
            (1..=63).contains(&l.len())
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        && !labels[labels.len() - 1].bytes().all(|b| b.is_ascii_digit())
}

/// The largest memory limit for a host with `ram` MiB: RAM minus the larger of 1536 MiB and 25%.
pub fn max_memory_mib(ram: u64) -> u64 {
    ram.saturating_sub(1536.max(ram / 4))
}

impl Options {
    /// Validates `raw` and merges it over `prior` (an option the command line did not give keeps
    /// the recorded value, or the default on a first run). Returns the options and the names of
    /// the options that were given explicitly.
    pub fn resolve(
        raw: &RawOptions,
        prior: Option<&Options>,
        facts: &HostFacts<'_>,
    ) -> Result<(Options, BTreeSet<&'static str>), InstallError> {
        let mut o = prior.cloned().unwrap_or_default();
        let mut explicit: BTreeSet<&'static str> = BTreeSet::new();
        for name in raw.values.keys() {
            explicit.insert(*name);
        }
        for f in &raw.flags {
            explicit.insert(*f);
        }
        let get = |n: &str| raw.get(n);
        if let Some(v) = get("--distro") {
            if !DISTROS.contains(&v) {
                return Err(usage(format!(
                    "--distro must be one of: {}",
                    DISTROS.join(", ")
                )));
            }
            o.distro = v.to_owned();
        }
        if let Some(v) = get("--desktop") {
            if v != "xfce" {
                return Err(usage("--desktop must be xfce"));
            }
            o.desktop = v.to_owned();
        }
        if let Some(v) = get("--user") {
            hx_provision::Username::new(v).map_err(|e| usage(format!("--user: {e}")))?;
            o.user = Some(v.to_owned());
        }
        if let Some(v) = get("--hostname") {
            hx_provision::Settings::none()
                .with_hostname(v)
                .map_err(|e| usage(format!("--hostname: {e}")))?;
            o.hostname = Some(v.to_owned());
        }
        if let Some(v) = get("--timezone") {
            hx_provision::Settings::none()
                .with_timezone_in(v, facts.zoneinfo)
                .map_err(|e| usage(format!("--timezone: {e}")))?;
            o.timezone = Some(v.to_owned());
        }
        if let Some(v) = get("--locale") {
            let s = hx_provision::Settings::none()
                .with_locale(v)
                .map_err(|e| usage(format!("--locale: {e}")))?;
            o.locale = s.locale().map(str::to_owned);
        }
        if let Some(v) = get("--keyboard") {
            hx_provision::Settings::none()
                .with_keyboard(v)
                .map_err(|e| usage(format!("--keyboard: {e}")))?;
            o.keyboard = Some(v.to_owned());
        }
        if let Some(v) = get("--apps") {
            if !matches!(v, "basic" | "developer") {
                return Err(usage("--apps must be basic or developer"));
            }
            o.apps = v.to_owned();
        }
        if raw.flags.contains("--docker") {
            o.docker = true;
        }
        if raw.flags.contains("--allow-private-networks") {
            o.allow_private_networks = true;
        }
        if let Some(v) = get("--backup") {
            if !matches!(v, "off" | "12h" | "24h") {
                return Err(usage("--backup must be off, 12h or 24h"));
            }
            o.backup = v.to_owned();
        }
        if let Some(v) = get("--backup-keep") {
            match v.parse::<u32>() {
                Ok(n) if (1..=1000).contains(&n) => o.backup_keep = Some(n),
                _ => return Err(usage("--backup-keep must be 1 to 1000")),
            }
        }
        if let Some(v) = get("--cpu") {
            match v.parse::<u32>() {
                Ok(n) if n >= 1 && n <= facts.cpus => o.cpu = Some(n),
                _ => {
                    return Err(usage(format!(
                        "--cpu must be 1 to {} (this host's CPUs)",
                        facts.cpus
                    )));
                }
            }
        }
        if let Some(v) = get("--memory") {
            let mib = parse_memory_mib(v)?;
            let max = max_memory_mib(facts.mem_mib);
            if mib < 1024 || mib > max {
                return Err(usage(format!(
                    "--memory must be 1024 MiB to {max} MiB on this host (RAM minus the larger of 1536 MiB and 25%)"
                )));
            }
            o.memory_mib = Some(mib);
        }
        if let Some(v) = get("--disk") {
            match v.trim_end_matches(['G', 'g']).parse::<u64>() {
                Ok(n) if (8..=1_000_000).contains(&n) => o.disk_gib = Some(n),
                _ => return Err(usage("--disk must be at least 8 (GiB)")),
            }
        }
        if let Some(v) = get("--storage-device") {
            if !v.starts_with("/dev/") || v.contains("..") || v.len() > 128 || v.contains('\0') {
                return Err(usage("--storage-device must be a path under /dev/"));
            }
            o.storage_device = Some(v.to_owned());
        }
        if let Some(v) = get("--image") {
            if !matches!(v, "auto" | "build" | "prebuilt") {
                return Err(usage("--image must be auto, build or prebuilt"));
            }
            o.image = v.to_owned();
        }
        if let Some(v) = get("--image-file")
            && !v.starts_with('/')
        {
            return Err(usage("--image-file must be an absolute path"));
        }
        if let Some(v) = get("--port") {
            match v.parse::<u16>() {
                Ok(n) if n >= 1 && n != 22 && n != 80 => o.port = n,
                _ => return Err(usage("--port must be 1 to 65535, and not 22 or 80")),
            }
        }
        if let Some(v) = get("--domain") {
            let d = v.to_ascii_lowercase();
            if !is_fqdn(&d) {
                return Err(usage("--domain must be a fully qualified domain name"));
            }
            o.domain = Some(d);
        }
        if let Some(v) = get("--channel") {
            if !matches!(v, "stable" | "beta") {
                return Err(usage("--channel must be stable or beta"));
            }
            o.channel = v.to_owned();
        }
        Ok((o, explicit))
    }

    /// The `hx_provision::Settings` equivalent is empty (nothing to send).
    pub fn settings_empty(&self) -> bool {
        self.hostname.is_none()
            && self.timezone.is_none()
            && self.locale.is_none()
            && self.keyboard.is_none()
    }
}

/// An option that cannot change on a re-run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    /// The option, with `--`.
    pub option: &'static str,
    /// The stage whose completion fixes it.
    pub fixed_by: &'static str,
    /// What to run to change it.
    pub remedy: &'static str,
}

const DESTROY: &str = "hx-agent uninstall --destroy-desktop, then install again";

fn diff(prior: &Options, new: &Options, option: &'static str) -> bool {
    match option {
        "--distro" => prior.distro != new.distro,
        "--desktop" => prior.desktop != new.desktop,
        "--user" => prior.user != new.user,
        "--hostname" => prior.hostname != new.hostname,
        "--timezone" => prior.timezone != new.timezone,
        "--locale" => prior.locale != new.locale,
        "--keyboard" => prior.keyboard != new.keyboard,
        "--apps" => prior.apps != new.apps,
        "--docker" => prior.docker != new.docker,
        "--image" => prior.image != new.image,
        "--storage-device" => prior.storage_device != new.storage_device,
        _ => false,
    }
}

/// The fixed options that the command line changed after the stage that fixes them is done.
/// (The reconcilable ones are never conflicts: they are applied.)
pub fn conflicts(
    prior: &InstallState,
    new: &Options,
    explicit: &BTreeSet<&'static str>,
) -> Vec<Conflict> {
    const FIXED: &[(&str, &str, &str)] = &[
        ("--distro", "desktop", DESTROY),
        ("--desktop", "desktop", DESTROY),
        ("--user", "desktop", DESTROY),
        ("--hostname", "desktop", DESTROY),
        ("--timezone", "desktop", DESTROY),
        ("--locale", "desktop", DESTROY),
        ("--keyboard", "desktop", DESTROY),
        ("--apps", "desktop", DESTROY),
        ("--image", "desktop", DESTROY),
        (
            "--docker",
            "desktop",
            "hx-agent docker enable, or hx-agent docker disable",
        ),
        ("--storage-device", "host", DESTROY),
    ];
    let mut out = Vec::new();
    for (option, stage, remedy) in FIXED {
        if explicit.contains(option) && prior.is_done(stage) && diff(&prior.options, new, option) {
            out.push(Conflict {
                option,
                fixed_by: stage,
                remedy,
            });
        }
    }
    out
}

/// The message of exit 12.
pub fn conflict_message(c: &[Conflict]) -> String {
    let mut s =
        String::from("these options conflict with the existing install and were not applied:");
    for x in c {
        s.push_str(&format!(
            "\n  {}: fixed once stage '{}' is done; to change it run: {}",
            x.option, x.fixed_by, x.remedy
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> HostFacts<'static> {
        HostFacts {
            cpus: 8,
            mem_mib: 16_384,
            zoneinfo: Path::new("/usr/share/zoneinfo"),
        }
    }

    fn raw(pairs: &[(&'static str, &str)], flags: &[&'static str]) -> RawOptions {
        RawOptions {
            values: pairs.iter().map(|(k, v)| (*k, (*v).to_owned())).collect(),
            flags: flags.iter().copied().collect(),
        }
    }

    fn bad(pairs: &[(&'static str, &str)]) -> String {
        Options::resolve(&raw(pairs, &[]), None, &facts())
            .unwrap_err()
            .message
    }

    #[test]
    fn defaults_apply_to_a_first_run() {
        let (o, e) = Options::resolve(&raw(&[], &[]), None, &facts()).unwrap();
        assert_eq!(o, Options::default());
        assert!(e.is_empty());
        assert_eq!(
            (o.distro.as_str(), o.port, o.channel.as_str()),
            ("ubuntu-24.04", 443, "stable")
        );
    }

    #[test]
    fn every_value_is_validated_at_the_boundary() {
        assert!(bad(&[("--distro", "ubuntu-22.04")]).contains("--distro"));
        assert!(bad(&[("--desktop", "kde")]).contains("xfce"));
        assert!(bad(&[("--user", "Root")]).contains("--user"));
        assert!(bad(&[("--user", "root")]).contains("--user"));
        assert!(bad(&[("--hostname", "-bad")]).contains("--hostname"));
        assert!(bad(&[("--timezone", "../etc")]).contains("--timezone"));
        assert!(bad(&[("--locale", "xx_XX")]).contains("--locale"));
        assert!(bad(&[("--keyboard", "DE")]).contains("--keyboard"));
        assert!(bad(&[("--apps", "all")]).contains("--apps"));
        assert!(bad(&[("--backup", "1h")]).contains("--backup"));
        assert!(bad(&[("--backup-keep", "0")]).contains("--backup-keep"));
        assert!(bad(&[("--backup-keep", "1001")]).contains("--backup-keep"));
        assert!(bad(&[("--cpu", "0")]).contains("--cpu"));
        assert!(bad(&[("--cpu", "9")]).contains("--cpu"));
        assert!(bad(&[("--memory", "512")]).contains("--memory"));
        assert!(bad(&[("--memory", "16G")]).contains("--memory"));
        assert!(bad(&[("--memory", "lots")]).contains("--memory"));
        assert!(bad(&[("--disk", "4")]).contains("--disk"));
        assert!(bad(&[("--storage-device", "sda")]).contains("/dev/"));
        assert!(bad(&[("--storage-device", "/dev/../etc/passwd")]).contains("/dev/"));
        assert!(bad(&[("--image", "x")]).contains("--image"));
        assert!(bad(&[("--image-file", "rel.img")]).contains("absolute"));
        for p in ["0", "22", "80", "65536", "x"] {
            assert!(bad(&[("--port", p)]).contains("--port"), "{p}");
        }
        assert!(bad(&[("--domain", "localhost")]).contains("--domain"));
        assert!(bad(&[("--domain", "a.1")]).contains("--domain"));
        assert!(bad(&[("--channel", "nightly")]).contains("--channel"));
    }

    #[test]
    fn good_values_are_normalized() {
        let (o, e) = Options::resolve(
            &raw(
                &[
                    ("--distro", "debian-13"),
                    ("--user", "alice"),
                    ("--hostname", "box-1"),
                    ("--locale", "de_DE"),
                    ("--keyboard", "de+nodeadkeys"),
                    ("--memory", "8G"),
                    ("--cpu", "4"),
                    ("--disk", "64"),
                    ("--port", "8443"),
                    ("--domain", "Desk.Example.COM"),
                    ("--channel", "beta"),
                ],
                &["--docker", "--allow-private-networks"],
            ),
            None,
            &facts(),
        )
        .unwrap();
        assert_eq!(o.locale.as_deref(), Some("de_DE.UTF-8"));
        assert_eq!(o.memory_mib, Some(8192));
        assert_eq!(o.domain.as_deref(), Some("desk.example.com"));
        assert!(o.docker && o.allow_private_networks);
        assert!(e.contains("--docker") && e.contains("--port"));
    }

    #[test]
    fn memory_limits_follow_the_host() {
        assert_eq!(max_memory_mib(16_384), 12_288);
        assert_eq!(max_memory_mib(4096), 2560);
        assert_eq!(parse_memory_mib("2048M").unwrap(), 2048);
    }

    #[test]
    fn options_not_given_keep_the_recorded_value() {
        let (first, _) = Options::resolve(
            &raw(&[("--user", "alice"), ("--port", "8443")], &["--docker"]),
            None,
            &facts(),
        )
        .unwrap();
        let (second, e) =
            Options::resolve(&raw(&[("--channel", "beta")], &[]), Some(&first), &facts()).unwrap();
        assert_eq!(second.user.as_deref(), Some("alice"));
        assert_eq!(second.port, 8443);
        assert!(second.docker);
        assert_eq!(second.channel, "beta");
        assert_eq!(e.len(), 1);
    }

    #[test]
    fn fixed_options_conflict_only_after_their_stage_is_done() {
        let (a, _) = Options::resolve(&raw(&[("--user", "alice")], &[]), None, &facts()).unwrap();
        let mut st = InstallState::new("0".repeat(32), "ssh", a.clone(), 1);
        let (b, e) = Options::resolve(
            &raw(&[("--user", "bob"), ("--cpu", "2")], &[]),
            Some(&a),
            &facts(),
        )
        .unwrap();
        assert!(
            conflicts(&st, &b, &e).is_empty(),
            "desktop not done: free to change"
        );
        st.record("desktop", "done", 2, None);
        let c = conflicts(&st, &b, &e);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].option, "--user");
        let msg = conflict_message(&c);
        assert!(msg.contains("--user") && msg.contains("uninstall --destroy-desktop"));
        // The same value is not a conflict; reconcilable options never are.
        let (same, e2) = Options::resolve(
            &raw(&[("--user", "alice"), ("--port", "9000")], &[]),
            Some(&a),
            &facts(),
        )
        .unwrap();
        assert!(conflicts(&st, &same, &e2).is_empty());
    }

    #[test]
    fn docker_after_ready_points_at_the_docker_commands() {
        let (a, _) = Options::resolve(&raw(&[], &[]), None, &facts()).unwrap();
        let mut st = InstallState::new("0".repeat(32), "ssh", a.clone(), 1);
        st.record("desktop", "done", 2, None);
        let (b, e) = Options::resolve(&raw(&[], &["--docker"]), Some(&a), &facts()).unwrap();
        let c = conflicts(&st, &b, &e);
        assert_eq!(c[0].option, "--docker");
        assert!(c[0].remedy.contains("docker enable"));
    }

    #[test]
    fn passwords_are_capped_at_what_libxcrypt_reads() {
        assert_eq!(MAX_PASSWORD_BYTES, 511);
        assert!(password_problem(&vec![b'a'; 511]).is_none());
        let e = password_problem(&vec![b'a'; 512]).unwrap();
        assert!(e.contains("512 bytes") && e.contains("511") && e.contains("never be checked"));
        assert!(password_problem(b"").is_some());
        for bad in [&b"a\nb"[..], b"a\rb", b"a\0b"] {
            assert!(password_problem(bad).unwrap().contains("1 to 511"));
        }
    }

    #[test]
    fn the_secret_string_never_prints() {
        let s = SecretString::new("hxt1-secret".into());
        assert!(!format!("{s:?}").contains("secret"));
    }
}
