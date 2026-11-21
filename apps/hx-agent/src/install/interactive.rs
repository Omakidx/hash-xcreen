//! `--interactive` (design D5) and the hidden token prompt of `--pair`.
//!
//! After the host checks every question is asked, **before any change**, on `/dev/tty` through the
//! CLI's [`Prompter`](crate::cli::Prompter): distro, user, apps, Docker (with the isolation
//! warning and a typed `yes`), limits, storage device, port, private networks, hostname, time
//! zone, locale and keyboard (defaulting to this host's values), then the password and the PIN,
//! hidden and asked twice. The secrets are held in `Zeroizing` buffers.

use std::collections::BTreeMap;

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::ctx::Ctx;
use super::error::{InstallError, Result};
use super::fsx::read_text;
use super::options::{HostFacts, Options, RawOptions};
use super::paths::{self, Paths};
use super::preflight::parse_mem_total_mib;

/// The warning shown before Docker is turned on (architecture 4.3).
pub const DOCKER_WARNING: &str = "Docker inside the desktop needs container nesting and syscall interception. With nesting, Incus drops the container's AppArmor denials for /proc/sys and /sys and allows mount, pivot_root, ptrace and signal, which enlarges the attack surface for container escapes. That is why Docker is off by default.";

/// The private-networks warning.
pub const PRIVATE_NETWORKS_WARNING: &str = "Allowing private networks lets the desktop reach the private address ranges of this host's network (your LAN or VPC). The desktop is isolated from them by default.";

/// The time zone this host uses (`/etc/localtime` points into the zoneinfo tree).
pub fn host_timezone(p: &Paths) -> Option<String> {
    let t = std::fs::read_link(p.at(paths::LOCALTIME)).ok()?;
    let s = t.to_string_lossy();
    let name = s.split_once("zoneinfo/")?.1;
    (!name.is_empty()).then(|| name.to_owned())
}

fn shell_value(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let v = l.trim().strip_prefix(key)?.strip_prefix('=')?;
        Some(v.trim().trim_matches('"').trim_matches('\'').to_owned())
    })
}

/// The locale this host uses (`LANG` of `/etc/default/locale`).
pub fn host_locale(p: &Paths) -> Option<String> {
    shell_value(&read_text(&p.at(paths::DEFAULT_LOCALE))?, "LANG")
        .filter(|v| !v.is_empty() && v != "C.UTF-8" && v != "POSIX")
}

/// The keyboard this host uses (`XKBLAYOUT` and `XKBVARIANT` of `/etc/default/keyboard`).
pub fn host_keyboard(p: &Paths) -> Option<String> {
    let t = read_text(&p.at(paths::DEFAULT_KEYBOARD))?;
    let layout = shell_value(&t, "XKBLAYOUT")?;
    let layout = layout.split(',').next()?.trim().to_owned();
    if layout.is_empty() {
        return None;
    }
    match shell_value(&t, "XKBVARIANT").and_then(|v| v.split(',').next().map(str::to_owned)) {
        Some(v) if !v.trim().is_empty() => Some(format!("{layout}+{}", v.trim())),
        _ => Some(layout),
    }
}

fn facts_of<'a>(ctx: &Ctx<'_>, zoneinfo: &'a std::path::Path) -> HostFacts<'a> {
    HostFacts {
        cpus: ctx.probe.cpus(),
        mem_mib: read_text(&ctx.paths.at("/proc/meminfo"))
            .and_then(|t| parse_mem_total_mib(&t))
            .unwrap_or(0),
        zoneinfo,
    }
}

/// Sets one option from an answer, re-asking up to three times when it does not validate.
fn ask_option(
    ctx: &mut Ctx<'_>,
    question: &str,
    key: &'static str,
    default: Option<&str>,
) -> Result<()> {
    for _ in 0..3 {
        let shown = default.map(|d| format!(" [{d}]")).unwrap_or_default();
        let answer = ctx.prompt.line(&format!("{question}{shown}: "))?;
        let value = if answer.is_empty() {
            default.unwrap_or("")
        } else {
            answer.as_str()
        };
        if value.is_empty() {
            return Ok(());
        }
        let mut values = BTreeMap::new();
        values.insert(key, value.to_owned());
        let raw = RawOptions {
            values,
            flags: Default::default(),
        };
        let zone = ctx.paths.at(paths::ZONEINFO);
        let facts = facts_of(ctx, &zone);
        match Options::resolve(&raw, Some(&ctx.opts), &facts) {
            Ok((o, _)) => {
                ctx.opts = o;
                return Ok(());
            }
            Err(e) => ctx.say(&format!("{}\n", e.message)),
        }
    }
    Err(InstallError::usage(format!(
        "no acceptable value for {key}"
    )))
}

fn yes(ctx: &mut Ctx<'_>, warning: Option<&str>, question: &str) -> Result<bool> {
    if let Some(w) = warning {
        ctx.say(&format!("{w}\n"));
    }
    Ok(ctx.prompt.line(&format!(
        "{question} (type 'yes' to confirm, anything else is no): "
    ))? == "yes")
}

fn ask_twice(
    ctx: &mut Ctx<'_>,
    first: &str,
    again: &str,
    max: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let a = ctx.prompt.secret(first, max)?;
    let b = ctx.prompt.secret(again, max)?;
    if a.len() != b.len() || a.ct_eq(&b).unwrap_u8() != 1 {
        return Err(InstallError::usage(
            "the two entries differ; nothing was changed",
        ));
    }
    Ok(a)
}

/// Asks every question. On return `ctx.opts` and the password and PIN are set.
pub fn gather(ctx: &mut Ctx<'_>) -> Result<()> {
    ctx.say(
        "hash-xcreen interactive install: nothing is changed until all questions are answered.\n",
    );
    let d = ctx.opts.distro.clone();
    ask_option(
        ctx,
        "Desktop distribution (ubuntu-24.04, ubuntu-26.04, debian-12, debian-13)",
        "--distro",
        Some(&d),
    )?;
    let u = ctx.opts.user.clone();
    ask_option(
        ctx,
        "Linux user name of the desktop",
        "--user",
        u.as_deref(),
    )?;
    if ctx.opts.user.is_none() {
        return Err(InstallError::usage("a user name is required"));
    }
    let a = ctx.opts.apps.clone();
    ask_option(ctx, "Apps (basic or developer)", "--apps", Some(&a))?;
    if !ctx.opts.docker && yes(ctx, Some(DOCKER_WARNING), "Enable Docker in the desktop?")? {
        ctx.opts.docker = true;
    }
    ask_option(ctx, "CPUs for the desktop (blank: all)", "--cpu", None)?;
    ask_option(
        ctx,
        "Memory for the desktop, MiB or NG (blank: automatic)",
        "--memory",
        None,
    )?;
    ask_option(
        ctx,
        "Disk for the desktop, GiB (blank: automatic)",
        "--disk",
        None,
    )?;
    ask_option(
        ctx,
        "Whole block device for the storage pool, e.g. /dev/sdb (blank: a file on this disk)",
        "--storage-device",
        None,
    )?;
    let port = ctx.opts.port.to_string();
    ask_option(ctx, "Public port", "--port", Some(&port))?;
    if !ctx.opts.allow_private_networks
        && yes(
            ctx,
            Some(PRIVATE_NETWORKS_WARNING),
            "Allow the desktop to reach private networks?",
        )?
    {
        ctx.opts.allow_private_networks = true;
    }
    let (tz, loc, kb) = (
        host_timezone(&ctx.paths),
        host_locale(&ctx.paths),
        host_keyboard(&ctx.paths),
    );
    ask_option(
        ctx,
        "Hostname of the desktop (blank: the client's)",
        "--hostname",
        ctx.opts.hostname.clone().as_deref(),
    )?;
    ask_option(
        ctx,
        "Time zone",
        "--timezone",
        ctx.opts.timezone.clone().or(tz).as_deref(),
    )?;
    ask_option(
        ctx,
        "Locale",
        "--locale",
        ctx.opts.locale.clone().or(loc).as_deref(),
    )?;
    ask_option(
        ctx,
        "Keyboard layout",
        "--keyboard",
        ctx.opts.keyboard.clone().or(kb).as_deref(),
    )?;
    let pw = ask_twice(
        ctx,
        "Linux password for the desktop user (input hidden): ",
        "Repeat the password: ",
        1024,
    )?;
    if pw.is_empty() || pw.iter().any(|b| matches!(b, 0 | b'\n' | b'\r')) {
        return Err(InstallError::usage(
            "a password is 1 to 1024 bytes with no newline or NUL",
        ));
    }
    let pin = ask_twice(
        ctx,
        "PIN, 6 to 16 digits (input hidden): ",
        "Repeat the PIN: ",
        32,
    )?;
    if !(6..=16).contains(&pin.len()) || !pin.iter().all(u8::is_ascii_digit) {
        return Err(InstallError::usage("a PIN is 6 to 16 digits"));
    }
    ctx.secrets.password = Some(pw);
    ctx.secrets.pin = Some(pin);
    ctx.gathered = true;
    Ok(())
}

/// The hidden prompt of `--pair`: the token is typed here, right after the host checks, and
/// installed at stage `pairing-token`.
pub fn ask_token(ctx: &mut Ctx<'_>) -> Result<()> {
    let typed = ctx.prompt.secret(
        "Pairing token (input hidden): ",
        hx_ipc::admin::MAX_PAIRING_TOKEN_BYTES,
    )?;
    let ok = std::str::from_utf8(&typed)
        .ok()
        .map(str::trim)
        .is_some_and(|s| hx_crypto::PairingToken::parse(s).is_ok());
    if !ok {
        return Err(InstallError::usage(
            "that is not a pairing token (expected hxt1-...)",
        ));
    }
    let trimmed = Zeroizing::new(
        std::str::from_utf8(&typed)
            .unwrap_or("")
            .trim()
            .as_bytes()
            .to_vec(),
    );
    ctx.secrets.token = Some(trimmed);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree() -> (tempfile::TempDir, Paths) {
        let d = tempfile::tempdir().unwrap();
        let p = Paths::under(d.path());
        (d, p)
    }

    #[test]
    fn the_host_time_zone_comes_from_the_localtime_link() {
        let (_d, p) = tree();
        std::fs::create_dir_all(p.at("/etc")).unwrap();
        std::os::unix::fs::symlink("/usr/share/zoneinfo/Europe/Berlin", p.at(paths::LOCALTIME))
            .unwrap();
        assert_eq!(host_timezone(&p).as_deref(), Some("Europe/Berlin"));
        std::fs::remove_file(p.at(paths::LOCALTIME)).unwrap();
        assert_eq!(host_timezone(&p), None);
    }

    #[test]
    fn locale_and_keyboard_come_from_the_default_files() {
        let (_d, p) = tree();
        std::fs::create_dir_all(p.at("/etc/default")).unwrap();
        std::fs::write(p.at(paths::DEFAULT_LOCALE), "LANG=de_DE.UTF-8\n").unwrap();
        std::fs::write(
            p.at(paths::DEFAULT_KEYBOARD),
            "XKBMODEL=\"pc105\"\nXKBLAYOUT=\"de,us\"\nXKBVARIANT=\"nodeadkeys,\"\n",
        )
        .unwrap();
        assert_eq!(host_locale(&p).as_deref(), Some("de_DE.UTF-8"));
        assert_eq!(host_keyboard(&p).as_deref(), Some("de+nodeadkeys"));
        std::fs::write(p.at(paths::DEFAULT_LOCALE), "LANG=C.UTF-8\n").unwrap();
        assert_eq!(host_locale(&p), None);
        std::fs::write(p.at(paths::DEFAULT_KEYBOARD), "XKBLAYOUT=us\n").unwrap();
        assert_eq!(host_keyboard(&p).as_deref(), Some("us"));
    }
}
