//! Stage `incus`: install or adopt Incus (design D4).
//!
//! * An Incus that is already there and is at least 6.0.0 is **adopted and never upgraded**. With
//!   `--docker` an existing Incus below 6.0.5 is refused at preflight.
//! * Otherwise the distro's candidate (`apt-cache policy incus`, after `apt-get update`) is used
//!   if it is at least 6.0.0 (6.0.5 with `--docker`).
//! * Otherwise the Zabbly `lts-6.0` repository, with its key embedded and its fingerprint
//!   pinned ([`crate::install::zabbly`]).
//! * Then `systemctl enable --now incus.socket` and a wait for `/var/lib/incus/unix.socket`.
//!   `incus admin init` is not needed: hx-provision sets up its own profiles.

use std::time::Duration;

use super::Outcome;
use super::packages::{apt_install, apt_update};
use crate::install::ctx::Ctx;
use crate::install::error::{InstallError, Result};
use crate::install::fsx::{ensure_dir, read_text, write_if_changed};
use crate::install::paths;
use crate::install::preflight::parse_os_release;
use crate::install::runner::{Call, Tool};
use crate::install::state::IncusRecord;
use crate::install::zabbly;

/// The oldest Incus hash-xcreen supports.
pub const MIN_VERSION: (u32, u32, u32) = (6, 0, 0);
/// The oldest Incus that supports Docker in the desktop.
pub const DOCKER_MIN_VERSION: (u32, u32, u32) = (6, 0, 5);

/// `1:6.0.4-1ubuntu1` to `(6, 0, 4)`; the epoch and everything after the numbers are ignored.
pub fn parse_version(s: &str) -> Option<(u32, u32, u32)> {
    let s = s.trim();
    let s = s.split_once(':').map_or(s, |(epoch, rest)| {
        if epoch.bytes().all(|b| b.is_ascii_digit()) {
            rest
        } else {
            s
        }
    });
    let mut nums = [0u32; 3];
    let mut it = s.split(|c: char| !c.is_ascii_digit());
    for slot in &mut nums {
        *slot = it.next().filter(|p| !p.is_empty())?.parse().ok()?;
    }
    Some((nums[0], nums[1], nums[2]))
}

/// `version` is at least `min`.
pub fn at_least(version: &str, min: (u32, u32, u32)) -> bool {
    parse_version(version).is_some_and(|v| v >= min)
}

/// The installed `incus` package version, if any.
pub fn existing_version(ctx: &mut Ctx<'_>) -> Result<Option<String>> {
    let out = ctx.run(Call::new(
        Tool::DpkgQuery,
        &["-W", "-f", "${db:Status-Abbrev}|${Version}\n", "incus"],
    ));
    let Ok(out) = out else {
        return Ok(None);
    };
    if !out.ok() {
        return Ok(None);
    }
    let text = out.out_text();
    let Some((status, version)) = text.trim().split_once('|') else {
        return Ok(None);
    };
    Ok(status
        .trim_start()
        .starts_with("ii")
        .then(|| version.trim().to_owned()))
}

/// The version apt would install.
pub fn candidate_version(ctx: &mut Ctx<'_>) -> Result<Option<String>> {
    let out = ctx.run_ok(
        Call::new(Tool::AptCache, &["policy", "incus"]).with_env(crate::install::runner::APT_ENV),
    )?;
    Ok(out.out_text().lines().find_map(|l| {
        let v = l.trim().strip_prefix("Candidate:")?.trim();
        (v != "(none)" && !v.is_empty()).then(|| v.to_owned())
    }))
}

fn needed(ctx: &Ctx<'_>) -> (u32, u32, u32) {
    if ctx.opts.docker {
        DOCKER_MIN_VERSION
    } else {
        MIN_VERSION
    }
}

fn socket_path(ctx: &Ctx<'_>) -> std::path::PathBuf {
    ctx.paths.at(paths::INCUS_SOCKET)
}

/// Done-check: Incus is recorded, its socket is enabled and exists.
pub fn check(ctx: &mut Ctx<'_>) -> Result<bool> {
    if ctx.state.created.incus.is_none() || !socket_path(ctx).exists() {
        return Ok(false);
    }
    Ok(ctx
        .run(Call::new(
            Tool::Systemctl,
            &["is-enabled", "--quiet", "incus.socket"],
        ))
        .is_ok_and(|o| o.ok()))
}

fn add_zabbly(ctx: &mut Ctx<'_>) -> Result<()> {
    let key = zabbly::verified_key()?;
    let os = read_text(&ctx.paths.at(paths::OS_RELEASE)).unwrap_or_default();
    let (_, _, codename) = parse_os_release(&os);
    if !zabbly::SUITES.contains(&codename.as_str()) {
        return Err(InstallError::preflight(format!(
            "the Zabbly repository has no suite for this host ({}); install Incus 6.0.5 or newer yourself",
            crate::cli::text::peer(&codename, 32)
        )));
    }
    let keyring = ctx.paths.at(paths::ZABBLY_KEY);
    if let Some(dir) = keyring.parent() {
        ensure_dir(dir, 0o755)?;
    }
    write_if_changed(&keyring, key.as_bytes(), 0o644)?;
    let sources = ctx.paths.at(paths::ZABBLY_SOURCES);
    write_if_changed(
        &sources,
        zabbly::sources_text(&codename, paths::ZABBLY_KEY).as_bytes(),
        0o644,
    )?;
    for p in [paths::ZABBLY_KEY, paths::ZABBLY_SOURCES] {
        if !ctx.state.created.apt.iter().any(|a| a == p) {
            ctx.state.created.apt.push(p.to_owned());
        }
    }
    Ok(())
}

/// Installs or adopts Incus, enables its socket and waits for it.
pub fn run(ctx: &mut Ctx<'_>) -> Result<Outcome> {
    let min = needed(ctx);
    if let Some(v) = existing_version(ctx)? {
        // Preflight already refused a version that is too old; adopt, never upgrade.
        ctx.state.created.incus = Some(IncusRecord {
            by_installer: ctx
                .state
                .created
                .incus
                .as_ref()
                .is_some_and(|i| i.by_installer),
            source: ctx
                .state
                .created
                .incus
                .as_ref()
                .map_or_else(|| "existing".to_owned(), |i| i.source.clone()),
            version: v,
        });
    } else if socket_path(ctx).exists() && ctx.state.created.incus.is_none() {
        ctx.state.created.incus = Some(IncusRecord {
            by_installer: false,
            source: "existing".into(),
            version: String::new(),
        });
    } else {
        apt_update(ctx)?;
        let candidate = candidate_version(ctx)?;
        let source = if candidate.as_deref().is_some_and(|c| at_least(c, min)) {
            "distro"
        } else {
            add_zabbly(ctx)?;
            apt_update(ctx)?;
            "zabbly"
        };
        apt_install(ctx, &["incus"])?;
        let version = existing_version(ctx)?.unwrap_or_default();
        if !at_least(&version, min) {
            return Err(InstallError::preflight(format!(
                "the Incus that apt installed ({}) is older than {}.{}.{}; install a newer one yourself",
                crate::cli::text::peer(&version, 40),
                min.0,
                min.1,
                min.2
            )));
        }
        ctx.state.created.incus = Some(IncusRecord {
            by_installer: true,
            source: source.into(),
            version,
        });
    }
    ctx.run_ok(Call::new(
        Tool::Systemctl,
        &["enable", "--now", "incus.socket"],
    ))?;
    wait_for_socket(ctx)?;
    Ok(Outcome::Done)
}

fn wait_for_socket(ctx: &mut Ctx<'_>) -> Result<()> {
    let path = socket_path(ctx);
    let step = Duration::from_millis(500);
    let mut waited = Duration::ZERO;
    loop {
        if path.exists() {
            return Ok(());
        }
        if waited >= ctx.timing.socket_wait {
            return Err(InstallError::tool(
                "Incus's socket (/var/lib/incus/unix.socket) did not appear; check: systemctl status incus.socket",
            ));
        }
        ctx.probe.sleep(step);
        waited += step;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_parsed_and_compared() {
        assert_eq!(parse_version("1:6.0.4-1ubuntu1"), Some((6, 0, 4)));
        assert_eq!(parse_version("6.0.0-1"), Some((6, 0, 0)));
        assert_eq!(parse_version("6.0.5"), Some((6, 0, 5)));
        assert_eq!(parse_version("6.1"), None);
        assert_eq!(parse_version("abc"), None);
        assert_eq!(parse_version(""), None);
        assert!(at_least("1:6.0.4-1", MIN_VERSION));
        assert!(!at_least("1:6.0.4-1", DOCKER_MIN_VERSION));
        assert!(at_least("6.0.5-ubuntu24.04-202411", DOCKER_MIN_VERSION));
        assert!(!at_least("5.21.2-1", MIN_VERSION));
        assert!(at_least("6.10.0-1", DOCKER_MIN_VERSION));
    }
}
