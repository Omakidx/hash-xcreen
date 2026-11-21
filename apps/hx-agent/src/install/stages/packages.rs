//! Stage `packages`: the prerequisite packages (design D4: `btrfs-progs`, `nftables`,
//! `ca-certificates`). Done when `dpkg-query` says every one is installed.
//!
//! apt runs with a cleared environment plus `DEBIAN_FRONTEND=noninteractive` and
//! `NEEDRESTART_MODE=a`, and waits up to 10 minutes for the dpkg lock (a fresh VPS runs
//! unattended-upgrades at first boot).

use super::Outcome;
use crate::install::ctx::Ctx;
use crate::install::error::Result;
use crate::install::runner::{APT_ENV, Call, Tool};

/// What the installer needs on the host.
pub const PACKAGES: &[&str] = &["btrfs-progs", "nftables", "ca-certificates"];

/// The apt lock wait, seconds.
pub const LOCK_WAIT: &str = "DPkg::Lock::Timeout=600";

/// True when `package` is installed (`ii`).
pub fn is_installed(ctx: &mut Ctx<'_>, package: &str) -> bool {
    ctx.run(Call::new(
        Tool::DpkgQuery,
        &["-W", "-f", "${db:Status-Abbrev}\n", package],
    ))
    .is_ok_and(|o| o.ok() && o.out_text().trim_start().starts_with("ii"))
}

/// `apt-get update`.
pub fn apt_update(ctx: &mut Ctx<'_>) -> Result<()> {
    let secs = ctx.timing.apt_secs;
    ctx.run_ok(
        Call::new(Tool::AptGet, &["-o", LOCK_WAIT, "update"])
            .with_env(APT_ENV)
            .timeout_secs(secs),
    )?;
    Ok(())
}

/// `apt-get install` of `packages`.
pub fn apt_install(ctx: &mut Ctx<'_>, packages: &[&str]) -> Result<()> {
    let secs = ctx.timing.apt_secs;
    let mut args = vec!["-y", "-o", LOCK_WAIT, "install", "--no-install-recommends"];
    args.extend_from_slice(packages);
    ctx.run_ok(
        Call::new(Tool::AptGet, &args)
            .with_env(APT_ENV)
            .timeout_secs(secs),
    )?;
    Ok(())
}

/// Done-check.
pub fn check(ctx: &mut Ctx<'_>) -> Result<bool> {
    Ok(PACKAGES.iter().all(|p| is_installed(ctx, p)))
}

/// Installs what is missing.
pub fn run(ctx: &mut Ctx<'_>) -> Result<Outcome> {
    let missing: Vec<&str> = PACKAGES
        .iter()
        .copied()
        .filter(|p| !is_installed(ctx, p))
        .collect();
    if missing.is_empty() {
        return Ok(Outcome::Done);
    }
    apt_update(ctx)?;
    apt_install(ctx, &missing)?;
    for m in &missing {
        if !ctx.state.created.packages.iter().any(|p| p == m) {
            ctx.state.created.packages.push((*m).to_owned());
        }
    }
    Ok(Outcome::Done)
}
