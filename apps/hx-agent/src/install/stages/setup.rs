//! The stages that talk to privd and gatewayd as `Admin`: `setup-window`, `host`, `pairing-token`,
//! `desktop`, `verifiers`, `owner-key`, `backup`, `pairing` and `finish` (design D3, D5, C2).
//!
//! Where each secret goes:
//!
//! * the **password**: `CreateDesktop` secret slot 0, and (as the Argon2id input of a verifier)
//!   `PepperEnrol(PASSWORD)` then `SetPasswordVerifier`;
//! * the **PIN**: Argon2id, `PepperEnrol(PIN)`, `SetPinVerifier{all}`;
//! * the **token**: `CreatePairingToken` (a secret frame), as the last step of an `--ssh` install
//!   so that its 15-minute lifetime starts after the desktop build; for `--pair` and `--token` at
//!   stage `pairing-token`;
//! * the **owner key**: `EnrolOwnerKey`.
//!
//! Nothing here puts a secret in a log line, a message, the state or an argument.

use argon2::{Algorithm, Argon2, Params, Version};
use hx_ipc::admin::pb as apb;
use hx_ipc::privd::pb::{self, LockoutPurpose};
use serde_json::Value;
use zeroize::Zeroizing;

use super::Outcome;
use crate::cli::text::hex;
use crate::install::ctx::Ctx;
use crate::install::daemons::Daemons;
use crate::install::error::{InstallError, Result};
use crate::install::options::Mode;
use crate::install::progress::{DesktopOut, PairingOut};
use crate::install::runner::{Call, Tool};
use crate::install::state::DesktopReport;

/// The desktop id of v1.
pub const DESKTOP_ID: &str = "main";
/// Lifetime of the pairing token or code.
pub const PAIR_TTL_S: u32 = 900;
/// Default length of the setup window.
pub const WINDOW_S: u32 = 7200;

// ----- setup-window ---------------------------------------------------------------------------

/// Done-check: the window is open, or the install is already past needing one.
pub fn window_check(ctx: &mut Ctx<'_>) -> Result<bool> {
    let h = ctx.daemons.hello()?;
    Ok(match h.phase {
        pb::Phase::SetupOpen => true,
        pb::Phase::Ready => ctx.mode.builds_desktop(),
        _ => false,
    })
}

/// Opens the window in privd and mirrors it into gatewayd.
pub fn window_run(ctx: &mut Ctx<'_>) -> Result<Outcome> {
    ctx.daemons.begin_setup(WINDOW_S)?;
    ctx.daemons
        .gateway_setup_window(apb::SetupWindowAction::Open, WINDOW_S)?;
    Ok(Outcome::Done)
}

// ----- host -----------------------------------------------------------------------------------

/// `SetupHost` (idempotent in privd) and a look at what it reports.
pub fn host_run(ctx: &mut Ctx<'_>) -> Result<Outcome> {
    let req = pb::SetupHostRequest {
        pool_size_gib: 0,
        pool_device: ctx.opts.storage_device.clone(),
        allow_private_networks: Some(ctx.opts.allow_private_networks),
        extra_host_addresses: None,
        ipv4: None,
    };
    {
        let progress = &mut ctx.progress;
        ctx.daemons
            .setup_host(req, &mut |p| progress.step("host", p))?;
    }
    let info = ctx.daemons.host_info()?;
    if !info.pool.as_ref().is_some_and(|p| p.exists) {
        return Err(InstallError::tool(
            "privd reports no storage pool after SetupHost",
        ));
    }
    if !info.host_firewall_loaded {
        return Err(InstallError::tool(
            "the host firewall (table inet hx) is not loaded after SetupHost",
        ));
    }
    if !info.sysctl_ok {
        ctx.warn("host", "the sysctl values for Incus could not be verified");
    }
    if let Some(v) = &info.incus_version {
        let min = if ctx.opts.docker {
            super::incus::DOCKER_MIN_VERSION
        } else {
            super::incus::MIN_VERSION
        };
        if !super::incus::at_least(v, min) {
            return Err(InstallError::preflight(format!(
                "the Incus on this host ({}) is too old{}",
                crate::cli::text::peer(v, 40),
                if ctx.opts.docker {
                    " for --docker (6.0.5 is needed)"
                } else {
                    " (6.0.0 is needed)"
                }
            )));
        }
    }
    Ok(Outcome::Done)
}

// ----- pairing-token (--pair, --token) ---------------------------------------------------------

/// Installs the pairing token of `--pair` or `--token` (never skipped on resume: a token must be
/// fresh).
pub fn token_run(ctx: &mut Ctx<'_>) -> Result<Outcome> {
    let Some(t) = ctx.secrets.token.as_ref() else {
        return Err(InstallError::usage(
            "no pairing token: run again with --pair (type it at the prompt) or --token <t>",
        ));
    };
    let expires = ctx.daemons.create_pairing_token(t, PAIR_TTL_S)?;
    ctx.report.pairing = PairingOut {
        kind: "token",
        expires_at_unix_s: expires,
    };
    Ok(Outcome::Done)
}

// ----- desktop --------------------------------------------------------------------------------

fn distro(name: &str) -> pb::Distro {
    match name {
        "ubuntu-26.04" => pb::Distro::Ubuntu2604,
        "debian-12" => pb::Distro::Debian12,
        "debian-13" => pb::Distro::Debian13,
        _ => pb::Distro::Ubuntu2404,
    }
}

fn usable(state: i32) -> bool {
    matches!(
        pb::DesktopState::try_from(state),
        Ok(pb::DesktopState::Ready
            | pb::DesktopState::Running
            | pb::DesktopState::Stopped
            | pb::DesktopState::Starting)
    )
}

fn wanted_limits(ctx: &Ctx<'_>) -> pb::Limits {
    pb::Limits {
        cpu: ctx.opts.cpu.unwrap_or(0),
        memory_mib: ctx.opts.memory_mib.unwrap_or(0),
        disk_gib: ctx.opts.disk_gib.unwrap_or(0),
    }
}

fn limits_differ(want: &pb::Limits, have: &pb::Limits) -> bool {
    (want.cpu != 0 && want.cpu != have.cpu)
        || (want.memory_mib != 0 && want.memory_mib != have.memory_mib)
        || (want.disk_gib != 0 && want.disk_gib != have.disk_gib)
}

/// Done-check: the desktop exists, is usable, and has the limits asked for.
pub fn desktop_check(ctx: &mut Ctx<'_>) -> Result<bool> {
    let Some(d) = ctx.daemons.get_desktop(DESKTOP_ID)? else {
        return Ok(false);
    };
    let want = wanted_limits(ctx);
    Ok(usable(d.state) && !limits_differ(&want, &d.limits.unwrap_or_default()))
}

/// Creates the desktop, or only applies new limits to an existing one.
pub fn desktop_run(ctx: &mut Ctx<'_>) -> Result<Outcome> {
    if let Some(d) = ctx.daemons.get_desktop(DESKTOP_ID)?
        && usable(d.state)
    {
        let have = d.limits.unwrap_or_default();
        let want = wanted_limits(ctx);
        if limits_differ(&want, &have) {
            let merged = pb::Limits {
                cpu: if want.cpu != 0 { want.cpu } else { have.cpu },
                memory_mib: if want.memory_mib != 0 {
                    want.memory_mib
                } else {
                    have.memory_mib
                },
                disk_gib: if want.disk_gib != 0 {
                    want.disk_gib
                } else {
                    have.disk_gib
                },
            };
            ctx.daemons.set_limits(DESKTOP_ID, merged)?;
        }
        return Ok(Outcome::Done);
    }
    let Some(pw) = ctx.secrets.password.as_ref() else {
        return Err(InstallError::usage(
            "the desktop's Linux password is needed to create it: run again with --ssh (secrets on stdin) or --interactive",
        ));
    };
    if let Some(why) = crate::install::options::password_problem(pw) {
        return Err(InstallError::usage(why));
    }
    let Some(user) = ctx.opts.user.clone() else {
        return Err(InstallError::usage(
            "--user is required to create the desktop",
        ));
    };
    let o = &ctx.opts;
    let settings = (!o.settings_empty()).then(|| pb::DesktopSettings {
        hostname: o.hostname.clone().unwrap_or_default(),
        timezone: o.timezone.clone().unwrap_or_default(),
        locale: o.locale.clone().unwrap_or_default(),
        keyboard: o.keyboard.clone().unwrap_or_default(),
    });
    let req = pb::CreateDesktopRequest {
        desktop_id: DESKTOP_ID.into(),
        distro: distro(&o.distro) as i32,
        desktop: pb::DesktopKind::Xfce as i32,
        preset: if o.apps == "developer" {
            pb::Preset::Developer
        } else {
            pb::Preset::Basic
        } as i32,
        username: user,
        image_mode: match o.image.as_str() {
            "build" => pb::ImageMode::Build,
            _ => pb::ImageMode::Auto,
        } as i32,
        limits: Some(wanted_limits(ctx)),
        docker: ctx.opts.docker,
        docker_isolation_acknowledged: ctx.opts.docker,
        settings,
        image_file: None,
    };
    let res = {
        let progress = &mut ctx.progress;
        let daemons = &mut *ctx.daemons;
        daemons.create_desktop(req, pw, &mut |p| progress.step("desktop", p))?
    };
    let path = pb::PathTaken::try_from(res.path_taken)
        .map(|p| {
            p.as_str_name()
                .strip_prefix("PATH_TAKEN_")
                .unwrap_or("UNKNOWN")
        })
        .unwrap_or("UNKNOWN");
    let warnings: Vec<String> = res
        .warnings
        .iter()
        .map(|w| crate::cli::text::peer(w, 256))
        .collect();
    for w in &warnings {
        ctx.warn("desktop", w);
    }
    let report = DesktopReport {
        id: crate::cli::text::peer(&res.desktop_id, 16),
        path_taken: path.to_owned(),
        reason: crate::cli::text::peer(&res.reason, 256),
        warnings,
    };
    ctx.report.desktop = Some(DesktopOut {
        id: report.id.clone(),
        path_taken: report.path_taken.clone(),
        reason: report.reason.clone(),
        warnings: report.warnings.clone(),
    });
    ctx.state.desktop = Some(report);
    Ok(Outcome::Done)
}

// ----- verifiers ------------------------------------------------------------------------------

/// `hx-pv1$m=..,t=..,p=..$<salt>$<mac>` for `secret` (`docs/ipc.md` 5.3): Argon2id here, the
/// pepper's MAC from privd's `PepperEnrol`. Only the Argon2id output reaches privd.
pub fn build_verifier(
    d: &mut dyn Daemons,
    purpose: LockoutPurpose,
    secret: &[u8],
    params: hx_crypto::PinParams,
) -> Result<Vec<u8>> {
    let mut salt = [0u8; 16];
    rustix::rand::getrandom(&mut salt, rustix::rand::GetRandomFlags::empty())
        .map_err(|e| InstallError::internal(format!("no randomness: {e}")))?;
    let p = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|_| InstallError::internal("the Argon2id parameters are invalid"))?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
        .hash_password_into(secret, &salt, &mut *out)
        .map_err(|_| InstallError::internal("hashing failed"))?;
    let mac = d.pepper_enrol(purpose, &*out)?;
    if mac.len() != 32 {
        return Err(InstallError::internal(
            "hx-privd returned a MAC that is not 32 bytes",
        ));
    }
    let record = format!(
        "{}$m={},t={},p={}${}${}",
        crate::gateway::verifier::PREFIX,
        params.memory_kib,
        params.iterations,
        params.parallelism,
        hex(&salt),
        hex(&mac)
    )
    .into_bytes();
    crate::gateway::verifier::VerifierRecord::parse(&record)
        .map_err(|e| InstallError::internal(format!("built a malformed verifier: {e}")))?;
    Ok(record)
}

/// Sets the PIN verifier for every device and the password verifier.
pub fn verifiers_run(ctx: &mut Ctx<'_>) -> Result<Outcome> {
    let (Some(pin), Some(pw)) = (ctx.secrets.pin.as_ref(), ctx.secrets.password.as_ref()) else {
        return Err(InstallError::usage(
            "the password and the PIN are needed to set the verifiers: run again with --ssh or --interactive",
        ));
    };
    let params = ctx.verifier_params;
    let pin_record = build_verifier(ctx.daemons, LockoutPurpose::Pin, pin, params)?;
    ctx.daemons.set_pin_verifier_all(pin_record)?;
    let pw_record = build_verifier(ctx.daemons, LockoutPurpose::Password, pw, params)?;
    ctx.daemons.set_password_verifier(pw_record)?;
    Ok(Outcome::Done)
}

// ----- owner-key, backup ----------------------------------------------------------------------

/// `EnrolOwnerKey` when the app sent one; otherwise the stage is skipped.
pub fn owner_key_run(ctx: &mut Ctx<'_>) -> Result<Outcome> {
    match ctx.secrets.owner_key.as_ref() {
        Some(k) => {
            ctx.daemons.enrol_owner_key(k)?;
            Ok(Outcome::Done)
        }
        None => Ok(Outcome::Skipped),
    }
}

/// The backup schedule is recorded in the options; the stage is `deferred` (Phase 2:
/// `SetBackupSchedule` is `UNIMPLEMENTED`).
pub fn backup_run(_ctx: &mut Ctx<'_>) -> Result<Outcome> {
    Ok(Outcome::Deferred)
}

// ----- pairing, finish ------------------------------------------------------------------------

/// The global addresses of `ip -j addr` output, without our bridge, Docker's and veth devices.
pub fn parse_addresses(json: &str) -> Vec<String> {
    let Ok(Value::Array(ifs)) = serde_json::from_str::<Value>(json) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for i in &ifs {
        let name = i.get("ifname").and_then(Value::as_str).unwrap_or("");
        if ["hxbr", "docker", "br-", "veth", "incus", "lo"]
            .iter()
            .any(|p| name.starts_with(p))
        {
            continue;
        }
        for a in i
            .get("addr_info")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if a.get("scope").and_then(Value::as_str) == Some("global")
                && let Some(l) = a.get("local").and_then(Value::as_str)
                && l.parse::<std::net::IpAddr>().is_ok()
                && !out.iter().any(|x| x == l)
            {
                out.push(l.to_owned());
            }
        }
    }
    out
}

/// Looks up the host's global addresses (best effort).
pub fn addresses(ctx: &mut Ctx<'_>) -> Vec<String> {
    ctx.run(Call::new(
        Tool::Ip,
        &["-j", "addr", "show", "scope", "global"],
    ))
    .ok()
    .filter(|o| o.ok())
    .map(|o| parse_addresses(&o.out_text()))
    .unwrap_or_default()
}

/// The last step: a pairing code (`--interactive`) or the app's token (`--ssh`). Never skipped on
/// resume.
pub fn pairing_run(ctx: &mut Ctx<'_>) -> Result<Outcome> {
    match ctx.mode {
        Mode::Interactive => {
            let (code, expires) = ctx.daemons.create_pairing_code(PAIR_TTL_S)?;
            let addrs = addresses(ctx);
            ctx.report.addresses = addrs.clone();
            ctx.report.pairing = PairingOut {
                kind: "code",
                expires_at_unix_s: expires,
            };
            let port = ctx.opts.port;
            let until = crate::cli::text::time(expires);
            ctx.progress
                .human_out("\nThe server is ready. Enter this code in the app to pair:\n");
            // Straight from the zeroizing buffer to the terminal.
            ctx.progress.secret_line("  pairing code: ", &code);
            drop(code);
            let at = if addrs.is_empty() {
                "(no global address found)".to_owned()
            } else {
                addrs
                    .iter()
                    .map(|a| format!("{a} port {port}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            ctx.progress.human_out(&format!(
                "  address: {at}\n  valid until {until} (15 minutes), single use. A new code: hx-agent pairing code\n"
            ));
            Ok(Outcome::Done)
        }
        Mode::Ssh => {
            if let Some(t) = ctx.secrets.token.as_ref() {
                let expires = ctx.daemons.create_pairing_token(t, PAIR_TTL_S)?;
                ctx.report.pairing = PairingOut {
                    kind: "token",
                    expires_at_unix_s: expires,
                };
            }
            Ok(Outcome::Done)
        }
        Mode::Pair | Mode::Token => Ok(Outcome::Skipped),
    }
}

/// Closes the setup window (privd and gatewayd). Never skipped on resume.
pub fn finish_run(ctx: &mut Ctx<'_>) -> Result<Outcome> {
    ctx.daemons.finish_setup(false)?;
    ctx.daemons
        .gateway_setup_window(apb::SetupWindowAction::Close, 0)?;
    Ok(Outcome::Done)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_the_global_ones_of_real_interfaces() {
        let j = r#"[
          {"ifname":"lo","addr_info":[{"local":"127.0.0.1","scope":"host"}]},
          {"ifname":"eth0","addr_info":[{"local":"203.0.113.5","scope":"global"},{"local":"fe80::1","scope":"link"},{"local":"2001:db8::5","scope":"global"}]},
          {"ifname":"hxbr0","addr_info":[{"local":"10.9.0.1","scope":"global"}]},
          {"ifname":"docker0","addr_info":[{"local":"172.17.0.1","scope":"global"}]}]"#;
        assert_eq!(parse_addresses(j), ["203.0.113.5", "2001:db8::5"]);
        assert!(parse_addresses("nope").is_empty());
    }

    #[test]
    fn the_distro_names_map_to_the_wire_enum() {
        assert_eq!(distro("debian-13"), pb::Distro::Debian13);
        assert_eq!(distro("ubuntu-24.04"), pb::Distro::Ubuntu2404);
        assert_eq!(distro("ubuntu-26.04"), pb::Distro::Ubuntu2604);
        assert_eq!(distro("debian-12"), pb::Distro::Debian12);
    }

    #[test]
    fn limits_only_differ_where_they_were_asked_for() {
        let have = pb::Limits {
            cpu: 4,
            memory_mib: 4096,
            disk_gib: 50,
        };
        assert!(!limits_differ(&pb::Limits::default(), &have));
        assert!(!limits_differ(
            &pb::Limits {
                cpu: 4,
                ..Default::default()
            },
            &have
        ));
        assert!(limits_differ(
            &pb::Limits {
                cpu: 2,
                ..Default::default()
            },
            &have
        ));
        assert!(limits_differ(
            &pb::Limits {
                disk_gib: 80,
                ..Default::default()
            },
            &have
        ));
    }
}
