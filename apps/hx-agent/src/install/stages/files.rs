//! Stages `system-files`, `config` and `units`: what goes on disk and what systemd runs.
//!
//! Files are written only when their content or mode differs, so a second run changes nothing
//! and a file edited by hand is put back (the stages converge). Every file the installer writes is
//! recorded in the state for uninstall.
//!
//! Paths (design C7): units below `/usr/local/lib/systemd/system` (outside dpkg's namespace),
//! sysusers and tmpfiles snippets below `/usr/local/lib`, installer drop-ins below
//! `/etc/systemd/system`, the logrotate snippet in `/etc/logrotate.d`.

use std::net::IpAddr;

use super::Outcome;
use crate::install::ctx::Ctx;
use crate::install::error::{InstallError, Result};
use crate::install::fsx::{ensure_dir, read_text, remove_file, write_if_changed};
use crate::install::paths;
use crate::install::runner::{Call, Tool};
use crate::install::units::{self, Dest, EmbeddedFile, Enable};

fn dest_dir(d: Dest) -> &'static str {
    match d {
        Dest::Unit => paths::UNIT_DIR,
        Dest::Sysusers => paths::SYSUSERS_DIR,
        Dest::Tmpfiles => paths::TMPFILES_DIR,
        Dest::Logrotate => paths::LOGROTATE_DIR,
    }
}

/// The absolute system path of an embedded file.
pub fn system_path(f: &EmbeddedFile) -> String {
    format!("{}/{}", dest_dir(f.dest), f.name)
}

fn file_matches(ctx: &Ctx<'_>, abs: &str, want: &[u8], mode: u32) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let p = ctx.paths.at(abs);
    std::fs::symlink_metadata(&p)
        .is_ok_and(|m| m.file_type().is_file() && m.permissions().mode() & 0o7777 == mode)
        && std::fs::read(&p).is_ok_and(|c| c == want)
}

fn put(ctx: &mut Ctx<'_>, abs: &str, bytes: &[u8], mode: u32) -> Result<()> {
    let p = ctx.paths.at(abs);
    write_if_changed(&p, bytes, mode)?;
    ctx.state.created_file(abs);
    Ok(())
}

fn put_dropin(ctx: &mut Ctx<'_>, abs: &str, bytes: &[u8]) -> Result<()> {
    let p = ctx.paths.at(abs);
    write_if_changed(&p, bytes, 0o644)?;
    ctx.state.created_dropin(abs);
    Ok(())
}

// ----- system-files ---------------------------------------------------------------------------

fn non_unit_rows() -> impl Iterator<Item = &'static EmbeddedFile> {
    units::FILES.iter().filter(|f| f.dest != Dest::Unit)
}

fn rescue_source(ctx: &Ctx<'_>) -> std::path::PathBuf {
    ctx.paths
        .at(paths::USR_LIB_HX)
        .join("current/hx-privd-rescue")
}

fn gateway_user_exists(ctx: &Ctx<'_>) -> bool {
    read_text(&ctx.paths.at(paths::PASSWD)).is_some_and(|t| {
        t.lines()
            .any(|l| l.starts_with(&format!("{}:", paths::GATEWAY_USER)))
    })
}

/// Done-check of `system-files`.
pub fn system_files_check(ctx: &mut Ctx<'_>) -> Result<bool> {
    for f in non_unit_rows() {
        if !file_matches(ctx, &system_path(f), f.text.as_bytes(), 0o644) {
            return Ok(false);
        }
    }
    let src = rescue_source(ctx);
    if let Ok(bytes) = std::fs::read(&src)
        && !file_matches(ctx, paths::RESCUE_BIN, &bytes, 0o755)
    {
        return Ok(false);
    }
    Ok(gateway_user_exists(ctx)
        && ctx.paths.at(paths::CREDS_DIR).is_dir()
        && ctx.paths.at(paths::USR_LIB_HX).is_dir())
}

/// sysusers, tmpfiles, logrotate, the rescue helper, the directories, the `hx-gatewayd` user.
pub fn system_files_run(ctx: &mut Ctx<'_>) -> Result<Outcome> {
    let existed = gateway_user_exists(ctx);
    ensure_dir(&ctx.paths.at(paths::ETC_HX), 0o755)?;
    ensure_dir(&ctx.paths.at(paths::CREDS_DIR), 0o700)?;
    ensure_dir(&ctx.paths.at(paths::RESCUE_DIR), 0o755)?;
    ensure_dir(&ctx.paths.at(paths::UNIT_DIR), 0o755)?;
    for f in non_unit_rows() {
        put(ctx, &system_path(f), f.text.as_bytes(), 0o644)?;
    }
    // The rescue helper is an optional member of the release; it lives outside /usr/lib/hx so
    // that pruning old releases never removes it.
    match std::fs::read(rescue_source(ctx)) {
        Ok(bytes) => put(ctx, paths::RESCUE_BIN, &bytes, 0o755)?,
        Err(_) => ctx.warn(
            "system-files",
            "this release has no hx-privd-rescue; a failed self-update will not be rolled back automatically",
        ),
    }
    let sysusers = ctx
        .paths
        .arg(&format!("{}/hx-gatewayd.conf", paths::SYSUSERS_DIR));
    ctx.run_ok(Call::owned(Tool::SystemdSysusers, vec![sysusers]))?;
    if !existed {
        ctx.state.created.user = true;
    }
    let tmpfiles = ctx.paths.arg(&format!("{}/hx.conf", paths::TMPFILES_DIR));
    ctx.run_ok(Call::owned(
        Tool::SystemdTmpfiles,
        vec!["--create".into(), tmpfiles],
    ))?;
    Ok(Outcome::Done)
}

// ----- config ---------------------------------------------------------------------------------

/// `/etc/hx/gatewayd.toml`: `listen` is the one key the installer sets (design D-Port).
pub fn gatewayd_toml(port: u16) -> String {
    format!(
        "# Written by hx-agent install. gatewayd takes its listeners from the systemd socket named\n\
         # `public` (hx-gatewayd-public.socket) and refuses a port that differs from this one.\n\
         listen = \"[::]:{port}\"\n"
    )
}

/// `/etc/hx/privd.toml`: the update channel.
pub fn privd_toml(channel: &str) -> String {
    format!("# Written by hx-agent install.\n[update]\nchannel = \"{channel}\"\n")
}

/// The drop-in that gives the public socket its port (resets the lists first).
pub fn port_dropin(port: u16) -> String {
    format!(
        "# Written by hx-agent install.\n[Socket]\nListenStream=\nListenDatagram=\nListenStream=[::]:{port}\nListenDatagram=[::]:{port}\n"
    )
}

/// Addresses that are never allowed: `IPAddressAllow` has no port limit, so allowing loopback
/// (every service on 127.0.0.1), link-local (the cloud metadata service at 169.254.169.254) or
/// multicast to the fetcher would be far wider than a resolver.
fn never_allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_loopback() || a.is_link_local() || a.is_multicast(),
        IpAddr::V6(a) => {
            a.is_loopback() || a.is_multicast() || (a.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Private ranges the fetcher's `IPAddressDeny` blocks and that a resolver may legitimately sit
/// in: RFC 1918, 100.64/10 and fc00::/7. (The allowance has no port limit either; that known risk
/// is accepted and documented.)
fn private_range(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 100 && (64..=127).contains(&o[1]))
        }
        IpAddr::V6(a) => (a.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// What to do with the resolvers of `resolv.conf`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ResolverPlan {
    /// Private resolvers that get an `IPAddressAllow`.
    pub allow: Vec<IpAddr>,
    /// Loopback, link-local and multicast nameservers that are skipped (never allowed).
    pub skipped: Vec<IpAddr>,
}

/// Splits the nameservers of `resolv.conf`: private ones are allowed, loopback, link-local and
/// multicast ones are skipped, public ones need nothing, and systemd-resolved's stubs
/// (127.0.0.53, 127.0.0.54) are already allowed by the fetcher's unit.
pub fn resolver_plan(resolv_conf: &str) -> ResolverPlan {
    let mut plan = ResolverPlan::default();
    for line in resolv_conf.lines() {
        let Some(rest) = line.trim().strip_prefix("nameserver") else {
            continue;
        };
        let Some(tok) = rest.split_whitespace().next() else {
            continue;
        };
        let tok = tok.split('%').next().unwrap_or(tok);
        let Ok(ip) = tok.parse::<IpAddr>() else {
            continue;
        };
        if ip == IpAddr::from([127, 0, 0, 53]) || ip == IpAddr::from([127, 0, 0, 54]) {
            continue;
        }
        if never_allowed(ip) {
            if !plan.skipped.contains(&ip) {
                plan.skipped.push(ip);
            }
        } else if private_range(ip) && !plan.allow.contains(&ip) {
            plan.allow.push(ip);
        }
    }
    plan
}

/// The two fetcher templates that get the resolver drop-in (the update fetcher and, for prebuilt
/// images, the image fetcher): both run with `IPAddressDeny` of the private ranges.
pub const RESOLVER_DROPINS: [&str; 2] = [paths::RESOLVERS_DROPIN, paths::IMAGE_RESOLVERS_DROPIN];

/// The resolver drop-in text, or `None` when no resolver needs an allowance.
pub fn resolvers_dropin(resolvers: &[IpAddr]) -> Option<String> {
    if resolvers.is_empty() {
        return None;
    }
    let mut s = String::from(
        "# Written by hx-agent install: the host's resolvers, so that the update fetcher and the image fetcher can resolve names.\n[Service]\n",
    );
    for r in resolvers {
        let bits = if r.is_ipv4() { 32 } else { 128 };
        s.push_str(&format!("IPAddressAllow={r}/{bits}\n"));
    }
    Some(s)
}

fn config_wants(ctx: &Ctx<'_>) -> (String, String, String, Option<String>) {
    let resolv = read_text(&ctx.paths.at(paths::RESOLV_CONF)).unwrap_or_default();
    (
        gatewayd_toml(ctx.opts.port),
        privd_toml(&ctx.opts.channel),
        port_dropin(ctx.opts.port),
        resolvers_dropin(&resolver_plan(&resolv).allow),
    )
}

/// Done-check of `config`: every file has exactly the content the options call for.
pub fn config_check(ctx: &mut Ctx<'_>) -> Result<bool> {
    let (g, p, d, r) = config_wants(ctx);
    let resolvers_ok = RESOLVER_DROPINS.iter().all(|d| match &r {
        Some(text) => file_matches(ctx, d, text.as_bytes(), 0o644),
        None => !ctx.paths.at(d).exists(),
    });
    Ok(file_matches(ctx, paths::GATEWAYD_TOML, g.as_bytes(), 0o644)
        && file_matches(ctx, paths::PRIVD_TOML, p.as_bytes(), 0o644)
        && file_matches(ctx, paths::PORT_DROPIN, d.as_bytes(), 0o644)
        && resolvers_ok)
}

/// Writes the configuration files and drop-ins.
pub fn config_run(ctx: &mut Ctx<'_>) -> Result<Outcome> {
    let (g, p, d, r) = config_wants(ctx);
    ensure_dir(&ctx.paths.at(paths::ETC_HX), 0o755)?;
    let skipped =
        resolver_plan(&read_text(&ctx.paths.at(paths::RESOLV_CONF)).unwrap_or_default()).skipped;
    if !skipped.is_empty() {
        let list = skipped
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let note = format!(
            "the nameserver(s) {list} in resolv.conf were not allowed for the update fetcher (loopback, link-local and multicast addresses are never allowed: the allowance has no port limit); CheckUpdate needs systemd-resolved or a private resolver"
        );
        ctx.warn("config", &note);
        if !ctx.state.notes.contains(&note) {
            ctx.state.notes.push(note);
        }
    }
    put(ctx, paths::GATEWAYD_TOML, g.as_bytes(), 0o644)?;
    put(ctx, paths::PRIVD_TOML, p.as_bytes(), 0o644)?;
    put_dropin(ctx, paths::PORT_DROPIN, d.as_bytes())?;
    for d in RESOLVER_DROPINS {
        match &r {
            Some(text) => put_dropin(ctx, d, text.as_bytes())?,
            None => {
                remove_file(&ctx.paths.at(d))?;
                ctx.state.created.dropins.retain(|x| x != d);
            }
        }
    }
    Ok(Outcome::Done)
}

// ----- units ----------------------------------------------------------------------------------

fn unit_rows() -> impl Iterator<Item = &'static EmbeddedFile> {
    units::FILES.iter().filter(|f| f.dest == Dest::Unit)
}

fn systemctl_ok(ctx: &mut Ctx<'_>, args: &[&str]) -> bool {
    ctx.run(Call::new(Tool::Systemctl, args))
        .is_ok_and(|o| o.ok())
}

/// Done-check of `units`: files, enablement, activity, privd answering, the socket's port.
pub fn units_check(ctx: &mut Ctx<'_>) -> Result<bool> {
    for f in unit_rows() {
        if !file_matches(ctx, &system_path(f), f.text.as_bytes(), 0o644) {
            return Ok(false);
        }
    }
    for f in unit_rows() {
        match f.enable {
            Enable::Now => {
                if !systemctl_ok(ctx, &["is-enabled", "--quiet", f.name])
                    || !systemctl_ok(ctx, &["is-active", "--quiet", f.name])
                {
                    return Ok(false);
                }
            }
            Enable::Enable => {
                if !systemctl_ok(ctx, &["is-enabled", "--quiet", f.name]) {
                    return Ok(false);
                }
            }
            Enable::No => {}
        }
    }
    if ctx.state.created.socket_port != ctx.opts.port {
        return Ok(false);
    }
    Ok(ctx.daemons.hello().is_ok() && ctx.daemons.host_info().is_ok())
}

/// Writes the units, reloads systemd, enables and starts them, and waits for privd.
pub fn units_run(ctx: &mut Ctx<'_>) -> Result<Outcome> {
    ensure_dir(&ctx.paths.at(paths::UNIT_DIR), 0o755)?;
    for f in unit_rows() {
        put(ctx, &system_path(f), f.text.as_bytes(), 0o644)?;
    }
    ctx.run_ok(Call::new(Tool::Systemctl, &["daemon-reload"]))?;
    for f in unit_rows() {
        match f.enable {
            Enable::Now => {
                ctx.run_ok(
                    Call::new(Tool::Systemctl, &["enable", "--now", f.name]).timeout_secs(120),
                )?;
            }
            Enable::Enable => {
                ctx.run_ok(Call::new(Tool::Systemctl, &["enable", f.name]))?;
            }
            Enable::No => {}
        }
    }
    // A port that changed after the sockets were listening: restart them so they bind the new one.
    let old = ctx.state.created.socket_port;
    if old != 0 && old != ctx.opts.port {
        let _ = ctx.run(Call::new(
            Tool::Systemctl,
            &[
                "restart",
                "hx-gatewayd-public.socket",
                "hx-gatewayd.service",
            ],
        ));
    }
    ctx.state.created.socket_port = ctx.opts.port;
    wait_for_privd(ctx)?;
    Ok(Outcome::Done)
}

fn wait_for_privd(ctx: &mut Ctx<'_>) -> Result<()> {
    let mut last = InstallError::unavailable("hx-privd did not answer");
    for _ in 0..60 {
        match ctx.daemons.hello().and_then(|_| ctx.daemons.host_info()) {
            Ok(_) => return Ok(()),
            Err(e) => last = e,
        }
        ctx.probe.sleep(std::time::Duration::from_millis(500));
    }
    Err(InstallError::unavailable(format!(
        "hx-privd did not come up after its units were started: {}",
        last.message
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_gateway_config_has_the_listen_key_gatewayd_expects() {
        let t = gatewayd_toml(8443);
        assert!(t.contains("listen = \"[::]:8443\"\n"));
        // Parses as TOML with exactly the key `listen` set.
        let v: toml::Table = t.parse().unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v["listen"].as_str(), Some("[::]:8443"));
        let c = crate::gateway::config::GatewayConfig::from_toml(&t).unwrap();
        assert_eq!(c.listen.port(), 8443);
    }

    #[test]
    fn the_privd_policy_is_what_privd_reads() {
        let t = privd_toml("beta");
        let v: toml::Table = t.parse().unwrap();
        assert_eq!(v["update"]["channel"].as_str(), Some("beta"));
    }

    #[test]
    fn the_port_dropin_resets_before_it_sets() {
        let t = port_dropin(443);
        let lines: Vec<&str> = t.lines().filter(|l| !l.starts_with('#')).collect();
        assert_eq!(
            lines,
            [
                "[Socket]",
                "ListenStream=",
                "ListenDatagram=",
                "ListenStream=[::]:443",
                "ListenDatagram=[::]:443"
            ]
        );
    }

    #[test]
    fn only_private_resolvers_are_allowed_and_loopback_link_local_multicast_are_skipped() {
        let conf = "nameserver 127.0.0.53\nnameserver 10.0.0.2\nnameserver 8.8.8.8\n\
                    nameserver 192.168.1.1\nnameserver fe80::1%eth0\nnameserver fd00::53\n\
                    nameserver 2001:4860:4860::8888\nnameserver 100.64.0.1\nnameserver 172.16.5.5\n\
                    nameserver 10.0.0.2\nnameserver 127.0.0.1\nnameserver ::1\n\
                    nameserver 169.254.169.254\nnameserver ff02::1\nnameserver 224.0.0.251\n\
                    nameserver bogus\nsearch example.com\n";
        let p = resolver_plan(conf);
        let allow: Vec<String> = p.allow.iter().map(ToString::to_string).collect();
        assert_eq!(
            allow,
            [
                "10.0.0.2",
                "192.168.1.1",
                "fd00::53",
                "100.64.0.1",
                "172.16.5.5"
            ]
        );
        let skipped: Vec<String> = p.skipped.iter().map(ToString::to_string).collect();
        assert_eq!(
            skipped,
            [
                "fe80::1",
                "127.0.0.1",
                "::1",
                "169.254.169.254",
                "ff02::1",
                "224.0.0.251"
            ]
        );
        let text = resolvers_dropin(&p.allow).unwrap();
        for bad in ["127.", "::1/", "169.254", "fe80", "ff02", "224."] {
            assert!(!text.contains(bad), "{bad} in the drop-in:\n{text}");
        }
        assert_eq!(
            resolver_plan("nameserver 127.0.0.54\nnameserver 1.1.1.1\n"),
            ResolverPlan::default()
        );
        assert_eq!(resolver_plan(""), ResolverPlan::default());
    }

    #[test]
    fn the_resolver_dropin_allows_each_address_exactly() {
        assert_eq!(resolvers_dropin(&[]), None);
        let t =
            resolvers_dropin(&["10.0.0.2".parse().unwrap(), "fd00::53".parse().unwrap()]).unwrap();
        assert!(t.contains("IPAddressAllow=10.0.0.2/32\n"));
        assert!(t.contains("IPAddressAllow=fd00::53/128\n"));
    }

    #[test]
    fn units_live_outside_the_package_namespace() {
        for f in units::FILES.iter().filter(|f| f.dest == Dest::Unit) {
            assert!(system_path(f).starts_with("/usr/local/lib/systemd/system/"));
        }
    }
}
