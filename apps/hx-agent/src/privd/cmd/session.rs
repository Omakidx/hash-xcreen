//! `ProvisionSessionLink`, `InstallSession`, `RestartSession` (ipc.md 6.11).
//!
//! The proxy device is computed by `hx_provision::incus::SessionLink` from the desktop id and
//! the two uid/gid pairs privd knows (the gateway's, resolved at start, and the desktop user's
//! 1000/1000 from the recipe); nothing in the request reaches it. privd creates nothing in
//! `/run/hx/link`: `systemd-tmpfiles` does (`root:hx-gatewayd 0750`).
//!
//! `InstallSession` pushes the `hx-session` package of the desktop's distro from privd's own
//! artifact store (`<session_store>/<distro>/hx-session.deb`, root-owned, installed with the
//! signed agent release), runs fixed `dpkg` and `systemctl` commands inside the container and
//! trusts nothing the container prints: the version is read back and validated.

use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::time::Duration;

use hx_ipc::privd::pb::{self, ErrorDetail, response};
use hx_ipc::text::sanitize_text;
use hx_provision::incus::{Client, IncusError, SessionLink, Transport};
use hx_provision::orchestrate::exec_captured;
use hx_provision::session::{SESSION_SERVICE_UNIT, SESSION_SOCKET_UNIT};
use rustix::fs::OFlags;

use super::common::recipe_from_text;
use crate::privd::config::DESKTOP_IDS;
use crate::privd::daemon::{Ctx, Daemon, Reply};
use crate::privd::error::CmdError;

/// Directory in the container that receives the package (ipc.md 6.11).
pub const CONTAINER_DIR: &str = "/var/lib/hx/session";
/// File name of the package in the store and in the container.
pub const PACKAGE_FILE: &str = "hx-session.deb";
/// Largest package accepted (ipc.md 6.12: each `hx-session` package at most 64 MiB).
pub const MAX_PACKAGE_BYTES: u64 = 64 * 1024 * 1024;

/// Provisions the link device (no state checks: `CreateDesktop` calls it before `ready`).
pub async fn provision_link_inner<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &Ctx,
    client: &Client<T>,
    id: &str,
    instance: &str,
) -> Result<String, CmdError> {
    // The host-side socket listens in this directory: it must be what tmpfiles made (root, the
    // gateway's group, 0750, not a symlink), or the gateway could replace sockets in it.
    if let Some(expected) = &d.cfg.expected_link_dir
        && let Some(v) = crate::privd::identity::link_dir_violation(&d.cfg.link_dir, expected)
    {
        crate::privd::log::error(&format!("link directory: {v}"));
        return Err(CmdError::precondition(
            ErrorDetail::Unspecified,
            "the link directory is not root:hx-gatewayd 0750; refusing to add the proxy device",
        ));
    }
    let link = SessionLink::new(id, (d.cfg.gateway.uid, d.cfg.gateway.gid), DESKTOP_IDS)?;
    let path = link.socket_path();
    d.run_cancellable(ctx, client, Some(id), async {
        client
            .add_session_link(instance, &link)
            .await
            .map_err(|e| match e {
                // The container did not accept the device: a state problem, with Incus's text.
                IncusError::Api { .. }
                | IncusError::Operation(_)
                | IncusError::InvalidArgument(_) => CmdError::precondition(
                    ErrorDetail::Unspecified,
                    format!(
                        "Incus refused the link device: {}",
                        sanitize_text(&e.to_string(), 150)
                    ),
                ),
                other => other.into(),
            })
    })
    .await?;
    Ok(path)
}

/// `ProvisionSessionLink` (class A). Returns the socket path.
pub async fn provision_link<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &mut Ctx,
    r: pb::ProvisionSessionLinkRequest,
) -> Result<Reply, CmdError> {
    let id = r.desktop_id;
    let _g = d.lock_desktop(ctx, &id, false).await?;
    let l = d.load_desktop(&id).await?;
    let client = d.incus.scoped();
    let path = provision_link_inner(d, ctx, &client, &id, &l.name).await?;
    Ok(response::Result::ProvisionSessionLink(
        pb::ProvisionSessionLinkResult { socket_path: path },
    ))
}

/// Reads the package once from a path privd controls: `O_NOFOLLOW`, a regular file owned by the
/// effective uid and not writable by group or others, within the size quota. `Ok(None)` when it
/// does not exist.
pub fn read_package(path: &std::path::Path) -> Result<Option<Vec<u8>>, CmdError> {
    let f = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let m = f.metadata()?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != rustix::process::geteuid().as_raw()
        || m.mode() & 0o022 != 0
        || m.len() > MAX_PACKAGE_BYTES
    {
        return Err(CmdError::internal(
            "the hx-session package in the artifact store is not acceptable (owner, mode, links or size)",
        ));
    }
    let mut buf = Vec::with_capacity(usize::try_from(m.len()).unwrap_or(0));
    f.take(MAX_PACKAGE_BYTES + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 != m.len() {
        return Err(CmdError::internal("the package changed while it was read"));
    }
    Ok(Some(buf))
}

async fn run_in<T: Transport + Clone + 'static>(
    client: &Client<T>,
    instance: &str,
    argv: &[&str],
    env: &[(String, String)],
    timeout: Duration,
) -> Result<hx_provision::incus::ExecResult, CmdError> {
    let argv: Vec<String> = argv.iter().map(|s| (*s).to_string()).collect();
    Ok(exec_captured(client, instance, &argv, env, None, None, timeout).await?)
}

/// The fixed restart sequence (ipc.md 6.11): `reset-failed` for the socket and the service (the
/// exit status is not used: the units may not be failed), then `restart` of both.
pub async fn restart_session_units<T: Transport + Clone + 'static>(
    client: &Client<T>,
    instance: &str,
) -> Result<(), CmdError> {
    let units = [SESSION_SOCKET_UNIT, SESSION_SERVICE_UNIT];
    let mut reset = vec!["systemctl", "reset-failed"];
    reset.extend(units);
    let _ = run_in(client, instance, &reset, &[], Duration::from_secs(30)).await?;
    let mut restart = vec!["systemctl", "restart"];
    restart.extend(units);
    let out = run_in(client, instance, &restart, &[], Duration::from_secs(60)).await?;
    if out.exit_code != 0 {
        return Err(CmdError::internal(
            "restarting the hx-session units failed inside the desktop",
        ));
    }
    Ok(())
}

/// A version string a package manager could have printed, which privd will store: 1 to 64 of
/// `[0-9A-Za-z.+~:-]`. Anything else (container output is untrusted) is rejected.
pub fn valid_package_version(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'+' | b'~' | b':' | b'-'))
}

/// Installs the package of the desktop's distro. `Ok(None)` when the host has no package for it.
pub async fn install_inner<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &Ctx,
    client: &Client<T>,
    id: &str,
    instance: &str,
    recipe_text: &str,
) -> Result<Option<String>, CmdError> {
    let recipe = recipe_from_text(recipe_text)
        .ok_or_else(|| CmdError::internal("the desktop has no valid recipe recorded"))?;
    let path = d
        .cfg
        .session_store
        .join(recipe.distro.as_str())
        .join(PACKAGE_FILE);
    let Some(bytes) = read_package(&path)? else {
        return Ok(None);
    };
    let target = format!("{CONTAINER_DIR}/{PACKAGE_FILE}");
    let env = vec![("DEBIAN_FRONTEND".to_string(), "noninteractive".to_string())];
    let version = d
        .run_cancellable(ctx, client, Some(id), async {
            client.push_dir(instance, CONTAINER_DIR, 0o700).await?;
            client.push_file(instance, &target, &bytes, 0o600).await?;
            let out = run_in(
                client,
                instance,
                &["dpkg", "-i", &target],
                &env,
                Duration::from_secs(180),
            )
            .await?;
            let _ = client.delete_file(instance, &target).await;
            if out.exit_code != 0 {
                return Err(CmdError::internal(
                    "installing the hx-session package failed inside the desktop",
                ));
            }
            let v = run_in(
                client,
                instance,
                &["dpkg-query", "-W", "-f=${Version}", "hx-session"],
                &[],
                Duration::from_secs(30),
            )
            .await?;
            let v = v.stdout.trim().to_string();
            if v.is_empty() || !valid_package_version(&v) {
                return Err(CmdError::internal(
                    "the installed hx-session version could not be read back",
                ));
            }
            restart_session_units(client, instance).await?;
            client
                .patch_instance_config(
                    instance,
                    &[("user.hx.session_version".to_string(), v.clone())]
                        .into_iter()
                        .collect(),
                )
                .await?;
            Ok::<_, CmdError>(v)
        })
        .await?;
    Ok(Some(version))
}

/// `InstallSession` (class A).
pub async fn install<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &mut Ctx,
    r: pb::InstallSessionRequest,
) -> Result<Reply, CmdError> {
    let id = r.desktop_id;
    let _g = d.lock_desktop(ctx, &id, false).await?;
    let l = d.load_desktop(&id).await?;
    let client = d.incus.scoped();
    if !client.instance_state(&l.name).await?.is_running() {
        return Err(CmdError::precondition(
            ErrorDetail::DesktopNotReady,
            "the desktop is not running",
        ));
    }
    let v = install_inner(d, ctx, &client, &id, &l.name, &l.meta.recipe)
        .await?
        .ok_or_else(|| {
            CmdError::precondition(
                ErrorDetail::Unspecified,
                "the hx-session package for this distro is not installed on the host",
            )
        })?;
    Ok(response::Result::InstallSession(pb::InstallSessionResult {
        installed_version: v,
        restarted: true,
    }))
}

/// `RestartSession` (class A): the fixed restart sequence and nothing else.
pub async fn restart<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &mut Ctx,
    r: pb::RestartSessionRequest,
) -> Result<Reply, CmdError> {
    let id = r.desktop_id;
    let _g = d.lock_desktop(ctx, &id, false).await?;
    let l = d.load_desktop(&id).await?;
    let client = d.incus.scoped();
    if !client.instance_state(&l.name).await?.is_running() {
        return Err(CmdError::precondition(
            ErrorDetail::DesktopNotReady,
            "the desktop is not running",
        ));
    }
    d.run_cancellable(ctx, &client, Some(&id), async {
        restart_session_units(&client, &l.name).await
    })
    .await?;
    Ok(response::Result::RestartSession(
        pb::RestartSessionResult {},
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn version_text_from_the_container_is_validated() {
        for ok in ["0.1.0", "1.2.3-1ubuntu1", "1:2.0+git~abc"] {
            assert!(valid_package_version(ok), "{ok}");
        }
        for bad in ["", "1 2", "$(id)", "a\nb", &"1".repeat(65), "1;2"] {
            assert!(!valid_package_version(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_package_must_be_ours_private_and_bounded() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("hx-session.deb");
        assert_eq!(read_package(&p).unwrap(), None);
        std::fs::write(&p, b"deb").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(read_package(&p).unwrap().as_deref(), Some(&b"deb"[..]));
        // Group- or world-writable: refused.
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_package(&p).is_err());
        // A symlink is not followed.
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let l = d.path().join("link.deb");
        std::os::unix::fs::symlink(&p, &l).unwrap();
        assert!(read_package(&l).is_err());
    }
}
