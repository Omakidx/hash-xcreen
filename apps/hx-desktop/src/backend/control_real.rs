//! The real [`ServerControl`]: server management (protocol 1.3) over the PIN-signed-in session
//! the Server details screen holds (`AdminContext::session`).
//!
//! The messages are the ones of `hx_crypto::server_admin::ServerAdmin`, sent by the app's own
//! session task (`Desk::server_request`), so the session has exactly one reader of control
//! answers for devices, pairing codes and server management alike (see `real.rs`).

use std::time::Duration;

use bytes::Bytes;
use hx_crypto::Pin;
use hx_crypto::setup::Password;
use hx_proto::pb::{self, server_mgmt::Body};

use super::*;
use crate::session::MgmtError;

/// Server management over the app's session.
pub struct RealControl;

const WAIT: Duration = Duration::from_secs(30);
/// The server gives up a release check after 60 s.
const CHECK_WAIT: Duration = Duration::from_secs(70);

fn session(ctx: &AdminContext) -> Result<Arc<dyn crate::session::Desk>, AdminError> {
    ctx.session.clone().ok_or(AdminError::SessionRequired)
}

async fn call(ctx: &AdminContext, body: Body, wait: Duration) -> Result<Body, AdminError> {
    session(ctx)?
        .server_request(body, wait)
        .await
        .map_err(|e| match e {
            MgmtError::Unsupported => AdminError::UpdateRequired,
            MgmtError::Closed | MgmtError::Timeout => AdminError::Unreachable,
        })
}

async fn result(
    ctx: &AdminContext,
    body: Body,
    wait: Duration,
) -> Result<pb::ServerResult, AdminError> {
    match call(ctx, body, wait).await? {
        Body::Result(r) => Ok(r),
        _ => Err(AdminError::Failed(
            "The server answered with something unexpected.".into(),
        )),
    }
}

fn text(r: &pb::ServerResult, default: &str) -> String {
    if r.message.is_empty() {
        default.to_owned()
    } else {
        crate::session::connect::sanitize(&r.message)
    }
}

/// A server decision that is not OK, as the screen's error.
pub fn status_error(r: &pb::ServerResult) -> Option<AdminError> {
    use pb::ServerStatus as S;
    Some(match r.status() {
        S::Ok => return None,
        S::WrongPin | S::WrongPassword => {
            if r.attempts_left == 0 {
                AdminError::Revoked
            } else {
                AdminError::Incorrect {
                    attempts_left: Some(r.attempts_left),
                }
            }
        }
        S::Backoff => AdminError::Failed(format!(
            "Wait {} seconds before trying again. Waiting does not use up an attempt.",
            r.retry_after_s.max(1)
        )),
        S::Locked => AdminError::Failed(format!(
            "This is locked for now. Try again in {} minutes.",
            r.retry_after_s.div_ceil(60).max(1)
        )),
        S::RateLimited => AdminError::RateLimited,
        S::AdminOnly => AdminError::Failed(format!(
            "This is done on the server: {}",
            text(r, "run it in a root shell")
        )),
        S::Unavailable => AdminError::Failed(text(r, "The server cannot do this right now.")),
        S::DesktopNotReady => AdminError::Failed(text(r, "The desktop is not ready yet.")),
        S::UpdateRefused => AdminError::Failed(text(r, "The server refused this update.")),
        S::Unsupported => AdminError::UpdateRequired,
        S::InvalidArgument => AdminError::Failed(text(r, "The server did not accept that value.")),
        S::Failed | S::Unspecified => AdminError::Failed(text(r, "The server could not do that.")),
    })
}

fn attention_text(a: pb::ServerAttention) -> Option<&'static str> {
    use pb::ServerAttention as A;
    Some(match a {
        A::Unspecified => return None,
        A::HostAccountPolicy => {
            "The host's account policy blocks the desktop user's password change."
        }
        A::StuckOperation => "An operation on the server did not finish.",
        A::IsolationNotRestored => {
            "Docker isolation was not restored after the last change. Run sudo hx-agent docker enable on the server."
        }
        A::PinLocked => "PIN checks are locked on the server for now.",
        A::PasswordLocked => "Password checks are locked on the server for now.",
        A::UpdateRolledBack => "The last update was rolled back.",
        A::HostDockerForwarding => {
            "Docker on the host forwards traffic around the desktop's firewall."
        }
    })
}

fn distro_label(d: pb::SetupDistro) -> &'static str {
    match d {
        pb::SetupDistro::Ubuntu2404 => "Ubuntu 24.04",
        pb::SetupDistro::Ubuntu2604 => "Ubuntu 26.04",
        pb::SetupDistro::Debian12 => "Debian 12",
        pb::SetupDistro::Debian13 => "Debian 13",
        pb::SetupDistro::Unspecified => "Unknown distribution",
    }
}

/// The server's overview as the screen's [`Overview`]. Only what the server reports.
pub fn overview_view(o: &pb::ServerOverview, protocol: Option<(u32, u32)>) -> Overview {
    use pb::ServerDesktopState as D;
    let d = o.desktop.clone();
    let (desktop, setup, limits, docker, mut attention) = match &d {
        Some(d) => {
            let status = match d.state() {
                D::Ready | D::Running => DesktopStatus::Running,
                D::Stopped | D::Failed => DesktopStatus::NotAnswering,
                D::Creating | D::Starting => DesktopStatus::Creating,
                D::None => DesktopStatus::NotCreated,
                D::Unknown | D::Unspecified => DesktopStatus::Unknown,
            };
            let docker = matches!(
                d.docker(),
                pb::ServerDockerState::On | pb::ServerDockerState::Degraded
            );
            let setup = format!(
                "{} · XFCE · {} · Docker {}",
                distro_label(d.distro()),
                if d.preset() == pb::SetupPreset::Developer {
                    "Developer"
                } else {
                    "Basic"
                },
                if docker { "on" } else { "off" }
            );
            let limits = d.limits.as_ref().map(|l| Limits {
                cpu: l.cpu,
                memory_gb: (l.memory_mib / 1024) as u32,
                disk_gb: l.disk_gib as u32,
            });
            let att: Vec<String> = d
                .needs_attention()
                .filter_map(attention_text)
                .map(str::to_owned)
                .collect();
            (status, setup, limits, docker, att)
        }
        None => (
            DesktopStatus::Unknown,
            String::new(),
            None,
            false,
            Vec::new(),
        ),
    };
    attention.extend(
        o.host_attention()
            .filter_map(attention_text)
            .map(str::to_owned),
    );
    let (host_os, host_cpus, host_mem_gb, host_disk_gb) = match &o.host {
        Some(h) => {
            let reserve = 1536u64.max(h.memory_total_mib / 4);
            (
                format!(
                    "{} {}, {} vCPU, {:.1} GB",
                    crate::session::connect::sanitize(&h.os),
                    crate::session::connect::sanitize(&h.arch),
                    h.cpu_count,
                    h.memory_total_mib as f64 / 1024.0
                ),
                h.cpu_count,
                (h.memory_total_mib.saturating_sub(reserve) / 1024).max(1) as u32,
                h.pool_total_gib as u32,
            )
        }
        None => (String::new(), 1, 1, 8),
    };
    let u = o.update.clone().unwrap_or_default();
    Overview {
        desktop,
        agent_uptime_secs: o.agent_uptime_s,
        session_active: o.session_active,
        setup,
        agent_version: crate::session::connect::sanitize(&o.agent_version),
        privd_version: crate::session::connect::sanitize(&o.privd_version),
        channel: match u.channel() {
            pb::ServerUpdateChannel::Beta => "beta",
            _ => "stable",
        }
        .to_owned(),
        update_available: (!u.available.is_empty())
            .then(|| crate::session::connect::sanitize(&u.available)),
        rolled_back: (!u.rolled_back_version.is_empty())
            .then(|| crate::session::connect::sanitize(&u.rolled_back_version)),
        protocol: protocol.map_or("1.3".to_owned(), |(a, b)| format!("{a}.{b}")),
        limits,
        host_os,
        host_cpus,
        host_mem_gb,
        host_disk_gb,
        docker,
        attention,
    }
}

impl ServerControl for RealControl {
    fn overview(&self, ctx: &AdminContext) -> BoxFuture<'_, Result<Overview, AdminError>> {
        let ctx = ctx.clone();
        Box::pin(async move {
            match call(&ctx, Body::GetOverview(pb::ServerGetOverview {}), WAIT).await? {
                Body::Overview(o) => Ok(overview_view(&o, ctx.server_version)),
                _ => Err(AdminError::Failed(
                    "The server answered with something unexpected.".into(),
                )),
            }
        })
    }

    fn change_pin(
        &self,
        ctx: &AdminContext,
        current: &Secret,
        new: &Secret,
    ) -> BoxFuture<'_, Result<(), AdminError>> {
        let ctx = ctx.clone();
        let (c, n) = (current.expose().to_owned(), new.expose().to_owned());
        Box::pin(async move {
            let (c, n) = (
                Pin::new(&c).map_err(|_| AdminError::Incorrect {
                    attempts_left: None,
                })?,
                Pin::new(&n)
                    .map_err(|_| AdminError::Failed("A PIN is 6 or more digits.".into()))?,
            );
            let body = Body::ChangePin(pb::ServerChangePin {
                current: Bytes::copy_from_slice(c.as_bytes()),
                new: Bytes::copy_from_slice(n.as_bytes()),
            });
            status_error(&result(&ctx, body, WAIT).await?).map_or(Ok(()), Err)
        })
    }

    fn change_password(
        &self,
        ctx: &AdminContext,
        current: &Secret,
        new: &Secret,
    ) -> BoxFuture<'_, Result<(), AdminError>> {
        let ctx = ctx.clone();
        let (c, n) = (current.expose().to_owned(), new.expose().to_owned());
        Box::pin(async move {
            let (c, n) = (
                Password::new(&c).map_err(|_| AdminError::Incorrect {
                    attempts_left: None,
                })?,
                Password::new(&n).map_err(|_| {
                    AdminError::Failed(
                        "The new password is not acceptable (1 to 511 bytes, no line breaks)."
                            .into(),
                    )
                })?,
            );
            let body = Body::ChangePassword(pb::ServerChangePassword {
                current: Bytes::copy_from_slice(c.as_bytes()),
                new: Bytes::copy_from_slice(n.as_bytes()),
            });
            status_error(&result(&ctx, body, WAIT).await?).map_or(Ok(()), Err)
        })
    }

    fn restart_desktop(&self, ctx: &AdminContext) -> BoxFuture<'_, Result<(), AdminError>> {
        let ctx = ctx.clone();
        Box::pin(async move {
            let r = result(
                &ctx,
                Body::RestartDesktop(pb::ServerRestartDesktop { force: false }),
                WAIT,
            )
            .await?;
            status_error(&r).map_or(Ok(()), Err)
        })
    }

    fn set_docker(&self, ctx: &AdminContext, on: bool) -> BoxFuture<'_, Result<(), AdminError>> {
        let ctx = ctx.clone();
        Box::pin(async move {
            let r = result(
                &ctx,
                Body::SetDocker(pb::ServerSetDocker { enable: on }),
                WAIT,
            )
            .await?;
            status_error(&r).map_or(Ok(()), Err)
        })
    }

    fn set_limits(&self, ctx: &AdminContext, l: Limits) -> BoxFuture<'_, Result<(), AdminError>> {
        let ctx = ctx.clone();
        Box::pin(async move {
            let limits = pb::SetupLimits {
                cpu: l.cpu,
                memory_mib: u64::from(l.memory_gb) * 1024,
                disk_gib: u64::from(l.disk_gb),
            };
            let r = result(
                &ctx,
                Body::SetLimits(pb::ServerSetLimits {
                    limits: Some(limits),
                }),
                WAIT,
            )
            .await?;
            status_error(&r).map_or(Ok(()), Err)
        })
    }

    fn update_agent(&self, ctx: &AdminContext) -> BoxFuture<'_, Result<String, AdminError>> {
        let ctx = ctx.clone();
        Box::pin(async move {
            let r = result(
                &ctx,
                Body::CheckUpdate(pb::ServerCheckUpdate {}),
                CHECK_WAIT,
            )
            .await?;
            if let Some(e) = status_error(&r) {
                return Err(e);
            }
            let info = r.update.unwrap_or_default();
            if info.available.is_empty() {
                return Ok(info.current);
            }
            let version = info.available;
            let r = result(
                &ctx,
                Body::ApplyUpdate(pb::ServerApplyUpdate {
                    version: version.clone(),
                }),
                WAIT,
            )
            .await?;
            // OK means the server accepted it and restarts: the session ends.
            status_error(&r).map_or(Ok(version), Err)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn res(s: pb::ServerStatus) -> pb::ServerResult {
        pb::ServerResult {
            status: s as i32,
            ..Default::default()
        }
    }

    #[test]
    fn decisions_map_to_the_screens_errors() {
        assert!(status_error(&res(pb::ServerStatus::Ok)).is_none());
        let wrong = pb::ServerResult {
            attempts_left: 3,
            ..res(pb::ServerStatus::WrongPin)
        };
        assert_eq!(
            status_error(&wrong),
            Some(AdminError::Incorrect {
                attempts_left: Some(3)
            })
        );
        let last = pb::ServerResult {
            attempts_left: 0,
            ..res(pb::ServerStatus::WrongPin)
        };
        assert_eq!(
            status_error(&last),
            Some(AdminError::Revoked),
            "the fifth wrong PIN revokes this device"
        );
        let admin = pb::ServerResult {
            message: "sudo hx-agent docker enable".into(),
            ..res(pb::ServerStatus::AdminOnly)
        };
        assert!(
            matches!(status_error(&admin), Some(AdminError::Failed(m)) if m.contains("sudo hx-agent docker enable"))
        );
        assert_eq!(
            status_error(&res(pb::ServerStatus::Unsupported)),
            Some(AdminError::UpdateRequired)
        );
        assert_eq!(
            status_error(&res(pb::ServerStatus::RateLimited)),
            Some(AdminError::RateLimited)
        );
    }

    #[test]
    fn the_overview_shows_only_what_the_server_reports() {
        let o = pb::ServerOverview {
            agent_version: "0.1.0".into(),
            agent_uptime_s: 90_000,
            desktop: Some(pb::ServerDesktop {
                state: pb::ServerDesktopState::Running as i32,
                username: "alex".into(),
                distro: pb::SetupDistro::Ubuntu2404 as i32,
                preset: pb::SetupPreset::Developer as i32,
                limits: Some(pb::SetupLimits {
                    cpu: 3,
                    memory_mib: 5120,
                    disk_gib: 60,
                }),
                docker: pb::ServerDockerState::On as i32,
                ..Default::default()
            }),
            host: Some(pb::SetupHostFacts {
                cpu_count: 4,
                memory_total_mib: 7987,
                pool_total_gib: 152,
                os: "Ubuntu 24.04".into(),
                arch: "x86_64".into(),
                ..Default::default()
            }),
            update: Some(pb::ServerUpdateInfo {
                current: "0.1.0".into(),
                available: "0.1.1".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let v = overview_view(&o, Some((1, 3)));
        assert_eq!(v.desktop, DesktopStatus::Running);
        assert_eq!(v.setup, "Ubuntu 24.04 · XFCE · Developer · Docker on");
        assert_eq!(
            v.limits,
            Some(Limits {
                cpu: 3,
                memory_gb: 5,
                disk_gb: 60
            })
        );
        assert_eq!(v.host_mem_gb, 5);
        assert_eq!(v.host_disk_gb, 152);
        assert_eq!(v.update_available.as_deref(), Some("0.1.1"));
        assert!(v.docker && v.attention.is_empty());
        let none = overview_view(&pb::ServerOverview::default(), None);
        assert_eq!(none.desktop, DesktopStatus::Unknown);
    }
}
