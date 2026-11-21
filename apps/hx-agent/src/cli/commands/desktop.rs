//! `desktop start | stop | restart | limits | password`.
//!
//! Calls: privd `StartDesktop`, `StopDesktop`, `RestartDesktop`, `GetDesktop` and `SetLimits`,
//! `SetUserPassword` (Admin may omit the current password, `docs/ipc.md` 6.9), and for the
//! password gatewayd `SetPasswordVerifier` (the CLI computes the verifier itself, so gatewayd
//! never sees the password: Argon2id here, `PepperEnrol` in privd).

use hx_ipc::admin::pb as apb;
use hx_ipc::privd::pb::{self, LockoutPurpose, request::Command, response::Result as R};
use serde_json::json;

use super::pin::ask_twice;
use super::{admin, privd};
use crate::cli::args::Power;
use crate::cli::error::CliError;
use crate::cli::gatewayd::unexpected as admin_unexpected;
use crate::cli::privd::{OutSecret, unexpected};
use crate::cli::verifier;
use crate::cli::{Env, Outcome};

pub(super) fn power(
    env: &mut Env<'_>,
    action: Power,
    id: &str,
    force: bool,
) -> Result<Outcome, CliError> {
    let mut p = privd(env)?;
    let desktop_id = id.to_owned();
    let (cmd, verb) = match action {
        Power::Start => (
            Command::StartDesktop(pb::StartDesktopRequest { desktop_id }),
            "started",
        ),
        Power::Stop => (
            Command::StopDesktop(pb::StopDesktopRequest { desktop_id, force }),
            "stopped",
        ),
        Power::Restart => (
            Command::RestartDesktop(pb::RestartDesktopRequest { desktop_id, force }),
            "restarted",
        ),
    };
    let r = match p.simple(cmd)? {
        R::StartDesktop(r) | R::StopDesktop(r) | R::RestartDesktop(r) => r,
        _ => return Err(unexpected("the power command")),
    };
    let text = if r.degraded {
        format!("desktop {id} {verb}; it is running but systemd reports it degraded\n")
    } else if r.running {
        format!("desktop {id} {verb}; it is running\n")
    } else {
        format!("desktop {id} {verb}; it is not running\n")
    };
    Ok(Outcome::ok(
        text,
        json!({"desktop": id, "running": r.running, "degraded": r.degraded}),
    ))
}

fn current_limits(p: &mut crate::cli::privd::PrivdConn, id: &str) -> Result<pb::Limits, CliError> {
    match p.simple(Command::GetDesktop(pb::GetDesktopRequest {
        desktop_id: id.to_owned(),
    }))? {
        R::GetDesktop(r) => Ok(r.desktop.and_then(|d| d.limits).unwrap_or_default()),
        _ => Err(unexpected("GetDesktop")),
    }
}

pub(super) fn limits(
    env: &mut Env<'_>,
    id: &str,
    cpu: Option<u32>,
    memory_mib: Option<u64>,
    disk_gib: Option<u64>,
) -> Result<Outcome, CliError> {
    let mut p = privd(env)?;
    let cur = current_limits(&mut p, id)?;
    if cpu.is_none() && memory_mib.is_none() && disk_gib.is_none() {
        return Ok(Outcome::ok(
            format!(
                "desktop {id}: {} CPU, {} MiB memory, {} GiB disk\n",
                cur.cpu, cur.memory_mib, cur.disk_gib
            ),
            json!({"desktop": id, "limits": {"cpu": cur.cpu, "memory_mib": cur.memory_mib, "disk_gib": cur.disk_gib}}),
        ));
    }
    // SetLimits wants every field: fill the ones not given from the current values.
    let want = pb::Limits {
        cpu: cpu.unwrap_or(cur.cpu),
        memory_mib: memory_mib.unwrap_or(cur.memory_mib),
        disk_gib: disk_gib.unwrap_or(cur.disk_gib),
    };
    let restart = match p.simple(Command::SetLimits(pb::SetLimitsRequest {
        desktop_id: id.to_owned(),
        limits: Some(want),
    }))? {
        R::SetLimits(r) => r.restart_required,
        _ => return Err(unexpected("SetLimits")),
    };
    let mut text = format!(
        "desktop {id}: now {} CPU, {} MiB memory, {} GiB disk\n",
        want.cpu, want.memory_mib, want.disk_gib
    );
    if restart {
        text.push_str("the CPU count changes only after a restart: hx-agent desktop restart\n");
    }
    Ok(Outcome::ok(
        text,
        json!({
            "desktop": id,
            "limits": {"cpu": want.cpu, "memory_mib": want.memory_mib, "disk_gib": want.disk_gib},
            "restart_required": restart,
        }),
    ))
}

pub(super) fn password(
    env: &mut Env<'_>,
    id: &str,
    verifier_only: bool,
) -> Result<Outcome, CliError> {
    let prompt = if verifier_only {
        "Current Linux password of the desktop user (input hidden): "
    } else {
        "New Linux password for the desktop user (input hidden): "
    };
    let pw = ask_twice(env, prompt, "Repeat the password: ", 1024)?;
    // The rules of `Secrets::with_user_password`, so a bad one is explained here.
    if pw.is_empty() || pw.contains(&0) || pw.contains(&b'\n') || pw.contains(&b'\r') {
        return Err(CliError::Usage(
            "a password is 1 to 1024 bytes with no newline or NUL".into(),
        ));
    }
    // Everything that can be checked or prepared comes BEFORE the Linux password changes:
    // gatewayd must be reachable (so the old password cannot stay valid for re-pairing because
    // the gateway was down), and the verifier is built now (`PepperEnrol` stores nothing).
    let mut a = admin(env)?;
    let mut p = privd(env)?;
    let record = verifier::enrol(
        &mut p,
        LockoutPurpose::Password,
        &pw,
        env.config.verifier_params,
    )?;
    if !verifier_only {
        if !env.json {
            let _ = env.err.write_all(
                b"changing the password now; if this is interrupted or times out it may already have changed
",
            );
        }
        match p.call(
            Command::SetUserPassword(pb::SetUserPasswordRequest {
                desktop_id: id.to_owned(),
            }),
            &[OutSecret {
                kind: pb::SecretKind::UserPassword,
                bytes: &pw,
            }],
            &mut |_| {},
        ) {
            Ok(R::SetUserPassword(_)) => {}
            Ok(_) => return Err(unexpected("SetUserPassword")),
            // The request was sent: a lost connection or a local timeout says nothing about
            // whether privd changed the password.
            Err(CliError::Unavailable(m)) => {
                return Err(CliError::Unavailable(format!(
                    "{m}; the Linux password MAY ALREADY HAVE CHANGED: if so, run hx-agent desktop password --verifier-only with the new password, otherwise run this command again"
                )));
            }
            Err(e) => return Err(e),
        }
    }
    drop(pw);
    let refreshed = match a.call(
        apb::request::Command::SetPasswordVerifier(apb::SetPasswordVerifierRequest {
            verifier: record.into(),
        }),
        None,
    ) {
        Ok(apb::response::Result::SetPasswordVerifier(_)) => Ok(()),
        Ok(_) => Err(admin_unexpected("SetPasswordVerifier")),
        Err(e) => Err(e),
    };
    match refreshed {
        Ok(()) => Ok(Outcome::ok(
            if verifier_only {
                "the gateway's password verifier is refreshed\n".to_owned()
            } else {
                format!(
                    "the Linux password of desktop {id} is changed and the gateway's verifier is refreshed\n"
                )
            },
            json!({"desktop": id, "password_changed": !verifier_only, "verifier_refreshed": true}),
        )),
        Err(e) => Err(CliError::Failed(format!(
            "{}the gateway's password verifier was NOT refreshed ({}); the gateway still accepts the OLD password for re-pairing until you run: hx-agent desktop password --verifier-only",
            if verifier_only {
                ""
            } else {
                "the Linux password is changed, but "
            },
            e.message()
        ))),
    }
}
