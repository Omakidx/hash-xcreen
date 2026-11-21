//! One module per command group, and the helpers they share.

use std::io::Write;

use super::args::Cmd;
use super::error::CliError;
use super::gatewayd::AdminConn;
use super::privd::{PrivdConn, ProgressLine};
use super::text::scrub_output;
use super::{Env, Outcome};

mod desktop;
mod devices;
mod docker;
mod logs;
mod pairing;
mod pin;
mod setup;
mod snapshots;
mod status;
mod uninstall;
mod update;

/// The name of a protobuf enum value without its prefix, as in the wire schema
/// (`PHASE_READY` becomes `READY`).
macro_rules! enum_name {
    ($ty:ty, $v:expr, $prefix:literal) => {
        <$ty>::try_from($v)
            .map(|e| e.as_str_name().strip_prefix($prefix).unwrap_or("UNKNOWN"))
            .unwrap_or("UNKNOWN")
    };
}
pub(crate) use enum_name;

/// Connects to privd as `Admin`.
pub(crate) fn privd(env: &Env<'_>) -> Result<PrivdConn, CliError> {
    PrivdConn::connect(&env.config.privd_socket)
}

/// Connects to the gatewayd admin socket.
pub(crate) fn admin(env: &Env<'_>) -> Result<AdminConn, CliError> {
    AdminConn::connect(&env.config.admin_socket)
}

/// Asks the operator to type `word` before something wide-reaching happens. `yes` (the
/// command's `--yes`) answers for them. The warning goes to stderr, the question to the
/// terminal; nothing is read from stdin.
pub(crate) fn confirm(
    env: &mut Env<'_>,
    warning: &str,
    word: &str,
    yes: bool,
) -> Result<(), CliError> {
    if yes {
        return Ok(());
    }
    let _ = env.err.write_all(scrub_output(warning).as_bytes());
    let _ = env.err.write_all(b"\n");
    let answer = env.prompt.line(&format!("Type '{word}' to continue: "))?;
    if answer == word {
        Ok(())
    } else {
        Err(CliError::Declined(
            "not confirmed; nothing was changed".into(),
        ))
    }
}

/// A progress callback that prints one line per report to stderr (nothing in `--json` mode,
/// where stdout carries the result and stderr stays quiet).
pub(crate) fn progress_printer<'a>(
    json: bool,
    err: &'a mut dyn Write,
) -> impl FnMut(&ProgressLine) + 'a {
    move |p: &ProgressLine| {
        if json {
            return;
        }
        let pct = p.percent.map(|x| format!(" {x}%")).unwrap_or_default();
        let line = format!(
            "  [{}] {}/{}{} {}\n",
            p.stage.to_lowercase(),
            p.index,
            p.total,
            pct,
            p.step
        );
        let _ = err.write_all(scrub_output(&line).as_bytes());
    }
}

pub(crate) fn dispatch(env: &mut Env<'_>, cmd: Cmd) -> Result<Option<Outcome>, CliError> {
    let some = |r: Result<Outcome, CliError>| r.map(Some);
    match cmd {
        Cmd::Help(_) | Cmd::Version => Ok(None),
        Cmd::Status => some(status::run(env)),
        Cmd::DevicesList => some(devices::list(env)),
        Cmd::DevicesRevoke { prefix } => some(devices::revoke(env, &prefix)),
        Cmd::DevicesReinstate { prefix, yes } => some(devices::reinstate(env, &prefix, yes)),
        Cmd::PairingCode { ttl_s } => some(pairing::code(env, ttl_s)),
        Cmd::PairingToken { source, ttl_s } => some(pairing::token(env, source, ttl_s)),
        Cmd::PinSet { device } => some(pin::set(env, device.as_deref())),
        Cmd::PinResetLockout { purpose, yes } => some(pin::reset_lockout(env, purpose, yes)),
        Cmd::SetupBegin { secs } => some(setup::begin(env, secs)),
        Cmd::SetupExtend { secs } => some(setup::extend(env, secs)),
        Cmd::SetupFinish { force } => some(setup::finish(env, force)),
        Cmd::DesktopPower { action, id, force } => some(desktop::power(env, action, &id, force)),
        Cmd::DesktopLimits {
            id,
            cpu,
            memory_mib,
            disk_gib,
        } => some(desktop::limits(env, &id, cpu, memory_mib, disk_gib)),
        Cmd::DesktopPassword { id, verifier_only } => {
            some(desktop::password(env, &id, verifier_only))
        }
        Cmd::DockerEnable { id, yes } => some(docker::enable(env, &id, yes)),
        Cmd::DockerDisable { id } => some(docker::disable(env, &id)),
        Cmd::SnapshotsList { id } => some(snapshots::list(env, &id)),
        Cmd::SnapshotsCreate { id } => some(snapshots::create(env, &id)),
        Cmd::SnapshotsDelete { id, name } => some(snapshots::delete(env, &id, &name)),
        Cmd::Logs {
            follow,
            lines,
            journal,
            audit,
        } => logs::run(env, follow, lines, journal, audit),
        Cmd::UpdateCheck => some(update::check(env)),
        Cmd::UpdateApply { version, yes } => some(update::apply(env, version, yes)),
        Cmd::UpdateRollback { yes } => some(update::rollback(env, yes)),
        Cmd::Uninstall { keep_desktop, yes } => some(uninstall::run(env, keep_desktop, yes)),
    }
}
