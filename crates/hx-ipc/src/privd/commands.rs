//! Per-command facts from `docs/ipc.md` sections 5.1, 6 and 8: class, deadline, which arguments
//! only `Admin` may set, and the syntax rules of the shared argument types.

use super::pb::request::Command;

/// Command class of `docs/ipc.md` section 5.1. Whether a class is allowed also depends on the
/// caller's role and privd's phase; that decision is privd's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandClass {
    /// Read-only: both roles, always.
    R,
    /// Routine desktop operation: Gateway when `READY` or `SETUP_OPEN`; Admin always.
    A,
    /// Setup: Gateway only while `SETUP_OPEN` and with the restricted argument set; Admin always.
    S,
    /// Privileged: Admin only.
    X,
}

/// Static facts about one command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandInfo {
    /// The command's name as used in logs, rate-limit keys and the audit log.
    pub name: &'static str,
    /// Its class (section 5.1).
    pub class: CommandClass,
    /// True for commands that are named but not implemented in Phase 1: privd answers
    /// `UNIMPLEMENTED` (sections 6.5, 6.9, 6.13, 6.14).
    pub reserved: bool,
    /// The command's maximum deadline in milliseconds: the value of section 8 where it gives
    /// one, otherwise the value chosen in this table (also listed in section 8). `None` only
    /// for reserved commands, which answer `UNIMPLEMENTED` at once and use
    /// [`DEFAULT_DEADLINE_MS`].
    pub max_deadline_ms: Option<u32>,
}

impl CommandInfo {
    /// The deadline to enforce, never unbounded (privd has one request in flight per
    /// connection, so a command without a deadline could hold the slot forever): the request's
    /// `deadline_ms` may only shorten the command's maximum, and 0 means the maximum. A command
    /// without a maximum uses [`DEFAULT_DEADLINE_MS`] as its maximum.
    pub fn effective_deadline_ms(&self, requested: u32) -> u32 {
        let max = self.max_deadline_ms.unwrap_or(DEFAULT_DEADLINE_MS);
        if requested == 0 {
            max
        } else {
            requested.min(max)
        }
    }
}

const fn info(
    name: &'static str,
    class: CommandClass,
    reserved: bool,
    max_deadline_ms: Option<u32>,
) -> CommandInfo {
    CommandInfo {
        name,
        class,
        reserved,
        max_deadline_ms,
    }
}

/// Maximum deadline of a command that has no specific one (the reserved commands): 60 s.
pub const DEFAULT_DEADLINE_MS: u32 = 60_000;

const S10: Option<u32> = Some(10_000);
const S30: Option<u32> = Some(30_000);
const S60: Option<u32> = Some(60_000);
const M2: Option<u32> = Some(120_000);
const M5: Option<u32> = Some(300_000);

/// Class, name and deadline of a command.
pub fn command_info(cmd: &Command) -> CommandInfo {
    use CommandClass::{A, R, S, X};
    match cmd {
        Command::GetHostInfo(_) => info("GetHostInfo", R, false, S10),
        Command::GetRecipientKey(_) => info("GetRecipientKey", R, false, S10),
        Command::BeginSetup(_) => info("BeginSetup", X, false, S30),
        Command::ExtendSetup(_) => info("ExtendSetup", X, false, S30),
        Command::FinishSetup(_) => info("FinishSetup", A, false, S30),
        Command::SetupHost(_) => info("SetupHost", S, false, M5),
        Command::CreateDesktop(_) => info("CreateDesktop", S, false, Some(45 * 60_000)),
        Command::GetDesktop(_) => info("GetDesktop", R, false, S10),
        Command::ListDesktops(_) => info("ListDesktops", R, false, S10),
        Command::StartDesktop(_) => info("StartDesktop", A, false, M2),
        Command::StopDesktop(_) => info("StopDesktop", A, false, M2),
        Command::RestartDesktop(_) => info("RestartDesktop", A, false, M2),
        Command::SetLimits(_) => info("SetLimits", A, false, S30),
        Command::SetUserPassword(_) => info("SetUserPassword", A, false, S60),
        Command::EnableDocker(_) => info("EnableDocker", S, false, Some(15 * 60_000)),
        Command::DisableDocker(_) => info("DisableDocker", A, false, M2),
        Command::CreateSnapshot(_) => info("CreateSnapshot", A, false, S60),
        Command::ListSnapshots(_) => info("ListSnapshots", R, false, S60),
        Command::DeleteSnapshot(_) => info("DeleteSnapshot", A, false, S60),
        Command::ProvisionSessionLink(_) => info("ProvisionSessionLink", A, false, S60),
        Command::InstallSession(_) => info("InstallSession", A, false, M5),
        Command::RestartSession(_) => info("RestartSession", A, false, S60),
        Command::CheckUpdate(_) => info("CheckUpdate", A, false, S60),
        Command::ApplyUpdate(_) => info("ApplyUpdate", A, false, Some(10 * 60_000)),
        Command::RollbackUpdate(_) => info("RollbackUpdate", X, false, M2),
        Command::DestroyDesktop(_) => info("DestroyDesktop", X, false, M5),
        Command::Uninstall(_) => info("Uninstall", X, false, Some(10 * 60_000)),
        Command::ResetLockout(_) => info("ResetLockout", X, false, S30),
        Command::EnrolOwnerKey(_) => info("EnrolOwnerKey", X, false, S30),
        Command::UpgradeIncus(_) => info("UpgradeIncus", X, true, None),
        Command::PepperVerify(_) => info("PepperVerify", A, false, S30),
        Command::PepperEnrol(_) => info("PepperEnrol", A, false, S30),
        Command::RecordEvent(_) => info("RecordEvent", A, false, S10),
        Command::BeginSecretUpload(_) => info("BeginSecretUpload", A, true, None),
        Command::BackupRun(_) => info("BackupRun", A, true, None),
        Command::BackupCancel(_) => info("BackupCancel", A, true, None),
        Command::BackupStatus(_) => info("BackupStatus", R, true, None),
        Command::ListBackups(_) => info("ListBackups", R, true, None),
        Command::SetBackupSchedule(_) => info("SetBackupSchedule", A, true, None),
        Command::SetBackupCredentials(_) => info("SetBackupCredentials", A, true, None),
        Command::VerifyBackup(_) => info("VerifyBackup", A, true, None),
        Command::PruneBackups(_) => info("PruneBackups", A, true, None),
        Command::RestoreStart(_) => info("RestoreStart", A, true, None),
        Command::RestoreStatus(_) => info("RestoreStatus", R, true, None),
        Command::RestoreConfirm(_) => info("RestoreConfirm", A, true, None),
        Command::GenerateRecoveryKey(_) => info("GenerateRecoveryKey", A, true, None),
    }
}

/// The one place for the **`PERMISSION_DENIED` rules of the Gateway role** that depend only on the
/// request and privd's phase. Returns the reason (a field or rule name, never a value) if a
/// `Gateway` caller must be refused, `None` if this layer has no objection. `Admin` is never
/// refused here; do not call it for `Admin`.
///
/// Rules implemented:
/// * class `X` commands are never allowed to Gateway (section 5.1);
/// * Admin-only arguments, by presence ([`admin_only_argument`]);
/// * `DeleteSnapshot`: Gateway may delete `manual` snapshots only (section 6.10);
/// * `SetUserPassword`: the `CURRENT_PASSWORD` slot (a second slot) is required unless the phase
///   is `SETUP_OPEN` (section 6.9). Whether it is *correct* is checked by privd against the
///   shadow hash and answers `PERMISSION_DENIED` too.
///
/// Rules that **stay in privd itself** because they need privd's state, other error codes or
/// the second stage of a request:
/// * phase gates of classes `A` and `S` (`SetupHost` and `CreateDesktop` outside `SETUP_OPEN`,
///   routine commands while `UNINITIALIZED`) are `FAILED_PRECONDITION`, not a permission error
///   (section 7 rule 6);
/// * `EnableDocker` is open to Gateway only while `SETUP_OPEN` and `PERMISSION_DENIED` after
///   (section 5.1, section 7 rule 5): decided by privd from its phase, then by the
///   acknowledgement flag;
/// * `StartDesktop` for Gateway while `needs_attention` holds `ISOLATION_NOT_RESTORED`
///   (section 7 rule 11);
/// * the `PepperEnrol` caps (5 per day after setup, 60 per hour in `SETUP_OPEN`, section 6.15),
///   all rate limits, the connection and lock limits, and the failure caps of section 5.3;
/// * a non-empty `CreateDesktop.settings` is `UNIMPLEMENTED` (section 6.5) and the reserved
///   commands (`CommandInfo::reserved`) are `UNIMPLEMENTED`;
/// * secret frames: privd must check that each kind-2 frame's `request_id` equals the pending
///   request's and its `slot` is a declared, not yet filled slot, that it arrives within 5 s of
///   the `Request` ([`super::BODY_TIMEOUT`]), and call [`super::check_secret_against_slot`];
///   anything missing, extra or late rejects the request (section 5.2);
/// * uniqueness of `request_id` on the connection, one request in flight (section 4).
pub fn gateway_denied(req: &super::pb::Request, phase: super::pb::Phase) -> Option<&'static str> {
    let cmd = req.command.as_ref()?;
    if command_info(cmd).class == CommandClass::X {
        return Some("command class X is Admin only");
    }
    if let Some(field) = admin_only_argument(cmd) {
        return Some(field);
    }
    match cmd {
        Command::DeleteSnapshot(r) if snapshot_kind_of(&r.name) != Some("manual") => {
            Some("delete_snapshot.name: Gateway may delete manual snapshots only")
        }
        Command::SetUserPassword(_)
            if req.secret_slots.len() < 2 && phase != super::pb::Phase::SetupOpen =>
        {
            Some("set_user_password: current password required outside the setup window")
        }
        _ => None,
    }
}

/// The first argument of `cmd` that only `Admin` may set and that is present (proto3 `optional`
/// presence, so a field set to its default value still counts), or `None`.
///
/// A `Gateway` request for which this returns `Some` is `PERMISSION_DENIED` (section 4).
/// `EnableDocker` is open to Gateway only while the setup window is open; that is a phase
/// rule, not an argument rule, and stays with privd.
pub fn admin_only_argument(cmd: &Command) -> Option<&'static str> {
    match cmd {
        Command::FinishSetup(r) if r.force.is_some() => Some("finish_setup.force"),
        Command::SetupHost(r) => {
            if r.pool_device.is_some() {
                Some("setup_host.pool_device")
            } else if r.allow_private_networks.is_some() {
                Some("setup_host.allow_private_networks")
            } else if r.extra_host_addresses.is_some() {
                Some("setup_host.extra_host_addresses")
            } else if r.ipv4.is_some() {
                Some("setup_host.ipv4")
            } else {
                None
            }
        }
        Command::CreateDesktop(r) if r.image_file.is_some() => Some("create_desktop.image_file"),
        _ => None,
    }
}

// ----- syntax of the shared argument types (section 6, "Shared types") -----

/// `DesktopId`: `^[a-z][a-z0-9]{0,11}$`.
pub fn is_valid_desktop_id(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 12
        && b[0].is_ascii_lowercase()
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

/// The syntax of `hx_provision::Username` (1 to 32 characters of `^[a-z_][a-z0-9_-]{0,31}$`).
/// Reserved names are refused by `hx-provision` itself.
pub fn is_valid_username_syntax(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// Snapshot name: `^hx-(manual|preupdate|backup)-[0-9TZ-]+-[0-9a-f]{4}$`.
pub fn is_valid_snapshot_name(s: &str) -> bool {
    snapshot_kind_of(s).is_some()
}

/// The kind segment (`manual`, `preupdate` or `backup`) of a valid snapshot name.
pub fn snapshot_kind_of(s: &str) -> Option<&'static str> {
    let rest = s.strip_prefix("hx-")?;
    let (kind, rest) = ["manual", "preupdate", "backup"]
        .into_iter()
        .find_map(|k| rest.strip_prefix(k)?.strip_prefix('-').map(|r| (k, r)))?;
    let (middle, tail) = rest.split_at_checked(rest.len().checked_sub(5)?)?;
    let tail = tail.strip_prefix('-')?;
    let ok = !middle.is_empty()
        && middle
            .bytes()
            .all(|c| c.is_ascii_digit() || c == b'T' || c == b'Z' || c == b'-')
        && tail.len() == 4
        && tail
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c));
    ok.then_some(kind)
}

/// Release version: `^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(-(alpha|beta|rc)\.[0-9]{1,4})?$`
/// (section 6.12, rule 1). Checked before the string is used in any path, command or log.
pub fn is_valid_update_version(s: &str) -> bool {
    fn num(p: &str) -> bool {
        (1..=4).contains(&p.len()) && p.bytes().all(|c| c.is_ascii_digit())
    }
    let (core, pre) = match s.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (s, None),
    };
    let mut parts = core.split('.');
    let core_ok = matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(a), Some(b), Some(c), None) if num(a) && num(b) && num(c)
    );
    let pre_ok = match pre {
        None => true,
        Some(p) => match p.split_once('.') {
            Some((tag, n)) => matches!(tag, "alpha" | "beta" | "rc") && num(n),
            None => false,
        },
    };
    core_ok && pre_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_ids() {
        for ok in ["main", "a", "a0123456789b"] {
            assert!(is_valid_desktop_id(ok), "{ok}");
        }
        for bad in ["", "Main", "1a", "a-b", "a01234567890b", "ma in", "é"] {
            assert!(!is_valid_desktop_id(bad), "{bad}");
        }
    }

    #[test]
    fn usernames() {
        assert!(is_valid_username_syntax("alice"));
        assert!(is_valid_username_syntax("_a-b_9"));
        assert!(!is_valid_username_syntax(""));
        assert!(!is_valid_username_syntax("Alice"));
        assert!(!is_valid_username_syntax("-a"));
        assert!(!is_valid_username_syntax(&"a".repeat(33)));
    }

    #[test]
    fn snapshot_names() {
        assert!(is_valid_snapshot_name("hx-manual-20261120T101500Z-a1b2"));
        assert!(is_valid_snapshot_name(
            "hx-preupdate-2026-11-20T10-15-00Z-00ff"
        ));
        assert!(is_valid_snapshot_name("hx-backup-1-dead"));
        assert_eq!(snapshot_kind_of("hx-backup-1-dead"), Some("backup"));
        for bad in [
            "",
            "manual-1-dead",
            "hx-other-1-dead",
            "hx-manual--dead",
            "hx-manual-1-DEAD",
            "hx-manual-1-dea",
            "hx-manual-1-deadb",
            "hx-manual-x-dead",
            "hx-manual-1-dead\n",
            "hx-manual-../x-dead",
        ] {
            assert!(!is_valid_snapshot_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn versions() {
        for ok in [
            "0.1.0",
            "1.2.3",
            "9999.9999.9999",
            "1.0.0-rc.1",
            "1.0.0-alpha.12",
        ] {
            assert!(is_valid_update_version(ok), "{ok}");
        }
        for bad in [
            "",
            "1.2",
            "1.2.3.4",
            "10000.0.0",
            "1.0.0-",
            "1.0.0-rc",
            "1.0.0-gamma.1",
            "1.0.0-rc.12345",
            "../1.0.0",
            "1.0.0\n",
            "v1.0.0",
            "1.0.0-rc.1-x",
        ] {
            assert!(!is_valid_update_version(bad), "{bad:?}");
        }
    }

    #[test]
    fn deadlines_only_shorten() {
        let i = info("x", CommandClass::R, false, Some(10_000));
        assert_eq!(i.effective_deadline_ms(0), 10_000);
        assert_eq!(i.effective_deadline_ms(500), 500);
        assert_eq!(i.effective_deadline_ms(60_000), 10_000);
        let none = info("x", CommandClass::R, true, None);
        assert_eq!(none.effective_deadline_ms(0), DEFAULT_DEADLINE_MS);
        assert_eq!(none.effective_deadline_ms(1_000_000), DEFAULT_DEADLINE_MS);
    }
}
