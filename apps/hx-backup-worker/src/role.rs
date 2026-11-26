//! Role dispatch and the exit codes of `hx-backup-worker` (ipc.md §24).
//!
//! The role is chosen by the environment variable `HX_BACKUP_ROLE` alone, fixed by whoever starts
//! the process (privd's helper has none; the root-owned `hx-drive.service` sets `drive`), following
//! the precedent of the fetcher's `HX_FETCH_TEMPLATE`. Nothing else selects it: there are no
//! arguments, and anything unexpected fails closed.

use std::ffi::{OsStr, OsString};

/// The session ended in order: one `JobResult` and `Bye`.
pub const EXIT_OK: i32 = 0;
/// The role fails closed (unknown role, or arguments).
pub const EXIT_ROLE: i32 = 64;
/// The Drive role is not built yet.
pub const EXIT_DRIVE_NOT_IMPLEMENTED: i32 = 65;
/// The sandbox could not be set up.
pub const EXIT_SANDBOX: i32 = 70;
/// No listener, or no connection within 60 s.
pub const EXIT_LISTEN: i32 = 71;
/// Protocol violation.
pub const EXIT_PROTOCOL: i32 = 72;
/// The link was lost, or privd was silent for 60 s.
pub const EXIT_LINK_LOST: i32 = 73;
/// Internal failure outside the job runner.
pub const EXIT_INTERNAL: i32 = 74;
/// Terminated by `SIGTERM` (128 + 15).
pub const EXIT_SIGTERM: i32 = 143;

/// What this process is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The backup worker.
    Worker,
    /// The Drive helper.
    Drive,
}

/// Why no role was chosen.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RoleError {
    /// `HX_BACKUP_ROLE` is set to something else than `worker` or `drive`.
    #[error("unknown role (HX_BACKUP_ROLE must be unset, `worker` or `drive`)")]
    UnknownRole,
    /// The process takes no arguments.
    #[error("takes no arguments")]
    Arguments,
}

/// Picks the role. `args` are the arguments after `argv[0]`; `env_role` is `HX_BACKUP_ROLE`.
///
/// # Errors
/// [`RoleError`] for arguments or a value other than `worker` and `drive`: the caller exits with
/// [`EXIT_ROLE`] and starts nothing.
pub fn select(args: &[OsString], env_role: Option<&OsStr>) -> Result<Role, RoleError> {
    if !args.is_empty() {
        return Err(RoleError::Arguments);
    }
    match env_role {
        None => Ok(Role::Worker),
        Some(v) if v == "worker" => Ok(Role::Worker),
        Some(v) if v == "drive" => Ok(Role::Drive),
        Some(_) => Err(RoleError::UnknownRole),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_role_is_chosen_by_the_variable_alone_and_everything_else_fails_closed() {
        assert_eq!(select(&[], None), Ok(Role::Worker));
        assert_eq!(select(&[], Some(OsStr::new("worker"))), Ok(Role::Worker));
        assert_eq!(select(&[], Some(OsStr::new("drive"))), Ok(Role::Drive));
        for bad in ["", "Drive", "drive ", "root", "worker,drive", "../drive"] {
            assert_eq!(
                select(&[], Some(OsStr::new(bad))),
                Err(RoleError::UnknownRole),
                "{bad:?}"
            );
        }
        assert_eq!(
            select(&[OsString::from("--version")], None),
            Err(RoleError::Arguments)
        );
        assert_eq!(
            select(&[OsString::from("drive")], Some(OsStr::new("drive"))),
            Err(RoleError::Arguments)
        );
    }
}
