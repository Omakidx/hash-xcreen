//! The commands of ipc.md section 6, one module per group. Each function takes the daemon, the
//! request context and the typed request, and returns the typed result or a [`CmdError`].
//!
//! Arguments are parsed into typed values at the top of each command and only those are used
//! afterwards. Instance names, paths, devices and every Incus parameter are derived here from
//! constants and privd's own state, never from the request (ipc.md 7 rules 1 to 4).

pub mod admin;
pub mod blockdev;
pub mod common;
pub mod create;
pub mod desktop;
pub mod docker;
pub mod hostsetup;
pub mod info;
pub mod limits;
pub mod password;
pub mod pepper_cmds;
pub mod power;
pub mod session;
pub mod setup;
pub mod snapshot;
