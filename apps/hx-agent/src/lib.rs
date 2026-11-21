//! Server agent library: the code behind the `hx-privd`, `hx-gatewayd`,
//! `hx-agent` and `hx-backup-worker` binaries.
//!
//! - [`privd`]: the root daemon and its fixed command set ([ipc.md](../../docs/ipc.md) Part 1).
//! - [`gateway`]: the internet-facing, unprivileged gateway.
//! - [`link`]: the gateway side of the session link to `hx-session` (ipc.md Part 2).

#![forbid(unsafe_code)]

pub mod gateway;
pub mod link;
pub mod privd;
