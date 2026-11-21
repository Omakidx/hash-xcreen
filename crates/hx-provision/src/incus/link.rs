//! The session-link proxy device (ipc.md 6.11 and 11).

use std::collections::BTreeMap;

use super::error::IncusError;

/// Name of the one device `hx-privd` ever adds to a desktop.
pub const SESSION_LINK_DEVICE: &str = "hx-link";
/// Host directory that holds the listening sockets of the proxy devices (`root:hx-gatewayd 0750`,
/// created and owned by `hx-privd`, not by this crate).
pub const SESSION_LINK_HOST_DIR: &str = "/run/hx/link";
/// The socket `hx-session.socket` creates inside the container (root-owned directory).
pub const SESSION_LINK_CONNECT: &str = "/run/hx-session/link.sock";
/// Permission bits of the host-side listening socket.
pub const SESSION_LINK_MODE: &str = "0600";

/// The proxy device that exposes `hx-session` to `hx-gatewayd` (ipc.md 6.11).
///
/// Everything is fixed except who owns what: the property set is computed here, so a caller cannot
/// ask for another device name, another connect path, a TCP listener, `bind=instance`, or a
/// connect side that runs as root. `security.uid` and `security.gid` are always set, to the
/// desktop user's ids, and there is no way to leave them out (ipc.md 11: no fallback to a
/// root-identity connect).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLink {
    desktop_id: String,
    gateway_uid: u32,
    gateway_gid: u32,
    desktop_uid: u32,
    desktop_gid: u32,
}

impl SessionLink {
    /// `desktop_id` must match `^[a-z][a-z0-9]{0,11}$` (ipc.md 6, `DesktopId`). `gateway` is the
    /// uid and gid that own the host-side socket (`hx-gatewayd`), `desktop` the uid and gid of the
    /// desktop user inside the container (the recipe's 1000). Root (0) and `u32::MAX` are refused
    /// for all four ids.
    pub fn new(
        desktop_id: &str,
        gateway: (u32, u32),
        desktop: (u32, u32),
    ) -> Result<Self, IncusError> {
        let mut c = desktop_id.chars();
        let ok = matches!(c.next(), Some(f) if f.is_ascii_lowercase())
            && desktop_id.len() <= 12
            && c.all(|x| x.is_ascii_lowercase() || x.is_ascii_digit());
        if !ok {
            return Err(IncusError::InvalidArgument(format!(
                "session link: desktop id `{desktop_id}` does not match ^[a-z][a-z0-9]{{0,11}}$"
            )));
        }
        for (what, id) in [
            ("gateway uid", gateway.0),
            ("gateway gid", gateway.1),
            ("desktop uid", desktop.0),
            ("desktop gid", desktop.1),
        ] {
            if id == 0 || id == u32::MAX {
                return Err(IncusError::InvalidArgument(format!(
                    "session link: {what} must not be 0 or {}",
                    u32::MAX
                )));
            }
        }
        Ok(Self {
            desktop_id: desktop_id.to_string(),
            gateway_uid: gateway.0,
            gateway_gid: gateway.1,
            desktop_uid: desktop.0,
            desktop_gid: desktop.1,
        })
    }

    /// The host-side socket path, `/run/hx/link/<desktop_id>.sock`.
    pub fn socket_path(&self) -> String {
        format!("{SESSION_LINK_HOST_DIR}/{}.sock", self.desktop_id)
    }

    /// The device's options, exactly as ipc.md 6.11 lists them.
    pub fn device(&self) -> BTreeMap<String, String> {
        [
            ("type", "proxy".to_string()),
            ("bind", "host".to_string()),
            ("listen", format!("unix:{}", self.socket_path())),
            ("connect", format!("unix:{SESSION_LINK_CONNECT}")),
            ("uid", self.gateway_uid.to_string()),
            ("gid", self.gateway_gid.to_string()),
            ("mode", SESSION_LINK_MODE.to_string()),
            ("security.uid", self.desktop_uid.to_string()),
            ("security.gid", self.desktop_gid.to_string()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect()
    }
}

/// What [`Client::add_session_link`](super::Client::add_session_link) did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkOutcome {
    /// The device did not exist and was added.
    Added,
    /// The device existed with exactly these options; nothing was changed.
    Unchanged,
    /// The device existed (as a proxy device) with other options and was replaced.
    Replaced,
}
