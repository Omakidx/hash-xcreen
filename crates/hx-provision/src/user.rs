//! The desktop user's Linux login name.
//!
//! The setup wizard lets the user choose the name (`--user`), so it is *user input*. It is
//! validated once, here, into a [`Username`], and only that type is ever substituted into a
//! recipe: `[vars]` cannot define `user` or `uid`, and nothing else derived from user input goes
//! through `{{var}}` substitution into shell text. The accepted alphabet (`a-z`, `0-9`, `_`, `-`)
//! contains no shell, systemd or path metacharacters.

use std::fmt;

/// The user a recipe creates when the caller does not choose one.
pub const DEFAULT_USERNAME: &str = "desk";

/// Names that must never be used for the desktop account: system accounts and groups that exist
/// in Ubuntu and Debian base images, the default cloud users, and privileged group names. The
/// ensure-user step additionally refuses any existing account or group below id 1000, which
/// catches names this static list does not know about.
const RESERVED: &[&str] = &[
    "root",
    "daemon",
    "bin",
    "sys",
    "sync",
    "games",
    "man",
    "lp",
    "mail",
    "news",
    "uucp",
    "proxy",
    "www-data",
    "backup",
    "list",
    "irc",
    "gnats",
    "nobody",
    "nogroup",
    "ubuntu",
    "debian",
    "docker",
    "sudo",
    "admin",
    "adm",
    "wheel",
    "users",
    "staff",
    "shadow",
    "disk",
    "kmem",
    "tty",
    "dialout",
    "cdrom",
    "floppy",
    "tape",
    "audio",
    "video",
    "plugdev",
    "netdev",
    "input",
    "render",
    "kvm",
    "lxd",
    "incus",
    "incus-admin",
    "sshd",
    "messagebus",
    "polkitd",
    "_apt",
    "systemd",
    "utmp",
    "operator",
    "src",
    "fax",
    "voice",
    "ssl-cert",
    "crontab",
    "mlocate",
    "uuidd",
    "tcpdump",
    "landscape",
    "fwupd-refresh",
    "pollinate",
    "syslog",
    "tss",
    "lpadmin",
    "scanner",
    "colord",
    "avahi",
    "hx",
    "hxd",
];

/// Why a username was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UsernameError {
    /// Does not match `^[a-z_][a-z0-9_-]{0,31}$`.
    #[error(
        "a username is 1-32 characters: a lower-case letter or `_`, then lower-case letters, digits, `_` or `-`"
    )]
    Invalid,
    /// A name the system or the base image uses.
    #[error("`{0}` is a reserved name (system account, group or image default)")]
    Reserved(String),
}

/// A validated Linux login name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Username(String);

impl Username {
    /// Validate `name`.
    pub fn new(name: &str) -> Result<Self, UsernameError> {
        let mut chars = name.chars();
        let ok = matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c == '_')
            && name.len() <= 32
            && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
        if !ok {
            return Err(UsernameError::Invalid);
        }
        if RESERVED.contains(&name) || name.starts_with("systemd-") {
            return Err(UsernameError::Reserved(name.to_string()));
        }
        Ok(Self(name.to_string()))
    }

    /// The default user (`desk`).
    pub fn default_user() -> Self {
        Self(DEFAULT_USERNAME.to_string())
    }

    /// The name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Username {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for Username {
    type Err = UsernameError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}
