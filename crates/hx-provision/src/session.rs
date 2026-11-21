//! Where the in-container session pieces live (ipc.md 6.9, 6.11 and 11).
//!
//! These constants are the one place the paths are defined for Rust code. The recipe
//! (`recipes/fragments/xfce-desktop.toml`) spells the same paths out in unit files; a test keeps
//! the two in step.
//!
//! The `hx-session` package (ipc.md 6.11, `InstallSession`: pushed to `/var/lib/hx/session/` and
//! installed with `dpkg -i`) must therefore install exactly these files:
//!
//! | File | Mode | Purpose |
//! |---|---|---|
//! | [`SESSION_BINARY`] | root:root 0755 | the streaming daemon, started by `hx-session.service` |
//! | [`PASSWORD_CHECK_HELPER`] | root:root 0755 | the fixed-argv current-password checker |

/// The `hx-session` streaming daemon, as installed by the package. Debian packaging convention
/// for a private executable (`/usr/lib/<package>/`). `hx-session.service` has this as `ExecStart=`
/// and the package install does not need to touch any unit file.
pub const SESSION_BINARY: &str = "/usr/lib/hx-session/hx-session";

/// The current-password checker shipped in the same package (ipc.md 6.9, decision 2).
///
/// **Contract (what the helper must do; the binary itself is not part of this crate):**
///
/// - argv is exactly `[PASSWORD_CHECK_HELPER, <login name>]`, nothing else. The login name has
///   already been validated as a [`Username`](crate::Username).
/// - The candidate password is the whole of standard input, without a trailing newline (the
///   caller redirects a 0600 file in the 0700 work directory into it and deletes it afterwards).
///   Environment: only what `exec_captured` sets, no secret.
/// - It compares against the user's hash in `/etc/shadow` (yescrypt, sha512 and the other
///   `crypt(3)` schemes the distro uses) and exits **0 only when the password matches**, **1 when
///   it does not match**, and any other status (2 usage error, 3 no such user, locked account or
///   no usable hash, ...) for "could not check".
/// - Callers use only the exit status. Its stdout and stderr are discarded unread: a helper
///   cannot talk the caller into anything by what it prints.
pub const PASSWORD_CHECK_HELPER: &str = "/usr/lib/hx-session/hx-pwcheck";

/// Exit status of [`PASSWORD_CHECK_HELPER`] that means "the password matches".
pub const PWCHECK_MATCH: i32 = 0;
/// Exit status of [`PASSWORD_CHECK_HELPER`] that means "the password does not match".
pub const PWCHECK_MISMATCH: i32 = 1;

/// The root-owned directory (root:root 0755, made by `systemd-tmpfiles` at boot) that holds the
/// session socket inside the container.
pub const SESSION_SOCKET_DIR: &str = "/run/hx-session";
/// The socket `hx-session.socket` creates (owned by the desktop user, mode 0600).
pub const SESSION_SOCKET: &str = "/run/hx-session/link.sock";
/// The system socket unit.
pub const SESSION_SOCKET_UNIT: &str = "hx-session.socket";
/// The system service unit that runs [`SESSION_BINARY`] as the desktop user.
pub const SESSION_SERVICE_UNIT: &str = "hx-session.service";
/// The user unit that runs `xfce4-session` (was `hx-session.service` before ipc.md 6.11).
pub const XSESSION_UNIT: &str = "hx-xsession.service";
