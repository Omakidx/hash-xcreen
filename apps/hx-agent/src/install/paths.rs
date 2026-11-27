//! Where the installer reads and writes, as one table.
//!
//! Every system path is a constant here. [`Paths`] joins them onto a root: `/` in production, a
//! temporary directory in tests (and for a non-production `Config`, so that no test can ever reach
//! the real host). No flag or environment variable moves any of them.

use std::path::{Path, PathBuf};

/// The install state (C7).
pub const STATE_FILE: &str = "/var/lib/hx/install-state.json";
/// The lock shared by install and uninstall (C1, C4).
pub const LOCK_FILE: &str = "/run/hx-install.lock";
/// The installer log (never holds a secret).
pub const LOG_FILE: &str = "/var/log/hx-install.log";
/// The uninstall resume file (outside `/var/lib/hx`, which U5 removes).
pub const UNINSTALL_STATE: &str = "/var/lib/hx-uninstall.json";
/// privd's own uninstall marker (C9).
pub const PRIVD_UNINSTALL_STATE: &str = "/var/lib/hx/uninstall-state";
/// Releases.
pub const USR_LIB_HX: &str = "/usr/lib/hx";
/// The rescue helper directory (outside `/usr/lib/hx`, so prune never touches it).
pub const RESCUE_DIR: &str = "/usr/lib/hx-rescue";
/// The rescue helper.
pub const RESCUE_BIN: &str = "/usr/lib/hx-rescue/hx-privd-rescue";
/// The `hx-agent` command on `PATH`: a symlink the installer owns only while it points at
/// [`CLI_LINK_TARGET`] (design §5.7).
pub const CLI_LINK: &str = "/usr/local/sbin/hx-agent";
/// What [`CLI_LINK`] points at: through `current`, so it follows updates and rollbacks.
pub const CLI_LINK_TARGET: &str = "/usr/lib/hx/current/hx-agent";
/// `/etc/hx`.
pub const ETC_HX: &str = "/etc/hx";
/// Sealed credentials.
pub const CREDS_DIR: &str = "/etc/hx/creds";
/// gatewayd's configuration.
pub const GATEWAYD_TOML: &str = "/etc/hx/gatewayd.toml";
/// privd's policy file.
pub const PRIVD_TOML: &str = "/etc/hx/privd.toml";
/// The firewall ruleset privd writes.
pub const HOST_FIREWALL: &str = "/etc/hx/host-firewall.nft";
/// Units (outside dpkg's namespace).
pub const UNIT_DIR: &str = "/usr/local/lib/systemd/system";
/// sysusers snippets.
pub const SYSUSERS_DIR: &str = "/usr/local/lib/sysusers.d";
/// tmpfiles snippets.
pub const TMPFILES_DIR: &str = "/usr/local/lib/tmpfiles.d";
/// logrotate snippets.
pub const LOGROTATE_DIR: &str = "/etc/logrotate.d";
/// Installer drop-ins.
pub const DROPIN_ROOT: &str = "/etc/systemd/system";
/// The public socket's port drop-in.
pub const PORT_DROPIN: &str = "/etc/systemd/system/hx-gatewayd-public.socket.d/50-port.conf";
/// The fetcher's resolver drop-in.
pub const RESOLVERS_DROPIN: &str =
    "/etc/systemd/system/hx-update-fetcher@.service.d/resolvers.conf";
/// The image fetcher's resolver drop-in (the same resolvers as the update fetcher's).
pub const IMAGE_RESOLVERS_DROPIN: &str =
    "/etc/systemd/system/hx-image-fetcher@.service.d/resolvers.conf";
/// The Drive helper's resolver drop-in (the same resolvers as the fetchers').
pub const DRIVE_RESOLVERS_DROPIN: &str = "/etc/systemd/system/hx-drive.service.d/resolvers.conf";
/// Where an offline `--image-file` and its signed manifest are placed for privd (root, 0700).
pub const IMPORT_DIR: &str = "/var/lib/hx/import";
/// The image fetcher's tmpfs mount point under privd's state directory.
pub const IMAGEIN_DIR: &str = "/var/lib/hx/imagein";
/// The Zabbly keyring file.
pub const ZABBLY_KEY: &str = "/etc/apt/keyrings/hx-zabbly.asc";
/// The Zabbly apt source.
pub const ZABBLY_SOURCES: &str = "/etc/apt/sources.list.d/hx-zabbly-incus.sources";
/// The Incus socket.
pub const INCUS_SOCKET: &str = "/var/lib/incus/unix.socket";
/// gatewayd's state directory.
pub const GATEWAYD_STATE: &str = "/var/lib/hx-gatewayd";
/// privd's state directory.
pub const VAR_LIB_HX: &str = "/var/lib/hx";
/// privd's old plaintext pepper.
pub const PEPPER_KEY: &str = "/var/lib/hx/pepper.key";
/// The audit and log directory of the agent.
pub const VAR_LOG_HX: &str = "/var/log/hx";
/// The runtime directory.
pub const RUN_HX: &str = "/run/hx";
/// Where `install.sh` makes the bootstrap hand-off directory: on the root filesystem, because
/// Ubuntu and Debian mount `/run` `noexec` and the agent is executed from that directory.
pub const BOOTSTRAP_BASE: &str = "/var/lib";
/// The bootstrap hand-off directories (`mktemp -d /var/lib/hx-bootstrap.XXXXXX`).
pub const BOOTSTRAP_PREFIX: &str = "/var/lib/hx-bootstrap.";
/// os-release.
pub const OS_RELEASE: &str = "/etc/os-release";
/// resolv.conf.
pub const RESOLV_CONF: &str = "/etc/resolv.conf";
/// The time zone database.
pub const ZONEINFO: &str = "/usr/share/zoneinfo";
/// The host's local time link.
pub const LOCALTIME: &str = "/etc/localtime";
/// The host's locale file.
pub const DEFAULT_LOCALE: &str = "/etc/default/locale";
/// The host's keyboard file.
pub const DEFAULT_KEYBOARD: &str = "/etc/default/keyboard";
/// The passwd file.
pub const PASSWD: &str = "/etc/passwd";
/// The group file.
pub const GROUP: &str = "/etc/group";
/// The gateway's system user.
pub const GATEWAY_USER: &str = "hx-gatewayd";
/// The privd socket.
pub const PRIVD_SOCKET: &str = "/run/hx/privd.sock";

/// The fixed `PATH` of every child process.
pub const CHILD_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// A root directory and the table above, joined.
#[derive(Debug, Clone)]
pub struct Paths {
    root: PathBuf,
}

impl Paths {
    /// The real system.
    pub fn system() -> Self {
        Self { root: "/".into() }
    }

    /// A tree below `root` (tests, and a non-production configuration).
    pub fn under(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// True for the real system root.
    pub fn is_system(&self) -> bool {
        self.root == Path::new("/")
    }

    /// The root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `abs` (one of the constants, or a path below one) below the root.
    pub fn at(&self, abs: &str) -> PathBuf {
        debug_assert!(abs.starts_with('/'));
        if self.is_system() {
            PathBuf::from(abs)
        } else {
            self.root.join(abs.trim_start_matches('/'))
        }
    }

    /// `<dir>/<name>` below the root.
    pub fn child(&self, dir: &str, name: &str) -> PathBuf {
        self.at(dir).join(name)
    }

    /// The text of a path as the tools see it: below a test root it is the test path, on the
    /// system it is the constant itself.
    pub fn arg(&self, abs: &str) -> String {
        self.at(abs).to_string_lossy().into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_paths_are_the_constants() {
        let p = Paths::system();
        assert_eq!(
            p.at(STATE_FILE),
            Path::new("/var/lib/hx/install-state.json")
        );
        assert!(p.is_system());
    }

    #[test]
    fn a_test_root_contains_everything() {
        let p = Paths::under("/tmp/x");
        assert_eq!(p.at(LOCK_FILE), Path::new("/tmp/x/run/hx-install.lock"));
        assert_eq!(p.child(ETC_HX, "a"), Path::new("/tmp/x/etc/hx/a"));
        assert!(!p.is_system());
    }
}
