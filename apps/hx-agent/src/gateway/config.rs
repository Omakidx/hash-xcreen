//! The gateway's configuration file (TOML, unknown keys rejected).
//!
//! The installer writes it to `/etc/hx/gatewayd.toml` (root-owned, 0644: it holds no secret);
//! the identity key is **not** in it but in a systemd credential (`docs/ipc.md` section 2).
//!
//! ```toml
//! listen = "[::]:4433"            # QUIC (UDP) and WebSocket (TCP), same port number
//! takeover = "allow"              # or "deny" (docs/ipc.md section 18)
//! desktop_id = "main"
//! server_name = "my server"       # shown to a client while pairing (at most 64 bytes)
//! state_dir = "/var/lib/hx-gatewayd"
//! privd_socket = "/run/hx/privd.sock"
//! admin_socket = "/run/hx/gatewayd-admin.sock"
//! identity_credential = "identity"   # a name under $CREDENTIALS_DIRECTORY, or an absolute path
//! max_file_bytes = 4294967296     # lower than 4 GiB to cap file transfers (protocol 5.6)
//! pairing_ttl_s = 900
//! manage_idle_s = 300
//! seccomp = "enforce"             # or "log" while developing a new build
//! mlock = true                    # mlockall at start (docs/ipc.md section 5.2); fatal on failure
//! ```
//!
//! `listen` is required: the unit runs with an empty capability bounding set, so it can only
//! bind ports of 1024 and above; the installer maps port 443 to it (a firewall redirect, or the
//! `net.ipv4.ip_unprivileged_port_start` sysctl) when the user asks for 443.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::takeover::TakeoverPolicy;

/// Which seccomp action the binary installs for syscalls outside its allowlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SeccompMode {
    /// Kill the process (the production setting).
    #[default]
    Enforce,
    /// Allow but log (`SECCOMP_RET_LOG`), to find a missing syscall without a crash loop.
    Log,
}

/// Configuration error.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("cannot read the configuration file: {0}")]
    Read(String),
    /// The text is not valid TOML, or has an unknown key or a wrong type.
    #[error("invalid configuration: {0}")]
    Parse(String),
    /// A value is out of range.
    #[error("invalid configuration: {0}")]
    Invalid(&'static str),
}

/// The gateway's settings. [`GatewayConfig::from_toml`] fills defaults and validates.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    /// Address for QUIC (UDP) and the WebSocket fallback (TCP), the same port number.
    pub listen: SocketAddr,
    /// Takeover policy (`docs/ipc.md` section 18).
    #[serde(default)]
    pub takeover: TakeoverPolicy,
    /// The desktop this gateway serves (v1 has exactly one; the installer uses `main`).
    #[serde(default = "default_desktop")]
    pub desktop_id: String,
    /// Label sent to a client while pairing.
    #[serde(default = "default_server_name")]
    pub server_name: String,
    /// The gateway's state directory: owned by `hx-gatewayd`, 0700.
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    /// The privd socket.
    #[serde(default = "default_privd")]
    pub privd_socket: PathBuf,
    /// The admin socket (used only when systemd does not hand it over by socket activation).
    #[serde(default = "default_admin")]
    pub admin_socket: PathBuf,
    /// The identity-key credential: a file name under `$CREDENTIALS_DIRECTORY`, or an absolute
    /// path.
    #[serde(default = "default_identity")]
    pub identity_credential: PathBuf,
    /// The largest file transfer offered (protocol 5.6); at most 4 GiB.
    #[serde(default = "default_max_file")]
    pub max_file_bytes: u64,
    /// How long a pairing token or code lives, in seconds (60 to 900).
    #[serde(default = "default_pairing_ttl")]
    pub pairing_ttl_s: u64,
    /// A session that never asks to view the desktop is closed after this many seconds
    /// (protocol 5.9, "Claiming the desktop").
    #[serde(default = "default_manage_idle")]
    pub manage_idle_s: u64,
    /// Seccomp action outside the allowlist.
    #[serde(default)]
    pub seccomp: SeccompMode,
    /// Lock all memory at start so that nothing is swapped (`docs/ipc.md` section 5.2). The
    /// unit sets `LimitMEMLOCK=infinity`; turn it off only in a development run.
    #[serde(default = "yes")]
    pub mlock: bool,
    /// Lowest Argon2id memory (KiB) accepted in a verifier an operator sets.
    #[serde(default = "default_min_memory")]
    pub argon2_min_memory_kib: u32,
}

fn default_desktop() -> String {
    "main".into()
}
fn default_server_name() -> String {
    "hash-xcreen server".into()
}
fn default_state_dir() -> PathBuf {
    "/var/lib/hx-gatewayd".into()
}
fn default_privd() -> PathBuf {
    "/run/hx/privd.sock".into()
}
fn default_admin() -> PathBuf {
    "/run/hx/gatewayd-admin.sock".into()
}
fn default_identity() -> PathBuf {
    "identity".into()
}
fn default_max_file() -> u64 {
    hx_proto::channel::MAX_FILE_SIZE
}
fn default_pairing_ttl() -> u64 {
    900
}
fn default_manage_idle() -> u64 {
    300
}
fn default_min_memory() -> u32 {
    super::verifier::DEFAULT_MIN_MEMORY_KIB
}
fn yes() -> bool {
    true
}

impl GatewayConfig {
    /// Parses and validates a configuration.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let cfg: Self = toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Reads and parses the file at `path`.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Read(e.kind().to_string()))?;
        Self::from_toml(&text)
    }

    /// A configuration with every default, listening on `listen` (tests and tools).
    pub fn with_listen(listen: SocketAddr, state_dir: PathBuf) -> Self {
        Self {
            listen,
            takeover: TakeoverPolicy::Allow,
            desktop_id: default_desktop(),
            server_name: default_server_name(),
            state_dir,
            privd_socket: default_privd(),
            admin_socket: default_admin(),
            identity_credential: default_identity(),
            max_file_bytes: default_max_file(),
            pairing_ttl_s: default_pairing_ttl(),
            manage_idle_s: default_manage_idle(),
            seccomp: SeccompMode::Enforce,
            mlock: true,
            argon2_min_memory_kib: default_min_memory(),
        }
    }

    /// Range checks.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !hx_ipc::privd::is_valid_desktop_id(&self.desktop_id) {
            return Err(ConfigError::Invalid("desktop_id is not a valid desktop id"));
        }
        if self.server_name.is_empty() || self.server_name.len() > 64 {
            return Err(ConfigError::Invalid("server_name must be 1 to 64 bytes"));
        }
        if self.server_name.chars().any(char::is_control) {
            return Err(ConfigError::Invalid("server_name has a control character"));
        }
        if self.max_file_bytes == 0 || self.max_file_bytes > hx_proto::channel::MAX_FILE_SIZE {
            return Err(ConfigError::Invalid("max_file_bytes must be 1 to 4 GiB"));
        }
        if !(60..=900).contains(&self.pairing_ttl_s) {
            return Err(ConfigError::Invalid("pairing_ttl_s must be 60 to 900"));
        }
        if !(10..=3600).contains(&self.manage_idle_s) {
            return Err(ConfigError::Invalid("manage_idle_s must be 10 to 3600"));
        }
        for p in [&self.state_dir, &self.privd_socket, &self.admin_socket] {
            if !p.is_absolute() {
                return Err(ConfigError::Invalid("paths must be absolute"));
            }
        }
        Ok(())
    }

    /// The identity credential's path: under `$CREDENTIALS_DIRECTORY` when relative.
    pub fn identity_path(&self, credentials_dir: Option<&Path>) -> Result<PathBuf, ConfigError> {
        if self.identity_credential.is_absolute() {
            return Ok(self.identity_credential.clone());
        }
        match credentials_dir {
            Some(d) => Ok(d.join(&self.identity_credential)),
            None => Err(ConfigError::Invalid(
                "identity_credential is relative but CREDENTIALS_DIRECTORY is not set",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_file_gets_defaults() {
        let c = GatewayConfig::from_toml("listen = \"127.0.0.1:4433\"").unwrap();
        assert_eq!(c.takeover, TakeoverPolicy::Allow);
        assert_eq!(c.desktop_id, "main");
        assert_eq!(c.seccomp, SeccompMode::Enforce);
        assert!(c.mlock);
        assert_eq!(c.max_file_bytes, 4 * 1024 * 1024 * 1024);
    }

    #[test]
    fn unknown_keys_and_bad_values_are_refused() {
        for bad in [
            "",
            "listen = \"127.0.0.1:4433\"\nsurprise = 1",
            "listen = \"nonsense\"",
            "listen = \"127.0.0.1:1\"\ntakeover = \"maybe\"",
            "listen = \"127.0.0.1:1\"\ndesktop_id = \"Bad Id\"",
            "listen = \"127.0.0.1:1\"\nmax_file_bytes = 0",
            "listen = \"127.0.0.1:1\"\nmax_file_bytes = 9999999999999",
            "listen = \"127.0.0.1:1\"\npairing_ttl_s = 5",
            "listen = \"127.0.0.1:1\"\nstate_dir = \"relative\"",
            "listen = \"127.0.0.1:1\"\nseccomp = \"off\"",
        ] {
            assert!(GatewayConfig::from_toml(bad).is_err(), "{bad}");
        }
        let deny = GatewayConfig::from_toml("listen = \"127.0.0.1:1\"\ntakeover = \"deny\"").unwrap();
        assert_eq!(deny.takeover, TakeoverPolicy::Deny);
    }

    #[test]
    fn identity_path_resolution() {
        let c = GatewayConfig::from_toml("listen = \"127.0.0.1:1\"").unwrap();
        assert_eq!(
            c.identity_path(Some(Path::new("/run/credentials/x"))).unwrap(),
            PathBuf::from("/run/credentials/x/identity")
        );
        assert!(c.identity_path(None).is_err());
    }
}
