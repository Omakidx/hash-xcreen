//! The saved server list: `servers.json` in the XDG config directory.
//!
//! The server's identity key is pinned on the first successful pairing and never replaced
//! silently: a different key on a later connection is [`PinCheck::Changed`] and the app shows
//! the "identity changed" screen with no override. No secret is stored here (the device key is
//! in the keyring, the PIN and passwords are never stored).

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// What the app knows about one server's state, besides reachability.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    /// Paired and set up.
    #[default]
    Ready,
    /// An install started from this app and has not finished.
    Installing,
    /// Paired through the one-liner, but no desktop yet.
    SetupPending,
    /// This device was revoked: it needs "Pair again".
    Revoked,
    /// The agent was uninstalled; the card stays until removed.
    Uninstalled,
}

/// One saved server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Server {
    /// Random local id.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Host name or IP address.
    pub host: String,
    /// Agent port.
    pub port: u16,
    /// Pinned server key, 64 hex digits. Empty only while an install has not paired yet.
    #[serde(default)]
    pub server_key: String,
    /// Lifecycle.
    #[serde(default)]
    pub lifecycle: Lifecycle,
    /// Unix time of the last successful connection, 0 = never.
    #[serde(default)]
    pub last_seen_unix: u64,
    /// Unix time the device was revoked (Revoked only).
    #[serde(default)]
    pub revoked_unix: u64,
}

impl Server {
    /// `host:port`, with IPv6 hosts bracketed.
    pub fn address(&self) -> String {
        format_address(&self.host, self.port)
    }

    /// The pinned key as four groups of four hex digits (`3f9a c1d4 77be 0a52`).
    pub fn short_fingerprint(&self) -> String {
        short_key(&self.server_key)
    }
}

/// `host:port`, bracketing IPv6.
pub fn format_address(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// First 16 hex digits of a key in groups of four, lowercase.
pub fn short_key(hex: &str) -> String {
    let h: String = hex
        .chars()
        .take(16)
        .collect::<String>()
        .to_ascii_lowercase();
    h.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Result of comparing the key a server presented with the pinned one.
#[derive(Debug, PartialEq, Eq)]
pub enum PinCheck {
    /// Same key.
    Match,
    /// No key pinned yet (first pairing).
    NotPinned,
    /// A different key: block, never override.
    Changed {
        /// The pinned key, hex.
        pinned: String,
        /// The presented key, hex.
        presented: String,
    },
}

/// Errors of the store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// File system problem.
    #[error("server list: {0}")]
    Io(#[from] std::io::Error),
    /// The file is not valid.
    #[error("server list is corrupt: {0}")]
    Corrupt(String),
}

#[derive(Default, Serialize, Deserialize)]
struct FileData {
    #[serde(default)]
    servers: Vec<Server>,
}

/// The list, loaded in memory and saved atomically after each change.
#[derive(Debug)]
pub struct ServerStore {
    path: Option<PathBuf>,
    servers: Vec<Server>,
}

/// `$XDG_CONFIG_HOME/hash-xcreen` or `~/.config/hash-xcreen`.
pub fn config_dir() -> Option<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(p) if !p.is_empty() && Path::new(&p).is_absolute() => PathBuf::from(p),
        _ => PathBuf::from(std::env::var_os("HOME")?).join(".config"),
    };
    Some(base.join("hash-xcreen"))
}

impl ServerStore {
    /// An in-memory store (demo mode and tests).
    pub fn in_memory(servers: Vec<Server>) -> Self {
        Self {
            path: None,
            servers,
        }
    }

    /// Opens (or starts) the file at `path`.
    pub fn open(path: PathBuf) -> Result<Self, StoreError> {
        let servers = match std::fs::read(&path) {
            Ok(b) => {
                serde_json::from_slice::<FileData>(&b)
                    .map_err(|e| StoreError::Corrupt(e.to_string()))?
                    .servers
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            path: Some(path),
            servers,
        })
    }

    /// All servers in order.
    pub fn list(&self) -> &[Server] {
        &self.servers
    }

    /// One server by id.
    pub fn get(&self, id: &str) -> Option<&Server> {
        self.servers.iter().find(|s| s.id == id)
    }

    /// Adds a server (or replaces the one with the same id) and saves.
    pub fn upsert(&mut self, s: Server) -> Result<(), StoreError> {
        match self.servers.iter_mut().find(|x| x.id == s.id) {
            Some(x) => *x = s,
            None => self.servers.push(s),
        }
        self.save()
    }

    /// Removes a server and saves.
    pub fn remove(&mut self, id: &str) -> Result<bool, StoreError> {
        let n = self.servers.len();
        self.servers.retain(|s| s.id != id);
        let removed = self.servers.len() != n;
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    /// Changes the lifecycle of one server and saves.
    pub fn set_lifecycle(&mut self, id: &str, l: Lifecycle, now: u64) -> Result<(), StoreError> {
        if let Some(s) = self.servers.iter_mut().find(|s| s.id == id) {
            s.lifecycle = l;
            if l == Lifecycle::Revoked {
                s.revoked_unix = now;
            }
            self.save()?;
        }
        Ok(())
    }

    /// Records a successful connection time.
    pub fn touch(&mut self, id: &str, now: u64) -> Result<(), StoreError> {
        if let Some(s) = self.servers.iter_mut().find(|s| s.id == id) {
            s.last_seen_unix = now;
            self.save()?;
        }
        Ok(())
    }

    /// Pins `key_hex` for server `id` if nothing is pinned. Never replaces a pinned key.
    pub fn pin(&mut self, id: &str, key_hex: &str) -> Result<PinCheck, StoreError> {
        let check = self.check_pin(id, key_hex);
        if check == PinCheck::NotPinned {
            if let Some(s) = self.servers.iter_mut().find(|s| s.id == id) {
                s.server_key = key_hex.to_ascii_lowercase();
            }
            self.save()?;
        }
        Ok(check)
    }

    /// Compares a presented key with the pinned one.
    pub fn check_pin(&self, id: &str, key_hex: &str) -> PinCheck {
        match self.get(id) {
            Some(s) if s.server_key.is_empty() => PinCheck::NotPinned,
            Some(s) if s.server_key.eq_ignore_ascii_case(key_hex) => PinCheck::Match,
            Some(s) => PinCheck::Changed {
                pinned: s.server_key.clone(),
                presented: key_hex.to_ascii_lowercase(),
            },
            None => PinCheck::NotPinned,
        }
    }

    fn save(&self) -> Result<(), StoreError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
            }
        }
        let data = serde_json::to_vec_pretty(&FileData {
            servers: self.servers.clone(),
        })
        .map_err(|e| StoreError::Corrupt(e.to_string()))?;
        let tmp = path.with_extension("json.tmp");
        {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp)?;
            f.write_all(&data)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

/// A fresh random local id (16 hex digits from the system random source).
pub fn new_id() -> String {
    let mut b = [0u8; 8];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut b);
    }
    if b == [0u8; 8] {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        b = t.to_le_bytes();
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn srv(id: &str) -> Server {
        Server {
            id: id.into(),
            name: "Workstation".into(),
            host: "203.0.113.10".into(),
            port: 443,
            server_key: String::new(),
            lifecycle: Lifecycle::Ready,
            last_seen_unix: 0,
            revoked_unix: 0,
        }
    }

    #[test]
    fn pins_on_first_pairing_and_blocks_a_different_key() {
        let mut s = ServerStore::in_memory(vec![srv("a")]);
        let k1 = "3f9ac1d477be0a52".repeat(4);
        let k2 = "b81e05f7d3906c2a".repeat(4);
        assert_eq!(s.pin("a", &k1).unwrap(), PinCheck::NotPinned);
        assert_eq!(s.check_pin("a", &k1), PinCheck::Match);
        // pinning again never replaces
        assert!(matches!(s.pin("a", &k2).unwrap(), PinCheck::Changed { .. }));
        assert_eq!(s.get("a").unwrap().server_key, k1);
    }

    #[test]
    fn round_trips_through_a_private_file() {
        let dir = std::env::temp_dir().join(format!("hx-desktop-store-{}", new_id()));
        let path = dir.join("servers.json");
        let mut s = ServerStore::open(path.clone()).unwrap();
        s.upsert(srv("a")).unwrap();
        s.set_lifecycle("a", Lifecycle::Revoked, 99).unwrap();
        let again = ServerStore::open(path.clone()).unwrap();
        assert_eq!(again.list().len(), 1);
        assert_eq!(again.list()[0].lifecycle, Lifecycle::Revoked);
        assert_eq!(again.list()[0].revoked_unix, 99);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(m, 0o600);
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn corrupt_file_is_an_error_not_an_empty_list() {
        let dir = std::env::temp_dir().join(format!("hx-desktop-store-{}", new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("servers.json");
        std::fs::write(&path, b"{not json").unwrap();
        assert!(matches!(
            ServerStore::open(path),
            Err(StoreError::Corrupt(_))
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn formats_addresses_and_fingerprints() {
        assert_eq!(format_address("::1", 443), "[::1]:443");
        assert_eq!(
            short_key(&"3F9AC1D477BE0A52".repeat(4)),
            "3f9a c1d4 77be 0a52"
        );
    }
}
