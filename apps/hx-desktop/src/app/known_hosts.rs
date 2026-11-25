//! SSH host keys the user confirmed: "The app remembers this key and warns you if it ever
//! changes". A changed key is a blocking error, never an override.

use std::collections::BTreeMap;
use std::path::PathBuf;

/// What is known about a host's key.
#[derive(Debug, PartialEq, Eq)]
pub enum Known {
    /// First time: ask the user.
    New,
    /// The same key as before.
    Same,
    /// A different key than the one trusted.
    Changed {
        /// The trusted fingerprint.
        trusted: String,
    },
}

/// Why the known-hosts file could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum KnownHostsError {
    /// File system problem.
    #[error("known hosts: {0}")]
    Io(#[from] std::io::Error),
    /// The file is not valid. It is never treated as empty: that would silently drop trust.
    #[error("known hosts file is corrupt: {0}")]
    Corrupt(String),
}

/// The trusted keys, by `host:port`.
#[derive(Debug, Default)]
pub struct KnownHosts {
    path: Option<PathBuf>,
    map: BTreeMap<String, String>,
}

impl KnownHosts {
    /// Loads the file. A missing file is empty (first run); an unreadable or corrupt file is an
    /// error the user must see, so trust is never reset silently.
    pub fn open(path: Option<PathBuf>) -> Result<Self, KnownHostsError> {
        let map = match &path {
            None => BTreeMap::new(),
            Some(p) => match std::fs::read(p) {
                Ok(b) => serde_json::from_slice(&b)
                    .map_err(|e| KnownHostsError::Corrupt(e.to_string()))?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
                Err(e) => return Err(e.into()),
            },
        };
        Ok(Self { path, map })
    }

    fn key(host: &str, port: u16) -> String {
        format!("{}:{port}", host.to_ascii_lowercase())
    }

    /// Compares a presented fingerprint with the trusted one.
    pub fn check(&self, host: &str, port: u16, fingerprint: &str) -> Known {
        match self.map.get(&Self::key(host, port)) {
            None => Known::New,
            Some(f) if f == fingerprint => Known::Same,
            Some(f) => Known::Changed { trusted: f.clone() },
        }
    }

    /// Remembers a fingerprint the user confirmed (never replaces a different one) and saves
    /// the file atomically. On a save error the in-memory entry is rolled back.
    pub fn trust(
        &mut self,
        host: &str,
        port: u16,
        fingerprint: &str,
    ) -> Result<(), KnownHostsError> {
        let k = Self::key(host, port);
        if self.map.contains_key(&k) {
            return Ok(());
        }
        self.map.insert(k.clone(), fingerprint.to_owned());
        let r = self.save();
        if r.is_err() {
            self.map.remove(&k);
        }
        r
    }

    /// Writes a 0600 temp file, fsyncs it and renames it over the old file.
    fn save(&self) -> Result<(), KnownHostsError> {
        use std::io::Write;
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
            #[cfg(unix)]
            {
                // The list of hosts and keys is the user's own business: 0700 directory.
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        let data = serde_json::to_vec_pretty(&self.map)
            .map_err(|e| KnownHostsError::Corrupt(e.to_string()))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_time_then_same_then_changed_and_never_replaced() {
        let mut k = KnownHosts::default();
        assert_eq!(k.check("A.test", 22, "SHA256:a"), Known::New);
        k.trust("a.test", 22, "SHA256:a").unwrap();
        assert_eq!(k.check("A.TEST", 22, "SHA256:a"), Known::Same);
        assert_eq!(
            k.check("a.test", 22, "SHA256:b"),
            Known::Changed {
                trusted: "SHA256:a".into()
            }
        );
        k.trust("a.test", 22, "SHA256:b").unwrap();
        assert_eq!(
            k.check("a.test", 22, "SHA256:a"),
            Known::Same,
            "trust never replaces"
        );
        assert_eq!(
            k.check("a.test", 2222, "SHA256:a"),
            Known::New,
            "the port is part of the key"
        );
    }

    #[test]
    fn atomic_save_round_trips_with_mode_0600() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("cfg").join("known_hosts.json");
        let mut k = KnownHosts::open(Some(p.clone())).unwrap();
        k.trust("a.test", 22, "SHA256:a").unwrap();
        assert!(
            !p.with_extension("json.tmp").exists(),
            "temp file renamed away"
        );
        let k2 = KnownHosts::open(Some(p.clone())).unwrap();
        assert_eq!(k2.check("a.test", 22, "SHA256:a"), Known::Same);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            let dir = std::fs::metadata(p.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir, 0o700);
        }
    }

    #[test]
    fn a_corrupt_file_is_an_error_and_a_missing_one_is_empty() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("known_hosts.json");
        assert!(KnownHosts::open(Some(p.clone())).unwrap().map.is_empty());
        std::fs::write(&p, b"{ not json").unwrap();
        assert!(matches!(
            KnownHosts::open(Some(p.clone())),
            Err(KnownHostsError::Corrupt(_))
        ));
        assert_eq!(std::fs::read(&p).unwrap(), b"{ not json", "left untouched");
    }
}
