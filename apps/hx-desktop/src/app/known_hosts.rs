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

/// The trusted keys, by `host:port`.
#[derive(Debug, Default)]
pub struct KnownHosts {
    path: Option<PathBuf>,
    map: BTreeMap<String, String>,
}

impl KnownHosts {
    /// Loads the file (missing or damaged means empty: the user is asked again, which is safe).
    pub fn open(path: Option<PathBuf>) -> Self {
        let map = path
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        Self { path, map }
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

    /// Remembers a fingerprint the user confirmed (never replaces a different one).
    pub fn trust(&mut self, host: &str, port: u16, fingerprint: &str) {
        self.map
            .entry(Self::key(host, port))
            .or_insert_with(|| fingerprint.to_owned());
        self.save();
    }

    fn save(&self) {
        let Some(p) = &self.path else { return };
        if let Some(d) = p.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        if let Ok(b) = serde_json::to_vec_pretty(&self.map) {
            let _ = std::fs::write(p, b);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_time_then_same_then_changed_and_never_replaced() {
        let mut k = KnownHosts::default();
        assert_eq!(k.check("A.test", 22, "SHA256:a"), Known::New);
        k.trust("a.test", 22, "SHA256:a");
        assert_eq!(k.check("A.TEST", 22, "SHA256:a"), Known::Same);
        assert_eq!(
            k.check("a.test", 22, "SHA256:b"),
            Known::Changed {
                trusted: "SHA256:a".into()
            }
        );
        k.trust("a.test", 22, "SHA256:b");
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
}
