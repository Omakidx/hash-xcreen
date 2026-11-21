//! The signed release manifest (ipc.md 6.12): format and the checks privd makes after the
//! signature has been verified.
//!
//! `manifest-<arch>.json` is published with a detached minisign signature
//! (`manifest-<arch>.json.minisig`) made by the release key. It is the **only** signed object: the
//! artifact is authenticated by the SHA-256 and size it carries, so verifying the manifest and
//! then hashing the artifact is the whole chain.
//!
//! ```json
//! {
//!   "schema": 1,
//!   "channel": "stable",
//!   "version": "1.4.2",
//!   "arch": "x86_64",
//!   "artifact": "hx-1.4.2-x86_64.tar.gz",
//!   "size": 41234567,
//!   "sha256": "<64 lowercase hex>",
//!   "timestamp": 1795000000,
//!   "min_previous": "1.2.0"
//! }
//! ```
//!
//! `timestamp` is when the release was signed (Unix seconds); privd persists the highest accepted
//! value and rejects an older manifest. `min_previous` (optional) is the oldest running version
//! that may update straight to this one; an older one must go through an intermediate release.

use serde::{Deserialize, Serialize};

use super::version::Version;

/// The only schema version.
pub const SCHEMA: u32 = 1;
/// Largest artifact a manifest may announce (ipc.md 6.12: agent release at most 256 MiB).
pub const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
/// A manifest dated further ahead than this is refused (a signing mistake must not pin the
/// freshness counter in the future for good).
pub const MAX_FUTURE_SKEW_SECS: u64 = 24 * 3600;

/// A parsed manifest, before the checks of [`Manifest::check`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Format version, 1.
    pub schema: u32,
    /// `stable` or `beta`.
    pub channel: String,
    /// The release version.
    pub version: String,
    /// `x86_64` or `aarch64`.
    pub arch: String,
    /// The artifact's file name; always [`artifact_name`] of the version and arch.
    pub artifact: String,
    /// Artifact size in bytes.
    pub size: u64,
    /// Artifact SHA-256, lowercase hex.
    pub sha256: String,
    /// When it was signed, Unix seconds.
    pub timestamp: u64,
    /// Oldest running version that may update directly.
    #[serde(default)]
    pub min_previous: Option<String>,
}

/// A manifest that passed [`Manifest::check`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    /// The manifest.
    pub manifest: Manifest,
    /// Its version, parsed.
    pub version: Version,
    /// `min_previous`, parsed.
    pub min_previous: Option<Version>,
}

/// What a manifest is checked against.
#[derive(Debug, Clone, Copy)]
pub struct Expect<'a> {
    /// The channel of `privd.toml`.
    pub channel: &'a str,
    /// This host's architecture.
    pub arch: &'a str,
    /// Now, Unix seconds.
    pub now: u64,
}

/// Why a manifest was refused. The text is privd's own, never the manifest's.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    /// Not JSON of the expected shape.
    #[error("the manifest is not valid JSON of the expected shape")]
    Malformed,
    /// A field has a value this privd does not accept.
    #[error("manifest field `{0}` is not acceptable")]
    Field(&'static str),
}

/// The artifact's file name for a version and architecture.
pub fn artifact_name(version: &str, arch: &str) -> String {
    format!("hx-{version}-{arch}.tar.gz")
}

fn is_arch(s: &str) -> bool {
    matches!(s, "x86_64" | "aarch64")
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Manifest {
    /// Parses signed manifest bytes (size-bounded by the caller).
    pub fn parse(bytes: &[u8]) -> Result<Self, ManifestError> {
        serde_json::from_slice(bytes).map_err(|_| ManifestError::Malformed)
    }

    /// Checks every field against what this host expects.
    pub fn check(self, e: &Expect<'_>) -> Result<Release, ManifestError> {
        let bad = ManifestError::Field;
        if self.schema != SCHEMA {
            return Err(bad("schema"));
        }
        if self.channel != e.channel {
            return Err(bad("channel"));
        }
        let version = Version::parse(&self.version).ok_or(bad("version"))?;
        if self.arch != e.arch || !is_arch(&self.arch) {
            return Err(bad("arch"));
        }
        if self.artifact != artifact_name(&self.version, &self.arch) {
            return Err(bad("artifact"));
        }
        if self.size == 0 || self.size > MAX_ARTIFACT_BYTES {
            return Err(bad("size"));
        }
        if !is_sha256_hex(&self.sha256) {
            return Err(bad("sha256"));
        }
        if self.timestamp == 0 || self.timestamp > e.now.saturating_add(MAX_FUTURE_SKEW_SECS) {
            return Err(bad("timestamp"));
        }
        let min_previous = match &self.min_previous {
            None => None,
            Some(s) => Some(Version::parse(s).ok_or(bad("min_previous"))?),
        };
        Ok(Release {
            manifest: self,
            version,
            min_previous,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good() -> Manifest {
        Manifest {
            schema: 1,
            channel: "stable".into(),
            version: "1.4.2".into(),
            arch: "x86_64".into(),
            artifact: artifact_name("1.4.2", "x86_64"),
            size: 1000,
            sha256: "0".repeat(64),
            timestamp: 1_700_000_000,
            min_previous: Some("1.2.0".into()),
        }
    }

    const E: Expect<'static> = Expect {
        channel: "stable",
        arch: "x86_64",
        now: 1_700_000_100,
    };

    #[test]
    fn a_good_manifest_passes_and_round_trips() {
        let m = good();
        let bytes = serde_json::to_vec(&m).unwrap();
        let r = Manifest::parse(&bytes).unwrap().check(&E).unwrap();
        assert_eq!(r.version.to_string(), "1.4.2");
        assert_eq!(r.min_previous.unwrap().to_string(), "1.2.0");
    }

    #[test]
    fn every_field_is_checked() {
        type Edit = Box<dyn Fn(&mut Manifest)>;
        let cases: Vec<(&str, Edit)> = vec![
            ("schema", Box::new(|m| m.schema = 2)),
            ("channel", Box::new(|m| m.channel = "beta".into())),
            ("version", Box::new(|m| m.version = "1.4".into())),
            ("version", Box::new(|m| m.version = "../1.4.2".into())),
            ("arch", Box::new(|m| m.arch = "aarch64".into())),
            (
                "artifact",
                Box::new(|m| m.artifact = "../evil.tar.gz".into()),
            ),
            ("size", Box::new(|m| m.size = 0)),
            ("size", Box::new(|m| m.size = MAX_ARTIFACT_BYTES + 1)),
            ("sha256", Box::new(|m| m.sha256 = "AB".repeat(32))),
            ("sha256", Box::new(|m| m.sha256 = "0".repeat(63))),
            ("timestamp", Box::new(|m| m.timestamp = 0)),
            (
                "timestamp",
                Box::new(|m| m.timestamp = 1_700_000_100 + 86_401),
            ),
            (
                "min_previous",
                Box::new(|m| m.min_previous = Some("x".into())),
            ),
        ];
        for (field, f) in cases {
            let mut m = good();
            f(&mut m);
            assert_eq!(m.check(&E), Err(ManifestError::Field(field)), "{field}");
        }
    }

    #[test]
    fn malformed_json_is_refused() {
        for b in [&b""[..], b"{}", b"[]", b"{\"schema\":1}", b"\xff\xfe"] {
            assert_eq!(Manifest::parse(b), Err(ManifestError::Malformed));
        }
    }
}
