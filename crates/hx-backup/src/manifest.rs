//! The backup manifest (architecture 9.4 step 3).
//!
//! A small JSON document describing what a snapshot is: which distro and desktop it came from,
//! the container configuration subset needed to recreate the container, the agent that wrote it,
//! the Docker mode and the size of the source. It is stored as the snapshot's *description*, so
//! it travels (encrypted) with the snapshot, shows up in a plain snapshot listing and needs no
//! file restore to read.
//!
//! # Versioning rule
//!
//! * `format_version` is the first thing read; everything else is parsed by the strict parser of
//!   that version (`deny_unknown_fields`), so a typo or an injected field is an error, not
//!   silently ignored.
//! * **A new agent must always be able to read the manifests of older agents** (restoring onto a
//!   newer agent, architecture 9.8 item 5). Any change that adds, removes or re-types a field
//!   bumps [`CURRENT_FORMAT_VERSION`]; the previous version's struct is kept (private) with a
//!   `From` conversion into the current [`Manifest`], and [`Manifest::from_slice`] dispatches on
//!   the version. Old structs are never deleted.
//! * An **older agent reading a newer manifest** cannot interpret it safely and returns
//!   [`ManifestError::NewerFormat`]; the user is told to update the agent.
//! * `format_version` 0 and unparsable versions are invalid.
//!
//! The manifest cannot contain its own snapshot id (the id is a hash of the file that would hold
//! it), so `rustic_snapshot_id` is absent inside the repository and filled in by whoever reads
//! the manifest back for a known snapshot (see `Engine::read_manifest`).

use std::collections::BTreeMap;
use std::str::FromStr;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::rules::DockerMode;

/// The manifest format written by this build.
pub const CURRENT_FORMAT_VERSION: u32 = 1;
/// Largest manifest accepted or produced, in bytes.
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
/// Most container configuration entries.
pub const MAX_CONFIG_ENTRIES: usize = 256;
/// Longest container configuration key, in bytes.
pub const MAX_CONFIG_KEY_BYTES: usize = 128;
/// Longest container configuration value, in bytes.
pub const MAX_CONFIG_VALUE_BYTES: usize = 1024;
/// Longest free-text field (distro, desktop, preset, agent version), in bytes.
pub const MAX_TEXT_BYTES: usize = 128;

/// Manifest errors.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    /// Input larger than [`MAX_MANIFEST_BYTES`].
    #[error("manifest is {size} bytes, over the {max} byte limit")]
    TooLarge {
        /// Bytes supplied.
        size: usize,
        /// Limit.
        max: usize,
    },
    /// Not JSON, wrong shape, or an unknown field at a known version.
    #[error("manifest is not valid: {0}")]
    Parse(String),
    /// `format_version` is 0.
    #[error("manifest format_version 0 is invalid")]
    InvalidVersion,
    /// Written by a newer agent than this one.
    #[error(
        "manifest format {found} is newer than this agent supports ({supported}); update the agent"
    )]
    NewerFormat {
        /// Version found in the manifest.
        found: u32,
        /// Newest version this build reads.
        supported: u32,
    },
    /// A field failed validation.
    #[error("manifest field `{field}` is invalid: {reason}")]
    Field {
        /// The field.
        field: &'static str,
        /// What is wrong.
        reason: &'static str,
    },
}

/// The distribution of the backed-up desktop (from `/etc/os-release`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Distro {
    /// `ID=`, for example `ubuntu`.
    pub id: String,
    /// `VERSION_ID=`, for example `24.04`.
    pub version_id: String,
    /// `PRETTY_NAME=`, for display only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pretty_name: Option<String>,
}

impl Distro {
    /// Parse the text of an `os-release` file (only the first 16 KiB is considered).
    ///
    /// # Errors
    /// [`ManifestError::Field`] when `ID` is missing; a missing `VERSION_ID` (rolling
    /// distributions) becomes the empty string.
    pub fn from_os_release(text: &str) -> Result<Self, ManifestError> {
        let mut id = None;
        let mut version_id = String::new();
        let mut pretty = None;
        let mut take = text.len().min(16 * 1024);
        while !text.is_char_boundary(take) {
            take -= 1;
        }
        for line in text[..take].lines() {
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let v = v.trim().trim_matches(|c| c == '"' || c == '\'').to_owned();
            match k.trim() {
                "ID" => id = Some(v),
                "VERSION_ID" => version_id = v,
                "PRETTY_NAME" => pretty = Some(v),
                _ => {}
            }
        }
        Ok(Self {
            id: id.ok_or(ManifestError::Field {
                field: "distro.id",
                reason: "os-release has no ID",
            })?,
            version_id,
            pretty_name: pretty,
        })
    }
}

/// Size of the source tree, measured before the backup (the exact figures of the run are in the
/// backup outcome).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSizes {
    /// Regular files that will be backed up.
    pub files: u64,
    /// Directories that will be backed up.
    pub directories: u64,
    /// Apparent size of those files (hard links counted once), in bytes.
    pub bytes: u64,
    /// Number of concrete excluded paths.
    pub excluded_paths: u64,
}

/// What the caller knows about the desktop; the engine adds the time and the sizes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestInput {
    /// Version of the agent writing the backup.
    pub agent_version: String,
    /// The distribution.
    pub distro: Distro,
    /// Desktop environment, for example `xfce4`.
    pub desktop: String,
    /// Preset name.
    pub preset: String,
    /// Docker data mode, `None` when Docker is not enabled.
    pub docker_mode: Option<DockerMode>,
    /// Container configuration subset (see [`restorable_container_config`]).
    pub container_config: BTreeMap<String, String>,
}

/// The manifest, current format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Always [`CURRENT_FORMAT_VERSION`] for a manifest built by this build.
    pub format_version: u32,
    /// RFC 3339 UTC time of the backup.
    pub created_at: String,
    /// Agent version.
    pub agent_version: String,
    /// Distribution.
    pub distro: Distro,
    /// Desktop environment.
    pub desktop: String,
    /// Preset name.
    pub preset: String,
    /// Docker mode, `None` when Docker is not enabled.
    pub docker_mode: Option<DockerMode>,
    /// Container configuration subset.
    pub container_config: BTreeMap<String, String>,
    /// Source sizes.
    pub source_sizes: SourceSizes,
    /// Hex id of the snapshot carrying this manifest. Absent inside the repository.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rustic_snapshot_id: Option<String>,
}

#[derive(Deserialize)]
struct Header {
    format_version: u32,
}

impl Manifest {
    /// Build a validated manifest in the current format.
    ///
    /// # Errors
    /// [`ManifestError::Field`] when an input field is not acceptable.
    pub fn new(
        input: ManifestInput,
        created_at: Timestamp,
        source_sizes: SourceSizes,
    ) -> Result<Self, ManifestError> {
        let m = Self {
            format_version: CURRENT_FORMAT_VERSION,
            created_at: created_at.to_string(),
            agent_version: input.agent_version,
            distro: input.distro,
            desktop: input.desktop,
            preset: input.preset,
            docker_mode: input.docker_mode,
            container_config: input.container_config,
            source_sizes,
            rustic_snapshot_id: None,
        };
        m.validate()?;
        Ok(m)
    }

    /// Parse a manifest of any supported version, strictly.
    ///
    /// # Errors
    /// [`ManifestError::TooLarge`] over [`MAX_MANIFEST_BYTES`] (checked before parsing),
    /// [`ManifestError::Parse`], [`ManifestError::InvalidVersion`],
    /// [`ManifestError::NewerFormat`] or [`ManifestError::Field`].
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ManifestError> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(ManifestError::TooLarge {
                size: bytes.len(),
                max: MAX_MANIFEST_BYTES,
            });
        }
        let header: Header =
            serde_json::from_slice(bytes).map_err(|e| ManifestError::Parse(e.to_string()))?;
        let manifest = match header.format_version {
            0 => return Err(ManifestError::InvalidVersion),
            // Future versions add arms here that parse the old struct and convert.
            CURRENT_FORMAT_VERSION => serde_json::from_slice::<Self>(bytes)
                .map_err(|e| ManifestError::Parse(e.to_string()))?,
            v => {
                return Err(ManifestError::NewerFormat {
                    found: v,
                    supported: CURRENT_FORMAT_VERSION,
                });
            }
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// Compact JSON for storing in the snapshot description.
    ///
    /// # Errors
    /// [`ManifestError::Field`] if the manifest is invalid, [`ManifestError::TooLarge`] if the
    /// result exceeds the limit.
    pub fn to_json(&self) -> Result<String, ManifestError> {
        self.validate()?;
        let s = serde_json::to_string(self).map_err(|e| ManifestError::Parse(e.to_string()))?;
        if s.len() > MAX_MANIFEST_BYTES {
            return Err(ManifestError::TooLarge {
                size: s.len(),
                max: MAX_MANIFEST_BYTES,
            });
        }
        Ok(s)
    }

    /// The same manifest with the snapshot id filled in.
    ///
    /// # Errors
    /// [`ManifestError::Field`] if `id` is not 64 lowercase hex digits.
    pub fn with_snapshot_id(mut self, id: &str) -> Result<Self, ManifestError> {
        self.rustic_snapshot_id = Some(id.to_owned());
        self.validate()?;
        Ok(self)
    }

    /// Check every field.
    ///
    /// # Errors
    /// [`ManifestError::Field`] naming the first bad field.
    pub fn validate(&self) -> Result<(), ManifestError> {
        let bad = |field, reason| Err(ManifestError::Field { field, reason });
        if self.format_version != CURRENT_FORMAT_VERSION {
            return bad("format_version", "not the current format");
        }
        if Timestamp::from_str(&self.created_at).is_err() {
            return bad("created_at", "not an RFC 3339 timestamp");
        }
        text("agent_version", &self.agent_version, false)?;
        text("distro.id", &self.distro.id, false)?;
        text("distro.version_id", &self.distro.version_id, true)?;
        if let Some(p) = &self.distro.pretty_name {
            text("distro.pretty_name", p, true)?;
        }
        text("desktop", &self.desktop, false)?;
        text("preset", &self.preset, false)?;
        if self.container_config.len() > MAX_CONFIG_ENTRIES {
            return bad("container_config", "too many entries");
        }
        for (k, v) in &self.container_config {
            if k.is_empty() || k.len() > MAX_CONFIG_KEY_BYTES || k.chars().any(char::is_control) {
                return bad("container_config", "bad key");
            }
            if v.len() > MAX_CONFIG_VALUE_BYTES || v.chars().any(char::is_control) {
                return bad("container_config", "bad value");
            }
        }
        if let Some(id) = &self.rustic_snapshot_id
            && (id.len() != 64 || !id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        {
            return bad("rustic_snapshot_id", "not 64 lowercase hex digits");
        }
        Ok(())
    }
}

fn text(field: &'static str, s: &str, may_be_empty: bool) -> Result<(), ManifestError> {
    if (!may_be_empty && s.is_empty())
        || s.len() > MAX_TEXT_BYTES
        || s.chars().any(char::is_control)
    {
        return Err(ManifestError::Field {
            field,
            reason: "empty, too long or contains control characters",
        });
    }
    Ok(())
}

/// Keep the container configuration worth restoring: resource limits, security flags and
/// autostart. Everything else (`volatile.*`, `image.*`, `user.*`, raw LXC, devices) is dropped:
/// it is either regenerated, host specific, or not something a backup should replay.
pub fn restorable_container_config<I, K, V>(config: I) -> BTreeMap<String, String>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: AsRef<str>,
{
    config
        .into_iter()
        .filter(|(k, v)| {
            let k = k.as_ref();
            let keep = k.starts_with("limits.")
                || k.starts_with("security.")
                || k == "boot.autostart"
                || k == "boot.autostart.priority";
            keep && k.len() <= MAX_CONFIG_KEY_BYTES && v.as_ref().len() <= MAX_CONFIG_VALUE_BYTES
        })
        .take(MAX_CONFIG_ENTRIES)
        .map(|(k, v)| (k.as_ref().to_owned(), v.as_ref().to_owned()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> ManifestInput {
        ManifestInput {
            agent_version: "0.1.0".into(),
            distro: Distro {
                id: "ubuntu".into(),
                version_id: "24.04".into(),
                pretty_name: Some("Ubuntu 24.04 LTS".into()),
            },
            desktop: "xfce4".into(),
            preset: "dev".into(),
            docker_mode: Some(DockerMode::Light),
            container_config: restorable_container_config([
                ("limits.cpu", "4"),
                ("security.idmap.isolated", "true"),
                ("volatile.eth0.hwaddr", "00:16:3e:aa:bb:cc"),
                ("image.os", "ubuntu"),
            ]),
        }
    }

    fn sample() -> Manifest {
        Manifest::new(
            input(),
            "2026-11-26T03:00:00Z".parse().unwrap(),
            SourceSizes {
                files: 70_575,
                directories: 9_000,
                bytes: 2_439_600_000,
                excluded_paths: 53,
            },
        )
        .unwrap()
    }

    #[test]
    fn round_trip() {
        let m = sample();
        let json = m.to_json().unwrap();
        assert_eq!(Manifest::from_slice(json.as_bytes()).unwrap(), m);
        assert!(!json.contains("rustic_snapshot_id"));
        assert!(!json.contains("volatile"));
        assert!(json.contains("\"docker_mode\":\"light\""));
        let id = "ab".repeat(32);
        let with = m.with_snapshot_id(&id).unwrap();
        let back = Manifest::from_slice(with.to_json().unwrap().as_bytes()).unwrap();
        assert_eq!(back.rustic_snapshot_id.as_deref(), Some(id.as_str()));
    }

    #[test]
    fn unknown_fields_are_rejected_at_the_current_version() {
        let mut v: serde_json::Value = serde_json::from_str(&sample().to_json().unwrap()).unwrap();
        v["surprise"] = 1.into();
        assert!(matches!(
            Manifest::from_slice(v.to_string().as_bytes()),
            Err(ManifestError::Parse(_))
        ));
        let mut v: serde_json::Value = serde_json::from_str(&sample().to_json().unwrap()).unwrap();
        v["distro"]["surprise"] = 1.into();
        assert!(matches!(
            Manifest::from_slice(v.to_string().as_bytes()),
            Err(ManifestError::Parse(_))
        ));
    }

    #[test]
    fn oversize_is_rejected_before_parsing() {
        let big = vec![b' '; MAX_MANIFEST_BYTES + 1];
        assert!(matches!(
            Manifest::from_slice(&big),
            Err(ManifestError::TooLarge { .. })
        ));
        let mut i = input();
        i.preset = "x".repeat(MAX_TEXT_BYTES + 1);
        assert!(matches!(
            Manifest::new(i, Timestamp::UNIX_EPOCH, SourceSizes::default()),
            Err(ManifestError::Field {
                field: "preset",
                ..
            })
        ));
    }

    #[test]
    fn version_rules() {
        let mut v: serde_json::Value = serde_json::from_str(&sample().to_json().unwrap()).unwrap();
        v["format_version"] = 0.into();
        assert!(matches!(
            Manifest::from_slice(v.to_string().as_bytes()),
            Err(ManifestError::InvalidVersion)
        ));
        // A newer manifest is refused whatever else it contains (even unknown fields).
        let newer = r#"{"format_version":2,"from_the_future":{"a":1}}"#;
        assert!(matches!(
            Manifest::from_slice(newer.as_bytes()),
            Err(ManifestError::NewerFormat {
                found: 2,
                supported: 1
            })
        ));
        for junk in [
            &b""[..],
            b"[]",
            b"{}",
            b"{\"format_version\":\"1\"}",
            b"\xff\xfe",
        ] {
            assert!(Manifest::from_slice(junk).is_err());
        }
        // A v1 document written by a future-proof reader stays readable: the rule is that
        // `Manifest::from_slice` accepts every version up to CURRENT (here: exactly 1).
        assert_eq!(CURRENT_FORMAT_VERSION, 1);
    }

    #[test]
    fn field_validation() {
        let mut v: serde_json::Value = serde_json::from_str(&sample().to_json().unwrap()).unwrap();
        v["created_at"] = "yesterday".into();
        assert!(matches!(
            Manifest::from_slice(v.to_string().as_bytes()),
            Err(ManifestError::Field {
                field: "created_at",
                ..
            })
        ));
        let mut v: serde_json::Value = serde_json::from_str(&sample().to_json().unwrap()).unwrap();
        v["rustic_snapshot_id"] = "../../x".into();
        assert!(matches!(
            Manifest::from_slice(v.to_string().as_bytes()),
            Err(ManifestError::Field {
                field: "rustic_snapshot_id",
                ..
            })
        ));
        let mut v: serde_json::Value = serde_json::from_str(&sample().to_json().unwrap()).unwrap();
        v["desktop"] = "xfce\n4".into();
        assert!(Manifest::from_slice(v.to_string().as_bytes()).is_err());
    }

    #[test]
    fn os_release_parsing() {
        let d = Distro::from_os_release(
            "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\n",
        )
        .unwrap();
        assert_eq!(d.id, "ubuntu");
        assert_eq!(d.version_id, "24.04");
        assert_eq!(d.pretty_name.as_deref(), Some("Ubuntu 24.04.1 LTS"));
        assert!(Distro::from_os_release("NAME=x\n").is_err());
        assert_eq!(Distro::from_os_release("ID=arch\n").unwrap().version_id, "");
    }

    #[test]
    fn container_config_subset() {
        let m = restorable_container_config([
            ("limits.cpu", "2"),
            ("volatile.base_image", "abc"),
            ("user.foo", "bar"),
            ("raw.lxc", "lxc.cap.drop ="),
            ("boot.autostart", "true"),
        ]);
        assert_eq!(
            m.keys().map(String::as_str).collect::<Vec<_>>(),
            ["boot.autostart", "limits.cpu"]
        );
    }
}
