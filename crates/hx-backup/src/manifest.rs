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
    /// The file comes from the (untrusted) guest, so every value is cleaned rather than
    /// rejected: control characters are removed and the value is cut at
    /// [`MAX_TEXT_BYTES`] on a character boundary. `PRETTY_NAME` is dropped if nothing usable is
    /// left of it.
    ///
    /// # Errors
    /// [`ManifestError::Field`] when no usable `ID` remains; a missing `VERSION_ID` (rolling
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
            let v = clean_text(v.trim().trim_matches(|c| c == '"' || c == '\''));
            match k.trim() {
                "ID" => id = Some(v),
                "VERSION_ID" => version_id = v,
                "PRETTY_NAME" => pretty = Some(v),
                _ => {}
            }
        }
        let id = id.filter(|i| !i.is_empty()).ok_or(ManifestError::Field {
            field: "distro.id",
            reason: "os-release has no usable ID",
        })?;
        Ok(Self {
            id,
            version_id,
            pretty_name: pretty.filter(|p| !p.is_empty()),
        })
    }
}

/// Remove control characters and cut at [`MAX_TEXT_BYTES`] on a character boundary.
fn clean_text(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars().filter(|c| !c.is_control()) {
        if out.len() + c.len_utf8() > MAX_TEXT_BYTES {
            break;
        }
        out.push(c);
    }
    out
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
    /// Directories or entries the pre-backup scan could not read (and so did not count).
    #[serde(default)]
    pub unreadable_entries: u64,
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
    /// Container configuration, filtered by [`restorable_container_config`] when the manifest is
    /// built (entries outside the allow-list are dropped, not fatal).
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
        docker_mode: Option<DockerMode>,
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
            docker_mode,
            container_config: restorable_container_config(input.container_config).config,
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
            if !config_entry_allowed(k, v) {
                return bad("container_config", "entry is not on the allow-list");
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

/// Whether a container configuration entry is on the allow-list and has an acceptable value.
///
/// | Key | Value |
/// |---|---|
/// | `limits.cpu` | a count or ranges of CPUs (`4`, `0-3`, `0,2`) |
/// | `limits.memory` | a size (`4GiB`, `512MB`) or a percentage (`50%`) |
/// | `limits.processes` | a positive integer, never `unlimited` or `0` |
/// | `root.size` | a size; the root disk size, flattened from the root device by the caller |
/// | `boot.autostart` | `true` or `false` |
/// | `security.nesting`, `security.syscalls.intercept.mknod`, `security.syscalls.intercept.setxattr` | `true` or `false` |
///
/// Everything else (`security.privileged`, `security.idmap.*`, `security.guestapi`, other
/// `security.syscalls.intercept.*`, `raw.*`, `volatile.*`, `image.*`, `user.*`, devices) is
/// refused: the manifest is writable by anyone holding a repository key, so it must never be able
/// to widen what a restored container may do.
#[must_use]
pub fn config_entry_allowed(key: &str, value: &str) -> bool {
    let is_bool = matches!(value, "true" | "false");
    match key {
        "limits.cpu" => {
            !value.is_empty()
                && value.len() <= 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b == b'-' || b == b',')
                && value.bytes().next().is_some_and(|b| b.is_ascii_digit())
        }
        "limits.memory" => is_size(value, true),
        "root.size" => is_size(value, false),
        "limits.processes" => {
            value.len() <= 9
                && !value.starts_with('0')
                && !value.is_empty()
                && value.bytes().all(|b| b.is_ascii_digit())
        }
        "boot.autostart"
        | "security.nesting"
        | "security.syscalls.intercept.mknod"
        | "security.syscalls.intercept.setxattr" => is_bool,
        _ => false,
    }
}

fn is_size(v: &str, allow_percent: bool) -> bool {
    if v.is_empty() || v.len() > 32 {
        return false;
    }
    let digits = v.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 || digits > 15 {
        return false;
    }
    let (num, unit) = v.split_at(digits);
    if num.starts_with('0') && num.len() > 1 {
        return false;
    }
    if unit == "%" {
        return allow_percent && num.parse::<u32>().is_ok_and(|n| (1..=100).contains(&n));
    }
    matches!(
        unit,
        "" | "B"
            | "kB"
            | "MB"
            | "GB"
            | "TB"
            | "PB"
            | "EB"
            | "KiB"
            | "MiB"
            | "GiB"
            | "TiB"
            | "PiB"
            | "EiB"
    )
}

/// Result of [`restorable_container_config`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RestorableConfig {
    /// The entries that passed the allow-list.
    pub config: BTreeMap<String, String>,
    /// How many entries were dropped (never fatal).
    pub dropped: usize,
}

/// Keep only the container configuration entries on the allow-list ([`config_entry_allowed`]);
/// count the rest. Never fails: a hostile or odd entry costs that entry, not the backup.
pub fn restorable_container_config<I, K, V>(config: I) -> RestorableConfig
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: AsRef<str>,
{
    let mut out = RestorableConfig::default();
    for (k, v) in config {
        if config_entry_allowed(k.as_ref(), v.as_ref()) {
            let _ = out
                .config
                .insert(k.as_ref().to_owned(), v.as_ref().to_owned());
        } else {
            out.dropped += 1;
        }
    }
    out
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
            container_config: restorable_container_config([
                ("limits.cpu", "4"),
                ("security.idmap.isolated", "true"),
                ("volatile.eth0.hwaddr", "00:16:3e:aa:bb:cc"),
                ("image.os", "ubuntu"),
            ])
            .config,
        }
    }

    fn sample() -> Manifest {
        Manifest::new(
            input(),
            Some(DockerMode::Light),
            "2026-11-26T03:00:00Z".parse().unwrap(),
            SourceSizes {
                files: 70_575,
                directories: 9_000,
                bytes: 2_439_600_000,
                excluded_paths: 53,
                unreadable_entries: 0,
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
            Manifest::new(i, None, Timestamp::UNIX_EPOCH, SourceSizes::default()),
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
    fn container_config_allow_list() {
        let r = restorable_container_config([
            ("limits.cpu", "2"),
            ("limits.memory", "4GiB"),
            ("limits.processes", "4096"),
            ("root.size", "50GB"),
            ("boot.autostart", "true"),
            ("security.nesting", "true"),
            ("security.syscalls.intercept.mknod", "false"),
            ("security.syscalls.intercept.setxattr", "true"),
            // refused keys
            ("security.privileged", "true"),
            ("security.idmap.isolated", "false"),
            ("security.idmap.base", "0"),
            ("security.guestapi", "true"),
            ("security.syscalls.intercept.bpf", "true"),
            ("raw.lxc", "lxc.cap.drop ="),
            ("volatile.base_image", "abc"),
            ("user.foo", "bar"),
            // right keys, refused values
            ("limits.processes", "unlimited"),
            ("limits.cpu", "all\nsecurity.privileged=true"),
            ("limits.memory", "lots"),
        ]);
        assert_eq!(r.dropped, 11);
        assert_eq!(r.config.len(), 8);
        assert_eq!(r.config["limits.processes"], "4096");
        for bad in ["0", "unlimited", "-1", "", "00", "1000000000", "1 2"] {
            assert!(!config_entry_allowed("limits.processes", bad), "{bad:?}");
        }
        for bad in ["yes", "1", "True", "true\n"] {
            assert!(!config_entry_allowed("security.nesting", bad), "{bad:?}");
        }
        assert!(config_entry_allowed("limits.memory", "50%"));
        assert!(!config_entry_allowed("limits.memory", "150%"));
        assert!(!config_entry_allowed("root.size", "50%"));
    }

    #[test]
    fn parsing_enforces_the_allow_list() {
        // The manifest is writable by any key holder: a restore that parses it must not see
        // dangerous configuration, even in an otherwise valid document.
        let mut v: serde_json::Value = serde_json::from_str(&sample().to_json().unwrap()).unwrap();
        v["container_config"]["security.privileged"] = "true".into();
        assert!(matches!(
            Manifest::from_slice(v.to_string().as_bytes()),
            Err(ManifestError::Field {
                field: "container_config",
                ..
            })
        ));
        // Building from hostile input drops entries instead of failing.
        let mut i = input();
        i.container_config
            .insert("security.privileged".into(), "true".into());
        i.container_config
            .insert("limits.cpu".into(), "a\nb".into());
        let m = Manifest::new(i, None, Timestamp::UNIX_EPOCH, SourceSizes::default()).unwrap();
        assert!(!m.container_config.contains_key("security.privileged"));
        assert!(!m.container_config.contains_key("limits.cpu"));
    }

    #[test]
    fn hostile_os_release_is_cleaned_not_fatal() {
        let long = "é".repeat(500);
        let text =
            format!("ID=\"ub\u{7}untu\"\nVERSION_ID={long}\nPRETTY_NAME=\"\u{1b}[31m\u{7}\"\n");
        let d = Distro::from_os_release(&text).unwrap();
        assert_eq!(d.id, "ubuntu");
        assert!(d.version_id.len() <= MAX_TEXT_BYTES && d.version_id.chars().all(|c| c == 'é'));
        assert_eq!(d.pretty_name.as_deref(), Some("[31m"));
        let m = Manifest::new(
            ManifestInput {
                distro: d,
                ..input()
            },
            None,
            Timestamp::UNIX_EPOCH,
            SourceSizes::default(),
        );
        assert!(m.is_ok());
        let d = Distro::from_os_release("ID=\"\u{7}\"\nPRETTY_NAME=\u{7}\n");
        assert!(d.is_err());
        let d = Distro::from_os_release("ID=x\nPRETTY_NAME=\u{7}\n").unwrap();
        assert_eq!(d.pretty_name, None);
    }
}
