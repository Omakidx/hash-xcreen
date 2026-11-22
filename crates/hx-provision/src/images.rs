//! The signed prebuilt-images manifest (contract C2/C8): parsing, validation and selection.
//!
//! The agent's privileged daemon and the image-CI tool share this code, so what CI publishes is
//! exactly what the agent accepts. The manifest is authenticated by a minisign signature that is
//! checked elsewhere; everything in it is still validated here, because the signature proves who
//! wrote it, not that it is well formed.
//!
//! An entry is used only when its `recipe_digest` equals the [`crate::Plan::build_digest`] of the
//! recipe embedded in the running agent: compatibility is bound by content, never by date.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::catalog::RecipeId;

/// Manifest `schema` this code understands.
pub const SCHEMA: u32 = 1;
/// Manifest `kind`.
pub const KIND: &str = "hx-images";
/// Only image format: a unified Incus image tarball (metadata and rootfs in one file).
pub const FORMAT_UNIFIED: &str = "incus-unified";
/// Largest image file: 4 GiB.
pub const MAX_IMAGE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Largest unpacked size: 64 GiB.
pub const MAX_UNPACKED_BYTES: u64 = 64 * 1024 * 1024 * 1024;
/// Largest single part: 1900 MiB (GitHub allows under 2 GiB per release asset).
pub const MAX_PART_BYTES: u64 = 1900 * 1024 * 1024;
/// Most parts of one image.
pub const MAX_PARTS: usize = 4;
/// Most entries in one manifest.
pub const MAX_ENTRIES: usize = 32;
/// Largest manifest document accepted by [`ImagesManifest::parse`]: 1 MiB.
pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
/// How far ahead of the clock a timestamp may be: 24 hours.
pub const MAX_CLOCK_SKEW_SECS: u64 = 24 * 60 * 60;
/// An entry older than this is not used online: 30 days.
pub const MAX_AGE_SECS: u64 = 30 * 24 * 60 * 60;
/// Allowed `compression` values.
pub const COMPRESSIONS: [&str; 3] = ["zstd", "gzip", "xz"];

/// Why a manifest was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ImagesError {
    /// Not JSON of the expected shape (unknown fields included).
    #[error("images manifest is not valid: {0}")]
    Parse(String),
    /// A rule was broken.
    #[error("images manifest {location}: {reason}")]
    Invalid {
        /// `envelope` or `images[<n>].<field>`.
        location: String,
        /// What is wrong.
        reason: String,
    },
}

fn invalid<T>(location: impl Into<String>, reason: impl Into<String>) -> Result<T, ImagesError> {
    Err(ImagesError::Invalid {
        location: location.into(),
        reason: reason.into(),
    })
}

/// One part of a split image file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Part {
    /// Size in bytes.
    pub size: u64,
    /// Lower-case hex SHA-256 of the part.
    pub sha256: String,
}

/// One published image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageEntry {
    /// Recipe name, `<distro>-<desktop>-<preset>`; one of [`RecipeId::all`].
    pub recipe: String,
    /// Distro; must agree with `recipe`.
    pub distro: String,
    /// Desktop; must agree with `recipe`.
    pub desktop: String,
    /// Preset; must agree with `recipe`.
    pub preset: String,
    /// [`crate::Plan::build_digest`] of the recipe the image was built from.
    pub recipe_digest: String,
    /// `YYYYMMDD.N`.
    pub build_id: String,
    /// Unix time the image was built.
    pub created: u64,
    /// Oldest agent version that may use the image (a format guard only).
    pub min_agent: String,
    /// Always [`FORMAT_UNIFIED`].
    pub format: String,
    /// One of [`COMPRESSIONS`].
    pub compression: String,
    /// Alias of the base image the build started from (informational).
    pub base_alias: String,
    /// Exactly [`file_name`] of the recipe and build id.
    pub file: String,
    /// Size of the whole file in bytes.
    pub size: u64,
    /// Lower-case hex SHA-256 of the whole file; it is also the Incus fingerprint.
    pub sha256: String,
    /// Space the image takes once unpacked, in bytes.
    pub unpacked_size: u64,
    /// The file as 1 to [`MAX_PARTS`] byte-split parts, in order.
    pub parts: Vec<Part>,
}

/// The images manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImagesManifest {
    /// Always [`SCHEMA`].
    pub schema: u32,
    /// Always [`KIND`].
    pub kind: String,
    /// `x86_64` or `aarch64`; must be the host's.
    pub arch: String,
    /// Unix time the manifest was signed (the online replay counter).
    pub timestamp: u64,
    /// At most [`MAX_ENTRIES`] images.
    pub images: Vec<ImageEntry>,
}

/// `<distro>-<desktop>-<preset>`.
pub fn recipe_name(id: RecipeId) -> String {
    format!("{}-{}-{}", id.distro, id.desktop, id.preset)
}

/// The recipe a name denotes, if it is one of [`RecipeId::all`].
pub fn recipe_by_name(name: &str) -> Option<RecipeId> {
    RecipeId::all()
        .into_iter()
        .find(|r| recipe_name(*r) == name)
}

/// The image file name: `hx-image-<recipe>-<build_id>.img`.
pub fn file_name(recipe: RecipeId, build_id: &str) -> String {
    format!("hx-image-{}-{build_id}.img", recipe_name(recipe))
}

/// Name of part `index` of `file`: `<file>.p<index>`.
pub fn part_file_name(file: &str, index: usize) -> String {
    format!("{file}.p{index}")
}

/// Name of the manifest asset for `arch`: `images-manifest-<arch>.json`.
pub fn manifest_file_name(arch: &str) -> String {
    format!("images-manifest-{arch}.json")
}

/// A parsed agent version (`1.2.3` or `1.2.3-rc.4`) with release ordering: a pre-release sorts
/// before its release, and `alpha` < `beta` < `rc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    major: u32,
    minor: u32,
    patch: u32,
    /// `(kind, n)`: alpha 0, beta 1, rc 2, release 3.
    pre: (u8, u32),
}

impl Version {
    /// Parse `^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(-(alpha|beta|rc)\.[0-9]{1,4})?$` (the update
    /// manifest's version rule).
    pub fn parse(s: &str) -> Option<Version> {
        fn num(s: &str) -> Option<u32> {
            if s.is_empty() || s.len() > 4 || !s.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            s.parse().ok()
        }
        let (core, pre) = match s.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (s, None),
        };
        let mut it = core.split('.');
        let (major, minor, patch) = (num(it.next()?)?, num(it.next()?)?, num(it.next()?)?);
        if it.next().is_some() {
            return None;
        }
        let pre = match pre {
            None => (3, 0),
            Some(p) => {
                let (kind, n) = p.split_once('.')?;
                let kind = match kind {
                    "alpha" => 0,
                    "beta" => 1,
                    "rc" => 2,
                    _ => return None,
                };
                (kind, num(n)?)
            }
        };
        Some(Version {
            major,
            minor,
            patch,
            pre,
        })
    }
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `^[0-9]{8}\.[0-9]{1,2}$`
fn is_build_id(s: &str) -> bool {
    match s.split_once('.') {
        Some((d, n)) => {
            d.len() == 8
                && d.bytes().all(|b| b.is_ascii_digit())
                && (1..=2).contains(&n.len())
                && n.bytes().all(|b| b.is_ascii_digit())
        }
        None => false,
    }
}

/// `^[a-z0-9][a-z0-9./_-]{0,63}$`
fn is_base_alias(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'/' | b'_' | b'-')
        })
}

impl ImageEntry {
    /// The recipe this entry is for.
    pub fn recipe_id(&self) -> Option<RecipeId> {
        recipe_by_name(&self.recipe)
    }

    /// Whether the entry is young enough to be used online (see [`MAX_AGE_SECS`]).
    pub fn is_fresh(&self, now: u64) -> bool {
        now.saturating_sub(self.created) <= MAX_AGE_SECS
    }

    /// Age in whole seconds (0 when `created` is in the future).
    pub fn age_secs(&self, now: u64) -> u64 {
        now.saturating_sub(self.created)
    }

    fn validate(&self, n: usize, timestamp: u64) -> Result<(), ImagesError> {
        let at = |f: &str| format!("images[{n}].{f}");
        let Some(id) = self.recipe_id() else {
            return invalid(at("recipe"), "not a known recipe");
        };
        if self.distro != id.distro.as_str() {
            return invalid(at("distro"), "does not match the recipe");
        }
        if self.desktop != id.desktop.as_str() {
            return invalid(at("desktop"), "does not match the recipe");
        }
        if self.preset != id.preset.as_str() {
            return invalid(at("preset"), "does not match the recipe");
        }
        if !is_hex64(&self.recipe_digest) {
            return invalid(at("recipe_digest"), "must be 64 lower-case hex digits");
        }
        if !is_build_id(&self.build_id) {
            return invalid(at("build_id"), "must match YYYYMMDD.N");
        }
        if self.created > timestamp {
            return invalid(at("created"), "is later than the manifest timestamp");
        }
        if Version::parse(&self.min_agent).is_none() {
            return invalid(at("min_agent"), "is not a version");
        }
        if self.format != FORMAT_UNIFIED {
            return invalid(at("format"), "must be `incus-unified`");
        }
        if !COMPRESSIONS.contains(&self.compression.as_str()) {
            return invalid(at("compression"), "must be zstd, gzip or xz");
        }
        if !is_base_alias(&self.base_alias) {
            return invalid(at("base_alias"), "is not a plain image alias");
        }
        if self.file != file_name(id, &self.build_id) {
            return invalid(at("file"), "is not the canonical file name");
        }
        if !(1..=MAX_IMAGE_BYTES).contains(&self.size) {
            return invalid(at("size"), "must be 1 byte to 4 GiB");
        }
        if !is_hex64(&self.sha256) {
            return invalid(at("sha256"), "must be 64 lower-case hex digits");
        }
        if !(self.size..=MAX_UNPACKED_BYTES).contains(&self.unpacked_size) {
            return invalid(at("unpacked_size"), "must be between size and 64 GiB");
        }
        if self.parts.is_empty() || self.parts.len() > MAX_PARTS {
            return invalid(at("parts"), "must hold 1 to 4 parts");
        }
        let mut sum: u64 = 0;
        for (i, p) in self.parts.iter().enumerate() {
            if !(1..=MAX_PART_BYTES).contains(&p.size) {
                return invalid(
                    format!("images[{n}].parts[{i}].size"),
                    "must be 1 byte to 1900 MiB",
                );
            }
            if !is_hex64(&p.sha256) {
                return invalid(
                    format!("images[{n}].parts[{i}].sha256"),
                    "must be 64 lower-case hex digits",
                );
            }
            sum = sum.saturating_add(p.size);
        }
        if sum != self.size {
            return invalid(at("parts"), "sizes do not add up to size");
        }
        if self.parts.len() == 1 && self.parts[0].sha256 != self.sha256 {
            return invalid(at("parts"), "the only part must carry the file's sha256");
        }
        Ok(())
    }
}

impl ImagesManifest {
    /// Parse a manifest document. Refuses more than [`MAX_MANIFEST_BYTES`], unknown fields and
    /// wrong types. Call [`ImagesManifest::validate`] on the result before using it.
    pub fn parse(bytes: &[u8]) -> Result<Self, ImagesError> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(ImagesError::Parse("document is larger than 1 MiB".into()));
        }
        serde_json::from_slice(bytes).map_err(|e| ImagesError::Parse(e.to_string()))
    }

    /// Compact JSON, as published.
    pub fn to_json(&self) -> Result<String, ImagesError> {
        serde_json::to_string(self).map_err(|e| ImagesError::Parse(e.to_string()))
    }

    /// Check every rule that needs no history: envelope, entries, sizes and parts.
    /// `arch` is the host's architecture; `now` is Unix time. The replay counter (the timestamp
    /// must not go backwards) is the caller's, because it needs persisted state.
    pub fn validate(&self, arch: &str, now: u64) -> Result<(), ImagesError> {
        if self.schema != SCHEMA {
            return invalid("envelope", "schema must be 1");
        }
        if self.kind != KIND {
            return invalid("envelope", "kind must be `hx-images`");
        }
        if self.arch != arch {
            return invalid("envelope", "arch is not this host's");
        }
        if self.timestamp > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
            return invalid("envelope", "timestamp is more than 24 h ahead of the clock");
        }
        if self.images.len() > MAX_ENTRIES {
            return invalid("envelope", "more than 32 images");
        }
        let mut seen = BTreeSet::new();
        for (n, e) in self.images.iter().enumerate() {
            e.validate(n, self.timestamp)?;
            if !seen.insert((e.recipe.as_str(), e.build_id.as_str())) {
                return invalid(format!("images[{n}]"), "duplicate recipe and build_id");
            }
        }
        Ok(())
    }

    /// The entry to use for `recipe`: its `recipe_digest` equals `digest` (the embedded recipe's
    /// [`crate::Plan::build_digest`]) and its `min_agent` is at most `agent_ver`; the newest
    /// `created` wins (then the larger `build_id`). Freshness is not checked here
    /// ([`ImageEntry::is_fresh`]). An unparsable `agent_ver` selects nothing.
    pub fn select(&self, recipe: RecipeId, digest: &str, agent_ver: &str) -> Option<&ImageEntry> {
        let agent = Version::parse(agent_ver)?;
        let name = recipe_name(recipe);
        self.images
            .iter()
            .filter(|e| e.recipe == name && e.recipe_digest == digest)
            .filter(|e| Version::parse(&e.min_agent).is_some_and(|m| m <= agent))
            .max_by(|a, b| (a.created, &a.build_id).cmp(&(b.created, &b.build_id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{Desktop, Distro, Preset};

    const NOW: u64 = 1_795_000_000;
    const D: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const H: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn rid() -> RecipeId {
        RecipeId {
            distro: Distro::Ubuntu2404,
            desktop: Desktop::Xfce,
            preset: Preset::Basic,
        }
    }

    fn entry() -> ImageEntry {
        ImageEntry {
            recipe: "ubuntu-24.04-xfce-basic".into(),
            distro: "ubuntu-24.04".into(),
            desktop: "xfce".into(),
            preset: "basic".into(),
            recipe_digest: D.into(),
            build_id: "20261123.1".into(),
            created: NOW - 1000,
            min_agent: "0.9.0".into(),
            format: FORMAT_UNIFIED.into(),
            compression: "zstd".into(),
            base_alias: "ubuntu/24.04".into(),
            file: "hx-image-ubuntu-24.04-xfce-basic-20261123.1.img".into(),
            size: 912_345_678,
            sha256: H.into(),
            unpacked_size: 3_456_789_012,
            parts: vec![Part {
                size: 912_345_678,
                sha256: H.into(),
            }],
        }
    }

    fn manifest() -> ImagesManifest {
        ImagesManifest {
            schema: 1,
            kind: "hx-images".into(),
            arch: "x86_64".into(),
            timestamp: NOW,
            images: vec![entry()],
        }
    }

    fn check(m: &ImagesManifest) -> Result<(), ImagesError> {
        m.validate("x86_64", NOW)
    }

    fn rejects(mutate: impl FnOnce(&mut ImagesManifest), needle: &str) {
        let mut m = manifest();
        mutate(&mut m);
        let err = check(&m).expect_err(needle).to_string();
        assert!(err.contains(needle), "{err} should mention {needle}");
    }

    #[test]
    fn the_design_example_is_valid_and_round_trips() {
        let m = manifest();
        check(&m).unwrap();
        let json = m.to_json().unwrap();
        assert_eq!(ImagesManifest::parse(json.as_bytes()).unwrap(), m);
    }

    #[test]
    fn envelope_rules() {
        rejects(|m| m.schema = 2, "schema");
        rejects(|m| m.kind = "hx-update".into(), "kind");
        rejects(|m| m.arch = "aarch64".into(), "arch");
        rejects(|m| m.timestamp = NOW + MAX_CLOCK_SKEW_SECS + 1, "timestamp");
        let mut m = manifest();
        m.timestamp = NOW + MAX_CLOCK_SKEW_SECS;
        m.images[0].created = NOW;
        check(&m).unwrap();
        rejects(
            |m| {
                let e = m.images[0].clone();
                m.images = (0..=MAX_ENTRIES)
                    .map(|i| ImageEntry {
                        build_id: format!("20261123.{}", i % 100),
                        ..e.clone()
                    })
                    .collect();
                // build ids repeat past 32 only through the modulo, which is fine here
                for (i, e) in m.images.iter_mut().enumerate() {
                    e.build_id = format!("{:08}.{}", 20_261_100 + i / 10, i % 10);
                    e.file = file_name(rid(), &e.build_id);
                }
            },
            "more than 32",
        );
    }

    #[test]
    fn exactly_max_entries_is_fine() {
        let mut m = manifest();
        let e = m.images[0].clone();
        m.images = (0..MAX_ENTRIES)
            .map(|i| {
                let build_id = format!("{:08}.{}", 20_261_100 + i / 10, i % 10);
                ImageEntry {
                    file: file_name(rid(), &build_id),
                    build_id,
                    ..e.clone()
                }
            })
            .collect();
        check(&m).unwrap();
    }

    #[test]
    fn recipe_and_its_parts_must_agree() {
        rejects(|m| m.images[0].recipe = "arch-xfce-basic".into(), "recipe");
        rejects(
            |m| m.images[0].recipe = "ubuntu-24.04-xfce-basic ".into(),
            "recipe",
        );
        rejects(|m| m.images[0].distro = "debian-13".into(), "distro");
        rejects(|m| m.images[0].desktop = "kde".into(), "desktop");
        rejects(|m| m.images[0].preset = "developer".into(), "preset");
    }

    #[test]
    fn digests_and_hashes_are_lower_case_hex() {
        rejects(
            |m| m.images[0].recipe_digest = D.to_uppercase(),
            "recipe_digest",
        );
        rejects(
            |m| m.images[0].recipe_digest = D[..63].into(),
            "recipe_digest",
        );
        rejects(|m| m.images[0].sha256 = format!("{}g", &H[..63]), "sha256");
        rejects(
            |m| {
                m.images[0].parts[0].sha256 = D.into();
                m.images[0].parts.push(Part {
                    size: 1,
                    sha256: H.into(),
                });
                m.images[0].parts[0].size = m.images[0].size - 1;
                m.images[0].parts[1].sha256 = "xyz".into();
            },
            "parts[1].sha256",
        );
    }

    #[test]
    fn build_id_shape() {
        for bad in [
            "2026112.1",
            "20261123",
            "20261123.",
            "20261123.123",
            "2026112a.1",
            "20261123.1.2",
            "",
        ] {
            rejects(|m| m.images[0].build_id = bad.into(), "build_id");
        }
        for good in ["20261123.1", "20261123.12", "20261123.0"] {
            let mut m = manifest();
            m.images[0].build_id = good.into();
            m.images[0].file = file_name(rid(), good);
            check(&m).unwrap();
        }
    }

    #[test]
    fn created_is_not_after_the_timestamp() {
        rejects(|m| m.images[0].created = NOW + 1, "created");
        let mut m = manifest();
        m.images[0].created = NOW;
        check(&m).unwrap();
    }

    #[test]
    fn versions_follow_the_update_rule() {
        for ok in [
            "0.9.0",
            "1.2.3",
            "9999.9999.9999",
            "1.0.0-rc.1",
            "1.0.0-alpha.0",
            "1.0.0-beta.9999",
        ] {
            assert!(Version::parse(ok).is_some(), "{ok}");
        }
        for bad in [
            "1.2",
            "1.2.3.4",
            "01234.0.0",
            "1.2.x",
            "v1.2.3",
            "1.2.3-",
            "1.2.3-rc",
            "1.2.3-gamma.1",
            "1.2.3-rc.12345",
            "1.2.3 ",
            "",
            "-1.2.3",
            "1..3",
        ] {
            assert!(Version::parse(bad).is_none(), "{bad}");
        }
        rejects(|m| m.images[0].min_agent = "1.2".into(), "min_agent");
    }

    #[test]
    fn version_ordering() {
        let v = |s| Version::parse(s).unwrap();
        assert!(v("1.0.0-alpha.1") < v("1.0.0-alpha.2"));
        assert!(v("1.0.0-alpha.9") < v("1.0.0-beta.1"));
        assert!(v("1.0.0-beta.9") < v("1.0.0-rc.1"));
        assert!(v("1.0.0-rc.9") < v("1.0.0"));
        assert!(v("1.0.0") < v("1.0.1"));
        assert!(v("1.9.9") < v("1.10.0"));
    }

    #[test]
    fn format_and_compression() {
        rejects(|m| m.images[0].format = "incus-split".into(), "format");
        rejects(|m| m.images[0].compression = "bzip2".into(), "compression");
        for c in COMPRESSIONS {
            let mut m = manifest();
            m.images[0].compression = c.into();
            check(&m).unwrap();
        }
    }

    #[test]
    fn base_alias_is_a_plain_alias() {
        for bad in ["", "-x", "ubuntu/24.04 ", "Ubuntu", "a;b", "../x\n"] {
            rejects(|m| m.images[0].base_alias = bad.into(), "base_alias");
        }
    }

    #[test]
    fn file_name_is_exact() {
        assert_eq!(
            file_name(rid(), "20261123.1"),
            "hx-image-ubuntu-24.04-xfce-basic-20261123.1.img"
        );
        assert_eq!(part_file_name("a.img", 2), "a.img.p2");
        assert_eq!(manifest_file_name("x86_64"), "images-manifest-x86_64.json");
        rejects(|m| m.images[0].file = "../hx-image.img".into(), "file");
        rejects(
            |m| m.images[0].file = "hx-image-ubuntu-24.04-xfce-basic-20261123.2.img".into(),
            "file",
        );
        rejects(|m| m.images[0].file.push_str(".p0"), "file");
    }

    #[test]
    fn size_bounds() {
        rejects(|m| m.images[0].size = 0, "size");
        rejects(|m| m.images[0].size = MAX_IMAGE_BYTES + 1, "size");
        rejects(
            |m| m.images[0].unpacked_size = m.images[0].size - 1,
            "unpacked_size",
        );
        rejects(
            |m| m.images[0].unpacked_size = MAX_UNPACKED_BYTES + 1,
            "unpacked_size",
        );
        let mut m = manifest();
        m.images[0].unpacked_size = m.images[0].size;
        check(&m).unwrap();
        m.images[0].unpacked_size = MAX_UNPACKED_BYTES;
        check(&m).unwrap();
    }

    fn split(m: &mut ImagesManifest, sizes: &[u64]) {
        let e = &mut m.images[0];
        e.size = sizes.iter().sum();
        e.unpacked_size = e.size;
        e.parts = sizes
            .iter()
            .map(|s| Part {
                size: *s,
                sha256: D.into(),
            })
            .collect();
    }

    #[test]
    fn parts_rules() {
        rejects(|m| m.images[0].parts.clear(), "parts");
        rejects(|m| split(m, &[10, 10, 10, 10, 10]), "parts");
        rejects(|m| split(m, &[MAX_PART_BYTES + 1]), "parts[0].size");
        rejects(|m| split(m, &[10, 0]), "parts[1].size");
        rejects(|m| m.images[0].parts[0].size += 1, "add up");
        rejects(
            |m| {
                split(m, &[10, 20]);
                m.images[0].size = 31;
                m.images[0].unpacked_size = 31;
            },
            "add up",
        );
        rejects(|m| m.images[0].parts[0].sha256 = D.into(), "only part");
        // parts at the cap, summing to exactly 4 GiB, are fine
        let mut m = manifest();
        split(
            &mut m,
            &[
                MAX_PART_BYTES,
                MAX_PART_BYTES,
                MAX_IMAGE_BYTES - 2 * MAX_PART_BYTES,
            ],
        );
        check(&m).unwrap();
        // a sum above 4 GiB fails the size rule even with valid parts
        let mut m = manifest();
        split(
            &mut m,
            &[
                MAX_PART_BYTES,
                MAX_PART_BYTES,
                MAX_PART_BYTES - 1,
                300 * 1024 * 1024,
            ],
        );
        assert!(check(&m).is_err());
    }

    #[test]
    fn parts_sum_cannot_overflow() {
        rejects(
            |m| {
                m.images[0].parts = vec![
                    Part {
                        size: MAX_PART_BYTES,
                        sha256: D.into(),
                    },
                    Part {
                        size: u64::MAX,
                        sha256: D.into(),
                    },
                ];
            },
            "parts[1].size",
        );
    }

    #[test]
    fn duplicates_are_refused() {
        rejects(
            |m| {
                let e = m.images[0].clone();
                m.images.push(e);
            },
            "duplicate",
        );
    }

    #[test]
    fn parse_denies_unknown_fields_and_oversize() {
        let good = manifest().to_json().unwrap();
        let extra = good.replacen("{\"schema\"", "{\"x\":1,\"schema\"", 1);
        assert!(matches!(
            ImagesManifest::parse(extra.as_bytes()),
            Err(ImagesError::Parse(_))
        ));
        let nested = good.replacen("\"recipe\":", "\"x\":1,\"recipe\":", 1);
        assert!(ImagesManifest::parse(nested.as_bytes()).is_err());
        let part = good.replace("\"parts\":[{", "\"parts\":[{\"x\":1,");
        assert!(ImagesManifest::parse(part.as_bytes()).is_err());
        assert!(ImagesManifest::parse(b"[]").is_err());
        assert!(ImagesManifest::parse(b"").is_err());
        let big = vec![b' '; MAX_MANIFEST_BYTES + 1];
        assert!(ImagesManifest::parse(&big).is_err());
        let wrong_type = good.replace("\"timestamp\":1795000000", "\"timestamp\":\"x\"");
        assert!(ImagesManifest::parse(wrong_type.as_bytes()).is_err());
        let negative = good.replace("\"timestamp\":1795000000", "\"timestamp\":-1");
        assert!(ImagesManifest::parse(negative.as_bytes()).is_err());
    }

    #[test]
    fn select_matches_recipe_digest_and_agent() {
        let mut m = manifest();
        let mut newer = entry();
        newer.build_id = "20261124.1".into();
        newer.file = file_name(rid(), "20261124.1");
        newer.created = NOW - 10;
        let mut other_digest = entry();
        other_digest.build_id = "20261125.1".into();
        other_digest.file = file_name(rid(), "20261125.1");
        other_digest.recipe_digest = H.into();
        other_digest.created = NOW;
        let mut too_new = entry();
        too_new.build_id = "20261126.1".into();
        too_new.file = file_name(rid(), "20261126.1");
        too_new.min_agent = "2.0.0".into();
        too_new.created = NOW;
        m.images.extend([newer, other_digest, too_new]);
        check(&m).unwrap();

        let pick = m.select(rid(), D, "1.0.0").unwrap();
        assert_eq!(
            pick.build_id, "20261124.1",
            "newest matching, skipping other digest and min_agent"
        );
        assert_eq!(m.select(rid(), D, "2.0.0").unwrap().build_id, "20261126.1");
        assert_eq!(m.select(rid(), D, "0.9.0").unwrap().build_id, "20261124.1");
        assert!(m.select(rid(), D, "0.8.9").is_none());
        assert!(m.select(rid(), D, "nonsense").is_none());
        assert_eq!(m.select(rid(), H, "1.0.0").unwrap().build_id, "20261125.1");
        assert!(m.select(rid(), &"c".repeat(64), "1.0.0").is_none());
        let other = RecipeId {
            preset: Preset::Developer,
            ..rid()
        };
        assert!(m.select(other, D, "1.0.0").is_none());
    }

    #[test]
    fn select_prefers_the_pre_release_guard_correctly() {
        let mut m = manifest();
        m.images[0].min_agent = "1.0.0".into();
        assert!(
            m.select(rid(), D, "1.0.0-rc.1").is_none(),
            "a pre-release is older than its release"
        );
        assert!(m.select(rid(), D, "1.0.0").is_some());
    }

    #[test]
    fn freshness_is_thirty_days() {
        let e = entry();
        assert!(e.is_fresh(e.created + MAX_AGE_SECS));
        assert!(!e.is_fresh(e.created + MAX_AGE_SECS + 1));
        assert!(
            e.is_fresh(e.created.saturating_sub(5)),
            "a future created is not stale"
        );
        assert_eq!(e.age_secs(e.created + 5), 5);
    }

    #[test]
    fn every_recipe_has_a_name_that_round_trips() {
        for r in RecipeId::all() {
            assert_eq!(recipe_by_name(&recipe_name(r)), Some(r));
        }
        assert_eq!(recipe_by_name(""), None);
        assert_eq!(recipe_by_name("ubuntu-24.04"), None);
    }
}
