//! `manifest` and `verify`: build the images manifest from the matrix cells' entries, and check a
//! manifest and its signature (optionally against an image file).
//!
//! `manifest [--entries DIR...] [--previous M --previous-sig S --pubkey K...] [--wanted FILE] [--drop R/B...]
//! --timestamp T --out M` reads `DIR/entry.json` of every cell (and re-hashes the image files next
//! to it, so what is published is what was built), carries over the still-wanted entries of the
//! previous manifest that no new entry replaces and that are within 30 days, validates the result
//! with the shared `hx_provision::images` rules and writes the compact JSON. It does not sign:
//! the minisign CLI does, in the `image-signing` job, and `verify` must accept the result.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use hx_provision::images::{
    self, ImageEntry, ImagesManifest, MAX_AGE_SECS, MAX_ENTRIES, MAX_MANIFEST_BYTES,
};

use crate::args::{Parsed, Spec};
use crate::build::{ARCH, ENTRY_FILE};
use crate::sign::{load_keys, verify_manifest};
use crate::util::{CliError, failed, now_unix, read_bounded, refused, sha256_file};

/// Options of `manifest`.
pub const MANIFEST_SPEC: Spec = Spec {
    values: &["previous", "previous-sig", "timestamp", "out", "wanted"],
    lists: &["entries", "pubkey", "drop"],
    flags: &[],
    positionals: 0,
};

/// Options of `verify`.
pub const VERIFY_SPEC: Spec = Spec {
    values: &["manifest", "sig", "image", "now"],
    lists: &["pubkey"],
    flags: &[],
    positionals: 0,
};

/// Read `DIR/entry.json` and check that the image files beside it match it (sizes and SHA-256 of
/// every part, and of the whole file when it is a single part).
pub fn load_entry(dir: &Path) -> Result<ImageEntry, CliError> {
    let bytes = read_bounded(&dir.join(ENTRY_FILE), 64 * 1024)?;
    let entry: ImageEntry = serde_json::from_slice(&bytes)
        .map_err(|e| failed(format!("{}/{ENTRY_FILE}: {e}", dir.display())))?;
    for (i, part) in entry.parts.iter().enumerate() {
        let name = if entry.parts.len() == 1 {
            entry.file.clone()
        } else {
            images::part_file_name(&entry.file, i)
        };
        let (sha, len) = sha256_file(&dir.join(&name))?;
        if len != part.size || sha != part.sha256 {
            return Err(failed(format!(
                "{}/{name} does not match its entry (size {len}, sha256 {sha})",
                dir.display()
            )));
        }
    }
    Ok(entry)
}

/// What the merge did, for the log.
#[derive(Debug, PartialEq, Eq, Default)]
pub struct Summary {
    /// Entries from this run's cells.
    pub new: usize,
    /// Entries of the previous manifest that were kept.
    pub carried: usize,
    /// Entries of the previous manifest that were dropped, with the reason.
    pub dropped: Vec<String>,
}

/// Merge `new` entries with the `previous` manifest's. A previous entry is carried over when no
/// new entry has the same recipe and digest, it is in `wanted` (when a set is given), and it is
/// at most 30 days old at `timestamp`. An entry named in `withdraw` (`recipe/build_id`) is removed
/// from the previous manifest (a withdrawal of a bad image; a name that matches nothing is an
/// error). If more than 32 would remain, the oldest carried entries go first. The timestamp must
/// not go backwards.
pub fn merge(
    new: Vec<ImageEntry>,
    previous: Option<&ImagesManifest>,
    wanted: Option<&BTreeSet<(String, String)>>,
    withdraw: &BTreeSet<String>,
    timestamp: u64,
    now: u64,
) -> Result<(ImagesManifest, Summary), CliError> {
    let mut summary = Summary {
        new: new.len(),
        ..Summary::default()
    };
    let covered: BTreeSet<(String, String)> = new
        .iter()
        .map(|e| (e.recipe.clone(), e.recipe_digest.clone()))
        .collect();
    let mut carried: Vec<ImageEntry> = Vec::new();
    if let Some(prev) = previous {
        if timestamp < prev.timestamp {
            return Err(refused(format!(
                "--timestamp {timestamp} is older than the previous manifest's {}: a client would refuse it as a replay",
                prev.timestamp
            )));
        }
        let mut withdrawn: BTreeSet<&str> = BTreeSet::new();
        for e in &prev.images {
            let key = (e.recipe.clone(), e.recipe_digest.clone());
            let label = format!("{} {}", e.recipe, e.build_id);
            let id = format!("{}/{}", e.recipe, e.build_id);
            if let Some(w) = withdraw.get(&id) {
                withdrawn.insert(w.as_str());
                summary.dropped.push(format!("{label}: withdrawn"));
            } else if covered.contains(&key) {
                summary
                    .dropped
                    .push(format!("{label}: replaced by a new build"));
            } else if wanted.is_some_and(|w| !w.contains(&key)) {
                summary
                    .dropped
                    .push(format!("{label}: its recipe digest is no longer wanted"));
            } else if timestamp.saturating_sub(e.created) > MAX_AGE_SECS {
                summary.dropped.push(format!("{label}: older than 30 days"));
            } else {
                carried.push(e.clone());
            }
        }
        if let Some(missing) = withdraw.iter().find(|w| !withdrawn.contains(w.as_str())) {
            return Err(refused(format!(
                "--drop {missing}: the previous manifest has no such image"
            )));
        }
    } else if !withdraw.is_empty() {
        return Err(CliError::Usage("--drop needs --previous".into()));
    }
    let mut total = new.len() + carried.len();
    if total > MAX_ENTRIES {
        carried.sort_by_key(|e| std::cmp::Reverse(e.created));
        while total > MAX_ENTRIES && !carried.is_empty() {
            if let Some(e) = carried.pop() {
                summary.dropped.push(format!(
                    "{} {}: over the {MAX_ENTRIES}-entry limit",
                    e.recipe, e.build_id
                ));
                total -= 1;
            }
        }
    }
    summary.carried = carried.len();
    let mut images: Vec<ImageEntry> = new.into_iter().chain(carried).collect();
    images.sort_by(|a, b| (&a.recipe, &a.build_id).cmp(&(&b.recipe, &b.build_id)));
    let m = ImagesManifest {
        schema: images::SCHEMA,
        kind: images::KIND.into(),
        arch: ARCH.into(),
        timestamp,
        images,
    };
    m.validate(ARCH, now)
        .map_err(|e| refused(format!("the merged manifest is not valid: {e}")))?;
    Ok((m, summary))
}

/// `--wanted FILE`: lines of `<recipe> <digest>` (the output of `digest --all`).
fn load_wanted(path: &Path) -> Result<BTreeSet<(String, String)>, CliError> {
    let text = String::from_utf8(read_bounded(path, 1 << 20)?)
        .map_err(|_| failed(format!("{} is not UTF-8", path.display())))?;
    let mut set = BTreeSet::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let mut w = line.split_whitespace();
        match (w.next(), w.next(), w.next()) {
            (Some(r), Some(d), None) => {
                set.insert((r.to_string(), d.to_string()));
            }
            _ => {
                return Err(failed(format!(
                    "{}: `{line}` is not `<recipe> <digest>`",
                    path.display()
                )));
            }
        }
    }
    Ok(set)
}

/// Run `manifest`.
pub fn run_manifest(p: &Parsed) -> Result<String, CliError> {
    let dirs = p.list("entries").unwrap_or(&[]);
    let timestamp: u64 = p
        .require("timestamp")?
        .parse()
        .map_err(|_| CliError::Usage("--timestamp must be Unix seconds".into()))?;
    let out = PathBuf::from(p.require("out")?);
    let now = now_unix();

    let mut new = Vec::new();
    for d in dirs {
        new.push(load_entry(Path::new(d))?);
    }
    let previous = match (p.get("previous"), p.get("previous-sig")) {
        (None, None) => None,
        (Some(m), Some(s)) => {
            let keys = load_keys(p.list("pubkey").ok_or_else(|| {
                CliError::Usage("--previous needs --pubkey to verify the previous manifest".into())
            })?)?;
            Some(verify_manifest(
                Path::new(m),
                Path::new(s),
                &keys,
                ARCH,
                now,
            )?)
        }
        _ => {
            return Err(CliError::Usage(
                "--previous and --previous-sig go together".into(),
            ));
        }
    };
    let wanted = p
        .get("wanted")
        .map(|w| load_wanted(Path::new(w)))
        .transpose()?;
    let withdraw: BTreeSet<String> = p.list("drop").unwrap_or(&[]).iter().cloned().collect();
    if new.is_empty() && previous.is_none() {
        return Err(CliError::Usage(
            "give --entries DIR..., or --previous to re-sign what is published".into(),
        ));
    }
    let (m, summary) = merge(
        new,
        previous.as_ref(),
        wanted.as_ref(),
        &withdraw,
        timestamp,
        now,
    )?;
    let json = m.to_json().map_err(|e| failed(e.to_string()))?;
    if json.len() > MAX_MANIFEST_BYTES {
        return Err(failed("the manifest is larger than 1 MiB"));
    }
    std::fs::write(&out, &json).map_err(|e| failed(format!("write {}: {e}", out.display())))?;
    let mut report = format!(
        "manifest {}: {} new, {} carried over, {} dropped\n",
        out.display(),
        summary.new,
        summary.carried,
        summary.dropped.len()
    );
    for d in &summary.dropped {
        report.push_str(&format!("  dropped {d}\n"));
    }
    Ok(report)
}

/// Run `verify`.
pub fn run_verify(p: &Parsed) -> Result<String, CliError> {
    let keys = load_keys(
        p.list("pubkey")
            .ok_or_else(|| CliError::Usage("--pubkey FILE is required".into()))?,
    )?;
    let now = match p.get("now") {
        Some(n) => n
            .parse()
            .map_err(|_| CliError::Usage("--now must be Unix seconds".into()))?,
        None => now_unix(),
    };
    let m = verify_manifest(
        Path::new(p.require("manifest")?),
        Path::new(p.require("sig")?),
        &keys,
        ARCH,
        now,
    )?;
    let mut report = format!(
        "ok: signature, trusted comment and rules verified; {} image(s), timestamp {}\n",
        m.images.len(),
        m.timestamp
    );
    if let Some(image) = p.get("image") {
        report.push_str(&check_image(&m, Path::new(image))?);
    }
    Ok(report)
}

/// The image file (the whole file, or one `.pN` part) must be one the manifest lists, with the
/// size and SHA-256 it states.
fn check_image(m: &ImagesManifest, image: &Path) -> Result<String, CliError> {
    let name = image
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| failed("--image has no file name"))?;
    let (sha, len) = sha256_file(image)?;
    for e in &m.images {
        let (want_size, want_sha, what) = if name == e.file {
            (e.size, &e.sha256, "image".to_string())
        } else if let Some(i) = (0..e.parts.len())
            .find(|i| e.parts.len() > 1 && name == images::part_file_name(&e.file, *i))
        {
            (e.parts[i].size, &e.parts[i].sha256, format!("part {i}"))
        } else {
            continue;
        };
        if len != want_size || &sha != want_sha {
            return Err(refused(format!(
                "{name} does not match the manifest (size {len} of {want_size}, sha256 {sha})"
            )));
        }
        return Ok(format!(
            "ok: {name} is the {what} of {} build {}\n",
            e.recipe, e.build_id
        ));
    }
    Err(refused(format!("{name} is not an image of this manifest")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hx_provision::images::{FORMAT_UNIFIED, Part};

    const NOW: u64 = 1_795_000_000;
    const DAY: u64 = 86_400;

    fn entry(recipe: &str, digest_char: char, build: &str, created: u64) -> ImageEntry {
        let id = images::recipe_by_name(recipe).unwrap();
        let sha = "c".repeat(64);
        ImageEntry {
            recipe: recipe.into(),
            distro: id.distro.as_str().into(),
            desktop: id.desktop.as_str().into(),
            preset: id.preset.as_str().into(),
            recipe_digest: digest_char.to_string().repeat(64),
            build_id: build.into(),
            created,
            min_agent: "0.1.0".into(),
            format: FORMAT_UNIFIED.into(),
            compression: "zstd".into(),
            base_alias: "ubuntu/24.04".into(),
            file: images::file_name(id, build),
            size: 1000,
            sha256: sha.clone(),
            unpacked_size: 4000,
            parts: vec![Part {
                size: 1000,
                sha256: sha,
            }],
        }
    }

    fn prev(entries: Vec<ImageEntry>, ts: u64) -> ImagesManifest {
        ImagesManifest {
            schema: 1,
            kind: "hx-images".into(),
            arch: ARCH.into(),
            timestamp: ts,
            images: entries,
        }
    }

    fn none() -> BTreeSet<String> {
        BTreeSet::new()
    }

    const R1: &str = "ubuntu-24.04-xfce-basic";
    const R2: &str = "debian-13-xfce-basic";

    #[test]
    fn a_new_build_replaces_the_previous_one_of_the_same_digest() {
        let p = prev(
            vec![entry(R1, 'a', "20261101.1", NOW - 10 * DAY)],
            NOW - 9 * DAY,
        );
        let n = entry(R1, 'a', "20261110.1", NOW - 10);
        let (m, s) = merge(vec![n], Some(&p), None, &none(), NOW, NOW).unwrap();
        assert_eq!(m.images.len(), 1);
        assert_eq!(m.images[0].build_id, "20261110.1");
        assert_eq!((s.new, s.carried, s.dropped.len()), (1, 0, 1));
    }

    #[test]
    fn a_failed_cell_keeps_its_previous_entry_while_it_is_young_and_wanted() {
        let keep = entry(R2, 'b', "20261101.1", NOW - 20 * DAY);
        let old = entry("debian-12-xfce-basic", 'c', "20261001.1", NOW - 40 * DAY);
        let unwanted = entry("debian-12-xfce-developer", 'd', "20261110.1", NOW - DAY);
        let p = prev(vec![keep.clone(), old, unwanted], NOW - DAY);
        let wanted: BTreeSet<(String, String)> = [
            (R1.to_string(), "a".repeat(64)),
            (R2.to_string(), "b".repeat(64)),
            ("debian-12-xfce-basic".to_string(), "c".repeat(64)),
        ]
        .into();
        let n = entry(R1, 'a', "20261120.1", NOW - 10);
        let (m, s) = merge(vec![n], Some(&p), Some(&wanted), &none(), NOW, NOW).unwrap();
        let names: Vec<&str> = m.images.iter().map(|e| e.recipe.as_str()).collect();
        assert_eq!(names, [R2, R1], "sorted by recipe name");
        assert_eq!(m.images[0], keep);
        assert_eq!((s.new, s.carried), (1, 1));
        assert!(s.dropped.iter().any(|d| d.contains("older than 30 days")));
        assert!(s.dropped.iter().any(|d| d.contains("no longer wanted")));
    }

    #[test]
    fn the_timestamp_never_goes_backwards() {
        let p = prev(vec![], NOW);
        let e = merge(
            vec![entry(R1, 'a', "20261120.1", NOW - 10)],
            Some(&p),
            None,
            &none(),
            NOW - 1,
            NOW,
        )
        .unwrap_err();
        assert!(matches!(e, CliError::Refused(_)));
    }

    #[test]
    fn an_entry_from_the_future_is_refused() {
        let e = merge(
            vec![entry(R1, 'a', "20261120.1", NOW + 100)],
            None,
            None,
            &none(),
            NOW,
            NOW,
        )
        .unwrap_err();
        assert!(matches!(e, CliError::Refused(_)), "{e:?}");
    }

    #[test]
    fn at_most_32_entries_the_oldest_carried_ones_go_first() {
        let old: Vec<ImageEntry> = (0..32u64)
            .map(|i| {
                entry(
                    R2,
                    'b',
                    &format!("20261101.{}", i + 1),
                    NOW - (i + 1) * 3600,
                )
            })
            .collect();
        let p = prev(old, NOW - 1);
        let n = entry(R1, 'a', "20261120.1", NOW - 10);
        let (m, s) = merge(vec![n], Some(&p), None, &none(), NOW, NOW).unwrap();
        assert_eq!(m.images.len(), MAX_ENTRIES);
        // the oldest carried entry (the largest i) was dropped
        assert!(m.images.iter().all(|e| e.build_id != "20261101.32"));
        assert_eq!((s.new, s.carried, s.dropped.len()), (1, 31, 1));
    }

    #[test]
    fn a_withdrawn_image_is_removed_and_a_typo_is_refused() {
        let bad = entry(R2, 'b', "20261110.1", NOW - DAY);
        let good = entry(R1, 'a', "20261110.1", NOW - DAY);
        let p = prev(vec![bad, good.clone()], NOW - DAY);
        let w: BTreeSet<String> = [format!("{R2}/20261110.1")].into();
        let (m, s) = merge(vec![], Some(&p), None, &w, NOW, NOW).unwrap();
        assert_eq!(m.images, [good]);
        assert_eq!((s.new, s.carried, s.dropped.len()), (0, 1, 1));
        assert!(s.dropped[0].contains("withdrawn"));
        let typo: BTreeSet<String> = [format!("{R2}/20261199.9")].into();
        let e = merge(vec![], Some(&p), None, &typo, NOW, NOW).unwrap_err();
        assert!(matches!(e, CliError::Refused(_)), "{e:?}");
        let e = merge(vec![], None, None, &w, NOW, NOW).unwrap_err();
        assert!(matches!(e, CliError::Usage(_)), "{e:?}");
    }

    #[test]
    fn wanted_file_syntax() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("w");
        std::fs::write(
            &f,
            format!("# c\n{R1} {}\n\n{R2} {}\n", "a".repeat(64), "b".repeat(64)),
        )
        .unwrap();
        assert_eq!(load_wanted(&f).unwrap().len(), 2);
        std::fs::write(&f, "one-word\n").unwrap();
        assert!(load_wanted(&f).is_err());
    }
}
