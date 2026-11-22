//! Shared helpers: errors and exit codes, recipe lookup, hashing and splitting files.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use hx_provision::images::{self, Part};
use hx_provision::{Catalog, Plan, RecipeId};
use sha2::{Digest, Sha256};

use crate::args::UsageError;

/// Why a command did not succeed. Each kind has its own exit status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    /// A command-line mistake: exit 2.
    Usage(String),
    /// The command ran and the answer is "no": drift between two desktops, a manifest or an image
    /// that does not verify. Exit 1.
    Refused(String),
    /// Something broke while running (Incus, the file system, a bad input file): exit 3.
    Failed(String),
}

impl CliError {
    /// The process exit status.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Refused(_) => 1,
            Self::Usage(_) => 2,
            Self::Failed(_) => 3,
        }
    }

    /// The message to print on stderr.
    pub fn message(&self) -> &str {
        match self {
            Self::Usage(m) | Self::Refused(m) | Self::Failed(m) => m,
        }
    }
}

impl From<UsageError> for CliError {
    fn from(e: UsageError) -> Self {
        Self::Usage(e.0)
    }
}

/// Shorthand for an operational failure.
pub fn failed(m: impl Into<String>) -> CliError {
    CliError::Failed(m.into())
}

/// Shorthand for a refusal.
pub fn refused(m: impl Into<String>) -> CliError {
    CliError::Refused(m.into())
}

/// The recipe named `name` (`ubuntu-24.04-xfce-basic`).
pub fn recipe(name: &str) -> Result<RecipeId, CliError> {
    images::recipe_by_name(name).ok_or_else(|| {
        let known: Vec<String> = RecipeId::all()
            .into_iter()
            .map(images::recipe_name)
            .collect();
        CliError::Usage(format!(
            "unknown recipe `{name}` (one of: {})",
            known.join(", ")
        ))
    })
}

/// The plan the digest is taken over: the embedded recipe, default-resolved (user `desk`, no
/// settings, no add-ons), exactly what the agent computes.
pub fn default_plan(id: RecipeId) -> Result<Plan, CliError> {
    Catalog::embedded().resolve(id, &[]).map_err(|e| {
        failed(format!(
            "recipe `{}` does not resolve: {e}",
            images::recipe_name(id)
        ))
    })
}

/// Lower-case hex.
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Unix time now.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `^[0-9]{8}\.[0-9]{1,2}$`, the build id syntax of the manifest.
pub fn valid_build_id(s: &str) -> bool {
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

/// SHA-256 (hex) and length of a file, read in 1 MiB blocks.
pub fn sha256_file(path: &Path) -> Result<(String, u64), CliError> {
    let mut f = File::open(path).map_err(|e| failed(format!("open {}: {e}", path.display())))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut len = 0u64;
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| failed(format!("read {}: {e}", path.display())))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        len += n as u64;
    }
    Ok((hex(&h.finalize()), len))
}

/// Read a small file, refusing more than `max` bytes.
pub fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>, CliError> {
    let f = File::open(path).map_err(|e| failed(format!("open {}: {e}", path.display())))?;
    let mut v = Vec::new();
    f.take(max + 1)
        .read_to_end(&mut v)
        .map_err(|e| failed(format!("read {}: {e}", path.display())))?;
    if v.len() as u64 > max {
        return Err(failed(format!(
            "{} is larger than {max} bytes",
            path.display()
        )));
    }
    Ok(v)
}

/// Split `src` into parts of at most `max_part` bytes, written as `<dir>/<file>.p0`, `.p1`, ...
/// Returns each part's size and SHA-256, in order.
pub fn split_file(
    src: &Path,
    dir: &Path,
    file: &str,
    max_part: u64,
) -> Result<Vec<Part>, CliError> {
    let mut input = File::open(src).map_err(|e| failed(format!("open {}: {e}", src.display())))?;
    let mut parts = Vec::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let name = images::part_file_name(file, parts.len());
        let path = dir.join(&name);
        let mut out =
            File::create(&path).map_err(|e| failed(format!("create {}: {e}", path.display())))?;
        let mut h = Sha256::new();
        let mut size = 0u64;
        while size < max_part {
            let want =
                usize::try_from((max_part - size).min(buf.len() as u64)).unwrap_or(buf.len());
            let n = input
                .read(&mut buf[..want])
                .map_err(|e| failed(format!("read {}: {e}", src.display())))?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
            out.write_all(&buf[..n])
                .map_err(|e| failed(format!("write {}: {e}", path.display())))?;
            size += n as u64;
        }
        out.sync_all()
            .map_err(|e| failed(format!("sync {}: {e}", path.display())))?;
        if size == 0 {
            // The previous part ended exactly at the end of the input.
            let _ = std::fs::remove_file(&path);
            break;
        }
        parts.push(Part {
            size,
            sha256: hex(&h.finalize()),
        });
        if size < max_part {
            break;
        }
    }
    Ok(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_distinct() {
        assert_eq!(CliError::Refused("x".into()).exit_code(), 1);
        assert_eq!(CliError::Usage("x".into()).exit_code(), 2);
        assert_eq!(CliError::Failed("x".into()).exit_code(), 3);
    }

    #[test]
    fn build_ids() {
        assert!(valid_build_id("20261123.1"));
        assert!(valid_build_id("20261123.12"));
        for bad in [
            "20261123",
            "2026112.1",
            "20261123.123",
            "20261123.",
            "x0261123.1",
            "",
        ] {
            assert!(!valid_build_id(bad), "{bad}");
        }
    }

    #[test]
    fn recipes_resolve_or_list_the_known_ones() {
        assert!(recipe("ubuntu-24.04-xfce-basic").is_ok());
        let CliError::Usage(m) = recipe("nope").unwrap_err() else {
            panic!("usage error expected")
        };
        assert!(m.contains("debian-13-xfce-developer"), "{m}");
    }

    #[test]
    fn splitting_covers_the_input_and_hashes_each_part() {
        let dir = tempfile::tempdir().unwrap();
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let src = dir.path().join("src");
        std::fs::write(&src, &data).unwrap();
        for max in [4096u64, 5000, 10_000, 20_000] {
            let out = dir.path().join(format!("o{max}"));
            std::fs::create_dir(&out).unwrap();
            let parts = split_file(&src, &out, "f.img", max).unwrap();
            let mut joined = Vec::new();
            for (i, p) in parts.iter().enumerate() {
                let b = std::fs::read(out.join(format!("f.img.p{i}"))).unwrap();
                assert_eq!(b.len() as u64, p.size);
                assert_eq!(hex(&Sha256::digest(&b)), p.sha256);
                assert!(p.size <= max);
                joined.extend(b);
            }
            assert_eq!(joined, data, "max {max}");
            assert!(!out.join(format!("f.img.p{}", parts.len())).exists());
        }
    }
}
