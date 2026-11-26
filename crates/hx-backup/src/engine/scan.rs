//! Source measurement before a backup, and mount-point recreation after a restore.

use std::collections::HashSet;
use std::fs::{self, DirBuilder, Permissions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use crate::manifest::SourceSizes;
use crate::rules::{MOUNT_POINTS, ResolvedRules};

use super::{CancelToken, EngineError};

/// Most directory entries the scan visits before giving up.
pub const MAX_SCAN_ENTRIES: u64 = 50_000_000;

/// Measure what a backup of `root` with these `rules` will contain, without following symlinks.
/// Counts regular files and directories; sizes are apparent lengths with hard links counted once.
pub(crate) fn scan_source(
    root: &Path,
    rules: &ResolvedRules,
    cancel: &CancelToken,
    on_progress: &mut dyn FnMut(u64),
) -> Result<SourceSizes, EngineError> {
    let excluded: HashSet<&Path> = rules.excluded().iter().map(PathBuf::as_path).collect();
    let mut sizes = SourceSizes {
        excluded_paths: rules.excluded().len() as u64,
        ..SourceSizes::default()
    };
    let mut seen_links: HashSet<(u64, u64)> = HashSet::new();
    let mut visited: u64 = 0;
    // (real path, rootfs-relative path)
    let mut stack: Vec<(PathBuf, PathBuf)> = vec![(root.to_owned(), PathBuf::from("/"))];
    sizes.directories += 1;
    // A hostile tree (a path chain longer than PATH_MAX, a directory the worker cannot read, more
    // entries than the cap) must not make the backup impossible: what cannot be read is skipped
    // and counted, and the backup itself reports its own errors.
    'walk: while let Some((dir, rel)) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else {
            sizes.unreadable_entries += 1;
            continue;
        };
        for ent in rd {
            visited += 1;
            if visited > MAX_SCAN_ENTRIES {
                sizes.unreadable_entries += 1;
                break 'walk;
            }
            if visited.is_multiple_of(1024) {
                cancel.check()?;
                on_progress(sizes.files);
            }
            let Ok(ent) = ent else {
                sizes.unreadable_entries += 1;
                continue;
            };
            let child_rel = rel.join(ent.file_name());
            if excluded.contains(child_rel.as_path()) {
                continue;
            }
            let Ok(ft) = ent.file_type() else {
                sizes.unreadable_entries += 1;
                continue;
            };
            if ft.is_dir() {
                sizes.directories += 1;
                stack.push((ent.path(), child_rel));
            } else if ft.is_file() {
                let Ok(md) = ent.metadata() else {
                    sizes.unreadable_entries += 1;
                    continue;
                };
                if md.nlink() > 1 && !seen_links.insert((md.dev(), md.ino())) {
                    continue;
                }
                sizes.files += 1;
                sizes.bytes = sizes.bytes.saturating_add(md.len());
            }
        }
    }
    cancel.check()?;
    on_progress(sizes.files);
    Ok(sizes)
}

/// Recreate the mount-point directories that backups skip (`/proc`, `/sys`, `/dev`, `/run`,
/// `/tmp`, `/var/tmp`) under `target`, if missing, with their standard modes.
///
/// Never follows a symlink: if a component on the way is a symlink or not a directory the mount
/// point is skipped (and logged), so a hostile snapshot cannot make this create directories
/// outside `target`. New directories are owned by the user running the restore (root in the
/// worker, which is what a system restore wants). Returns the directories created.
pub(crate) fn recreate_mount_points(target: &Path) -> io::Result<Vec<PathBuf>> {
    let mut created = Vec::new();
    for (mp, mode) in MOUNT_POINTS {
        let comps: Vec<&std::ffi::OsStr> = Path::new(mp)
            .components()
            .filter_map(|c| match c {
                Component::Normal(n) => Some(n),
                _ => None,
            })
            .collect();
        let mut cur = target.to_owned();
        for (i, c) in comps.iter().enumerate() {
            cur.push(c);
            let last = i + 1 == comps.len();
            match fs::symlink_metadata(&cur) {
                Ok(md) if md.is_dir() => {}
                Ok(_) => {
                    tracing::warn!(
                        mount_point = mp,
                        "not recreated: path exists and is not a directory"
                    );
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    let this_mode = if last { mode & 0o777 } else { 0o755 };
                    DirBuilder::new().mode(this_mode).create(&cur)?;
                    if last {
                        // `mode` is subject to the umask and cannot carry the sticky bit.
                        fs::set_permissions(&cur, Permissions::from_mode(mode))?;
                        created.push(cur.clone());
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }
    Ok(created)
}

/// Whether the process has `CAP_CHOWN` in its effective set (bit 0 of `CapEff`).
///
/// False when it cannot be determined: a restore that must set numeric owners should fail early
/// rather than discover, file by file, that rustic only logs the `chown` failures.
pub(crate) fn has_cap_chown() -> bool {
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return false;
    };
    status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
        .is_some_and(|caps| caps & 1 != 0)
}
