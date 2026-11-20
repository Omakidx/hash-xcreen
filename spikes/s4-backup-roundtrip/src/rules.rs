//! Exclude rules and protected paths (architecture section 9.2).
//!
//! Design: excludes are *exact cache locations* written as absolute path patterns whose segments
//! may contain glob wildcards (`*` never crosses a `/`). They are resolved against the real
//! mounted tree into concrete directories, and every concrete candidate that is inside, equal
//! to, or an ancestor of a protected path is dropped. The surviving concrete paths become
//! literal `!`-prefixed ignore globs for rustic. A protected path therefore can never be pruned,
//! whatever the user-editable exclude list says.

use globset::{Glob, GlobBuilder, GlobMatcher};
use std::path::{Path, PathBuf};

/// Home directory roots. `*` is a single path segment.
const HOMES: [&str; 2] = ["/home/*", "/root"];

/// Default excludes: exact cache and scratch locations. Patterns are rootfs-relative.
pub fn default_excludes() -> Vec<String> {
    let mut v: Vec<String> = [
        // pseudo filesystems and scratch (mount points are recreated on restore)
        "/proc",
        "/sys",
        "/dev",
        "/run",
        "/tmp",
        "/var/tmp",
        // package manager caches
        "/var/cache/apt",
        "/var/lib/apt/lists/*",
        // logs
        "/var/log/journal",
        "/var/log/*.log",
        "/var/log/*.gz",
        "/var/log/*.[0-9]",
        // docker BuildKit cache
        "/var/lib/docker/buildkit",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    for h in HOMES {
        for rel in [
            ".cache",
            ".local/share/Trash",
            ".npm/_cacache",
            ".cargo/registry/cache",
            // Electron / Chromium-style exact cache directories under ~/.config/<App>/
            ".config/*/Cache",
            ".config/*/Code Cache",
            ".config/*/GPUCache",
            ".config/*/DawnCache",
            ".config/*/GrShaderCache",
            ".config/*/ShaderCache",
            ".config/Code/CachedData",
            ".config/Code/Cache",
        ] {
            v.push(format!("{h}/{rel}"));
        }
    }
    v
}

/// Protected paths: always backed up, override every exclude.
pub fn protected_patterns() -> Vec<String> {
    let mut v = Vec::new();
    for h in HOMES {
        for rel in [
            ".claude",
            ".claude.json",
            ".codex",
            ".gemini",
            ".cursor",
            ".config/*/Local Storage",
            ".config/*/IndexedDB",
            ".config/*/Session Storage",
            ".config/Code/User",
            ".local/share",
            // browser profiles
            ".config/chromium",
            ".config/google-chrome",
            ".config/BraveSoftware",
            ".config/microsoft-edge",
            ".config/vivaldi",
            ".mozilla",
            "snap/*/common/.mozilla",
        ] {
            v.push(format!("{h}/{rel}"));
        }
    }
    v
}

/// A rootfs-relative absolute path pattern, one glob matcher per segment.
#[derive(Debug, Clone)]
pub struct PathPattern {
    segs: Vec<GlobMatcher>,
}

fn seg_glob(s: &str) -> Result<GlobMatcher, globset::Error> {
    Ok(GlobBuilder::new(s)
        .literal_separator(true)
        .backslash_escape(false)
        .build()?
        .compile_matcher())
}

impl PathPattern {
    pub fn new(raw: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(raw.starts_with('/'), "pattern must be absolute: {raw}");
        let segs = raw
            .split('/')
            .filter(|s| !s.is_empty())
            .map(seg_glob)
            .collect::<Result<Vec<_>, _>>()?;
        anyhow::ensure!(!segs.is_empty(), "the root itself cannot be a pattern");
        Ok(Self { segs })
    }

    /// True when the pattern and the concrete path overlap: the path is equal to, inside, or an
    /// ancestor of something the pattern can match.
    pub fn overlaps(&self, comps: &[String]) -> bool {
        self.segs
            .iter()
            .zip(comps.iter())
            .all(|(g, c)| g.is_match(c.as_str()))
    }
}

pub struct Protected(Vec<PathPattern>);

impl Protected {
    pub fn new(patterns: &[String]) -> anyhow::Result<Self> {
        Ok(Self(
            patterns
                .iter()
                .map(|p| PathPattern::new(p))
                .collect::<anyhow::Result<_>>()?,
        ))
    }

    pub fn default_set() -> Self {
        Self::new(&protected_patterns()).expect("default protected patterns are valid")
    }

    /// Would excluding this path remove a protected path (or part of one)?
    pub fn conflicts(&self, comps: &[String]) -> bool {
        self.0.iter().any(|p| p.overlaps(comps))
    }
}

fn components(p: &Path) -> Vec<String> {
    p.components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect()
}

/// Drop every candidate that would prune a protected path.
pub fn filter_candidates(candidates: Vec<PathBuf>, protected: &Protected) -> Vec<PathBuf> {
    candidates
        .into_iter()
        .filter(|c| !protected.conflicts(&components(c)))
        .collect()
}

/// Resolve one pattern into concrete paths below `root` by walking only the directories the
/// pattern needs. Symlinks are never followed. Returned paths are rootfs-relative (`/a/b`).
pub fn expand(root: &Path, pattern: &PathPattern) -> Vec<PathBuf> {
    let mut frontier = vec![PathBuf::from("/")];
    for g in &pattern.segs {
        let mut next = Vec::new();
        for dir in &frontier {
            let real = root.join(dir.strip_prefix("/").unwrap_or(dir));
            // A literal segment avoids listing the directory.
            let Ok(rd) = std::fs::read_dir(&real) else {
                continue;
            };
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if g.is_match(name.as_str()) {
                    // Do not descend through symlinks.
                    if e.file_type().map(|t| t.is_symlink()).unwrap_or(true) {
                        continue;
                    }
                    next.push(dir.join(&name));
                }
            }
        }
        frontier = next;
        if frontier.is_empty() {
            break;
        }
    }
    frontier
}

/// Resolve all excludes against the real tree, apply the protected override, and return the
/// surviving rootfs-relative concrete paths.
pub fn resolve_excludes(
    root: &Path,
    excludes: &[String],
    protected: &Protected,
) -> anyhow::Result<Vec<PathBuf>> {
    let mut all = Vec::new();
    for e in excludes {
        all.extend(expand(root, &PathPattern::new(e)?));
    }
    all.sort();
    all.dedup();
    Ok(filter_candidates(all, protected))
}

/// Escape gitignore metacharacters in a literal path segment.
fn escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for ch in s.chars() {
        if matches!(ch, '*' | '?' | '[' | ']' | '\\' | '!' | '#' | '{' | '}') {
            o.push('\\');
        }
        o.push(ch);
    }
    o
}

/// Literal ignore globs for rustic (`!` marks an exclusion in an override). `prefix` is the
/// absolute location of the tree root as the backup walker sees it (for example `/src`).
pub fn to_rustic_globs(prefix: &str, resolved: &[PathBuf]) -> Vec<String> {
    resolved
        .iter()
        .map(|p| {
            let rel = p.to_string_lossy();
            let esc: String = rel.split('/').map(escape).collect::<Vec<_>>().join("/");
            format!("!{}{}", prefix.trim_end_matches('/'), esc)
        })
        .collect()
}

/// Concrete protected-path check used by tests and by the post-backup audit.
#[allow(dead_code)]
pub fn is_protected_path(protected: &Protected, comps: &[String]) -> bool {
    protected
        .0
        .iter()
        .any(|p| p.segs.len() <= comps.len() && p.overlaps(comps))
}

#[allow(dead_code)]
pub fn glob_is_valid(g: &str) -> bool {
    Glob::new(g).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::fs;

    #[test]
    fn default_caches_are_excluded_and_chat_data_is_kept() {
        let tmp = tempfile_dir("rules1");
        for d in [
            "home/alice/.cache/x",
            "home/alice/.config/App/Cache",
            "home/alice/.config/App/Code Cache",
            "home/alice/.config/App/Local Storage/leveldb",
            "home/alice/.config/chromium/Default/Cache",
            "home/alice/.claude/projects",
            "home/alice/.local/share/Trash/files",
            "tmp",
            "proc",
        ] {
            fs::create_dir_all(tmp.join(d)).unwrap();
        }
        let r = resolve_excludes(&tmp, &default_excludes(), &Protected::default_set()).unwrap();
        let s: Vec<String> = r.iter().map(|p| p.to_string_lossy().into_owned()).collect();
        assert!(s.contains(&"/home/alice/.cache".to_string()));
        assert!(s.contains(&"/home/alice/.config/App/Cache".to_string()));
        assert!(s.contains(&"/home/alice/.config/App/Code Cache".to_string()));
        assert!(s.contains(&"/tmp".to_string()));
        assert!(!s.iter().any(|p| p.contains("Local Storage")));
        assert!(!s.iter().any(|p| p.contains(".claude")));
        // protected wins over the Trash exclude (it lives under ~/.local/share)
        assert!(!s.iter().any(|p| p.contains("Trash")));
        // chromium profile is protected, so its Cache is kept
        assert!(!s.iter().any(|p| p.contains("chromium")));
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn globs_are_escaped_and_anchored() {
        let g = to_rustic_globs("/src", &[PathBuf::from("/home/a/.config/X [1]/Code Cache")]);
        assert_eq!(g, vec!["!/src/home/a/.config/X \\[1\\]/Code Cache"]);
    }

    #[test]
    fn user_exclude_that_contains_a_protected_path_is_dropped() {
        let tmp = tempfile_dir("rules2");
        fs::create_dir_all(tmp.join("home/alice/.claude/projects")).unwrap();
        fs::create_dir_all(tmp.join("home/alice/.config/Slack/Local Storage")).unwrap();
        let bad = vec![
            "/home/*".to_string(),
            "/home/*/.claude".to_string(),
            "/home/*/.config/*".to_string(),
            "/home/*/.claude/projects".to_string(),
        ];
        let r = resolve_excludes(&tmp, &bad, &Protected::default_set()).unwrap();
        assert!(r.is_empty(), "{r:?}");
        let _ = fs::remove_dir_all(&tmp);
    }

    fn tempfile_dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("s4-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    // Property: for random trees and random (user-editable) exclude lists, no resolved exclude
    // prunes a protected path, and no protected path is covered by any resolved exclude.
    fn seg() -> impl Strategy<Value = String> {
        prop_oneof![
            Just(".claude".to_string()),
            Just(".codex".to_string()),
            Just(".config".to_string()),
            Just(".local".to_string()),
            Just("share".to_string()),
            Just("Local Storage".to_string()),
            Just("IndexedDB".to_string()),
            Just("Session Storage".to_string()),
            Just("Cache".to_string()),
            Just("Code Cache".to_string()),
            Just("GPUCache".to_string()),
            Just("chromium".to_string()),
            Just("Default".to_string()),
            Just(".cache".to_string()),
            Just("App".to_string()),
            Just("User".to_string()),
            Just("Code".to_string()),
            "[a-z]{1,3}",
        ]
    }

    fn rel_path() -> impl Strategy<Value = Vec<String>> {
        prop::collection::vec(seg(), 1..6)
    }

    fn pat_seg() -> impl Strategy<Value = String> {
        prop_oneof![
            3 => seg(),
            1 => Just("*".to_string()),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(200))]
        #[test]
        fn protected_paths_are_never_excluded(
            user_files in prop::collection::vec(rel_path(), 1..25),
            home in prop_oneof![Just("home/alice".to_string()), Just("root".to_string())],
            extra_rules in prop::collection::vec(prop::collection::vec(pat_seg(), 1..5), 0..8),
            use_defaults in any::<bool>(),
        ) {
            let tmp = tempfile_dir(&format!("prop{}", rand_tag(&user_files)));
            // Always include the canonical protected and cache locations too.
            let mut files: Vec<PathBuf> = user_files.iter().map(|c| tmp.join(&home).join(c.join("/"))).collect();
            for must in [".claude/projects/s.jsonl", ".config/App/Local Storage/leveldb/1.ldb",
                         ".config/App/Cache/x", ".config/chromium/Default/Cache/y", ".cache/z",
                         ".local/share/Trash/files/t", ".config/Code/User/settings.json"] {
                files.push(tmp.join(&home).join(must));
            }
            for f in &files {
                if let Some(p) = f.parent() { let _ = fs::create_dir_all(p); }
                if !f.exists() { let _ = fs::write(f, b"x"); }
            }
            let mut excludes = if use_defaults { default_excludes() } else { vec![] };
            for r in &extra_rules {
                excludes.push(format!("/{}/{}", home, r.join("/")));
            }
            let prot = Protected::default_set();
            let resolved = resolve_excludes(&tmp, &excludes, &prot).unwrap();
            // Check every path that exists in the tree.
            let mut stack = vec![tmp.clone()];
            while let Some(d) = stack.pop() {
                for e in fs::read_dir(&d).unwrap().flatten() {
                    let p = e.path();
                    let rel = PathBuf::from("/").join(p.strip_prefix(&tmp).unwrap());
                    let c = components(&rel);
                    let pruned = resolved.iter().any(|r| rel.starts_with(r));
                    if is_protected_path(&prot, &c) {
                        prop_assert!(!pruned, "protected path {} pruned by {:?}", rel.display(), resolved);
                    }
                    if e.file_type().unwrap().is_dir() { stack.push(p); }
                }
            }
            // The documented credential files are protected explicitly.
            for cred in [format!("/{home}/.claude/.credentials.json"), format!("/{home}/.codex/auth.json"), format!("/{home}/.claude.json")] {
                prop_assert!(is_protected_path(&prot, &components(Path::new(&cred))));
                prop_assert!(!resolved.iter().any(|r| Path::new(&cred).starts_with(r)));
            }
            let _ = fs::remove_dir_all(&tmp);
        }
    }

    fn rand_tag(v: &[Vec<String>]) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        v.hash(&mut h);
        std::thread::current().id().hash(&mut h);
        h.finish()
    }
}
