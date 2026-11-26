//! Exclude rules and protected paths (architecture section 9.2 and 9.3).
//!
//! # Model
//!
//! * An **exclude** is an exact cache location written as an absolute path pattern. Segments are
//!   separated by `/`; a segment may use `*`, `?` and `[...]` and never matches across a `/`
//!   (so `*` is exactly one path segment). `**` is rejected.
//! * The **protected list** (credentials of coding agents, app state, browser profile data, ...) is
//!   built in and cannot be edited. A protected path always wins over an exclude.
//! * **Named caches** are the one exception: a fixed list of cache directories that live *inside*
//!   protected trees (`~/.local/share/Trash`, a browser profile's `Cache*`, `Code Cache`,
//!   `GPUCache`, ...) and are excluded anyway ("protected wins, except named caches"). They are
//!   always applied; they are not part of the user-editable list.
//! * [`resolve`] matches all of this against the real mounted tree and returns concrete paths
//!   ([`ResolvedRules`]). rustic's own glob overrides cannot express "protected wins, except
//!   named caches", so the decision is made here and handed to rustic as literal ignore globs
//!   ([`ResolvedRules::rustic_globs`]).
//!
//! # Guarantees
//!
//! * Resolution never follows a symlink: intermediate path components must be real directories,
//!   so a symlink in the tree cannot redirect resolution outside the root. A symlink can itself
//!   be an exclude target (the link node is excluded, nothing behind it is read).
//! * A candidate exclude that equals, contains (is an ancestor of) or lies inside an existing
//!   protected path is rejected and reported in [`ResolvedRules::rejected`]; the only candidates
//!   allowed inside a protected tree are named caches, and only when they do not contain another
//!   protected path.
//! * Resolution is bounded by an entry budget so a hostile tree cannot stall it.
//!
//! Homes are `/home/*` and `/root`.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use globset::{GlobBuilder, GlobMatcher};
use serde::{Deserialize, Serialize};

/// Longest accepted pattern, in bytes.
pub const MAX_PATTERN_BYTES: usize = 1024;
/// Most segments a pattern may have.
pub const MAX_PATTERN_SEGMENTS: usize = 32;
/// Most user-supplied exclude patterns accepted.
pub const MAX_EXCLUDES: usize = 512;
/// Default bound on directory entries inspected while resolving.
pub const DEFAULT_ENTRY_BUDGET: u64 = 5_000_000;

/// How deep below a browser profile root the named-cache walk goes.
const MAX_CACHE_WALK_DEPTH: usize = 8;

const HOMES: [&str; 2] = ["/home/*", "/root"];

/// Directories that stay in the backup but are excluded because the rootfs is rebuilt around
/// them: pseudo filesystems and scratch space. A restore recreates them empty, with these modes.
pub const MOUNT_POINTS: [(&str, u32); 6] = [
    ("/proc", 0o555),
    ("/sys", 0o555),
    ("/dev", 0o755),
    ("/run", 0o755),
    ("/tmp", 0o1777),
    ("/var/tmp", 0o1777),
];

/// Docker data modes (architecture 9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DockerMode {
    /// All of `/var/lib/docker` except the BuildKit cache.
    Complete,
    /// Volumes, container configuration and Compose files only; images are pulled again on
    /// restore. (Compose files live in the users' project directories, which are backed up like
    /// any other home content.)
    Light,
}

/// Errors from building or resolving rules.
#[derive(Debug, thiserror::Error)]
pub enum RulesError {
    /// A pattern is not acceptable.
    #[error("invalid exclude pattern {pattern:?}: {reason}")]
    InvalidPattern {
        /// The offending pattern (truncated to a sane length).
        pattern: String,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// More exclude patterns than [`MAX_EXCLUDES`].
    #[error("too many exclude patterns: {got} (at most {max})")]
    TooManyExcludes {
        /// Limit.
        max: usize,
        /// Count supplied.
        got: usize,
    },
    /// The tree root is not usable.
    #[error("tree root {path} is not a directory")]
    RootNotDirectory {
        /// The root given.
        path: PathBuf,
    },
    /// The tree has more entries than the budget allows.
    #[error("resolving rules inspected more than {budget} directory entries")]
    BudgetExceeded {
        /// The budget that was exhausted.
        budget: u64,
    },
    /// A filesystem error other than "not found".
    #[error("reading {path}: {source}")]
    Io {
        /// Path involved.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: io::Error,
    },
    /// The tree root cannot be expressed as a rustic glob prefix.
    #[error("path {path:?} is not valid UTF-8 and cannot be used as an ignore glob prefix")]
    NonUtf8Prefix {
        /// The path.
        path: PathBuf,
    },
}

// ---------------------------------------------------------------------------------------------
// Patterns
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Segment {
    Literal(OsString),
    Glob(GlobMatcher),
}

impl Segment {
    fn parse(s: &str) -> Result<Self, &'static str> {
        if s == "." || s == ".." {
            return Err("`.` and `..` segments are not allowed");
        }
        if s.contains("**") {
            return Err("`**` is not supported; `*` already means one whole segment");
        }
        if s.contains(['*', '?', '[', ']', '{', '}']) {
            let glob = GlobBuilder::new(s)
                .literal_separator(true)
                .backslash_escape(false)
                .build()
                .map_err(|_| "segment is not a valid glob")?;
            Ok(Self::Glob(glob.compile_matcher()))
        } else {
            Ok(Self::Literal(OsString::from(s)))
        }
    }

    fn is_match(&self, name: &OsStr) -> bool {
        match self {
            Self::Literal(l) => l == name,
            Self::Glob(g) => g.is_match(Path::new(name)),
        }
    }
}

/// An absolute, rootfs-relative path pattern (`/home/*/.cache`).
#[derive(Debug, Clone)]
pub struct PathPattern {
    raw: String,
    segs: Vec<Segment>,
}

impl PathPattern {
    /// Parse and validate a pattern.
    ///
    /// # Errors
    /// [`RulesError::InvalidPattern`] when the pattern is not absolute, is the root itself,
    /// contains NUL, `.`/`..` or `**` segments, an invalid glob, or exceeds the size limits.
    pub fn parse(raw: &str) -> Result<Self, RulesError> {
        let bad = |reason: &'static str| RulesError::InvalidPattern {
            pattern: raw.chars().take(128).collect(),
            reason,
        };
        if raw.len() > MAX_PATTERN_BYTES {
            return Err(bad("pattern is too long"));
        }
        if raw.contains('\0') {
            return Err(bad("pattern contains NUL"));
        }
        if !raw.starts_with('/') {
            return Err(bad("pattern must be absolute"));
        }
        let segs = raw
            .split('/')
            .filter(|s| !s.is_empty())
            .map(|s| Segment::parse(s).map_err(bad))
            .collect::<Result<Vec<_>, _>>()?;
        if segs.is_empty() {
            return Err(bad("the root itself cannot be excluded"));
        }
        if segs.len() > MAX_PATTERN_SEGMENTS {
            return Err(bad("pattern has too many segments"));
        }
        Ok(Self {
            raw: raw.to_owned(),
            segs,
        })
    }

    /// The pattern as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

impl fmt::Display for PathPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

fn builtin(raw: &str) -> PathPattern {
    // Built-in patterns are literals in this file; `builtin_patterns_parse` covers them.
    PathPattern::parse(raw).unwrap_or_else(|e| unreachable!("built-in pattern {raw}: {e}"))
}

fn under_homes(rels: &[&str]) -> Vec<String> {
    HOMES
        .iter()
        .flat_map(|h| rels.iter().map(move |r| format!("{h}/{r}")))
        .collect()
}

/// The default, user-editable exclude list: exact cache and scratch locations.
///
/// Callers may show it, edit it and pass the result to [`RuleSet::new`]. Trash and browser
/// profile caches are *not* here: they are named caches, always applied. Docker's BuildKit cache
/// is handled by [`DockerMode`].
#[must_use]
pub fn default_excludes() -> Vec<String> {
    let mut v: Vec<String> = [
        // Pseudo filesystems and scratch space (recreated empty on restore, see MOUNT_POINTS).
        "/proc",
        "/sys",
        "/dev",
        "/run",
        "/tmp",
        "/var/tmp",
        // Package manager caches.
        "/var/cache/apt",
        "/var/lib/apt/lists/*",
        // Logs.
        "/var/log/journal",
        "/var/log/*.log",
        "/var/log/*.gz",
        "/var/log/*.[0-9]",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    v.extend(under_homes(&[
        ".cache",
        ".npm/_cacache",
        ".cargo/registry/cache",
        ".gradle/caches",
        // Electron and Chromium-style exact cache directories under ~/.config/<App>/.
        ".config/*/Cache",
        ".config/*/Code Cache",
        ".config/*/GPUCache",
        ".config/*/DawnCache",
        ".config/*/GrShaderCache",
        ".config/*/ShaderCache",
        ".config/Code/CachedData",
    ]));
    v
}

/// Browser profile roots, relative to a home. Whole profiles are protected; their caches are
/// named caches.
const BROWSER_ROOTS: [&str; 8] = [
    ".config/chromium",
    ".config/google-chrome",
    ".config/BraveSoftware",
    ".config/microsoft-edge",
    ".config/vivaldi",
    ".mozilla",
    "snap/*/common/.mozilla",
    "snap/*/common/chromium",
];

/// The built-in protected patterns (architecture 9.2). Not editable.
#[must_use]
pub fn protected_patterns() -> Vec<String> {
    let mut rels = vec![
        ".claude",
        ".claude.json",
        ".codex",
        ".gemini",
        ".cursor",
        ".config/*/Local Storage",
        ".config/*/IndexedDB",
        ".config/*/Session Storage",
        ".config/Code/User",
        // App data under ~/.local/share/<app>/, plus loose files and keyrings: the whole tree.
        ".local/share",
    ];
    rels.extend(BROWSER_ROOTS);
    under_homes(&rels)
}

/// Single-segment (or `a/b`) names of cache directories inside browser profiles, matched at any
/// depth below a profile root (but not inside the user's web data, see `DATA_DIRS`).
const PROFILE_CACHE_SUFFIXES: [&str; 9] = [
    "Cache*",
    "Code Cache",
    "GPUCache",
    "DawnCache",
    "GraphiteDawnCache",
    "GrShaderCache",
    "ShaderCache",
    "Service Worker/ScriptCache",
    "cache2",
];

/// Directories holding the user's web data; the cache walk never descends into them.
const DATA_DIRS: [&str; 5] = [
    "Local Storage",
    "IndexedDB",
    "Session Storage",
    "Extensions",
    "Local Extension Settings",
];

/// Fixed named caches inside protected trees, relative to a home.
const FIXED_NAMED_CACHES: [&str; 1] = [".local/share/Trash"];

// ---------------------------------------------------------------------------------------------
// Rule set
// ---------------------------------------------------------------------------------------------

/// The rules for one backup: editable excludes, Docker mode, and the built-in protected list.
#[derive(Debug, Clone)]
pub struct RuleSet {
    excludes: Vec<PathPattern>,
    docker: DockerMode,
    budget: u64,
}

impl RuleSet {
    /// Rules with the given exclude patterns (the full list: nothing is added to it).
    ///
    /// # Errors
    /// [`RulesError::TooManyExcludes`] or [`RulesError::InvalidPattern`].
    pub fn new<I, S>(docker: DockerMode, excludes: I) -> Result<Self, RulesError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut out = Vec::new();
        for e in excludes {
            if out.len() >= MAX_EXCLUDES {
                return Err(RulesError::TooManyExcludes {
                    max: MAX_EXCLUDES,
                    got: out.len() + 1,
                });
            }
            out.push(PathPattern::parse(e.as_ref())?);
        }
        Ok(Self {
            excludes: out,
            docker,
            budget: DEFAULT_ENTRY_BUDGET,
        })
    }

    /// Rules with [`default_excludes`].
    #[must_use]
    pub fn with_defaults(docker: DockerMode) -> Self {
        Self {
            excludes: default_excludes().iter().map(|s| builtin(s)).collect(),
            docker,
            budget: DEFAULT_ENTRY_BUDGET,
        }
    }

    /// Override the directory-entry budget (tests, unusually large trees).
    #[must_use]
    pub fn with_entry_budget(mut self, budget: u64) -> Self {
        self.budget = budget;
        self
    }

    /// The exclude patterns in force.
    pub fn excludes(&self) -> impl Iterator<Item = &str> {
        self.excludes.iter().map(PathPattern::as_str)
    }

    /// The Docker mode.
    #[must_use]
    pub fn docker_mode(&self) -> DockerMode {
        self.docker
    }
}

// ---------------------------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------------------------

/// Why a candidate exclude was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// The candidate equals or contains a protected path.
    ContainsProtected,
    /// The candidate lies inside a protected tree and is not a named cache.
    InsideProtected,
}

/// An exclude that was refused because of the protected list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedExclude {
    /// The concrete candidate (rootfs-relative, absolute form).
    pub path: PathBuf,
    /// The protected path it conflicts with.
    pub protected: PathBuf,
    /// Why.
    pub reason: RejectReason,
}

/// The outcome of [`resolve`]: concrete paths, all in absolute rootfs-relative form (`/home/a/.cache`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedRules {
    excluded: Vec<PathBuf>,
    protected: Vec<PathBuf>,
    rejected: Vec<RejectedExclude>,
    discovery_skipped: u32,
}

/// Literal ignore globs for rustic plus the entries that could not be expressed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RusticGlobs {
    /// `!`-prefixed override globs, to put in `BackupOptions::excludes.globs`.
    pub globs: Vec<String>,
    /// Excluded paths that are not valid UTF-8. They cannot be expressed as globs and therefore
    /// stay in the backup (over-inclusion is the safe direction).
    pub skipped_non_utf8: Vec<PathBuf>,
}

impl ResolvedRules {
    /// The concrete excluded paths: sorted, deduplicated, none inside another.
    #[must_use]
    pub fn excluded(&self) -> &[PathBuf] {
        &self.excluded
    }

    /// The concrete protected paths found in the tree (for audit and logs).
    #[must_use]
    pub fn protected(&self) -> &[PathBuf] {
        &self.protected
    }

    /// How many discovery steps were skipped because the entry budget ran out or a directory
    /// could not be read. Skipping only ever leaves more in the backup. If the protected paths
    /// themselves could not be discovered, nothing is excluded at all.
    #[must_use]
    pub fn discovery_skipped(&self) -> u32 {
        self.discovery_skipped
    }

    /// Candidate excludes refused because of the protected list.
    #[must_use]
    pub fn rejected(&self) -> &[RejectedExclude] {
        &self.rejected
    }

    /// Whether a rootfs-relative absolute path is excluded (it, or an ancestor, is listed).
    #[must_use]
    pub fn is_excluded(&self, path: &Path) -> bool {
        self.excluded.iter().any(|e| path.starts_with(e))
    }

    /// Literal ignore globs for rustic. `prefix` is the location of the tree root as the backup
    /// walker sees it (the canonical source path).
    ///
    /// # Errors
    /// [`RulesError::NonUtf8Prefix`] when `prefix` is not valid UTF-8.
    pub fn rustic_globs(&self, prefix: &Path) -> Result<RusticGlobs, RulesError> {
        let prefix_str = prefix.to_str().ok_or_else(|| RulesError::NonUtf8Prefix {
            path: prefix.to_owned(),
        })?;
        let prefix_esc = escape_glob(prefix_str.trim_end_matches('/'));
        let mut out = RusticGlobs::default();
        for p in &self.excluded {
            match p.to_str() {
                Some(s) => out.globs.push(format!("!{prefix_esc}{}", escape_glob(s))),
                None => out.skipped_non_utf8.push(p.clone()),
            }
        }
        Ok(out)
    }

    /// A human-readable listing for logs.
    #[must_use]
    pub fn report(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for ResolvedRules {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "excluded ({}):", self.excluded.len())?;
        for p in &self.excluded {
            writeln!(f, "  {}", p.display())?;
        }
        writeln!(f, "protected, kept ({}):", self.protected.len())?;
        for p in &self.protected {
            writeln!(f, "  {}", p.display())?;
        }
        writeln!(f, "discovery steps skipped: {}", self.discovery_skipped)?;
        writeln!(f, "rejected excludes ({}):", self.rejected.len())?;
        for r in &self.rejected {
            let why = match r.reason {
                RejectReason::ContainsProtected => "contains protected",
                RejectReason::InsideProtected => "inside protected",
            };
            writeln!(
                f,
                "  {} ({why} {})",
                r.path.display(),
                r.protected.display()
            )?;
        }
        Ok(())
    }
}

/// Escape gitignore/glob metacharacters in a literal path.
fn escape_glob(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 4);
    for ch in s.chars() {
        if matches!(ch, '*' | '?' | '[' | ']' | '{' | '}' | '\\') {
            o.push('\\');
        }
        o.push(ch);
    }
    // A trailing space would be dropped by gitignore parsing unless escaped.
    if o.ends_with(' ') {
        o.pop();
        o.push_str("\\ ");
    }
    o
}

/// Walks the tree under `root` without ever following a symlink, within an entry budget.
struct Walker<'a> {
    root: &'a Path,
    limit: u64,
    remaining: u64,
}

impl<'a> Walker<'a> {
    fn new(root: &'a Path, budget: u64) -> Self {
        Self {
            root,
            limit: budget,
            remaining: budget,
        }
    }

    fn spend(&mut self, n: u64) -> Result<(), RulesError> {
        self.remaining = self
            .remaining
            .checked_sub(n)
            .ok_or(RulesError::BudgetExceeded { budget: self.limit })?;
        Ok(())
    }

    fn real(&self, rel: &Path) -> PathBuf {
        self.root.join(rel)
    }

    /// `lstat` of a tree-relative path; `None` when it does not exist.
    fn lstat(&mut self, rel: &Path) -> Result<Option<fs::FileType>, RulesError> {
        self.spend(1)?;
        let p = self.real(rel);
        match fs::symlink_metadata(&p) {
            Ok(m) => Ok(Some(m.file_type())),
            Err(e) if gone(&e) => Ok(None),
            Err(source) => Err(RulesError::Io { path: p, source }),
        }
    }

    /// Entries of a tree-relative directory as (name, file type), types from the directory
    /// entry itself (never following links). A missing directory lists as empty.
    fn list(&mut self, rel: &Path) -> Result<Vec<(OsString, fs::FileType)>, RulesError> {
        let p = self.real(rel);
        let rd = match fs::read_dir(&p) {
            Ok(rd) => rd,
            Err(e) if gone(&e) => return Ok(Vec::new()),
            Err(source) => return Err(RulesError::Io { path: p, source }),
        };
        let mut out = Vec::new();
        for ent in rd {
            self.spend(1)?;
            let ent = ent.map_err(|source| RulesError::Io {
                path: p.clone(),
                source,
            })?;
            let ft = ent.file_type().map_err(|source| RulesError::Io {
                path: ent.path(),
                source,
            })?;
            out.push((ent.file_name(), ft));
        }
        Ok(out)
    }

    /// Concrete tree-relative paths matching a pattern. Intermediate components must be real
    /// directories; the last component may be any node type.
    fn expand(&mut self, pat: &PathPattern) -> Result<Vec<PathBuf>, RulesError> {
        let mut frontier = vec![PathBuf::new()];
        let last = pat.segs.len() - 1;
        for (i, seg) in pat.segs.iter().enumerate() {
            let mut next = Vec::new();
            for dir in &frontier {
                match seg {
                    Segment::Literal(name) => {
                        let cand = dir.join(name);
                        if let Some(ft) = self.lstat(&cand)?
                            && (i == last || ft.is_dir())
                        {
                            next.push(cand);
                        }
                    }
                    Segment::Glob(_) => {
                        for (name, ft) in self.list(dir)? {
                            if seg.is_match(&name) && (i == last || ft.is_dir()) {
                                next.push(dir.join(name));
                            }
                        }
                    }
                }
            }
            frontier = next;
            if frontier.is_empty() {
                break;
            }
        }
        Ok(frontier)
    }

    /// Named caches below browser profile roots: directories matching `PROFILE_CACHE_SUFFIXES`
    /// at any depth, found without following links and without entering web-data directories.
    fn profile_caches(&mut self, suffixes: &[Vec<Segment>]) -> Result<Vec<PathBuf>, RulesError> {
        let mut found = Vec::new();
        let roots: Vec<PathBuf> = {
            let pats: Vec<PathBuf> = {
                let mut v = Vec::new();
                for p in under_homes(&BROWSER_ROOTS) {
                    v.extend(self.expand(&builtin(&p))?);
                }
                v
            };
            pats
        };
        for root in roots {
            if !self.lstat(&root)?.is_some_and(|ft| ft.is_dir()) {
                continue;
            }
            // (path relative to the tree, components relative to the profile root)
            let mut stack: Vec<(PathBuf, Vec<OsString>)> = vec![(root.clone(), Vec::new())];
            while let Some((dir, comps)) = stack.pop() {
                for (name, ft) in self.list(&dir)? {
                    if !ft.is_dir() {
                        continue;
                    }
                    let child = dir.join(&name);
                    let mut child_comps = comps.clone();
                    child_comps.push(name.clone());
                    if suffixes.iter().any(|s| tail_matches(&child_comps, s)) {
                        found.push(child);
                    } else if child_comps.len() < MAX_CACHE_WALK_DEPTH
                        && !DATA_DIRS.iter().any(|d| OsStr::new(d) == name)
                    {
                        stack.push((child, child_comps));
                    }
                }
            }
        }
        Ok(found)
    }
}

fn gone(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

fn tail_matches(comps: &[OsString], suffix: &[Segment]) -> bool {
    comps.len() >= suffix.len()
        && comps[comps.len() - suffix.len()..]
            .iter()
            .zip(suffix)
            .all(|(c, s)| s.is_match(c))
}

fn abs(rel: &Path) -> PathBuf {
    Path::new("/").join(rel)
}

/// Docker candidates for the mode (architecture 9.3), tree-relative.
fn docker_candidates(w: &mut Walker<'_>, mode: DockerMode) -> Result<Vec<PathBuf>, RulesError> {
    let data = PathBuf::from("var/lib/docker");
    if !w.lstat(&data)?.is_some_and(|ft| ft.is_dir()) {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    match mode {
        DockerMode::Complete => out.push(data.join("buildkit")),
        DockerMode::Light => {
            for (name, _) in w.list(&data)? {
                if name != "volumes" && name != "containers" {
                    out.push(data.join(name));
                }
            }
            // Container configuration only: drop logs, mounts and runtime state.
            let containers = data.join("containers");
            if w.lstat(&containers)?.is_some_and(|ft| ft.is_dir()) {
                for (id, ft) in w.list(&containers)? {
                    if !ft.is_dir() {
                        continue;
                    }
                    let cdir = containers.join(id);
                    for (name, _) in w.list(&cdir)? {
                        if name != "config.v2.json" && name != "hostconfig.json" {
                            out.push(cdir.join(name));
                        }
                    }
                }
            }
        }
    }
    Ok(out)
}

/// Resolve `rules` against the tree mounted at `root`.
///
/// # Errors
/// [`RulesError::RootNotDirectory`] only. Budget exhaustion and unreadable directories do not fail
/// the call: they skip discovery steps (see [`ResolvedRules::discovery_skipped`]).
pub fn resolve(root: &Path, rules: &RuleSet) -> Result<ResolvedRules, RulesError> {
    if !fs::metadata(root).is_ok_and(|m| m.is_dir()) {
        return Err(RulesError::RootNotDirectory {
            path: root.to_owned(),
        });
    }
    let mut w = Walker::new(root, rules.budget);

    // 1. Concrete protected paths. If they cannot all be found we cannot tell what an exclude
    //    would remove, so nothing is excluded: inclusion is always safe for them.
    let mut protected: BTreeSet<PathBuf> = BTreeSet::new();
    for p in protected_patterns() {
        match w.expand(&builtin(&p)) {
            Ok(found) => protected.extend(found),
            Err(e) => {
                tracing_warn(&e);
                return Ok(ResolvedRules {
                    discovery_skipped: 1,
                    ..ResolvedRules::default()
                });
            }
        }
    }

    // Everything below degrades toward inclusion: a step that fails (budget, unreadable
    // directory) finds nothing, and what it would have excluded stays in the backup.
    let mut skipped: u32 = 0;
    let mut soft = |res: Result<Vec<PathBuf>, RulesError>| -> Vec<PathBuf> {
        res.unwrap_or_else(|e| {
            tracing_warn(&e);
            skipped += 1;
            Vec::new()
        })
    };

    // 2. Ordinary candidates: the editable list plus the Docker mode.
    let mut ordinary: BTreeSet<PathBuf> = BTreeSet::new();
    for pat in &rules.excludes {
        ordinary.extend(soft(w.expand(pat)));
    }
    ordinary.extend(soft(docker_candidates(&mut w, rules.docker)));

    // 3. Named caches.
    let mut named: BTreeSet<PathBuf> = BTreeSet::new();
    for p in under_homes(&FIXED_NAMED_CACHES) {
        named.extend(soft(w.expand(&builtin(&p))));
    }
    let suffixes: Vec<Vec<Segment>> = PROFILE_CACHE_SUFFIXES
        .iter()
        .map(|s| s.split('/').map(|p| Segment::parse(p)).collect())
        .collect::<Result<_, _>>()
        .map_err(|reason| RulesError::InvalidPattern {
            pattern: "profile cache suffix".to_owned(),
            reason,
        })?;
    named.extend(soft(w.profile_caches(&suffixes)));

    // 4. Decide.
    let mut accepted: Vec<PathBuf> = Vec::new();
    let mut rejected: Vec<RejectedExclude> = Vec::new();
    for c in &ordinary {
        match conflict(c, &protected, false) {
            None => accepted.push(c.clone()),
            Some((m, reason)) => rejected.push(RejectedExclude {
                path: abs(c),
                protected: abs(m),
                reason,
            }),
        }
    }
    for c in &named {
        // Named caches may sit inside a protected tree; they must not contain protected paths.
        if conflict(c, &protected, true).is_none() {
            accepted.push(c.clone());
        }
    }

    // 5. Normalise: sorted, deduplicated, nothing inside another entry.
    accepted.sort();
    accepted.dedup();
    let mut excluded: Vec<PathBuf> = Vec::with_capacity(accepted.len());
    for c in accepted {
        if excluded.last().is_none_or(|last| !c.starts_with(last)) {
            excluded.push(c);
        }
    }
    let excluded: Vec<PathBuf> = excluded.iter().map(|p| abs(p)).collect();
    // A refused candidate that a named cache (or anything else) excludes anyway is not news.
    rejected.retain(|r| !excluded.iter().any(|e| r.path.starts_with(e)));
    rejected.sort_by(|a, b| a.path.cmp(&b.path));

    Ok(ResolvedRules {
        excluded,
        protected: protected.iter().map(|p| abs(p)).collect(),
        rejected,
        discovery_skipped: skipped,
    })
}

/// The `tracing` dependency belongs to the `engine` feature; the rules stay free of it.
fn tracing_warn(_e: &RulesError) {
    #[cfg(feature = "engine")]
    tracing::warn!(error = %_e, "rule discovery step skipped; its paths stay in the backup");
}

/// The protected path a candidate conflicts with, if any. `named_cache` candidates may lie
/// strictly inside a protected tree.
fn conflict<'a>(
    c: &Path,
    protected: &'a BTreeSet<PathBuf>,
    named_cache: bool,
) -> Option<(&'a Path, RejectReason)> {
    for m in protected {
        if m.starts_with(c) {
            return Some((m, RejectReason::ContainsProtected));
        }
        if !named_cache && c.starts_with(m) {
            return Some((m, RejectReason::InsideProtected));
        }
    }
    None
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::os::unix::fs::symlink;

    fn tree(paths: &[&str]) -> tempfile::TempDir {
        let t = tempfile::tempdir().unwrap();
        for p in paths {
            let full = t.path().join(p);
            if p.ends_with('/') {
                fs::create_dir_all(&full).unwrap();
            } else {
                fs::create_dir_all(full.parent().unwrap()).unwrap();
                fs::write(&full, b"x").unwrap();
            }
        }
        t
    }

    fn strs(r: &ResolvedRules) -> Vec<String> {
        r.excluded()
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn builtin_patterns_parse() {
        for p in default_excludes()
            .into_iter()
            .chain(protected_patterns())
            .chain(under_homes(&BROWSER_ROOTS))
            .chain(under_homes(&FIXED_NAMED_CACHES))
        {
            PathPattern::parse(&p).unwrap();
        }
        for (mp, _) in MOUNT_POINTS {
            assert!(default_excludes().iter().any(|e| e == mp), "{mp}");
        }
    }

    #[test]
    fn invalid_patterns_are_rejected() {
        for bad in [
            "",
            "relative/path",
            "/",
            "//",
            "/a/../b",
            "/a/./b",
            "/a/**/b",
            "/a/b[",
            "/a\0b",
            &format!("/{}", "a".repeat(MAX_PATTERN_BYTES)),
            &format!("/{}", "a/".repeat(MAX_PATTERN_SEGMENTS + 1)),
        ] {
            assert!(
                matches!(
                    PathPattern::parse(bad),
                    Err(RulesError::InvalidPattern { .. })
                ),
                "{bad:?}"
            );
        }
        let many = (0..=MAX_EXCLUDES).map(|i| format!("/x{i}"));
        assert!(matches!(
            RuleSet::new(DockerMode::Complete, many),
            Err(RulesError::TooManyExcludes { .. })
        ));
    }

    #[test]
    fn wildcard_is_one_segment() {
        let t = tree(&[
            "home/alice/.config/App/Cache/x",
            "home/alice/.config/App/Deep/Cache/x",
        ]);
        let r = resolve(
            t.path(),
            &RuleSet::new(DockerMode::Complete, ["/home/*/.config/*/Cache"]).unwrap(),
        )
        .unwrap();
        assert_eq!(strs(&r), vec!["/home/alice/.config/App/Cache"]);
    }

    #[test]
    fn defaults_exclude_caches_and_keep_agent_state() {
        let t = tree(&[
            "home/alice/.cache/x",
            "home/alice/.config/App/Cache/x",
            "home/alice/.config/App/Code Cache/x",
            "home/alice/.config/App/Local Storage/leveldb/1",
            "home/alice/.claude/projects/s.jsonl",
            "home/alice/.claude/.credentials.json",
            "home/alice/.claude.json",
            "home/alice/.codex/auth.json",
            "home/alice/.local/share/Trash/files/t",
            "home/alice/.local/share/app/data.db",
            "root/.cache/y",
            "tmp/x",
            "proc/",
            "var/tmp/x",
            "var/log/syslog.log",
            "var/log/journal/j",
        ]);
        let r = resolve(t.path(), &RuleSet::with_defaults(DockerMode::Complete)).unwrap();
        let s = strs(&r);
        for want in [
            "/home/alice/.cache",
            "/home/alice/.config/App/Cache",
            "/home/alice/.config/App/Code Cache",
            "/home/alice/.local/share/Trash",
            "/root/.cache",
            "/tmp",
            "/proc",
            "/var/tmp",
            "/var/log/syslog.log",
            "/var/log/journal",
        ] {
            assert!(s.iter().any(|p| p == want), "missing {want} in {s:?}");
        }
        for banned in [
            ".claude",
            ".codex",
            "Local Storage",
            "share/app",
            ".credentials",
        ] {
            assert!(!s.iter().any(|p| p.contains(banned)), "{banned} in {s:?}");
        }
    }

    #[test]
    fn browser_profile_caches_are_excluded_inside_protected_profiles() {
        let t = tree(&[
            "home/alice/.config/chromium/Default/Cache/Cache_Data/f_1",
            "home/alice/.config/chromium/Default/Code Cache/js/x",
            "home/alice/.config/chromium/Default/GPUCache/x",
            "home/alice/.config/chromium/Default/Service Worker/CacheStorage/x",
            "home/alice/.config/chromium/Default/Service Worker/Database/000003.log",
            "home/alice/.config/chromium/Default/Service Worker/ScriptCache/x",
            "home/alice/.config/chromium/Profile 1/Cache/x",
            "home/alice/.config/chromium/ShaderCache/x",
            "home/alice/.config/chromium/Default/Cookies",
            "home/alice/.config/chromium/Default/Login Data",
            "home/alice/.config/chromium/Default/History",
            "home/alice/.config/chromium/Default/Local Storage/leveldb/CacheNotACache/x",
            "home/alice/.config/chromium/Default/IndexedDB/https_x_0.indexeddb.leveldb/Cache/y",
            "home/alice/.mozilla/firefox/abc.default/cache2/entries/e",
            "home/alice/.mozilla/firefox/abc.default/cookies.sqlite",
        ]);
        let r = resolve(t.path(), &RuleSet::with_defaults(DockerMode::Complete)).unwrap();
        let s = strs(&r);
        for want in [
            "/home/alice/.config/chromium/Default/Cache",
            "/home/alice/.config/chromium/Default/Code Cache",
            "/home/alice/.config/chromium/Default/GPUCache",
            "/home/alice/.config/chromium/Default/Service Worker/CacheStorage",
            "/home/alice/.config/chromium/Default/Service Worker/ScriptCache",
            "/home/alice/.config/chromium/Profile 1/Cache",
            "/home/alice/.config/chromium/ShaderCache",
            "/home/alice/.mozilla/firefox/abc.default/cache2",
        ] {
            assert!(s.iter().any(|p| p == want), "missing {want} in {s:?}");
        }
        // Data stays: nothing excluded outside the named caches, and the web-data directories
        // were not searched for caches.
        assert_eq!(s.len(), 8, "{s:?}");
    }

    #[test]
    fn user_excludes_cannot_remove_protected_paths() {
        let t = tree(&[
            "home/alice/.claude/projects/p",
            "home/alice/.config/Slack/Local Storage/x",
            "home/alice/.local/share/app/data",
        ]);
        let bad = [
            "/home",
            "/home/*",
            "/home/*/.claude",
            "/home/*/.claude/projects",
            "/home/*/.config/*",
            "/home/*/.config",
            "/home/*/.local/share/app",
            "/home/*/.local",
        ];
        let r = resolve(t.path(), &RuleSet::new(DockerMode::Complete, bad).unwrap()).unwrap();
        assert!(r.excluded().is_empty(), "{r}");
        assert!(!r.rejected().is_empty());
    }

    #[test]
    fn excluding_a_home_without_protected_content_is_allowed() {
        let t = tree(&["home/bob/stuff/a", "home/alice/.claude/x"]);
        let r = resolve(
            t.path(),
            &RuleSet::new(DockerMode::Complete, ["/home/bob"]).unwrap(),
        )
        .unwrap();
        assert_eq!(strs(&r), vec!["/home/bob"]);
    }

    #[test]
    fn symlinks_are_never_followed() {
        let outside = tree(&["secret/.cache/x", "secret/.claude/x"]);
        let t = tree(&["home/alice/keep"]);
        // A home that is a link to elsewhere, a link as an intermediate component, and a
        // link in place of the cache.
        symlink(outside.path().join("secret"), t.path().join("home/mallory")).unwrap();
        symlink(
            outside.path().join("secret"),
            t.path().join("home/alice/.config"),
        )
        .unwrap();
        symlink("/etc", t.path().join("home/alice/.cache")).unwrap();
        fs::create_dir_all(t.path().join("var/lib")).unwrap();
        symlink(
            outside.path().join("secret"),
            t.path().join("var/lib/docker"),
        )
        .unwrap();

        let rules = RuleSet::new(
            DockerMode::Light,
            [
                "/home/*/.cache",
                "/home/*/.config/*/Cache",
                "/home/mallory/.cache",
            ],
        )
        .unwrap();
        let r = resolve(t.path(), &rules).unwrap();
        // The link node itself may be excluded; nothing behind a link is ever reached.
        assert_eq!(strs(&r), vec!["/home/alice/.cache"]);
        // And protected paths behind links are not discovered through them.
        assert!(r.protected().is_empty(), "{r}");
    }

    #[test]
    fn docker_complete_excludes_only_buildkit() {
        let t = tree(&[
            "var/lib/docker/buildkit/cache.db",
            "var/lib/docker/overlay2/l/x",
            "var/lib/docker/volumes/v/_data/f",
        ]);
        let r = resolve(t.path(), &RuleSet::with_defaults(DockerMode::Complete)).unwrap();
        assert_eq!(strs(&r), vec!["/var/lib/docker/buildkit"]);
    }

    #[test]
    fn docker_light_keeps_volumes_and_container_configuration() {
        let t = tree(&[
            "var/lib/docker/buildkit/cache.db",
            "var/lib/docker/overlay2/l/x",
            "var/lib/docker/image/overlay2/imagedb",
            "var/lib/docker/volumes/v/_data/f",
            "var/lib/docker/volumes/metadata.db",
            "var/lib/docker/containers/abc/config.v2.json",
            "var/lib/docker/containers/abc/hostconfig.json",
            "var/lib/docker/containers/abc/abc-json.log",
            "var/lib/docker/containers/abc/mounts/shm/x",
        ]);
        let r = resolve(t.path(), &RuleSet::with_defaults(DockerMode::Light)).unwrap();
        let s = strs(&r);
        for want in [
            "/var/lib/docker/buildkit",
            "/var/lib/docker/overlay2",
            "/var/lib/docker/image",
            "/var/lib/docker/containers/abc/abc-json.log",
            "/var/lib/docker/containers/abc/mounts",
        ] {
            assert!(s.iter().any(|p| p == want), "missing {want} in {s:?}");
        }
        assert_eq!(s.len(), 5, "{s:?}");
    }

    #[test]
    fn missing_root_is_an_error_and_budget_degrades_toward_inclusion() {
        assert!(matches!(
            resolve(
                Path::new("/definitely/not/here"),
                &RuleSet::with_defaults(DockerMode::Complete)
            ),
            Err(RulesError::RootNotDirectory { .. })
        ));
        let t = tree(&[
            "a/1",
            "a/2",
            "a/3",
            "a/4",
            "home/alice/.claude/x",
            "home/alice/.config/chromium/Default/Cache/y",
            "home/alice/.cache/z",
        ]);
        let mut saw_full = false;
        for budget in [0, 1, 2, 5, 10, 20, 40, 60, 80, 100, 150, 200, 400, 10_000] {
            let rules = RuleSet::new(
                DockerMode::Complete,
                ["/a/*", "/home/*", "/home/*/.claude", "/home/*/.cache"],
            )
            .unwrap()
            .with_entry_budget(budget);
            // Never an error, and the protected path is never excluded, whatever ran out.
            let r = resolve(t.path(), &rules).unwrap();
            assert!(
                !r.is_excluded(Path::new("/home/alice/.claude/x")),
                "{budget}: {r}"
            );
            assert!(
                !r.is_excluded(Path::new("/home/alice/.claude")),
                "{budget}: {r}"
            );
            if r.discovery_skipped() == 0 {
                saw_full = true;
                assert!(r.is_excluded(Path::new("/a/3")));
                assert!(r.is_excluded(Path::new("/home/alice/.cache")));
            }
            if budget == 0 {
                // Protected paths could not be discovered: exclude nothing at all.
                assert!(r.excluded().is_empty() && r.discovery_skipped() == 1);
            }
        }
        assert!(saw_full);
    }

    #[test]
    fn globs_are_escaped_and_anchored() {
        let r = ResolvedRules {
            excluded: vec![
                PathBuf::from("/home/a/.config/X [1]/Code Cache"),
                PathBuf::from("/home/a/trailing "),
            ],
            ..ResolvedRules::default()
        };
        let g = r.rustic_globs(Path::new("/src/")).unwrap();
        assert_eq!(
            g.globs,
            vec![
                "!/src/home/a/.config/X \\[1\\]/Code Cache",
                "!/src/home/a/trailing\\ "
            ]
        );
    }

    #[test]
    fn non_utf8_excluded_paths_are_reported_not_dropped_silently() {
        use std::os::unix::ffi::OsStrExt;
        let odd = PathBuf::from(OsStr::from_bytes(b"/tmp/\xff"));
        let r = ResolvedRules {
            excluded: vec![odd.clone(), PathBuf::from("/tmp/ok")],
            ..ResolvedRules::default()
        };
        let g = r.rustic_globs(Path::new("/src")).unwrap();
        assert_eq!(g.globs, vec!["!/src/tmp/ok"]);
        assert_eq!(g.skipped_non_utf8, vec![odd]);
    }

    // -----------------------------------------------------------------------------------------
    // Property test with an independent oracle
    // -----------------------------------------------------------------------------------------

    fn seg() -> impl Strategy<Value = String> {
        prop_oneof![
            Just(".claude".to_string()),
            Just(".claude.json".to_string()),
            Just(".codex".to_string()),
            Just(".config".to_string()),
            Just(".local".to_string()),
            Just("share".to_string()),
            Just("Trash".to_string()),
            Just("Local Storage".to_string()),
            Just("IndexedDB".to_string()),
            Just("Session Storage".to_string()),
            Just("Cache".to_string()),
            Just("CacheStorage".to_string()),
            Just("Code Cache".to_string()),
            Just("GPUCache".to_string()),
            Just("chromium".to_string()),
            Just("Default".to_string()),
            Just(".cache".to_string()),
            Just("App".to_string()),
            Just("User".to_string()),
            Just("Code".to_string()),
            "[a-c]{1,2}",
        ]
    }

    fn pat_seg() -> impl Strategy<Value = String> {
        prop_oneof![4 => seg(), 1 => Just("*".to_string())]
    }

    /// Oracle: is the home-relative path inside (or equal to) a protected tree?
    fn oracle_protected(c: &[&str]) -> bool {
        let starts = |p: &[&str]| c.len() >= p.len() && c[..p.len()] == *p;
        let star =
            |p: &[&str]| c.len() >= p.len() && p.iter().zip(c).all(|(a, b)| *a == "*" || a == b);
        [".claude", ".claude.json", ".codex", ".gemini", ".cursor"]
            .iter()
            .any(|n| starts(&[n]))
            || starts(&[".local", "share"])
            || starts(&[".config", "chromium"])
            || starts(&[".mozilla"])
            || starts(&[".config", "Code", "User"])
            || star(&[".config", "*", "Local Storage"])
            || star(&[".config", "*", "IndexedDB"])
            || star(&[".config", "*", "Session Storage"])
    }

    /// Oracle: is the path, or one of its prefixes, a named cache location?
    fn oracle_named_cache(c: &[&str], leaf_is_dir: bool) -> bool {
        let n = c.len();
        (0..n).any(|i| {
            let pre = &c[..=i];
            let trash = pre == [".local", "share", "Trash"];
            let in_chromium = pre.len() > 2 && pre[..2] == [".config", "chromium"];
            // Not inside web data directories.
            let in_data = in_chromium
                && pre[2..pre.len() - 1]
                    .iter()
                    .any(|s| ["Local Storage", "IndexedDB", "Session Storage"].contains(s));
            let last = pre[pre.len() - 1];
            // Profile caches are directories; a plain file with such a name is just a file.
            let is_dir = i + 1 < n || leaf_is_dir;
            trash
                || (in_chromium
                    && is_dir
                    && !in_data
                    && (last.starts_with("Cache") || last == "Code Cache" || last == "GPUCache"))
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        #[test]
        fn protected_paths_survive_any_exclude_list(
            files in prop::collection::vec(prop::collection::vec(seg(), 1..6), 1..25),
            home in prop_oneof![Just("home/alice"), Just("root")],
            user in prop::collection::vec(prop::collection::vec(pat_seg(), 1..6), 0..8),
            use_defaults in any::<bool>(),
        ) {
            let t = tempfile::tempdir().unwrap();
            // The fixed paths come first, so that a random entry (a plain file named `.local`, say)
            // can never block them; random entries that collide with them are skipped below.
            let mut all: Vec<Vec<String>> = Vec::new();
            for must in [
                ".claude/projects/s.jsonl",
                ".claude/.credentials.json",
                ".config/App/Local Storage/leveldb/1.ldb",
                ".config/App/Cache/x",
                ".config/chromium/Default/Cache/y",
                ".config/chromium/Default/Cookies",
                ".cache/z",
                ".local/share/Trash/files/t",
                ".local/share/keyrings/login.keyring",
                ".config/Code/User/settings.json",
            ] {
                all.push(must.split('/').map(str::to_owned).collect());
            }
            all.extend(files);
            for f in &all {
                let full = t.path().join(home).join(f.join("/"));
                // A path may collide with a file made by an earlier entry; ignore those.
                if let Some(parent) = full.parent()
                    && fs::create_dir_all(parent).is_err()
                {
                    continue;
                }
                if !full.exists() { let _ = fs::write(&full, b"x"); }
            }
            let mut pats: Vec<String> = if use_defaults { default_excludes() } else { vec![] };
            for u in &user {
                pats.push(format!("/{home}/{}", u.join("/")));
            }
            let rules = RuleSet::new(DockerMode::Complete, pats).unwrap();
            let r = resolve(t.path(), &rules).unwrap();

            // Walk every real path of the tree and check it against the oracle.
            let mut stack = vec![t.path().join(home)];
            let mut seen_named_cache_root = 0usize;
            while let Some(dir) = stack.pop() {
                for e in fs::read_dir(&dir).unwrap().flatten() {
                    let p = e.path();
                    let rel_home = p.strip_prefix(t.path().join(home)).unwrap().to_path_buf();
                    let comps: Vec<String> = rel_home
                        .components()
                        .map(|c| c.as_os_str().to_string_lossy().into_owned())
                        .collect();
                    let comps: Vec<&str> = comps.iter().map(String::as_str).collect();
                    let abs_path = Path::new("/").join(home).join(&rel_home);
                    let excluded = r.is_excluded(&abs_path);
                    let is_dir = e.file_type().unwrap().is_dir();
                    let named = oracle_named_cache(&comps, is_dir);
                    if oracle_protected(&comps) && !named {
                        prop_assert!(!excluded, "protected {} excluded\n{}", abs_path.display(), r);
                    }
                    // Ancestors of protected content are never excluded either: a directory
                    // that is an ancestor of an existing protected path stays.
                    if excluded && !named {
                        // Everything excluded and not named cache must contain no protected path.
                        prop_assert!(!oracle_protected(&comps), "{}", abs_path.display());
                    }
                    if named && oracle_protected(&comps) {
                        // Named caches in protected trees are excluded unless they hold a
                        // protected path themselves (none of the vocabulary does).
                        prop_assert!(excluded, "named cache {} kept\n{}", abs_path.display(), r);
                        seen_named_cache_root += 1;
                    }
                    if is_dir { stack.push(p); }
                }
            }
            prop_assert!(seen_named_cache_root > 0);
            // Concrete protected paths are reachable: no excluded entry is their ancestor.
            for m in r.protected() {
                prop_assert!(!r.is_excluded(m), "{} excluded\n{}", m.display(), r);
            }
            // Canonical credential files in particular.
            for cred in [".claude/.credentials.json", ".claude/projects/s.jsonl"] {
                prop_assert!(!r.is_excluded(&Path::new("/").join(home).join(cred)));
            }
        }
    }
}
