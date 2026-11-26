//! The backup engine: `rustic_core` operations against any rustic backend.
//!
//! The engine knows nothing about Google Drive, Incus, HTTP or `hx-privd`. It is handed a
//! rustic backend (a [`RepositoryBackends`], or one `Arc<dyn WriteBackend>`), the repository key
//! and, per call, a source tree or a restore target as a plain path.
//!
//! # Where the manifest lives
//!
//! The [`Manifest`] is stored as the snapshot's *description* (`SnapshotFile::description`),
//! not as a file inside the snapshot:
//!
//! * it is part of the encrypted snapshot object, so it travels with the repository and needs no
//!   separate upload or index entry;
//! * it is readable from a snapshot listing without walking the tree or fetching data packs
//!   (a restore-onto-a-new-server picker needs it before any file is chosen);
//! * it does not pollute the restored root file system, and cannot be shadowed by the source
//!   tree or by an exclude rule;
//! * its size is bounded ([`crate::manifest::MAX_MANIFEST_BYTES`]) and it is parsed strictly.
//!
//! The cost is that the manifest cannot contain its own snapshot id; [`Engine::read_manifest`]
//! and [`Engine::snapshots`] fill `rustic_snapshot_id` in when reading it back.
//!
//! # Repository key
//!
//! [`RepoKey`] holds the key in a zeroizing buffer and never prints it. `rustic_core` takes the
//! password as a `String`, so a copy of it lives inside rustic for as long as the repository is
//! open and is not wiped by this crate.

mod integrity;
mod progress;
mod scan;

use std::fmt;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use jiff::{Timestamp, tz::TimeZone};
use rustic_core::repofile::SnapshotFile;
use rustic_core::{
    BackupOptions, CheckOptions, ConfigOptions, Credentials, IndexedFullStatus, KeepOptions,
    KeyOptions, LocalDestination, LsOptions, OpenStatus, PathList, PruneOptions, ReadSubsetOption,
    Repository, RepositoryOptions, RestoreOptions, RusticError, SnapshotOptions,
};
use zeroize::{Zeroize, Zeroizing};

use crate::manifest::{Manifest, ManifestError, ManifestInput, restorable_container_config};
use crate::rules::{self, ResolvedRules, RuleSet, RulesError};

pub use progress::{CancelToken, NullSink, Phase, ProgressEvent, ProgressSink, ProgressUnit};
pub use rustic_core::{ReadBackend, RepositoryBackends, WriteBackend};

use integrity::IndexGuard;
pub use integrity::MAX_DUPLICATE_VERIFY_BYTES;
use progress::{Bars, Shared};

/// zstd level used for new repositories (architecture 9.4: level 9 cost about 70% more CPU for
/// 4% smaller output).
pub const DEFAULT_COMPRESSION_LEVEL: i32 = 3;
/// Largest accepted repository key, in bytes.
pub const MAX_KEY_BYTES: usize = 1024;
/// Largest accepted tag, in bytes.
const MAX_TAG_BYTES: usize = 64;
/// Most tags per snapshot.
const MAX_TAGS: usize = 16;

/// Engine errors.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// The key is empty, too long or not valid UTF-8.
    #[error("invalid repository key: {0}")]
    InvalidKey(&'static str),
    /// The key does not open this repository.
    #[error("the repository key is wrong")]
    WrongKey,
    /// [`OpenMode::OpenExisting`] and the location holds no repository.
    #[error("no repository exists at this location")]
    RepositoryNotFound,
    /// The cancellation token was triggered.
    #[error("cancelled")]
    Cancelled,
    /// A request field is not acceptable.
    #[error("invalid {what}: {reason}")]
    InvalidInput {
        /// Which field.
        what: &'static str,
        /// What is wrong.
        reason: String,
    },
    /// No snapshot matches the selector.
    #[error("snapshot not found: {0}")]
    SnapshotNotFound(String),
    /// The snapshot carries no valid manifest.
    #[error("snapshot {id} has no valid manifest: {reason}")]
    NoManifest {
        /// The snapshot.
        id: SnapshotId,
        /// Why.
        reason: String,
    },
    /// Rules could not be built or resolved.
    #[error(transparent)]
    Rules(#[from] RulesError),
    /// The manifest is invalid.
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    /// A local filesystem operation failed.
    #[error("{context}: {source}")]
    Io {
        /// What was being done.
        context: &'static str,
        /// The OS error.
        #[source]
        source: std::io::Error,
    },
    /// The process lacks a capability the request needs.
    #[error("missing capability {0}: needed to restore numeric owner ids")]
    MissingCapability(&'static str),
    /// A restored entry does not have the owner or mode recorded in the snapshot.
    #[error(
        "{mismatches} restored entries differ from the snapshot (owner or mode); first: {examples:?}"
    )]
    RestoreVerification {
        /// How many entries differ.
        mismatches: usize,
        /// Up to five paths (lossy), for the log.
        examples: Vec<String>,
    },
    /// A previous call failed while loading the index and consumed the repository handle;
    /// open the engine again.
    #[error("the engine is closed after a failed index load; open it again")]
    Closed,
    /// A prune was refused because the repository does not read back as its index says (ipc.md
    /// section 36, Q-S1): nothing was deleted.
    #[error("prune refused, the repository failed verification: {finding}")]
    Integrity {
        /// What was found (never contains key material).
        finding: String,
    },
    /// `rustic_core` (or the backend behind it) failed.
    #[error("{operation} failed: {source}")]
    Repository {
        /// Engine operation.
        operation: &'static str,
        /// The rustic error.
        #[source]
        source: Box<RusticError>,
    },
}

fn rustic(operation: &'static str) -> impl FnOnce(Box<RusticError>) -> EngineError {
    move |source| EngineError::Repository { operation, source }
}

/// The repository key. Zeroized on drop; `Debug` is redacted; not `Clone`.
pub struct RepoKey(Zeroizing<Vec<u8>>);

impl RepoKey {
    /// Wrap key bytes (a UTF-8 passphrase, as rustic derives the master key from a password).
    ///
    /// # Errors
    /// [`EngineError::InvalidKey`] when empty, longer than [`MAX_KEY_BYTES`] or not UTF-8.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, EngineError> {
        let bytes = Zeroizing::new(bytes.into());
        if bytes.is_empty() {
            return Err(EngineError::InvalidKey("empty"));
        }
        if bytes.len() > MAX_KEY_BYTES {
            return Err(EngineError::InvalidKey("too long"));
        }
        if std::str::from_utf8(&bytes).is_err() {
            return Err(EngineError::InvalidKey("not valid UTF-8"));
        }
        Ok(Self(bytes))
    }

    fn as_str(&self) -> Result<&str, EngineError> {
        std::str::from_utf8(&self.0).map_err(|_| EngineError::InvalidKey("not valid UTF-8"))
    }

    /// A password credential, never a raw master key, so stock rustic and restic can open the
    /// repository with the same passphrase.
    fn credentials(&self) -> Result<Credentials, EngineError> {
        Ok(Credentials::Password(self.as_str()?.to_owned()))
    }
}

impl fmt::Debug for RepoKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RepoKey(<redacted>)")
    }
}

/// A snapshot id: 64 lowercase hex digits.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SnapshotId(String);

impl SnapshotId {
    /// The hex string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for SnapshotId {
    type Err = EngineError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            Ok(Self(s.to_owned()))
        } else {
            Err(EngineError::InvalidInput {
                what: "snapshot id",
                reason: "expected 64 lowercase hex digits".to_owned(),
            })
        }
    }
}

impl fmt::Display for SnapshotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The id of a key file: 64 lowercase hex digits.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyId(String);

impl KeyId {
    /// The hex string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for KeyId {
    type Err = EngineError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SnapshotId::from_str(s)
            .map(|i| Self(i.0))
            .map_err(|_| EngineError::InvalidInput {
                what: "key id",
                reason: "expected 64 lowercase hex digits".to_owned(),
            })
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which snapshot to act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotSelector {
    /// The newest snapshot.
    Latest,
    /// This snapshot.
    Id(SnapshotId),
}

/// Whether to create a missing repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OpenMode {
    /// Fail with [`EngineError::RepositoryNotFound`] when there is no repository. The default:
    /// a missing repository (wrong location, a listing that came back empty) must not turn into
    /// a silently created new one.
    #[default]
    OpenExisting,
    /// Create the repository when there is none. Ask for it explicitly. A wrong key on an
    /// existing repository is still an error: it is never re-initialised.
    OpenOrInit,
}

/// Options for [`Engine::open`].
#[derive(Debug, Clone)]
pub struct EngineOptions {
    /// zstd level for a repository created by this call (ignored when opening an existing one).
    pub compression_level: i32,
    /// Open or init.
    pub open_mode: OpenMode,
}

impl Default for EngineOptions {
    /// [`OpenMode::OpenExisting`], zstd level 3 (used when a repository is created).
    fn default() -> Self {
        Self {
            compression_level: DEFAULT_COMPRESSION_LEVEL,
            open_mode: OpenMode::default(),
        }
    }
}

/// A backup request.
#[derive(Debug, Clone)]
pub struct BackupRequest {
    /// Root of the (mounted, read-only) tree to back up; stored in the snapshot as `/`.
    pub source: PathBuf,
    /// Exclude and protected-path rules.
    pub rules: RuleSet,
    /// What goes into the manifest besides time, sizes and the Docker mode (which always comes
    /// from `rules`: one source of truth). `docker_enabled` says whether Docker is in use.
    pub manifest: ManifestInput,
    /// Whether Docker is enabled on the desktop; the manifest records `rules.docker_mode()` if so.
    pub docker_enabled: bool,
    /// Extra tags (letters, digits, `-`, `_`, `.`, `:`; at most 64 bytes, at most 16 tags).
    /// `hx-backup` is always added.
    pub tags: Vec<String>,
    /// Host name recorded in the snapshot. Snapshots with the same host and paths are chained
    /// as parents for incremental backups, so keep it stable for a desktop.
    pub host: String,
    /// Snapshot time; now when `None` (tests and synthetic snapshots).
    pub time: Option<Timestamp>,
}

/// Exact figures of a finished backup run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BackupSummary {
    /// Files not in the parent snapshot.
    pub files_new: u64,
    /// Files changed since the parent.
    pub files_changed: u64,
    /// Files identical to the parent's.
    pub files_unmodified: u64,
    /// All files processed.
    pub total_files: u64,
    /// All bytes processed.
    pub total_bytes: u64,
    /// New data added to the repository before compression.
    pub data_added: u64,
    /// New data added to the repository, as stored (compressed and encrypted).
    pub data_added_packed: u64,
    /// Files or directories rustic could not read or archive. The snapshot was still written,
    /// without them: **a non-zero count means a partial backup** and the caller must not report
    /// it as a clean success.
    pub error_count: u64,
}

/// The result of a backup.
#[derive(Debug, Clone)]
pub struct BackupOutcome {
    /// The new snapshot.
    pub snapshot_id: SnapshotId,
    /// The manifest stored with it, with `rustic_snapshot_id` filled in.
    pub manifest: Manifest,
    /// Exact figures from rustic.
    pub summary: BackupSummary,
    /// The rules as resolved against the tree.
    pub resolved: ResolvedRules,
    /// Excluded paths that could not be expressed as globs (not UTF-8) and so stayed in the backup.
    pub skipped_non_utf8: Vec<PathBuf>,
    /// Container configuration entries left out of the manifest by the allow-list.
    pub config_entries_dropped: usize,
}

impl BackupOutcome {
    /// Whether the backup is partial: rustic skipped unreadable files
    /// ([`BackupSummary::error_count`]) or the pre-backup scan could not read part of the tree.
    #[must_use]
    pub fn is_partial(&self) -> bool {
        self.summary.error_count > 0 || self.manifest.source_sizes.unreadable_entries > 0
    }
}

/// How a restore treats files already present in the target (resume).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Resume {
    /// Read and checksum existing files; skip those that match the snapshot, rewrite the rest.
    /// Safe after an interruption (a half-written file is never trusted). The default.
    #[default]
    VerifyContent,
    /// Trust size and modification time of existing files. Faster, but not a content check.
    TrustMetadata,
}

/// How a restore treats file ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Ownership {
    /// Restore the numeric uid/gid recorded in the snapshot, never looking names up in the
    /// target's databases (the target has none of its own yet). Needs root. The default.
    #[default]
    Numeric,
    /// Do not touch ownership (restores as an unprivileged user; tests).
    Skip,
}

/// A restore request.
#[derive(Debug, Clone)]
pub struct RestoreRequest {
    /// Snapshot to restore.
    pub snapshot: SnapshotSelector,
    /// Directory to restore into; created when missing.
    pub target: PathBuf,
    /// Recreate holes for zero-filled blocks so sparse files stay sparse.
    pub sparse: bool,
    /// Resume behaviour for files already in `target`.
    pub resume: Resume,
    /// Ownership handling.
    pub ownership: Ownership,
    /// Recreate `/proc`, `/sys`, `/dev`, `/run`, `/tmp`, `/var/tmp` when missing.
    pub recreate_mount_points: bool,
}

impl RestoreRequest {
    /// A request with the safe defaults for a full desktop restore.
    #[must_use]
    pub fn new(snapshot: SnapshotSelector, target: impl Into<PathBuf>) -> Self {
        Self {
            snapshot,
            target: target.into(),
            sparse: true,
            resume: Resume::default(),
            ownership: Ownership::default(),
            recreate_mount_points: true,
        }
    }
}

/// The result of a restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreOutcome {
    /// The snapshot restored.
    pub snapshot_id: SnapshotId,
    /// Files written in this run.
    pub files_restored: u64,
    /// Files already in place and skipped on size and mtime.
    pub files_unchanged: u64,
    /// Files already in place and skipped after a content check.
    pub files_verified: u64,
    /// Bytes written in this run.
    pub bytes_restored: u64,
    /// Bytes already present and skipped.
    pub bytes_matched: u64,
    /// Mount-point directories created.
    pub mount_points_created: Vec<PathBuf>,
}

/// Retention rules (counts of snapshots to keep per period; `0` or `None` disables a period).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeepRules {
    /// Newest N snapshots.
    pub last: Option<u32>,
    /// One per hour for N hours.
    pub hourly: Option<u32>,
    /// One per day for N days.
    pub daily: Option<u32>,
    /// One per week for N weeks.
    pub weekly: Option<u32>,
    /// One per month for N months.
    pub monthly: Option<u32>,
    /// One per year for N years.
    pub yearly: Option<u32>,
}

/// A forget request.
#[derive(Debug, Clone, Copy)]
pub struct ForgetRequest {
    /// What to keep. At least one period must be set.
    pub keep: KeepRules,
    /// The newest N snapshots are never removed, whatever `keep` says (architecture 12:
    /// retention never deletes the latest successes).
    pub protect_latest: usize,
    /// Only report.
    pub dry_run: bool,
    /// Reference time; now when `None`.
    pub now: Option<Timestamp>,
}

impl ForgetRequest {
    /// A request protecting the two newest snapshots.
    #[must_use]
    pub fn new(keep: KeepRules) -> Self {
        Self {
            keep,
            protect_latest: 2,
            dry_run: false,
            now: None,
        }
    }
}

/// The result of a forget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgetOutcome {
    /// Snapshots kept.
    pub kept: Vec<SnapshotId>,
    /// Snapshots removed (or that would be, in a dry run).
    pub removed: Vec<SnapshotId>,
    /// Snapshots the keep rules would have removed but `protect_latest` saved.
    pub protected: Vec<SnapshotId>,
}

/// The result of a prune. Prune always deletes immediately (rustic's `--instant`): otherwise
/// rustic keeps removed packs for 23 hours, which on Google Drive means space is freed a day late.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PruneOutcome {
    /// Bytes of unused data found.
    pub unused_bytes: u64,
    /// Bytes removed from the repository.
    pub removed_bytes: u64,
    /// Bytes rewritten into new packs.
    pub repacked_bytes: u64,
}

/// How much pack data a check reads.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ReadData {
    /// Metadata only (index, snapshots, trees).
    None,
    /// A random subset of about this percentage of the data, `0 < p <= 100` (100 reads everything).
    Percent(f64),
    /// Everything.
    All,
}

/// The result of a check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckReport {
    /// No errors found (warnings do not fail a check).
    pub ok: bool,
    /// Findings, one line each, prefixed with their severity.
    pub findings: Vec<String>,
    /// Bytes of pack data rustic read to verify (0 for a metadata-only check). rustic does not
    /// report how many packs that was.
    pub bytes_read: u64,
}

/// A snapshot as listed.
#[derive(Debug, Clone)]
pub struct SnapshotInfo {
    /// Its id.
    pub id: SnapshotId,
    /// Snapshot time.
    pub time: Timestamp,
    /// Host recorded.
    pub host: String,
    /// Tags.
    pub tags: Vec<String>,
    /// The manifest, when the description holds a valid one.
    pub manifest: Option<Manifest>,
}

/// An open repository.
pub struct Engine {
    /// `None` only after loading the index failed (the repository handle is consumed by that call).
    repo: Option<Repository<OpenStatus>>,
    shared: Arc<Shared>,
    /// The repository backend as rustic sees it: hides unreadable index files, defers removals.
    guard: Arc<IndexGuard>,
}

impl fmt::Debug for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Engine").finish_non_exhaustive()
    }
}

impl Engine {
    fn repo(&self) -> Result<&Repository<OpenStatus>, EngineError> {
        self.repo.as_ref().ok_or(EngineError::Closed)
    }
}

/// The full hex form of a rustic snapshot id (its `Display` is the short form).
fn hex_id<T: std::ops::Deref<Target = rustic_core::Id>>(id: T) -> Result<SnapshotId, EngineError> {
    id.to_hex().as_str().parse()
}

fn selector_string(sel: &SnapshotSelector) -> String {
    match sel {
        SnapshotSelector::Latest => "latest".to_owned(),
        SnapshotSelector::Id(id) => id.to_string(),
    }
}

fn to_u32_i32(n: Option<u32>) -> Option<i32> {
    n.filter(|n| *n > 0)
        .map(|n| i32::try_from(n).unwrap_or(i32::MAX))
}

fn validate_tag(tag: &str) -> Result<(), EngineError> {
    let ok = !tag.is_empty()
        && tag.len() <= MAX_TAG_BYTES
        && tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'));
    if ok {
        Ok(())
    } else {
        Err(EngineError::InvalidInput {
            what: "tag",
            reason: format!("must be 1-{MAX_TAG_BYTES} bytes of [A-Za-z0-9-_.:]"),
        })
    }
}

impl Engine {
    /// Open (or create) the repository behind `backends`.
    ///
    /// # Errors
    /// [`EngineError::WrongKey`], [`EngineError::RepositoryNotFound`],
    /// [`EngineError::InvalidInput`] (compression level), [`EngineError::Repository`].
    pub fn open(
        backends: &RepositoryBackends,
        key: &RepoKey,
        options: &EngineOptions,
        sink: Arc<dyn ProgressSink>,
    ) -> Result<Self, EngineError> {
        let shared = Shared::new(sink);
        shared.set_phase(Phase::OpenRepository);
        // No local cache, ever: the worker is sandboxed and must not create directories.
        let ropts = RepositoryOptions::default().no_cache(true);
        let guard = Arc::new(IndexGuard::new(backends.repository()));
        let guarded = RepositoryBackends::new(guard.clone(), backends.repo_hot());
        let repo = Repository::new_with_progress(&ropts, &guarded, Bars(Arc::clone(&shared)))
            .map_err(rustic("opening the repository"))?;
        let mut creds = key.credentials()?;
        let opened = Self::open_or_init(repo, &creds, options);
        // The engine's own copy of the password is wiped; rustic keeps its own while open.
        if let Credentials::Password(p) = &mut creds {
            p.zeroize();
        }
        let repo = opened?;
        Ok(Self {
            repo: Some(repo),
            shared,
            guard,
        })
    }

    fn open_or_init(
        repo: Repository<()>,
        creds: &Credentials,
        options: &EngineOptions,
    ) -> Result<Repository<OpenStatus>, EngineError> {
        let exists = repo
            .config_id()
            .map_err(rustic("looking for the repository"))?
            .is_some();
        let repo = if exists {
            repo.open(creds).map_err(|e| {
                if e.is_incorrect_password() {
                    EngineError::WrongKey
                } else {
                    rustic("opening the repository")(e)
                }
            })?
        } else {
            if options.open_mode == OpenMode::OpenExisting {
                return Err(EngineError::RepositoryNotFound);
            }
            if !rustic_core::compression_level_range().contains(&options.compression_level) {
                return Err(EngineError::InvalidInput {
                    what: "compression level",
                    reason: format!("outside {:?}", rustic_core::compression_level_range()),
                });
            }
            // Packs stay at most 64 MiB (data) and 16 MiB (tree): the link to the privileged side
            // caps objects at 96 MiB, and rustic's own limit is u32::MAX. `ByteSize` is not
            // exported by rustic_core, so the options go in through their serde form.
            let cfg: ConfigOptions = serde_json::from_value(serde_json::json!({
                "set-compression": options.compression_level,
                "set-datapack-size-limit": "64 MiB",
                "set-treepack-size-limit": "16 MiB",
            }))
            .map_err(|e| EngineError::InvalidInput {
                what: "repository configuration",
                reason: e.to_string(),
            })?;
            repo.init(creds, &KeyOptions::default(), &cfg)
                .map_err(rustic("initialising the repository"))?
        };
        Ok(repo)
    }

    /// Open (or create) a repository on a single backend.
    ///
    /// # Errors
    /// As [`Engine::open`].
    pub fn open_with_backend(
        backend: Arc<dyn WriteBackend>,
        key: &RepoKey,
        options: &EngineOptions,
        sink: Arc<dyn ProgressSink>,
    ) -> Result<Self, EngineError> {
        Self::open(&RepositoryBackends::new(backend, None), key, options, sink)
    }

    /// The zstd level the repository was configured with (`None`: not compressed).
    ///
    /// # Errors
    /// [`EngineError::Repository`] if the configuration is unreadable.
    pub fn compression_level(&self) -> Result<Option<i32>, EngineError> {
        self.repo()?
            .config()
            .zstd()
            .map_err(rustic("reading the repository configuration"))
    }

    /// The configured pack size limits in bytes: (data, tree).
    ///
    /// # Errors
    /// [`EngineError::Closed`].
    pub fn pack_size_limits(&self) -> Result<(Option<u32>, Option<u32>), EngineError> {
        let c = self.repo()?.config();
        Ok((c.datapack_size_limit, c.treepack_size_limit))
    }

    /// Add a second key (for example the recovery key) that opens the same repository. The new
    /// key is an ordinary rustic key file, so stock rustic or restic can open the repository
    /// with it. Returns the new key file's id.
    ///
    /// # Errors
    /// [`EngineError::InvalidKey`], [`EngineError::Repository`].
    pub fn add_key(&self, new_key: &RepoKey) -> Result<KeyId, EngineError> {
        let id = self
            .repo()?
            .add_key(new_key.as_str()?, &KeyOptions::default())
            .map_err(rustic("adding a key"))?;
        hex_id(id)?.0.parse()
    }

    /// Remove a key file. The key this engine was opened with cannot be removed, so at least
    /// one key always remains.
    ///
    /// # Errors
    /// [`EngineError::Repository`] (including the refusal to remove the key in use).
    pub fn remove_key(&self, id: &KeyId) -> Result<(), EngineError> {
        let raw = id
            .as_str()
            .parse::<rustic_core::Id>()
            .map_err(rustic("reading the key id"))?;
        self.repo()?
            .delete_key(&raw.into())
            .map_err(rustic("removing a key"))
    }

    /// Back up `req.source`.
    ///
    /// Steps: `repair index` (so packs left by an interrupted run are reused instead of
    /// uploaded again), resolve the rules, measure the source, write the manifest into the
    /// snapshot description, back up with the resolved excludes. The caller owns the
    /// single-writer repository lock (rustic has none).
    ///
    /// # Errors
    /// [`EngineError::Cancelled`] between steps, [`EngineError::InvalidInput`],
    /// [`EngineError::Rules`], [`EngineError::Manifest`], [`EngineError::Io`],
    /// [`EngineError::Repository`].
    pub fn backup(
        &mut self,
        req: &BackupRequest,
        cancel: &CancelToken,
    ) -> Result<BackupOutcome, EngineError> {
        cancel.check()?;
        if req.tags.len() > MAX_TAGS {
            return Err(EngineError::InvalidInput {
                what: "tags",
                reason: format!("more than {MAX_TAGS}"),
            });
        }
        for t in &req.tags {
            validate_tag(t)?;
        }
        if req.host.is_empty() || req.host.len() > 255 || req.host.chars().any(char::is_control) {
            return Err(EngineError::InvalidInput {
                what: "host",
                reason: "must be 1-255 bytes without control characters".to_owned(),
            });
        }
        let source = fs::canonicalize(&req.source).map_err(|source| EngineError::Io {
            context: "resolving the backup source",
            source,
        })?;
        if !source.is_dir() {
            return Err(EngineError::InvalidInput {
                what: "source",
                reason: "not a directory".to_owned(),
            });
        }
        let source_str = source.to_str().ok_or_else(|| EngineError::InvalidInput {
            what: "source",
            reason: "path is not valid UTF-8".to_owned(),
        })?;

        // Step 0: orphan packs from an interrupted run become part of the index.
        self.shared.set_phase(Phase::RepairIndex);
        self.repair_index_for_backup()?;
        cancel.check()?;

        self.shared.set_phase(Phase::ResolveRules);
        let resolved = rules::resolve(&source, &req.rules)?;
        tracing::info!(
            excluded = resolved.excluded().len(),
            protected = resolved.protected().len(),
            rejected = resolved.rejected().len(),
            "resolved backup rules"
        );
        let globs = resolved.rustic_globs(&source)?;
        for p in &globs.skipped_non_utf8 {
            tracing::warn!(path = %p.display(), "excluded path is not UTF-8; it stays in the backup");
        }
        cancel.check()?;

        self.shared.set_phase(Phase::ScanSource);
        let shared = Arc::clone(&self.shared);
        let sizes = scan::scan_source(&source, &resolved, cancel, &mut |files| {
            shared.emit(
                ProgressUnit::Items,
                "measuring the source",
                files,
                None,
                false,
            );
        })?;
        self.shared.emit(
            ProgressUnit::Items,
            "measuring the source",
            sizes.files,
            Some(sizes.files),
            true,
        );

        let time = req.time.unwrap_or_else(Timestamp::now);
        let docker_mode = req.docker_enabled.then(|| req.rules.docker_mode());
        let config_entries_dropped =
            restorable_container_config(&req.manifest.container_config).dropped;
        if config_entries_dropped > 0 {
            tracing::warn!(
                dropped = config_entries_dropped,
                "container configuration entries are not on the allow-list; left out of the manifest"
            );
        }
        let manifest = Manifest::new(req.manifest.clone(), docker_mode, time, sizes)?;
        let description = manifest.to_json()?;

        let mut snap_opts = SnapshotOptions::default()
            .host(req.host.clone())
            // A fixed command: the worker's argv must not be recorded in every snapshot.
            .command("hx-backup".to_owned())
            .description(description)
            .time(time.to_zoned(TimeZone::UTC));
        snap_opts = snap_opts
            .add_tags("hx-backup")
            .map_err(rustic("tagging the snapshot"))?;
        for t in &req.tags {
            snap_opts = snap_opts
                .add_tags(t)
                .map_err(rustic("tagging the snapshot"))?;
        }
        let snap = snap_opts
            .to_snapshot()
            .map_err(rustic("building the snapshot"))?;

        let mut bo = BackupOptions::default().as_path(PathBuf::from("/"));
        bo.excludes.globs = globs.globs;
        // The snapshot is mounted anew for every run, so inode numbers are meaningless.
        bo.parent_opts.ignore_inode = true;
        let paths = PathList::from_string(source_str)
            .map_err(rustic("reading the source path"))?
            .sanitize()
            .map_err(|e| EngineError::InvalidInput {
                what: "source",
                reason: e.to_string(),
            })?;

        cancel.check()?;
        self.shared.set_phase(Phase::Backup);
        let open = self.repo.take().ok_or(EngineError::Closed)?;
        let indexed = open.to_indexed_ids().map_err(rustic("loading the index"))?;
        let result = indexed.backup(&bo, &paths, snap);
        self.repo = Some(indexed.drop_index());
        let snap = result.map_err(rustic("backing up"))?;
        let id: SnapshotId = hex_id(snap.id)?;
        let s = snap.summary.unwrap_or_default();
        let manifest = manifest.with_snapshot_id(id.as_str())?;
        Ok(BackupOutcome {
            snapshot_id: id,
            manifest,
            summary: BackupSummary {
                files_new: s.files_new,
                files_changed: s.files_changed,
                files_unmodified: s.files_unmodified,
                total_files: s.total_files_processed,
                total_bytes: s.total_bytes_processed,
                data_added: s.data_added,
                data_added_packed: s.data_added_packed,
                error_count: s.error_count,
            },
            resolved,
            skipped_non_utf8: globs.skipped_non_utf8,
            config_entries_dropped,
        })
    }

    /// List snapshots, oldest first, with their manifests.
    ///
    /// # Errors
    /// [`EngineError::Repository`].
    pub fn snapshots(&self) -> Result<Vec<SnapshotInfo>, EngineError> {
        let mut snaps = self
            .repo()?
            .get_all_snapshots()
            .map_err(rustic("listing snapshots"))?;
        snaps.sort_by(|a, b| a.time.cmp(&b.time));
        snaps.iter().map(snapshot_info).collect()
    }

    /// Read the manifest of one snapshot.
    ///
    /// # Errors
    /// [`EngineError::SnapshotNotFound`], [`EngineError::NoManifest`], [`EngineError::Repository`].
    pub fn read_manifest(&self, sel: &SnapshotSelector) -> Result<Manifest, EngineError> {
        let snap = self.find_snapshot(sel)?;
        let id: SnapshotId = hex_id(snap.id)?;
        let desc = snap
            .description
            .as_deref()
            .ok_or_else(|| EngineError::NoManifest {
                id: id.clone(),
                reason: "no description".to_owned(),
            })?;
        Manifest::from_slice(desc.as_bytes())
            .and_then(|m| m.with_snapshot_id(id.as_str()))
            .map_err(|e| EngineError::NoManifest {
                id,
                reason: e.to_string(),
            })
    }

    fn find_snapshot(&self, sel: &SnapshotSelector) -> Result<SnapshotFile, EngineError> {
        let s = selector_string(sel);
        self.repo()?
            .get_snapshot_from_str(&s, |_| true)
            .map_err(|e| {
                // rustic reports an unknown id or an empty repository as a plain input error.
                tracing::debug!(selector = %s, error = %e, "snapshot lookup failed");
                EngineError::SnapshotNotFound(s.clone())
            })
    }

    /// Restore a snapshot into `req.target`.
    ///
    /// Numeric owner ids, permissions, extended attributes, symlinks and hard links are
    /// restored; sparse files stay sparse (`req.sparse`); the mount points that backups skip
    /// are recreated. With the default [`Resume::VerifyContent`], files already present and
    /// matching the snapshot are skipped, so an interrupted restore continues with what is
    /// missing. Restoring onto a new server must also give the desktop a new hostname and
    /// `/etc/machine-id`; that is the caller's step (architecture 9.8 item 6).
    ///
    /// # Errors
    /// [`EngineError::Cancelled`] (checked before the data transfer starts),
    /// [`EngineError::SnapshotNotFound`], [`EngineError::InvalidInput`], [`EngineError::Io`],
    /// [`EngineError::Repository`].
    pub fn restore(
        &mut self,
        req: &RestoreRequest,
        cancel: &CancelToken,
    ) -> Result<RestoreOutcome, EngineError> {
        cancel.check()?;
        let target_str = req
            .target
            .to_str()
            .ok_or_else(|| EngineError::InvalidInput {
                what: "restore target",
                reason: "path is not valid UTF-8".to_owned(),
            })?;
        fs::create_dir_all(&req.target).map_err(|source| EngineError::Io {
            context: "creating the restore target",
            source,
        })?;
        if !fs::metadata(&req.target).is_ok_and(|m| m.is_dir()) {
            return Err(EngineError::InvalidInput {
                what: "restore target",
                reason: "not a directory".to_owned(),
            });
        }
        let snap = self.find_snapshot(&req.snapshot)?;
        let id: SnapshotId = hex_id(snap.id)?;

        self.prepare_index(false)?;
        let open = self.repo.take().ok_or(EngineError::Closed)?;
        let indexed = open.to_indexed().map_err(rustic("loading the index"))?;
        let result = restore_indexed(&indexed, &self.shared, req, &id, target_str, cancel);
        self.repo = Some(indexed.drop_index());
        let outcome = result?;

        let mut created = Vec::new();
        if req.recreate_mount_points {
            self.shared.set_phase(Phase::RestoreMountPoints);
            created =
                scan::recreate_mount_points(&req.target).map_err(|source| EngineError::Io {
                    context: "recreating mount points",
                    source,
                })?;
        }
        Ok(RestoreOutcome {
            snapshot_id: id,
            files_restored: outcome.0,
            files_unchanged: outcome.1,
            files_verified: outcome.2,
            bytes_restored: outcome.3,
            bytes_matched: outcome.4,
            mount_points_created: created,
        })
    }

    /// Apply retention rules to all snapshots of the repository (one group: a repository holds
    /// one desktop), removing what the rules do not keep, except the newest
    /// `req.protect_latest`. Space is only freed by [`Engine::prune`].
    ///
    /// **Never use this for the `FORGET_PRUNE` job** (ipc.md section 36, decision 10). It takes
    /// the snapshots from the repository listing, and a compromised `BACKUP` worker can write
    /// snapshots dated in the future that fill the keep slots and the protected newest ones, so that
    /// every real snapshot is removed. That job deletes exactly the ids privd chose from its own
    /// record of successful backups. This method is for tools that own the whole repository.
    ///
    /// # Errors
    /// [`EngineError::InvalidInput`] if no keep period is set, [`EngineError::Cancelled`],
    /// [`EngineError::Repository`].
    pub fn forget(
        &self,
        req: &ForgetRequest,
        cancel: &CancelToken,
    ) -> Result<ForgetOutcome, EngineError> {
        cancel.check()?;
        let k = req.keep;
        let mut opts = KeepOptions::default();
        let mut any = false;
        if let Some(n) = to_u32_i32(k.last) {
            opts = opts.keep_last(n);
            any = true;
        }
        if let Some(n) = to_u32_i32(k.hourly) {
            opts = opts.keep_hourly(n);
            any = true;
        }
        if let Some(n) = to_u32_i32(k.daily) {
            opts = opts.keep_daily(n);
            any = true;
        }
        if let Some(n) = to_u32_i32(k.weekly) {
            opts = opts.keep_weekly(n);
            any = true;
        }
        if let Some(n) = to_u32_i32(k.monthly) {
            opts = opts.keep_monthly(n);
            any = true;
        }
        if let Some(n) = to_u32_i32(k.yearly) {
            opts = opts.keep_yearly(n);
            any = true;
        }
        if !any {
            return Err(EngineError::InvalidInput {
                what: "keep rules",
                reason: "at least one keep period must be set".to_owned(),
            });
        }
        self.shared.set_phase(Phase::Forget);
        let snaps = self
            .repo()?
            .get_all_snapshots()
            .map_err(rustic("listing snapshots"))?;
        let mut newest: Vec<&SnapshotFile> = snaps.iter().collect();
        newest.sort_by(|a, b| b.time.cmp(&a.time));
        let protected_ids: Vec<SnapshotId> = newest
            .iter()
            .take(req.protect_latest)
            .map(|s| hex_id(s.id))
            .collect::<Result<_, _>>()?;
        let now = req
            .now
            .unwrap_or_else(Timestamp::now)
            .to_zoned(TimeZone::UTC);
        let decided = opts
            .apply(snaps.clone(), &now)
            .map_err(rustic("applying keep rules"))?;

        let mut kept = Vec::new();
        let mut removed = Vec::new();
        let mut protected = Vec::new();
        let mut to_delete = Vec::new();
        for d in &decided {
            let id: SnapshotId = hex_id(d.snapshot.id)?;
            if d.keep {
                kept.push(id);
            } else if protected_ids.contains(&id) {
                protected.push(id.clone());
                kept.push(id);
            } else {
                to_delete.push(d.snapshot.id);
                removed.push(id);
            }
        }
        cancel.check()?;
        if !req.dry_run && !to_delete.is_empty() {
            self.repo()?
                .delete_snapshots(&to_delete)
                .map_err(rustic("removing snapshots"))?;
        }
        Ok(ForgetOutcome {
            kept,
            removed,
            protected,
        })
    }

    /// Remove data no snapshot uses, deleting immediately (`--instant`), **after making sure the
    /// index can be trusted** (ipc.md section 36, Q-S1).
    ///
    /// A compromised `BACKUP` worker holds the repository password, so it can write validly
    /// encrypted index files, remove index files and add pack files. `rustic_core`'s prune believes
    /// the index: a forged one makes it delete the real packs that live snapshots need (a decoy pack
    /// listing the same blobs, a marked-for-deletion entry, swapped blob locations). Pack files and
    /// snapshots cannot be removed or overwritten by that worker, so the real data is always still
    /// there; only the index and the decoys lie. Before planning, this method therefore:
    ///
    /// 1. removes index files that cannot be read (junk: they hold no data);
    /// 2. rebuilds the index from the pack headers (`repair index --read-all-packs`), writing the new
    ///    index before removing the old files, so the index says what the packs say whatever index
    ///    files were written or removed, and a kill in between loses nothing;
    /// 3. refuses if a pack file is in no index (an unreadable pack would be deleted as
    ///    unreferenced);
    /// 4. reads every copy of every blob that is stored in more than one pack (ranged reads of
    ///    those blobs only) and refuses unless each decrypts, decompresses and hashes to its blob id.
    ///    A decoy has to list real blobs to win over a real pack, so it always shows up here, and
    ///    only a copy that verifies passes. `check --read-data` cannot settle it: it reads only the
    ///    one copy per blob that the index lookup picks, while prune keeps the copy in the pack with
    ///    the highest id. Honest duplicates (an interrupted prune leaves the repacked blobs in two
    ///    packs) verify and are harmless; the prune then removes the extra copies.
    ///
    /// The cost is one header read per pack and one listing, plus a read of the duplicated blobs
    /// (at most [`MAX_DUPLICATE_VERIFY_BYTES`], else the prune is refused) and about 100 bytes of
    /// memory per blob while the index is scanned. The repository format does not change.
    ///
    /// # Errors
    /// [`EngineError::Cancelled`] (before the plan), [`EngineError::Integrity`] (nothing was
    /// deleted), [`EngineError::Repository`].
    pub fn prune(&self, cancel: &CancelToken) -> Result<PruneOutcome, EngineError> {
        cancel.check()?;
        self.verify_index_before_prune(cancel)?;
        cancel.check()?;
        self.shared.set_phase(Phase::Prune);
        let opts = PruneOptions::default().instant_delete(true);
        let plan = self
            .repo()?
            .prune_plan(&opts)
            .map_err(rustic("planning the prune"))?;
        // The plan deletes every pack file that is in no index (instant delete). The check above
        // makes that impossible; this ties it to the exact listing the plan acted on.
        if plan.stats.packs_unref != 0 {
            return Err(EngineError::Integrity {
                finding: format!(
                    "{} pack files are in no index; the prune would delete them",
                    plan.stats.packs_unref
                ),
            });
        }
        let st = plan.stats.size_sum();
        let outcome = PruneOutcome {
            unused_bytes: st.unused,
            removed_bytes: st.remove + st.repackrm,
            repacked_bytes: st.repack,
        };
        cancel.check()?;
        self.repo()?.prune(&opts, plan).map_err(rustic("pruning"))?;
        Ok(outcome)
    }

    /// Check the repository; optionally read and verify pack data.
    ///
    /// A repository with errors is a normal result, not an `Err`: see [`CheckReport::ok`].
    ///
    /// # Errors
    /// [`EngineError::InvalidInput`] for a bad percentage, [`EngineError::Cancelled`],
    /// [`EngineError::Repository`] when the check itself could not run.
    pub fn check(&self, read: ReadData, cancel: &CancelToken) -> Result<CheckReport, EngineError> {
        cancel.check()?;
        self.prepare_index(false)?;
        let mut opts = CheckOptions::default();
        self.shared.reset_read_bytes();
        match read {
            ReadData::None => self.shared.set_phase(Phase::Check),
            ReadData::All => {
                self.shared.set_phase(Phase::ReadData);
                opts = opts.read_data(true).read_data_subset(ReadSubsetOption::All);
            }
            // rustic's subset selection never takes the last pack at exactly 100%, so 100% means All.
            ReadData::Percent(100.0) => {
                self.shared.set_phase(Phase::ReadData);
                opts = opts.read_data(true).read_data_subset(ReadSubsetOption::All);
            }
            ReadData::Percent(p) => {
                if !(p > 0.0 && p < 100.0) {
                    return Err(EngineError::InvalidInput {
                        what: "read-data percentage",
                        reason: "must be above 0 and at most 100".to_owned(),
                    });
                }
                self.shared.set_phase(Phase::ReadData);
                // rustic keeps a randomly ordered pack only while the remaining budget is larger
                // than the pack, so a budget below one pack reads nothing and reports "ok". The
                // budget is therefore p% plus the largest pack: at least p% of the data, rounded
                // up to whole packs, and never less than one pack.
                let info = self
                    .repo()?
                    .infos_index()
                    .map_err(rustic("measuring the repository"))?;
                let largest = info
                    .packs
                    .iter()
                    .filter_map(|p| p.max_size)
                    .max()
                    .unwrap_or(0);
                let total: u64 = info.blobs.iter().map(|b| b.size).sum();
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let wanted = (total as f64 * p / 100.0) as u64;
                let budget = wanted.saturating_add(largest).saturating_add(1);
                opts = opts
                    .read_data(true)
                    .read_data_subset(ReadSubsetOption::Size(budget));
            }
        }
        let results = self
            .repo()?
            .check(opts)
            .map_err(rustic("checking the repository"))?;
        let ok = results.is_ok().is_ok();
        let findings = results
            .0
            .iter()
            .map(|(level, err)| format!("{level:?}: {err}"))
            .collect();
        Ok(CheckReport {
            ok,
            findings,
            bytes_read: self.shared.read_bytes(),
        })
    }
}

/// The index-dependent part of a restore: (restored, unchanged, verified, bytes written, bytes matched).
fn restore_indexed(
    repo: &Repository<IndexedFullStatus>,
    shared: &Shared,
    req: &RestoreRequest,
    id: &SnapshotId,
    target_str: &str,
    cancel: &CancelToken,
) -> Result<(u64, u64, u64, u64, u64), EngineError> {
    let node = repo
        .node_from_snapshot_path(id.as_str(), |_| true)
        .map_err(rustic("reading the snapshot tree"))?;
    let ls = repo
        .ls(&node, &LsOptions::default())
        .map_err(rustic("listing the snapshot"))?;
    let dest_dir = format!("{}/", target_str.trim_end_matches('/'));
    let dest = LocalDestination::new(&dest_dir, true, false)
        .map_err(rustic("preparing the restore target"))?;

    let mut ro = RestoreOptions::default();
    match req.ownership {
        Ownership::Numeric => {
            if !scan::has_cap_chown() {
                return Err(EngineError::MissingCapability("CAP_CHOWN"));
            }
            ro.numeric_id = true;
        }
        Ownership::Skip => ro.no_ownership = true,
    }
    ro.verify_existing = req.resume == Resume::VerifyContent;
    if req.sparse {
        // `SparseRestore` is not re-exported by rustic_core 0.14; its serde form is.
        ro.sparse = Some(
            serde_json::from_value(serde_json::Value::String("ByContent".to_owned())).map_err(
                |e| EngineError::InvalidInput {
                    what: "sparse restore",
                    reason: e.to_string(),
                },
            )?,
        );
    }

    shared.set_phase(Phase::PrepareRestore);
    let plan = repo
        .prepare_restore(&ro, ls.clone(), &dest, false)
        .map_err(rustic("preparing the restore"))?;
    let stats = (
        plan.stats.files.restore + plan.stats.files.modify,
        plan.stats.files.unchanged,
        plan.stats.files.verified,
        plan.restore_size,
        plan.matched_size,
    );
    cancel.check()?;
    shared.set_phase(Phase::Restore);
    repo.restore(plan, &ro, ls.clone(), &dest)
        .map_err(rustic("restoring"))?;
    // rustic only logs a failed chown, chmod or utime. Check the result against the snapshot.
    shared.set_phase(Phase::VerifyRestore);
    verify_restored(
        Path::new(target_str),
        ls,
        req.ownership == Ownership::Numeric,
    )?;
    Ok(stats)
}

/// Compare owner (when `check_owner`) and permission bits of every restored entry with the
/// snapshot's nodes. The root of the restore is not compared (it belongs to the caller).
fn verify_restored(
    target: &Path,
    nodes: impl Iterator<Item = rustic_core::RusticResult<(PathBuf, rustic_core::repofile::Node)>>,
    check_owner: bool,
) -> Result<(), EngineError> {
    let mut mismatches = 0usize;
    let mut examples = Vec::new();
    for item in nodes {
        let (path, node) = item.map_err(rustic("listing the snapshot"))?;
        let rel = path.strip_prefix("/").unwrap_or(&path);
        if rel.as_os_str().is_empty() {
            continue;
        }
        let ok = match fs::symlink_metadata(target.join(rel)) {
            Err(_) => false,
            Ok(md) => {
                let owner_ok = !check_owner
                    || (node.meta.uid.is_none_or(|u| u == md.uid())
                        && node.meta.gid.is_none_or(|g| g == md.gid()));
                let mode_ok = node.is_symlink()
                    || node
                        .meta
                        .mode
                        .is_none_or(|m| (m & 0o7777) == (md.mode() & 0o7777));
                owner_ok && mode_ok
            }
        };
        if !ok {
            mismatches += 1;
            if examples.len() < 5 {
                examples.push(rel.display().to_string());
            }
        }
    }
    if mismatches > 0 {
        return Err(EngineError::RestoreVerification {
            mismatches,
            examples,
        });
    }
    Ok(())
}

fn snapshot_info(s: &SnapshotFile) -> Result<SnapshotInfo, EngineError> {
    let id: SnapshotId = hex_id(s.id)?;
    let manifest = s.description.as_deref().and_then(|d| {
        Manifest::from_slice(d.as_bytes())
            .and_then(|m| m.with_snapshot_id(id.as_str()))
            .map_err(
                |e| tracing::warn!(snapshot = %id, error = %e, "snapshot has no valid manifest"),
            )
            .ok()
    });
    Ok(SnapshotInfo {
        host: s.hostname.clone(),
        time: s.time.timestamp(),
        tags: s.tags.iter().map(ToString::to_string).collect(),
        id,
        manifest,
    })
}
