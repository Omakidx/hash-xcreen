//! The job slot and the small records of the runner (ipc.md section 35).
//!
//! Everything lives in `<state dir>/backup/` (root, 0700): `server-id`, and per desktop
//! `<desktop id>/job.json`, `resume.json`, `backoff.json` and `completed.json` (the last one is
//! [`super::completed`]). Every write is atomic (temporary file, `fsync`, `rename`, `fsync` of the
//! directory, [`write_atomic`]); a file that exists but does not parse is an error, never a reset
//! (the caller refuses jobs for that desktop and crash recovery leaves the file alone).

use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use hx_ipc::repo::pb::JobKind;
use hx_provision::incus::{BackupSnapshotName, HelperName, JobId, RestoreTargetName};
use serde::{Deserialize, Serialize};

use crate::privd::state::write_atomic;

/// The current format of every record.
pub const FORMAT: u32 = 1;

/// The directories and files of the runner under the state directory.
#[derive(Debug, Clone)]
pub struct BackupDirs {
    root: PathBuf,
}

/// A record on disk that exists and is not what this version writes.
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    /// The file cannot be read or written.
    #[error("{what}: {source}")]
    Io {
        /// Which record.
        what: &'static str,
        /// The error.
        #[source]
        source: io::Error,
    },
    /// The file does not parse or has a field this version refuses; it is left as it is.
    #[error("{0} is corrupt; it is left for an administrator")]
    Corrupt(&'static str),
}

fn io_err(what: &'static str) -> impl FnOnce(io::Error) -> RecordError {
    move |source| RecordError::Io { what, source }
}

impl BackupDirs {
    /// The runner's directory under privd's state directory (`<state dir>/backup`).
    pub fn new(state_dir: &Path) -> Self {
        Self {
            root: state_dir.join("backup"),
        }
    }

    /// The root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Creates the root (0700) if it is not there.
    pub fn ensure_root(&self) -> io::Result<()> {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.root)
    }

    /// `<root>/<desktop id>`, for an id that passed [`crate::privd::is_safe_desktop_id`].
    pub fn desktop_dir(&self, desktop_id: &str) -> io::Result<PathBuf> {
        if !crate::privd::is_safe_desktop_id(desktop_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a desktop id",
            ));
        }
        Ok(self.root.join(desktop_id))
    }

    /// Creates the desktop's directory (0700).
    pub fn ensure_desktop_dir(&self, desktop_id: &str) -> io::Result<PathBuf> {
        use std::os::unix::fs::DirBuilderExt;
        self.ensure_root()?;
        let d = self.desktop_dir(desktop_id)?;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&d)
            .or_else(|e| {
                if e.kind() == io::ErrorKind::AlreadyExists {
                    Ok(())
                } else {
                    Err(e)
                }
            })?;
        Ok(d)
    }

    /// `job.json`.
    pub fn job_path(&self, desktop_id: &str) -> io::Result<PathBuf> {
        Ok(self.desktop_dir(desktop_id)?.join("job.json"))
    }

    /// `resume.json`.
    pub fn resume_path(&self, desktop_id: &str) -> io::Result<PathBuf> {
        Ok(self.desktop_dir(desktop_id)?.join("resume.json"))
    }

    /// `backoff.json`.
    pub fn backoff_path(&self, desktop_id: &str) -> io::Result<PathBuf> {
        Ok(self.desktop_dir(desktop_id)?.join("backoff.json"))
    }

    /// `completed.json`.
    pub fn completed_path(&self, desktop_id: &str) -> io::Result<PathBuf> {
        Ok(self.desktop_dir(desktop_id)?.join("completed.json"))
    }

    /// The server id of ipc.md section 29: 16 random bytes, kept as 32 lower-case hex digits and
    /// a newline in `<root>/server-id` (0600). Created once.
    pub fn server_id(&self) -> io::Result<[u8; 16]> {
        self.ensure_root()?;
        let path = self.root.join("server-id");
        match std::fs::read_to_string(&path) {
            Ok(text) => parse_hex16(text.trim_end_matches('\n'))
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "server-id is corrupt")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut id = [0u8; 16];
                getrandom::fill(&mut id).map_err(|_| io::Error::other("no randomness"))?;
                write_atomic(&path, format!("{}\n", hex(&id)).as_bytes(), 0o600)?;
                Ok(id)
            }
            Err(e) => Err(e),
        }
    }
}

/// Lower-case hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn parse_hex16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32
        || !s
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(out)
}

/// Parses 64 lower-case hex digits (a snapshot id or a key id).
pub fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(out)
}

/// The `JobKind` name of ipc.md section 27, as written in the records.
pub fn kind_name(kind: JobKind) -> &'static str {
    match kind {
        JobKind::Unspecified => "UNSPECIFIED",
        JobKind::Init => "INIT",
        JobKind::Backup => "BACKUP",
        JobKind::Snapshots => "SNAPSHOTS",
        JobKind::RestorePlan => "RESTORE_PLAN",
        JobKind::Restore => "RESTORE",
        JobKind::ForgetPrune => "FORGET_PRUNE",
        JobKind::Check => "CHECK",
        JobKind::Keys => "KEYS",
    }
}

/// The inverse of [`kind_name`]; `UNSPECIFIED` is refused.
pub fn parse_kind(name: &str) -> Option<JobKind> {
    [
        JobKind::Init,
        JobKind::Backup,
        JobKind::Snapshots,
        JobKind::RestorePlan,
        JobKind::Restore,
        JobKind::ForgetPrune,
        JobKind::Check,
        JobKind::Keys,
    ]
    .into_iter()
    .find(|k| kind_name(*k) == name)
}

fn read_strict<T: for<'de> Deserialize<'de>>(
    path: &Path,
    what: &'static str,
) -> Result<Option<T>, RecordError> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_file() => {}
        Ok(_) => return Err(RecordError::Corrupt(what)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_err(what)(e)),
    }
    let bytes = std::fs::read(path).map_err(io_err(what))?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| RecordError::Corrupt(what))
}

fn write_record<T: Serialize>(path: &Path, what: &'static str, v: &T) -> Result<(), RecordError> {
    let bytes = serde_json::to_vec(v).map_err(|_| RecordError::Corrupt(what))?;
    write_atomic(path, &bytes, 0o600).map_err(io_err(what))
}

/// Removes a record file (already absent is fine) and syncs the directory.
pub fn remove_record(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    }
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

// ----- job.json ------------------------------------------------------------------------------

/// `job.json` (ipc.md section 35): written before the helper is created, removed after cleanup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobRecord {
    /// Always [`FORMAT`].
    pub format: u32,
    /// 32 lower-case hex digits.
    pub job_id: String,
    /// The `JobKind` name.
    pub kind: String,
    /// The desktop id.
    pub desktop_id: String,
    /// Start time, Unix seconds.
    pub started_unix: u64,
    /// The helper's name (`hx-bkw-<8 hex>`), derived from the job id.
    pub helper: String,
    /// The snapshot's name (`BACKUP` only).
    pub snapshot: Option<String>,
    /// The restore target's instance name (`RESTORE` only).
    pub target: Option<String>,
    /// The caller's flag of a `RESTORE`: keep the target for resuming or promotion.
    pub resumable: bool,
}

impl JobRecord {
    /// Whether every field is what this version writes (names parse, the helper's name is the
    /// job's, the kind is known). A record that is not is [`RecordError::Corrupt`].
    pub fn validate(&self) -> bool {
        let Ok(job) = JobId::from_hex(&self.job_id) else {
            return false;
        };
        self.format == FORMAT
            && parse_kind(&self.kind).is_some()
            && crate::privd::is_safe_desktop_id(&self.desktop_id)
            && HelperName::new(&self.helper).is_ok_and(|h| h == job.helper_name())
            && self
                .snapshot
                .as_deref()
                .is_none_or(|s| BackupSnapshotName::new(s).is_ok())
            && self
                .target
                .as_deref()
                .is_none_or(|t| RestoreTargetName::new(t).is_ok())
    }

    /// The job id, if the record is valid.
    pub fn job(&self) -> Option<JobId> {
        JobId::from_hex(&self.job_id).ok()
    }

    /// Reads `job.json`; `None` when there is none.
    pub fn load(path: &Path) -> Result<Option<Self>, RecordError> {
        let r: Option<Self> = read_strict(path, "job.json")?;
        match r {
            Some(r) if r.validate() => Ok(Some(r)),
            Some(_) => Err(RecordError::Corrupt("job.json")),
            None => Ok(None),
        }
    }

    /// Writes it atomically (0600).
    pub fn store(&self, path: &Path) -> Result<(), RecordError> {
        write_record(path, "job.json", self)
    }
}

// ----- resume.json ---------------------------------------------------------------------------

/// `resume.json`: a restore target that crash recovery or a finished job kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeRecord {
    /// Always [`FORMAT`].
    pub format: u32,
    /// The job that made the target.
    pub job_id: String,
    /// The target's instance name.
    pub target: String,
    /// Always true (a record exists only for a resumable restore).
    pub resumable: bool,
}

impl ResumeRecord {
    /// A record for `target` of `job`.
    pub fn new(job: JobId, target: &RestoreTargetName) -> Self {
        Self {
            format: FORMAT,
            job_id: job.hex(),
            target: target.to_string(),
            resumable: true,
        }
    }

    fn valid(&self) -> bool {
        self.format == FORMAT
            && self.resumable
            && JobId::from_hex(&self.job_id).is_ok()
            && RestoreTargetName::new(&self.target).is_ok()
    }

    /// Reads `resume.json`.
    pub fn load(path: &Path) -> Result<Option<Self>, RecordError> {
        match read_strict::<Self>(path, "resume.json")? {
            Some(r) if r.valid() => Ok(Some(r)),
            Some(_) => Err(RecordError::Corrupt("resume.json")),
            None => Ok(None),
        }
    }

    /// Writes it atomically.
    pub fn store(&self, path: &Path) -> Result<(), RecordError> {
        write_record(path, "resume.json", self)
    }
}

// ----- backoff.json --------------------------------------------------------------------------

/// Why writing jobs are refused for a while (ipc.md section 31, "Effects").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BackoffReason {
    /// The Drive helper's daily-limit gate gave up.
    DailyLimit,
    /// privd refused an operation of the worker.
    PolicyDenied,
    /// A hash mismatch, or the engine's own refusal before a prune.
    Integrity,
    /// A request over the size cap.
    TooLarge,
    /// The quiet period after a lease takeover.
    Takeover,
}

/// `backoff.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backoff {
    /// Always [`FORMAT`].
    pub format: u32,
    /// Writing jobs are refused until this Unix time.
    pub until_unix: u64,
    /// Why.
    pub reason: BackoffReason,
}

impl Backoff {
    /// Reads `backoff.json`.
    pub fn load(path: &Path) -> Result<Option<Self>, RecordError> {
        match read_strict::<Self>(path, "backoff.json")? {
            Some(b) if b.format == FORMAT => Ok(Some(b)),
            Some(_) => Err(RecordError::Corrupt("backoff.json")),
            None => Ok(None),
        }
    }

    /// Extends the back-off to `until_unix`: a later time replaces an earlier one and an earlier
    /// time never replaces a later one.
    pub fn extend(path: &Path, until_unix: u64, reason: BackoffReason) -> Result<(), RecordError> {
        let keep = Self::load(path)
            .ok()
            .flatten()
            .filter(|b| b.until_unix >= until_unix);
        if keep.is_some() {
            return Ok(());
        }
        write_record(
            path,
            "backoff.json",
            &Self {
                format: FORMAT,
                until_unix,
                reason,
            },
        )
    }
}

// ----- the in-memory slot --------------------------------------------------------------------

/// The in-memory half of the job slot: one holder per desktop id.
#[derive(Debug, Clone, Default)]
pub struct SlotTable(Arc<Mutex<HashSet<String>>>);

/// A held slot; released on drop.
#[derive(Debug)]
pub struct SlotGuard {
    table: SlotTable,
    desktop: String,
}

impl SlotTable {
    /// Takes the slot of `desktop`, or `None` when it is held.
    pub fn take(&self, desktop: &str) -> Option<SlotGuard> {
        let mut g = self.0.lock().unwrap_or_else(|e| e.into_inner());
        g.insert(desktop.to_string()).then(|| SlotGuard {
            table: self.clone(),
            desktop: desktop.to_string(),
        })
    }

    /// Whether the slot of `desktop` is held.
    pub fn held(&self, desktop: &str) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(desktop)
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.table
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.desktop);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn dirs() -> (tempfile::TempDir, BackupDirs) {
        let d = tempfile::tempdir().unwrap();
        let b = BackupDirs::new(d.path());
        (d, b)
    }

    fn record() -> JobRecord {
        let job = JobId::from_bytes([7; 16]).unwrap();
        JobRecord {
            format: FORMAT,
            job_id: job.hex(),
            kind: "BACKUP".into(),
            desktop_id: "main".into(),
            started_unix: 1_800_000_000,
            helper: job.helper_name().to_string(),
            snapshot: Some("hx-backup-20261127T030000Z-ab12".into()),
            target: None,
            resumable: false,
        }
    }

    #[test]
    fn a_job_record_round_trips_with_mode_0600_and_exact_fields() {
        let (_d, b) = dirs();
        b.ensure_desktop_dir("main").unwrap();
        let p = b.job_path("main").unwrap();
        record().store(&p).unwrap();
        assert_eq!(JobRecord::load(&p).unwrap(), Some(record()));
        let mode = std::fs::metadata(&p).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let dir_mode = std::fs::metadata(p.parent().unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700);
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        let mut keys: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "desktop_id",
                "format",
                "helper",
                "job_id",
                "kind",
                "resumable",
                "snapshot",
                "started_unix",
                "target"
            ]
        );
    }

    #[test]
    fn a_corrupt_or_foreign_record_is_an_error_and_is_left_alone() {
        let (_d, b) = dirs();
        b.ensure_desktop_dir("main").unwrap();
        let p = b.job_path("main").unwrap();
        for bad in [
            "{not json".to_string(),
            r#"{"format":1,"extra":1}"#.to_string(),
            serde_json::to_string(&JobRecord {
                helper: "hx-bkw-00000000".into(),
                ..record()
            })
            .unwrap(),
            serde_json::to_string(&JobRecord {
                kind: "NOPE".into(),
                ..record()
            })
            .unwrap(),
        ] {
            std::fs::write(&p, &bad).unwrap();
            assert!(
                matches!(JobRecord::load(&p), Err(RecordError::Corrupt(_))),
                "{bad}"
            );
            assert_eq!(std::fs::read_to_string(&p).unwrap(), bad);
        }
        std::fs::remove_file(&p).unwrap();
        assert_eq!(JobRecord::load(&p).unwrap(), None);
    }

    #[test]
    fn the_server_id_is_created_once_and_is_32_hex_digits() {
        let (d, b) = dirs();
        let a = b.server_id().unwrap();
        assert_eq!(a, b.server_id().unwrap());
        let text = std::fs::read_to_string(d.path().join("backup/server-id")).unwrap();
        assert_eq!(text.len(), 33);
        assert!(text.ends_with('\n'));
        std::fs::write(d.path().join("backup/server-id"), "zz\n").unwrap();
        assert!(b.server_id().is_err());
    }

    #[test]
    fn a_later_backoff_replaces_an_earlier_and_never_the_other_way() {
        let (_d, b) = dirs();
        b.ensure_desktop_dir("main").unwrap();
        let p = b.backoff_path("main").unwrap();
        Backoff::extend(&p, 100, BackoffReason::DailyLimit).unwrap();
        Backoff::extend(&p, 50, BackoffReason::Integrity).unwrap();
        let got = Backoff::load(&p).unwrap().unwrap();
        assert_eq!(
            (got.until_unix, got.reason),
            (100, BackoffReason::DailyLimit)
        );
        Backoff::extend(&p, 200, BackoffReason::Takeover).unwrap();
        assert_eq!(Backoff::load(&p).unwrap().unwrap().until_unix, 200);
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains(r#""reason":"TAKEOVER""#), "{text}");
    }

    #[test]
    fn the_slot_is_taken_once_and_released_on_drop() {
        let t = SlotTable::default();
        let g = t.take("main").unwrap();
        assert!(t.held("main"));
        assert!(t.take("main").is_none());
        assert!(t.take("other").is_some());
        drop(g);
        assert!(!t.held("main"));
        assert!(t.take("main").is_some());
    }

    #[test]
    fn an_unsafe_desktop_id_gets_no_path() {
        let (_d, b) = dirs();
        for id in ["", "../x", "a/b", "Main", "a b"] {
            assert!(b.job_path(id).is_err(), "{id}");
        }
    }
}
