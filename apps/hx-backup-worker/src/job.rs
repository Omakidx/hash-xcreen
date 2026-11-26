//! The job runner (ipc.md §28): runs one `Job` with the engine over the link backend and turns the
//! outcome into the one `JobResult`.
//!
//! Nothing here sends a frame except through [`Link`]; the runner returns the result and the
//! session sends it. No text crosses the link: a failure is a [`pb::WorkerError`], the detail goes to
//! the console log (stderr), which privd never parses (ipc.md §31).

use std::collections::{BTreeMap, HashSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use hx_backup::engine::{
    BackupRequest, CancelToken, Engine, EngineError, EngineOptions, FileType, JobStart, KeyId,
    Link, LinkBackend, OpenMode, Ownership, ProgressSink, ReadBackend, ReadData, RepoKey,
    RestoreRequest, SnapshotId, SnapshotSelector, WriteBackend,
};
use hx_backup::manifest::{CURRENT_FORMAT_VERSION, Distro, ManifestInput};
use hx_backup::rules::{DockerMode, RuleSet};
use hx_ipc::repo::{self, pb};
use hx_ipc::secret::Secret;
use sha2::{Digest, Sha256};

/// The host name recorded in every snapshot: a repository holds one desktop, and rustic chains
/// snapshots of one host and path as parents of each other.
const SNAPSHOT_HOST: &str = "hx-desktop";

/// What differs between production and a test of the runner.
#[derive(Debug, Clone)]
pub struct JobOptions {
    /// The read-only snapshot mount (`/src`).
    pub src: PathBuf,
    /// The restore target (`/dst`).
    pub dst: PathBuf,
    /// How a restore treats owners: numeric ids in production (needs `CAP_CHOWN`).
    pub ownership: Ownership,
}

impl JobOptions {
    /// `/src`, `/dst` and numeric ownership.
    #[must_use]
    pub fn production() -> Self {
        Self {
            src: PathBuf::from("/src"),
            dst: PathBuf::from("/dst"),
            ownership: Ownership::Numeric,
        }
    }
}

/// What a failed job knew when it failed, for [`classify`].
#[derive(Debug, Clone, Copy)]
pub struct Facts {
    /// The kind of the job.
    pub kind: pb::JobKind,
    /// `Cancel` was received.
    pub cancelled: bool,
    /// The first `RepoError` class other than `NOT_FOUND` that privd answered.
    pub repo_error: Option<pb::ErrorClass>,
}

/// Why a job did not produce a result of its own.
enum Fail {
    Engine(EngineError),
    Worker(pb::WorkerError),
}

impl From<EngineError> for Fail {
    fn from(e: EngineError) -> Self {
        Fail::Engine(e)
    }
}

/// Is `e` the kind of error a refused or failed backend call turns into? (rustic reports a failed
/// listing as an unknown snapshot, for one.)
fn backend_caused(e: &EngineError) -> bool {
    matches!(
        e,
        EngineError::Repository { .. }
            | EngineError::Closed
            | EngineError::SnapshotNotFound(_)
            | EngineError::NoManifest { .. }
    )
}

/// Chooses the `WorkerError` of a failed engine call (ipc.md §31, "How the worker chooses"): the
/// first rule that matches.
#[must_use]
pub fn classify(f: &Facts, e: &EngineError) -> pb::WorkerError {
    use pb::JobKind as K;
    use pb::WorkerError as W;
    if matches!(e, EngineError::Cancelled) || (f.cancelled && backend_caused(e)) {
        return W::Cancelled;
    }
    if backend_caused(e) && f.repo_error.is_some() {
        return W::Repo;
    }
    match e {
        EngineError::WrongKey | EngineError::InvalidKey(_) => W::WrongPassword,
        EngineError::RepositoryNotFound => W::NoRepository,
        // Q-S1 HOOK: when `EngineError::Integrity` lands, map it here: `EngineError::Integrity { .. } => W::Integrity,`
        EngineError::SnapshotNotFound(_) => W::SnapshotNotFound,
        EngineError::Io { .. } => match f.kind {
            K::Backup => W::SourceUnreadable,
            K::Restore => W::TargetUnwritable,
            _ => W::Engine,
        },
        EngineError::InvalidInput { what, .. } => match (f.kind, *what) {
            (K::Backup, "source") => W::SourceUnreadable,
            (K::Restore, "restore target") => W::TargetUnwritable,
            _ => W::Engine,
        },
        EngineError::MissingCapability(_) | EngineError::RestoreVerification { .. } => {
            W::TargetUnwritable
        }
        // A restore that fails inside rustic with the link healthy failed on the local side.
        EngineError::Repository { operation, .. }
            if f.kind == K::Restore
                && matches!(
                    *operation,
                    "preparing the restore target" | "preparing the restore" | "restoring"
                ) =>
        {
            W::TargetUnwritable
        }
        _ => W::Engine,
    }
}

fn failed(e: pb::WorkerError) -> pb::JobResult {
    pb::JobResult {
        ok: false,
        error: e as i32,
        ..pb::JobResult::default()
    }
}

fn success() -> pb::JobResult {
    pb::JobResult {
        ok: true,
        ..pb::JobResult::default()
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in s.as_bytes().chunks(2).enumerate() {
        let d = |c: u8| (c as char).to_digit(16).map(|v| v as u8);
        out[i] = d(pair[0])? << 4 | d(pair[1])?;
    }
    Some(out)
}

fn snapshot_selector(id: &[u8]) -> Result<SnapshotSelector, Fail> {
    Ok(SnapshotSelector::Id(SnapshotId::from_str(&hex(id))?))
}

/// The secret of `slot`, as an engine key.
fn key(secrets: &[(u8, Secret)], slot: u8) -> Result<RepoKey, Fail> {
    let (_, secret) = secrets
        .iter()
        .find(|(s, _)| *s == slot)
        .ok_or(Fail::Worker(pb::WorkerError::Engine))?;
    // `RepoKey` takes the bytes and zeroizes them; the frame's own copy is zeroized with `Secret`.
    Ok(RepoKey::from_bytes(secret.expose().to_vec())?)
}

struct Ctx<'a> {
    backend: Arc<LinkBackend>,
    cancel: CancelToken,
    sink: Arc<dyn ProgressSink>,
    secrets: &'a [(u8, Secret)],
    opts: &'a JobOptions,
}

impl Ctx<'_> {
    fn open(&self, key: &RepoKey, mode: OpenMode) -> Result<Engine, EngineError> {
        let backend: Arc<dyn WriteBackend> = Arc::clone(&self.backend) as Arc<dyn WriteBackend>;
        Engine::open_with_backend(
            backend,
            key,
            &EngineOptions {
                compression_level: i32::try_from(repo::INIT_COMPRESSION).unwrap_or(3),
                open_mode: mode,
            },
            Arc::clone(&self.sink),
        )
    }

    /// A listing through the link, as the engine's own error.
    fn list(&self, tpe: FileType, what: &'static str) -> Result<Vec<String>, EngineError> {
        self.backend
            .list(tpe)
            .map(|ids| {
                ids.iter()
                    .map(|id| id.to_hex().as_str().to_owned())
                    .collect()
            })
            .map_err(|source| EngineError::Repository {
                operation: what,
                source,
            })
    }
}

/// Runs the job of `start` and returns its `JobResult` (successful or failed). Panics inside the
/// job are caught and reported as `ENGINE`. The caller sends the result with [`Link::finish`].
pub fn run(
    link: &Arc<Link>,
    start: JobStart,
    opts: &JobOptions,
    sink: Arc<dyn ProgressSink>,
) -> pb::JobResult {
    let JobStart { job, secrets, .. } = start;
    let kind = pb::JobKind::try_from(job.kind).unwrap_or(pb::JobKind::Unspecified);
    let ctx = Ctx {
        backend: Arc::new(link.backend()),
        cancel: link.cancel_token(),
        sink,
        secrets: &secrets,
        opts,
    };
    let outcome = catch_unwind(AssertUnwindSafe(|| execute(&ctx, &job)));
    let facts = Facts {
        kind,
        cancelled: link.is_cancelled(),
        repo_error: link.first_repo_error(),
    };
    let result = match outcome {
        Ok(Ok(r)) => r,
        Ok(Err(Fail::Worker(w))) => failed(w),
        Ok(Err(Fail::Engine(e))) => {
            let w = classify(&facts, &e);
            // The detail: the console log only, never the link. `EngineError` text never holds
            // key material (ipc.md §34); paths of the user's files are only at `debug`.
            tracing::warn!(error = %e, worker_error = ?w, "the job failed");
            failed(w)
        }
        Err(_) => {
            // `rustic_core` unwraps the result of a backend call inside its restore threads, so a
            // refused call (after `Cancel`) or a repository error from privd arrives here as a
            // panic: the link's own record says why.
            let w = if facts.cancelled {
                pb::WorkerError::Cancelled
            } else if facts.repo_error.is_some() {
                pb::WorkerError::Repo
            } else {
                pb::WorkerError::Engine
            };
            tracing::error!(worker_error = ?w, "the job panicked");
            failed(w)
        }
    };
    // A result the codec would refuse (a listing that does not fit the frame, a manifest that is
    // too large) fails the job instead of being sent (ipc.md §25).
    match link.validate_result(&result) {
        Ok(()) => result,
        Err(rule) => {
            tracing::warn!(rule, "the result does not fit the link; failing the job");
            failed(pb::WorkerError::Engine)
        }
    }
}

fn execute(ctx: &Ctx<'_>, job: &pb::Job) -> Result<pb::JobResult, Fail> {
    use pb::job::Spec;
    let Some(spec) = &job.spec else {
        return Err(Fail::Worker(pb::WorkerError::Engine));
    };
    match spec {
        Spec::Init(_) => init(ctx),
        Spec::Backup(s) => backup(ctx, s),
        Spec::Snapshots(_) => snapshots(ctx),
        Spec::RestorePlan(s) => restore_plan(ctx, s),
        Spec::Restore(s) => restore(ctx, s),
        Spec::ForgetPrune(s) => forget_prune(ctx, s),
        Spec::Check(s) => check(ctx, s),
        Spec::Keys(s) => keys(ctx, s),
    }
}

fn init(ctx: &Ctx<'_>) -> Result<pb::JobResult, Fail> {
    let host_key = key(ctx.secrets, 0)?;
    let recovery_key = key(ctx.secrets, 1)?;
    // Only on a location without a repository (ipc.md §28); `OpenOrInit` would open an existing one.
    if !ctx
        .list(FileType::Config, "looking for the repository")?
        .is_empty()
    {
        return Err(Fail::Worker(pb::WorkerError::RepositoryExists));
    }
    let engine = ctx.open(&host_key, OpenMode::OpenOrInit)?;
    // A fresh repository has exactly the key just created: the host key.
    let keys = ctx.list(FileType::Key, "listing the keys")?;
    let [host_id] = keys.as_slice() else {
        tracing::warn!(
            keys = keys.len(),
            "a new repository must have exactly one key"
        );
        return Err(Fail::Worker(pb::WorkerError::Engine));
    };
    let recovery_id = engine.add_key(&recovery_key)?;
    let ids = [host_id.as_str(), recovery_id.as_str()]
        .iter()
        .map(|h| unhex32(h).map(|b| b.to_vec().into()))
        .collect::<Option<Vec<_>>>()
        .ok_or(Fail::Worker(pb::WorkerError::Engine))?;
    Ok(pb::JobResult {
        key_ids: ids,
        ..success()
    })
}

fn docker_mode(m: i32) -> Result<DockerMode, Fail> {
    match pb::DockerMode::try_from(m) {
        Ok(pb::DockerMode::Complete) => Ok(DockerMode::Complete),
        Ok(pb::DockerMode::Light) => Ok(DockerMode::Light),
        _ => Err(Fail::Worker(pb::WorkerError::Engine)),
    }
}

fn backup(ctx: &Ctx<'_>, spec: &pb::BackupSpec) -> Result<pb::JobResult, Fail> {
    let key = key(ctx.secrets, 0)?;
    let m = spec
        .manifest
        .as_ref()
        .ok_or(Fail::Worker(pb::WorkerError::Engine))?;
    let d = m
        .distro
        .as_ref()
        .ok_or(Fail::Worker(pb::WorkerError::Engine))?;
    if m.format_version != CURRENT_FORMAT_VERSION {
        tracing::warn!(
            version = m.format_version,
            "unsupported backup format version"
        );
        return Err(Fail::Worker(pb::WorkerError::Engine));
    }
    let manifest = ManifestInput {
        agent_version: m.agent_version.clone(),
        distro: Distro {
            id: d.id.clone(),
            version_id: d.version_id.clone(),
            pretty_name: (!d.pretty_name.is_empty()).then(|| d.pretty_name.clone()),
        },
        desktop: m.desktop.clone(),
        preset: m.preset.clone(),
        container_config: m
            .container_config
            .iter()
            .map(|e| (e.key.clone(), e.value.clone()))
            .collect::<BTreeMap<_, _>>(),
    };
    let mode = docker_mode(spec.docker_mode)?;
    let rules = RuleSet::new(mode, spec.excludes.iter()).map_err(EngineError::from)?;
    let req = BackupRequest {
        source: ctx.opts.src.clone(),
        rules,
        manifest,
        // The spec always carries a Docker mode; it is recorded in the manifest.
        docker_enabled: true,
        tags: spec.tags.clone(),
        host: SNAPSHOT_HOST.to_owned(),
        time: None,
    };
    let mut engine = ctx.open(&key, OpenMode::OpenExisting)?;
    // `Engine::backup` runs `repair index` first (ipc.md §28).
    let out = engine.backup(&req, &ctx.cancel)?;
    if out.is_partial() {
        // The snapshot was written but is not complete: reported as a failure without it (§28).
        tracing::warn!(
            errors = out.summary.error_count,
            unreadable = out.manifest.source_sizes.unreadable_entries,
            "the source was only partly readable"
        );
        return Err(Fail::Worker(pb::WorkerError::SourceUnreadable));
    }
    let id = unhex32(out.snapshot_id.as_str()).ok_or(Fail::Worker(pb::WorkerError::Engine))?;
    Ok(pb::JobResult {
        snapshot_id: id.to_vec().into(),
        files_new: out.summary.files_new,
        files_changed: out.summary.files_changed,
        files_unmodified: out.summary.files_unmodified,
        bytes_processed: out.summary.total_bytes,
        bytes_added: out.summary.data_added_packed,
        ..success()
    })
}

fn valid_tag(t: &str) -> bool {
    (1..=repo::MAX_TAG_LEN).contains(&t.len())
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn snapshots(ctx: &Ctx<'_>) -> Result<pb::JobResult, Fail> {
    let key = key(ctx.secrets, 0)?;
    let engine = ctx.open(&key, OpenMode::OpenExisting)?;
    let list = engine.snapshots()?;
    if list.len() > repo::MAX_SNAPSHOTS {
        return Err(Fail::Worker(pb::WorkerError::Engine));
    }
    let mut out = Vec::with_capacity(list.len());
    for s in &list {
        let (digest, size) = match &s.manifest {
            Some(m) => match m.to_json() {
                Ok(json) => (
                    Sha256::digest(json.as_bytes()).to_vec(),
                    m.source_sizes.bytes,
                ),
                Err(_) => (vec![0; 32], 0),
            },
            None => (vec![0; 32], 0),
        };
        out.push(pb::SnapshotInfo {
            id: unhex32(s.id.as_str())
                .ok_or(Fail::Worker(pb::WorkerError::Engine))?
                .to_vec()
                .into(),
            time: s.time.as_second().max(0),
            tags: s
                .tags
                .iter()
                .filter(|t| t.as_str() != "hx-backup" && valid_tag(t))
                .take(repo::MAX_TAGS)
                .cloned()
                .collect(),
            manifest_digest: digest.into(),
            size,
        });
    }
    Ok(pb::JobResult {
        snapshots: out,
        ..success()
    })
}

fn restore_plan(ctx: &Ctx<'_>, spec: &pb::RestorePlanSpec) -> Result<pb::JobResult, Fail> {
    let key = key(ctx.secrets, 0)?;
    let sel = snapshot_selector(&spec.snapshot_id)?;
    let engine = ctx.open(&key, OpenMode::OpenExisting)?;
    let manifest = engine.read_manifest(&sel)?;
    let json = manifest.to_json().map_err(EngineError::from)?;
    if json.len() > repo::MAX_MANIFEST_BYTES {
        return Err(Fail::Worker(pb::WorkerError::Engine));
    }
    Ok(pb::JobResult {
        manifest: json.into_bytes().into(),
        ..success()
    })
}

fn restore(ctx: &Ctx<'_>, spec: &pb::RestoreSpec) -> Result<pb::JobResult, Fail> {
    let key = key(ctx.secrets, 0)?;
    let sel = snapshot_selector(&spec.snapshot_id)?;
    let mut engine = ctx.open(&key, OpenMode::OpenExisting)?;
    let mut req = RestoreRequest::new(sel, ctx.opts.dst.clone());
    req.ownership = ctx.opts.ownership;
    // `verify_existing` is accepted; v1 always verifies the content of what is already there.
    let _ = spec.verify_existing;
    let out = engine.restore(&req, &ctx.cancel)?;
    tracing::info!(
        restored = out.files_restored,
        unchanged = out.files_unchanged,
        verified = out.files_verified,
        "restore finished"
    );
    Ok(success())
}

fn forget_prune(ctx: &Ctx<'_>, spec: &pb::ForgetPruneSpec) -> Result<pb::JobResult, Fail> {
    let key = key(ctx.secrets, 0)?;
    let engine = ctx.open(&key, OpenMode::OpenExisting)?;
    // Exactly the snapshots privd named, and only those that exist: an id that is already gone is
    // skipped, which makes a retried job idempotent (privd's policy allows `Remove` of `SNAPSHOT`
    // only for these ids; a missing one would be an error of the backend).
    let present: HashSet<String> = ctx
        .list(FileType::Snapshot, "listing snapshots")?
        .into_iter()
        .collect();
    let mut ids = Vec::new();
    for raw in &spec.forget {
        let h = hex(raw);
        if present.contains(&h) {
            ids.push(SnapshotId::from_str(&h)?);
        } else {
            tracing::info!("a snapshot to forget is already gone");
        }
    }
    engine.delete_snapshots(&ids, &ctx.cancel)?;
    // Q-S1 (docs/ipc.md §36, open): a step that makes prune safe against removed or forged indexes
    // belongs HERE, before `prune`: for example `repair index`, or a check that no pack is dropped
    // that is unreferenced only because an index is missing. `Engine::prune` is deliberately called
    // as it is until that is decided.
    engine.prune(&ctx.cancel)?;
    Ok(success())
}

fn check(ctx: &Ctx<'_>, spec: &pb::CheckSpec) -> Result<pb::JobResult, Fail> {
    let key = key(ctx.secrets, 0)?;
    let engine = ctx.open(&key, OpenMode::OpenExisting)?;
    let read = match spec.read_data_percent {
        0 => ReadData::None,
        p => ReadData::Percent(f64::from(p)),
    };
    let report = engine.check(read, &ctx.cancel)?;
    for f in &report.findings {
        tracing::info!(finding = %f, "check");
    }
    if report.ok {
        Ok(success())
    } else {
        // v1 has no distinct code for "the repository has errors" (ipc.md §28).
        tracing::warn!("the check found errors");
        Err(Fail::Worker(pb::WorkerError::Engine))
    }
}

fn keys(ctx: &Ctx<'_>, spec: &pb::KeysSpec) -> Result<pb::JobResult, Fail> {
    let key0 = key(ctx.secrets, 0)?;
    let engine = ctx.open(&key0, OpenMode::OpenExisting)?;
    let mut key_ids = Vec::new();
    if spec.add {
        let new = key(ctx.secrets, 1)?;
        let id = engine.add_key(&new)?;
        key_ids.push(
            unhex32(id.as_str())
                .ok_or(Fail::Worker(pb::WorkerError::Engine))?
                .to_vec()
                .into(),
        );
    }
    for raw in &spec.remove_key_ids {
        engine.remove_key(&KeyId::from_str(&hex(raw))?)?;
    }
    Ok(pb::JobResult {
        key_ids,
        ..success()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(kind: pb::JobKind) -> Facts {
        Facts {
            kind,
            cancelled: false,
            repo_error: None,
        }
    }

    fn repo_err() -> EngineError {
        EngineError::Repository {
            operation: "reading",
            source: hx_backup::engine::link::BackendFault::Unexpected.into_rustic(),
        }
    }

    #[test]
    fn hex_round_trips_and_refuses_what_is_not_an_id() {
        let id = [0xabu8; 32];
        assert_eq!(unhex32(&hex(&id)), Some(id));
        assert_eq!(unhex32("zz"), None);
        assert_eq!(unhex32(&"g".repeat(64)), None);
    }

    #[test]
    fn engine_errors_map_to_worker_errors() {
        use pb::JobKind as K;
        use pb::WorkerError as W;
        let f = facts(K::Backup);
        assert_eq!(classify(&f, &EngineError::WrongKey), W::WrongPassword);
        assert_eq!(
            classify(&f, &EngineError::InvalidKey("x")),
            W::WrongPassword
        );
        assert_eq!(
            classify(&f, &EngineError::RepositoryNotFound),
            W::NoRepository
        );
        assert_eq!(
            classify(&f, &EngineError::SnapshotNotFound("x".into())),
            W::SnapshotNotFound
        );
        assert_eq!(classify(&f, &EngineError::Cancelled), W::Cancelled);
        assert_eq!(classify(&f, &repo_err()), W::Engine);
        let io = || EngineError::Io {
            context: "x",
            source: std::io::Error::other("x"),
        };
        assert_eq!(classify(&f, &io()), W::SourceUnreadable);
        assert_eq!(classify(&facts(K::Restore), &io()), W::TargetUnwritable);
        assert_eq!(classify(&facts(K::Check), &io()), W::Engine);
        assert_eq!(
            classify(
                &facts(K::Restore),
                &EngineError::MissingCapability("CAP_CHOWN")
            ),
            W::TargetUnwritable
        );
    }

    #[test]
    fn a_recorded_repository_error_selects_repo_only_for_errors_it_can_cause() {
        use pb::JobKind as K;
        use pb::WorkerError as W;
        let f = Facts {
            repo_error: Some(pb::ErrorClass::Transient),
            ..facts(K::Backup)
        };
        assert_eq!(classify(&f, &repo_err()), W::Repo);
        assert_eq!(
            classify(&f, &EngineError::SnapshotNotFound("latest".into())),
            W::Repo
        );
        // A wrong key is the key's fault, whatever the link said before.
        assert_eq!(classify(&f, &EngineError::WrongKey), W::WrongPassword);
    }

    #[test]
    fn cancel_wins_over_the_errors_it_causes_but_not_over_an_independent_one() {
        use pb::JobKind as K;
        use pb::WorkerError as W;
        let f = Facts {
            cancelled: true,
            repo_error: Some(pb::ErrorClass::Cancelled),
            ..facts(K::Backup)
        };
        assert_eq!(classify(&f, &repo_err()), W::Cancelled);
        assert_eq!(classify(&f, &EngineError::Closed), W::Cancelled);
        assert_eq!(classify(&f, &EngineError::WrongKey), W::WrongPassword);
    }
}
