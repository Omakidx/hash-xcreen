//! Validation rules of `docs/ipc.md` sections 25 to 31 that depend only on one message and on the
//! endpoint that receives it.
//!
//! What this checks: structure ("exactly one variant"), the direction table (which variants may
//! travel towards which endpoint), enum values the receiver knows (never `UNSPECIFIED`), fixed
//! sizes of ids, every count and size limit, string lengths and character rules, and the shape
//! of a `Job` and of a `JobResult` that can be checked without state. What it does not check,
//! because it needs the link's history: ordering, uniqueness of `req_id`, outstanding counts,
//! stream sizes, whether a response matches a request, and whether a `JobResult` matches the job
//! kind (the last two are [`super::LinkState`]'s).
//!
//! Errors name the offending field and never include its value.

use super::limits::{
    ID_LEN, INIT_COMPRESSION, INIT_DATAPACK_SIZE_LIMIT, INIT_TREEPACK_SIZE_LIMIT, JOB_ID_LEN,
    MAX_CONFIG_ENTRIES, MAX_CONFIG_KEY_LEN, MAX_CONFIG_VALUE_LEN, MAX_EXCLUDE_LEN, MAX_EXCLUDES,
    MAX_FOLDER_LEN, MAX_FORGET, MAX_KEY_IDS, MAX_LIST_PAGE_ENTRIES, MAX_MANIFEST_BYTES,
    MAX_OBJECT_SIZE, MAX_REMOVE_KEY_IDS, MAX_SECRET_BYTES, MAX_SECRET_SLOTS, MAX_SNAPSHOTS,
    MAX_SOFTWARE_LEN, MAX_TAG_LEN, MAX_TAGS, MAX_TEXT_LEN, MIN_SECRET_BYTES, SERVER_ID_LEN,
    max_object_size,
};
use super::{Endpoint, pb};
use crate::error::FrameError;
use crate::secret::SecretFrame;
use crate::text::is_unsafe_char;

type Check = Result<(), FrameError>;

fn invalid(what: &'static str) -> Check {
    Err(FrameError::Invalid(what))
}

fn require(cond: bool, what: &'static str) -> Check {
    if cond { Ok(()) } else { invalid(what) }
}

/// `v` must be a defined, non-zero value of enum `E`.
fn known<E: TryFrom<i32>>(v: i32, what: &'static str) -> Check {
    require(v != 0 && E::try_from(v).is_ok(), what)
}

fn object_type(v: i32, what: &'static str) -> Result<pb::ObjectType, FrameError> {
    pb::ObjectType::try_from(v)
        .ok()
        .filter(|t| *t != pb::ObjectType::Unspecified)
        .ok_or(FrameError::Invalid(what))
}

fn all_zero(b: &[u8]) -> bool {
    b.iter().all(|x| *x == 0)
}

/// An id of an object of `ty`: 32 bytes, all zero for `CONFIG` (its name is fixed) and not all
/// zero for everything else.
fn object_id(ty: pb::ObjectType, id: &[u8], what: &'static str) -> Check {
    require(id.len() == ID_LEN, what)?;
    require((ty == pb::ObjectType::Config) == all_zero(id), what)
}

/// A snapshot id or a key id: 32 bytes, not all zero.
fn plain_id(id: &[u8], what: &'static str) -> Check {
    require(id.len() == ID_LEN && !all_zero(id), what)
}

/// A string of `min..=max` bytes without control or format characters.
fn text(s: &str, min: usize, max: usize, what: &'static str) -> Check {
    require(
        (min..=max).contains(&s.len()) && !s.chars().any(is_unsafe_char),
        what,
    )
}

/// A tag: 1 to 64 bytes of `[A-Za-z0-9._-]`.
fn tag(s: &str, what: &'static str) -> Check {
    require(
        (1..=MAX_TAG_LEN).contains(&s.len())
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-')),
        what,
    )
}

fn tags(list: &[String], what: &'static str) -> Check {
    require(list.len() <= MAX_TAGS, what)?;
    list.iter().try_for_each(|t| tag(t, what))
}

/// Which endpoint receives a frame's variant: the direction table of sections 27 and 29.
fn travels_to(variant: &pb::repo_frame::Frame, to: Endpoint) -> bool {
    use Endpoint as E;
    use pb::repo_frame::Frame as F;
    match variant {
        F::Hello(_) => matches!(to, E::Worker | E::DriveHelper),
        F::HelloAck(_) => matches!(to, E::PrivdWorkerLink | E::PrivdDriveLink),
        F::Job(_) | F::Cancel(_) => to == E::Worker,
        F::Request(_) => matches!(to, E::PrivdWorkerLink | E::DriveHelper),
        F::Response(_) => matches!(to, E::Worker | E::PrivdDriveLink),
        F::Progress(_) | F::Result(_) => to == E::PrivdWorkerLink,
        F::Ping(_) | F::Pong(_) | F::Bye(_) => true,
        F::CancelRequest(_) => to == E::DriveHelper,
        F::Event(_) => to == E::PrivdDriveLink,
    }
}

/// Checks one decoded kind-1 frame that is about to be accepted by, or sent to, the endpoint
/// `to`.
pub fn validate_frame(frame: &pb::RepoFrame, to: Endpoint) -> Check {
    use pb::repo_frame::Frame as F;
    let Some(variant) = &frame.frame else {
        return invalid("frame: no variant set");
    };
    require(
        travels_to(variant, to),
        "frame: variant not valid in this direction",
    )?;
    match variant {
        F::Hello(h) => require(
            h.job_id.len() == JOB_ID_LEN && !all_zero(&h.job_id),
            "hello.job_id",
        ),
        F::HelloAck(a) => text(&a.software, 0, MAX_SOFTWARE_LEN, "hello_ack.software"),
        F::Job(j) => validate_job(j),
        F::Request(r) => validate_request(r, to),
        F::Response(r) => validate_response(r, to),
        F::Progress(p) => known::<pb::ProgressPhase>(p.phase, "progress.phase"),
        F::Result(r) => validate_result(r),
        F::Cancel(_) | F::Ping(_) | F::Pong(_) | F::Bye(_) => Ok(()),
        F::CancelRequest(c) => require(c.req_id != 0, "cancel_request.req_id"),
        F::Event(e) => known::<pb::EventKind>(e.kind, "event.kind"),
    }
}

// ----- requests and responses -----

/// Checks a `RepoRequest` received by `to`: non-zero `req_id`, one operation, ids, bounds, and
/// that the privd-only operations are only addressed to the Drive helper.
pub fn validate_request(r: &pb::RepoRequest, to: Endpoint) -> Check {
    use pb::repo_request::Op;
    require(r.req_id != 0, "request.req_id")?;
    let Some(op) = &r.op else {
        return invalid("request: no operation set");
    };
    match op {
        Op::List(l) => object_type(l.object_type, "list.object_type").map(|_| ()),
        Op::ReadFull(x) => {
            let ty = object_type(x.object_type, "read_full.object_type")?;
            object_id(ty, &x.id, "read_full.id")
        }
        Op::ReadPartial(x) => {
            let ty = object_type(x.object_type, "read_partial.object_type")?;
            object_id(ty, &x.id, "read_partial.id")?;
            let cap = max_object_size(ty).map_or(0, u64::from);
            require(x.length >= 1, "read_partial.length")?;
            require(
                u64::from(x.offset) + u64::from(x.length) <= cap,
                "read_partial.range",
            )
        }
        Op::Write(x) => {
            let ty = object_type(x.object_type, "write.object_type")?;
            object_id(ty, &x.id, "write.id")?;
            require(
                max_object_size(ty).is_some_and(|cap| x.size <= cap),
                "write.size",
            )
        }
        Op::Remove(x) => {
            let ty = object_type(x.object_type, "remove.object_type")?;
            object_id(ty, &x.id, "remove.id")
        }
        Op::Create(_) => Ok(()),
        Op::OpenRepo(o) => {
            require(to == Endpoint::DriveHelper, "open_repo: Drive link only")?;
            let name = o.folder.as_bytes();
            require(
                (1..=MAX_FOLDER_LEN).contains(&name.len())
                    && name[0].is_ascii_alphanumeric()
                    && name
                        .iter()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-')),
                "open_repo.folder",
            )?;
            require(
                o.server_id.len() == SERVER_ID_LEN && !all_zero(&o.server_id),
                "open_repo.server_id",
            )
        }
        Op::Quota(_) => require(to == Endpoint::DriveHelper, "quota: Drive link only"),
        Op::SetUploadRate(_) => require(
            to == Endpoint::DriveHelper,
            "set_upload_rate: Drive link only",
        ),
    }
}

fn validate_response(r: &pb::RepoResponse, to: Endpoint) -> Check {
    use pb::repo_response::Result as R;
    require(r.req_id != 0, "response.req_id")?;
    match &r.result {
        None => invalid("response: no result set"),
        Some(R::ListPage(p)) => {
            require(
                p.entries.len() <= MAX_LIST_PAGE_ENTRIES,
                "list_page.entries",
            )?;
            require(
                p.entries
                    .iter()
                    .all(|e| e.id.len() == ID_LEN && e.size <= MAX_OBJECT_SIZE),
                "list_page.entry",
            )
        }
        Some(R::ReadBegin(b)) => require(b.size <= MAX_OBJECT_SIZE, "read_begin.size"),
        Some(R::Done(_)) => Ok(()),
        Some(R::Error(e)) => {
            use pb::ErrorClass as C;
            known::<C>(e.class, "error.class")?;
            // From the Drive helper: the classes that are privd's own verdicts (section 31) are
            // not the helper's to give.
            let privd_own = matches!(
                C::try_from(e.class),
                Ok(C::PolicyDenied | C::Integrity | C::TooLarge | C::Unavailable)
            );
            require(
                !(to == Endpoint::PrivdDriveLink && privd_own),
                "error.class: privd-only class from the Drive helper",
            )
        }
        Some(R::QuotaResult(_)) => require(
            to == Endpoint::PrivdDriveLink,
            "quota_result: Drive link only",
        ),
    }
}

// ----- job (section 28) -----

fn validate_job(j: &pb::Job) -> Check {
    use pb::JobKind as K;
    use pb::job::Spec;
    require(
        j.job_id.len() == JOB_ID_LEN && !all_zero(&j.job_id),
        "job.job_id",
    )?;
    known::<K>(j.kind, "job.kind")?;
    let kind = K::try_from(j.kind).map_err(|_| FrameError::Invalid("job.kind"))?;
    let Some(spec) = &j.spec else {
        return invalid("job: no spec set");
    };
    let mut add = false;
    match (kind, spec) {
        (K::Init, Spec::Init(s)) => require(
            s.compression == INIT_COMPRESSION
                && s.datapack_size_limit == INIT_DATAPACK_SIZE_LIMIT
                && s.treepack_size_limit == INIT_TREEPACK_SIZE_LIMIT,
            "init: constants",
        )?,
        (K::Backup, Spec::Backup(s)) => validate_backup(s)?,
        (K::Snapshots, Spec::Snapshots(_)) => {}
        (K::RestorePlan, Spec::RestorePlan(s)) => {
            plain_id(&s.snapshot_id, "restore_plan.snapshot_id")?
        }
        (K::Restore, Spec::Restore(s)) => plain_id(&s.snapshot_id, "restore.snapshot_id")?,
        (K::ForgetPrune, Spec::ForgetPrune(s)) => {
            require(s.instant, "forget_prune.instant")?;
            require(s.forget.len() <= MAX_FORGET, "forget_prune.forget")?;
            s.forget
                .iter()
                .try_for_each(|id| plain_id(id, "forget_prune.forget"))?;
            let mut seen: Vec<&[u8]> = s.forget.iter().map(|b| b.as_ref()).collect();
            seen.sort_unstable();
            require(
                seen.windows(2).all(|w| w[0] != w[1]),
                "forget_prune.forget: duplicate",
            )?;
        }
        (K::Check, Spec::Check(s)) => {
            require(s.read_data_percent <= 100, "check.read_data_percent")?
        }
        (K::Keys, Spec::Keys(s)) => {
            add = s.add;
            require(
                s.remove_key_ids.len() <= MAX_REMOVE_KEY_IDS,
                "keys.remove_key_ids",
            )?;
            s.remove_key_ids
                .iter()
                .try_for_each(|id| plain_id(id, "keys.remove_key_ids"))?;
        }
        _ => return invalid("job: spec does not match kind"),
    }
    validate_slots(kind, add, &j.secret_slots)
}

/// The secret slots a job of `kind` must declare (section 28): `INIT` 0 and 1, `KEYS` 0 and, when
/// it adds a key, 1; every other kind 0.
fn expected_slots(kind: pb::JobKind, add: bool) -> &'static [(u32, pb::SecretKind)] {
    use pb::JobKind as K;
    use pb::SecretKind as S;
    const ONE: &[(u32, S)] = &[(0, S::RepoPassword)];
    const TWO: &[(u32, S)] = &[(0, S::RepoPassword), (1, S::NewKeyPassword)];
    match kind {
        K::Init => TWO,
        K::Keys if add => TWO,
        _ => ONE,
    }
}

fn validate_slots(kind: pb::JobKind, add: bool, slots: &[pb::SecretSlot]) -> Check {
    let want = expected_slots(kind, add);
    require(
        slots.len() <= MAX_SECRET_SLOTS && slots.len() == want.len(),
        "job.secret_slots",
    )?;
    for (got, (slot, sk)) in slots.iter().zip(want) {
        require(
            got.slot == *slot
                && got.kind == *sk as i32
                && (MIN_SECRET_BYTES..=MAX_SECRET_BYTES).contains(&(got.length as usize)),
            "job.secret_slots",
        )?;
    }
    Ok(())
}

fn validate_backup(s: &pb::BackupSpec) -> Check {
    let Some(m) = &s.manifest else {
        return invalid("backup.manifest");
    };
    text(&m.agent_version, 1, MAX_TEXT_LEN, "manifest.agent_version")?;
    let Some(d) = &m.distro else {
        return invalid("manifest.distro");
    };
    text(&d.id, 1, MAX_TEXT_LEN, "manifest.distro.id")?;
    text(&d.version_id, 0, MAX_TEXT_LEN, "manifest.distro.version_id")?;
    text(
        &d.pretty_name,
        0,
        MAX_TEXT_LEN,
        "manifest.distro.pretty_name",
    )?;
    text(&m.desktop, 1, MAX_TEXT_LEN, "manifest.desktop")?;
    text(&m.preset, 1, MAX_TEXT_LEN, "manifest.preset")?;
    require(m.format_version >= 1, "manifest.format_version")?;
    require(
        m.container_config.len() <= MAX_CONFIG_ENTRIES,
        "manifest.container_config",
    )?;
    for e in &m.container_config {
        text(
            &e.key,
            1,
            MAX_CONFIG_KEY_LEN,
            "manifest.container_config.key",
        )?;
        require(
            !e.key.starts_with("volatile.") && e.value.len() <= MAX_CONFIG_VALUE_LEN,
            "manifest.container_config",
        )?;
    }
    require(s.excludes.len() <= MAX_EXCLUDES, "backup.excludes")?;
    for x in &s.excludes {
        text(x, 1, MAX_EXCLUDE_LEN, "backup.excludes")?;
    }
    known::<pb::DockerMode>(s.docker_mode, "backup.docker_mode")?;
    tags(&s.tags, "backup.tags")
}

// ----- job result (sections 27, 31) -----

fn validate_result(r: &pb::JobResult) -> Check {
    if r.ok {
        require(r.error == 0, "result.error: set on success")?;
    } else {
        known::<pb::WorkerError>(r.error, "result.error")?;
        require(
            r.snapshot_id.is_empty()
                && r.key_ids.is_empty()
                && r.manifest.is_empty()
                && r.snapshots.is_empty(),
            "result: payload on failure",
        )?;
    }
    require(
        r.snapshot_id.is_empty() || plain_id(&r.snapshot_id, "result.snapshot_id").is_ok(),
        "result.snapshot_id",
    )?;
    require(r.key_ids.len() <= MAX_KEY_IDS, "result.key_ids")?;
    r.key_ids
        .iter()
        .try_for_each(|id| plain_id(id, "result.key_ids"))?;
    require(r.manifest.len() <= MAX_MANIFEST_BYTES, "result.manifest")?;
    require(r.snapshots.len() <= MAX_SNAPSHOTS, "result.snapshots")?;
    for s in &r.snapshots {
        plain_id(&s.id, "snapshot.id")?;
        require(s.time >= 0, "snapshot.time")?;
        require(
            s.manifest_digest.len() == ID_LEN,
            "snapshot.manifest_digest",
        )?;
        tags(&s.tags, "snapshot.tags")?;
    }
    Ok(())
}

/// Whether a `JobResult` has the shape its job `kind` allows (what [`validate_frame`] cannot know):
/// `snapshot_id` exactly for a successful `BACKUP`, `manifest` exactly for a successful
/// `RESTORE_PLAN`, `snapshots` only for `SNAPSHOTS`, `key_ids` only for `INIT` and `KEYS`.
pub fn check_result_shape(kind: pb::JobKind, r: &pb::JobResult) -> Check {
    use pb::JobKind as K;
    require(
        r.snapshot_id.is_empty() != (r.ok && kind == K::Backup),
        "result.snapshot_id: does not match the job kind",
    )?;
    require(
        r.manifest.is_empty() != (r.ok && kind == K::RestorePlan),
        "result.manifest: does not match the job kind",
    )?;
    require(
        r.snapshots.is_empty() || kind == K::Snapshots,
        "result.snapshots: does not match the job kind",
    )?;
    require(
        r.key_ids.is_empty() || matches!(kind, K::Init | K::Keys),
        "result.key_ids: does not match the job kind",
    )
}

// ----- secrets -----

/// Checks a decoded kind-2 frame: `request_id` 0 (the job), a slot of 0 or 1, 16 to 1 024 bytes.
pub fn validate_secret(f: &SecretFrame) -> Check {
    require(f.request_id == 0, "secret.request_id")?;
    require(usize::from(f.slot) < MAX_SECRET_SLOTS, "secret.slot")?;
    require(
        (MIN_SECRET_BYTES..=MAX_SECRET_BYTES).contains(&f.secret.len()),
        "secret.length",
    )
}
