//! The operation policy of `docs/ipc.md` section 30, as a pure function.
//!
//! privd checks every request of the worker against the job kind before it forwards it. This
//! module decides only what the table says; it does not look at the repository, at sizes
//! (those are the codec's, [`super::validate_frame`]) or at hashes (privd's relay checks
//! SHA-256 of every `Write` body against its `id`).
//!
//! | Job kind | List | Read | Write | Remove | Create |
//! |---|---|---|---|---|---|
//! | `INIT` | all | `CONFIG`, `KEY` | `CONFIG` (only if absent), `KEY` | none | yes |
//! | `BACKUP` | all | all | `PACK`, `INDEX`, `SNAPSHOT` | `INDEX` | no |
//! | `SNAPSHOTS`, `RESTORE_PLAN`, `RESTORE`, `CHECK` | all | all | none | none | no |
//! | `FORGET_PRUNE` | all | all | `PACK`, `INDEX` | `PACK`, `INDEX`; `SNAPSHOT` only for the spec's ids | no |
//! | `KEYS` | all | all | `KEY` | `KEY` only for the spec's ids | no |
//!
//! `Create` is allowed for `INIT` only (the reading of `docs/ipc.md` section 36, Q-C1). The
//! operations that only privd may send to the Drive helper (`OpenRepo`, `Quota`,
//! `SetUploadRate`) are never allowed to a job. Everything unknown or unset is denied: the
//! function fails closed.

use super::pb::{self, ObjectType as T, repo_request::Op};

/// What the policy says about one request.
///
/// **`AllowIfAbsent` is not `Allow`.** Code that treats every non-`Deny` as "forward" lets an
/// `INIT` job overwrite an existing repository config; match all three variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a verdict must be acted on; AllowIfAbsent is not Allow"]
pub enum Verdict {
    /// Forward the request.
    Allow,
    /// Forward it **only if the object does not exist yet**: the `INIT` write of `CONFIG`
    /// ("only if absent"). The codec cannot know; the caller must ask the repository (a `List`
    /// of `CONFIG` through the Drive link, or the job's own earlier listing) and treat an
    /// existing `CONFIG` as `POLICY_DENIED`. Never forward this verdict unchecked.
    AllowIfAbsent,
    /// Answer `POLICY_DENIED`, audit it and fail the job.
    Deny,
}

fn object(v: i32) -> Option<T> {
    T::try_from(v).ok().filter(|t| *t != T::Unspecified)
}

fn has_id(ids: &[bytes::Bytes], id: &[u8]) -> bool {
    ids.iter().any(|i| i.as_ref() == id)
}

/// The policy of section 30: may a job of `kind` with `spec` send `op`?
///
/// `spec` is the job's own spec (as sent in `Job`); only `FORGET_PRUNE` (the snapshot ids in
/// `forget`) and `KEYS` (`remove_key_ids`) consult it. A spec that does not belong to the kind
/// counts as an empty one, which denies the id-bound removals.
pub fn check_op(kind: pb::JobKind, spec: Option<&pb::job::Spec>, op: &Op) -> Verdict {
    use pb::JobKind as K;
    if kind == K::Unspecified {
        return Verdict::Deny;
    }
    match op {
        Op::List(l) => allow_if(object(l.object_type).is_some()),
        Op::ReadFull(r) => read(kind, object(r.object_type)),
        Op::ReadPartial(r) => read(kind, object(r.object_type)),
        Op::Write(w) => write(kind, object(w.object_type)),
        Op::Remove(r) => remove(kind, spec, object(r.object_type), &r.id),
        Op::Create(_) => allow_if(kind == K::Init),
        Op::OpenRepo(_) | Op::Quota(_) | Op::SetUploadRate(_) => Verdict::Deny,
    }
}

/// [`check_op`] for a whole `Job` message.
pub fn check_job_op(job: &pb::Job, op: &Op) -> Verdict {
    match pb::JobKind::try_from(job.kind) {
        Ok(kind) => check_op(kind, job.spec.as_ref(), op),
        Err(_) => Verdict::Deny,
    }
}

fn allow_if(cond: bool) -> Verdict {
    if cond { Verdict::Allow } else { Verdict::Deny }
}

fn read(kind: pb::JobKind, ty: Option<T>) -> Verdict {
    match (kind, ty) {
        (_, None) => Verdict::Deny,
        (pb::JobKind::Init, Some(t)) => allow_if(matches!(t, T::Config | T::Key)),
        (_, Some(_)) => Verdict::Allow,
    }
}

fn write(kind: pb::JobKind, ty: Option<T>) -> Verdict {
    use pb::JobKind as K;
    let Some(ty) = ty else { return Verdict::Deny };
    match kind {
        K::Init => match ty {
            T::Config => Verdict::AllowIfAbsent,
            T::Key => Verdict::Allow,
            _ => Verdict::Deny,
        },
        K::Backup => allow_if(matches!(ty, T::Pack | T::Index | T::Snapshot)),
        K::ForgetPrune => allow_if(matches!(ty, T::Pack | T::Index)),
        K::Keys => allow_if(ty == T::Key),
        K::Snapshots | K::RestorePlan | K::Restore | K::Check | K::Unspecified => Verdict::Deny,
    }
}

fn remove(kind: pb::JobKind, spec: Option<&pb::job::Spec>, ty: Option<T>, id: &[u8]) -> Verdict {
    use pb::JobKind as K;
    let Some(ty) = ty else { return Verdict::Deny };
    match kind {
        K::Backup => allow_if(ty == T::Index),
        K::ForgetPrune => match ty {
            T::Pack | T::Index => Verdict::Allow,
            T::Snapshot => match spec {
                Some(pb::job::Spec::ForgetPrune(s)) => allow_if(has_id(&s.forget, id)),
                _ => Verdict::Deny,
            },
            _ => Verdict::Deny,
        },
        K::Keys => match (ty, spec) {
            (T::Key, Some(pb::job::Spec::Keys(s))) => allow_if(has_id(&s.remove_key_ids, id)),
            _ => Verdict::Deny,
        },
        K::Init | K::Snapshots | K::RestorePlan | K::Restore | K::Check | K::Unspecified => {
            Verdict::Deny
        }
    }
}
