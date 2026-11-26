#![cfg(feature = "repo")]
//! The operation policy of `docs/ipc.md` section 30, checked exhaustively: every job kind
//! against every operation against every object type, from an independent copy of the table.

mod repo_common;

use bytes::Bytes;
use hx_ipc::repo::pb::{self, JobKind as K, ObjectType as T, job::Spec, repo_request::Op};
use hx_ipc::repo::policy::{Verdict, check_job_op, check_op};
use repo_common::*;

use Verdict::{Allow as A, AllowIfAbsent as I, Deny as D};

/// One row of section 30.
struct Row {
    kind: K,
    read: &'static [T],
    write: &'static [(T, Verdict)],
    /// Types whose removal is allowed outright.
    remove: &'static [T],
    create: bool,
}

const ALL_TYPES: &[T] = &[T::Config, T::Key, T::Snapshot, T::Index, T::Pack];

const ROWS: &[Row] = &[
    Row {
        kind: K::Init,
        read: &[T::Config, T::Key],
        write: &[(T::Config, I), (T::Key, A)],
        remove: &[],
        create: true,
    },
    Row {
        kind: K::Backup,
        read: ALL_TYPES,
        write: &[(T::Pack, A), (T::Index, A), (T::Snapshot, A)],
        remove: &[T::Index],
        create: false,
    },
    Row {
        kind: K::Snapshots,
        read: ALL_TYPES,
        write: &[],
        remove: &[],
        create: false,
    },
    Row {
        kind: K::RestorePlan,
        read: ALL_TYPES,
        write: &[],
        remove: &[],
        create: false,
    },
    Row {
        kind: K::Restore,
        read: ALL_TYPES,
        write: &[],
        remove: &[],
        create: false,
    },
    Row {
        kind: K::Check,
        read: ALL_TYPES,
        write: &[],
        remove: &[],
        create: false,
    },
    Row {
        kind: K::ForgetPrune,
        read: ALL_TYPES,
        write: &[(T::Pack, A), (T::Index, A)],
        remove: &[T::Pack, T::Index],
        create: false,
    },
    Row {
        kind: K::Keys,
        read: ALL_TYPES,
        write: &[(T::Key, A)],
        remove: &[],
        create: false,
    },
];

fn spec_of(kind: K) -> Spec {
    job(kind).spec.unwrap()
}

#[test]
fn the_whole_table() {
    assert_eq!(ROWS.len(), 8, "every job kind has a row");
    for row in ROWS {
        let spec = spec_of(row.kind);
        let check = |op: &Op| check_op(row.kind, Some(&spec), op);
        for &ty in ALL_TYPES {
            // List: all types, every kind.
            assert_eq!(check(&list(ty)), A, "{:?} list {ty:?}", row.kind);
            // Reads, whole and partial.
            let want = if row.read.contains(&ty) { A } else { D };
            assert_eq!(
                check(&read_full(ty, 1)),
                want,
                "{:?} read_full {ty:?}",
                row.kind
            );
            assert_eq!(
                check(&read_partial(ty, 1, 0, 8)),
                want,
                "{:?} read_partial {ty:?}",
                row.kind
            );
            // Writes.
            let want = row
                .write
                .iter()
                .find(|(t, _)| *t == ty)
                .map_or(D, |(_, v)| *v);
            assert_eq!(check(&write(ty, 1, 1)), want, "{:?} write {ty:?}", row.kind);
            // Removes: the unconditional ones; the id-bound ones are tested below.
            let uncond = row.remove.contains(&ty);
            let got = check(&remove(ty, 0xEE)); // an id that is in no spec
            let id_bound = matches!(
                (row.kind, ty),
                (K::ForgetPrune, T::Snapshot) | (K::Keys, T::Key)
            );
            assert_eq!(
                got,
                if uncond { A } else { D },
                "{:?} remove {ty:?}",
                row.kind
            );
            assert!(id_bound || !matches!(got, I));
        }
        assert_eq!(
            check(&Op::Create(pb::Create {})),
            if row.create { A } else { D },
            "{:?} create",
            row.kind
        );
        // Nothing may ask for the privd-only operations.
        assert_eq!(check(&open_repo()), D, "{:?}", row.kind);
        assert_eq!(check(&Op::Quota(pb::Quota {})), D);
        assert_eq!(
            check(&Op::SetUploadRate(pb::SetUploadRate { bytes_per_s: 1 })),
            D
        );
    }
}

#[test]
fn removals_bound_to_ids_in_the_spec() {
    // FORGET_PRUNE: a SNAPSHOT only if its id is in `forget`.
    let spec = Spec::ForgetPrune(pb::ForgetPruneSpec {
        forget: vec![id(1), id(2)],
        instant: true,
    });
    for (b, want) in [(1, A), (2, A), (3, D), (0xEE, D)] {
        assert_eq!(
            check_op(K::ForgetPrune, Some(&spec), &remove(T::Snapshot, b)),
            want,
            "snapshot {b}"
        );
    }
    // KEYS: a KEY only if its id is in `remove_key_ids`.
    let spec = Spec::Keys(pb::KeysSpec {
        add: true,
        remove_key_ids: vec![id(3)],
    });
    for (b, want) in [(3, A), (1, D), (0xEE, D)] {
        assert_eq!(
            check_op(K::Keys, Some(&spec), &remove(T::Key, b)),
            want,
            "key {b}"
        );
    }
    // Ids are compared whole: a prefix or a longer id never matches.
    let short = Op::Remove(pb::Remove {
        object_type: T::Key as i32,
        id: Bytes::from(vec![3u8; 31]),
    });
    assert_eq!(check_op(K::Keys, Some(&spec), &short), D);
    let long = Op::Remove(pb::Remove {
        object_type: T::Key as i32,
        id: Bytes::from(vec![3u8; 33]),
    });
    assert_eq!(check_op(K::Keys, Some(&spec), &long), D);
    // Fail closed: no spec, or the spec of another kind, is an empty list.
    assert_eq!(check_op(K::Keys, None, &remove(T::Key, 3)), D);
    assert_eq!(check_op(K::ForgetPrune, None, &remove(T::Snapshot, 1)), D);
    let other = spec_of(K::Check);
    assert_eq!(check_op(K::Keys, Some(&other), &remove(T::Key, 3)), D);
    let keys_spec = Spec::Keys(pb::KeysSpec {
        add: false,
        remove_key_ids: vec![id(1)],
    });
    assert_eq!(
        check_op(K::ForgetPrune, Some(&keys_spec), &remove(T::Snapshot, 1)),
        D
    );
    // The id lists of one kind do not leak into the other's removals.
    let forget = Spec::ForgetPrune(pb::ForgetPruneSpec {
        forget: vec![id(1)],
        instant: true,
    });
    assert_eq!(
        check_op(K::ForgetPrune, Some(&forget), &remove(T::Key, 1)),
        D
    );
    assert_eq!(check_op(K::Keys, Some(&forget), &remove(T::Key, 1)), D);
}

#[test]
fn unknown_values_fail_closed() {
    for kind in KINDS {
        let spec = spec_of(kind);
        for ty in [0, 6, 99] {
            for op in [
                Op::List(pb::List { object_type: ty }),
                Op::ReadFull(pb::ReadFull {
                    object_type: ty,
                    id: id(1),
                }),
                Op::ReadPartial(pb::ReadPartial {
                    object_type: ty,
                    id: id(1),
                    offset: 0,
                    length: 1,
                }),
                Op::Write(pb::Write {
                    object_type: ty,
                    id: id(1),
                    size: 1,
                }),
                Op::Remove(pb::Remove {
                    object_type: ty,
                    id: id(1),
                }),
            ] {
                assert_eq!(check_op(kind, Some(&spec), &op), D, "{kind:?} type {ty}");
            }
        }
    }
    for op in [
        list(T::Pack),
        read_full(T::Pack, 1),
        write(T::Pack, 1, 1),
        Op::Create(pb::Create {}),
    ] {
        assert_eq!(check_op(K::Unspecified, None, &op), D);
    }
    let mut j = job(K::Backup);
    j.kind = 77;
    assert_eq!(check_job_op(&j, &list(T::Pack)), D);
}

#[test]
fn check_job_op_uses_the_jobs_own_spec() {
    let mut j = job(K::ForgetPrune);
    assert_eq!(check_job_op(&j, &remove(T::Snapshot, 1)), A);
    assert_eq!(check_job_op(&j, &remove(T::Snapshot, 9)), D);
    j.spec = None;
    assert_eq!(check_job_op(&j, &remove(T::Snapshot, 1)), D);
    let j = job(K::Init);
    assert_eq!(
        check_job_op(&j, &write(T::Config, 0, 10)),
        I,
        "the caller must check that CONFIG is absent"
    );
    assert_eq!(check_job_op(&j, &Op::Create(pb::Create {})), A);
}

#[test]
fn the_anti_ransomware_property() {
    // A BACKUP worker can add objects but never overwrite or delete packs, snapshots, keys or
    // the config; a CHECK/RESTORE worker changes nothing at all.
    let spec = spec_of(K::Backup);
    for ty in [T::Pack, T::Snapshot, T::Key, T::Config] {
        assert_eq!(
            check_op(K::Backup, Some(&spec), &remove(ty, 1)),
            D,
            "{ty:?}"
        );
    }
    assert_eq!(check_op(K::Backup, Some(&spec), &write(T::Key, 1, 1)), D);
    assert_eq!(check_op(K::Backup, Some(&spec), &write(T::Config, 0, 1)), D);
    for kind in [K::Snapshots, K::RestorePlan, K::Restore, K::Check] {
        let spec = spec_of(kind);
        for &ty in ALL_TYPES {
            assert_eq!(check_op(kind, Some(&spec), &write(ty, 1, 1)), D);
            assert_eq!(check_op(kind, Some(&spec), &remove(ty, 1)), D);
        }
    }
}
