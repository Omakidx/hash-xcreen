#![cfg(feature = "repo")]
//! Contract tests for the repository link codec (`docs/ipc.md` Part 3): every message
//! round-trips, every limit is enforced at N and N+1, every variant is refused towards an
//! endpoint it may not travel to, the frame policy differs per endpoint, and the data and
//! secret frames behave as sections 25 and 34 say.

mod repo_common;

use bytes::{Bytes, BytesMut};
use hx_ipc::error::FrameError;
use hx_ipc::frame::{Decoder, FramePolicy, RawFrame, encode_frame};
use hx_ipc::repo::pb::{self, JobKind, ObjectType, repo_frame::Frame as F, repo_request::Op};
use hx_ipc::repo::{
    self, DataFrame, Endpoint, Incoming, RepoFramePolicy, encode_data, encode_data_header,
    encode_message, encode_secret, message_raw_frame, validate_frame,
};
use proptest::prelude::*;
use repo_common::*;

/// Decodes `wire` at `endpoint` through a `Decoder`, in chunks of `chunk` bytes.
fn through_decoder(wire: &[u8], endpoint: Endpoint, chunk: usize) -> Result<Incoming, FrameError> {
    let mut d = Decoder::new(RepoFramePolicy::new(endpoint));
    let mut rest = wire;
    let mut frame: Option<RawFrame> = None;
    while !rest.is_empty() && frame.is_none() {
        let take = rest.len().min(chunk);
        let (used, f) = d.feed(&rest[..take])?;
        rest = &rest[used..];
        frame = f;
    }
    let raw = frame.ok_or(FrameError::Truncated)?;
    assert!(rest.is_empty(), "one frame in, one frame out");
    repo::decode(raw, endpoint)
}

// ----- round trips and the direction table -----

#[test]
fn every_message_round_trips_towards_every_endpoint_it_may_travel_to() {
    let frames = every_frame();
    assert_eq!(frames.len(), 32, "every variant, op and result is covered");
    for (name, f, to) in &frames {
        for e in to {
            let wire = encode_message(f, *e).unwrap_or_else(|err| panic!("{name} -> {e:?}: {err}"));
            for chunk in [1, 7, 4096] {
                match through_decoder(&wire, *e, chunk) {
                    Ok(Incoming::Message(back)) => assert_eq!(&back, f, "{name} -> {e:?}"),
                    other => panic!("{name} -> {e:?}: {other:?}"),
                }
            }
        }
    }
}

#[test]
fn every_message_is_refused_towards_every_other_endpoint() {
    for (name, f, to) in every_frame() {
        for e in ALL {
            if to.contains(&e) {
                continue;
            }
            assert!(
                matches!(
                    encode_message(&f, e),
                    Err(FrameError::Invalid(m)) if m.contains("direction") || m.contains("only")
                ),
                "{name} must not be encodable towards {e:?}"
            );
            // And a hostile sender that hand-builds the bytes gets the same answer.
            assert!(
                repo::decode(message_raw_frame(&f), e).is_err(),
                "{name} must not decode at {e:?}"
            );
        }
    }
}

#[test]
fn the_variant_sets_per_endpoint_match_the_contract() {
    // Section 27 and 29 as one table, written out once more from the other side.
    let accepted = |e: Endpoint| -> Vec<String> {
        every_frame()
            .into_iter()
            .filter(|(_, f, _)| validate_frame(f, e).is_ok())
            .map(|(n, ..)| n)
            .collect()
    };
    let privd_on_worker = accepted(Endpoint::PrivdWorkerLink);
    for n in [
        "hello_ack",
        "progress",
        "result",
        "request_list",
        "request_write",
        "ping",
        "bye",
    ] {
        assert!(privd_on_worker.iter().any(|x| x == n), "{n}");
    }
    for n in [
        "request_open_repo",
        "request_quota",
        "request_set_upload_rate",
        "event",
        "cancel",
    ] {
        assert!(
            !privd_on_worker.iter().any(|x| x == n),
            "{n} never on the worker link"
        );
    }
    let worker = accepted(Endpoint::Worker);
    assert!(worker.iter().any(|n| n.starts_with("job_")));
    assert!(!worker.iter().any(|n| n.starts_with("request_")));
    assert!(!worker.iter().any(|n| n == "response_quota_result"));
}

#[test]
fn an_empty_frame_and_an_empty_oneof_are_invalid() {
    for e in ALL {
        assert!(validate_frame(&pb::RepoFrame { frame: None }, e).is_err());
        let no_op = frame(F::Request(pb::RepoRequest {
            req_id: 1,
            op: None,
        }));
        let no_result = frame(F::Response(pb::RepoResponse {
            req_id: 1,
            result: None,
        }));
        let no_spec = frame(F::Job(pb::Job {
            spec: None,
            ..job(JobKind::Check)
        }));
        for f in [no_op, no_result, no_spec] {
            assert!(validate_frame(&f, e).is_err());
        }
    }
    // An empty body decodes to a frame with no variant, which is refused.
    let raw = RawFrame {
        kind: repo::KIND_MESSAGE,
        body: BytesMut::new(),
    };
    assert!(repo::decode(raw, Endpoint::Worker).is_err());
}

// ----- the frame policy -----

#[test]
fn kinds_and_lengths_per_endpoint() {
    for e in ALL {
        let p = RepoFramePolicy::new(e);
        assert_eq!(p.max_length(repo::KIND_MESSAGE), Ok(65_536));
        assert_eq!(p.max_length(repo::KIND_DATA), Ok(1_048_586));
        assert_eq!(p.absolute_max_length(), 1_048_586);
        for k in [0u8, 4, 9, 255] {
            assert_eq!(p.max_length(k), Err(FrameError::UnknownKind(k)));
        }
        assert!(p.is_sensitive(repo::KIND_SECRET));
        assert!(
            !p.is_sensitive(repo::KIND_DATA),
            "kind 3 is encrypted repository data"
        );
        assert!(!p.is_sensitive(repo::KIND_MESSAGE));
    }
    assert_eq!(
        RepoFramePolicy::new(Endpoint::Worker).max_length(repo::KIND_SECRET),
        Ok(8_192)
    );
    for e in [
        Endpoint::PrivdWorkerLink,
        Endpoint::PrivdDriveLink,
        Endpoint::DriveHelper,
    ] {
        assert_eq!(
            RepoFramePolicy::new(e).max_length(repo::KIND_SECRET),
            Err(FrameError::KindNotAllowed(2)),
            "{e:?}"
        );
    }
}

fn prefix(length: u32, kind: u8) -> Vec<u8> {
    let mut v = length.to_le_bytes().to_vec();
    v.push(kind);
    v
}

#[test]
fn length_limits_are_checked_before_any_body_arrives() {
    for e in ALL {
        let feed = |length: u32, kind: u8| {
            Decoder::new(RepoFramePolicy::new(e)).feed(&prefix(length, kind))
        };
        // Exactly at the limit: accepted so far (the body is still to come).
        assert!(feed(65_536, 1).is_ok());
        assert!(feed(1_048_586, 3).is_ok());
        // One over.
        assert!(matches!(
            feed(65_537, 1),
            Err(FrameError::TooLong { max: 65_536, .. })
        ));
        assert!(matches!(
            feed(1_048_587, 3),
            Err(FrameError::TooLong { max: 1_048_586, .. })
        ));
        assert!(matches!(feed(0, 1), Err(FrameError::ZeroLength)));
    }
    let worker =
        |length: u32| Decoder::new(RepoFramePolicy::new(Endpoint::Worker)).feed(&prefix(length, 2));
    assert!(worker(8_192).is_ok());
    assert!(matches!(
        worker(8_193),
        Err(FrameError::TooLong { max: 8_192, .. })
    ));
    // Nothing above the absolute maximum, whatever the kind byte will be.
    let mut d = Decoder::new(RepoFramePolicy::new(Endpoint::Worker));
    assert!(matches!(
        d.feed(&1_048_587u32.to_le_bytes()),
        Err(FrameError::TooLong { .. })
    ));
}

// ----- field rules, each at N and N+1 -----

fn ok(f: &pb::RepoFrame, e: Endpoint) {
    if let Err(err) = validate_frame(f, e) {
        panic!("expected valid, got {err}");
    }
}

fn bad(f: &pb::RepoFrame, e: Endpoint) {
    assert!(validate_frame(f, e).is_err(), "expected invalid");
}

/// `(valid, invalid)` at the boundary, at `e`.
fn edge(valid: pb::RepoFrame, invalid: pb::RepoFrame, e: Endpoint) {
    ok(&valid, e);
    bad(&invalid, e);
}

fn backup_job_with(f: impl FnOnce(&mut pb::BackupSpec)) -> pb::RepoFrame {
    let mut j = job(JobKind::Backup);
    let Some(pb::job::Spec::Backup(b)) = &mut j.spec else {
        unreachable!()
    };
    f(b);
    frame(F::Job(j))
}

fn manifest_of(b: &mut pb::BackupSpec) -> &mut pb::ManifestInput {
    b.manifest.as_mut().unwrap()
}

fn s(len: usize) -> String {
    "a".repeat(len)
}

#[test]
fn backup_spec_limits() {
    let w = Endpoint::Worker;
    edge(
        backup_job_with(|b| b.excludes = vec!["/x".into(); 256]),
        backup_job_with(|b| b.excludes = vec!["/x".into(); 257]),
        w,
    );
    edge(
        backup_job_with(|b| b.excludes = vec![s(1024)]),
        backup_job_with(|b| b.excludes = vec![s(1025)]),
        w,
    );
    bad(&backup_job_with(|b| b.excludes = vec![String::new()]), w);
    bad(&backup_job_with(|b| b.excludes = vec!["/a\n/b".into()]), w);
    bad(&backup_job_with(|b| b.excludes = vec!["/a\0b".into()]), w);
    edge(
        backup_job_with(|b| b.tags = vec![s(64); 4]),
        backup_job_with(|b| b.tags = vec![s(64); 5]),
        w,
    );
    edge(
        backup_job_with(|b| b.tags = vec![s(64)]),
        backup_job_with(|b| b.tags = vec![s(65)]),
        w,
    );
    bad(&backup_job_with(|b| b.tags = vec!["has space".into()]), w);
    bad(&backup_job_with(|b| b.tags = vec![String::new()]), w);
    // The manifest input.
    {
        let (valid, invalid) = (128, 129);
        edge(
            backup_job_with(|b| manifest_of(b).agent_version = s(valid)),
            backup_job_with(|b| manifest_of(b).agent_version = s(invalid)),
            w,
        );
        edge(
            backup_job_with(|b| manifest_of(b).desktop = s(valid)),
            backup_job_with(|b| manifest_of(b).desktop = s(invalid)),
            w,
        );
        edge(
            backup_job_with(|b| manifest_of(b).preset = s(valid)),
            backup_job_with(|b| manifest_of(b).preset = s(invalid)),
            w,
        );
        edge(
            backup_job_with(|b| manifest_of(b).distro.as_mut().unwrap().id = s(valid)),
            backup_job_with(|b| manifest_of(b).distro.as_mut().unwrap().id = s(invalid)),
            w,
        );
        edge(
            backup_job_with(|b| manifest_of(b).distro.as_mut().unwrap().pretty_name = s(valid)),
            backup_job_with(|b| manifest_of(b).distro.as_mut().unwrap().pretty_name = s(invalid)),
            w,
        );
    }
    bad(
        &backup_job_with(|b| manifest_of(b).desktop = String::new()),
        w,
    );
    bad(
        &backup_job_with(|b| manifest_of(b).desktop = "x\u{1b}[31m".into()),
        w,
    );
    bad(&backup_job_with(|b| manifest_of(b).format_version = 0), w);
    bad(&backup_job_with(|b| b.manifest = None), w);
    bad(&backup_job_with(|b| manifest_of(b).distro = None), w);
    let entry = |i: usize| pb::ConfigEntry {
        key: format!("user.k{i}"),
        value: String::new(),
    };
    edge(
        backup_job_with(|b| manifest_of(b).container_config = (0..256).map(entry).collect()),
        backup_job_with(|b| manifest_of(b).container_config = (0..257).map(entry).collect()),
        w,
    );
    let kv = |k: String, v: String| vec![pb::ConfigEntry { key: k, value: v }];
    edge(
        backup_job_with(|b| manifest_of(b).container_config = kv(s(128), s(1024))),
        backup_job_with(|b| manifest_of(b).container_config = kv(s(129), String::new())),
        w,
    );
    bad(
        &backup_job_with(|b| manifest_of(b).container_config = kv("k".into(), s(1025))),
        w,
    );
    bad(
        &backup_job_with(|b| {
            manifest_of(b).container_config = kv("volatile.eth0.hwaddr".into(), "x".into())
        }),
        w,
    );
    // Docker mode must be a real one.
    bad(&backup_job_with(|b| b.docker_mode = 0), w);
    bad(&backup_job_with(|b| b.docker_mode = 9), w);
}

#[test]
fn other_job_specs() {
    let w = Endpoint::Worker;
    let with = |kind, f: &dyn Fn(&mut pb::job::Spec)| {
        let mut j = job(kind);
        f(j.spec.as_mut().unwrap());
        frame(F::Job(j))
    };
    // FORGET_PRUNE: at most 4096 ids, 32 bytes, non-zero, unique, instant.
    let forget = |n: usize| {
        with(JobKind::ForgetPrune, &|s| {
            let pb::job::Spec::ForgetPrune(f) = s else {
                unreachable!()
            };
            f.forget = (0..n as u32)
                .map(|i| Bytes::from([&i.to_le_bytes()[..], &[1u8; 28]].concat()))
                .collect();
        })
    };
    edge(forget(4096), forget(4097), w);
    ok(&forget(0), w);
    bad(
        &with(JobKind::ForgetPrune, &|s| {
            let pb::job::Spec::ForgetPrune(f) = s else {
                unreachable!()
            };
            f.forget = vec![id(1), id(1)];
        }),
        w,
    );
    bad(
        &with(JobKind::ForgetPrune, &|s| {
            let pb::job::Spec::ForgetPrune(f) = s else {
                unreachable!()
            };
            f.forget = vec![Bytes::from(vec![1u8; 31])];
        }),
        w,
    );
    bad(
        &with(JobKind::ForgetPrune, &|s| {
            let pb::job::Spec::ForgetPrune(f) = s else {
                unreachable!()
            };
            f.forget = vec![Bytes::from(vec![0u8; 32])];
        }),
        w,
    );
    bad(
        &with(JobKind::ForgetPrune, &|s| {
            let pb::job::Spec::ForgetPrune(f) = s else {
                unreachable!()
            };
            f.instant = false;
        }),
        w,
    );
    // KEYS: at most 4 removals.
    let keys = |n: u8| {
        with(JobKind::Keys, &|s| {
            let pb::job::Spec::Keys(k) = s else {
                unreachable!()
            };
            k.remove_key_ids = (1..=n).map(id).collect();
        })
    };
    edge(keys(4), keys(5), w);
    // CHECK: 0 to 100.
    let check = |p: u32| {
        with(JobKind::Check, &|s| {
            let pb::job::Spec::Check(c) = s else {
                unreachable!()
            };
            c.read_data_percent = p;
        })
    };
    edge(check(100), check(101), w);
    ok(&check(0), w);
    // INIT constants.
    for f in [
        |i: &mut pb::InitSpec| i.compression = 4,
        |i: &mut pb::InitSpec| i.datapack_size_limit += 1,
        |i: &mut pb::InitSpec| i.treepack_size_limit -= 1,
    ] {
        bad(
            &with(JobKind::Init, &|s| {
                let pb::job::Spec::Init(i) = s else {
                    unreachable!()
                };
                f(i);
            }),
            w,
        );
    }
    // Snapshot ids: 32 bytes, non-zero.
    for kind in [JobKind::RestorePlan, JobKind::Restore] {
        for badid in [
            Bytes::new(),
            Bytes::from(vec![1u8; 31]),
            Bytes::from(vec![1u8; 33]),
            Bytes::from(vec![0u8; 32]),
        ] {
            bad(
                &with(kind, &|s| match s {
                    pb::job::Spec::RestorePlan(r) => r.snapshot_id = badid.clone(),
                    pb::job::Spec::Restore(r) => r.snapshot_id = badid.clone(),
                    _ => unreachable!(),
                }),
                w,
            );
        }
    }
}

#[test]
fn job_identity_kind_spec_and_secret_slots() {
    let w = Endpoint::Worker;
    for k in KINDS {
        ok(&job_frame(k), w);
    }
    // job_id: 16 bytes, non-zero.
    for badid in [
        Bytes::new(),
        Bytes::from(vec![1u8; 15]),
        Bytes::from(vec![1u8; 17]),
        Bytes::from(vec![0u8; 16]),
    ] {
        bad(
            &frame(F::Job(pb::Job {
                job_id: badid.clone(),
                ..job(JobKind::Check)
            })),
            w,
        );
        bad(
            &frame(F::Hello(pb::Hello {
                major: 1,
                minor: 0,
                job_id: badid,
            })),
            w,
        );
    }
    // kind unspecified / unknown / mismatched with the spec.
    for kind in [0, 99] {
        bad(
            &frame(F::Job(pb::Job {
                kind,
                ..job(JobKind::Check)
            })),
            w,
        );
    }
    bad(
        &frame(F::Job(pb::Job {
            kind: JobKind::Backup as i32,
            ..job(JobKind::Check)
        })),
        w,
    );
    // Slots: declared exactly as the kind needs.
    for k in KINDS {
        let mut j = job(k);
        j.secret_slots.clear();
        bad(&frame(F::Job(j)), w);
        let mut j = job(k);
        j.secret_slots.push(j.secret_slots[0]);
        bad(&frame(F::Job(j)), w);
        let mut j = job(k);
        j.secret_slots[0].length = 15;
        bad(&frame(F::Job(j)), w);
        let mut j = job(k);
        j.secret_slots[0].length = 16;
        ok(&frame(F::Job(j)), w);
        let mut j = job(k);
        j.secret_slots[0].length = 1024;
        ok(&frame(F::Job(j)), w);
        let mut j = job(k);
        j.secret_slots[0].length = 1025;
        bad(&frame(F::Job(j)), w);
        let mut j = job(k);
        j.secret_slots[0].slot = 1;
        bad(&frame(F::Job(j)), w);
        let mut j = job(k);
        j.secret_slots[0].kind = pb::SecretKind::NewKeyPassword as i32;
        bad(&frame(F::Job(j)), w);
        let mut j = job(k);
        j.secret_slots[0].kind = 0;
        bad(&frame(F::Job(j)), w);
    }
    // KEYS without `add` declares slot 0 only; with it, 0 and 1. INIT always 0 and 1.
    let mut j = job(JobKind::Keys);
    let Some(pb::job::Spec::Keys(k)) = &mut j.spec else {
        unreachable!()
    };
    k.add = false;
    bad(&frame(F::Job(j.clone())), w);
    j.secret_slots = secret_slots(JobKind::Keys, false);
    ok(&frame(F::Job(j)), w);
    let mut j = job(JobKind::Init);
    j.secret_slots.truncate(1);
    bad(&frame(F::Job(j)), w);
}

#[test]
fn secret_slot_counts_are_bounded_on_the_wire_and_in_validation() {
    // Three slots: the pre-scan refuses it before decoding, validation would anyway.
    let mut j = job(JobKind::Init);
    j.secret_slots.push(j.secret_slots[0]);
    let f = frame(F::Job(j));
    assert!(validate_frame(&f, Endpoint::Worker).is_err());
    assert!(repo::decode(message_raw_frame(&f), Endpoint::Worker).is_err());
}

fn ids_of_every_request_op(make: impl Fn(ObjectType, Bytes) -> Op, what: &str, e: Endpoint) {
    for ty in TYPES {
        let good = oid(ty, 9);
        ok(&req(1, make(ty, good.clone())), e);
        for len in [0usize, 31, 33] {
            bad(&req(1, make(ty, Bytes::from(vec![9u8; len]))), e);
        }
        // CONFIG is all zero, everything else is not.
        let wrong = if ty == ObjectType::Config {
            id(9)
        } else {
            Bytes::from(vec![0u8; 32])
        };
        assert!(
            validate_frame(&req(1, make(ty, wrong)), e).is_err(),
            "{what} {ty:?}: the id rule"
        );
    }
    for ty in [0, 6, 99] {
        let op = make(ObjectType::Pack, id(1));
        let op = match op {
            Op::ReadFull(mut x) => {
                x.object_type = ty;
                Op::ReadFull(x)
            }
            Op::ReadPartial(mut x) => {
                x.object_type = ty;
                Op::ReadPartial(x)
            }
            Op::Write(mut x) => {
                x.object_type = ty;
                Op::Write(x)
            }
            Op::Remove(mut x) => {
                x.object_type = ty;
                Op::Remove(x)
            }
            _ => unreachable!(),
        };
        bad(&req(1, op), e);
    }
}

#[test]
fn request_fields() {
    for e in [Endpoint::PrivdWorkerLink, Endpoint::DriveHelper] {
        ids_of_every_request_op(
            |ty, id| {
                Op::ReadFull(pb::ReadFull {
                    object_type: ty as i32,
                    id,
                })
            },
            "read_full",
            e,
        );
        ids_of_every_request_op(
            |ty, id| {
                Op::ReadPartial(pb::ReadPartial {
                    object_type: ty as i32,
                    id,
                    offset: 0,
                    length: 10,
                })
            },
            "read_partial",
            e,
        );
        ids_of_every_request_op(
            |ty, id| {
                Op::Write(pb::Write {
                    object_type: ty as i32,
                    id,
                    size: 10,
                })
            },
            "write",
            e,
        );
        ids_of_every_request_op(
            |ty, id| {
                Op::Remove(pb::Remove {
                    object_type: ty as i32,
                    id,
                })
            },
            "remove",
            e,
        );
        // req_id is never zero.
        bad(&req(0, list(ObjectType::Pack)), e);
        ok(&req(u64::MAX, list(ObjectType::Pack)), e);
        // List needs a real type.
        for ty in [0, 6] {
            bad(&req(1, Op::List(pb::List { object_type: ty })), e);
        }
        // Write caps per type, at N and N+1.
        for (ty, cap) in [
            (ObjectType::Config, 64 << 10),
            (ObjectType::Key, 64 << 10),
            (ObjectType::Snapshot, 4 << 20),
            (ObjectType::Index, 96 << 20),
            (ObjectType::Pack, 96 << 20),
        ] {
            edge(req(1, write(ty, 1, cap)), req(1, write(ty, 1, cap + 1)), e);
            ok(&req(1, write(ty, 1, 0)), e);
        }
        // ReadPartial: length at least 1, the range inside the type's cap.
        edge(
            req(1, read_partial(ObjectType::Pack, 1, 0, 96 << 20)),
            req(1, read_partial(ObjectType::Pack, 1, 1, 96 << 20)),
            e,
        );
        edge(
            req(1, read_partial(ObjectType::Pack, 1, (96 << 20) - 5, 5)),
            req(1, read_partial(ObjectType::Pack, 1, (96 << 20) - 5, 6)),
            e,
        );
        bad(&req(1, read_partial(ObjectType::Pack, 1, 0, 0)), e);
        bad(
            &req(1, read_partial(ObjectType::Pack, 1, u32::MAX, u32::MAX)),
            e,
        );
        edge(
            req(1, read_partial(ObjectType::Snapshot, 1, 0, 4 << 20)),
            req(1, read_partial(ObjectType::Snapshot, 1, 0, (4 << 20) + 1)),
            e,
        );
    }
}

#[test]
fn drive_only_operations() {
    let d = Endpoint::DriveHelper;
    let open = |f: &dyn Fn(&mut pb::OpenRepo)| {
        let Op::OpenRepo(mut o) = open_repo() else {
            unreachable!()
        };
        f(&mut o);
        req(1, Op::OpenRepo(o))
    };
    ok(&open(&|_| {}), d);
    edge(
        open(&|o| o.folder = s(128)),
        open(&|o| o.folder = s(129)),
        d,
    );
    for badname in ["", ".hidden", "-x", "a b", "a/b", "a\0b", "é"] {
        bad(&open(&|o| o.folder = badname.into()), d);
    }
    for len in [0usize, 15, 17] {
        bad(&open(&|o| o.server_id = Bytes::from(vec![9u8; len])), d);
    }
    bad(&open(&|o| o.server_id = Bytes::from(vec![0u8; 16])), d);
    for e in [
        Endpoint::PrivdWorkerLink,
        Endpoint::Worker,
        Endpoint::PrivdDriveLink,
    ] {
        bad(&open(&|_| {}), e);
    }
    bad(&req(1, Op::Quota(pb::Quota {})), Endpoint::PrivdWorkerLink);
    ok(
        &req(1, Op::SetUploadRate(pb::SetUploadRate { bytes_per_s: 0 })),
        d,
    );
    bad(&frame(F::CancelRequest(pb::CancelRequest { req_id: 0 })), d);
    ok(&frame(F::CancelRequest(pb::CancelRequest { req_id: 1 })), d);
    for kind in [0, 4, 99] {
        bad(
            &frame(F::Event(pb::Event { kind, until_ms: 0 })),
            Endpoint::PrivdDriveLink,
        );
    }
}

#[test]
fn responses() {
    for e in [Endpoint::Worker, Endpoint::PrivdDriveLink] {
        bad(&resp(0, repo_common::page(ObjectType::Pack, 1, true)), e);
        edge(
            resp(1, page(ObjectType::Pack, 1024, false)),
            resp(1, page(ObjectType::Pack, 1025, false)),
            e,
        );
        bad(
            &resp(
                1,
                pb::repo_response::Result::ListPage(pb::ListPage {
                    entries: vec![pb::ListEntry {
                        id: Bytes::from(vec![1u8; 31]),
                        size: 1,
                    }],
                    last: true,
                }),
            ),
            e,
        );
        edge(
            resp(1, read_begin(96 << 20)),
            resp(1, read_begin((96 << 20) + 1)),
            e,
        );
        for class in [0, 15, 99] {
            bad(
                &resp(
                    1,
                    pb::repo_response::Result::Error(pb::RepoError {
                        class,
                        retry_after_ms: 0,
                    }),
                ),
                e,
            );
        }
    }
    // The Drive helper may not claim privd's own verdicts; privd may tell them to the worker.
    use pb::ErrorClass as C;
    for c in [C::PolicyDenied, C::Integrity, C::TooLarge, C::Unavailable] {
        ok(&error(1, c), Endpoint::Worker);
        bad(&error(1, c), Endpoint::PrivdDriveLink);
    }
    for c in [
        C::NotFound,
        C::Transient,
        C::RateLimited,
        C::DailyLimit,
        C::QuotaExceeded,
        C::AuthRevoked,
        C::Permission,
        C::LeaseHeld,
        C::Cancelled,
        C::Internal,
    ] {
        ok(&error(1, c), Endpoint::PrivdDriveLink);
        ok(&error(1, c), Endpoint::Worker);
    }
}

#[test]
fn hello_ack_progress_and_event() {
    let ack_with = |s: &str| {
        frame(F::HelloAck(pb::HelloAck {
            major: 1,
            minor: 0,
            software: s.into(),
        }))
    };
    for e in [Endpoint::PrivdWorkerLink, Endpoint::PrivdDriveLink] {
        edge(ack_with(&s(64)), ack_with(&s(65)), e);
        ok(&ack_with("hx-backup-worker_0.1.0+build.5"), e);
        bad(&ack_with(""), e);
        for text in [
            "evil\u{1b}[2J",
            "a\nb",
            "has space",
            "caf\u{e9}",
            "a\u{200b}b",
            "x/y",
        ] {
            bad(&ack_with(text), e);
        }
    }
    let prog = |phase| {
        frame(F::Progress(pb::Progress {
            phase,
            files_done: u64::MAX,
            files_total: 0,
            bytes_done: u64::MAX,
            bytes_total: u64::MAX,
        }))
    };
    ok(&prog(1), Endpoint::PrivdWorkerLink);
    ok(&prog(11), Endpoint::PrivdWorkerLink);
    for p in [0, 12, 99] {
        bad(&prog(p), Endpoint::PrivdWorkerLink);
    }
}

#[test]
fn job_result_rules() {
    let p = Endpoint::PrivdWorkerLink;
    let with = |f: &dyn Fn(&mut pb::JobResult)| {
        let mut r = result_for(JobKind::Backup);
        f(&mut r);
        result_frame(r)
    };
    ok(&with(&|_| {}), p);
    // ok and error agree.
    bad(&with(&|r| r.error = pb::WorkerError::Engine as i32), p);
    let failed = |f: &dyn Fn(&mut pb::JobResult)| {
        let mut r = pb::JobResult {
            ok: false,
            error: pb::WorkerError::Engine as i32,
            ..Default::default()
        };
        f(&mut r);
        result_frame(r)
    };
    ok(&failed(&|r| r.files_new = 3), p);
    for e in [0, 10, 99] {
        bad(&failed(&|r| r.error = e), p);
    }
    for e in 1..=9 {
        ok(&failed(&|r| r.error = e), p);
    }
    bad(&failed(&|r| r.snapshot_id = id(1)), p);
    bad(&failed(&|r| r.key_ids = vec![id(1)]), p);
    bad(&failed(&|r| r.manifest = Bytes::from_static(b"{}")), p);
    bad(&failed(&|r| r.snapshots = vec![snapshot_info(1)]), p);
    // ids, key_ids at N and N+1.
    bad(&with(&|r| r.snapshot_id = Bytes::from(vec![1u8; 31])), p);
    bad(&with(&|r| r.snapshot_id = Bytes::from(vec![0u8; 32])), p);
    let keys = |n: u8| {
        with(&|r| {
            r.snapshot_id = Bytes::new();
            r.key_ids = (1..=n).map(id).collect()
        })
    };
    edge(keys(4), keys(5), p);
    // manifest.
    let manifest = |n: usize| {
        with(&|r| {
            r.snapshot_id = Bytes::new();
            r.manifest = Bytes::from(vec![b'x'; n])
        })
    };
    edge(manifest(61_440), manifest(61_441), p);
    // snapshots: count and entry rules.
    let snaps = |n: usize| {
        with(&|r| {
            r.snapshot_id = Bytes::new();
            r.snapshots = (0..n as u32)
                .map(|i| pb::SnapshotInfo {
                    id: Bytes::from([&i.to_le_bytes()[..], &[1u8; 28]].concat()),
                    ..snapshot_info(1)
                })
                .collect();
        })
    };
    edge(snaps(4096), snaps(4097), p);
    let snap = |f: &dyn Fn(&mut pb::SnapshotInfo)| {
        with(&|r| {
            r.snapshot_id = Bytes::new();
            let mut s = snapshot_info(1);
            f(&mut s);
            r.snapshots = vec![s];
        })
    };
    ok(&snap(&|_| {}), p);
    ok(
        &snap(&|s| s.manifest_digest = Bytes::from(vec![0u8; 32])),
        p,
    );
    bad(&snap(&|s| s.manifest_digest = Bytes::new()), p);
    bad(&snap(&|s| s.id = Bytes::from(vec![0u8; 32])), p);
    bad(&snap(&|s| s.time = -1), p);
    edge(
        snap(&|s| s.tags = vec!["a".into(); 4]),
        snap(&|s| s.tags = vec!["a".into(); 5]),
        p,
    );
    edge(
        snap(&|s| s.tags = vec![s_len(64)]),
        snap(&|s| s.tags = vec![s_len(65)]),
        p,
    );
    bad(&snap(&|s| s.tags = vec!["free text".into()]), p);
    bad(&snap(&|s| s.tags = vec!["tag\u{1b}".into()]), p);
}

fn s_len(n: usize) -> String {
    "t".repeat(n)
}

#[test]
fn job_result_shape_follows_the_job_kind() {
    use repo::check_result_shape as shape;
    for kind in KINDS {
        assert!(shape(kind, &result_for(kind)).is_ok(), "{kind:?}");
        // Every kind's success result is wrong for each other kind that cares.
        for other in KINDS {
            if other == kind {
                continue;
            }
            let r = result_for(other);
            let empty = r.snapshot_id.is_empty()
                && r.manifest.is_empty()
                && r.snapshots.is_empty()
                && r.key_ids.is_empty();
            if !empty
                && !(kind == JobKind::Keys && other == JobKind::Init)
                && !(kind == JobKind::Init && other == JobKind::Keys)
            {
                assert!(
                    shape(kind, &r).is_err(),
                    "{other:?} result for a {kind:?} job"
                );
            }
        }
    }
    // A successful BACKUP needs its snapshot; a successful RESTORE_PLAN its manifest.
    assert!(shape(JobKind::Backup, &ok_result()).is_err());
    assert!(shape(JobKind::RestorePlan, &ok_result()).is_err());
    // A failed job carries nothing.
    let failed = pb::JobResult {
        ok: false,
        error: 1,
        ..Default::default()
    };
    for kind in KINDS {
        assert!(shape(kind, &failed).is_ok(), "{kind:?}");
    }
}

// ----- secrets -----

#[test]
fn secret_frames() {
    let secret = vec![0xA5u8; 32];
    let wire = encode_secret(0, 1, &secret).unwrap();
    assert_eq!(&wire[..4], &(1u32 + 9 + 32).to_le_bytes());
    assert_eq!(wire[4], 2);
    let Incoming::Secret(f) = through_decoder(&wire, Endpoint::Worker, 5).unwrap() else {
        panic!("not a secret")
    };
    assert_eq!((f.request_id, f.slot), (0, 1));
    assert!(f.secret.ct_eq(&secret));
    assert!(
        !format!("{f:?}").contains("165"),
        "Debug never shows secret bytes"
    );

    // Length 16 to 1024, slot 0 or 1, request id 0.
    assert!(encode_secret(0, 0, &[1; 15]).is_err());
    assert!(encode_secret(0, 0, &[1; 16]).is_ok());
    assert!(encode_secret(0, 0, &[1; 1024]).is_ok());
    assert!(encode_secret(0, 0, &[1; 1025]).is_err());
    assert!(encode_secret(0, 0, &[]).is_err());
    assert!(encode_secret(0, 1, &[1; 16]).is_ok());
    assert!(encode_secret(0, 2, &[1; 16]).is_err());
    assert!(encode_secret(1, 0, &[1; 16]).is_err());

    // A hostile frame with the same defects is refused at decode.
    let hand = |request_id: u64, slot: u8, n: usize| {
        let mut body = request_id.to_le_bytes().to_vec();
        body.push(slot);
        body.extend(vec![1u8; n]);
        encode_frame(repo::KIND_SECRET, &body, 8_192).unwrap()
    };
    assert!(through_decoder(&hand(0, 0, 16), Endpoint::Worker, 64).is_ok());
    for (id, slot, n) in [(0, 0, 15), (0, 0, 1025), (0, 2, 16), (1, 0, 16), (0, 0, 0)] {
        assert!(
            through_decoder(&hand(id, slot, n), Endpoint::Worker, 64).is_err(),
            "{id} {slot} {n}"
        );
    }
    // Nobody but the worker takes a secret frame.
    for e in [
        Endpoint::PrivdWorkerLink,
        Endpoint::PrivdDriveLink,
        Endpoint::DriveHelper,
    ] {
        assert_eq!(
            through_decoder(&hand(0, 0, 16), e, 64).unwrap_err(),
            FrameError::KindNotAllowed(2)
        );
        let raw = RawFrame {
            kind: 2,
            body: BytesMut::from(&[0u8; 30][..]),
        };
        assert!(repo::decode(raw, e).is_err());
    }
}

// ----- data frames -----

#[test]
fn data_frame_codec() {
    let payload = vec![0x42u8; 1000];
    let wire = encode_data(77, false, &payload).unwrap();
    assert_eq!(wire.len(), 14 + 1000);
    assert_eq!(&wire[..4], &(1u32 + 9 + 1000).to_le_bytes());
    assert_eq!(wire[4], 3);
    assert_eq!(&wire[5..13], &77u64.to_le_bytes());
    assert_eq!(wire[13], 0);
    for e in ALL {
        let Incoming::Data(d) = through_decoder(&wire, e, 333).unwrap() else {
            panic!()
        };
        assert_eq!(
            (d.stream_id, d.end, d.payload.as_ref()),
            (77, false, &payload[..])
        );
    }
    // END, and an empty payload.
    let wire = encode_data(u64::MAX, true, &[]).unwrap();
    let Incoming::Data(d) = through_decoder(&wire, Endpoint::DriveHelper, 4096).unwrap() else {
        panic!()
    };
    assert_eq!((d.stream_id, d.end, d.payload.len()), (u64::MAX, true, 0));
    assert!(
        !format!("{d:?}").contains("payload:"),
        "Debug shows the length only"
    );

    // The header alone is what a vectored writer sends before the payload.
    let h = encode_data_header(5, true, 10).unwrap();
    assert_eq!(h.len(), 14);
    assert_eq!(h[..], encode_data(5, true, &[0; 10]).unwrap()[..14]);
}

#[test]
fn data_frame_limits_and_rules() {
    // Payload at 1 MiB and one over.
    assert!(encode_data_header(1, false, 1_048_576).is_ok());
    assert!(matches!(
        encode_data_header(1, false, 1_048_577),
        Err(FrameError::TooLong { max: 1_048_586, .. })
    ));
    assert!(
        encode_data_header(0, false, 1).is_err(),
        "stream 0 does not exist"
    );
    let big = encode_data(1, false, &vec![0u8; 1_048_576]).unwrap();
    assert_eq!(big.len(), 4 + 1_048_586);
    assert!(through_decoder(&big, Endpoint::PrivdWorkerLink, 1 << 20).is_ok());
    // A hand-built frame one byte over is refused by the decoder before any body is read.
    let over = [prefix(1_048_587, 3), vec![0u8; 20]].concat();
    assert!(matches!(
        through_decoder(&over, Endpoint::DriveHelper, 64),
        Err(FrameError::TooLong { .. })
    ));
    // Flags: only bit 0.
    let hand = |stream: u64, flags: u8, n: usize| {
        let mut body = stream.to_le_bytes().to_vec();
        body.push(flags);
        body.extend(vec![1u8; n]);
        encode_frame(repo::KIND_DATA, &body, 1_048_586).unwrap()
    };
    assert!(through_decoder(&hand(1, 0, 4), Endpoint::Worker, 64).is_ok());
    assert!(through_decoder(&hand(1, 1, 4), Endpoint::Worker, 64).is_ok());
    for flags in [2u8, 3, 0x80, 0xFF] {
        assert!(
            through_decoder(&hand(1, flags, 4), Endpoint::Worker, 64).is_err(),
            "flags {flags:#x}"
        );
    }
    assert!(through_decoder(&hand(0, 0, 4), Endpoint::Worker, 64).is_err());
    // A body shorter than the header.
    for n in 0..9 {
        let raw = RawFrame {
            kind: 3,
            body: BytesMut::from(&vec![1u8; n][..]),
        };
        assert!(repo::decode(raw, Endpoint::Worker).is_err(), "{n}");
    }
}

#[test]
fn a_data_payload_is_the_decoders_own_buffer() {
    let payload = vec![0x42u8; 4096];
    let wire = encode_data(9, false, &payload).unwrap();
    let mut d = Decoder::new(RepoFramePolicy::new(Endpoint::PrivdWorkerLink));
    let raw = d.read_from(&mut &wire[..]).unwrap().unwrap();
    let base = raw.body.as_ptr();
    let frame = DataFrame::from_body(raw.body).unwrap();
    assert_eq!(
        frame.payload.as_ptr(),
        base.wrapping_add(9),
        "split, not copied"
    );
    assert_eq!(frame.payload.as_ref(), &payload[..]);
}

// ----- properties -----

fn arb_frame() -> impl Strategy<Value = (pb::RepoFrame, Vec<Endpoint>)> {
    let n = every_frame().len();
    (0..n, any::<u64>(), 0usize..300, any::<u32>()).prop_map(|(i, nonce, count, size)| {
        let (_, mut f, to) = every_frame().swap_remove(i);
        let req_id = nonce.max(1);
        match &mut f.frame {
            Some(F::Request(r)) => r.req_id = req_id,
            Some(F::Response(r)) => {
                r.req_id = req_id;
                if let Some(pb::repo_response::Result::ListPage(p)) = &mut r.result {
                    *p = match page(ObjectType::Index, count % 200, count % 2 == 0) {
                        pb::repo_response::Result::ListPage(p) => p,
                        _ => unreachable!(),
                    };
                }
                if let Some(pb::repo_response::Result::ReadBegin(b)) = &mut r.result {
                    b.size = size % (96 << 20);
                }
            }
            Some(F::Ping(p)) => p.nonce = nonce,
            Some(F::Pong(p)) => p.nonce = nonce,
            Some(F::CancelRequest(c)) => c.req_id = req_id,
            Some(F::Event(e)) => e.until_ms = nonce,
            Some(F::Progress(p)) => {
                p.files_done = nonce;
                p.bytes_total = u64::from(size);
            }
            Some(F::Result(r)) => {
                r.files_new = nonce;
                r.bytes_added = u64::from(size);
            }
            _ => {}
        }
        (f, to)
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// encode then decode is the identity for every valid frame, whatever the chunking.
    #[test]
    fn encode_decode_is_identity((f, to) in arb_frame(), chunk in 1usize..2000) {
        for e in to {
            let wire = encode_message(&f, e).unwrap();
            match through_decoder(&wire, e, chunk) {
                Ok(Incoming::Message(back)) => prop_assert_eq!(&back, &f),
                other => prop_assert!(false, "{:?}", other),
            }
        }
    }

    /// Data frames: identity, and the header function agrees with the whole-frame encoder.
    #[test]
    fn data_frames_round_trip(stream in 1u64.., end: bool, payload in proptest::collection::vec(any::<u8>(), 0..3000)) {
        let wire = encode_data(stream, end, &payload).unwrap();
        prop_assert_eq!(&encode_data_header(stream, end, payload.len()).unwrap()[..], &wire[..14]);
        match through_decoder(&wire, Endpoint::PrivdDriveLink, 1000) {
            Ok(Incoming::Data(d)) => {
                prop_assert_eq!(d.stream_id, stream);
                prop_assert_eq!(d.end, end);
                prop_assert_eq!(d.payload.as_ref(), &payload[..]);
            }
            other => prop_assert!(false, "{:?}", other),
        }
    }

    /// Arbitrary bytes never panic, at any endpoint, whatever the chunking; whatever decodes is
    /// valid there and re-encodes.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..400), chunk in 1usize..64, which in 0usize..4) {
        let e = ALL[which];
        let mut d = Decoder::new(RepoFramePolicy::new(e));
        let mut rest = &bytes[..];
        'outer: while !rest.is_empty() {
            let take = rest.len().min(chunk);
            let mut piece = &rest[..take];
            while !piece.is_empty() {
                match d.feed(piece) {
                    Ok((used, frame)) => {
                        piece = &piece[used..];
                        if let Some(raw) = frame
                            && let Ok(Incoming::Message(m)) = repo::decode(raw, e)
                        {
                            prop_assert!(validate_frame(&m, e).is_ok());
                            prop_assert!(encode_message(&m, e).is_ok());
                        }
                    }
                    Err(_) => break 'outer,
                }
            }
            rest = &rest[take..];
        }
    }

    /// Arbitrary protobuf bodies (not just framed bytes) never panic the decode path.
    #[test]
    fn arbitrary_message_bodies_never_panic(body in proptest::collection::vec(any::<u8>(), 0..2000), kind in 0u8..5, which in 0usize..4) {
        let raw = RawFrame { kind, body: BytesMut::from(&body[..]) };
        let _ = repo::decode(raw, ALL[which]);
    }
}

// ----- review additions -----

#[test]
fn retry_after_is_at_most_a_day_and_text_rules_refuse_format_characters() {
    let err = |ms: u32| {
        resp(
            1,
            pb::repo_response::Result::Error(pb::RepoError {
                class: pb::ErrorClass::RateLimited as i32,
                retry_after_ms: ms,
            }),
        )
    };
    for e in [Endpoint::Worker, Endpoint::PrivdDriveLink] {
        edge(err(86_400_000), err(86_400_001), e);
    }
    // Event.until_ms stays unbounded in the codec (privd clamps it).
    ok(
        &frame(F::Event(pb::Event {
            kind: 1,
            until_ms: u64::MAX,
        })),
        Endpoint::PrivdDriveLink,
    );
    // Cf and Zl characters are refused in the manifest text and in excludes.
    let w = Endpoint::Worker;
    for bad_text in ["a\u{200b}b", "a\u{2028}b", "a\u{202e}b", "a\u{feff}"] {
        bad(
            &backup_job_with(|b| {
                manifest_of(b).distro.as_mut().unwrap().pretty_name = bad_text.into()
            }),
            w,
        );
        bad(&backup_job_with(|b| b.excludes = vec![bad_text.into()]), w);
    }
    // KEYS: removals must not repeat an id.
    let keys = |ids: Vec<Bytes>| {
        let mut j = job(JobKind::Keys);
        let Some(pb::job::Spec::Keys(k)) = &mut j.spec else {
            unreachable!()
        };
        k.remove_key_ids = ids;
        frame(F::Job(j))
    };
    ok(&keys(vec![id(1), id(2)]), w);
    bad(&keys(vec![id(1), id(1)]), w);
}

#[test]
fn a_variant_that_may_not_travel_here_is_refused_before_decoding() {
    // The pre-scan reads only the top-level field number: a Job towards privd is refused even
    // when its body is garbage that would not decode.
    for (field_number, refused_at) in [
        (
            3u8,
            vec![
                Endpoint::PrivdWorkerLink,
                Endpoint::PrivdDriveLink,
                Endpoint::DriveHelper,
            ],
        ),
        (4, vec![Endpoint::Worker, Endpoint::PrivdDriveLink]),
        (
            6,
            vec![
                Endpoint::Worker,
                Endpoint::PrivdDriveLink,
                Endpoint::DriveHelper,
            ],
        ),
        (
            12,
            vec![
                Endpoint::Worker,
                Endpoint::PrivdWorkerLink,
                Endpoint::PrivdDriveLink,
            ],
        ),
        (
            13,
            vec![
                Endpoint::Worker,
                Endpoint::PrivdWorkerLink,
                Endpoint::DriveHelper,
            ],
        ),
    ] {
        let body = [(field_number << 3) | 2, 3, 0xFF, 0xFF, 0xFF];
        for e in refused_at {
            let raw = RawFrame {
                kind: 1,
                body: BytesMut::from(&body[..]),
            };
            let err = repo::decode(raw, e).unwrap_err();
            assert!(
                matches!(&err, FrameError::Invalid(m) if m.contains("direction")),
                "field {field_number} at {e:?}: {err:?}"
            );
        }
    }
}
