//! Builders shared by the repository-link tests: one valid instance of every message of
//! `docs/ipc.md` sections 27 to 29.
#![allow(dead_code)] // each test binary uses a different subset

use bytes::Bytes;
use hx_ipc::repo::Endpoint::{self, DriveHelper, PrivdDriveLink, PrivdWorkerLink, Worker};
use hx_ipc::repo::pb::{
    self, JobKind, ObjectType, repo_frame::Frame as F, repo_request::Op,
    repo_response::Result as Res,
};

pub const ALL: [Endpoint; 4] = [Worker, PrivdWorkerLink, PrivdDriveLink, DriveHelper];

pub fn id(b: u8) -> Bytes {
    Bytes::from(vec![b; 32])
}

pub fn job_id() -> Bytes {
    Bytes::from(vec![7u8; 16])
}

pub fn frame(f: F) -> pb::RepoFrame {
    pb::RepoFrame { frame: Some(f) }
}

pub fn hello() -> pb::RepoFrame {
    frame(F::Hello(pb::Hello {
        major: 1,
        minor: 0,
        job_id: job_id(),
    }))
}

pub fn ack() -> pb::RepoFrame {
    frame(F::HelloAck(pb::HelloAck {
        major: 1,
        minor: 0,
        software: "hx-backup-worker-0.1.0".into(),
    }))
}

pub fn req(req_id: u64, op: Op) -> pb::RepoFrame {
    frame(F::Request(pb::RepoRequest {
        req_id,
        op: Some(op),
    }))
}

pub fn resp(req_id: u64, r: Res) -> pb::RepoFrame {
    frame(F::Response(pb::RepoResponse {
        req_id,
        result: Some(r),
    }))
}

pub fn done(req_id: u64) -> pb::RepoFrame {
    resp(req_id, Res::Done(pb::Done {}))
}

pub fn error(req_id: u64, class: pb::ErrorClass) -> pb::RepoFrame {
    resp(
        req_id,
        Res::Error(pb::RepoError {
            class: class as i32,
            retry_after_ms: 0,
        }),
    )
}

pub fn list(ty: ObjectType) -> Op {
    Op::List(pb::List {
        object_type: ty as i32,
    })
}

pub fn read_full(ty: ObjectType, b: u8) -> Op {
    Op::ReadFull(pb::ReadFull {
        object_type: ty as i32,
        id: oid(ty, b),
    })
}

pub fn read_partial(ty: ObjectType, b: u8, offset: u32, length: u32) -> Op {
    Op::ReadPartial(pb::ReadPartial {
        object_type: ty as i32,
        id: oid(ty, b),
        offset,
        length,
    })
}

pub fn write(ty: ObjectType, b: u8, size: u32) -> Op {
    Op::Write(pb::Write {
        object_type: ty as i32,
        id: oid(ty, b),
        size,
    })
}

pub fn remove(ty: ObjectType, b: u8) -> Op {
    Op::Remove(pb::Remove {
        object_type: ty as i32,
        id: oid(ty, b),
    })
}

/// The id of an object of `ty`: all zero for `CONFIG`, `b` repeated otherwise.
pub fn oid(ty: ObjectType, b: u8) -> Bytes {
    if ty == ObjectType::Config {
        Bytes::from(vec![0u8; 32])
    } else {
        id(b)
    }
}

pub fn open_repo() -> Op {
    Op::OpenRepo(pb::OpenRepo {
        folder: "hx-backup-0a1b2c3d-main".into(),
        create: true,
        server_id: Bytes::from(vec![9u8; 16]),
        takeover: false,
    })
}

pub fn page(ty: ObjectType, n: usize, last: bool) -> Res {
    Res::ListPage(pb::ListPage {
        entries: (0..n)
            .map(|i| pb::ListEntry {
                id: oid(ty, (i % 250) as u8 + 1),
                size: 100,
            })
            .collect(),
        last,
    })
}

pub fn read_begin(size: u32) -> Res {
    Res::ReadBegin(pb::ReadBegin { size })
}

pub fn secret_slots(kind: JobKind, add: bool) -> Vec<pb::SecretSlot> {
    let slot = |slot, kind: pb::SecretKind| pb::SecretSlot {
        slot,
        kind: kind as i32,
        length: 32,
    };
    let repo = slot(0, pb::SecretKind::RepoPassword);
    let new = slot(1, pb::SecretKind::NewKeyPassword);
    match kind {
        JobKind::Init => vec![repo, new],
        JobKind::Keys if add => vec![repo, new],
        _ => vec![repo],
    }
}

pub fn backup_spec() -> pb::BackupSpec {
    pb::BackupSpec {
        manifest: Some(pb::ManifestInput {
            agent_version: "0.1.0".into(),
            distro: Some(pb::Distro {
                id: "ubuntu".into(),
                version_id: "24.04".into(),
                pretty_name: "Ubuntu 24.04 LTS".into(),
            }),
            desktop: "xfce4".into(),
            preset: "basic".into(),
            container_config: vec![pb::ConfigEntry {
                key: "limits.cpu".into(),
                value: "2".into(),
            }],
            format_version: 1,
        }),
        excludes: vec!["/home/*/.cache".into(), "/var/tmp".into()],
        docker_mode: pb::DockerMode::Light as i32,
        tags: vec!["hx-backup-20261126T101500Z-0a1b".into(), "scheduled".into()],
        docker_enabled: true,
    }
}

/// A valid `Job` of `kind`, with its spec and the secret slots its kind declares.
pub fn job(kind: JobKind) -> pb::Job {
    use pb::job::Spec;
    let spec = match kind {
        JobKind::Init => Spec::Init(pb::InitSpec {
            compression: 3,
            datapack_size_limit: 64 << 20,
            treepack_size_limit: 16 << 20,
        }),
        JobKind::Backup => Spec::Backup(backup_spec()),
        JobKind::Snapshots => Spec::Snapshots(pb::SnapshotsSpec {}),
        JobKind::RestorePlan => Spec::RestorePlan(pb::RestorePlanSpec { snapshot_id: id(5) }),
        JobKind::Restore => Spec::Restore(pb::RestoreSpec {
            snapshot_id: id(5),
            verify_existing: true,
        }),
        JobKind::ForgetPrune => Spec::ForgetPrune(pb::ForgetPruneSpec {
            forget: vec![id(1), id(2)],
            instant: true,
        }),
        JobKind::Check => Spec::Check(pb::CheckSpec {
            read_data_percent: 10,
        }),
        JobKind::Keys => Spec::Keys(pb::KeysSpec {
            add: true,
            remove_key_ids: vec![id(3)],
        }),
        JobKind::Unspecified => unreachable!(),
    };
    let add = matches!(&spec, Spec::Keys(k) if k.add);
    pb::Job {
        job_id: job_id(),
        kind: kind as i32,
        secret_slots: secret_slots(kind, add),
        spec: Some(spec),
    }
}

pub const KINDS: [JobKind; 8] = [
    JobKind::Init,
    JobKind::Backup,
    JobKind::Snapshots,
    JobKind::RestorePlan,
    JobKind::Restore,
    JobKind::ForgetPrune,
    JobKind::Check,
    JobKind::Keys,
];

pub const TYPES: [ObjectType; 5] = [
    ObjectType::Config,
    ObjectType::Key,
    ObjectType::Snapshot,
    ObjectType::Index,
    ObjectType::Pack,
];

pub fn job_frame(kind: JobKind) -> pb::RepoFrame {
    frame(F::Job(job(kind)))
}

pub fn snapshot_info(b: u8) -> pb::SnapshotInfo {
    pb::SnapshotInfo {
        id: id(b),
        time: 1_764_000_000,
        tags: vec!["hx-backup-20261126T101500Z-0a1b".into()],
        manifest_digest: id(0xEE),
        size: 1 << 30,
    }
}

pub fn ok_result() -> pb::JobResult {
    pb::JobResult {
        ok: true,
        ..Default::default()
    }
}

pub fn result_frame(r: pb::JobResult) -> pb::RepoFrame {
    frame(F::Result(r))
}

/// One valid `JobResult` for a successful job of `kind`.
pub fn result_for(kind: JobKind) -> pb::JobResult {
    let mut r = ok_result();
    match kind {
        JobKind::Backup => {
            r.snapshot_id = id(0x11);
            r.files_new = 5;
            r.bytes_added = 9;
        }
        JobKind::Init | JobKind::Keys => r.key_ids = vec![id(0x21), id(0x22)],
        JobKind::RestorePlan => r.manifest = Bytes::from_static(b"{\"format_version\":1}"),
        JobKind::Snapshots => r.snapshots = vec![snapshot_info(1), snapshot_info(2)],
        _ => {}
    }
    r
}

/// One valid instance of every variant, request operation and response result, with the
/// endpoints it may travel to.
pub fn every_frame() -> Vec<(String, pb::RepoFrame, Vec<Endpoint>)> {
    let both = vec![PrivdWorkerLink, DriveHelper];
    let responses = vec![Worker, PrivdDriveLink];
    let mut v: Vec<(String, pb::RepoFrame, Vec<Endpoint>)> = vec![
        ("hello".into(), hello(), vec![Worker, DriveHelper]),
        (
            "hello_ack".into(),
            ack(),
            vec![PrivdWorkerLink, PrivdDriveLink],
        ),
    ];
    for k in KINDS {
        v.push((format!("job_{k:?}"), job_frame(k), vec![Worker]));
    }
    for (n, op) in [
        ("list", list(ObjectType::Pack)),
        ("read_full", read_full(ObjectType::Index, 4)),
        ("read_partial", read_partial(ObjectType::Pack, 4, 100, 200)),
        ("write", write(ObjectType::Pack, 4, 1000)),
        ("remove", remove(ObjectType::Index, 4)),
        ("create", Op::Create(pb::Create {})),
    ] {
        v.push((format!("request_{n}"), req(1, op), both.clone()));
    }
    for (n, op) in [
        ("open_repo", open_repo()),
        ("quota", Op::Quota(pb::Quota {})),
        (
            "set_upload_rate",
            Op::SetUploadRate(pb::SetUploadRate {
                bytes_per_s: 1 << 20,
            }),
        ),
    ] {
        v.push((format!("request_{n}"), req(1, op), vec![DriveHelper]));
    }
    for (n, r) in [
        ("list_page", page(ObjectType::Pack, 3, true)),
        ("read_begin", read_begin(10)),
        ("done", Res::Done(pb::Done {})),
        (
            "error",
            Res::Error(pb::RepoError {
                class: pb::ErrorClass::Transient as i32,
                retry_after_ms: 1500,
            }),
        ),
    ] {
        v.push((format!("response_{n}"), resp(1, r), responses.clone()));
    }
    v.push((
        "response_quota_result".into(),
        resp(
            1,
            Res::QuotaResult(pb::QuotaResult {
                limit: 15 << 30,
                usage: 3 << 30,
                usage_in_trash: 1 << 20,
            }),
        ),
        vec![PrivdDriveLink],
    ));
    v.push((
        "progress".into(),
        frame(F::Progress(pb::Progress {
            phase: pb::ProgressPhase::ScanAndUpload as i32,
            files_done: 1,
            files_total: 2,
            bytes_done: 3,
            bytes_total: 0,
        })),
        vec![PrivdWorkerLink],
    ));
    v.push((
        "result".into(),
        result_frame(result_for(JobKind::Backup)),
        vec![PrivdWorkerLink],
    ));
    v.push((
        "cancel".into(),
        frame(F::Cancel(pb::Cancel {})),
        vec![Worker],
    ));
    v.push((
        "ping".into(),
        frame(F::Ping(pb::Ping { nonce: 42 })),
        ALL.to_vec(),
    ));
    v.push((
        "pong".into(),
        frame(F::Pong(pb::Pong { nonce: 42 })),
        ALL.to_vec(),
    ));
    v.push(("bye".into(), frame(F::Bye(pb::Bye {})), ALL.to_vec()));
    v.push((
        "cancel_request".into(),
        frame(F::CancelRequest(pb::CancelRequest { req_id: 3 })),
        vec![DriveHelper],
    ));
    v.push((
        "event".into(),
        frame(F::Event(pb::Event {
            kind: pb::EventKind::PausedDailyLimit as i32,
            until_ms: 1_764_000_000_000,
        })),
        vec![PrivdDriveLink],
    ));
    v
}
