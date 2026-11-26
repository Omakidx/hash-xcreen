//! The harness of the `ipc_repo` fuzz target, shared with `gen-seeds` (which replays every
//! `talk_*` seed through it and insists that it is accepted to its end).
//!
//! It plays **one end of one repository link** against bytes from the fuzzer: the peer's frames
//! come from the input and go through the `Decoder`, `decode` and the `LinkState`, while the
//! harness supplies the local end's own frames through `sent_message`, `sent_secret` and
//! `sent_data`, as a real daemon would, so that the later states of the tracker are reachable:
//!
//! * a privd end sends `Hello` first and, on the worker link, the `Job` (of the kind the
//!   selector names) and its secrets as soon as the peer's `HelloAck` has been accepted;
//! * a worker or Drive helper end answers the peer's `Hello` with `HelloAck`;
//! * with `respond` set, a responder end (privd on the worker link, the Drive helper) answers
//!   every request it receives (a write once its `END` has arrived), and a requester end (the
//!   worker, privd on the Drive link) sends one new request after every frame it accepts, in the
//!   fixed order `OpenRepo` (Drive link only), then `List`, `Write` (10 bytes, sent in full with
//!   `END` at once), `ReadFull`, `Create`, repeating; request `n` has `req_id` `n`.
//!
//! Input layout of the target: `selector | chunk size | stream`; `selector & 3` is the endpoint,
//! bit 2 `respond`, bits 3 to 5 the job kind (index into [`KINDS`]).

use bytes::Bytes;
use hx_ipc::frame::{Decoder, RawFrame};
use hx_ipc::repo::{
    self, Endpoint, Incoming, LinkState, MAX_DATA_PAYLOAD, MAX_DRIVE_OUTSTANDING_REQUESTS,
    MAX_OUTSTANDING_REQUESTS, MAX_OUTSTANDING_WRITES, RepoFramePolicy, check_op, pb,
};
use repo::pb::repo_frame::Frame as F;
use repo::pb::repo_request::Op;
use repo::pb::repo_response::Result as Res;

/// The job kinds a selector can pick.
pub const KINDS: [pb::JobKind; 8] = [
    pb::JobKind::Init,
    pb::JobKind::Backup,
    pb::JobKind::Snapshots,
    pb::JobKind::RestorePlan,
    pb::JobKind::Restore,
    pb::JobKind::ForgetPrune,
    pb::JobKind::Check,
    pb::JobKind::Keys,
];

fn id(b: u8) -> Bytes {
    Bytes::from(vec![b; 32])
}

/// The job id used on both links.
pub fn job_id() -> Bytes {
    Bytes::from(vec![7u8; 16])
}

/// A valid `Job` of `kind`, with its spec and the secret slots its kind declares (32 bytes each).
pub fn job(kind: pb::JobKind) -> pb::Job {
    use pb::job::Spec;
    let spec = match kind {
        pb::JobKind::Init => Spec::Init(pb::InitSpec {
            compression: 3,
            datapack_size_limit: 64 << 20,
            treepack_size_limit: 16 << 20,
        }),
        pb::JobKind::Backup => Spec::Backup(pb::BackupSpec {
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
            excludes: vec!["/home/*/.cache".into()],
            docker_mode: pb::DockerMode::Light as i32,
            tags: vec!["hx-backup-20261126T101500Z-0a1b".into()],
        }),
        pb::JobKind::Snapshots => Spec::Snapshots(pb::SnapshotsSpec {}),
        pb::JobKind::RestorePlan => Spec::RestorePlan(pb::RestorePlanSpec { snapshot_id: id(5) }),
        pb::JobKind::Restore => Spec::Restore(pb::RestoreSpec {
            snapshot_id: id(5),
            verify_existing: false,
        }),
        pb::JobKind::ForgetPrune => Spec::ForgetPrune(pb::ForgetPruneSpec {
            forget: vec![id(1), id(2)],
            instant: true,
        }),
        pb::JobKind::Check | pb::JobKind::Unspecified => Spec::Check(pb::CheckSpec {
            read_data_percent: 5,
        }),
        pb::JobKind::Keys => Spec::Keys(pb::KeysSpec {
            add: true,
            remove_key_ids: vec![id(3)],
        }),
    };
    let two = matches!(kind, pb::JobKind::Init | pb::JobKind::Keys);
    let slot = |slot: u32| pb::SecretSlot {
        slot,
        kind: if slot == 0 {
            pb::SecretKind::RepoPassword
        } else {
            pb::SecretKind::NewKeyPassword
        } as i32,
        length: 32,
    };
    pb::Job {
        job_id: job_id(),
        kind: if kind == pb::JobKind::Unspecified {
            pb::JobKind::Check
        } else {
            kind
        } as i32,
        secret_slots: if two {
            vec![slot(0), slot(1)]
        } else {
            vec![slot(0)]
        },
        spec: Some(spec),
    }
}

fn msg(f: F) -> pb::RepoFrame {
    pb::RepoFrame { frame: Some(f) }
}

fn request(req_id: u64, op: Op) -> pb::RepoFrame {
    msg(F::Request(pb::RepoRequest {
        req_id,
        op: Some(op),
    }))
}

fn response(req_id: u64, r: Res) -> pb::RepoFrame {
    msg(F::Response(pb::RepoResponse {
        req_id,
        result: Some(r),
    }))
}

/// The answer a responder gives to `op` (a write is answered when its `END` arrives).
fn answer(req_id: u64, op: &Op) -> pb::RepoFrame {
    let done = || Res::Done(pb::Done {});
    response(
        req_id,
        match op {
            Op::List(_) => Res::ListPage(pb::ListPage {
                entries: vec![],
                last: true,
            }),
            Op::ReadFull(_) | Op::ReadPartial(_) => Res::Error(pb::RepoError {
                class: pb::ErrorClass::NotFound as i32,
                retry_after_ms: 0,
            }),
            Op::Quota(_) => Res::QuotaResult(pb::QuotaResult {
                limit: 1 << 30,
                usage: 1 << 20,
                usage_in_trash: 0,
            }),
            Op::Write(_)
            | Op::Remove(_)
            | Op::Create(_)
            | Op::OpenRepo(_)
            | Op::SetUploadRate(_) => done(),
        },
    )
}

struct Harness {
    endpoint: Endpoint,
    link: LinkState,
    respond: bool,
    kind: pb::JobKind,
    job_sent: bool,
    next_id: u64,
    /// Writes (ids) a responder is waiting to see the `END` of.
    pending_writes: Vec<u64>,
}

type Out = Result<(), String>;

impl Harness {
    fn send(&mut self, f: &pb::RepoFrame) -> Out {
        self.link
            .sent_message(f)
            .map(|_| ())
            .map_err(|e| format!("own frame refused: {e}"))
    }

    fn start(&mut self) -> Out {
        if self.endpoint.is_privd() {
            let hello = msg(F::Hello(pb::Hello {
                major: repo::VERSION_MAJOR,
                minor: repo::VERSION_MINOR,
                job_id: job_id(),
            }));
            self.send(&hello)?;
        }
        Ok(())
    }

    fn requester(&self) -> bool {
        matches!(self.endpoint, Endpoint::Worker | Endpoint::PrivdDriveLink)
    }

    /// What the harness does after the peer's frame `incoming` was accepted.
    fn react(&mut self, incoming: &Incoming) -> Out {
        if let Incoming::Message(pb::RepoFrame { frame: Some(f) }) = incoming {
            match f {
                F::Hello(_) if !self.endpoint.is_privd() => {
                    let ack = msg(F::HelloAck(pb::HelloAck {
                        major: repo::VERSION_MAJOR,
                        minor: repo::VERSION_MINOR,
                        software: "hx-fuzz-0.0.0".into(),
                    }));
                    self.send(&ack)?;
                }
                F::HelloAck(_) if self.endpoint == Endpoint::PrivdWorkerLink && !self.job_sent => {
                    self.job_sent = true;
                    let job = job(self.kind);
                    let secrets: Vec<(u32, u32)> = job
                        .secret_slots
                        .iter()
                        .map(|s| (s.slot, s.length))
                        .collect();
                    self.send(&msg(F::Job(job)))?;
                    for (slot, len) in secrets {
                        self.link
                            .sent_secret(0, slot as u8, len as usize)
                            .map_err(|e| format!("own secret refused: {e}"))?;
                    }
                }
                F::Request(r) if self.respond && !self.requester() => {
                    if let Some(op) = &r.op {
                        // The policy is total whatever the request.
                        for k in KINDS {
                            let _ = check_op(k, None, op);
                        }
                        if matches!(op, Op::Write(_)) {
                            self.pending_writes.push(r.req_id);
                        } else {
                            self.send(&answer(r.req_id, op))?;
                        }
                    }
                }
                _ => {}
            }
        }
        if let Incoming::Data(d) = incoming
            && self.respond
            && !self.requester()
            && d.end
            && let Some(pos) = self.pending_writes.iter().position(|w| *w == d.stream_id)
        {
            self.pending_writes.swap_remove(pos);
            // The upload may have been aborted by an earlier answer; a refusal is then ours.
            let _ = self.send(&answer(d.stream_id, &Op::Create(pb::Create {})));
        }
        if self.respond && self.requester() {
            self.next_request()?;
        }
        Ok(())
    }

    fn next_request(&mut self) -> Out {
        let drive = self.endpoint == Endpoint::PrivdDriveLink;
        let n = self.next_id;
        let step = if drive {
            n.wrapping_sub(2)
        } else {
            n.wrapping_sub(1)
        };
        let op = if drive && n == 1 {
            Op::OpenRepo(pb::OpenRepo {
                folder: "hx-fuzz-folder".into(),
                create: true,
                server_id: Bytes::from(vec![9u8; 16]),
                takeover: false,
            })
        } else {
            match step % 4 {
                0 => Op::List(pb::List {
                    object_type: pb::ObjectType::Pack as i32,
                }),
                1 => Op::Write(pb::Write {
                    object_type: pb::ObjectType::Pack as i32,
                    id: id(7),
                    size: 10,
                }),
                2 => Op::ReadFull(pb::ReadFull {
                    object_type: pb::ObjectType::Pack as i32,
                    id: id(7),
                }),
                _ => Op::Create(pb::Create {}),
            }
        };
        let is_write = matches!(op, Op::Write(_));
        if !self.link.can_request(is_write) {
            return Ok(());
        }
        self.send(&request(n, op))?;
        self.next_id += 1;
        if is_write {
            self.link
                .sent_data(n, true, 10)
                .map_err(|e| format!("own data refused: {e}"))?;
        }
        Ok(())
    }
}

/// Plays `endpoint` against `stream` (the peer's bytes, fed in chunks of `chunk`). Returns the
/// number of peer frames that were accepted when the stream ended cleanly at a frame boundary,
/// or the reason it was not accepted to its end (a peer violation or a refused frame of ours).
/// Panics only on a broken invariant of the codec.
pub fn run(
    endpoint: Endpoint,
    respond: bool,
    kind: pb::JobKind,
    chunk: usize,
    stream: &[u8],
) -> Result<usize, String> {
    let mut h = Harness {
        endpoint,
        link: LinkState::new(endpoint),
        respond,
        kind,
        job_sent: false,
        next_id: 1,
        pending_writes: Vec::new(),
    };
    h.start()?;
    let mut decoder = Decoder::new(RepoFramePolicy::new(endpoint));
    let mut frames = 0usize;
    let mut rest = stream;
    while !rest.is_empty() {
        let take = rest.len().min(chunk.max(1));
        let mut piece = &rest[..take];
        while !piece.is_empty() {
            let (used, raw) = decoder.feed(piece).map_err(|e| format!("framing: {e}"))?;
            piece = &piece[used..];
            let Some(raw) = raw else { continue };
            let incoming = repo::decode(raw, endpoint).map_err(|e| format!("decode: {e}"))?;
            check_stable(&incoming, endpoint);
            h.link
                .received(&incoming)
                .map_err(|e| format!("peer violation: {e}"))?;
            frames += 1;
            let cap = if endpoint.on_worker_link() {
                MAX_OUTSTANDING_REQUESTS
            } else {
                MAX_DRIVE_OUTSTANDING_REQUESTS
            };
            assert!(h.link.outstanding() <= cap);
            assert!(h.link.outstanding_writes() <= MAX_OUTSTANDING_WRITES);
            h.react(&incoming)?;
        }
        rest = &rest[take..];
    }
    decoder.finish().map_err(|e| format!("truncated: {e}"))?;
    Ok(frames)
}

/// An accepted frame re-encodes for the same peer and decodes to the same value.
fn check_stable(incoming: &Incoming, endpoint: Endpoint) {
    match incoming {
        Incoming::Message(frame) => {
            let wire = repo::encode_message(frame, endpoint).expect("an accepted frame encodes");
            let again = repo::decode(
                RawFrame {
                    kind: wire[4],
                    body: wire[5..].into(),
                },
                endpoint,
            )
            .expect("and decodes");
            match again {
                Incoming::Message(f2) => assert_eq!(&f2, frame),
                _ => panic!("a message became something else"),
            }
        }
        Incoming::Secret(s) => {
            assert_eq!(endpoint, Endpoint::Worker);
            let _ = format!("{s:?}");
        }
        Incoming::Data(d) => {
            assert!(d.stream_id != 0);
            assert!(d.payload.len() <= MAX_DATA_PAYLOAD);
            let _ = format!("{d:?}");
        }
    }
}
