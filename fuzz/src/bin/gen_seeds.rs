//! Writes the seed corpora under `fuzz/seeds/<target>/` from real messages built with the
//! production encoders, so every target starts from inputs that get past the first checks.
//!
//! ```text
//! cd fuzz && cargo run --bin gen-seeds        # stable toolchain is fine
//! ```
//!
//! Deterministic: nothing here reads the clock or a random source (keys come from fixed seeds).

use std::{fs, io::Write, path::PathBuf};

use hx_crypto::{
    IdentityKey, PairingCode, PairingToken, PinHash, PinParams,
    wire::{
        AuthMessage, PairConfirm, PairMode, PairServerHello, PairStart, PairingMessage, PinAttempt,
        auth_message, pairing_message::Body,
    },
};
use hx_ipc::{
    admin,
    link::{
        self, Role,
        frames::{
            encode_gateway_message, encode_session_message, encode_transfer_abort,
            encode_transfer_end, encode_transfer_open, encode_video_prefix,
        },
        pb as lpb,
    },
    privd::{self, Side, pb as ppb},
    repo::{self, Endpoint, pb as rpb},
};
use hx_proto::{
    VideoCodec,
    datagram::{AudioPacket, MouseMove},
    media::{FLAG_KEY, FLAG_RESYNC, MediaHeader},
    message,
    pb::{
        self, ControlMessage, CursorEvent, InputEvent, Intent, TransferHeader,
        control_message::Message as Ctl, cursor_event, input_event,
    },
    version::{Features, capabilities},
};
use prost::Message;

struct Out {
    root: PathBuf,
    count: usize,
}

impl Out {
    fn put(&mut self, target: &str, name: &str, bytes: &[u8]) {
        let dir = self.root.join(target);
        fs::create_dir_all(&dir).expect("create seed dir");
        fs::write(dir.join(name), bytes).expect("write seed");
        self.count += 1;
    }
}

fn prefixed(first: &[u8], rest: &[u8]) -> Vec<u8> {
    [first, rest].concat()
}

/// A masked client-to-server WebSocket binary frame (mask key zero, so the payload is as is).
fn ws_frame(payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0x82];
    match payload.len() {
        n if n < 126 => f.push(0x80 | n as u8),
        n => {
            f.push(0x80 | 126);
            f.extend((n as u16).to_be_bytes());
        }
    }
    f.extend([0, 0, 0, 0]);
    f.extend(payload);
    f
}

fn on_channel(ch: u8, body: &[u8]) -> Vec<u8> {
    prefixed(&[ch], body)
}

fn ctl(m: Ctl) -> Vec<u8> {
    message::encode(&ControlMessage::new(m))
        .expect("encode")
        .to_vec()
}

fn hello(intent: Intent) -> Vec<u8> {
    ctl(Ctl::Hello(pb::Hello {
        version: Some(pb::Version { major: 1, minor: 2 }),
        capabilities: Some(capabilities(
            &[VideoCodec::H264],
            Features::defined_up_to(2),
        )),
        intent: intent as i32,
        software: "hx-desktop 0.1.0 (seed)".into(),
        device_name: "Seed phone".into(),
    }))
}

fn key_event(scancode: u32) -> Vec<u8> {
    message::encode(&InputEvent {
        event: Some(input_event::Event::Key(pb::KeyEvent {
            scancode,
            pressed: true,
        })),
    })
    .expect("encode")
    .to_vec()
}

fn cursor_position() -> Vec<u8> {
    message::encode(&CursorEvent {
        event: Some(cursor_event::Event::Position(pb::CursorPosition {
            x: 100,
            y: -20,
            shape_id: 1,
            visible: true,
        })),
    })
    .expect("encode")
    .to_vec()
}

fn cursor_shape() -> Vec<u8> {
    message::encode(&CursorEvent {
        event: Some(cursor_event::Event::Shape(pb::CursorShape {
            id: 1,
            width: 2,
            height: 2,
            hotspot_x: 0,
            hotspot_y: 0,
            rgba: vec![0xff; 16].into(),
        })),
    })
    .expect("encode")
    .to_vec()
}

fn transfer_header_file() -> Vec<u8> {
    message::encode(&TransferHeader {
        mime: "text/plain".into(),
        name: "notes.txt".into(),
        size: 12,
    })
    .expect("encode")
    .to_vec()
}

fn transfer_header_clip() -> Vec<u8> {
    message::encode(&TransferHeader {
        mime: "text/plain".into(),
        name: String::new(),
        size: 5,
    })
    .expect("encode")
    .to_vec()
}

fn media_header(frame: u32, key: bool, payload: usize) -> MediaHeader {
    MediaHeader {
        codec: VideoCodec::H264,
        flags: if key { FLAG_KEY | FLAG_RESYNC } else { 0 },
        frame_number: frame,
        capture_timestamp_us: 1_000_000 + u64::from(frame) * 16_666,
        payload_len: payload as u32,
    }
}

const SPS_1080P: [u8; 27] = [
    0x67, 0x64, 0x00, 0x28, 0xAC, 0xD9, 0x40, 0x78, 0x02, 0x27, 0xE5, 0xC0, 0x44, 0x00, 0x00, 0x03,
    0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0xF0, 0x3C, 0x60, 0xC6, 0x58,
];

fn key_payload() -> Vec<u8> {
    let mut p = vec![0, 0, 0, 1];
    p.extend(SPS_1080P);
    p.extend([0, 0, 0, 1, 0x68, 0xEB, 0xE3, 0xCB, 0x22, 0xC0]);
    p.extend([0, 0, 1, 0x65, 0x88, 0x84, 0x00, 0x10]);
    p
}

fn p_payload() -> Vec<u8> {
    let mut p = vec![0, 0, 0, 1, 0x41, 0x9A];
    p.resize(p.len() + 40, 0xAA);
    p
}

fn video_frame(frame: u32, key: bool) -> Vec<u8> {
    let payload = if key { key_payload() } else { p_payload() };
    let mut w = encode_video_prefix(&media_header(frame, key, payload.len()), 4 << 20)
        .expect("video prefix")
        .to_vec();
    w.extend(payload);
    w
}

/// A whole link frame as `[kind, body...]` (what the `ipc_link` target takes after its selector).
fn kind_body(wire: &[u8]) -> Vec<u8> {
    wire[4..].to_vec()
}

fn info() -> lpb::SessionToGateway {
    lpb::SessionToGateway {
        message: Some(lpb::session_to_gateway::Message::Info(lpb::Info {
            software: "hx-session 0.1.0".into(),
            features: link::validate::FEATURE_INPUT | link::validate::FEATURE_CLIPBOARD,
            codecs: vec![VideoCodec::H264 as i32],
            display: Some(lpb::Display {
                width: 1920,
                height: 1080,
            }),
            max_fps: 60,
        })),
    }
}

fn stream_format() -> lpb::SessionToGateway {
    lpb::SessionToGateway {
        message: Some(lpb::session_to_gateway::Message::StreamFormat(
            lpb::StreamFormat {
                epoch: 1,
                codec: VideoCodec::H264 as i32,
                width: 1920,
                height: 1080,
                fps: 60,
                first_frame: 1,
            },
        )),
    }
}

fn session_msg(m: lpb::session_to_gateway::Message) -> Vec<u8> {
    encode_session_message(&lpb::SessionToGateway { message: Some(m) }).expect("encode")
}

fn transfer_open(id: u32, channel: lpb::TransferChannel, clip: bool) -> lpb::TransferOpen {
    lpb::TransferOpen {
        id,
        channel: channel as i32,
        header: Some(
            TransferHeader::decode(
                if clip {
                    transfer_header_clip()
                } else {
                    transfer_header_file()
                }
                .as_slice(),
            )
            .expect("header"),
        ),
    }
}

fn data_frame(id: u32, data: &[u8]) -> Vec<u8> {
    let mut w = hx_ipc::link::frames::encode_transfer_data_prefix(id, data.len())
        .expect("prefix")
        .to_vec();
    w.extend(data);
    w
}

fn privd_frames() -> Vec<(&'static str, ppb::Frame)> {
    use ppb::frame::Frame as F;
    vec![
        (
            "hello",
            ppb::Frame {
                frame: Some(F::Hello(ppb::Hello {
                    major: 1,
                    minor: 0,
                    software: "hx-gatewayd 0.1.0".into(),
                })),
            },
        ),
        (
            "ping",
            ppb::Frame {
                frame: Some(F::Ping(ppb::Ping { nonce: 7 })),
            },
        ),
        (
            "get_host_info",
            ppb::Frame {
                frame: Some(F::Request(ppb::Request {
                    request_id: 1,
                    deadline_ms: 5_000,
                    secret_slots: vec![],
                    command: Some(ppb::request::Command::GetHostInfo(
                        ppb::GetHostInfoRequest {},
                    )),
                })),
            },
        ),
        (
            "list_desktops",
            ppb::Frame {
                frame: Some(F::Request(ppb::Request {
                    request_id: 2,
                    deadline_ms: 0,
                    secret_slots: vec![],
                    command: Some(ppb::request::Command::ListDesktops(
                        ppb::ListDesktopsRequest {},
                    )),
                })),
            },
        ),
    ]
}

fn admin_frames() -> Vec<(&'static str, admin::pb::Frame)> {
    use admin::pb::frame::Frame as F;
    vec![
        (
            "list_devices",
            admin::pb::Frame {
                frame: Some(F::Request(admin::pb::Request {
                    request_id: 1,
                    deadline_ms: 0,
                    secret_slots: vec![],
                    command: Some(admin::pb::request::Command::ListDevices(
                        admin::pb::ListDevicesRequest {},
                    )),
                })),
            },
        ),
        (
            "revoke_device",
            admin::pb::Frame {
                frame: Some(F::Request(admin::pb::Request {
                    request_id: 2,
                    deadline_ms: 0,
                    secret_slots: vec![],
                    command: Some(admin::pb::request::Command::RevokeDevice(
                        admin::pb::RevokeDeviceRequest {
                            device_id: vec![9; 16].into(),
                        },
                    )),
                })),
            },
        ),
    ]
}

fn tar_gz_parts() -> (Vec<u8>, Vec<u8>) {
    let mut b = tar::Builder::new(Vec::new());
    let mut dir = tar::Header::new_gnu();
    dir.set_entry_type(tar::EntryType::Directory);
    dir.set_path("bin/").expect("path");
    dir.set_mode(0o755);
    dir.set_size(0);
    dir.set_cksum();
    b.append(&dir, std::io::empty()).expect("dir");
    for (path, body, mode) in [
        ("bin/hx-agent", b"#!/bin/sh\nexit 0\n".as_slice(), 0o755),
        ("VERSION", b"0.1.0\n".as_slice(), 0o644),
    ] {
        let mut h = tar::Header::new_gnu();
        h.set_path(path).expect("path");
        h.set_mode(mode);
        h.set_size(body.len() as u64);
        h.set_cksum();
        b.append(&h, body).expect("file");
    }
    let raw = b.into_inner().expect("tar");
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&raw).expect("gzip");
    (raw, gz.finish().expect("gzip"))
}

/// The repository link seeds (`ipc_repo`): `selector | chunk | whole frames`. The selector is the
/// receiving endpoint (0 worker, 1 privd on the worker link, 2 privd on the Drive link, 3 Drive
/// helper), plus 4 to make the harness respond or send requests, plus 8 times the job kind index.
/// The `talk_*` seeds are whole conversations; they are replayed through the harness here and
/// must be accepted to their end (past the handshake, through requests, streams and the result).
#[path = "../ipc_repo_harness.rs"]
mod harness;

mod repo_seeds {
    use super::harness;
    use super::*;
    use bytes::Bytes;
    use rpb::repo_frame::Frame as F;

    fn msg(to: Endpoint, f: F) -> Vec<u8> {
        repo::encode_message(&rpb::RepoFrame { frame: Some(f) }, to).expect("repo frame")
    }

    fn id(b: u8) -> Bytes {
        Bytes::from(vec![b; 32])
    }

    fn req(to: Endpoint, req_id: u64, op: rpb::repo_request::Op) -> Vec<u8> {
        msg(
            to,
            F::Request(rpb::RepoRequest {
                req_id,
                op: Some(op),
            }),
        )
    }

    fn resp(to: Endpoint, req_id: u64, r: rpb::repo_response::Result) -> Vec<u8> {
        msg(
            to,
            F::Response(rpb::RepoResponse {
                req_id,
                result: Some(r),
            }),
        )
    }

    fn write_op(ty: rpb::ObjectType, b: u8, size: u32) -> rpb::repo_request::Op {
        rpb::repo_request::Op::Write(rpb::Write {
            object_type: ty as i32,
            id: id(b),
            size,
        })
    }

    pub fn put(o: &mut Out) {
        use rpb::{ObjectType as T, repo_request::Op, repo_response::Result as R};
        let hello = || {
            F::Hello(rpb::Hello {
                major: 1,
                minor: 0,
                job_id: harness::job_id(),
            })
        };
        let ack = || {
            F::HelloAck(rpb::HelloAck {
                major: 1,
                minor: 0,
                software: "hx-backup-worker-0.1.0".into(),
            })
        };
        let list = |t: T| {
            Op::List(rpb::List {
                object_type: t as i32,
            })
        };
        let page = R::ListPage(rpb::ListPage {
            entries: vec![
                rpb::ListEntry {
                    id: id(1),
                    size: 4096,
                },
                rpb::ListEntry {
                    id: id(2),
                    size: 100,
                },
            ],
            last: true,
        });
        let done = || R::Done(rpb::Done {});
        let page_last = || {
            R::ListPage(rpb::ListPage {
                entries: vec![],
                last: true,
            })
        };
        let w = Endpoint::Worker;
        let pw = Endpoint::PrivdWorkerLink;
        let pd = Endpoint::PrivdDriveLink;
        let dh = Endpoint::DriveHelper;
        let kind_index =
            |k: rpb::JobKind| harness::KINDS.iter().position(|x| *x == k).unwrap() as u8;
        let selector = |e: Endpoint, respond: bool, abort: bool, k: rpb::JobKind| {
            let ep = Endpoint::ALL.iter().position(|x| *x == e).unwrap() as u8;
            ep | if respond { 4 } else { 0 } | (kind_index(k) << 3) | if abort { 0x40 } else { 0 }
        };
        // `min_aborts`: how many aborted uploads a replay must have reached.
        let seed_with = |o: &mut Out,
                         name: &str,
                         e: Endpoint,
                         respond: bool,
                         abort: bool,
                         min_aborts: usize,
                         k: rpb::JobKind,
                         frames: &[Vec<u8>]| {
            let mut v = vec![selector(e, respond, abort, k), 64];
            v.extend(frames.concat());
            o.put("ipc_repo", name, &v);
            if name.starts_with("talk_") {
                let got = harness::run(e, respond, abort, k, 64, &v[2..])
                    .unwrap_or_else(|err| panic!("seed {name} is not accepted to its end: {err}"));
                assert_eq!(
                    got.frames,
                    frames.len(),
                    "seed {name}: every frame must be accepted"
                );
                assert!(
                    got.aborts >= min_aborts,
                    "seed {name}: reached {} aborted uploads, wanted {min_aborts}",
                    got.aborts
                );
            }
        };
        let seed = |o: &mut Out,
                    name: &str,
                    e: Endpoint,
                    respond: bool,
                    k: rpb::JobKind,
                    frames: &[Vec<u8>]| {
            seed_with(o, name, e, respond, false, 0, k, frames)
        };
        let check = rpb::JobKind::Check;

        // One frame per kind of message, at the first endpoint that receives it.
        for kind in harness::KINDS {
            let name = format!("job_{kind:?}").to_lowercase();
            seed(
                o,
                &name,
                w,
                false,
                kind,
                &[msg(w, F::Job(harness::job(kind)))],
            );
        }
        seed(o, "hello", w, false, check, &[msg(w, hello())]);
        seed(o, "hello_ack", pw, false, check, &[msg(pw, ack())]);
        seed(
            o,
            "request_list",
            pw,
            true,
            check,
            &[req(pw, 1, list(T::Pack))],
        );
        seed(
            o,
            "request_write",
            pw,
            true,
            check,
            &[req(pw, 1, write_op(T::Pack, 7, 1000))],
        );
        seed(
            o,
            "request_read_partial",
            pw,
            true,
            check,
            &[req(
                pw,
                1,
                Op::ReadPartial(rpb::ReadPartial {
                    object_type: T::Pack as i32,
                    id: id(7),
                    offset: 100,
                    length: 200,
                }),
            )],
        );
        seed(
            o,
            "request_open_repo",
            dh,
            true,
            check,
            &[req(
                dh,
                1,
                Op::OpenRepo(rpb::OpenRepo {
                    folder: "hx-backup-0a1b2c3d-main".into(),
                    create: true,
                    server_id: Bytes::from(vec![9u8; 16]),
                    takeover: false,
                }),
            )],
        );
        seed(
            o,
            "request_quota",
            dh,
            true,
            check,
            &[req(dh, 2, Op::Quota(rpb::Quota {}))],
        );
        seed(
            o,
            "response_list_page",
            w,
            false,
            check,
            &[resp(w, 1, page.clone())],
        );
        seed(
            o,
            "response_quota_result",
            pd,
            false,
            check,
            &[resp(
                pd,
                1,
                R::QuotaResult(rpb::QuotaResult {
                    limit: 15 << 30,
                    usage: 3 << 30,
                    usage_in_trash: 1 << 20,
                }),
            )],
        );
        seed(
            o,
            "progress",
            pw,
            false,
            check,
            &[msg(
                pw,
                F::Progress(rpb::Progress {
                    phase: rpb::ProgressPhase::ScanAndUpload as i32,
                    files_done: 1,
                    files_total: 10,
                    bytes_done: 100,
                    bytes_total: 1000,
                }),
            )],
        );
        let backup_result = rpb::JobResult {
            ok: true,
            snapshot_id: id(0x11),
            files_new: 5,
            bytes_added: 99,
            ..Default::default()
        };
        seed(
            o,
            "job_result",
            pw,
            false,
            check,
            &[msg(pw, F::Result(backup_result.clone()))],
        );
        seed(
            o,
            "event",
            pd,
            false,
            check,
            &[msg(
                pd,
                F::Event(rpb::Event {
                    kind: rpb::EventKind::PausedDailyLimit as i32,
                    until_ms: 1_764_000_000_000,
                }),
            )],
        );
        seed(
            o,
            "cancel_request",
            dh,
            false,
            check,
            &[msg(dh, F::CancelRequest(rpb::CancelRequest { req_id: 3 }))],
        );
        let secret = repo::encode_secret(0, 0, &[0x5A; 32]).expect("secret");
        seed(o, "secret", w, false, check, &[secret.to_vec()]);
        let payload = vec![0x42u8; 1000];
        seed(
            o,
            "data",
            pw,
            false,
            check,
            &[repo::encode_data(1, true, &payload).expect("data")],
        );

        // Whole conversations, as each end reads them. The harness answers the peer's Hello,
        // sends the job (privd) or its requests (worker, privd on the Drive link), and answers
        // requests; see its module documentation for the exact order.
        let data =
            |id: u64, end: bool, n: usize| repo::encode_data(id, end, &payload[..n]).expect("data");
        let init = rpb::JobKind::Init;
        seed(
            o,
            "talk_worker",
            w,
            true,
            init,
            &[
                msg(w, hello()),
                msg(w, F::Job(harness::job(init))),
                repo::encode_secret(0, 0, &[1; 32]).expect("s0").to_vec(),
                // the worker now sends request 1 (List)
                repo::encode_secret(0, 1, &[2; 32]).expect("s1").to_vec(),
                resp(w, 1, page.clone()),
                // request 2 (Write 10 bytes, sent in full)
                resp(w, 2, done()),
                // request 3 (ReadFull)
                resp(w, 3, R::ReadBegin(rpb::ReadBegin { size: 8 })),
                data(3, false, 4),
                data(3, true, 4),
                msg(w, F::Ping(rpb::Ping { nonce: 9 })),
                msg(w, F::Bye(rpb::Bye {})),
            ],
        );
        let backup = rpb::JobKind::Backup;
        seed(
            o,
            "talk_privd_worker",
            pw,
            true,
            backup,
            &[
                msg(pw, ack()),
                req(pw, 1, list(T::Config)),
                req(pw, 2, write_op(T::Snapshot, 0x11, 1000)),
                data(2, false, 600),
                data(2, true, 400),
                req(
                    pw,
                    3,
                    Op::Remove(rpb::Remove {
                        object_type: T::Index as i32,
                        id: id(4),
                    }),
                ),
                msg(
                    pw,
                    F::Progress(rpb::Progress {
                        phase: 2,
                        ..Default::default()
                    }),
                ),
                msg(pw, F::Result(backup_result)),
                msg(pw, F::Bye(rpb::Bye {})),
            ],
        );
        seed(
            o,
            "talk_privd_drive",
            pd,
            true,
            check,
            &[
                msg(pd, ack()),
                // request 1 (OpenRepo)
                resp(pd, 1, done()),
                // request 2 (List)
                resp(pd, 2, page),
                // request 3 (Write 10 bytes, sent in full)
                resp(pd, 3, done()),
                // request 4 (ReadFull)
                resp(pd, 4, R::ReadBegin(rpb::ReadBegin { size: 8 })),
                data(4, true, 8),
                msg(
                    pd,
                    F::Event(rpb::Event {
                        kind: 3,
                        until_ms: 0,
                    }),
                ),
                msg(pd, F::Bye(rpb::Bye {})),
            ],
        );
        seed(
            o,
            "talk_drive_helper",
            dh,
            true,
            check,
            &[
                msg(dh, hello()),
                req(
                    dh,
                    1,
                    Op::OpenRepo(rpb::OpenRepo {
                        folder: "hx-backup-0a1b2c3d-main".into(),
                        create: false,
                        server_id: Bytes::from(vec![9u8; 16]),
                        takeover: true,
                    }),
                ),
                req(dh, 2, write_op(T::Index, 9, 300)),
                data(2, false, 100),
                data(2, true, 200),
                req(
                    dh,
                    3,
                    Op::SetUploadRate(rpb::SetUploadRate {
                        bytes_per_s: 1 << 20,
                    }),
                ),
                req(dh, 4, Op::Quota(rpb::Quota {})),
                msg(dh, F::CancelRequest(rpb::CancelRequest { req_id: 2 })),
                msg(dh, F::Bye(rpb::Bye {})),
            ],
        );
        // Aborted uploads (abort mode): the tracker's Aborted state at both ends.
        let failed = rpb::JobResult {
            ok: false,
            error: rpb::WorkerError::Engine as i32,
            ..Default::default()
        };
        seed_with(
            o,
            "talk_privd_worker_abort",
            pw,
            true,
            true,
            1,
            backup,
            &[
                msg(pw, ack()),
                // privd answers Error after the first data frame; the rest is discarded
                req(pw, 1, write_op(T::Pack, 7, 20)),
                data(1, false, 10),
                data(1, false, 5),
                data(1, true, 0),
                msg(pw, F::Result(failed)),
                msg(pw, F::Bye(rpb::Bye {})),
            ],
        );
        let error = |to: Endpoint, id: u64| {
            resp(
                to,
                id,
                R::Error(rpb::RepoError {
                    class: rpb::ErrorClass::QuotaExceeded as i32,
                    retry_after_ms: 0,
                }),
            )
        };
        // The Error arrives before the rest of the upload: privd owes the closing empty END.
        seed_with(
            o,
            "talk_privd_drive_abort",
            pd,
            true,
            true,
            1,
            check,
            &[
                msg(pd, ack()),
                resp(pd, 1, done()),
                resp(pd, 2, page_last()),
                // request 3 (Write, first 5 of 10 bytes sent)
                error(pd, 3),
                msg(pd, F::Bye(rpb::Bye {})),
            ],
        );
        // The Error crosses privd's END: the request is finished and no END is owed.
        seed_with(
            o,
            "talk_privd_drive_crossed",
            pd,
            true,
            true,
            0,
            check,
            &[
                msg(pd, ack()),
                resp(pd, 1, done()),
                resp(pd, 2, page_last()),
                msg(
                    pd,
                    F::Event(rpb::Event {
                        kind: 2,
                        until_ms: 0,
                    }),
                ),
                error(pd, 3),
                msg(pd, F::Bye(rpb::Bye {})),
            ],
        );
        seed_with(
            o,
            "talk_worker_abort",
            w,
            true,
            true,
            1,
            init,
            &[
                msg(w, hello()),
                msg(w, F::Job(harness::job(init))),
                repo::encode_secret(0, 0, &[1; 32]).expect("s0").to_vec(),
                repo::encode_secret(0, 1, &[2; 32]).expect("s1").to_vec(),
                resp(w, 1, page_last()),
                error(w, 2),
                msg(w, F::Bye(rpb::Bye {})),
            ],
        );
    }
}

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("seeds");
    let _ = fs::remove_dir_all(&root);
    let mut o = Out { root, count: 0 };

    // ---- hx-proto
    let hello_session = hello(Intent::Session);
    let hello_pair = hello(Intent::Pair);
    let control: Vec<(&str, Vec<u8>)> = vec![
        ("hello_session", hello_session.clone()),
        ("hello_pair", hello_pair.clone()),
        ("ping", ctl(Ctl::Ping(pb::Ping { nonce: 42 }))),
        (
            "view_config",
            ctl(Ctl::ViewConfig(pb::ViewConfig {
                codec: VideoCodec::H264 as i32,
                max_fps: 60,
                bandwidth_cap_kbps: 20_000,
                width: 1280,
                height: 720,
                scale_percent: 100,
                audio_enabled: false,
                clipboard_enabled: true,
                stats_enabled: false,
            })),
        ),
        (
            "server_get_overview",
            ctl(Ctl::ServerMgmt(pb::ServerMgmt {
                request_id: 1,
                body: Some(pb::server_mgmt::Body::GetOverview(pb::ServerGetOverview {})),
            })),
        ),
        (
            "server_change_pin",
            ctl(Ctl::ServerMgmt(pb::ServerMgmt {
                request_id: 2,
                body: Some(pb::server_mgmt::Body::ChangePin(pb::ServerChangePin {
                    current: b"123456".as_slice().into(),
                    new: b"654321".as_slice().into(),
                })),
            })),
        ),
        (
            "server_result",
            ctl(Ctl::ServerMgmt(pb::ServerMgmt {
                request_id: 3,
                body: Some(pb::server_mgmt::Body::Result(pb::ServerResult {
                    status: pb::ServerStatus::WrongPin as i32,
                    retry_after_s: 1,
                    attempts_left: 4,
                    message: "wrong".into(),
                    ..Default::default()
                })),
            })),
        ),
        (
            "goodbye",
            ctl(Ctl::Goodbye(pb::Goodbye {
                code: 0,
                message: "bye".into(),
                peer_device_name: String::new(),
                peer_device_id: Default::default(),
            })),
        ),
    ];
    for (n, b) in &control {
        o.put("proto_control", n, b);
        o.put("transport_hello", n, b);
    }
    o.put(
        "proto_control",
        "hello_framed",
        &message::encode_framed(&ControlMessage::decode(hello_session.as_slice()).expect("hello"))
            .expect("framed"),
    );

    o.put(
        "proto_messages",
        "input_key",
        &prefixed(&[0], &key_event(0x04)),
    );
    o.put(
        "proto_messages",
        "cursor_position",
        &prefixed(&[1], &cursor_position()),
    );
    o.put(
        "proto_messages",
        "cursor_shape",
        &prefixed(&[1], &cursor_shape()),
    );
    o.put(
        "proto_messages",
        "transfer_file",
        &prefixed(&[2], &transfer_header_file()),
    );
    o.put(
        "proto_messages",
        "transfer_clip",
        &prefixed(&[2], &transfer_header_clip()),
    );
    o.put("proto_messages", "frame_len", &[3, 0x10, 0, 0, 0]);
    o.put(
        "proto_messages",
        "name_text",
        &prefixed(&[4], b"report \xe2\x80\xae.txt"),
    );

    o.put(
        "proto_media",
        "video_header",
        &media_header(7, true, 0).encode().expect("header"),
    );
    let mut frame = media_header(8, false, 4).encode().expect("header").to_vec();
    frame.extend([1, 2, 3, 4]);
    o.put("proto_media", "video_frame", &frame);
    o.put(
        "proto_media",
        "mouse",
        &MouseMove {
            relative: true,
            seq: 5,
            x: -3,
            y: 4,
        }
        .encode(),
    );
    o.put(
        "proto_media",
        "audio",
        &AudioPacket {
            seq: 1,
            timestamp: 960,
            payload: vec![0xAB; 20].into(),
        }
        .encode()
        .expect("audio"),
    );

    // ---- hx-transport
    o.put(
        "transport_ws_first",
        "hello",
        &ws_frame(&on_channel(0x01, &hello_session)),
    );
    o.put(
        "transport_ws_first",
        "hello_pair",
        &ws_frame(&on_channel(0x01, &hello_pair)),
    );
    let mut ping_frame = vec![0x89, 0x80, 0, 0, 0, 0];
    ping_frame.extend(ws_frame(&on_channel(0x01, &hello_session)));
    o.put("transport_ws_first", "ping_then_hello", &ping_frame);

    let mut server_stream = vec![0u8];
    for f in [
        on_channel(0x01, &ctl(Ctl::Ping(pb::Ping { nonce: 1 }))),
        on_channel(0x02, &key_event(0x04)),
        MouseMove {
            relative: false,
            seq: 1,
            x: 10,
            y: 20,
        }
        .encode()
        .to_vec(),
        on_channel(0x09, &1u32.to_le_bytes()),
    ] {
        server_stream.extend(ws_frame(&f));
    }
    o.put("transport_ws_session", "server_basic", &server_stream);
    let mut transfer = vec![0u8];
    let id = 1u32.to_le_bytes();
    transfer.extend(ws_frame(&on_channel(
        0x07,
        &[&id[..], &[1], &transfer_header_clip()].concat(),
    )));
    transfer.extend(ws_frame(&on_channel(
        0x07,
        &[&id[..], &[2], b"hello"].concat(),
    )));
    transfer.extend(ws_frame(&on_channel(0x07, &[&id[..], &[3]].concat())));
    o.put("transport_ws_session", "server_clipboard", &transfer);
    let mut file = vec![0u8];
    let id3 = 3u32.to_le_bytes();
    file.extend(ws_frame(&on_channel(
        0x08,
        &[&id3[..], &[1], &transfer_header_file()].concat(),
    )));
    file.extend(ws_frame(&on_channel(0x08, &[&id3[..], &[4]].concat())));
    o.put("transport_ws_session", "server_file_abort", &file);
    let mut client_stream = vec![1u8];
    client_stream.extend(ws_frame(&on_channel(0x04, &cursor_position())));
    client_stream.extend(ws_frame(&on_channel(0x04, &cursor_shape())));
    let mut vid = media_header(1, true, 4).encode().expect("header").to_vec();
    vid.extend([9, 9, 9, 9]);
    client_stream.extend(ws_frame(&on_channel(0x05, &vid)));
    client_stream.extend(ws_frame(&on_channel(
        0x06,
        &AudioPacket {
            seq: 1,
            timestamp: 0,
            payload: vec![1; 8].into(),
        }
        .encode()
        .expect("audio")[1..],
    )));
    o.put("transport_ws_session", "client_basic", &client_stream);

    // ---- hx-crypto
    let (spake_a, spake_msg) = spake2::Spake2::<spake2::Ed25519Group>::start_a(
        &spake2::Password::new(b"seed password"),
        &spake2::Identity::new(b"hx-pair-client"),
        &spake2::Identity::new(b"hx-pair-server"),
    );
    drop(spake_a);
    let start = |mode: PairMode, token_id: Vec<u8>| {
        PairingMessage::new(Body::Start(PairStart {
            mode: mode as i32,
            token_id,
            spake: spake_msg.clone(),
            device_name: "Seed phone".into(),
        }))
        .into_control()
        .expect("control")
    };
    for (n, m) in [
        ("start_token", start(PairMode::Token, vec![1; 8])),
        ("start_code", start(PairMode::Code, vec![])),
        (
            "server_hello",
            PairingMessage::new(Body::ServerHello(PairServerHello {
                spake: spake_msg.clone(),
                server_name: "seed-server".into(),
            }))
            .into_control()
            .expect("control"),
        ),
        (
            "client_confirm",
            PairingMessage::new(Body::ClientConfirm(PairConfirm { mac: vec![5; 32] }))
                .into_control()
                .expect("control"),
        ),
        (
            "pin_attempt",
            AuthMessage::new(auth_message::Body::Pin(PinAttempt {
                pin: b"123456".to_vec(),
            }))
            .into_control()
            .expect("control"),
        ),
    ] {
        o.put("crypto_pairing", n, &message::encode(&m).expect("encode"));
    }

    let token = PairingToken::generate().expect("token");
    let code = PairingCode::generate().expect("code");
    o.put(
        "crypto_secrets",
        "token",
        &prefixed(&[1], token.to_text().as_bytes()),
    );
    o.put(
        "crypto_secrets",
        "code",
        &prefixed(&[1], code.to_text().as_bytes()),
    );
    o.put("crypto_secrets", "pin", &prefixed(&[0], b"123456"));
    o.put(
        "crypto_secrets",
        "device_id",
        &prefixed(&[1], b"00112233445566778899aabbccddeeff"),
    );

    let seed_key = IdentityKey::from_seed(&[7u8; 32]).expect("key");
    o.put(
        "crypto_registry",
        "known_key",
        &prefixed(&[1], &seed_key.public().spki()),
    );
    let other = IdentityKey::from_seed(&[8u8; 32]).expect("key");
    o.put(
        "crypto_registry",
        "other_key",
        &prefixed(&[1], &other.public().spki()),
    );
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("registry");
        // The registry refuses a group-writable directory, whatever the umask made of this one.
        fs::set_permissions(
            dir.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("chmod");
        let reg = hx_crypto::FileRegistry::open(&path).expect("open registry");
        hx_crypto::DeviceRegistry::upsert_paired(
            &reg,
            &seed_key.public(),
            "Seed phone",
            1_700_000_000,
        )
        .expect("upsert");
        drop(reg);
        o.put(
            "crypto_registry",
            "file",
            &prefixed(&[0], &fs::read(&path).expect("registry file")),
        );
    }

    let pin = hx_crypto::Pin::new("123456").expect("pin");
    let cheap = PinHash::with_params(
        &pin,
        PinParams {
            memory_kib: 64,
            iterations: 1,
            parallelism: 1,
        },
    )
    .expect("hash");
    o.put(
        "crypto_pin_record",
        "cheap",
        cheap.to_storage_string().as_bytes(),
    );

    // ---- hx-ipc
    for (n, f) in privd_frames() {
        let wire = privd::encode_message(&f, Side::Server).expect("encode");
        o.put(
            "ipc_privd_admin",
            &format!("privd_{n}"),
            &[&[0u8][..], &kind_body(&wire)].concat(),
        );
        o.put(
            "ipc_frame",
            &format!("privd_{n}"),
            &[&[0u8, 3][..], &wire].concat(),
        );
    }
    for (n, f) in admin_frames() {
        let wire = admin::encode_message(&f, Side::Server).expect("encode");
        o.put(
            "ipc_privd_admin",
            &format!("admin_{n}"),
            &[&[2u8][..], &kind_body(&wire)].concat(),
        );
        o.put(
            "ipc_frame",
            &format!("admin_{n}"),
            &[&[0u8, 7][..], &wire].concat(),
        );
    }
    repo_seeds::put(&mut o);
    // A kind-2 secret frame: kind byte 2 and a few bytes of body.
    o.put("ipc_privd_admin", "secret", &[0, 2, b's', b'e', b'c']);

    use lpb::{gateway_to_session::Message as G, session_to_gateway::Message as S};
    let session_msgs: Vec<(&str, Vec<u8>)> = vec![
        ("info", encode_session_message(&info()).expect("info")),
        (
            "stream_format",
            encode_session_message(&stream_format()).expect("fmt"),
        ),
        ("pong", session_msg(S::Pong(lpb::Pong { nonce: 5 }))),
        (
            "event",
            session_msg(S::Event(lpb::Event {
                kind: lpb::EventKind::DisplayChanged as i32,
                message: "display changed".into(),
            })),
        ),
        (
            "cursor",
            session_msg(S::Cursor(
                CursorEvent::decode(cursor_position().as_slice()).expect("cursor"),
            )),
        ),
        (
            "cancel",
            session_msg(S::CancelFrames(lpb::CancelFrames { up_to_frame: 3 })),
        ),
    ];
    for (n, w) in &session_msgs {
        o.put(
            "ipc_link",
            &format!("session_{n}"),
            &[&[0u8][..], &kind_body(w)].concat(),
        );
        o.put(
            "ipc_frame",
            &format!("link_session_{n}"),
            &[&[2u8, 5][..], w].concat(),
        );
    }
    let gateway_msgs = [
        encode_gateway_message(&lpb::GatewayToSession {
            message: Some(G::Start(lpb::Start {
                epoch: 1,
                config: Some(lpb::StreamConfig {
                    codec: VideoCodec::H264 as i32,
                    max_fps: 60,
                    bitrate_cap_kbps: 10_000,
                    width: 1280,
                    height: 720,
                    scale_percent: 100,
                    audio_enabled: false,
                    clipboard_enabled: true,
                    file_transfer_enabled: true,
                }),
            })),
        })
        .expect("start"),
        encode_gateway_message(&lpb::GatewayToSession {
            message: Some(G::Ping(lpb::Ping { nonce: 9 })),
        })
        .expect("ping"),
    ];
    for (i, w) in gateway_msgs.iter().enumerate() {
        o.put(
            "ipc_link",
            &format!("gateway_{i}"),
            &[&[1u8][..], &kind_body(w)].concat(),
        );
    }
    let key_video = video_frame(1, true);
    o.put(
        "ipc_link",
        "video_key",
        &[&[2u8 << 1][..], &kind_body(&key_video)].concat(),
    );
    o.put(
        "ipc_frame",
        "link_video",
        &[&[10u8, 64][..], &key_video].concat(),
    );
    let open = encode_transfer_open(
        Role::Session,
        &transfer_open(2, lpb::TransferChannel::Clipboard, true),
        u64::MAX,
    )
    .expect("open");
    o.put(
        "ipc_link",
        "transfer_open",
        &[&[4u8 << 1][..], &kind_body(&open)].concat(),
    );
    o.put("ipc_frame", "link_bulk", &[&[18u8, 32][..], &open].concat());
    o.put(
        "ipc_link",
        "transfer_end",
        &[
            &[4u8 << 1][..],
            &kind_body(&encode_transfer_end(2).expect("end")),
        ]
        .concat(),
    );
    o.put(
        "ipc_link",
        "transfer_abort",
        &[
            &[4u8 << 1][..],
            &kind_body(&encode_transfer_abort(2, 1).expect("abort")),
        ]
        .concat(),
    );
    o.put(
        "ipc_text",
        "ansi",
        &prefixed(&[40], "ok \u{1b}[31mred\u{1b}[0m \u{202e}rtl".as_bytes()),
    );
    o.put(
        "ipc_text",
        "plain",
        &prefixed(&[8], "hello world, a longer text".as_bytes()),
    );

    // ---- hx-agent: the session link as the gateway reads it
    let lane = |frames: &[Vec<u8>]| frames.concat();
    let ctl_lane = lane(&[
        encode_session_message(&stream_format()).expect("fmt"),
        session_msg(S::Pong(lpb::Pong { nonce: 1 })),
        session_msg(S::Cursor(
            CursorEvent::decode(cursor_position().as_slice()).expect("cursor"),
        )),
        session_msg(S::Event(lpb::Event {
            kind: lpb::EventKind::CaptureError as i32,
            message: "capture failed".into(),
        })),
    ]);
    let media_lane = lane(&[
        video_frame(1, true),
        video_frame(2, false),
        video_frame(3, false),
    ]);
    let bulk_lane = lane(&[
        encode_transfer_open(
            Role::Session,
            &transfer_open(2, lpb::TransferChannel::Clipboard, true),
            u64::MAX,
        )
        .expect("open"),
        data_frame(2, b"hello"),
        encode_transfer_end(2).expect("end"),
        encode_transfer_open(
            Role::Session,
            &transfer_open(4, lpb::TransferChannel::File, false),
            u64::MAX,
        )
        .expect("open"),
        data_frame(4, b"file body"),
        encode_transfer_abort(4, 1).expect("abort"),
    ]);
    let mut all = Vec::new();
    all.extend((ctl_lane.len() as u16).to_le_bytes());
    all.extend((media_lane.len() as u16).to_le_bytes());
    all.extend(&ctl_lane);
    all.extend(&media_lane);
    all.extend(&bulk_lane);
    o.put("agent_link_session", "all_lanes", &all);
    let mut ctl_only = Vec::new();
    ctl_only.extend((ctl_lane.len() as u16).to_le_bytes());
    ctl_only.extend(0u16.to_le_bytes());
    ctl_only.extend(&ctl_lane);
    o.put("agent_link_session", "ctl_only", &ctl_only);

    o.put("agent_annexb", "key", &prefixed(&[1], &key_payload()));
    o.put("agent_annexb", "p_frame", &prefixed(&[0], &p_payload()));

    // ---- hx-agent: update path
    let manifest = |version: &str| {
        format!(
            "{{\"schema\":1,\"channel\":\"stable\",\"version\":\"{version}\",\"arch\":\"x86_64\",\"artifact\":\"hx-{version}-x86_64.tar.gz\",\"size\":1048576,\"sha256\":\"{}\",\"timestamp\":1700000000,\"min_previous\":\"0.1.0\"}}",
            "ab".repeat(32)
        )
    };
    o.put(
        "agent_update_manifest",
        "stable",
        manifest("0.2.0").as_bytes(),
    );
    o.put(
        "agent_update_manifest",
        "prerelease",
        manifest("1.0.0-rc.1").as_bytes(),
    );

    // The published example of the minisign-verify crate: key RWQf6LRC..., signature of `test`.
    let sig = "untrusted comment: signature from minisign secret key\nRWQf6LRCGA9i59SLOFxz6NxvASXDJeRtuZykwQepbDEGt87ig1BNpWaVWuNrm73YiIiJbq71Wi+dP9eKL8OC351vwIasSSbXxwA=\ntrusted comment: timestamp:1555779966\tfile:test\nQtKMXWyYcwdpZAlPF7tE2ENJkRd1ujvKjlj1m9RtHTBnZPa5WKU5uWRs5GoP5M/VqE81QFuMKI5k/SfNQUaOAA==";
    o.put(
        "agent_update_sig",
        "valid",
        &[&4u16.to_le_bytes()[..], b"test", sig.as_bytes()].concat(),
    );

    let (raw_tar, tgz) = tar_gz_parts();
    o.put("agent_update_extract", "tar_gz", &prefixed(&[0], &tgz));
    o.put("agent_update_extract", "raw_tar", &prefixed(&[1], &raw_tar));

    // ---- hx-agent: installer stdin, verifier record, fetcher URL
    let record = |k: u8, v: &[u8]| {
        let mut r = vec![k];
        r.extend((v.len() as u16).to_le_bytes());
        r.extend(v);
        r
    };
    let mut stdin = vec![1u8];
    stdin.extend(b"HXI1");
    stdin.extend(record(1, b"correct horse battery staple"));
    stdin.extend(record(2, b"123456"));
    stdin.extend(record(3, token.to_text().as_bytes()));
    stdin.extend(record(4, &[0x42; 32]));
    stdin.extend([0, 0, 0]);
    o.put("agent_install_stdin", "full", &stdin);
    let mut minimal = vec![0u8];
    minimal.extend(b"HXI1");
    minimal.extend(record(2, b"654321"));
    minimal.extend([0, 0, 0]);
    o.put("agent_install_stdin", "pin_only", &minimal);

    o.put(
        "agent_verifier_record",
        "typical",
        format!(
            "hx-pv1$m=19456,t=2,p=1${}${}",
            "0a".repeat(16),
            "1b".repeat(32)
        )
        .as_bytes(),
    );
    o.put(
        "agent_fetcher_url",
        "release",
        b"https://objects.githubusercontent.com/github-production-release-asset/1/hx-0.2.0-x86_64.tar.gz?X-Amz-Expires=300",
    );
    o.put(
        "agent_fetcher_url",
        "port",
        b"https://github.com:443/Omakidx/hash-xcreen/releases/download/v0.2.0/manifest.json",
    );

    // ---- hx-pwcheck
    let shadow = "root:$6$saltsalt$abcdefghijklmnop:19000:0:99999:7:::\ndaemon:*:19000:0:99999:7:::\nz11:$y$j9T$abcdefg$hijklmnop:19500:0:99999:7:::\nlocked:!$6$x$y:19000::::::\n";
    let mut s = vec![3u8];
    s.extend(b"z11");
    s.extend(shadow.as_bytes());
    o.put("pwcheck_shadow", "shadow", &s);
    let mut s = vec![6u8];
    s.extend(b"locked");
    s.extend(shadow.as_bytes());
    o.put("pwcheck_shadow", "locked", &s);

    println!("wrote {} seeds under fuzz/seeds", o.count);
}
