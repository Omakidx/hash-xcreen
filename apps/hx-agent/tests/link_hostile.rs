//! Hostile-session tests: `LinkClient` against a fake session that breaks every rule of
//! `docs/ipc.md` section 19.1 in turn. Nothing here needs a display.
//!
//! Each test says which rule it exercises; the report maps them to the contract. A violation
//! must end the link as [`FailureClass::Violation`] without a panic; a rate or range overage must
//! be dropped and counted while the link lives.

use bytes::Bytes;
use hx_agent::link::{
    ConnectError, FailureClass, LinkClient, LinkConfig, LinkEvent, LinkEvents, TransferEvent,
};
use hx_ipc::frame::{Decoder, encode_frame};
use hx_ipc::link::preamble::{CLIENT_PREAMBLE_LEN, ClientPreamble, Preamble};
use hx_ipc::link::{
    KIND_AUDIO, KIND_SESSION_TO_GATEWAY, KIND_TRANSFER_ABORT, KIND_TRANSFER_DATA,
    KIND_TRANSFER_END, KIND_TRANSFER_OPEN, KIND_VIDEO, Lane, LinkPolicy, Role, pb,
};
use hx_ipc::recv::NoCmsgReader;
use hx_proto::VideoCodec;
use hx_proto::pb::{CursorEvent, CursorShape, TransferHeader, cursor_event};
use prost::Message;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering::SeqCst};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tokio::time::timeout;

static NEXT: AtomicU32 = AtomicU32::new(0);

// ----- the fake session -----

struct Lanes {
    ctl: UnixStream,
    media: UnixStream,
    bulk: UnixStream,
}

struct Fake {
    dir: PathBuf,
    sock: PathBuf,
    done: Option<mpsc::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for Fake {
    fn drop(&mut self) {
        drop(self.done.take());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn info(codecs: &[VideoCodec]) -> pb::Info {
    pb::Info {
        software: "fake-session".into(),
        features: 0x302,
        codecs: codecs.iter().map(|c| *c as i32).collect(),
        display: Some(pb::Display {
            width: 1920,
            height: 1080,
        }),
        max_fps: 60,
    }
}

fn ctl_frame(m: pb::session_to_gateway::Message) -> Vec<u8> {
    // Encoded without the sender-side validation, so tests can send what a hostile session would.
    let msg = pb::SessionToGateway { message: Some(m) };
    encode_frame(KIND_SESSION_TO_GATEWAY, &msg.encode_to_vec(), 327_685).unwrap()
}

fn accept_lane(l: &UnixListener, minor: u8, major: u8) -> (UnixStream, ClientPreamble) {
    let (s, _) = l.accept().unwrap();
    answer_lane_with(s, minor, major)
}

fn answer_lane(s: UnixStream, minor: u8, major: u8) -> UnixStream {
    answer_lane_with(s, minor, major).0
}

fn answer_lane_with(mut s: UnixStream, minor: u8, major: u8) -> (UnixStream, ClientPreamble) {
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut b = [0u8; CLIENT_PREAMBLE_LEN];
    s.read_exact(&mut b).unwrap();
    let cp = ClientPreamble::decode(&b).unwrap();
    let mut answer = Preamble {
        major,
        minor: cp.preamble.minor.min(minor),
        lane: cp.preamble.lane,
    }
    .encode();
    answer[4] = major;
    s.write_all(&answer).unwrap();
    (s, cp)
}

/// A fake session whose `script` runs after a normal handshake (`info` sent, three lanes up).
/// The lanes stay open until the returned [`Fake`] is dropped.
fn session(first_ctl: Option<Vec<u8>>, script: impl FnOnce(&mut Lanes) + Send + 'static) -> Fake {
    let dir = std::env::temp_dir().join(format!(
        "hx-link-hostile-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("link.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let (done_tx, done_rx) = mpsc::channel::<()>();
    listener.set_nonblocking(true).unwrap();
    let thread = std::thread::spawn(move || {
        // Accepting polls, so a client that never opens the next lane cannot hang the test.
        let accept = |done: &mpsc::Receiver<()>| -> Option<UnixStream> {
            loop {
                match listener.accept() {
                    Ok((s, _)) => {
                        s.set_nonblocking(false).unwrap();
                        return Some(answer_lane(s, 0, 1));
                    }
                    Err(_) => {
                        if matches!(done.try_recv(), Err(mpsc::TryRecvError::Disconnected)) {
                            return None;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
            }
        };
        let Some(mut ctl) = accept(&done_rx) else {
            return;
        };
        let first = first_ctl.unwrap_or_else(|| {
            ctl_frame(pb::session_to_gateway::Message::Info(info(&[
                VideoCodec::H264,
            ])))
        });
        ctl.write_all(&first).unwrap();
        let Some(media) = accept(&done_rx) else {
            return;
        };
        let Some(bulk) = accept(&done_rx) else {
            return;
        };
        let mut lanes = Lanes { ctl, media, bulk };
        script(&mut lanes);
        let _ = done_rx.recv_timeout(Duration::from_secs(30));
    });
    Fake {
        dir,
        sock,
        done: Some(done_tx),
        thread: Some(thread),
    }
}

async fn connect(f: &Fake) -> (LinkClient, LinkEvents) {
    connect_with(f, |_| {}).await
}

async fn connect_with(f: &Fake, tweak: impl FnOnce(&mut LinkConfig)) -> (LinkClient, LinkEvents) {
    let mut cfg = LinkConfig::default();
    tweak(&mut cfg);
    LinkClient::connect(&f.sock, cfg).await.expect("connect")
}

fn start_config() -> pb::StreamConfig {
    pb::StreamConfig {
        codec: VideoCodec::H264 as i32,
        ..pb::StreamConfig::default()
    }
}

/// Waits for the final event and checks the classification and a fragment of the reason.
async fn closed(ev: &mut LinkEvents, class: FailureClass, fragment: &str, within: Duration) {
    let end = Instant::now() + within;
    loop {
        let left = end.saturating_duration_since(Instant::now());
        if let LinkEvent::Closed(c) = timeout(left, ev.next()).await.expect("the link must end") {
            assert_eq!(c.class, class, "{c:?}");
            assert!(
                c.detail.contains(fragment),
                "reason {:?} should mention {fragment:?}",
                c.detail
            );
            // The reason is sanitised text: no control characters.
            assert!(!c.detail.chars().any(char::is_control));
            return;
        }
    }
}

// ----- builders -----

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

fn p_payload(extra: usize) -> Vec<u8> {
    let mut p = vec![0, 0, 0, 1, 0x41, 0x9A];
    p.resize(p.len() + extra, 0xAA);
    p
}

/// A whole media-lane video frame.
fn video(number: u32, flags: u16, codec: u8, payload: &[u8]) -> Vec<u8> {
    let mut h = vec![1u8, codec];
    h.extend(flags.to_le_bytes());
    h.extend(number.to_le_bytes());
    h.extend(1_000u64.to_le_bytes());
    h.extend((payload.len() as u32).to_le_bytes());
    let mut body = h;
    body.extend(payload);
    encode_frame(KIND_VIDEO, &body, 4 * 1024 * 1024 + 21).unwrap()
}

fn stream_format(epoch: u32, first: u32) -> Vec<u8> {
    ctl_frame(pb::session_to_gateway::Message::StreamFormat(
        pb::StreamFormat {
            epoch,
            codec: VideoCodec::H264 as i32,
            width: 1920,
            height: 1080,
            fps: 60,
            first_frame: first,
        },
    ))
}

fn open(id: u32, channel: pb::TransferChannel, name: &str, size: u64) -> Vec<u8> {
    let o = pb::TransferOpen {
        id,
        channel: channel as i32,
        header: Some(TransferHeader {
            mime: "application/octet-stream".into(),
            name: name.into(),
            size,
        }),
    };
    encode_frame(KIND_TRANSFER_OPEN, &o.encode_to_vec(), 4_200).unwrap()
}

fn data(id: u32, bytes: &[u8]) -> Vec<u8> {
    let mut b = id.to_le_bytes().to_vec();
    b.extend(bytes);
    encode_frame(KIND_TRANSFER_DATA, &b, 65_541).unwrap()
}

fn end(id: u32) -> Vec<u8> {
    encode_frame(KIND_TRANSFER_END, &id.to_le_bytes(), 5).unwrap()
}

/// Reads whatever the gateway sent on `ctl` within `within`, decoded.
fn gateway_messages(s: &mut UnixStream, within: Duration) -> Vec<pb::GatewayToSession> {
    use hx_ipc::link::frames::{LinkFrame, parse};
    let policy = LinkPolicy::new(Role::Session, Lane::Ctl);
    let mut d = Decoder::new(policy);
    let end = Instant::now() + within;
    let mut out = Vec::new();
    s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
    while Instant::now() < end {
        match d.read_from(&mut NoCmsgReader(&*s)) {
            Ok(Some(raw)) => {
                if let Ok(LinkFrame::FromGateway(m)) = parse(&policy, raw, u64::MAX) {
                    out.push(m);
                }
            }
            Ok(None) => break,
            Err(hx_ipc::ReadError::Io(e))
                if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => break,
        }
    }
    out
}

async fn next_frame(ev: &mut LinkEvents) -> hx_agent::link::Frame {
    loop {
        if let LinkEvent::Frame(f) = timeout(Duration::from_secs(5), ev.next()).await.unwrap() {
            return f;
        }
    }
}

// ----- handshake -----

#[tokio::test(flavor = "multi_thread")]
async fn preamble_and_info_failures_are_classified() {
    // Rule: a session that never answers is "unavailable" within the 5 s (here 1 s) timeout.
    let dir = std::env::temp_dir().join(format!("hx-link-hostile-pre-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("silent.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let t0 = Instant::now();
    let cfg = LinkConfig {
        handshake_timeout: Duration::from_secs(1),
        ..LinkConfig::default()
    };
    let err: ConnectError = LinkClient::connect(&sock, cfg.clone()).await.err().unwrap();
    assert_eq!(err.class, FailureClass::Unavailable);
    assert!(t0.elapsed() < Duration::from_secs(3));
    drop(listener);

    // A reset right after accept (the proxy could not reach the container) is unavailable.
    let sock2 = dir.join("reset.sock");
    let listener = UnixListener::bind(&sock2).unwrap();
    let t = std::thread::spawn(move || {
        let (s, _) = listener.accept().unwrap();
        drop(s);
    });
    let err = LinkClient::connect(&sock2, cfg).await.err().unwrap();
    assert_eq!(err.class, FailureClass::Unavailable);
    t.join().unwrap();

    // Rule: a different major in the answer means "session outdated".
    let sock3 = dir.join("major.sock");
    let listener = UnixListener::bind(&sock3).unwrap();
    let t = std::thread::spawn(move || {
        let _ = accept_lane(&listener, 0, 2);
    });
    let err = LinkClient::connect(&sock3, LinkConfig::default())
        .await
        .err()
        .unwrap();
    assert_eq!(err.class, FailureClass::Outdated);
    t.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    // Rule: the first ctl message must be info.
    let f = session(
        Some(ctl_frame(pb::session_to_gateway::Message::Pong(pb::Pong {
            nonce: 1,
        }))),
        |_| {},
    );
    let err = LinkClient::connect(&f.sock, LinkConfig::default())
        .await
        .err()
        .unwrap();
    assert_eq!(err.class, FailureClass::Violation);

    // Rule: codec intersection. A session offering nothing the gateway accepts is incompatible.
    let f = session(
        Some(ctl_frame(pb::session_to_gateway::Message::Info(info(&[
            VideoCodec::Av1,
        ])))),
        |_| {},
    );
    let err = LinkClient::connect(&f.sock, LinkConfig::default())
        .await
        .err()
        .unwrap();
    assert_eq!(err.class, FailureClass::Incompatible);

    // The negotiated set is the intersection, and text is sanitised.
    let mut i = info(&[VideoCodec::Av1, VideoCodec::H264, VideoCodec::H264]);
    i.software = "evil\x1b[31m\u{202e}name".into();
    let f = session(
        Some(ctl_frame(pb::session_to_gateway::Message::Info(i))),
        |_| {},
    );
    let (link, _ev) = connect(&f).await;
    assert_eq!(link.info().codecs, [VideoCodec::H264]);
    assert_eq!(link.info().software, "evil[31mname");

    // Rule: an invalid info (display 0, too many codecs, software over 128 bytes) is a violation.
    for bad in [
        pb::Info {
            display: Some(pb::Display {
                width: 0,
                height: 5,
            }),
            ..info(&[VideoCodec::H264])
        },
        pb::Info {
            codecs: vec![1; 5],
            ..info(&[])
        },
        pb::Info {
            software: "x".repeat(129),
            ..info(&[VideoCodec::H264])
        },
    ] {
        let f = session(
            Some(ctl_frame(pb::session_to_gateway::Message::Info(bad))),
            |_| {},
        );
        let err = LinkClient::connect(&f.sock, LinkConfig::default())
            .await
            .err()
            .unwrap();
        assert_eq!(err.class, FailureClass::Violation);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_info_is_a_violation() {
    let f = session(None, |l| {
        std::thread::sleep(Duration::from_millis(200));
        l.ctl
            .write_all(&ctl_frame(pb::session_to_gateway::Message::Info(info(&[
                VideoCodec::H264,
            ]))))
            .unwrap();
    });
    let (_link, mut ev) = connect(&f).await;
    closed(
        &mut ev,
        FailureClass::Violation,
        "second info",
        Duration::from_secs(5),
    )
    .await;
}

// ----- framing and limits -----

#[tokio::test(flavor = "multi_thread")]
async fn oversize_frames_are_refused_before_their_body_is_read() {
    // ctl: one byte over the 327 685 limit.
    let f = session(None, |l| {
        let mut w = 327_686u32.to_le_bytes().to_vec();
        w.push(KIND_SESSION_TO_GATEWAY);
        l.ctl.write_all(&w).unwrap();
    });
    let (_l, mut ev) = connect(&f).await;
    closed(
        &mut ev,
        FailureClass::Violation,
        "exceeds the limit",
        Duration::from_secs(5),
    )
    .await;

    // media: above max_frame_bytes + 21 (the body is never sent: refused at the prefix).
    let f = session(None, |l| {
        let mut w = (4 * 1024 * 1024u32 + 22).to_le_bytes().to_vec();
        w.push(KIND_VIDEO);
        l.media.write_all(&w).unwrap();
    });
    let (_l, mut ev) = connect(&f).await;
    closed(
        &mut ev,
        FailureClass::Violation,
        "exceeds the limit",
        Duration::from_secs(5),
    )
    .await;

    // A zero length, an unknown kind and a kind from the wrong lane.
    for (lane_media, bytes) in [
        (false, vec![0, 0, 0, 0, 1]),
        (false, vec![1, 0, 0, 0, 0x7f]),
        (false, vec![1, 0, 0, 0, KIND_VIDEO]),
        (true, vec![1, 0, 0, 0, KIND_SESSION_TO_GATEWAY]),
    ] {
        let f = session(None, move |l| {
            let s = if lane_media { &mut l.media } else { &mut l.ctl };
            s.write_all(&bytes).unwrap();
        });
        let (_l, mut ev) = connect(&f).await;
        closed(&mut ev, FailureClass::Violation, "", Duration::from_secs(5)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_descriptor_sent_with_scm_rights_is_a_violation() {
    use std::io::IoSlice;
    use std::mem::MaybeUninit;
    use std::os::fd::AsFd;
    let f = session(None, |l| {
        let null = std::fs::File::open("/dev/null").unwrap();
        let fds = [null.as_fd()];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = rustix::net::SendAncillaryBuffer::new(&mut space);
        assert!(control.push(rustix::net::SendAncillaryMessage::ScmRights(&fds)));
        let wire = ctl_frame(pb::session_to_gateway::Message::Pong(pb::Pong { nonce: 7 }));
        rustix::net::sendmsg(
            &l.ctl,
            &[IoSlice::new(&wire)],
            &mut control,
            rustix::net::SendFlags::empty(),
        )
        .unwrap();
    });
    let (_l, mut ev) = connect(&f).await;
    closed(
        &mut ev,
        FailureClass::Violation,
        "ancillary",
        Duration::from_secs(5),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_flood_of_tiny_frames_hits_the_frame_count_limit() {
    // 2 500 valid, tiny cancel_frames messages in one burst: more than the 2 000 frames per
    // second the gateway accepts on ctl, although a few hundred kilobytes is far under the byte
    // budget.
    let f = session(None, |l| {
        let one = ctl_frame(pb::session_to_gateway::Message::CancelFrames(
            pb::CancelFrames { up_to_frame: 1 },
        ));
        let burst: Vec<u8> = one
            .iter()
            .copied()
            .cycle()
            .take(one.len() * 2_500)
            .collect();
        l.ctl.write_all(&burst).unwrap();
    });
    let (_l, mut ev) = connect(&f).await;
    closed(
        &mut ev,
        FailureClass::Violation,
        "frame-count",
        Duration::from_secs(5),
    )
    .await;

    // The same on bulk (2 048 per second): tiny aborts for unknown, never-opened ids.
    let f = session(None, |l| {
        let one = encode_frame(KIND_TRANSFER_ABORT, &[2, 0, 0, 0, 0, 1, 0, 0], 9).unwrap();
        let burst: Vec<u8> = one
            .iter()
            .copied()
            .cycle()
            .take(one.len() * 2_300)
            .collect();
        l.bulk.write_all(&burst).unwrap();
    });
    let (_l, mut ev) = connect(&f).await;
    closed(
        &mut ev,
        FailureClass::Violation,
        "frame-count",
        Duration::from_secs(5),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn frames_of_unknown_variants_are_counted_and_a_flood_is_a_violation() {
    // An empty SessionToGateway decodes to no variant: ignored and counted, 10 per second.
    let empty = encode_frame(KIND_SESSION_TO_GATEWAY, &[], 327_685);
    // A zero-length body is a valid empty message (length 1: kind only).
    let empty = empty.unwrap();
    let e2 = empty.clone();
    let f = session(None, move |l| {
        for _ in 0..5 {
            l.ctl.write_all(&e2).unwrap();
        }
    });
    let (link, ev) = connect(&f).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(link.counters().unknown_variants, 5);
    assert!(!link.is_closed());
    drop(ev);
    let e3 = empty;
    let f = session(None, move |l| {
        for _ in 0..40 {
            l.ctl.write_all(&e3).unwrap();
        }
    });
    let (_l, mut ev) = connect(&f).await;
    closed(
        &mut ev,
        FailureClass::Violation,
        "unknown variants",
        Duration::from_secs(5),
    )
    .await;
}

// ----- timeouts -----

#[tokio::test(flavor = "multi_thread")]
async fn a_slow_reader_hits_the_idle_and_body_timeouts() {
    // Idle: nothing on ctl for the liveness timeout (1 s here) is a fault.
    let f = session(None, |_| {});
    let (_l, mut ev) = connect_with(&f, |c| c.liveness_timeout = Duration::from_secs(1)).await;
    closed(
        &mut ev,
        FailureClass::Fault,
        "liveness",
        Duration::from_secs(5),
    )
    .await;

    // Body: the prefix of a 100-byte frame, ten bytes, then silence. The frame has 5 s (plus a
    // little for its size) to arrive; the liveness timeout is not what ends this link.
    let f = session(None, |l| {
        let mut w = 101u32.to_le_bytes().to_vec();
        w.push(KIND_SESSION_TO_GATEWAY);
        w.extend([0u8; 10]);
        l.ctl.write_all(&w).unwrap();
    });
    let t0 = Instant::now();
    let (_l, mut ev) = connect(&f).await;
    closed(
        &mut ev,
        FailureClass::Violation,
        "timed out",
        Duration::from_secs(15),
    )
    .await;
    let took = t0.elapsed();
    assert!(
        took >= Duration::from_secs(4) && took < Duration::from_secs(9),
        "{took:?}"
    );
}

// ----- media -----

#[tokio::test(flavor = "multi_thread")]
async fn media_validation_and_monotonic_frame_numbers() {
    let f = session(None, |l| {
        std::thread::sleep(Duration::from_millis(300));
        l.ctl.write_all(&stream_format(1, 100)).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let w = [
            video(100, 1 | 2, 1, &key_payload()), // a RESYNC IDR
            video(101, 0, 1, &p_payload(50)),
            video(101, 0, 1, &p_payload(50)), // a repeat: not newer, dropped
            video(99, 0, 1, &p_payload(50)),  // older: dropped
            video(102, 0, 1, &p_payload(50)),
        ]
        .concat();
        l.media.write_all(&w).unwrap();
    });
    let (link, mut ev) = connect(&f).await;
    link.start(1, start_config()).unwrap();
    let mut numbers = Vec::new();
    while numbers.len() < 3 {
        if let LinkEvent::Frame(fr) = timeout(Duration::from_secs(5), ev.next()).await.unwrap() {
            assert_eq!(
                (fr.format.width, fr.format.height, fr.format.epoch),
                (1920, 1080, 1)
            );
            numbers.push((fr.number(), fr.is_key(), fr.is_resync()));
        }
    }
    assert_eq!(
        numbers,
        [(100, true, true), (101, false, false), (102, false, false)]
    );
    assert_eq!(
        link.counters().stale_frames,
        2,
        "non-monotonic frame numbers are dropped, counted"
    );
    assert!(!link.is_closed());
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_bitstreams_are_violations() {
    // (what the frame carries, expected fragment of the reason)
    let cases: Vec<(Vec<u8>, &str)> = vec![
        (vec![0x12, 0x34, 0x56, 0x78, 0x9A], "start code"),
        (vec![0, 0, 1], "empty NAL"),
        (vec![0, 0, 1, 0x81, 0, 0], "forbidden_zero_bit"),
        (vec![0, 0, 1, 0x41, 0xAA, 0, 0, 1, 0x1F, 0], "NAL unit type"),
        // A key frame without an SPS.
        (vec![0, 0, 0, 1, 0x65, 0x88, 0x84, 0x00], "SPS"),
    ];
    for (payload, fragment) in cases {
        let f = session(None, move |l| {
            std::thread::sleep(Duration::from_millis(300));
            l.ctl.write_all(&stream_format(1, 0)).unwrap();
            std::thread::sleep(Duration::from_millis(100));
            l.media.write_all(&video(0, 1 | 2, 1, &payload)).unwrap();
        });
        let (link, mut ev) = connect(&f).await;
        link.start(1, start_config()).unwrap();
        closed(
            &mut ev,
            FailureClass::Violation,
            fragment,
            Duration::from_secs(5),
        )
        .await;
    }
}

/// An SPS builder for sizes the encoder would never produce.
fn sps_for(width_mbs: u32, height_units: u32) -> Vec<u8> {
    let mut bits: Vec<u8> = Vec::new();
    let put = |bits: &mut Vec<u8>, v: u64, n: u32| {
        for i in (0..n).rev() {
            bits.push(((v >> i) & 1) as u8);
        }
    };
    let ue = |bits: &mut Vec<u8>, v: u32| {
        let x = u64::from(v) + 1;
        let len = 64 - x.leading_zeros();
        for _ in 0..len - 1 {
            bits.push(0);
        }
        for i in (0..len).rev() {
            bits.push(((x >> i) & 1) as u8);
        }
    };
    put(&mut bits, 66, 8); // baseline
    put(&mut bits, 0, 8);
    put(&mut bits, 40, 8);
    ue(&mut bits, 0); // sps id
    ue(&mut bits, 0); // log2_max_frame_num_minus4
    ue(&mut bits, 2); // poc type 2
    ue(&mut bits, 1); // max refs
    put(&mut bits, 0, 1);
    ue(&mut bits, width_mbs - 1);
    ue(&mut bits, height_units - 1);
    put(&mut bits, 1, 1); // frame_mbs_only
    put(&mut bits, 1, 1); // direct 8x8
    put(&mut bits, 0, 1); // no crop
    put(&mut bits, 0, 1); // no vui
    bits.push(1);
    while !bits.len().is_multiple_of(8) {
        bits.push(0);
    }
    let mut out = vec![0, 0, 0, 1, 0x67];
    let mut zeros = 0;
    for c in bits.chunks(8) {
        let b = c.iter().fold(0u8, |a, x| (a << 1) | x);
        if zeros >= 2 && b <= 3 {
            out.push(3);
            zeros = 0;
        }
        zeros = if b == 0 { zeros + 1 } else { 0 };
        out.push(b);
    }
    out.extend([0, 0, 1, 0x65, 0x88]);
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn sps_dimensions_over_the_limit_or_unlike_stream_format_are_violations() {
    // 8 192 x 8 192: inside the side limit, above the 7680 x 4320 pixel cap. The stream_format
    // announced is legal (1920x1080), so the SPS is what is wrong.
    let big = sps_for(512, 512);
    let f = session(None, move |l| {
        std::thread::sleep(Duration::from_millis(300));
        l.ctl.write_all(&stream_format(1, 0)).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        l.media.write_all(&video(0, 1 | 2, 1, &big)).unwrap();
    });
    let (link, mut ev) = connect(&f).await;
    link.start(1, start_config()).unwrap();
    closed(
        &mut ev,
        FailureClass::Violation,
        "exceeds the limit",
        Duration::from_secs(5),
    )
    .await;

    // A legal SPS (1280x720) that does not equal the announced 1920x1080.
    let small = sps_for(80, 45);
    let f = session(None, move |l| {
        std::thread::sleep(Duration::from_millis(300));
        l.ctl.write_all(&stream_format(1, 0)).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        l.media.write_all(&video(0, 1 | 2, 1, &small)).unwrap();
    });
    let (link, mut ev) = connect(&f).await;
    link.start(1, start_config()).unwrap();
    closed(
        &mut ev,
        FailureClass::Violation,
        "stream_format says",
        Duration::from_secs(5),
    )
    .await;

    // The honest SPS of the announced size passes.
    let ok = sps_for(120, 68); // 1920 x 1088, no crop: so announce 1920x1088 instead
    let f = session(None, move |l| {
        std::thread::sleep(Duration::from_millis(300));
        let sf = ctl_frame(pb::session_to_gateway::Message::StreamFormat(
            pb::StreamFormat {
                epoch: 1,
                codec: VideoCodec::H264 as i32,
                width: 1920,
                height: 1088,
                fps: 60,
                first_frame: 0,
            },
        ));
        l.ctl.write_all(&sf).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        l.media.write_all(&video(0, 1 | 2, 1, &ok)).unwrap();
    });
    let (link, mut ev) = connect(&f).await;
    link.start(1, start_config()).unwrap();
    loop {
        if let LinkEvent::Frame(fr) = timeout(Duration::from_secs(5), ev.next()).await.unwrap() {
            assert!(fr.is_key());
            break;
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn audio_a_codec_not_negotiated_and_a_missing_stream_format_are_violations() {
    // Audio is reserved: a 0x11 frame while it was not negotiated.
    let f = session(None, |l| {
        let mut body = 1u32.to_le_bytes().to_vec();
        body.extend(1u32.to_le_bytes());
        body.extend([0xAA; 20]);
        l.media
            .write_all(&encode_frame(KIND_AUDIO, &body, 1_110).unwrap())
            .unwrap();
    });
    let (_l, mut ev) = connect(&f).await;
    closed(
        &mut ev,
        FailureClass::Violation,
        "audio",
        Duration::from_secs(5),
    )
    .await;

    // A frame in AV1 when only H.264 was negotiated.
    let f = session(None, |l| {
        l.media.write_all(&video(0, 0, 2, &p_payload(10))).unwrap();
    });
    let (_l, mut ev) = connect(&f).await;
    closed(
        &mut ev,
        FailureClass::Violation,
        "codec",
        Duration::from_secs(5),
    )
    .await;

    // A reserved flag bit, a bad header version and a payload_len that disagrees with the length.
    let mutations: [fn(&mut Vec<u8>); 3] = [|w| w[5 + 2] |= 0x80, |w| w[5] = 9, |w| w[5 + 16] += 1];
    for mutate in mutations {
        let mut w = video(0, 0, 1, &p_payload(10));
        mutate(&mut w);
        let f = session(None, move |l| {
            l.media.write_all(&w).unwrap();
        });
        let (_l, mut ev) = connect(&f).await;
        closed(&mut ev, FailureClass::Violation, "", Duration::from_secs(5)).await;
    }

    // A frame with no stream_format at all.
    let f = session(None, |l| {
        l.media.write_all(&video(0, 0, 1, &p_payload(10))).unwrap();
    });
    let (link, mut ev) = connect(&f).await;
    // The fake writes at once, so the link may already be closed when this runs: both fine.
    let _ = link.start(1, start_config());
    closed(
        &mut ev,
        FailureClass::Violation,
        "stream_format",
        Duration::from_secs(5),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_slow_consumer_never_pauses_the_session_and_the_pool_is_bounded() {
    // 30 one-MiB frames: far more than the 12 MiB pool. The fake's writes must all complete (the
    // media lane is always drained) while the consumer reads nothing.
    let (tx, rx) = mpsc::channel::<Instant>();
    let f = session(None, move |l| {
        std::thread::sleep(Duration::from_millis(300));
        l.ctl.write_all(&stream_format(1, 0)).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let t0 = Instant::now();
        let mut w = video(0, 1 | 2, 1, &key_payload());
        for n in 1..30u32 {
            w.extend(video(n, 0, 1, &p_payload(1024 * 1024)));
        }
        l.media.write_all(&w).unwrap();
        tx.send(t0).unwrap();
        // The gateway must have asked for a fresh image and reported what it dropped.
        let msgs = gateway_messages(&mut l.ctl, Duration::from_secs(2));
        let idr = msgs.iter().any(|m| {
            matches!(
                m.message,
                Some(pb::gateway_to_session::Message::RequestIdr(_))
            )
        });
        let dropped: usize = msgs
            .iter()
            .filter_map(|m| match &m.message {
                Some(pb::gateway_to_session::Message::FrameFeedback(f)) => Some(
                    f.results
                        .iter()
                        .filter(|r| r.outcome == pb::FrameOutcome::Dropped as i32)
                        .count(),
                ),
                _ => None,
            })
            .sum();
        assert!(idr, "an IDR request follows a drop");
        assert!(dropped >= 1, "dropped frames are reported");
    });
    let (link, mut ev) = connect(&f).await;
    link.start(1, start_config()).unwrap();
    let t0 = timeout(
        Duration::from_secs(20),
        tokio::task::spawn_blocking(move || rx.recv().unwrap()),
    )
    .await
    .expect("all frames written: the lane is drained")
    .unwrap();
    assert!(t0.elapsed() < Duration::from_secs(20));
    tokio::time::sleep(Duration::from_millis(300)).await;
    let pool = 12 * 1024 * 1024;
    assert!(
        link.queued_video_bytes() <= pool,
        "{}",
        link.queued_video_bytes()
    );
    let c = link.counters();
    assert!(c.evicted_frames >= 1, "{c:?}");
    assert!(c.discarded_frames >= 1, "{c:?}");
    assert!(!link.is_closed());
    // What is still queued can be read; nothing newer than the gate lets through.
    let first = next_frame(&mut ev).await;
    assert!(first.number() < 30);
    drop(ev);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_gateway_never_writes_on_the_media_lane() {
    let (tx, rx) = mpsc::channel::<usize>();
    let f = session(None, move |l| {
        l.media
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut seen = 0;
        let end = Instant::now() + Duration::from_millis(1_500);
        let mut b = [0u8; 64];
        while Instant::now() < end {
            match l.media.read(&mut b) {
                Ok(0) => break,
                Ok(n) => seen += n,
                Err(_) => {}
            }
        }
        tx.send(seen).unwrap();
    });
    let (link, _ev) = connect(&f).await;
    link.start(1, start_config()).unwrap();
    link.request_idr(0).unwrap();
    link.frame_feedback(&[pb::FrameResult {
        frame_number: 1,
        outcome: pb::FrameOutcome::Delivered as i32,
        ..pb::FrameResult::default()
    }])
    .unwrap();
    let seen = tokio::task::spawn_blocking(move || rx.recv().unwrap())
        .await
        .unwrap();
    assert_eq!(seen, 0, "the media lane is silent from the gateway");
}

// ----- ctl message rules -----

#[tokio::test(flavor = "multi_thread")]
async fn range_and_rate_rules_drop_and_count_without_ending_the_link() {
    let f = session(None, |l| {
        std::thread::sleep(Duration::from_millis(300));
        let mut w = Vec::new();
        // stream_format out of range: bad size, bad fps, unknown codec, first_frame far ahead.
        for (width, height, fps, codec) in [
            (0, 10, 60, 1),
            (20_000, 10, 60, 1),
            (64, 64, 0, 1),
            (64, 64, 60, 2),
        ] {
            w.extend(ctl_frame(pb::session_to_gateway::Message::StreamFormat(
                pb::StreamFormat {
                    epoch: 1,
                    codec,
                    width,
                    height,
                    fps,
                    first_frame: 0,
                },
            )));
            // spread them out: the gateway also limits stream_format to 4 per second
            l.ctl.write_all(&w).unwrap();
            w.clear();
            std::thread::sleep(Duration::from_millis(300));
        }
        // cancel_frames with nothing received yet: ignored.
        l.ctl
            .write_all(&ctl_frame(pb::session_to_gateway::Message::CancelFrames(
                pb::CancelFrames { up_to_frame: 5 },
            )))
            .unwrap();
        // 30 events in a burst: 10 per second are kept, the rest dropped.
        let mut burst = Vec::new();
        for _ in 0..30 {
            burst.extend(ctl_frame(pb::session_to_gateway::Message::Event(
                pb::Event {
                    kind: pb::EventKind::CaptureError as i32,
                    message: "e\x1b[2Jvil".into(),
                },
            )));
        }
        l.ctl.write_all(&burst).unwrap();
        // 12 statistics in a burst: 4 per second.
        let mut burst = Vec::new();
        for _ in 0..12 {
            burst.extend(ctl_frame(pb::session_to_gateway::Message::Stats(
                pb::SessionStats::default(),
            )));
        }
        l.ctl.write_all(&burst).unwrap();
        // 30 cursor shapes of 4 KiB: 20 per second.
        let mut burst = Vec::new();
        for i in 0..30u64 {
            burst.extend(ctl_frame(pb::session_to_gateway::Message::Cursor(
                CursorEvent {
                    event: Some(cursor_event::Event::Shape(CursorShape {
                        id: i,
                        width: 32,
                        height: 32,
                        hotspot_x: 1,
                        hotspot_y: 1,
                        rgba: Bytes::from(vec![0u8; 32 * 32 * 4]),
                    })),
                },
            )));
        }
        l.ctl.write_all(&burst).unwrap();
        // pongs the gateway never asked for.
        for n in 0..3 {
            l.ctl
                .write_all(&ctl_frame(pb::session_to_gateway::Message::Pong(
                    pb::Pong { nonce: 1_000 + n },
                )))
                .unwrap();
        }
    });
    let (link, mut ev) = connect(&f).await;
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    let c = link.counters();
    assert_eq!(c.bad_stream_formats, 4, "{c:?}");
    assert_eq!(c.ignored_cancels, 1, "{c:?}");
    assert_eq!(c.dropped_stats_events, 20 + 8, "{c:?}");
    assert_eq!(c.dropped_shapes, 10, "{c:?}");
    assert_eq!(c.unexpected_pongs, 3, "{c:?}");
    assert!(!link.is_closed(), "overages are dropped, not punished");
    // What got through: 10 events, sanitised; 4 stats; 20 shapes.
    let (mut events, mut stats, mut shapes) = (0, 0, 0);
    while let Ok(e) = timeout(Duration::from_millis(100), ev.next()).await {
        match e {
            LinkEvent::Event(s) => {
                assert_eq!(s.message, "e[2Jvil");
                events += 1;
            }
            LinkEvent::Stats(_) => stats += 1,
            LinkEvent::Cursor(hx_agent::link::CursorUpdate::Shape(_)) => shapes += 1,
            _ => {}
        }
    }
    assert_eq!((events, stats, shapes), (10, 4, 20));
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_cursor_content_is_a_violation_and_too_many_pongs_too() {
    // A shape whose rgba does not match width x height; a hotspot outside the image; a shape
    // above 256 x 256.
    for shape in [
        CursorShape {
            id: 1,
            width: 4,
            height: 4,
            hotspot_x: 0,
            hotspot_y: 0,
            rgba: Bytes::from(vec![0u8; 10]),
        },
        CursorShape {
            id: 1,
            width: 2,
            height: 2,
            hotspot_x: 5,
            hotspot_y: 0,
            rgba: Bytes::from(vec![0u8; 16]),
        },
        CursorShape {
            id: 1,
            width: 300,
            height: 2,
            hotspot_x: 0,
            hotspot_y: 0,
            rgba: Bytes::from(vec![0u8; 2400]),
        },
    ] {
        let f = session(None, move |l| {
            l.ctl
                .write_all(&ctl_frame(pb::session_to_gateway::Message::Cursor(
                    CursorEvent {
                        event: Some(cursor_event::Event::Shape(shape)),
                    },
                )))
                .unwrap();
        });
        let (_l, mut ev) = connect(&f).await;
        closed(&mut ev, FailureClass::Violation, "", Duration::from_secs(5)).await;
    }
    // More than 10 pongs in a second.
    let f = session(None, |l| {
        let mut burst = Vec::new();
        for n in 0..30 {
            burst.extend(ctl_frame(pb::session_to_gateway::Message::Pong(pb::Pong {
                nonce: n,
            })));
        }
        l.ctl.write_all(&burst).unwrap();
    });
    let (_l, mut ev) = connect(&f).await;
    closed(
        &mut ev,
        FailureClass::Violation,
        "pongs",
        Duration::from_secs(5),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn cancel_frames_is_validated_against_the_newest_frame() {
    let f = session(None, |l| {
        std::thread::sleep(Duration::from_millis(300));
        l.ctl.write_all(&stream_format(1, 10)).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        l.media
            .write_all(&video(10, 1 | 2, 1, &key_payload()))
            .unwrap();
        std::thread::sleep(Duration::from_millis(200));
        for up_to in [11u32, 500, 10u32.wrapping_sub(257)] {
            // newer than newest, and more than 256 behind: both ignored
            l.ctl
                .write_all(&ctl_frame(pb::session_to_gateway::Message::CancelFrames(
                    pb::CancelFrames { up_to_frame: up_to },
                )))
                .unwrap();
            std::thread::sleep(Duration::from_millis(150));
        }
        l.ctl
            .write_all(&ctl_frame(pb::session_to_gateway::Message::CancelFrames(
                pb::CancelFrames { up_to_frame: 10 },
            )))
            .unwrap();
    });
    let (link, mut ev) = connect(&f).await;
    link.start(1, start_config()).unwrap();
    let mut cancel = None;
    while cancel.is_none() {
        if let LinkEvent::CancelFrames { up_to_frame } =
            timeout(Duration::from_secs(5), ev.next()).await.unwrap()
        {
            cancel = Some(up_to_frame);
        }
    }
    assert_eq!(cancel, Some(10));
    assert_eq!(link.counters().ignored_cancels, 3);
}

// ----- bulk -----

#[tokio::test(flavor = "multi_thread")]
async fn transfer_rules() {
    // An id in use is a violation.
    let f = session(None, |l| {
        let mut w = open(2, pb::TransferChannel::File, "a.bin", 10);
        w.extend(open(2, pb::TransferChannel::File, "b.bin", 10));
        l.bulk.write_all(&w).unwrap();
    });
    let (_l, mut ev) = connect(&f).await;
    closed(
        &mut ev,
        FailureClass::Violation,
        "already in use",
        Duration::from_secs(5),
    )
    .await;

    // Data for an unknown id, and an odd id from the session, are violations.
    let f = session(None, |l| {
        l.bulk.write_all(&data(8, b"x")).unwrap();
    });
    let (_l, mut ev) = connect(&f).await;
    closed(
        &mut ev,
        FailureClass::Violation,
        "unknown transfer",
        Duration::from_secs(5),
    )
    .await;
    let f = session(None, |l| {
        l.bulk
            .write_all(&open(3, pb::TransferChannel::File, "a.bin", 10))
            .unwrap();
    });
    let (_l, mut ev) = connect(&f).await;
    closed(&mut ev, FailureClass::Violation, "", Duration::from_secs(5)).await;

    // A file name that is a path, and a clipboard with a name, are violations.
    for (ch, name) in [
        (pb::TransferChannel::File, "../../etc/passwd"),
        (pb::TransferChannel::File, "a/b"),
        (pb::TransferChannel::Clipboard, "named"),
        (pb::TransferChannel::File, ""),
    ] {
        let f = session(None, move |l| {
            l.bulk.write_all(&open(2, ch, name, 10)).unwrap();
        });
        let (_l, mut ev) = connect(&f).await;
        closed(&mut ev, FailureClass::Violation, "", Duration::from_secs(5)).await;
    }

    // A body longer than announced, and one shorter at the end, abort that transfer only; a
    // header above the limit is refused with TRANSFER_REJECTED; policy off is refused too. The
    // lane continues and the fake sees the aborts.
    let (tx, rx) = mpsc::channel::<Vec<(u32, u32)>>();
    let f = session(None, move |l| {
        let mut w = Vec::new();
        w.extend(open(2, pb::TransferChannel::File, "long.bin", 4));
        w.extend(data(2, b"toolong")); // 7 > 4
        w.extend(open(4, pb::TransferChannel::File, "short.bin", 8));
        w.extend(data(4, b"abc"));
        w.extend(end(4)); // 3 < 8
        w.extend(open(6, pb::TransferChannel::File, "huge.bin", 5_000)); // over the 1 000 limit
        w.extend(data(6, b"late")); // in-flight data for a refused id is ignored
        w.extend(open(8, pb::TransferChannel::File, "ok.bin", 3));
        w.extend(data(8, b"abc"));
        w.extend(end(8));
        l.bulk.write_all(&w).unwrap();
        // Collect the abort frames (id, code) the gateway wrote back.
        l.bulk
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut buf = Vec::new();
        let end_at = Instant::now() + Duration::from_secs(2);
        let mut chunk = [0u8; 256];
        while Instant::now() < end_at {
            if let Ok(n) = l.bulk.read(&mut chunk) {
                buf.extend(&chunk[..n]);
            }
        }
        let mut aborts = Vec::new();
        let mut at = 0;
        while at + 13 <= buf.len() {
            // length(4) kind(1) id(4) code(4)
            assert_eq!(buf[at + 4], KIND_TRANSFER_ABORT);
            let id = u32::from_le_bytes(buf[at + 5..at + 9].try_into().unwrap());
            let code = u32::from_le_bytes(buf[at + 9..at + 13].try_into().unwrap());
            aborts.push((id, code));
            at += 13;
        }
        tx.send(aborts).unwrap();
    });
    let (link, mut ev) = connect_with(&f, |c| c.max_file_bytes = 1_000).await;
    let mut got = Vec::new();
    let end_at = Instant::now() + Duration::from_secs(5);
    let mut ended = false;
    while Instant::now() < end_at && !ended {
        match timeout(Duration::from_millis(200), ev.next()).await {
            Ok(LinkEvent::Transfer(t)) => {
                let tag = match &t {
                    TransferEvent::Open { id, .. } => format!("open {id}"),
                    TransferEvent::Data(c) => format!("data {}", c.id),
                    TransferEvent::End { id } => {
                        ended = *id == 8;
                        format!("end {id}")
                    }
                    TransferEvent::Aborted { id, code, outgoing } => {
                        format!("aborted {id} {code:#x} {outgoing}")
                    }
                };
                got.push(tag);
            }
            Ok(LinkEvent::Closed(c)) => panic!("closed: {c:?}"),
            _ => {}
        }
    }
    assert!(!link.is_closed(), "the lane continues: {got:?}");
    assert_eq!(
        got,
        [
            "open 2",
            "aborted 2 0x100 false", // more than announced
            "open 4",
            "data 4",
            "aborted 4 0x100 false", // fewer than announced at the end
            "open 8",
            "data 8",
            "end 8",
        ]
    );
    assert_eq!(link.counters().refused_transfers, 1);
    let aborts = tokio::task::spawn_blocking(move || rx.recv().unwrap())
        .await
        .unwrap();
    assert!(aborts.contains(&(2, 0x100)), "{aborts:?}");
    assert!(aborts.contains(&(4, 0x100)), "{aborts:?}");
    assert!(aborts.contains(&(6, 0x101)), "{aborts:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_transfer_consumer_pauses_bulk_and_never_ctl() {
    // 5 MiB for a transfer nobody consumes: the gateway stops reading `bulk` once about 1 MiB
    // is held unread, so the fake's writes block (kernel buffers full) while ctl keeps flowing.
    // When the consumer lets go, the lane resumes and the whole transfer arrives intact.
    let (tx, rx) = mpsc::channel::<usize>();
    let f = session(None, move |l| {
        l.bulk
            .write_all(&open(
                2,
                pb::TransferChannel::File,
                "big.bin",
                5 * 1024 * 1024,
            ))
            .unwrap();
        l.bulk
            .set_write_timeout(Some(Duration::from_millis(1_500)))
            .unwrap();
        let frame = data(2, &[7u8; 65_536]);
        let (mut off, mut done, mut written, mut blocked) = (0usize, 0usize, 0usize, false);
        while done < 80 {
            match l.bulk.write(&frame[off..]) {
                Ok(n) => {
                    off += n;
                    written += n;
                    if off == frame.len() {
                        off = 0;
                        done += 1;
                    }
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    if blocked {
                        break;
                    }
                    blocked = true;
                    tx.send(written).unwrap();
                    // ctl still works while bulk is paused.
                    let _ = l
                        .ctl
                        .write_all(&ctl_frame(pb::session_to_gateway::Message::Stats(
                            pb::SessionStats::default(),
                        )));
                    l.bulk
                        .set_write_timeout(Some(Duration::from_secs(20)))
                        .unwrap();
                }
                Err(_) => break,
            }
        }
        l.bulk.write_all(&end(2)).unwrap();
        tx.send(done).unwrap();
    });
    let (link, mut ev) = connect_with(&f, |c| c.liveness_timeout = Duration::from_secs(60)).await;
    let (written, rx) = tokio::task::spawn_blocking(move || (rx.recv().unwrap(), rx))
        .await
        .unwrap();
    // The reader took about 1 MiB (plus what fits in the socket buffers), far less than 5 MiB.
    assert!(
        written < 4 * 1024 * 1024,
        "wrote {written}: the lane was not paused"
    );
    // ctl is not held up: the stats event arrives while the chunks are still unread.
    let mut stats = false;
    let mut held = Vec::new();
    let end_at = Instant::now() + Duration::from_secs(5);
    while !stats && Instant::now() < end_at {
        match timeout(Duration::from_millis(200), ev.next()).await {
            Ok(LinkEvent::Stats(_)) => stats = true,
            Ok(LinkEvent::Transfer(TransferEvent::Data(c))) => held.push(c),
            _ => {}
        }
    }
    assert!(stats, "ctl is not held behind bulk");
    let held_bytes: usize = held.iter().map(|c| c.data.len()).sum();
    assert!(
        held_bytes <= 2 * 1024 * 1024,
        "unread data is bounded: {held_bytes}"
    );
    // Releasing the chunks lets the lane resume; nothing is lost.
    let mut total = held_bytes;
    drop(held);
    let mut ended = false;
    let end_at = Instant::now() + Duration::from_secs(20);
    while !ended && Instant::now() < end_at {
        match timeout(Duration::from_millis(500), ev.next()).await {
            Ok(LinkEvent::Transfer(TransferEvent::Data(c))) => total += c.data.len(),
            Ok(LinkEvent::Transfer(TransferEvent::End { id })) => {
                assert_eq!(id, 2);
                ended = true;
            }
            Ok(LinkEvent::Closed(c)) => panic!("closed: {c:?}"),
            _ => {}
        }
    }
    assert!(ended, "the transfer finished after the consumer resumed");
    assert_eq!(total, 5 * 1024 * 1024);
    let done = tokio::task::spawn_blocking(move || rx.recv().unwrap())
        .await
        .unwrap();
    assert_eq!(done, 80);
    assert!(!link.is_closed());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_frame_may_win_the_race_against_its_stream_format() {
    // The lanes race: the media lane can deliver the IDR of a new size before the ctl lane
    // delivers the stream_format that announces it. The key frame waits for it (bounded), it
    // is neither refused nor delivered with the old format.
    let new_sps = sps_for(80, 45); // 1280 x 720
    let f = session(None, move |l| {
        std::thread::sleep(Duration::from_millis(300));
        l.ctl.write_all(&stream_format(1, 0)).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        l.media
            .write_all(&video(0, 1 | 2, 1, &key_payload()))
            .unwrap();
        std::thread::sleep(Duration::from_millis(100));
        // The IDR at the new size first ...
        l.media.write_all(&video(1, 1 | 2, 1, &new_sps)).unwrap();
        std::thread::sleep(Duration::from_millis(400));
        // ... its announcement afterwards.
        let sf = ctl_frame(pb::session_to_gateway::Message::StreamFormat(
            pb::StreamFormat {
                epoch: 1,
                codec: VideoCodec::H264 as i32,
                width: 1280,
                height: 720,
                fps: 60,
                first_frame: 1,
            },
        ));
        l.ctl.write_all(&sf).unwrap();
    });
    let (link, mut ev) = connect(&f).await;
    link.start(1, start_config()).unwrap();
    let first = next_frame(&mut ev).await;
    assert_eq!((first.format.width, first.format.height), (1920, 1080));
    let second = next_frame(&mut ev).await;
    assert_eq!(second.number(), 1);
    assert_eq!((second.format.width, second.format.height), (1280, 720));
    assert!(!link.is_closed());
}

#[tokio::test(flavor = "multi_thread")]
async fn sps_in_a_non_key_frame_is_compared_and_idr_outside_key_is_refused() {
    // Review M1 (c): a frame not flagged KEY that carries an SPS of another size.
    let mut other = sps_for(80, 45); // 1280 x 720
    other.truncate(other.len() - 5); // without the IDR slice sps_for appends
    let f = session(None, move |l| {
        std::thread::sleep(Duration::from_millis(300));
        l.ctl.write_all(&stream_format(1, 0)).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let mut w = video(0, 1 | 2, 1, &key_payload());
        let mut p = other.clone();
        p.extend([0, 0, 1, 0x41, 0x9A, 0x00]);
        w.extend(video(1, 0, 1, &p));
        l.media.write_all(&w).unwrap();
    });
    let (link, mut ev) = connect(&f).await;
    link.start(1, start_config()).unwrap();
    closed(
        &mut ev,
        FailureClass::Violation,
        "stream_format says",
        Duration::from_secs(5),
    )
    .await;

    // An IDR slice in a non-key frame (the reviewer's T3: SPS and IDR) is refused.
    let idr = sps_for(80, 45);
    let f = session(None, move |l| {
        std::thread::sleep(Duration::from_millis(300));
        l.ctl.write_all(&stream_format(1, 0)).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let mut w = video(0, 1 | 2, 1, &key_payload());
        w.extend(video(1, 0, 1, &idr));
        l.media.write_all(&w).unwrap();
    });
    let (link, mut ev) = connect(&f).await;
    link.start(1, start_config()).unwrap();
    closed(
        &mut ev,
        FailureClass::Violation,
        "IDR slice",
        Duration::from_secs(5),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_media_flood_of_large_frames_is_throttled_to_the_budget_and_then_a_violation() {
    // Review M2: 4 MiB frames written as fast as the socket takes them. The media budget is
    // 16 MiB/s with a 32 MiB burst; the debt of every frame is paid before the next is read,
    // so the fake's writes block, and after three seconds of that the link is a violation.
    let (tx, rx) = mpsc::channel::<(u64, Duration)>();
    let f = session(None, move |l| {
        std::thread::sleep(Duration::from_millis(300));
        l.ctl.write_all(&stream_format(1, 0)).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        l.media
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let t0 = Instant::now();
        let mut written = 0u64;
        let first = video(0, 1 | 2, 1, &key_payload());
        l.media.write_all(&first).unwrap();
        let mut n = 1u32;
        'flood: while t0.elapsed() < Duration::from_secs(12) {
            let frame = video(n, 0, 1, &p_payload(4 * 1024 * 1024 - 64));
            let mut off = 0;
            while off < frame.len() {
                match l.media.write(&frame[off..]) {
                    Ok(0) => break 'flood,
                    Ok(k) => {
                        off += k;
                        written += k as u64;
                    }
                    Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                        // A stalled write is the backpressure working; keep pushing.
                        if t0.elapsed() > Duration::from_secs(12) {
                            break 'flood;
                        }
                    }
                    Err(_) => break 'flood, // the gateway closed the link
                }
            }
            n += 1;
        }
        tx.send((written, t0.elapsed())).unwrap();
    });
    let (link, mut ev) = connect_with(&f, |c| c.liveness_timeout = Duration::from_secs(60)).await;
    link.start(1, start_config()).unwrap();
    closed(
        &mut ev,
        FailureClass::Violation,
        "byte budget",
        Duration::from_secs(12),
    )
    .await;
    let (written, took) = tokio::task::spawn_blocking(move || rx.recv().unwrap())
        .await
        .unwrap();
    let mib = 1024 * 1024u64;
    // Burst (32 MiB) plus the rate over the time it took, plus what the kernel buffers hold and
    // one frame of overshoot. Line speed would be gigabytes.
    let bound = 32 * mib + 16 * mib * took.as_secs().max(1) + 24 * mib;
    assert!(
        written <= bound,
        "wrote {} MiB in {took:?}: the budget did not throttle",
        written / mib
    );
}
