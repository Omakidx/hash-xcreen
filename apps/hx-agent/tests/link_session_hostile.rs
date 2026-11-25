//! The session end against a hostile gateway: raw sockets that break the contract, against the
//! real `hx-session` link server under a private Xvfb (`HX_REQUIRE_XVFB=1` makes a missing Xvfb
//! a failure). The link must close, the daemon must keep listening, and nothing may be left
//! behind.

#[path = "../../../crates/hx-capture/tests/common/mod.rs"]
mod common;

use common::Xvfb;
use hx_ipc::frame::encode_frame;
use hx_ipc::link::preamble::{CLIENT_PREAMBLE_LEN, ClientPreamble, Preamble};
use hx_ipc::link::{
    KIND_GATEWAY_TO_SESSION, KIND_SESSION_TO_GATEWAY, KIND_TRANSFER_DATA, KIND_TRANSFER_OPEN, Lane,
    pb,
};
use hx_proto::pb::TransferHeader;
use hx_session::link::{Server, ServerHandle, SessionConfig};
use prost::Message;
use std::io::{IoSlice, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering::SeqCst};
use std::time::{Duration, Instant};

static NEXT: AtomicU32 = AtomicU32::new(0);

struct Env {
    _x: Xvfb,
    dir: PathBuf,
    sock: PathBuf,
    server: Option<ServerHandle>,
}

impl Env {
    fn start(tweak: impl FnOnce(&mut SessionConfig)) -> Option<Env> {
        let x = Xvfb::start(640, 360)?;
        let dir = std::env::temp_dir().join(format!(
            "hx-link-sh-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("link.sock");
        let mut cfg = SessionConfig::new(Some(x.display.clone()));
        cfg.received_dir = dir.join("received");
        cfg.clipboard = None;
        cfg.pipeline.encoder.threads = 2;
        tweak(&mut cfg);
        let server = Server::bind(&sock, cfg).unwrap().spawn();
        Some(Env {
            _x: x,
            dir,
            sock,
            server: Some(server),
        })
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        drop(self.server.take());
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

struct Raw {
    ctl: UnixStream,
    media: UnixStream,
    bulk: UnixStream,
}

fn raw_lane(sock: &Path, lane: Lane, link_id: [u8; 16]) -> UnixStream {
    let mut s = UnixStream::connect(sock).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let offer = ClientPreamble {
        preamble: Preamble::ours(lane),
        link_id,
    }
    .encode();
    assert_eq!(offer.len(), CLIENT_PREAMBLE_LEN);
    s.write_all(&offer).unwrap();
    let mut answer = [0u8; 8];
    s.read_exact(&mut answer).unwrap();
    assert_eq!(&answer[..4], b"HXLK");
    s
}

/// One whole `ctl` frame from the session: (kind, body).
fn read_frame(s: &mut UnixStream) -> (u8, Vec<u8>) {
    let mut head = [0u8; 5];
    s.read_exact(&mut head).unwrap();
    let len = u32::from_le_bytes([head[0], head[1], head[2], head[3]]) as usize;
    let mut body = vec![0u8; len - 1];
    s.read_exact(&mut body).unwrap();
    (head[4], body)
}

fn raw_link(sock: &Path, link_id: [u8; 16]) -> Raw {
    let mut ctl = raw_lane(sock, Lane::Ctl, link_id);
    // The session's first message is `info`.
    let (kind, _) = read_frame(&mut ctl);
    assert_eq!(kind, KIND_SESSION_TO_GATEWAY);
    let media = raw_lane(sock, Lane::Media, link_id);
    let bulk = raw_lane(sock, Lane::Bulk, link_id);
    Raw { ctl, media, bulk }
}

/// True if the peer closes the stream within `within`.
fn closes(s: &mut UnixStream, within: Duration) -> bool {
    s.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let end = Instant::now() + within;
    let mut b = [0u8; 4096];
    while Instant::now() < end {
        match s.read(&mut b) {
            Ok(0) => return true,
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return true,
        }
    }
    false
}

fn gw_frame(m: pb::gateway_to_session::Message) -> Vec<u8> {
    let msg = pb::GatewayToSession { message: Some(m) };
    encode_frame(KIND_GATEWAY_TO_SESSION, &msg.encode_to_vec(), 16_384).unwrap()
}

/// Starts streaming with file transfers enabled (the policy is switched on by `start`), and
/// gives the engine a moment to apply it.
fn start_stream(ctl: &mut UnixStream) {
    ctl.write_all(&gw_frame(pb::gateway_to_session::Message::Start(
        pb::Start {
            epoch: 1,
            config: Some(pb::StreamConfig {
                codec: hx_proto::VideoCodec::H264 as i32,
                file_transfer_enabled: true,
                ..pb::StreamConfig::default()
            }),
        },
    )))
    .unwrap();
    std::thread::sleep(Duration::from_millis(500));
}

fn open(id: u32, name: &str, size: u64) -> Vec<u8> {
    let o = pb::TransferOpen {
        id,
        channel: pb::TransferChannel::File as i32,
        header: Some(TransferHeader {
            mime: "text/plain".into(),
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

#[test]
fn the_session_closes_the_link_for_a_hostile_gateway() {
    let Some(env) = Env::start(|cfg| {
        cfg.preamble_timeout = Duration::from_secs(1);
        cfg.extra_lanes_timeout = Duration::from_secs(1);
        cfg.max_file_bytes = 1_000;
    }) else {
        return;
    };
    let sock = env.sock.clone();

    // A byte on the media lane (gateway to session) is a violation: the whole link closes.
    let mut r = raw_link(&sock, [1; 16]);
    r.media.write_all(&[0]).unwrap();
    assert!(closes(&mut r.ctl, Duration::from_secs(5)), "ctl closes");
    assert!(closes(&mut r.bulk, Duration::from_secs(5)), "bulk closes");

    // An oversize ctl frame (16 385 > 16 384).
    let mut r = raw_link(&sock, [2; 16]);
    let mut w = 16_385u32.to_le_bytes().to_vec();
    w.push(KIND_GATEWAY_TO_SESSION);
    r.ctl.write_all(&w).unwrap();
    assert!(closes(&mut r.ctl, Duration::from_secs(5)));
    assert!(closes(&mut r.media, Duration::from_secs(5)));

    // A descriptor sent with SCM_RIGHTS on bulk.
    let mut r = raw_link(&sock, [3; 16]);
    let null = std::fs::File::open("/dev/null").unwrap();
    let fds = [null.as_fd()];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = rustix::net::SendAncillaryBuffer::new(&mut space);
    assert!(control.push(rustix::net::SendAncillaryMessage::ScmRights(&fds)));
    rustix::net::sendmsg(
        &r.bulk,
        &[IoSlice::new(&[0, 0])],
        &mut control,
        rustix::net::SendFlags::empty(),
    )
    .unwrap();
    assert!(
        closes(&mut r.ctl, Duration::from_secs(5)),
        "ancillary data closes the link"
    );

    // A transfer id already in use on bulk (the gateway's ids are odd); the partial file of the
    // first open is removed when the link ends.
    let mut r = raw_link(&sock, [4; 16]);
    start_stream(&mut r.ctl);
    let mut w = open(1, "a.txt", 10);
    w.extend(data(1, b"abc"));
    w.extend(open(1, "b.txt", 10));
    r.bulk.write_all(&w).unwrap();
    assert!(
        closes(&mut r.ctl, Duration::from_secs(5)),
        "an id in use is a violation"
    );
    std::thread::sleep(Duration::from_millis(300));
    let leftovers = std::fs::read_dir(env.dir.join("received"))
        .map(|d| d.count())
        .unwrap_or(0);
    assert_eq!(leftovers, 0, "an aborted transfer leaves nothing behind");

    // A file above the session's limit is refused with TRANSFER_REJECTED and the link goes on.
    let mut r = raw_link(&sock, [9; 16]);
    start_stream(&mut r.ctl);
    r.bulk.write_all(&open(1, "huge.bin", 5_000)).unwrap();
    r.bulk
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut abort = [0u8; 13];
    r.bulk.read_exact(&mut abort).unwrap();
    assert_eq!(abort[4], hx_ipc::link::KIND_TRANSFER_ABORT);
    assert_eq!(u32::from_le_bytes(abort[5..9].try_into().unwrap()), 1);
    assert_eq!(u32::from_le_bytes(abort[9..13].try_into().unwrap()), 0x101);
    assert!(
        !closes(&mut r.ctl, Duration::from_millis(500)),
        "the link lives"
    );
    assert!(
        !env.dir.join("received").join("huge.bin").exists(),
        "nothing written for a refused file"
    );
    drop(r);

    // A flood of tiny ctl frames far above the 20 000 per second ceiling closes the link.
    let mut r = raw_link(&sock, [5; 16]);
    let one = gw_frame(pb::gateway_to_session::Message::ClientStats(
        Default::default(),
    ));
    let burst: Vec<u8> = one
        .iter()
        .copied()
        .cycle()
        .take(one.len() * 30_000)
        .collect();
    let _ = r.ctl.write_all(&burst);
    assert!(
        closes(&mut r.ctl, Duration::from_secs(5)),
        "frame-count limit"
    );

    // An unknown frame kind and a zero length.
    for (n, bytes) in [vec![1, 0, 0, 0, 0x7f], vec![0, 0, 0, 0, 2]]
        .into_iter()
        .enumerate()
    {
        let mut r = raw_link(&sock, [20 + n as u8; 16]);
        r.ctl.write_all(&bytes).unwrap();
        assert!(closes(&mut r.ctl, Duration::from_secs(5)));
    }

    // A preamble that never completes, and a ctl lane whose extra lanes never come, time out.
    let mut s = UnixStream::connect(&sock).unwrap();
    s.write_all(b"HXLK").unwrap();
    assert!(closes(&mut s, Duration::from_secs(4)), "preamble timeout");
    let mut ctl = raw_lane(&sock, Lane::Ctl, [7; 16]);
    assert!(
        closes(&mut ctl, Duration::from_secs(5)),
        "extra-lanes timeout"
    );

    // A duplicate lane of the live link is closed without disturbing the link.
    let mut r = raw_link(&sock, [8; 16]);
    let mut dup = UnixStream::connect(&sock).unwrap();
    dup.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let offer = ClientPreamble {
        preamble: Preamble::ours(Lane::Media),
        link_id: [8; 16],
    }
    .encode();
    dup.write_all(&offer).unwrap();
    assert!(
        closes(&mut dup, Duration::from_secs(5)),
        "duplicate lane closed"
    );
    // The live link still answers a ping, from its control thread.
    r.ctl
        .write_all(&gw_frame(pb::gateway_to_session::Message::Ping(pb::Ping {
            nonce: 77,
        })))
        .unwrap();
    r.ctl
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let (kind, body) = read_frame(&mut r.ctl);
    assert_eq!(kind, KIND_SESSION_TO_GATEWAY);
    let msg = pb::SessionToGateway::decode(&body[..]).unwrap();
    assert!(matches!(
        msg.message,
        Some(pb::session_to_gateway::Message::Pong(p)) if p.nonce == 77
    ));
}

#[test]
fn a_stalled_ctl_readers_backlog_does_not_close_the_link() {
    // Review L2: the session's ctl reader pauses for a second (an XTest flush) while the gateway
    // keeps sending at its documented maximum (3 652 frames per second); the queued frames
    // reach the reader as one burst of about 7 000. Above the soft 4 000 per second that is
    // only counted, never a closed link (and never a fault that ends in RestartSession).
    let Some(env) = Env::start(|_| {}) else {
        return;
    };
    let mut r = raw_link(&env.sock, [30; 16]);
    let one = gw_frame(pb::gateway_to_session::Message::ClientStats(
        Default::default(),
    ));
    let chunk = |n: usize| -> Vec<u8> { one.iter().copied().cycle().take(one.len() * n).collect() };
    // The backlog of a one-second stall plus the second that follows it.
    r.ctl.write_all(&chunk(3_652 * 2)).unwrap();
    for _ in 0..3 {
        std::thread::sleep(Duration::from_secs(1));
        r.ctl.write_all(&chunk(3_652)).unwrap();
    }
    assert!(
        !closes(&mut r.ctl, Duration::from_millis(500)),
        "the link lives"
    );
    r.ctl
        .write_all(&gw_frame(pb::gateway_to_session::Message::Ping(pb::Ping {
            nonce: 5,
        })))
        .unwrap();
    r.ctl
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let (kind, body) = read_frame(&mut r.ctl);
    assert_eq!(kind, KIND_SESSION_TO_GATEWAY);
    let msg = pb::SessionToGateway::decode(&body[..]).unwrap();
    assert!(matches!(
        msg.message,
        Some(pb::session_to_gateway::Message::Pong(p)) if p.nonce == 5
    ));
}

#[test]
fn the_received_quota_refuses_a_file_that_does_not_fit() {
    // Review (received files): an aggregate quota for the directory.
    let Some(env) = Env::start(|cfg| cfg.received_quota_bytes = 2_000) else {
        return;
    };
    let mut r = raw_link(&env.sock, [30; 16]);
    start_stream(&mut r.ctl);
    // 1 500 announced fits; a second file of 1 000 does not (1 500 in flight + 1 000 > 2 000).
    let mut w = open(1, "first.bin", 1_500);
    w.extend(open(3, "second.bin", 1_000));
    r.bulk.write_all(&w).unwrap();
    r.bulk
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut abort = [0u8; 13];
    r.bulk.read_exact(&mut abort).unwrap();
    assert_eq!(abort[4], hx_ipc::link::KIND_TRANSFER_ABORT);
    assert_eq!(u32::from_le_bytes(abort[5..9].try_into().unwrap()), 3);
    assert_eq!(u32::from_le_bytes(abort[9..13].try_into().unwrap()), 0x101);
    assert!(!env.dir.join("received").join("second.bin").exists());
    assert!(env.dir.join("received").join("first.bin").exists());
    assert!(
        !closes(&mut r.ctl, Duration::from_millis(500)),
        "a refusal is not a violation"
    );
}

#[test]
fn a_hung_display_cannot_hold_the_handshake_slots() {
    // Review: build_info connected to X with no timeout. A server that accepts and never
    // answers used to park every handshake thread for ever.
    let dir = std::env::temp_dir().join(format!("hx-link-hung-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let hung = dir.join("x.sock");
    let hung_listener = std::os::unix::net::UnixListener::bind(&hung).unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop2 = stop.clone();
    let keep = std::thread::spawn(move || {
        // Accept and say nothing; keep the connections open.
        let mut held = Vec::new();
        hung_listener.set_nonblocking(true).unwrap();
        while !stop2.load(std::sync::atomic::Ordering::Relaxed) {
            if let Ok((s, _)) = hung_listener.accept() {
                held.push(s);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    });
    let sock = dir.join("link.sock");
    let mut cfg = SessionConfig::new(Some(format!("{}:0", hung.display())));
    cfg.display_probe_timeout = Duration::from_millis(400);
    cfg.max_handshakes = 4;
    cfg.clipboard = None;
    let server = Server::bind(&sock, cfg).unwrap().spawn();
    let t0 = Instant::now();
    // Many more connections than handshake slots: each ctl lane is refused within the probe
    // timeout (or at once, once two probes are parked), and the server keeps accepting.
    let mut refused = 0;
    for i in 0..12u8 {
        let mut s = UnixStream::connect(&sock).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let offer = ClientPreamble {
            preamble: Preamble::ours(Lane::Ctl),
            link_id: [i + 1; 16],
        }
        .encode();
        s.write_all(&offer).unwrap();
        let mut answer = [0u8; 8];
        s.read_exact(&mut answer).unwrap(); // the preamble is answered first
        if closes(&mut s, Duration::from_secs(3)) {
            refused += 1;
        }
    }
    assert_eq!(refused, 12, "every link is refused, none hangs");
    assert!(
        t0.elapsed() < Duration::from_secs(10),
        "{:?}: the probes are bounded",
        t0.elapsed()
    );
    server.shutdown();
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    keep.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
