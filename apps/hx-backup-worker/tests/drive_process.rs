//! The Drive helper as a process (ipc.md §24): one connection at a time, `SO_PEERCRED`, the idle
//! exit, what a protocol violation does, and the exit codes of the role.

mod drive_common;

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use drive_common::*;
use hx_backup_worker::drive::run::{Listen, RoleConfig, serve_listener};
use hx_backup_worker::drive::server::End;
use hx_backup_worker::role;
use hx_ipc::frame::encode_frame;
use hx_ipc::repo::{self, Endpoint, encode_message, message_raw_frame, pb};

fn my_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

fn role_cfg(rig: &Rig, idle: Duration) -> RoleConfig {
    RoleConfig {
        client_file: PathBuf::from("/nonexistent"),
        peer_uid: my_uid(),
        idle_exit: idle,
        listen: Listen::Activated,
        http: rig.cfg.http.clone(),
        timing: rig.cfg.timing,
        silence: rig.cfg.silence,
        harden: false,
    }
}

struct Loop {
    path: PathBuf,
    handle: Option<JoinHandle<i32>>,
}

impl Loop {
    fn start(rig: &Rig, role: RoleConfig) -> Self {
        let path = rig.dir.path().join("drive.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let drive = rig.cfg.clone();
        let handle = std::thread::spawn(move || serve_listener(&listener, &role, &drive));
        Loop {
            path,
            handle: Some(handle),
        }
    }

    fn connect(&self) -> UnixStream {
        UnixStream::connect(&self.path).unwrap()
    }

    fn privd(&self) -> PrivdEnd {
        PrivdEnd::new(self.connect())
    }

    fn exit(mut self) -> i32 {
        self.handle.take().unwrap().join().unwrap()
    }
}

fn hello_frame() -> Vec<u8> {
    let f = pb::RepoFrame {
        frame: Some(pb::repo_frame::Frame::Hello(pb::Hello {
            major: repo::VERSION_MAJOR,
            minor: repo::VERSION_MINOR,
            job_id: bytes::Bytes::copy_from_slice(&JOB),
        })),
    };
    encode_message(&f, Endpoint::DriveHelper).unwrap()
}

/// Reads until the peer closes or `d` passes; returns the bytes received.
fn drain(s: &mut UnixStream, d: Duration) -> (Vec<u8>, bool) {
    s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
    let end = Instant::now() + d;
    let mut got = vec![];
    let mut buf = [0u8; 4096];
    while Instant::now() < end {
        match s.read(&mut buf) {
            Ok(0) => return (got, true),
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return (got, true),
        }
    }
    (got, false)
}

#[test]
fn one_connection_is_served_at_a_time_and_the_next_waits() {
    let rig = Rig::new();
    let lp = Loop::start(&rig, role_cfg(&rig, Duration::from_secs(30)));
    let mut first = lp.privd();
    first.hello();
    first.open("repo", true, SERVER_A, false).ok();
    // a second connection is accepted by the kernel but not served
    let mut second = lp.connect();
    second.write_all(&hello_frame()).unwrap();
    let (got, closed) = drain(&mut second, Duration::from_millis(500));
    assert!(
        got.is_empty() && !closed,
        "the helper answered a second connection: {got:?}"
    );
    // the first goes on working meanwhile
    first.list(T::Pack).ok();
    first.bye();
    drop(first);
    // now the second is served, from its Hello
    let (got, _) = drain(&mut second, Duration::from_secs(5));
    assert!(!got.is_empty(), "the second connection was never served");
    second.shutdown(std::net::Shutdown::Both).unwrap();
}

#[test]
fn a_peer_with_another_uid_is_closed_without_a_byte_read_or_written() {
    let rig = Rig::new();
    let mut cfg = role_cfg(&rig, Duration::from_secs(30));
    cfg.peer_uid = my_uid() + 1;
    let lp = Loop::start(&rig, cfg);
    let mut c = lp.connect();
    let _ = c.write_all(&hello_frame());
    let (got, closed) = drain(&mut c, Duration::from_secs(3));
    assert!(got.is_empty(), "nothing is answered to an unexpected peer");
    assert!(closed, "the connection is closed");
    assert_eq!(rig.fake.with(|m| m.log.len()), 0);
}

#[test]
fn the_helper_exits_zero_after_the_idle_time_and_the_clock_restarts_at_each_close() {
    let rig = Rig::new();
    let lp = Loop::start(&rig, role_cfg(&rig, Duration::from_millis(700)));
    // a connection that lasts longer than the idle time does not make the helper exit
    let mut c = lp.privd();
    c.hello();
    std::thread::sleep(Duration::from_millis(1000));
    c.ping(1);
    c.pump_for(Duration::from_millis(100));
    assert_eq!(c.pongs, [1], "still serving after more than the idle time");
    c.bye();
    drop(c);
    let closed = Instant::now();
    let code = lp.exit();
    let waited = closed.elapsed();
    assert_eq!(code, role::EXIT_OK);
    assert!(
        waited >= Duration::from_millis(600),
        "{waited:?}: the idle time counts from the close"
    );
    assert!(waited < Duration::from_secs(5));
}

#[test]
fn a_helper_nobody_connects_to_exits_after_the_idle_time() {
    let rig = Rig::new();
    let began = Instant::now();
    let lp = Loop::start(&rig, role_cfg(&rig, Duration::from_millis(300)));
    assert_eq!(lp.exit(), role::EXIT_OK);
    assert!(began.elapsed() >= Duration::from_millis(250));
}

fn raw_message(f: pb::repo_frame::Frame) -> Vec<u8> {
    let frame = pb::RepoFrame { frame: Some(f) };
    let raw = message_raw_frame(&frame);
    encode_frame(1, &raw.body, 65_536).unwrap()
}

fn open_with_folder(folder: &str) -> Vec<u8> {
    raw_message(pb::repo_frame::Frame::Request(pb::RepoRequest {
        req_id: 1,
        op: Some(pb::repo_request::Op::OpenRepo(pb::OpenRepo {
            folder: folder.to_owned(),
            create: true,
            server_id: bytes::Bytes::copy_from_slice(&SERVER_A),
            takeover: false,
        })),
    }))
}

fn with_hello(tail: Vec<u8>) -> Vec<u8> {
    let mut v = hello_frame();
    v.extend(tail);
    v
}

#[test]
fn a_violation_closes_that_connection_silently_and_the_helper_serves_the_next() {
    let rig = Rig::new();
    let lp = Loop::start(&rig, role_cfg(&rig, Duration::from_secs(60)));
    let list_first = raw_message(pb::repo_frame::Frame::Request(pb::RepoRequest {
        req_id: 1,
        op: Some(pb::repo_request::Op::List(pb::List {
            object_type: T::Pack as i32,
        })),
    }));
    let hello_again = hello_frame();
    let too_long = {
        let mut v = 70_000u32.to_le_bytes().to_vec();
        v.push(1);
        v
    };
    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("the first request is not OpenRepo", with_hello(list_first)),
        ("a second Hello", with_hello(hello_again)),
        ("an unknown frame kind", with_hello(vec![2, 0, 0, 0, 9, 0])),
        ("a frame longer than the limit", with_hello(too_long)),
        (
            "a secret frame (worker link only)",
            with_hello(vec![3, 0, 0, 0, 2, 0, 0]),
        ),
        (
            "a frame before Hello",
            raw_message(pb::repo_frame::Frame::Ping(pb::Ping { nonce: 1 })),
        ),
        (
            "a worker-only variant",
            with_hello(raw_message(pb::repo_frame::Frame::Cancel(pb::Cancel {}))),
        ),
        ("garbage", vec![0xff; 64]),
    ];
    for bad in ["", "../x", "a/b", ".hidden", "a b", "é", &"a".repeat(129)] {
        cases.push(("an invalid folder name", with_hello(open_with_folder(bad))));
    }
    for (what, bytes) in cases {
        let mut c = lp.connect();
        c.write_all(&bytes).unwrap();
        let (got, closed) = drain(&mut c, Duration::from_secs(5));
        // the only thing the helper may have sent is the HelloAck that answered the valid Hello
        assert!(closed, "{what}: the connection must be closed");
        assert!(
            got.len() < 200,
            "{what}: nothing but a HelloAck may be sent ({} bytes)",
            got.len()
        );
        assert_eq!(
            rig.fake.with(|m| m.log.len()),
            0,
            "{what}: no Google request"
        );
        // and the helper is fine
        let mut p = lp.privd();
        p.hello();
        p.bye();
    }
    assert!(
        !lp.handle.as_ref().unwrap().is_finished(),
        "a violation never ends the helper"
    );
}

#[test]
fn a_descriptor_sent_on_the_link_is_a_violation() {
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};
    let rig = Rig::new();
    let lp = Loop::start(&rig, role_cfg(&rig, Duration::from_secs(60)));
    let c = lp.connect();
    let file = std::fs::File::open("/dev/null").unwrap();
    let fds = [std::os::fd::AsFd::as_fd(&file)];
    let mut space = [std::mem::MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    assert!(ancillary.push(SendAncillaryMessage::ScmRights(&fds)));
    let hello = hello_frame();
    sendmsg(
        &c,
        &[std::io::IoSlice::new(&hello)],
        &mut ancillary,
        SendFlags::empty(),
    )
    .unwrap();
    let mut c = c;
    let (got, closed) = drain(&mut c, Duration::from_secs(5));
    assert!(closed, "the connection must be closed");
    assert!(
        got.is_empty(),
        "no HelloAck for a Hello that came with a descriptor"
    );
    // still serving
    let mut p = lp.privd();
    p.hello();
}

#[test]
fn privd_silence_ends_the_connection() {
    let rig = Rig::with(|c| c.silence = Duration::from_millis(300));
    let mut s = rig.session();
    s.env.hello();
    // privd pings every 15 s in production; here it says nothing
    assert_eq!(s.join_without_closing(), End::Silent);
}

#[test]
fn the_exit_codes_of_the_role() {
    let rig = Rig::new();
    let client = rig.dir.path().join("drive-client.json");
    std::fs::write(&client, client_json()).unwrap();
    let base = |listen: Listen, client_file: PathBuf| RoleConfig {
        client_file,
        listen,
        harden: false,
        ..role_cfg(&rig, Duration::from_millis(200))
    };
    // the OAuth client is missing, unreadable or malformed: fail closed, nothing served
    assert_eq!(
        hx_backup_worker::drive::run(&base(
            Listen::Path(rig.dir.path().join("a.sock")),
            rig.dir.path().join("none")
        )),
        role::EXIT_DRIVE_CLIENT
    );
    let bad = rig.dir.path().join("bad.json");
    std::fs::write(&bad, r#"{"client_id":"x"}"#).unwrap();
    assert_eq!(
        hx_backup_worker::drive::run(&base(Listen::Path(rig.dir.path().join("b.sock")), bad)),
        role::EXIT_DRIVE_CLIENT
    );
    assert!(
        !rig.dir.path().join("a.sock").exists() && !rig.dir.path().join("b.sock").exists(),
        "no listener without the client"
    );
    // no activated socket (this process was not started by systemd)
    assert_eq!(
        hx_backup_worker::drive::run(&base(Listen::Activated, client.clone())),
        role::EXIT_LISTEN
    );
    // a path that cannot be bound
    assert_eq!(
        hx_backup_worker::drive::run(&base(
            Listen::Path(PathBuf::from("/nonexistent/dir/x.sock")),
            client.clone()
        )),
        role::EXIT_LISTEN
    );
    // a good start that idles out
    assert_eq!(
        hx_backup_worker::drive::run(&base(Listen::Path(rig.dir.path().join("c.sock")), client)),
        role::EXIT_OK
    );
}
