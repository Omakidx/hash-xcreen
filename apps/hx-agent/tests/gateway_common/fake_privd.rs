//! A fake `hx-privd` for the gateway tests, written from `docs/ipc.md` and nothing else.
//!
//! It speaks the framing of section 4 (blocking threads, `recvmsg` reads), derives its own
//! pepper (which the gateway never sees), and implements only what the gateway role calls:
//! `PepperVerify` with failure caps and the `LOCKED` state of section 5.3, `PepperEnrol`,
//! `RecordEvent`, `GetDesktop`, `StartDesktop`, `ProvisionSessionLink`, `GetHostInfo`.
//! Knobs let a test restart it, take it down, slow it, make it lie about the role, or send a
//! file descriptor along with a response.

use std::io::Write;
use std::os::fd::AsFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hmac::{Hmac, Mac};
use hx_ipc::frame::Decoder;
use hx_ipc::privd::{self, Incoming, PrivdPolicy, Side, pb};
use hx_ipc::recv::NoCmsgReader;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// What the fake has seen and how it behaves.
#[derive(Default)]
pub struct State {
    /// Pepper (never leaves this process).
    pub pepper: [u8; 32],
    /// Failed `PepperVerify` per purpose until it locks (0 = never locks).
    pub pin_failure_cap: u32,
    pin_failures: u32,
    /// True once the PIN purpose is locked.
    pub pin_locked: bool,
    /// Every command name received, in order.
    pub commands: Vec<String>,
    /// Audit events: (event, device id, label).
    pub events: Vec<(pb::AuditEvent, Option<Vec<u8>>, String)>,
    /// `PepperVerify` calls answered `ok = true` / `ok = false`.
    pub verify_ok: u32,
    /// See `verify_ok`.
    pub verify_fail: u32,
    /// Whether the desktop exists.
    pub desktop_exists: bool,
    /// The desktop's state.
    pub desktop_state: i32,
    /// `StartDesktop` calls.
    pub start_calls: u32,
    /// `ProvisionSessionLink` calls.
    pub provision_calls: u32,
    /// Delay before answering `PepperVerify` (milliseconds).
    pub verify_delay_ms: u64,
    /// Role reported in `HelloAck`.
    pub role: i32,
    /// Connections accepted so far.
    pub connections: u32,
    /// The request ids of every request, to check uniqueness per connection.
    pub request_ids: Vec<(u32, u64)>,
    /// Cancels received.
    pub cancels: u32,
    /// Set when a request's secret frames did not follow it at once.
    pub secret_problem: Option<String>,
    /// Send a file descriptor (SCM_RIGHTS) with the next response.
    pub send_fd_with_next_response: bool,
    streams: Vec<UnixStream>,
}

/// The running fake.
pub struct FakePrivd {
    pub path: PathBuf,
    pub state: Arc<Mutex<State>>,
    refuse: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    conn_ids: Arc<AtomicU64>,
}

fn purpose_key(pepper: &[u8; 32], purpose: i32) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(pepper).unwrap();
    m.update(match purpose {
        1 => b"hx-pepper pin",
        _ => b"hx-pepper password",
    });
    m.finalize().into_bytes().into()
}

fn mac(pepper: &[u8; 32], purpose: i32, input: &[u8]) -> [u8; 32] {
    let key = purpose_key(pepper, purpose);
    let mut m = HmacSha256::new_from_slice(&key).unwrap();
    m.update(input);
    m.finalize().into_bytes().into()
}

impl FakePrivd {
    /// Listens at `dir/privd.sock`.
    pub fn start(dir: &Path) -> Self {
        let path = dir.join("privd.sock");
        let listener = UnixListener::bind(&path).expect("bind fake privd");
        listener.set_nonblocking(true).unwrap();
        let state = Arc::new(Mutex::new(State {
            pepper: [0x5a; 32],
            desktop_exists: true,
            desktop_state: pb::DesktopState::Running as i32,
            role: pb::Role::Gateway as i32,
            ..Default::default()
        }));
        let refuse = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let conn_ids = Arc::new(AtomicU64::new(0));
        let (st, rf, sp, ids) = (
            state.clone(),
            refuse.clone(),
            stop.clone(),
            conn_ids.clone(),
        );
        std::thread::spawn(move || {
            while !sp.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if rf.load(Ordering::Relaxed) {
                            drop(stream);
                            continue;
                        }
                        stream.set_nonblocking(false).unwrap();
                        let conn = ids.fetch_add(1, Ordering::Relaxed) as u32;
                        {
                            let mut s = st.lock().unwrap();
                            s.connections += 1;
                            s.streams.push(stream.try_clone().unwrap());
                        }
                        let st = st.clone();
                        std::thread::spawn(move || serve(stream, st, conn));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        Self {
            path,
            state,
            refuse,
            stop,
            conn_ids,
        }
    }

    /// Simulates a privd restart: every open connection is cut, new ones are accepted.
    pub fn restart(&self) {
        let mut s = self.state.lock().unwrap();
        for st in s.streams.drain(..) {
            let _ = st.shutdown(std::net::Shutdown::Both);
        }
    }

    /// While set, new connections are closed at once (privd is down).
    pub fn set_down(&self, down: bool) {
        self.refuse.store(down, Ordering::Relaxed);
        if down {
            self.restart();
        }
    }

    pub fn commands(&self) -> Vec<String> {
        self.state.lock().unwrap().commands.clone()
    }

    pub fn events(&self) -> Vec<(pb::AuditEvent, Option<Vec<u8>>, String)> {
        self.state.lock().unwrap().events.clone()
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        f(&mut self.state.lock().unwrap())
    }

    /// Waits until `pred` holds on the state (events are recorded in the background). Async so
    /// that a current-thread test runtime keeps running the gateway's tasks meanwhile.
    pub async fn wait_for(&self, pred: impl Fn(&State) -> bool) -> bool {
        for _ in 0..200 {
            if pred(&self.state.lock().unwrap()) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        false
    }
}

impl Drop for FakePrivd {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.conn_ids.load(Ordering::Relaxed);
        let mut s = self.state.lock().unwrap();
        for st in s.streams.drain(..) {
            let _ = st.shutdown(std::net::Shutdown::Both);
        }
    }
}

fn send(stream: &mut UnixStream, frame: pb::Frame) -> std::io::Result<()> {
    let bytes = privd::encode_message(&frame, Side::Client).expect("encode");
    stream.write_all(&bytes)
}

fn send_with_fd(stream: &UnixStream, frame: pb::Frame) {
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};
    let bytes = privd::encode_message(&frame, Side::Client).expect("encode");
    let (a, _b) = UnixStream::pair().unwrap();
    let fds = [a.as_fd()];
    let mut space = [std::mem::MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut anc = SendAncillaryBuffer::new(&mut space);
    assert!(anc.push(SendAncillaryMessage::ScmRights(&fds)));
    sendmsg(
        stream,
        &[std::io::IoSlice::new(&bytes)],
        &mut anc,
        SendFlags::empty(),
    )
    .unwrap();
}

fn error(code: pb::ErrorCode, detail: pb::ErrorDetail, retryable: bool) -> pb::response::Result {
    pb::response::Result::Error(pb::Error {
        code: code as i32,
        detail: detail as i32,
        message: "fake privd".into(),
        retryable,
        retry_after_ms: 0,
        stage: None,
    })
}

fn serve(mut stream: UnixStream, state: Arc<Mutex<State>>, conn: u32) {
    let mut decoder = Decoder::new(PrivdPolicy::new(Side::Server));
    let next = |decoder: &mut Decoder<PrivdPolicy>, s: &UnixStream| -> Option<Incoming> {
        s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
        let raw = decoder.read_from(&mut NoCmsgReader(s)).ok()??;
        privd::decode(raw, Side::Server).ok()
    };
    // Hello.
    match next(&mut decoder, &stream) {
        Some(Incoming::Message(pb::Frame {
            frame: Some(pb::frame::Frame::Hello(h)),
        })) if h.major == 1 => {}
        _ => return,
    }
    let role = state.lock().unwrap().role;
    let ack = pb::Frame {
        frame: Some(pb::frame::Frame::HelloAck(pb::HelloAck {
            major: 1,
            minor: 0,
            privd_version: "fake".into(),
            phase: pb::Phase::Ready as i32,
            role,
        })),
    };
    if send(&mut stream, ack).is_err() {
        return;
    }
    loop {
        stream.set_read_timeout(Some(Duration::from_secs(600))).ok();
        let Some(Incoming::Message(pb::Frame { frame: Some(f) })) =
            next_idle(&mut decoder, &stream)
        else {
            return;
        };
        let req = match f {
            pb::frame::Frame::Request(r) => r,
            pb::frame::Frame::Cancel(_) => {
                state.lock().unwrap().cancels += 1;
                continue;
            }
            pb::frame::Frame::Ping(p) => {
                let _ = send(
                    &mut stream,
                    pb::Frame {
                        frame: Some(pb::frame::Frame::Pong(pb::Pong { nonce: p.nonce })),
                    },
                );
                continue;
            }
            _ => continue,
        };
        // Secret frames must follow at once, one per declared slot.
        let mut secrets: Vec<Vec<u8>> = Vec::new();
        for slot in &req.secret_slots {
            match next(&mut decoder, &stream) {
                Some(Incoming::Secret(sf))
                    if sf.request_id == req.request_id && u32::from(sf.slot) == slot.slot =>
                {
                    secrets.push(sf.secret.expose().to_vec());
                }
                _ => {
                    state.lock().unwrap().secret_problem =
                        Some("secret frame missing or wrong".into());
                    return;
                }
            }
        }
        let Some(cmd) = req.command.clone() else {
            return;
        };
        let name = privd::command_info(&cmd).name.to_string();
        {
            let mut s = state.lock().unwrap();
            s.commands.push(name);
            s.request_ids.push((conn, req.request_id));
        }
        use pb::request::Command as C;
        use pb::response::Result as R;
        let result = match cmd {
            C::PepperVerify(r) => {
                let (delay, pepper) = {
                    let s = state.lock().unwrap();
                    (s.verify_delay_ms, s.pepper)
                };
                if delay > 0 {
                    std::thread::sleep(Duration::from_millis(delay));
                }
                let mut s = state.lock().unwrap();
                if s.pin_locked {
                    error(
                        pb::ErrorCode::ResourceExhausted,
                        pb::ErrorDetail::Locked,
                        false,
                    )
                } else {
                    let ok = secrets.first().is_some_and(|input| {
                        mac(&pepper, r.purpose, input)[..] == r.expected_verifier[..]
                    });
                    if ok {
                        s.verify_ok += 1;
                    } else {
                        s.verify_fail += 1;
                        s.pin_failures += 1;
                        if s.pin_failure_cap > 0 && s.pin_failures >= s.pin_failure_cap {
                            s.pin_locked = true;
                        }
                    }
                    R::PepperVerify(pb::PepperVerifyResult { ok })
                }
            }
            C::PepperEnrol(r) => {
                let pepper = state.lock().unwrap().pepper;
                let m = mac(
                    &pepper,
                    r.purpose,
                    secrets.first().map(|v| &v[..]).unwrap_or(&[]),
                );
                R::PepperEnrol(pb::PepperEnrolResult {
                    mac: bytes::Bytes::copy_from_slice(&m),
                    version: 1,
                })
            }
            C::RecordEvent(r) => {
                state.lock().unwrap().events.push((
                    pb::AuditEvent::try_from(r.event).unwrap(),
                    r.device_id.map(|d| d.to_vec()),
                    r.label,
                ));
                R::RecordEvent(pb::RecordEventResult {})
            }
            C::GetDesktop(r) => {
                let s = state.lock().unwrap();
                if !s.desktop_exists {
                    error(pb::ErrorCode::NotFound, pb::ErrorDetail::Unspecified, false)
                } else {
                    R::GetDesktop(pb::GetDesktopResult {
                        desktop: Some(pb::Desktop {
                            desktop_id: r.desktop_id,
                            state: s.desktop_state,
                            session: Some(pb::SessionInfo {
                                installed_version: "0".into(),
                                link_provisioned: s.provision_calls > 0,
                            }),
                            ..Default::default()
                        }),
                    })
                }
            }
            C::StartDesktop(_) => {
                let mut s = state.lock().unwrap();
                s.start_calls += 1;
                s.desktop_state = pb::DesktopState::Running as i32;
                R::StartDesktop(pb::PowerResult {
                    running: true,
                    degraded: false,
                })
            }
            C::ProvisionSessionLink(r) => {
                state.lock().unwrap().provision_calls += 1;
                R::ProvisionSessionLink(pb::ProvisionSessionLinkResult {
                    socket_path: format!("/run/hx/link/{}.sock", r.desktop_id),
                })
            }
            C::GetHostInfo(_) => R::GetHostInfo(pb::GetHostInfoResult {
                privd_version: "fake".into(),
                ..Default::default()
            }),
            _ => error(
                pb::ErrorCode::Unimplemented,
                pb::ErrorDetail::Unspecified,
                false,
            ),
        };
        let frame = pb::Frame {
            frame: Some(pb::frame::Frame::Response(pb::Response {
                request_id: req.request_id,
                result: Some(result),
            })),
        };
        let with_fd = std::mem::take(&mut state.lock().unwrap().send_fd_with_next_response);
        if with_fd {
            send_with_fd(&stream, frame);
        } else if send(&mut stream, frame).is_err() {
            return;
        }
    }
}

/// Like `next` but with the long idle timeout already set on the stream.
fn next_idle(decoder: &mut Decoder<PrivdPolicy>, s: &UnixStream) -> Option<Incoming> {
    let raw = decoder.read_from(&mut NoCmsgReader(s)).ok()??;
    privd::decode(raw, Side::Server).ok()
}
