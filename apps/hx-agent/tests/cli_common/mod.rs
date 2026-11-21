//! Shared harness of the CLI tests.
//!
//! * [`cli`] runs the real CLI (`hx_agent::cli::run`) on a blocking thread with a scripted
//!   prompter, so it can talk to servers running on the test's tokio runtime.
//! * [`World`] is the real stack: the real gateway admin server (`gateway_common::Env`, with its
//!   `OnlyUid` test policy) and the real `hx-privd` `Daemon` on its fakes. The privd socket server
//!   cannot be reached as `Admin` by a non-root test (the role comes from `SO_PEERCRED`, and
//!   uid 0 is the only Admin), so [`daemon_handler`] serves a socket of the test's own whose
//!   requests go through the real `Daemon::handle` with an `Admin` `Ctx`: the real commands,
//!   authorization, phase rules, rate limits, lockout and audit, behind the real framing of
//!   `hx-ipc`.
//! * [`ScriptedPrivd`] and [`ScriptedAdmin`] answer with canned or hostile data, which the real
//!   servers (that sanitize their own text) cannot produce.
#![allow(dead_code)]

#[path = "../gateway_common/mod.rs"]
pub mod gateway_common;

use std::collections::VecDeque;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use hx_agent::cli::{Config, Env, Prompter, error::CliError};
use hx_agent::privd::daemon::{Ctx, Daemon};
use hx_agent::privd::testing::{FakeIncus, Harness};
use hx_crypto::PinParams;
use hx_ipc::admin::{self as ipc_admin, Incoming as AIncoming, pb as apb};
use hx_ipc::frame::Decoder;
use hx_ipc::privd::{self, Incoming, PrivdPolicy, Side, pb};
use hx_ipc::secret::Secret;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use zeroize::Zeroizing;

pub const GW_UID: u32 = 4_242;
/// Cheap Argon2id so that verifier tests are fast (the gateway's floor in the harness is 32 KiB).
pub const CHEAP: PinParams = PinParams {
    memory_kib: 64,
    iterations: 1,
    parallelism: 1,
};

// ------------------------------------------------------------------------------------- prompts

/// Answers the CLI's questions from a script and records what it was asked.
pub struct Scripted {
    secrets: VecDeque<Vec<u8>>,
    lines: VecDeque<String>,
    pub asked: Arc<Mutex<Vec<String>>>,
}

impl Scripted {
    pub fn new(secrets: &[&[u8]], lines: &[&str]) -> Self {
        Self {
            secrets: secrets.iter().map(|s| s.to_vec()).collect(),
            lines: lines.iter().map(|s| (*s).to_owned()).collect(),
            asked: Arc::default(),
        }
    }
}

impl Prompter for Scripted {
    fn secret(&mut self, prompt: &str, max: usize) -> Result<Zeroizing<Vec<u8>>, CliError> {
        self.asked.lock().unwrap().push(format!("secret: {prompt}"));
        match self.secrets.pop_front() {
            Some(s) if s.len() <= max => Ok(Zeroizing::new(s)),
            Some(_) => Err(CliError::Usage("too long".into())),
            None => Err(CliError::Declined("no terminal to ask on".into())),
        }
    }

    fn line(&mut self, prompt: &str) -> Result<String, CliError> {
        self.asked.lock().unwrap().push(format!("line: {prompt}"));
        self.lines
            .pop_front()
            .ok_or_else(|| CliError::Declined("no terminal to ask on".into()))
    }
}

/// What a CLI run produced.
#[derive(Debug)]
pub struct Run {
    pub code: u8,
    pub stdout: String,
    pub stderr: String,
    pub asked: Vec<String>,
}

impl Run {
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(self.stdout.trim()).unwrap_or_else(|e| {
            panic!(
                "stdout is not one JSON value ({e}): {:?} (stderr {:?})",
                self.stdout, self.stderr
            )
        })
    }
}

/// Runs the CLI as euid 0 (the binary passes the real uid; tests inject it).
pub async fn cli(cfg: &Config, args: &[&str], secrets: &[&[u8]], lines: &[&str]) -> Run {
    cli_as(cfg, 0, args, secrets, lines).await
}

pub async fn cli_as(
    cfg: &Config,
    euid: u32,
    args: &[&str],
    secrets: &[&[u8]],
    lines: &[&str],
) -> Run {
    let cfg = cfg.clone();
    let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    let mut prompt = Scripted::new(secrets, lines);
    let asked = prompt.asked.clone();
    let join = tokio::task::spawn_blocking(move || {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = {
            let mut env = Env {
                config: cfg,
                euid,
                out: &mut out,
                err: &mut err,
                prompt: &mut prompt,
                stop: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                now: hx_agent::cli::system_now,
                json: false,
            };
            hx_agent::cli::run(&args, &mut env)
        };
        (code, out, err)
    });
    let (code, out, err) = join.await.expect("the CLI thread panicked");
    let asked = asked.lock().unwrap().clone();
    Run {
        code,
        stdout: String::from_utf8_lossy(&out).into_owned(),
        stderr: String::from_utf8_lossy(&err).into_owned(),
        asked,
    }
}

/// A `Config` whose sockets do not exist (for tests that must not reach a daemon).
pub fn unreachable_config(dir: &Path) -> Config {
    Config {
        privd_socket: dir.join("no-privd.sock"),
        admin_socket: dir.join("no-admin.sock"),
        audit_log: dir.join("audit.log"),
        audit_owner_uid: my_uid(),
        journalctl: dir.join("no-journalctl"),
        verifier_params: CHEAP,
    }
}

pub fn my_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

// -------------------------------------------------------------------------- framed test servers

/// Reads frames from a stream, keeping bytes that belong to the next frame.
struct FrameSource {
    stream: UnixStream,
    decoder: Decoder<PrivdPolicy>,
    pending: Vec<u8>,
}

impl FrameSource {
    fn new(stream: UnixStream) -> Self {
        Self {
            stream,
            decoder: Decoder::new(PrivdPolicy::new(Side::Server)),
            pending: Vec::new(),
        }
    }

    async fn next(&mut self) -> Option<hx_ipc::RawFrame> {
        loop {
            if !self.pending.is_empty() {
                let (used, frame) = self.decoder.feed(&self.pending).ok()?;
                self.pending.drain(..used);
                if frame.is_some() {
                    return frame;
                }
            }
            let mut buf = [0u8; 8192];
            let n = self.stream.read(&mut buf).await.ok()?;
            if n == 0 {
                return None;
            }
            self.pending.extend_from_slice(&buf[..n]);
        }
    }
}

/// `(request_id, slot, bytes)` of every secret frame a stand-in received.
pub type SecretLog = Arc<Mutex<Vec<(u64, u8, Vec<u8>)>>>;

pub type Handled<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// What a privd handler answers: progress frames, then the response (its `request_id` is set
/// by the server).
pub struct PrivdReply {
    pub progress: Vec<pb::Progress>,
    pub result: pb::response::Result,
}

impl From<pb::response::Result> for PrivdReply {
    fn from(result: pb::response::Result) -> Self {
        Self {
            progress: vec![],
            result,
        }
    }
}

pub type PrivdHandler =
    Arc<dyn Fn(pb::Request, Vec<Option<Secret>>) -> Handled<PrivdReply> + Send + Sync>;

/// A privd stand-in on a socket of the test.
pub struct ScriptedPrivd {
    pub path: PathBuf,
    /// Every `(request_id, slot, bytes)` secret frame received.
    pub secrets: SecretLog,
    /// Every request received, in order.
    pub requests: Arc<Mutex<Vec<pb::Request>>>,
    /// Every raw request body (protobuf bytes), to prove that no secret is inside.
    pub encoded: Arc<Mutex<Vec<Vec<u8>>>>,
}

pub struct PrivdOptions {
    pub version: String,
    pub role: pb::Role,
    pub phase: pb::Phase,
}

impl Default for PrivdOptions {
    fn default() -> Self {
        Self {
            version: "0.1.0".into(),
            role: pb::Role::Admin,
            phase: pb::Phase::Ready,
        }
    }
}

impl ScriptedPrivd {
    pub async fn start(dir: &Path, name: &str, opts: PrivdOptions, handler: PrivdHandler) -> Self {
        use prost::Message;
        let path = dir.join(name);
        let listener = UnixListener::bind(&path).expect("bind privd stand-in");
        let secrets: SecretLog = Arc::default();
        let requests: Arc<Mutex<Vec<pb::Request>>> = Arc::default();
        let encoded: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
        let (s2, r2, e2) = (secrets.clone(), requests.clone(), encoded.clone());
        let opts = Arc::new(opts);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let (handler, opts) = (handler.clone(), opts.clone());
                let (secrets, requests, encoded) = (s2.clone(), r2.clone(), e2.clone());
                tokio::spawn(async move {
                    let mut src = FrameSource::new(stream);
                    // Hello
                    let Some(raw) = src.next().await else { return };
                    let Ok(Incoming::Message(pb::Frame {
                        frame: Some(pb::frame::Frame::Hello(_)),
                    })) = privd::decode(raw, Side::Server)
                    else {
                        return;
                    };
                    let ack = pb::Frame {
                        frame: Some(pb::frame::Frame::HelloAck(pb::HelloAck {
                            major: 1,
                            minor: 0,
                            privd_version: opts.version.clone(),
                            phase: opts.phase as i32,
                            role: opts.role as i32,
                        })),
                    };
                    if send(&mut src.stream, &ack).await.is_err() {
                        return;
                    }
                    loop {
                        let Some(raw) = src.next().await else { return };
                        match privd::decode(raw, Side::Server) {
                            Ok(Incoming::Message(pb::Frame {
                                frame: Some(pb::frame::Frame::Request(req)),
                            })) => {
                                encoded.lock().unwrap().push(req.encode_to_vec());
                                let mut got = Vec::new();
                                for slot in &req.secret_slots {
                                    let Some(raw) = src.next().await else { return };
                                    let Ok(Incoming::Secret(sf)) = privd::decode(raw, Side::Server)
                                    else {
                                        return;
                                    };
                                    assert_eq!(sf.request_id, req.request_id);
                                    assert_eq!(u32::from(sf.slot), slot.slot);
                                    secrets.lock().unwrap().push((
                                        sf.request_id,
                                        sf.slot,
                                        sf.secret.expose().to_vec(),
                                    ));
                                    got.push(Some(sf.secret));
                                }
                                requests.lock().unwrap().push(req.clone());
                                let reply = handler(req.clone(), got).await;
                                // A handler can make the stand-in vanish without answering.
                                if matches!(&reply.result, pb::response::Result::Error(e) if e.message == DROP)
                                {
                                    return;
                                }
                                for mut p in reply.progress {
                                    p.request_id = req.request_id;
                                    let f = pb::Frame {
                                        frame: Some(pb::frame::Frame::Progress(p)),
                                    };
                                    if send(&mut src.stream, &f).await.is_err() {
                                        return;
                                    }
                                }
                                let f = pb::Frame {
                                    frame: Some(pb::frame::Frame::Response(pb::Response {
                                        request_id: req.request_id,
                                        result: Some(reply.result),
                                    })),
                                };
                                if send(&mut src.stream, &f).await.is_err() {
                                    return;
                                }
                            }
                            Ok(Incoming::Message(pb::Frame {
                                frame: Some(pb::frame::Frame::Ping(p)),
                            })) => {
                                let f = pb::Frame {
                                    frame: Some(pb::frame::Frame::Pong(pb::Pong {
                                        nonce: p.nonce,
                                    })),
                                };
                                if send(&mut src.stream, &f).await.is_err() {
                                    return;
                                }
                            }
                            _ => return,
                        }
                    }
                });
            }
        });
        Self {
            path,
            secrets,
            requests,
            encoded,
        }
    }

    /// The commands received so far, by name.
    pub fn commands(&self) -> Vec<&'static str> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter_map(|r| r.command.as_ref().map(|c| privd::command_info(c).name))
            .collect()
    }
}

async fn send(stream: &mut UnixStream, f: &pb::Frame) -> Result<(), ()> {
    let bytes = privd::encode_message(f, Side::Client).map_err(|_| ())?;
    stream.write_all(&bytes).await.map_err(|_| ())
}

/// The real `Daemon`, as `Admin`, behind a socket of the test.
pub fn daemon_handler(d: Arc<Daemon<FakeIncus>>) -> PrivdHandler {
    Arc::new(move |req, secrets| {
        let d = d.clone();
        Box::pin(async move {
            let mut ctx = Ctx::new(pb::Role::Admin);
            ctx.request_id = req.request_id;
            ctx.secrets = secrets;
            let resp = d.handle(req, ctx).await;
            PrivdReply {
                progress: vec![],
                result: resp.result.expect("a response without a result"),
            }
        })
    })
}

// ------------------------------------------------------------------------------ admin stand-in

pub type AdminHandler =
    Arc<dyn Fn(apb::Request, Vec<Vec<u8>>) -> Handled<apb::response::Result> + Send + Sync>;

/// A gatewayd admin-socket stand-in.
pub struct ScriptedAdmin {
    pub path: PathBuf,
    pub secrets: SecretLog,
    pub requests: Arc<Mutex<Vec<apb::Request>>>,
    pub encoded: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl ScriptedAdmin {
    pub async fn start(dir: &Path, name: &str, version: &str, handler: AdminHandler) -> Self {
        use prost::Message;
        let path = dir.join(name);
        let listener = UnixListener::bind(&path).expect("bind admin stand-in");
        let secrets: SecretLog = Arc::default();
        let requests: Arc<Mutex<Vec<apb::Request>>> = Arc::default();
        let encoded: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
        let (s2, r2, e2) = (secrets.clone(), requests.clone(), encoded.clone());
        let version = version.to_owned();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let (handler, version) = (handler.clone(), version.clone());
                let (secrets, requests, encoded) = (s2.clone(), r2.clone(), e2.clone());
                tokio::spawn(async move {
                    let mut src = FrameSource::new(stream);
                    let Some(raw) = src.next().await else { return };
                    let Ok(AIncoming::Message(apb::Frame {
                        frame: Some(apb::frame::Frame::Hello(_)),
                    })) = ipc_admin::decode(raw, Side::Server)
                    else {
                        return;
                    };
                    let ack = apb::Frame {
                        frame: Some(apb::frame::Frame::HelloAck(apb::HelloAck {
                            major: 1,
                            minor: 0,
                            gatewayd_version: version,
                        })),
                    };
                    if asend(&mut src.stream, &ack).await.is_err() {
                        return;
                    }
                    loop {
                        let Some(raw) = src.next().await else { return };
                        let Ok(AIncoming::Message(apb::Frame {
                            frame: Some(apb::frame::Frame::Request(req)),
                        })) = ipc_admin::decode(raw, Side::Server)
                        else {
                            return;
                        };
                        encoded.lock().unwrap().push(req.encode_to_vec());
                        let mut got = Vec::new();
                        for slot in &req.secret_slots {
                            let Some(raw) = src.next().await else { return };
                            let Ok(AIncoming::Secret(sf)) = ipc_admin::decode(raw, Side::Server)
                            else {
                                return;
                            };
                            assert_eq!(sf.request_id, req.request_id);
                            assert_eq!(u32::from(sf.slot), slot.slot);
                            secrets.lock().unwrap().push((
                                sf.request_id,
                                sf.slot,
                                sf.secret.expose().to_vec(),
                            ));
                            got.push(sf.secret.expose().to_vec());
                        }
                        requests.lock().unwrap().push(req.clone());
                        let result = handler(req.clone(), got).await;
                        let f = apb::Frame {
                            frame: Some(apb::frame::Frame::Response(apb::Response {
                                request_id: req.request_id,
                                result: Some(result),
                            })),
                        };
                        if asend(&mut src.stream, &f).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Self {
            path,
            secrets,
            requests,
            encoded,
        }
    }

    pub fn commands(&self) -> Vec<&'static str> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter_map(|r| r.command.as_ref().map(ipc_admin::command_name))
            .collect()
    }
}

async fn asend(stream: &mut UnixStream, f: &apb::Frame) -> Result<(), ()> {
    let bytes = ipc_admin::encode_message(f, Side::Client).map_err(|_| ())?;
    stream.write_all(&bytes).await.map_err(|_| ())
}

/// An error message that makes a stand-in close the connection instead of answering.
pub const DROP: &str = "__drop_the_connection__";

pub fn privd_error(code: pb::ErrorCode, message: &str) -> pb::response::Result {
    pb::response::Result::Error(pb::Error {
        code: code as i32,
        detail: 0,
        message: message.into(),
        retryable: false,
        retry_after_ms: 0,
        stage: None,
    })
}

pub fn admin_error(code: pb::ErrorCode, message: &str) -> apb::response::Result {
    apb::response::Result::Error(pb::Error {
        code: code as i32,
        detail: 0,
        message: message.into(),
        retryable: false,
        retry_after_ms: 0,
        stage: None,
    })
}

// ----------------------------------------------------------------------------- the real stack

/// The real gateway, the real privd daemon, and the CLI's `Config` pointed at them.
pub struct World {
    pub gw: gateway_common::Env,
    pub privd: Harness,
    pub privd_admin: ScriptedPrivd,
    pub cfg: Config,
    pub dir: tempfile::TempDir,
}

impl World {
    pub async fn start() -> Self {
        let gw = gateway_common::Env::start().await;
        let privd = Harness::start(GW_UID);
        let dir = private_tempdir();
        let privd_admin = ScriptedPrivd::start(
            dir.path(),
            "privd-admin.sock",
            PrivdOptions::default(),
            daemon_handler(privd.daemon.clone()),
        )
        .await;
        let audit = dir.path().join("audit.log");
        let journalctl = write_script(dir.path(), "journalctl", "exit 0\n");
        let cfg = Config {
            privd_socket: privd_admin.path.clone(),
            admin_socket: gw.admin_path.clone(),
            audit_log: audit,
            audit_owner_uid: my_uid(),
            journalctl,
            verifier_params: CHEAP,
        };
        Self {
            gw,
            privd,
            privd_admin,
            cfg,
            dir,
        }
    }

    /// Registers the one desktop `main` (ready and running) in the real privd.
    pub fn add_desktop(&self) {
        self.privd
            .incus
            .add_desktop("hx-main", "ubuntu-24.04-xfce-basic", "alice", true);
        self.privd.daemon.register_desktop("main").unwrap();
    }
}

/// A temporary directory closed to group and others (the audit-log check requires it, and the
/// umask of the test environment may leave it open).
pub fn private_tempdir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().expect("tempdir");
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

/// Writes an audit-log stand-in: private, as the CLI requires of the real one.
pub fn write_audit(path: &Path, text: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// Writes an executable `#!/bin/sh` script and returns its path.
pub fn write_script(dir: &Path, name: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

/// Panics if `text` contains a character the terminal must never receive from a peer, other
/// than the newline and tab the CLI uses for layout.
pub fn assert_terminal_safe(text: &str) {
    for c in text.chars() {
        assert!(
            c == '\n' || c == '\t' || !hx_ipc::text::is_unsafe_char(c),
            "unsafe character {c:?} (U+{:04X}) in {text:?}",
            c as u32
        );
    }
}
