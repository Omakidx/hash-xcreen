//! Test support (feature `test-support` and unit tests): fakes for everything privd talks to, a
//! harness that runs the daemon in-process on a temporary socket, and a raw client that speaks the
//! wire protocol through `hx-ipc`.
//!
//! None of this is reachable from the binary: the daemon binary never enables the feature, and
//! the constructors that inject a gateway uid live only here and in `PrivdConfig::for_tests`.

use std::collections::BTreeMap;
use std::future::Future;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use hx_ipc::privd::pb::{self, frame::Frame as F, request::Command};
use hx_ipc::privd::{self, Incoming, PrivdPolicy, Side};
use hx_ipc::{Decoder, NoCmsgReader};
use hx_provision::incus::{Client, IncusError, Request, Response, Transport};
use serde_json::{Value, json};

use super::audit::MemoryAudit;
use super::clock::ManualClock;
use super::config::PrivdConfig;
use super::daemon::{Daemon, Deps};
use super::identity::GatewayIdentity;
use super::probe::HostProbe;
use super::runner::{CommandRunner, Program, RunFuture, RunOutput};

// ----- fake runner and probe -----------------------------------------------------------------

type RunnerRule = Box<dyn FnMut(&Program) -> RunOutput + Send>;

/// A runner that records every program and answers with a script (success by default). Used to
/// test `nft`, `sysctl`, `iptables`, `ip` and `blkid` handling without root.
pub struct FakeRunner {
    calls: Mutex<Vec<Program>>,
    rule: Mutex<RunnerRule>,
}

impl FakeRunner {
    /// Every call succeeds with empty output.
    pub fn new() -> Arc<Self> {
        Self::with(|_| RunOutput {
            code: Some(0),
            ..RunOutput::default()
        })
    }

    /// Answers with `f`.
    pub fn with(f: impl FnMut(&Program) -> RunOutput + Send + 'static) -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            rule: Mutex::new(Box::new(f)),
        })
    }

    /// Every program run so far.
    pub fn calls(&self) -> Vec<Program> {
        self.calls.lock().map(|c| c.clone()).unwrap_or_default()
    }
}

impl CommandRunner for FakeRunner {
    fn run<'a>(&'a self, program: Program) -> RunFuture<'a> {
        let out = {
            let mut rule = self.rule.lock().unwrap_or_else(|e| e.into_inner());
            rule(&program)
        };
        self.calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(program);
        Box::pin(async move { Ok(out) })
    }
}

/// Host facts with chosen numbers.
#[derive(Debug, Clone)]
pub struct FakeProbe {
    /// CPUs.
    pub cpus: u32,
    /// Total RAM, MiB.
    pub mem_total_mib: u64,
    /// Available RAM, MiB.
    pub mem_available_mib: u64,
    /// `(total, free)` bytes of the pool.
    pub pool: Option<(u64, u64)>,
    /// Free bytes where Incus keeps its data.
    pub incus_free: Option<u64>,
    /// Whether the sysctls are in place.
    pub sysctl_ok: bool,
}

impl Default for FakeProbe {
    fn default() -> Self {
        const GIB: u64 = 1 << 30;
        Self {
            cpus: 8,
            mem_total_mib: 16_384,
            mem_available_mib: 8_192,
            pool: Some((100 * GIB, 80 * GIB)),
            incus_free: Some(500 * GIB),
            sysctl_ok: true,
        }
    }
}

impl HostProbe for FakeProbe {
    fn cpu_count(&self) -> u32 {
        self.cpus
    }
    fn memory_mib(&self) -> (u64, u64) {
        (self.mem_total_mib, self.mem_available_mib)
    }
    fn os_release(&self) -> (String, String) {
        ("ubuntu".into(), "24.04".into())
    }
    fn pool_space(&self, _pool: &str) -> Option<(u64, u64)> {
        self.pool
    }
    fn incus_dir_free(&self) -> Option<u64> {
        self.incus_free
    }
    fn sysctl_ok(&self) -> bool {
        self.sysctl_ok
    }
}

// ----- fake Incus ----------------------------------------------------------------------------

/// An instance of the fake daemon.
#[derive(Debug, Clone, Default)]
pub struct FakeInstance {
    /// `Running` or `Stopped`.
    pub status: String,
    /// Instance config.
    pub config: BTreeMap<String, String>,
    /// Instance devices.
    pub devices: BTreeMap<String, BTreeMap<String, String>>,
    /// Snapshot names.
    pub snapshots: Vec<String>,
}

struct FakeOp {
    instance: String,
    /// When it completes; `None` means never, until its instance is stopped or deleted.
    ready_at: Option<Instant>,
    ended: bool,
    exit: i32,
}

/// What an exec does: matched by a substring of the joined command.
#[derive(Debug, Clone)]
pub struct ExecRule {
    /// Substring of the command line.
    pub needle: String,
    /// Exit status.
    pub exit: i32,
    /// Captured stdout.
    pub stdout: String,
    /// Run for this long first; `None` hangs until the instance is stopped.
    pub delay: Option<Duration>,
}

/// The mutable state of [`FakeIncus`].
pub struct FakeState {
    /// Instances by name.
    pub instances: BTreeMap<String, FakeInstance>,
    /// Whether the storage pool exists.
    pub pool_exists: bool,
    /// `METHOD path` of every request, in order.
    pub log: Vec<String>,
    /// Exec rules, first match wins.
    pub exec_rules: Vec<ExecRule>,
    /// Files in instances by path.
    pub files: BTreeMap<String, Vec<u8>>,
    /// Commands passed to `exec`, joined, in order.
    pub execs: Vec<String>,
    /// Push bodies by path (first 64 bytes only; for assertions about secrets never leaking).
    pub pushed: Vec<(String, usize)>,
    ops: BTreeMap<String, FakeOp>,
    next_op: u64,
}

/// A fake Incus daemon implementing [`Transport`]: enough of the REST API for the commands.
#[derive(Clone)]
pub struct FakeIncus {
    inner: Arc<Mutex<FakeState>>,
}

fn ok_sync(meta: Value) -> Response {
    json_response(
        200,
        json!({"type": "sync", "status": "Success", "status_code": 200, "metadata": meta}),
    )
}

fn json_response(status: u16, v: Value) -> Response {
    Response {
        status,
        body: Bytes::from(serde_json::to_vec(&v).unwrap_or_default()),
        headers: BTreeMap::new(),
    }
}

fn err_response(code: u16, msg: &str) -> Response {
    json_response(
        code,
        json!({"type": "error", "error_code": code, "error": msg}),
    )
}

impl Default for FakeIncus {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeIncus {
    /// An Incus with the pool present and no instances; `systemctl is-system-running` answers
    /// `running`.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(FakeState {
                instances: BTreeMap::new(),
                pool_exists: true,
                log: Vec::new(),
                exec_rules: vec![ExecRule {
                    needle: "is-system-running".into(),
                    exit: 0,
                    stdout: "running\n".into(),
                    delay: Some(Duration::ZERO),
                }],
                files: BTreeMap::new(),
                execs: Vec::new(),
                pushed: Vec::new(),
                ops: BTreeMap::new(),
                next_op: 1,
            })),
        }
    }

    /// Reads or changes the state.
    pub fn with<R>(&self, f: impl FnOnce(&mut FakeState) -> R) -> R {
        f(&mut self.inner.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// A [`Client`] on this fake.
    pub fn client(&self) -> Client<FakeIncus> {
        Client::new(self.clone())
    }

    /// Adds a ready, running desktop named `name` (an instance name such as `hx-main`).
    pub fn add_desktop(&self, name: &str, recipe: &str, username: &str, running: bool) {
        self.with(|s| {
            let mut cfg = BTreeMap::new();
            for (k, v) in [
                ("user.hx.state", "ready"),
                ("user.hx.username", username),
                ("user.hx.recipe", recipe),
                ("user.hx.created", "1700000000"),
                ("limits.cpu", "2"),
                ("limits.memory", "4096MiB"),
            ] {
                cfg.insert(k.to_string(), v.to_string());
            }
            let mut root = BTreeMap::new();
            for (k, v) in [
                ("type", "disk"),
                ("path", "/"),
                ("pool", "hx-pool"),
                ("size", "20GiB"),
            ] {
                root.insert(k.to_string(), v.to_string());
            }
            s.instances.insert(
                name.to_string(),
                FakeInstance {
                    status: if running { "Running" } else { "Stopped" }.into(),
                    config: cfg,
                    devices: [("root".to_string(), root)].into_iter().collect(),
                    snapshots: Vec::new(),
                },
            );
        });
    }

    /// Instance names currently present.
    pub fn instance_names(&self) -> Vec<String> {
        self.with(|s| s.instances.keys().cloned().collect())
    }

    /// `METHOD path` of every request so far.
    pub fn log(&self) -> Vec<String> {
        self.with(|s| s.log.clone())
    }

    fn end_ops_of(s: &mut FakeState, instance: &str) {
        for op in s.ops.values_mut().filter(|o| o.instance == instance) {
            op.ended = true;
        }
    }

    async fn handle(&self, req: Request) -> Result<Response, IncusError> {
        let (path, query) = req.path.split_once('?').unwrap_or((req.path.as_str(), ""));
        let method = req.method.as_str().to_string();
        let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
        let query_path = || {
            query
                .split('&')
                .find_map(|kv| kv.strip_prefix("path="))
                .map(|p| p.replace("%2F", "/"))
                .unwrap_or_default()
        };

        // The wait endpoint may need to sleep without holding the lock.
        if let ["1.0", "operations", id, "wait"] = segs.as_slice() {
            let id = (*id).to_string();
            let pending = {
                let mut s = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                s.log.push(format!("{method} {path}"));
                match s.ops.get(&id) {
                    None => return Ok(err_response(404, "not found")),
                    Some(op) => {
                        let due = op.ready_at.is_some_and(|t| Instant::now() >= t);
                        !(op.ended || due)
                    }
                }
            };
            if pending {
                tokio::time::sleep(Duration::from_millis(20)).await;
                let still = {
                    let s = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                    s.ops.get(&id).is_some_and(|op| {
                        !(op.ended || op.ready_at.is_some_and(|t| Instant::now() >= t))
                    })
                };
                if still {
                    return Ok(err_response(500, "context deadline exceeded"));
                }
            }
            let s = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let Some(op) = s.ops.get(&id) else {
                return Ok(err_response(404, "not found"));
            };
            let (code, status) = if op.ended && op.ready_at.is_none() {
                (400, "Failure")
            } else {
                (200, "Success")
            };
            return Ok(ok_sync(json!({
                "id": id, "status": status, "status_code": code,
                "err": if code == 400 { "the instance was stopped" } else { "" },
                "metadata": {"return": op.exit},
            })));
        }

        let mut s = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        s.log.push(format!("{method} {path}"));
        let segs = segs.as_slice();
        Ok(match (method.as_str(), segs) {
            ("GET", ["1.0"]) => ok_sync(json!({
                "api_version": "1.0", "auth": "trusted",
                "environment": {"server_version": "6.0.0", "firewall": "nftables",
                    "kernel_version": "6.8", "storage_supported_drivers": [{"Name": "btrfs"}]}
            })),
            ("GET", ["1.0", "storage-pools", _]) => {
                if s.pool_exists {
                    ok_sync(json!({"name": "hx-pool", "driver": "btrfs", "config": {},
                        "status": "Created", "description": "hash-xcreen: storage pool for desktops"}))
                } else {
                    err_response(404, "not found")
                }
            }
            ("POST", ["1.0", "instances"]) => {
                let name = body["name"].as_str().unwrap_or_default().to_string();
                let map = |v: &Value| -> BTreeMap<String, String> {
                    v.as_object()
                        .map(|o| {
                            o.iter()
                                .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
                                .collect()
                        })
                        .unwrap_or_default()
                };
                let devices = body["devices"]
                    .as_object()
                    .map(|o| o.iter().map(|(k, v)| (k.clone(), map(v))).collect())
                    .unwrap_or_default();
                s.instances.insert(
                    name,
                    FakeInstance {
                        status: "Stopped".into(),
                        config: map(&body["config"]),
                        devices,
                        snapshots: Vec::new(),
                    },
                );
                ok_sync(Value::Null)
            }
            ("GET", ["1.0", "instances", name]) => match s.instances.get(*name) {
                None => err_response(404, "Instance not found"),
                Some(i) => {
                    let mut devices = i.devices.clone();
                    devices.entry("root".into()).or_insert_with(|| {
                        [("type", "disk"), ("path", "/"), ("pool", "hx-pool")]
                            .into_iter()
                            .map(|(k, v)| (k.to_string(), v.to_string()))
                            .collect()
                    });
                    let mut r = ok_sync(json!({
                        "name": name, "status": i.status, "type": "container",
                        "profiles": ["hx-desktop"], "config": i.config, "description": "",
                        "architecture": "x86_64", "devices": i.devices,
                        "expanded_devices": devices,
                    }));
                    r.headers.insert("etag".into(), "etag-1".into());
                    r
                }
            },
            ("PATCH", ["1.0", "instances", name]) | ("PUT", ["1.0", "instances", name]) => {
                let replace = method == "PUT";
                let Some(i) = s.instances.get_mut(*name) else {
                    return Ok(err_response(404, "Instance not found"));
                };
                if let Some(o) = body["config"].as_object() {
                    if replace {
                        i.config.clear();
                    }
                    for (k, v) in o {
                        if let Some(v) = v.as_str() {
                            i.config.insert(k.clone(), v.to_string());
                        }
                    }
                }
                if let Some(o) = body["devices"].as_object() {
                    if replace {
                        i.devices.clear();
                    }
                    for (k, v) in o {
                        let d: BTreeMap<String, String> = v
                            .as_object()
                            .map(|m| {
                                m.iter()
                                    .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
                                    .collect()
                            })
                            .unwrap_or_default();
                        i.devices.entry(k.clone()).or_default().extend(d);
                    }
                }
                ok_sync(Value::Null)
            }
            ("DELETE", ["1.0", "instances", name]) => {
                Self::end_ops_of(&mut s, name);
                s.instances.remove(*name);
                ok_sync(Value::Null)
            }
            ("PUT", ["1.0", "instances", name, "state"]) => {
                let action = body["action"].as_str().unwrap_or_default().to_string();
                let Some(i) = s.instances.get_mut(*name) else {
                    return Ok(err_response(404, "Instance not found"));
                };
                match action.as_str() {
                    "start" | "restart" => i.status = "Running".into(),
                    "stop" => {
                        i.status = "Stopped".into();
                        Self::end_ops_of(&mut s, name);
                    }
                    _ => {}
                }
                ok_sync(Value::Null)
            }
            ("GET", ["1.0", "instances", name, "state"]) => match s.instances.get(*name) {
                None => err_response(404, "Instance not found"),
                Some(i) => ok_sync(json!({"status": i.status, "pid": 1,
                    "network": {"eth0": {"addresses": [
                        {"family": "inet", "scope": "global", "address": "10.77.0.5"}]}}})),
            },
            ("GET", ["1.0", "instances", name, "snapshots"]) => match s.instances.get(*name) {
                None => err_response(404, "Instance not found"),
                Some(i) => ok_sync(Value::Array(
                    i.snapshots
                        .iter()
                        .map(|n| {
                            json!({"name": format!("{name}/{n}"),
                            "created_at": "2026-11-21T09:15:00.000000000Z", "stateful": false})
                        })
                        .collect(),
                )),
            },
            ("POST", ["1.0", "instances", name, "snapshots"]) => {
                let n = body["name"].as_str().unwrap_or_default().to_string();
                if let Some(i) = s.instances.get_mut(*name) {
                    i.snapshots.push(n);
                }
                ok_sync(Value::Null)
            }
            ("DELETE", ["1.0", "instances", name, "snapshots", snap]) => {
                if let Some(i) = s.instances.get_mut(*name) {
                    i.snapshots.retain(|n| n != snap);
                }
                ok_sync(Value::Null)
            }
            ("POST", ["1.0", "instances", name, "exec"]) => {
                let command: Vec<String> = body["command"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                let joined = command.join(" ");
                s.execs.push(joined.clone());
                let rule = s
                    .exec_rules
                    .iter()
                    .find(|r| joined.contains(&r.needle))
                    .cloned();
                let (exit, stdout, delay) = rule.map(|r| (r.exit, r.stdout, r.delay)).unwrap_or((
                    0,
                    String::new(),
                    Some(Duration::ZERO),
                ));
                // The capture wrapper: `sh -c SCRIPT sh <base> <stdin> timeout ...`.
                if command.first().map(String::as_str) == Some("sh")
                    && let Some(base) = command.get(4)
                {
                    s.files.insert(format!("{base}.out"), stdout.into_bytes());
                }
                let id = format!("op-{}", s.next_op);
                s.next_op += 1;
                let op = FakeOp {
                    instance: (*name).to_string(),
                    ready_at: delay.map(|d| Instant::now() + d),
                    ended: false,
                    exit,
                };
                s.ops.insert(id.clone(), op);
                json_response(
                    200,
                    json!({"type": "async", "status_code": 100,
                        "operation": format!("/1.0/operations/{id}"), "metadata": {"id": id}}),
                )
            }
            ("DELETE", ["1.0", "operations", id]) => {
                // Exec operations cannot be cancelled on Incus 6.0.0.
                if s.ops.contains_key(*id) {
                    err_response(400, "This operation can't be cancelled")
                } else {
                    err_response(404, "not found")
                }
            }
            ("GET", ["1.0", "instances", _, "files"]) => match s.files.get(&query_path()) {
                Some(b) => {
                    let mut r = Response {
                        status: 200,
                        body: Bytes::from(b.clone()),
                        headers: BTreeMap::new(),
                    };
                    r.headers.insert("x-incus-type".into(), "file".into());
                    r
                }
                None => err_response(404, "not found"),
            },
            ("POST", ["1.0", "instances", _, "files"]) => {
                let p = query_path();
                s.pushed.push((p.clone(), req.body.len()));
                if req
                    .headers
                    .iter()
                    .any(|(k, v)| k.eq_ignore_ascii_case("x-incus-type") && v == "file")
                {
                    s.files.insert(p, req.body.to_vec());
                }
                ok_sync(Value::Null)
            }
            ("DELETE", ["1.0", "instances", _, "files"]) => {
                s.files.remove(&query_path());
                ok_sync(Value::Null)
            }
            _ => err_response(404, "the fake daemon does not implement this"),
        })
    }
}

impl Transport for FakeIncus {
    fn send(&self, request: Request) -> impl Future<Output = Result<Response, IncusError>> + Send {
        async move { self.handle(request).await }
    }
}

// ----- the harness: privd in-process on a temporary socket ----------------------------------------

/// A running daemon on a temporary socket with fakes behind it.
pub struct Harness {
    /// The daemon.
    pub daemon: Arc<Daemon<FakeIncus>>,
    /// The fake Incus.
    pub incus: FakeIncus,
    /// The fake runner.
    pub runner: Arc<FakeRunner>,
    /// The audit lines.
    pub audit: Arc<MemoryAudit>,
    /// The clock.
    pub clock: Arc<ManualClock>,
    /// The temporary directory (state, socket, package store).
    pub dir: tempfile::TempDir,
    /// The socket path.
    pub socket: PathBuf,
    /// The gateway uid the daemon was configured with.
    pub gateway_uid: u32,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Harness {
    /// A daemon whose **gateway uid is `gateway_uid`** (the test constructor; never reachable from
    /// config, environment or argv) and whose Admin is uid 0. Running tests as an ordinary user
    /// the real peer uid is that user's: pass its own uid to be the Gateway, or a different one to
    /// be refused (an ordinary user is never uid 0, so no test connection is Admin; Admin is
    /// exercised through [`Harness::daemon`]'s `handle` with a `Ctx`).
    pub fn start(gateway_uid: u32) -> Self {
        Self::start_with(
            gateway_uid,
            FakeProbe::default(),
            FakeIncus::new(),
            FakeRunner::new(),
        )
    }

    /// Like [`Harness::start`] with chosen fakes.
    pub fn start_with(
        gateway_uid: u32,
        probe: FakeProbe,
        incus: FakeIncus,
        runner: Arc<FakeRunner>,
    ) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = PrivdConfig::for_tests(
            dir.path(),
            GatewayIdentity {
                uid: gateway_uid,
                gid: gateway_uid,
            },
        );
        let socket = cfg.socket_path.clone();
        let audit = Arc::new(MemoryAudit::default());
        let clock = Arc::new(ManualClock::new(1_800_000_000));
        let daemon = Daemon::new(
            cfg,
            incus.client(),
            Deps {
                runner: runner.clone(),
                probe: Arc::new(probe),
                clock: clock.clone(),
                audit: audit.clone(),
            },
        )
        .expect("daemon");
        let listener = super::activation::bind_path(&socket).expect("bind");
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let d = daemon.clone();
        tokio::spawn(async move {
            let _ = super::server::serve(
                d,
                listener,
                super::server::ServeOptions {
                    background_tasks: false,
                },
                async {
                    let _ = rx.await;
                },
            )
            .await;
        });
        Self {
            daemon,
            incus,
            runner,
            audit,
            clock,
            dir,
            socket,
            gateway_uid,
            shutdown: Some(tx),
        }
    }

    /// Connects a raw client.
    pub fn connect(&self) -> RawClient {
        RawClient::connect(&self.socket)
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

// ----- the raw client ---------------------------------------------------------------------------

/// A blocking client over `hx-ipc`, the way gatewayd's client talks to privd. Methods panic on
/// protocol surprises, which is what a test wants.
pub struct RawClient {
    /// The socket.
    pub stream: UnixStream,
    decoder: Decoder<PrivdPolicy>,
    next_id: u64,
}

impl RawClient {
    /// Connects.
    pub fn connect(path: &std::path::Path) -> Self {
        let stream = UnixStream::connect(path).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        Self {
            stream,
            decoder: Decoder::new(PrivdPolicy::new(Side::Client)),
            next_id: 1,
        }
    }

    /// Sends a frame.
    pub fn send(&mut self, frame: F) {
        let bytes =
            privd::encode_message(&pb::Frame { frame: Some(frame) }, Side::Server).expect("encode");
        self.stream.write_all(&bytes).expect("write");
    }

    /// Sends bytes as they are (malformed frames).
    pub fn send_raw(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).expect("write");
    }

    /// Sends a secret frame.
    pub fn send_secret(&mut self, request_id: u64, slot: u8, secret: &[u8]) {
        let bytes = privd::encode_secret(request_id, slot, secret).expect("encode secret");
        self.stream.write_all(&bytes).expect("write");
    }

    /// The next frame from the daemon, or `None` at end of stream or on a read error.
    pub fn try_recv(&mut self) -> Option<pb::Frame> {
        let raw = self
            .decoder
            .read_from(&mut NoCmsgReader(&self.stream))
            .ok()??;
        match privd::decode(raw, Side::Client).ok()? {
            Incoming::Message(f) => Some(f),
            Incoming::Secret(_) => None,
        }
    }

    /// The next frame; panics if there is none.
    pub fn recv(&mut self) -> pb::Frame {
        self.try_recv().expect("a frame from privd")
    }

    /// `Hello` and the `HelloAck` it earns.
    pub fn hello(&mut self) -> pb::HelloAck {
        self.send(F::Hello(pb::Hello {
            major: privd::VERSION_MAJOR,
            minor: privd::VERSION_MINOR,
            software: "test".into(),
        }));
        match self.recv().frame {
            Some(F::HelloAck(a)) => a,
            other => panic!("expected HelloAck, got {other:?}"),
        }
    }

    /// A fresh request id.
    pub fn fresh_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    /// Sends a request (with its secret frames) and returns the `Response`, skipping `Progress`.
    pub fn call(&mut self, command: Command, secrets: &[(pb::SecretKind, &[u8])]) -> pb::Response {
        let id = self.fresh_id();
        self.call_with_id(id, command, secrets, 0)
    }

    /// [`RawClient::call`] with a chosen id and deadline.
    pub fn call_with_id(
        &mut self,
        id: u64,
        command: Command,
        secrets: &[(pb::SecretKind, &[u8])],
        deadline_ms: u32,
    ) -> pb::Response {
        self.send_request(id, command, secrets, deadline_ms);
        self.wait_response(id)
    }

    /// Sends a request and its secrets without waiting.
    pub fn send_request(
        &mut self,
        id: u64,
        command: Command,
        secrets: &[(pb::SecretKind, &[u8])],
        deadline_ms: u32,
    ) {
        let slots = secrets
            .iter()
            .enumerate()
            .map(|(i, (k, s))| pb::SecretSlot {
                slot: i as u32,
                kind: *k as i32,
                sealed: false,
                length: s.len() as u32,
                ..Default::default()
            })
            .collect();
        self.send(F::Request(pb::Request {
            request_id: id,
            deadline_ms,
            secret_slots: slots,
            command: Some(command),
        }));
        for (i, (_, s)) in secrets.iter().enumerate() {
            self.send_secret(id, i as u8, s);
        }
    }

    /// Reads frames until the `Response` of `id`.
    pub fn wait_response(&mut self, id: u64) -> pb::Response {
        loop {
            match self.recv().frame {
                Some(F::Response(r)) if r.request_id == id => return r,
                Some(F::Progress(_) | F::Pong(_)) => {}
                other => panic!("unexpected frame while waiting for a response: {other:?}"),
            }
        }
    }
}

/// The error of a response, if it is one.
pub fn error_of(r: &pb::Response) -> Option<&pb::Error> {
    match &r.result {
        Some(pb::response::Result::Error(e)) => Some(e),
        _ => None,
    }
}

/// Short constructor of a request for a command with no arguments that matter.
pub fn request(id: u64, command: Command) -> pb::Request {
    pb::Request {
        request_id: id,
        deadline_ms: 0,
        secret_slots: Vec::new(),
        command: Some(command),
    }
}
