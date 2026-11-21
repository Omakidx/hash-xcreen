//! A fake Incus daemon on a real unix socket (served with hyper), for tests of the REST client
//! and everything built on it.

#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::net::UnixListener;

pub const OP_ID: &str = "6b2d0c1e-0a5e-4f0e-9a52-0f0b7d3e3b11";

pub fn fixture(name: &str) -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap_or_else(|e| panic!("fixture {name}: {e}"))
}

#[derive(Debug, Clone)]
pub struct Recorded {
    pub method: String,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl Recorded {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
    pub fn key(&self) -> String {
        format!("{} {}", self.method, self.path)
    }
}

#[derive(Clone)]
pub struct ExecRule {
    pub needle: String,
    pub exit: i64,
    pub stdout: String,
    pub stderr: String,
}

pub struct State {
    pub log: Vec<Recorded>,
    pub version: String,
    pub pools: HashMap<String, Value>,
    pub networks: HashMap<String, BTreeMap<String, String>>,
    pub acls: HashMap<String, Value>,
    pub profiles: HashMap<String, Value>,
    pub instances: HashMap<String, String>,
    pub snapshots: Vec<String>,
    pub exec_rules: Vec<ExecRule>,
    /// Answers to `systemctl is-system-running`, consumed in order; the last one repeats.
    pub running_states: VecDeque<String>,
    pub ops: HashMap<String, Value>,
    /// Files in the container (pushed, or written by the capture wrapper), by path.
    pub files: HashMap<String, Vec<u8>>,
    /// Store pushed `.../stdin-*` files, then answer the push with an error.
    pub fail_stdin_push_after_store: bool,
    /// Answer the second `PATCH /1.0/instances/<n>` with an error.
    pub fail_second_instance_patch: bool,
    /// `X-Incus-Type` answered for GET files of these paths (default `file`).
    pub file_types: HashMap<String, String>,
    /// Type answered for any other path, when set.
    pub default_file_type: Option<String>,
    pub instance_patches: u32,
    /// Instance-local devices by instance name, as `PATCH`/`PUT` set them.
    pub devices: HashMap<String, BTreeMap<String, BTreeMap<String, String>>>,
    /// Instance-local config by instance name, as `PATCH` sets it.
    pub config: HashMap<String, BTreeMap<String, String>>,
    /// Expanded (profile) devices answered for every instance.
    pub expanded_devices: BTreeMap<String, BTreeMap<String, String>>,
    /// Waits that answer `Running` before an operation completes.
    pub pending_waits: HashMap<String, u32>,
    pub next: u64,
    /// Respond to these `METHOD path` keys with a raw body instead (malformed-response tests).
    pub overrides: HashMap<String, (u16, String)>,
    /// Never complete operations.
    pub stuck_ops: bool,
    /// Operations a `DELETE` has been received for (they then wait as `Cancelled`).
    pub cancelled_ops: std::collections::HashSet<String>,
    /// Operations the daemon has purged (404).
    pub forgotten_ops: std::collections::HashSet<String>,
    /// Accept `DELETE /operations/<id>` but never end the operation.
    pub refuse_cancel: bool,
}

impl State {
    fn new() -> Self {
        Self {
            log: Vec::new(),
            version: "6.0.5".into(),
            pools: HashMap::new(),
            networks: HashMap::new(),
            acls: HashMap::new(),
            profiles: HashMap::new(),
            instances: HashMap::new(),
            snapshots: Vec::new(),
            exec_rules: Vec::new(),
            running_states: VecDeque::from(["running".to_string()]),
            ops: HashMap::new(),
            files: HashMap::new(),
            fail_stdin_push_after_store: false,
            fail_second_instance_patch: false,
            file_types: HashMap::new(),
            default_file_type: None,
            instance_patches: 0,
            devices: HashMap::new(),
            config: HashMap::new(),
            expanded_devices: BTreeMap::new(),
            pending_waits: HashMap::new(),
            next: 0,
            overrides: HashMap::new(),
            stuck_ops: false,
            cancelled_ops: Default::default(),
            forgotten_ops: Default::default(),
            refuse_cancel: false,
        }
    }
}

pub struct Fake {
    pub socket: PathBuf,
    pub state: Arc<Mutex<State>>,
    _dir: tempdir::Dir,
}

mod tempdir {
    pub struct Dir(pub std::path::PathBuf);
    impl Dir {
        pub fn new() -> Self {
            static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let p = std::env::temp_dir().join(format!(
                "hx-fake-incus-{}-{}",
                std::process::id(),
                N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Dir(p)
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn sync(meta: Value) -> (u16, String) {
    (200, json!({"type":"sync","status":"Success","status_code":200,"operation":"","error_code":0,"error":"","metadata":meta}).to_string())
}

fn not_found(what: &str) -> (u16, String) {
    (404, json!({"type":"error","error_code":404,"error":format!("{what} not found"),"metadata":null}).to_string())
}

impl State {
    fn new_op(&mut self, metadata: Value, waits: u32) -> (u16, String) {
        self.next += 1;
        let id = if self.next == 1 {
            OP_ID.to_string()
        } else {
            format!("00000000-0000-4000-8000-{:012}", self.next)
        };
        let done = json!({"id":id,"class":"task","status":"Success","status_code":200,"resources":{},"metadata":metadata,"may_cancel":false,"err":"","location":"none"});
        self.ops.insert(id.clone(), done);
        self.pending_waits.insert(id.clone(), waits);
        let running = json!({"id":id,"class":"task","status":"Running","status_code":103,"resources":{},"metadata":null,"may_cancel":false,"err":"","location":"none"});
        (
            200,
            json!({"type":"async","status":"Operation created","status_code":100,"operation":format!("/1.0/operations/{id}"),"error_code":0,"error":"","metadata":running}).to_string(),
        )
    }

    fn handle(&mut self, r: &Recorded) -> (u16, String) {
        if let Some(o) = self.overrides.get(&r.key()) {
            return o.clone();
        }
        let (path, _query) = r.path.split_once('?').unwrap_or((r.path.as_str(), ""));
        let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        let body = r.json();
        match (r.method.as_str(), segs.as_slice()) {
            ("GET", ["1.0"]) => {
                let mut v: Value = serde_json::from_str(&fixture("server_info.json")).unwrap();
                v["metadata"]["environment"]["server_version"] =
                    Value::String(self.version.clone());
                (200, v.to_string())
            }
            ("GET", ["1.0", "storage-pools", n]) => match self.pools.get(*n) {
                Some(p) => sync(p.clone()),
                None => not_found("pool"),
            },
            ("POST", ["1.0", "storage-pools"]) => {
                let n = body["name"].as_str().unwrap_or_default().to_string();
                self.pools.insert(n.clone(), json!({"name":n,"driver":body["driver"],"config":body["config"],"status":"Created"}));
                sync(Value::Null)
            }
            ("GET", ["1.0", "networks", n]) => match self.networks.get(*n) {
                Some(c) => sync(json!({"name":n,"type":"bridge","config":c,"status":"Created"})),
                None => not_found("network"),
            },
            ("POST", ["1.0", "networks"]) => {
                let n = body["name"].as_str().unwrap_or_default().to_string();
                let mut cfg: BTreeMap<String, String> =
                    serde_json::from_value(body["config"].clone()).unwrap_or_default();
                if cfg.get("ipv4.address").map(String::as_str) == Some("auto") {
                    cfg.insert("ipv4.address".into(), "10.99.1.1/24".into());
                }
                self.networks.insert(n, cfg);
                sync(Value::Null)
            }
            ("PATCH", ["1.0", "networks", n]) => {
                let add: BTreeMap<String, String> =
                    serde_json::from_value(body["config"].clone()).unwrap_or_default();
                match self.networks.get_mut(*n) {
                    Some(c) => {
                        c.extend(add);
                        sync(Value::Null)
                    }
                    None => not_found("network"),
                }
            }
            ("GET", ["1.0", "network-acls", n]) => match self.acls.get(*n) {
                Some(a) => sync(a.clone()),
                None => not_found("acl"),
            },
            ("POST", ["1.0", "network-acls"]) => {
                self.acls
                    .insert(body["name"].as_str().unwrap_or_default().to_string(), body);
                sync(Value::Null)
            }
            ("PUT", ["1.0", "network-acls", n]) => {
                self.acls.insert(n.to_string(), body);
                sync(Value::Null)
            }
            ("GET", ["1.0", "profiles", n]) => match self.profiles.get(*n) {
                Some(p) => sync(p.clone()),
                None => not_found("profile"),
            },
            ("POST", ["1.0", "profiles"]) => {
                self.profiles
                    .insert(body["name"].as_str().unwrap_or_default().to_string(), body);
                sync(Value::Null)
            }
            ("POST", ["1.0", "instances"]) => {
                self.instances.insert(
                    body["name"].as_str().unwrap_or_default().to_string(),
                    "Stopped".into(),
                );
                self.new_op(Value::Null, 1)
            }
            ("GET", ["1.0", "instances", n]) => match self.instances.get(*n) {
                Some(s) => {
                    let devices = self.devices.get(*n).cloned().unwrap_or_default();
                    let mut expanded = self.expanded_devices.clone();
                    expanded.extend(devices.clone());
                    sync(json!({
                        "name":n,"status":s,"type":"container","profiles":["p"],
                        "architecture":"x86_64",
                        "config":self.config.get(*n).cloned().unwrap_or_default(),
                        "devices":devices,"expanded_devices":expanded,
                    }))
                }
                None => not_found("instance"),
            },
            ("PUT", ["1.0", "instances", n]) => {
                if !self.instances.contains_key(*n) {
                    return not_found("instance");
                }
                let devs: BTreeMap<String, BTreeMap<String, String>> =
                    serde_json::from_value(body["devices"].clone()).unwrap_or_default();
                self.devices.insert(n.to_string(), devs);
                self.new_op(Value::Null, 0)
            }
            ("DELETE", ["1.0", "instances", n]) => {
                self.instances.remove(*n);
                self.new_op(Value::Null, 0)
            }
            ("PATCH", ["1.0", "instances", n]) => {
                self.instance_patches += 1;
                if let Ok(devs) = serde_json::from_value::<BTreeMap<String, BTreeMap<String, String>>>(
                    body["devices"].clone(),
                ) {
                    self.devices.entry(n.to_string()).or_default().extend(devs);
                }
                if let Ok(cfg) =
                    serde_json::from_value::<BTreeMap<String, String>>(body["config"].clone())
                {
                    self.config.entry(n.to_string()).or_default().extend(cfg);
                }
                if self.fail_second_instance_patch && self.instance_patches == 2 {
                    return (
                        500,
                        json!({"type":"error","error_code":500,"error":"busy"}).to_string(),
                    );
                }
                self.new_op(Value::Null, 0)
            }
            ("PUT", ["1.0", "instances", n, "state"]) => {
                let st = match body["action"].as_str() {
                    Some("stop") => "Stopped",
                    _ => "Running",
                };
                self.instances.insert(n.to_string(), st.into());
                self.new_op(Value::Null, 0)
            }
            ("GET", ["1.0", "instances", n, "state"]) => match self.instances.get(*n) {
                Some(s) => sync(
                    json!({"status":s,"pid":42,"network":{"eth0":{"addresses":[{"family":"inet","address":"10.99.1.5","scope":"global"},{"family":"inet6","address":"fe80::1","scope":"link"}]}}}),
                ),
                None => not_found("instance"),
            },
            ("POST", ["1.0", "instances", _, "files"]) => {
                let p = query_path(&r.path);
                if r.headers.get("x-incus-type").map(String::as_str) != Some("directory") {
                    self.files.insert(p.clone(), r.body.clone());
                }
                if self.fail_stdin_push_after_store && p.contains("/stdin-") {
                    return (
                        500,
                        json!({"type":"error","error_code":500,"error":"disk full"}).to_string(),
                    );
                }
                sync(Value::Null)
            }
            ("GET", ["1.0", "instances", _, "files"]) => match self.files.get(&query_path(&r.path))
            {
                Some(b) => (200, String::from_utf8_lossy(b).into_owned()),
                None => not_found("file"),
            },
            ("DELETE", ["1.0", "instances", _, "files"]) => {
                match self.files.remove(&query_path(&r.path)) {
                    Some(_) => sync(Value::Null),
                    None => not_found("file"),
                }
            }
            ("POST", ["1.0", "instances", n, "exec"]) => self.exec(n, &body),
            ("POST", ["1.0", "instances", _, "snapshots"]) => {
                self.snapshots
                    .push(body["name"].as_str().unwrap_or_default().to_string());
                self.new_op(Value::Null, 0)
            }
            ("DELETE", ["1.0", "instances", _, "snapshots", s]) => {
                self.snapshots.retain(|x| x != s);
                self.new_op(Value::Null, 0)
            }
            ("GET", ["1.0", "instances", n, "snapshots"]) => {
                let items: Vec<Value> = self
                    .snapshots
                    .iter()
                    .map(|s| json!({"name":format!("{n}/{s}"),"created_at":"2026-11-20T10:00:00Z","stateful":false}))
                    .collect();
                sync(Value::Array(items))
            }
            ("GET", ["1.0", "operations", id, "wait"]) => {
                if self.forgotten_ops.contains(*id) {
                    return not_found("operation");
                }
                if self.cancelled_ops.contains(*id) {
                    return sync(
                        json!({"id":id,"status":"Cancelled","status_code":401,"metadata":null,"err":""}),
                    );
                }
                if self.stuck_ops {
                    return sync(
                        json!({"id":id,"status":"Running","status_code":103,"metadata":null,"err":""}),
                    );
                }
                let left = self.pending_waits.entry(id.to_string()).or_insert(0);
                if *left > 0 {
                    *left -= 1;
                    return sync(
                        json!({"id":id,"status":"Running","status_code":103,"metadata":null,"err":""}),
                    );
                }
                match self.ops.get(*id) {
                    Some(op) => sync(op.clone()),
                    None => not_found("operation"),
                }
            }
            ("DELETE", ["1.0", "operations", id]) => {
                if self.forgotten_ops.contains(*id) {
                    return not_found("operation");
                }
                if !self.refuse_cancel {
                    self.cancelled_ops.insert(id.to_string());
                }
                sync(Value::Null)
            }
            _ => (
                599,
                format!("fake incus: unhandled {} {}", r.method, r.path),
            ),
        }
    }

    fn exec(&mut self, _instance: &str, body: &Value) -> (u16, String) {
        let cmd: Vec<String> = body["command"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        // The capture wrapper: sh -c SCRIPT sh <base> <stdin-file|""> timeout --kill-after=N SECS argv...
        let wrapped = cmd.first().map(String::as_str) == Some("sh")
            && cmd.get(3).map(String::as_str) == Some("sh")
            && cmd.len() > 6;
        let inner: Vec<String> = if wrapped {
            cmd[6..].to_vec()
        } else {
            cmd.clone()
        };
        let joined = inner.join(" ");
        let (exit, out, err) = if joined.contains("systemctl is-system-running") {
            let s = if self.running_states.len() > 1 {
                self.running_states.pop_front().unwrap()
            } else {
                self.running_states[0].clone()
            };
            (
                if s == "running" { 0 } else { 1 },
                format!("{s}\n"),
                String::new(),
            )
        } else {
            match self.exec_rules.iter().find(|r| joined.contains(&r.needle)) {
                Some(r) => (r.exit, r.stdout.clone(), r.stderr.clone()),
                None => (0, String::new(), String::new()),
            }
        };
        if wrapped {
            let base = &cmd[4];
            self.files.insert(format!("{base}.out"), out.into_bytes());
            self.files.insert(format!("{base}.err"), err.into_bytes());
            if !cmd[5].is_empty() {
                self.files.remove(&cmd[5]); // the wrapper removes the stdin file
            }
        }
        self.new_op(json!({ "return": exit }), 0)
    }
}

fn query_path(path: &str) -> String {
    let q = path.split_once("path=").map(|(_, q)| q).unwrap_or_default();
    let q = q.split('&').next().unwrap_or_default();
    let b = q.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Ok(v) = u8::from_str_radix(&q[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl Fake {
    pub async fn start() -> Self {
        let dir = tempdir::Dir::new();
        let socket = dir.0.join("unix.socket");
        let listener = UnixListener::bind(&socket).unwrap();
        let state = Arc::new(Mutex::new(State::new()));
        let st = state.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let st = st.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let st = st.clone();
                        async move {
                            let method = req.method().to_string();
                            let path = req
                                .uri()
                                .path_and_query()
                                .map(|p| p.to_string())
                                .unwrap_or_default();
                            let headers = req
                                .headers()
                                .iter()
                                .map(|(k, v)| {
                                    (
                                        k.as_str().to_ascii_lowercase(),
                                        v.to_str().unwrap_or_default().to_string(),
                                    )
                                })
                                .collect();
                            let body = req
                                .into_body()
                                .collect()
                                .await
                                .map(|b| b.to_bytes().to_vec())
                                .unwrap_or_default();
                            let rec = Recorded {
                                method,
                                path,
                                headers,
                                body,
                            };
                            let (status, text, ftype) = {
                                let mut s = st.lock().unwrap();
                                s.log.push(rec.clone());
                                let ft = (rec.method == "GET" && rec.path.contains("/files?path="))
                                    .then(|| {
                                        s.file_types
                                            .get(&query_path(&rec.path))
                                            .cloned()
                                            .or_else(|| s.default_file_type.clone())
                                            .unwrap_or_else(|| "file".to_string())
                                    });
                                let (status, text) = s.handle(&rec);
                                (status, text, ft)
                            };
                            Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(status)
                                    .header("X-Incus-Type", ftype.unwrap_or_default())
                                    .header("Content-Type", "application/json")
                                    .body(Full::new(Bytes::from(text)))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        Fake {
            socket,
            state,
            _dir: dir,
        }
    }

    pub fn client(&self) -> hx_provision::incus::Client<hx_provision::incus::UnixTransport> {
        hx_provision::incus::Client::unix(&self.socket)
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        f(&mut self.state.lock().unwrap())
    }

    pub fn log(&self) -> Vec<Recorded> {
        self.with(|s| s.log.clone())
    }

    pub fn keys(&self) -> Vec<String> {
        self.log().iter().map(Recorded::key).collect()
    }

    pub fn rule(&self, needle: &str, exit: i64, stdout: &str, stderr: &str) {
        self.with(|s| {
            s.exec_rules.push(ExecRule {
                needle: needle.into(),
                exit,
                stdout: stdout.into(),
                stderr: stderr.into(),
            })
        });
    }
}
