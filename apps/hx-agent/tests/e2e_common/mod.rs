//! Helpers of `e2e_real_incus.rs`: the Incus transport shim, the apt proxy, the host-side fakes
//! that keep the run off the host's firewall, the `incus` command line, the real `hx-gatewayd`
//! process, an FFmpeg decoder and a few measurements.
//!
//! Nothing here is production code. Every deviation from a production host is listed in the
//! test's module documentation and in `docs/spikes/1c-e2e-real-incus.md`.
#![allow(dead_code)]

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use hx_agent::privd::probe::{HostProbe, SystemProbe};
use hx_agent::privd::runner::{CommandRunner, Program, RunFuture, RunOutput, SystemRunner, Tool};
use hx_agent::privd::testing::RawClient;
use hx_ipc::privd::pb;
use hx_provision::incus::{IncusError, Request, Response, Transport, UnixTransport};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub const PREFIX: &str = "hx3e-";
pub const INSTANCE: &str = "hx3e-main";
pub const USER: &str = "alice";
pub const UID: u32 = 1000;

// ----- the results table ------------------------------------------------------------------------------

static ROWS: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

/// Records one passed check for the final table (a failed one panics at once).
pub fn pass(check: &str, detail: impl std::fmt::Display) {
    let detail = detail.to_string();
    eprintln!("PASS [{check}] {detail}");
    ROWS.lock().unwrap().push((check.to_string(), detail));
}

pub fn print_rows() {
    for (c, d) in ROWS.lock().unwrap().iter() {
        eprintln!("RESULT | {c} | PASS | {d}");
    }
}

// ----- the Incus transport shim (the same one as privd_real_incus.rs) ------------------------------------

#[derive(Clone)]
pub struct Shim {
    pub inner: UnixTransport,
    /// `http://gateway:port` of the apt proxy, once the bridge exists.
    pub proxy: Arc<Mutex<Option<String>>>,
    /// A locally cached image fingerprint for the recipe's distro.
    pub image: Arc<Option<String>>,
    /// The host directory standing in for `/run/hx/link`.
    pub link_dir: Arc<String>,
}

const PROD_LINK_PREFIX: &str = "unix:/run/hx/link/";

impl Transport for Shim {
    async fn send(&self, mut req: Request) -> Result<Response, IncusError> {
        let test_prefix = format!("unix:{}/", self.link_dir);
        if req.method == hyper::Method::POST && req.path == "/1.0/instances" {
            let mut v: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            let proxy = self.proxy.lock().unwrap().clone();
            if let (Some(cfg), Some(proxy)) = (v["config"].as_object_mut(), proxy) {
                for k in ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"] {
                    cfg.insert(format!("environment.{k}"), Value::String(proxy.clone()));
                }
            }
            if let Some(fp) = self.image.as_ref() {
                v["source"] = serde_json::json!({"type": "image", "fingerprint": fp});
            }
            req.body = Bytes::from(serde_json::to_vec(&v).unwrap());
        }
        if req.path.starts_with("/1.0/instances/") && !req.body.is_empty() {
            let s = String::from_utf8_lossy(&req.body).replace(PROD_LINK_PREFIX, &test_prefix);
            req.body = Bytes::from(s.into_bytes());
        }
        let mut resp = self.inner.send(req).await?;
        if !resp.body.is_empty() {
            let s = String::from_utf8_lossy(&resp.body).replace(&test_prefix, PROD_LINK_PREFIX);
            resp.body = Bytes::from(s.into_bytes());
        }
        Ok(resp)
    }
}

pub fn socket() -> String {
    std::env::var("HX_INCUS_SOCKET").unwrap_or_else(|_| UnixTransport::DEFAULT_SOCKET.to_string())
}

/// The fingerprint of the cached Ubuntu 24.04 container image, if there is one.
pub async fn local_image() -> Option<String> {
    use hyper::Method;
    let t = UnixTransport::new(socket());
    let r = t
        .send(Request {
            method: Method::GET,
            path: "/1.0/images?recursion=1".into(),
            headers: vec![],
            body: Bytes::new(),
            content_type: None,
            max_response: None,
            timeout: Duration::from_secs(60),
        })
        .await
        .ok()?;
    let v: Value = serde_json::from_slice(&r.body).ok()?;
    v["metadata"].as_array()?.iter().find_map(|i| {
        let p = &i["properties"];
        let ok = p["os"]
            .as_str()
            .is_some_and(|s| s.eq_ignore_ascii_case("ubuntu"))
            && p["release"]
                .as_str()
                .is_some_and(|r| ["noble", "24.04"].contains(&r))
            && i["type"] == "container"
            && i["architecture"] == "x86_64";
        ok.then(|| i["fingerprint"].as_str().map(str::to_string))?
    })
}

// ----- host-side stand-ins: no firewall, no sysctl ------------------------------------------------------------

/// Runs `ip` and `blkid` for real, and answers every other host tool without running it: `nft` and
/// `sysctl` succeed (so `SetupHost` reaches the end), `iptables` says there is no `DOCKER-USER`
/// chain. Nothing on the host's firewall is read or changed. The programs it was asked for are
/// kept, to show in the report.
#[derive(Default)]
pub struct HostRunner {
    pub log: Mutex<Vec<String>>,
}

impl CommandRunner for HostRunner {
    fn run<'a>(&'a self, p: Program) -> RunFuture<'a> {
        self.log
            .lock()
            .unwrap()
            .push(format!("{} {}", p.tool.name(), p.args.join(" ")));
        match p.tool {
            Tool::Ip | Tool::Blkid => SystemRunner.run(p),
            Tool::Nft | Tool::Sysctl => Box::pin(async {
                Ok(RunOutput {
                    code: Some(0),
                    ..RunOutput::default()
                })
            }),
            _ => Box::pin(async {
                Ok(RunOutput {
                    code: Some(1),
                    stderr: "not run by the end-to-end test".into(),
                    ..RunOutput::default()
                })
            }),
        }
    }
}

/// The real host's numbers; the free space is that of `/var/lib` (Incus's directory is not
/// readable for this user) and the sysctls count as applied (the stand-in runner did not apply
/// them).
pub struct RealProbe(pub SystemProbe);

impl HostProbe for RealProbe {
    fn cpu_count(&self) -> u32 {
        self.0.cpu_count()
    }
    fn memory_mib(&self) -> (u64, u64) {
        self.0.memory_mib()
    }
    fn os_release(&self) -> (String, String) {
        self.0.os_release()
    }
    fn pool_space(&self, pool: &str) -> Option<(u64, u64)> {
        self.0.pool_space(pool).or(Some((30 << 30, 25 << 30)))
    }
    fn incus_dir_free(&self) -> Option<u64> {
        let s = rustix::fs::statvfs("/var/lib").ok()?;
        Some(s.f_bavail.saturating_mul(s.f_frsize))
    }
    fn sysctl_ok(&self) -> bool {
        true
    }
}

// ----- the apt proxy (the same one as privd_real_incus.rs) ----------------------------------------------------

pub async fn start_proxy(bind: IpAddr) -> (u16, tokio::task::JoinHandle<()>) {
    let l = TcpListener::bind(SocketAddr::new(bind, 0)).await.unwrap();
    let port = l.local_addr().unwrap().port();
    let h = tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            tokio::spawn(async move {
                let _ = proxy_conn(s).await;
            });
        }
    });
    (port, h)
}

async fn proxy_conn(mut client: TcpStream) -> std::io::Result<()> {
    let mut head = Vec::new();
    let mut buf = [0u8; 2048];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = client.read(&mut buf).await?;
        if n == 0 || head.len() > 16 * 1024 {
            return Ok(());
        }
        head.extend_from_slice(&buf[..n]);
    }
    let end = head.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let text = String::from_utf8_lossy(&head[..end]).to_string();
    let mut lines = text.split("\r\n");
    let first = lines.next().unwrap_or_default().to_string();
    let parts: Vec<&str> = first.split(' ').collect();
    let refuse = async |mut c: TcpStream| {
        let _ = c
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await;
        Ok::<(), std::io::Error>(())
    };
    if parts.len() < 3 {
        return refuse(client).await;
    }
    let (host, port, request): (String, u16, Option<Vec<u8>>) = if parts[0] == "CONNECT" {
        let Some((h, p)) = parts[1].rsplit_once(':') else {
            return refuse(client).await;
        };
        (h.to_string(), p.parse().unwrap_or(0), None)
    } else {
        let Some(rest) = parts[1].strip_prefix("http://") else {
            return refuse(client).await;
        };
        let (authority, path) = rest
            .split_once('/')
            .map_or((rest, "/".to_string()), |(a, p)| (a, format!("/{p}")));
        let (h, p) = authority
            .rsplit_once(':')
            .map_or((authority, 80u16), |(h, p)| (h, p.parse().unwrap_or(0)));
        let mut req = format!("{} {} HTTP/1.1\r\n", parts[0], path).into_bytes();
        for l in lines.filter(|l| !l.is_empty()) {
            let low = l.to_ascii_lowercase();
            if low.starts_with("proxy-") || low.starts_with("connection:") {
                continue;
            }
            req.extend_from_slice(l.as_bytes());
            req.extend_from_slice(b"\r\n");
        }
        req.extend_from_slice(b"Connection: close\r\n\r\n");
        (h.to_string(), p, Some(req))
    };
    if port != 80 && port != 443 {
        return refuse(client).await;
    }
    let mut up = TcpStream::connect((host.as_str(), port)).await?;
    match request {
        None => {
            client
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await?;
            client.write_all(&head[end..]).await?;
        }
        Some(req) => up.write_all(&req).await?,
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut up).await;
    Ok(())
}

// ----- the incus command line --------------------------------------------------------------------------------

/// Output of a finished command.
pub struct Out {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

async fn run_cmd(mut c: std::process::Command) -> Out {
    tokio::task::spawn_blocking(move || {
        let o = c.stdin(Stdio::null()).output().expect("spawn");
        Out {
            code: o.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        }
    })
    .await
    .expect("command task")
}

pub async fn incus(args: &[&str]) -> Out {
    let mut c = std::process::Command::new("incus");
    c.args(args);
    run_cmd(c).await
}

/// `bash -c script` in the container as root.
pub async fn exec_root(script: &str) -> Out {
    incus(&["exec", INSTANCE, "--", "bash", "-c", script]).await
}

/// `bash -c script` in the container as the desktop user, with the display of the desktop.
pub async fn exec_user(script: &str) -> Out {
    incus(&[
        "exec",
        INSTANCE,
        "--user",
        &UID.to_string(),
        "--group",
        &UID.to_string(),
        "--cwd",
        &format!("/home/{USER}"),
        "--env",
        "DISPLAY=:0",
        "--env",
        "XAUTHORITY=/run/hx-xorg/Xauthority",
        "--env",
        &format!("XDG_RUNTIME_DIR=/run/user/{UID}"),
        "--env",
        &format!("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{UID}/bus"),
        "--",
        "bash",
        "-c",
        script,
    ])
    .await
}

/// Runs `bash -c script` as the desktop user in a transient system unit named `unit` (the
/// output goes to `/tmp/<unit>.log`), so that no `incus exec` session waits for it. Stop it with
/// [`bg_stop`].
pub async fn bg_user(unit: &str, script: &str) {
    let o = incus(&[
        "exec",
        INSTANCE,
        "--",
        "systemd-run",
        "--collect",
        "--quiet",
        &format!("--unit={unit}"),
        &format!("--uid={UID}"),
        "--setenv=DISPLAY=:0",
        "--setenv=XAUTHORITY=/run/hx-xorg/Xauthority",
        &format!("--setenv=XDG_RUNTIME_DIR=/run/user/{UID}"),
        &format!("--setenv=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{UID}/bus"),
        &format!("--working-directory=/home/{USER}"),
        "-p",
        &format!("StandardOutput=truncate:/tmp/{unit}.log"),
        "-p",
        &format!("StandardError=append:/tmp/{unit}.log"),
        "--",
        "bash",
        "-c",
        script,
    ])
    .await;
    assert_eq!(o.code, 0, "systemd-run {unit}: {} {}", o.stdout, o.stderr);
}

/// Stops a unit started with [`bg_user`] (it is fine if it has ended).
pub async fn bg_stop(unit: &str) {
    let _ = exec_root(&format!("systemctl stop {unit} 2>/dev/null; true")).await;
}

pub async fn root_ok(script: &str) -> String {
    let o = exec_root(script).await;
    assert_eq!(o.code, 0, "`{script}` failed: {} {}", o.stdout, o.stderr);
    o.stdout
}

pub async fn user_ok(script: &str) -> String {
    let o = exec_user(script).await;
    assert_eq!(o.code, 0, "`{script}` failed: {} {}", o.stdout, o.stderr);
    o.stdout
}

/// Polls `f` every 250 ms until it returns `Some`, for at most `secs`.
pub async fn poll<T, F: std::future::Future<Output = Option<T>>>(
    secs: u64,
    mut f: impl FnMut() -> F,
) -> Option<T> {
    let end = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(v) = f().await {
            return Some(v);
        }
        if tokio::time::Instant::now() >= end {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

// ----- the blocking privd client, driven from async code -------------------------------------------------------

pub struct Gw(pub Option<RawClient>);

impl Gw {
    pub async fn with<T: Send + 'static>(
        &mut self,
        f: impl FnOnce(&mut RawClient) -> T + Send + 'static,
    ) -> T {
        let mut c = self.0.take().expect("client");
        let (c, r) = tokio::task::spawn_blocking(move || {
            let r = f(&mut c);
            (c, r)
        })
        .await
        .expect("blocking client task");
        self.0 = Some(c);
        r
    }

    pub async fn call(
        &mut self,
        command: pb::request::Command,
        secrets: &[(pb::SecretKind, &[u8])],
    ) -> pb::Response {
        let owned: Vec<(pb::SecretKind, Vec<u8>)> =
            secrets.iter().map(|(k, v)| (*k, v.to_vec())).collect();
        self.with(move |c| {
            let s: Vec<(pb::SecretKind, &[u8])> =
                owned.iter().map(|(k, v)| (*k, v.as_slice())).collect();
            c.call(command, &s)
        })
        .await
    }
}

pub fn expect_ok(r: pb::Response) -> pb::response::Result {
    match r.result {
        Some(pb::response::Result::Error(e)) => panic!(
            "{:?} {:?} (stage {:?}): {}",
            e.code(),
            e.detail(),
            e.stage,
            e.message
        ),
        Some(v) => v,
        None => panic!("empty response"),
    }
}

// ----- the real hx-gatewayd process ---------------------------------------------------------------------------

pub struct Gatewayd {
    pub child: Child,
    pub quic: SocketAddr,
    pub websocket: SocketAddr,
    pub admin: PathBuf,
    pub log: PathBuf,
}

impl Gatewayd {
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// SIGTERM, then waits for the graceful exit.
    pub fn terminate(&mut self) -> Option<std::process::ExitStatus> {
        let _ = rustix::process::kill_process(
            rustix::process::Pid::from_raw(self.child.id() as i32).unwrap(),
            rustix::process::Signal::TERM,
        );
        for _ in 0..100 {
            if let Ok(Some(s)) = self.child.try_wait() {
                return Some(s);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
        self.child.wait().ok()
    }
}

impl Drop for Gatewayd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub struct GatewaydSpec<'a> {
    pub dir: &'a Path,
    pub privd_socket: &'a Path,
    pub link_socket: &'a Path,
    /// The identity seed (32 bytes): the "systemd credential".
    pub identity_seed: &'a [u8],
    pub seccomp: &'a str,
}

/// Starts the real binary and waits for its "listening" line.
pub async fn start_gatewayd(s: GatewaydSpec<'_>) -> Gatewayd {
    use std::os::unix::fs::PermissionsExt;
    let state = s.dir.join("gw-state");
    let identity = s.dir.join("gw-identity");
    // A kept directory (HX_E2E_REUSE) holds the previous run's registry and read-only key.
    let _ = std::fs::remove_dir_all(&state);
    let _ = std::fs::remove_file(&identity);
    std::fs::create_dir_all(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(&identity, s.identity_seed).unwrap();
    std::fs::set_permissions(&identity, std::fs::Permissions::from_mode(0o400)).unwrap();
    let admin = s.dir.join("gw-admin.sock");
    let config = s.dir.join("gatewayd.toml");
    std::fs::write(
        &config,
        format!(
            "listen = \"127.0.0.1:0\"\n\
             server_name = \"hx3e\"\n\
             state_dir = \"{}\"\n\
             privd_socket = \"{}\"\n\
             admin_socket = \"{}\"\n\
             identity_credential = \"{}\"\n\
             seccomp = \"{}\"\n\
             argon2_min_memory_kib = 1024\n\
             mlock = false\n",
            state.display(),
            s.privd_socket.display(),
            admin.display(),
            identity.display(),
            s.seccomp
        ),
    )
    .unwrap();
    let log = s.dir.join("gatewayd.log");
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_hx-gatewayd"));
    cmd.arg("--config")
        .arg(&config)
        .arg("--admin-allow-uid")
        .arg(rustix::process::getuid().as_raw().to_string())
        .arg("--link-socket")
        .arg(s.link_socket)
        .stdout(Stdio::piped())
        .stderr(std::fs::File::create(&log).unwrap())
        .env_remove("CREDENTIALS_DIRECTORY")
        .env_remove("LISTEN_FDS")
        .env_remove("NOTIFY_SOCKET")
        .env("HX_LOG", "info");
    let mut child = cmd.spawn().expect("spawn hx-gatewayd");
    let stdout = child.stdout.take().unwrap();
    let line = tokio::task::spawn_blocking(move || {
        use std::io::BufRead;
        let mut line = String::new();
        std::io::BufReader::new(stdout)
            .read_line(&mut line)
            .map(|_| line)
    });
    let line = match tokio::time::timeout(Duration::from_secs(30), line).await {
        Ok(Ok(Ok(l))) if !l.is_empty() => l,
        other => {
            let _ = child.kill();
            panic!(
                "the gateway did not start ({other:?}); log:\n{}",
                std::fs::read_to_string(&log).unwrap_or_default()
            );
        }
    };
    let addr = |key: &str| -> SocketAddr {
        line.split_whitespace()
            .find_map(|w| w.strip_prefix(key))
            .unwrap()
            .parse()
            .unwrap()
    };
    // The reader above owned the pipe; the child may now get SIGPIPE on a later println, but
    // the gateway prints that one line only.
    Gatewayd {
        quic: addr("quic="),
        websocket: addr("websocket="),
        child,
        admin,
        log,
    }
}

// ----- measurements ------------------------------------------------------------------------------------------

/// utime + stime (clock ticks, 100 a second) of a process.
pub fn proc_ticks(pid: u32) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name is in parentheses and may contain spaces: fields count from after it.
    let rest = &s[s.rfind(')')? + 2..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    Some(f.get(11)?.parse::<u64>().ok()? + f.get(12)?.parse::<u64>().ok()?)
}

/// CPU microseconds used by the whole container (its cgroup), and by `hx-session.service`.
pub async fn container_cpu_usec() -> (u64, u64) {
    let out = root_ok(
        "u=$(awk '/^usage_usec/{print $2}' /sys/fs/cgroup/cpu.stat); \
         s=$(awk '/^usage_usec/{print $2}' /sys/fs/cgroup/system.slice/hx-session.service/cpu.stat 2>/dev/null); \
         echo \"$u ${s:-0}\"",
    )
    .await;
    let mut it = out
        .split_whitespace()
        .map(|v| v.parse::<u64>().unwrap_or(0));
    (it.next().unwrap_or(0), it.next().unwrap_or(0))
}

// ----- an FFmpeg H.264 decoder: proof that a frame is a picture -------------------------------------------------

pub struct Decoded {
    pub width: u32,
    pub height: u32,
    pub luma: Vec<u8>,
}

/// Luma statistics of a picture: a uniform picture has a standard deviation of 0.
pub struct PictureStats {
    pub mean: f64,
    pub stddev: f64,
    pub distinct_luma: usize,
}

impl Decoded {
    /// Computed on demand: a 1080p picture is two million samples, too slow to do for every
    /// frame of a debug build.
    pub fn stats(&self) -> PictureStats {
        let n = self.luma.len() as f64;
        let mean = self.luma.iter().map(|&v| f64::from(v)).sum::<f64>() / n;
        let var = self
            .luma
            .iter()
            .map(|&v| (f64::from(v) - mean).powi(2))
            .sum::<f64>()
            / n;
        let mut seen = [false; 256];
        for &v in &self.luma {
            seen[v as usize] = true;
        }
        PictureStats {
            mean,
            stddev: var.sqrt(),
            distinct_luma: seen.iter().filter(|b| **b).count(),
        }
    }
}

pub struct Decoder {
    dec: ffmpeg_next::decoder::Video,
}

impl Decoder {
    pub fn new() -> Self {
        ffmpeg_next::init().expect("ffmpeg init");
        let codec = ffmpeg_next::decoder::find(ffmpeg_next::codec::Id::H264).expect("h264");
        let dec = ffmpeg_next::codec::context::Context::new_with_codec(codec)
            .decoder()
            .video()
            .expect("decoder");
        Self { dec }
    }

    /// Feeds one access unit; the picture, if the decoder produced one.
    pub fn decode(&mut self, data: &[u8]) -> Option<Decoded> {
        let pkt = ffmpeg_next::Packet::copy(data);
        self.dec.send_packet(&pkt).ok()?;
        let mut f = ffmpeg_next::frame::Video::empty();
        self.dec.receive_frame(&mut f).ok()?;
        let (w, h) = (f.width() as usize, f.height() as usize);
        let (y, stride) = (f.data(0), f.stride(0));
        let mut luma = Vec::with_capacity(w * h);
        for row in 0..h {
            luma.extend_from_slice(&y[row * stride..row * stride + w]);
        }
        Some(Decoded {
            width: w as u32,
            height: h as u32,
            luma,
        })
    }
}

/// Writes the luma plane as a PGM and, if the `ffmpeg` program is there, a PNG next to it.
pub fn save_picture(d: &Decoded, dir: &Path, name: &str) -> Option<PathBuf> {
    let pgm = dir.join(format!("{name}.pgm"));
    let mut bytes = format!("P5\n{} {}\n255\n", d.width, d.height).into_bytes();
    bytes.extend_from_slice(&d.luma);
    std::fs::write(&pgm, bytes).ok()?;
    let png = dir.join(format!("{name}.png"));
    let ok = std::process::Command::new("ffmpeg")
        .args(["-v", "error", "-y", "-i"])
        .arg(&pgm)
        .arg(&png)
        .status()
        .is_ok_and(|s| s.success());
    Some(if ok { png } else { pgm })
}

/// A throwaway secret: `n` random bytes as hex.
pub fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    rustix::rand::getrandom(&mut b, rustix::rand::GetRandomFlags::empty()).unwrap();
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A throwaway six-digit PIN that the PIN policy accepts.
pub fn random_pin() -> String {
    loop {
        let mut b = [0u8; 4];
        rustix::rand::getrandom(&mut b, rustix::rand::GetRandomFlags::empty()).unwrap();
        let pin = format!("{:06}", u32::from_le_bytes(b) % 1_000_000);
        if hx_crypto::Pin::new(&pin).is_ok() {
            return pin;
        }
    }
}

pub async fn lines_of(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .map(|t| t.lines().map(str::to_string).collect())
        .unwrap_or_default()
}
