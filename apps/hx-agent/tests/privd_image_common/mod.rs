//! Shared support of the `privd_image*` tests: a test image-signing key made at run time (it exists
//! only in these tests and is injected through `Daemon::set_image_deps`), fake images and signed
//! manifests, a fake systemd whose "image fetcher" is a thread that writes into the fetch directory
//! the way the real one does (or hostilely), a loopback HTTPS server for the real fetcher, and the
//! helpers to call `CreateDesktop`.
//!
//! Nothing here needs root, a real Incus or the network.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hx_agent::fetcher::images::{END_FILE, chunk_name, marker_name};
use hx_agent::fetcher::{Config as FetchConfig, ImageJob, ImageLimits, Url, run_image};
use hx_agent::privd::daemon::Ctx;
use hx_agent::privd::image::{ImageDeps, ImageKeys};
use hx_agent::privd::testing::{FakeIncus, FakeProbe, FakeRunner, Harness, request};
use hx_agent::privd::update::system::{BoxFut, JobState, Systemd, Unit, UnitState};
use hx_agent::privd::update::verify::sha256_hex;
use hx_ipc::privd::pb::{self, Role, request::Command, response::Result as R};
use hx_ipc::secret::Secret;
use hx_provision::images::{
    FORMAT_UNIFIED, ImageEntry, ImagesManifest, KIND, Part, SCHEMA, file_name, manifest_file_name,
    recipe_name,
};
use hx_provision::{Catalog, RecipeId};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};

pub const GW: u32 = 4_242;
/// The harness clock.
pub const NOW: u64 = 1_800_000_000;
pub const PASSWORD: &[u8] = b"Correct-Horse-Battery-9";
pub const GIB: u64 = 1 << 30;
/// Chunk size of the fake and real fetchers in these tests (the daemon's `ImageConfig::for_tests`).
pub const CHUNK: u64 = 64 * 1024;

pub fn rid() -> RecipeId {
    hx_provision::images::recipe_by_name("ubuntu-24.04-xfce-basic").unwrap()
}

/// The digest of the recipe embedded in this agent, as privd computes it.
pub fn digest_of(id: RecipeId) -> String {
    Catalog::embedded().resolve(id, &[]).unwrap().build_digest()
}

pub fn arch() -> String {
    std::env::consts::ARCH.to_string()
}

// ----- signing ------------------------------------------------------------------------------

pub struct Signer {
    kp: minisign::KeyPair,
}

impl Signer {
    pub fn new() -> Self {
        Self {
            kp: minisign::KeyPair::generate_unencrypted_keypair().expect("keypair"),
        }
    }

    pub fn public(&self) -> String {
        self.kp.pk.to_base64()
    }

    /// A prehashed signature whose trusted comment is the one image CI writes.
    pub fn sign_manifest(&self, data: &[u8], timestamp: u64) -> String {
        self.sign_with_comment(
            data,
            &format!(
                "hx-images-manifest schema=1 arch={} timestamp={timestamp}",
                arch()
            ),
        )
    }

    pub fn sign_with_comment(&self, data: &[u8], comment: &str) -> String {
        minisign::sign(
            Some(&self.kp.pk),
            &self.kp.sk,
            Cursor::new(data),
            Some(comment),
            None,
        )
        .expect("sign")
        .into_string()
    }
}

// ----- images and manifests -----------------------------------------------------------------

/// Deterministic bytes that do not compress or repeat.
pub fn image_bytes(n: usize, seed: u8) -> Vec<u8> {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15 ^ u64::from(seed);
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// A manifest entry for `data` as a prebuilt image of `id` with this agent's embedded recipe
/// digest, `created` seconds Unix, split into `parts` byte ranges.
pub fn entry_for(
    id: RecipeId,
    data: &[u8],
    build_id: &str,
    created: u64,
    parts: usize,
) -> ImageEntry {
    let per = data.len().div_ceil(parts);
    let parts: Vec<Part> = data
        .chunks(per.max(1))
        .map(|c| Part {
            size: c.len() as u64,
            sha256: sha256_hex(c),
        })
        .collect();
    ImageEntry {
        recipe: recipe_name(id),
        distro: id.distro.as_str().into(),
        desktop: id.desktop.to_string(),
        preset: id.preset.to_string(),
        recipe_digest: digest_of(id),
        build_id: build_id.into(),
        created,
        min_agent: "0.9.0".into(),
        format: FORMAT_UNIFIED.into(),
        compression: "zstd".into(),
        base_alias: "ubuntu/24.04".into(),
        file: file_name(id, build_id),
        size: data.len() as u64,
        sha256: sha256_hex(data),
        unpacked_size: 3 * GIB,
        parts,
    }
}

pub fn manifest_json(entries: Vec<ImageEntry>, timestamp: u64) -> Vec<u8> {
    ImagesManifest {
        schema: SCHEMA,
        kind: KIND.into(),
        arch: arch(),
        timestamp,
        images: entries,
    }
    .to_json()
    .unwrap()
    .into_bytes()
}

// ----- the fake fetcher unit ----------------------------------------------------------------

/// What the "fetcher" does for a job instead of the default: it gets the job, the fetch directory
/// and a flag that is set when the unit is stopped, and returns the unit's exit.
pub type Hook = Arc<dyn Fn(&ImageJob, &Path, &AtomicBool) -> Result<(), String> + Send + Sync>;

#[derive(Default)]
pub struct Script {
    /// The manifest and signature the `images-manifest` job writes; `None`: the job fails.
    pub manifest: Option<(Vec<u8>, String)>,
    /// The `probe.json` text; `None`: the job fails.
    pub probe: Option<String>,
    /// The image the `image-…` job writes; `None`: the job fails.
    pub image: Option<Vec<u8>>,
    /// Overrides all of the above.
    pub hook: Option<Hook>,
}

struct Run {
    state: Arc<AtomicU8>,
    stop: Arc<AtomicBool>,
}

const RUNNING: u8 = 0;
const OK: u8 = 1;
const FAILED: u8 = 2;

pub struct FakeFetcher {
    pub fetch_dir: PathBuf,
    pub chunk: u64,
    pub script: Mutex<Script>,
    runs: Mutex<HashMap<String, Run>>,
    pub started: Mutex<Vec<String>>,
    pub stopped: Mutex<Vec<String>>,
}

pub fn write_new(dir: &Path, name: &str, bytes: &[u8]) {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(dir.join(name))
        .unwrap_or_else(|e| panic!("`{name}` must not exist yet: {e}"));
    f.write_all(bytes).unwrap();
    f.sync_all().unwrap();
}

/// Waits (at most `limit`) until `name` is gone from `dir` or `stop` is set.
pub fn wait_gone(dir: &Path, name: &str, stop: &AtomicBool, limit: Duration) -> bool {
    let t = Instant::now();
    while dir.join(name).symlink_metadata().is_ok() {
        if stop.load(Ordering::SeqCst) || t.elapsed() > limit {
            return false;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    true
}

/// The honest chunk protocol for `data`: chunk files of `chunk` bytes, a marker after each,
/// back-pressure on the chunk two behind, `end` at the finish.
pub fn write_chunks(dir: &Path, data: &[u8], chunk: u64, stop: &AtomicBool) -> Result<(), String> {
    let chunk = usize::try_from(chunk).unwrap();
    for (k, piece) in data.chunks(chunk).enumerate() {
        let k = u32::try_from(k).unwrap();
        if k >= 2 && !wait_gone(dir, &chunk_name(k - 2), stop, Duration::from_secs(10)) {
            return Err("the consumer did not take a chunk".into());
        }
        write_new(dir, &chunk_name(k), piece);
        write_new(dir, &marker_name(k), b"");
    }
    write_new(dir, END_FILE, b"");
    Ok(())
}

impl FakeFetcher {
    pub fn started(&self) -> Vec<String> {
        self.started.lock().unwrap().clone()
    }
    pub fn stopped(&self) -> Vec<String> {
        self.stopped.lock().unwrap().clone()
    }

    fn work(&self, job: &ImageJob, stop: &AtomicBool) -> Result<(), String> {
        let (hook, manifest, probe, image) = {
            let s = self.script.lock().unwrap();
            (
                s.hook.clone(),
                s.manifest.clone(),
                s.probe.clone(),
                s.image.clone(),
            )
        };
        if let Some(h) = hook {
            return h(job, &self.fetch_dir, stop);
        }
        match job {
            ImageJob::Manifest => {
                let (m, sig) = manifest.ok_or("no manifest published")?;
                write_new(&self.fetch_dir, "images.json", &m);
                write_new(&self.fetch_dir, "images.json.minisig", sig.as_bytes());
                Ok(())
            }
            ImageJob::Probe { .. } => {
                let p = probe.ok_or("the probe failed")?;
                write_new(&self.fetch_dir, "probe.json", p.as_bytes());
                Ok(())
            }
            ImageJob::Image { .. } => {
                let data = image.ok_or("no such image")?;
                write_chunks(&self.fetch_dir, &data, self.chunk, stop)
            }
        }
    }
}

/// A fake systemd: the image units run [`FakeFetcher`] on a thread; the update-path methods are
/// never used here.
pub struct FakeImageSystemd {
    pub fetcher: Arc<FakeFetcher>,
}

impl FakeImageSystemd {
    pub fn new(fetch_dir: &Path, chunk: u64) -> Arc<Self> {
        Arc::new(Self {
            fetcher: Arc::new(FakeFetcher {
                fetch_dir: fetch_dir.to_path_buf(),
                chunk,
                script: Mutex::new(Script::default()),
                runs: Mutex::new(HashMap::new()),
                started: Mutex::new(Vec::new()),
                stopped: Mutex::new(Vec::new()),
            }),
        })
    }
}

impl Systemd for FakeImageSystemd {
    fn fetch<'a>(&'a self, _job: &'a hx_agent::fetcher::Job) -> BoxFut<'a, Result<(), String>> {
        Box::pin(async { Err("not an update test".into()) })
    }
    fn stop_fetch<'a>(&'a self, _job: &'a hx_agent::fetcher::Job) -> BoxFut<'a, ()> {
        Box::pin(async {})
    }
    fn restart<'a>(&'a self, _unit: Unit) -> BoxFut<'a, Result<(), String>> {
        Box::pin(async { Ok(()) })
    }
    fn state<'a>(&'a self, _unit: Unit) -> BoxFut<'a, Result<UnitState, String>> {
        Box::pin(async {
            Ok(UnitState {
                active: true,
                main_pid: 1,
            })
        })
    }

    fn start_image_job<'a>(&'a self, job: &'a ImageJob) -> BoxFut<'a, Result<(), String>> {
        Box::pin(async move {
            let f = self.fetcher.clone();
            let name = job.instance();
            f.started.lock().unwrap().push(name.clone());
            // A new run replaces (and stops) an earlier one of the same instance.
            if let Some(old) = f.runs.lock().unwrap().remove(&name) {
                old.stop.store(true, Ordering::SeqCst);
            }
            let state = Arc::new(AtomicU8::new(RUNNING));
            let stop = Arc::new(AtomicBool::new(false));
            f.runs.lock().unwrap().insert(
                name,
                Run {
                    state: state.clone(),
                    stop: stop.clone(),
                },
            );
            let job = job.clone();
            std::thread::spawn(move || {
                let r = f.work(&job, &stop);
                let end = if r.is_ok() && !stop.load(Ordering::SeqCst) {
                    OK
                } else {
                    FAILED
                };
                state.store(end, Ordering::SeqCst);
            });
            Ok(())
        })
    }

    fn image_job_state<'a>(&'a self, job: &'a ImageJob) -> BoxFut<'a, Result<JobState, String>> {
        Box::pin(async move {
            let runs = self.fetcher.runs.lock().unwrap();
            let r = runs.get(&job.instance()).ok_or("never started")?;
            Ok(match r.state.load(Ordering::SeqCst) {
                RUNNING => JobState::Running,
                OK => JobState::Succeeded,
                _ => JobState::Failed,
            })
        })
    }

    fn stop_image_job<'a>(&'a self, job: &'a ImageJob) -> BoxFut<'a, ()> {
        Box::pin(async move {
            self.fetcher.stopped.lock().unwrap().push(job.instance());
            let state = self
                .fetcher
                .runs
                .lock()
                .unwrap()
                .get(&job.instance())
                .map(|r| {
                    r.stop.store(true, Ordering::SeqCst);
                    r.state.clone()
                });
            // `systemctl stop` returns when the unit has ended: so does this.
            if let Some(state) = state {
                for _ in 0..1000 {
                    if state.load(Ordering::SeqCst) != RUNNING {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            }
        })
    }
}

// ----- a loopback HTTPS server for the real fetcher ----------------------------------------

#[derive(Clone, Default)]
pub struct Route {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Stall this long after the head, before the body.
    pub stall: Duration,
    /// Send only this many body bytes and close.
    pub cut_at: Option<usize>,
}

pub fn ok_route(body: &[u8]) -> Route {
    Route {
        status: 200,
        body: body.to_vec(),
        ..Route::default()
    }
}

pub struct TestServer {
    pub port: u16,
    pub roots: Arc<RootCertStore>,
    routes: Arc<Mutex<HashMap<String, Route>>>,
    hits: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
}

impl TestServer {
    pub fn start() -> Self {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert: CertificateDer<'static> = ck.cert.der().clone();
        let key = PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = Arc::new(
            ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert.clone()], key.into())
                .unwrap(),
        );
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let routes: Arc<Mutex<HashMap<String, Route>>> = Arc::default();
        let hits: Arc<Mutex<Vec<String>>> = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        {
            let (routes, hits, stop) = (routes.clone(), hits.clone(), stop.clone());
            std::thread::spawn(move || {
                for conn in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(tcp) = conn else { continue };
                    let (cfg, routes, hits) = (cfg.clone(), routes.clone(), hits.clone());
                    std::thread::spawn(move || serve(tcp, cfg, &routes, &hits));
                }
            });
        }
        Self {
            port,
            roots: Arc::new(roots),
            routes,
            hits,
            stop,
        }
    }

    pub fn route(&self, path: &str, r: Route) {
        self.routes.lock().unwrap().insert(path.to_string(), r);
    }

    pub fn hits(&self) -> Vec<String> {
        self.hits.lock().unwrap().clone()
    }

    /// A fetcher configuration aimed at this server, writing into `out`, with the small chunk
    /// size of these tests and a mirror probe of `/mirror/Packages.xz` on the same server.
    pub fn fetch_config(&self, out: &Path) -> FetchConfig {
        FetchConfig {
            hosts: vec!["localhost".into()],
            port: self.port,
            releases_path: "/rel".into(),
            arch: arch(),
            roots: self.roots.clone(),
            out_dir: out.to_path_buf(),
            allow_non_global: true,
            connect_timeout: Duration::from_secs(2),
            manifest_timeout: Duration::from_secs(3),
            artifact_timeout: Duration::from_secs(3),
            max_manifest: 1024 * 1024,
            max_artifact: 4096,
            image: ImageLimits {
                timeout: Duration::from_secs(15),
                manifest_timeout: Duration::from_secs(5),
                probe_overall: Duration::from_secs(5),
                probe_bytes: 8 * 1024,
                probe_body_time: Duration::from_secs(2),
                probe_connect: Duration::from_secs(2),
                chunk_bytes: CHUNK,
                max_total: 4 * GIB,
                max_part: 1900 * 1024 * 1024,
                stall: Duration::from_secs(5),
                mirror_hosts: vec!["localhost".into()],
                mirror_override: Some(Url::https("localhost", self.port, "/mirror/Packages.xz")),
            },
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn serve(
    tcp: TcpStream,
    cfg: Arc<ServerConfig>,
    routes: &Mutex<HashMap<String, Route>>,
    hits: &Mutex<Vec<String>>,
) {
    let Ok(conn) = ServerConnection::new(cfg) else {
        return;
    };
    let mut tls = StreamOwned::new(conn, tcp);
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match tls.read(&mut b) {
            Ok(1) => head.push(b[0]),
            _ => return,
        }
        if head.len() > 8192 {
            return;
        }
    }
    let text = String::from_utf8_lossy(&head).to_string();
    let path = text
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/")
        .to_string();
    hits.lock().unwrap().push(path.clone());
    let route = routes.lock().unwrap().get(&path).cloned();
    let Some(r) = route else {
        let _ = tls
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let _ = tls.flush();
        return;
    };
    let status = if r.status == 0 { 200 } else { r.status };
    let mut out = format!("HTTP/1.1 {status} X\r\n");
    for (k, v) in &r.headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        r.body.len()
    ));
    let _ = tls.write_all(out.as_bytes());
    let _ = tls.flush();
    std::thread::sleep(r.stall);
    let n = r.cut_at.unwrap_or(r.body.len()).min(r.body.len());
    // In pieces, so that a client that stops reading early is not blocked on a huge write.
    for piece in r.body[..n].chunks(16 * 1024) {
        if tls.write_all(piece).is_err() {
            return;
        }
    }
    let _ = tls.flush();
}

// ----- the environment ----------------------------------------------------------------------

/// The daemon on fakes with a test image key and a fake image fetcher.
pub struct Env {
    pub h: Harness,
    pub signer: Signer,
    pub systemd: Arc<FakeImageSystemd>,
    pub probe: FakeProbe,
}

impl Env {
    /// Must be called inside a tokio runtime (the harness spawns the server).
    pub async fn new() -> Self {
        Self::with(FakeProbe::default(), FakeIncus::new()).await
    }

    pub async fn with(probe: FakeProbe, incus: FakeIncus) -> Self {
        let h = Harness::start_with(GW, probe.clone(), incus, FakeRunner::new());
        let cfg = &h.daemon.cfg.image;
        let systemd = FakeImageSystemd::new(&cfg.fetch_dir, cfg.chunk_bytes);
        let signer = Signer::new();
        let env = Self {
            h,
            signer,
            systemd,
            probe,
        };
        env.use_keys(&[&env.signer.public()]);
        env.make_ready().await;
        env
    }

    /// A second daemon over the same state and fakes with a changed configuration (a short
    /// deadline, a short idle limit), wired to the same image collaborators.
    pub fn daemon_with(
        &self,
        change: impl FnOnce(&mut hx_agent::privd::PrivdConfig),
    ) -> Arc<hx_agent::privd::daemon::Daemon<FakeIncus>> {
        let mut cfg = self.h.daemon.cfg.clone();
        change(&mut cfg);
        let d = hx_agent::privd::daemon::Daemon::new(
            cfg,
            self.h.incus.client(),
            hx_agent::privd::daemon::Deps {
                runner: self.h.runner.clone(),
                probe: Arc::new(self.probe.clone()),
                clock: self.h.clock.clone(),
                audit: self.h.audit.clone(),
            },
        )
        .expect("daemon");
        d.set_image_deps(ImageDeps {
            keys: ImageKeys::from_public_keys(&[&self.signer.public()]).expect("keys"),
            systemd: self.systemd.clone(),
        });
        d
    }

    pub fn use_keys(&self, keys: &[&str]) {
        self.h.daemon.set_image_deps(ImageDeps {
            keys: ImageKeys::from_public_keys(keys).expect("keys"),
            systemd: self.systemd.clone(),
        });
    }

    pub fn no_keys(&self) {
        self.h.daemon.set_image_deps(ImageDeps {
            keys: ImageKeys::none(),
            systemd: self.systemd.clone(),
        });
    }

    async fn make_ready(&self) {
        let call = |c: Command| self.h.daemon.handle(request(1, c), Ctx::new(Role::Admin));
        ok(call(Command::BeginSetup(Default::default())).await);
        ok(call(Command::FinishSetup(pb::FinishSetupRequest {
            force: Some(true),
        }))
        .await);
    }

    pub fn script<R>(&self, f: impl FnOnce(&mut Script) -> R) -> R {
        f(&mut self.systemd.fetcher.script.lock().unwrap())
    }

    /// Publishes a manifest of `entries` signed by the test key at `timestamp`.
    pub fn publish(&self, entries: Vec<ImageEntry>, timestamp: u64) {
        let m = manifest_json(entries, timestamp);
        let sig = self.signer.sign_manifest(&m, timestamp);
        self.script(|s| s.manifest = Some((m, sig)));
    }

    /// Publishes one image of `data` (the manifest, the image, a probe of `release` and `mirror`
    /// bytes per second): the common case.
    pub fn publish_image(&self, data: &[u8], age_secs: u64) -> ImageEntry {
        let e = entry_for(rid(), data, "20261120.1", NOW - age_secs, 1);
        self.publish(vec![e.clone()], NOW);
        self.script(|s| {
            s.image = Some(data.to_vec());
            s.probe = Some(probe_json(Some(40 << 20), Some(20 << 20)));
        });
        e
    }

    pub fn request(&self, mode: pb::ImageMode) -> pb::CreateDesktopRequest {
        pb::CreateDesktopRequest {
            desktop_id: "main".into(),
            distro: pb::Distro::Ubuntu2404 as i32,
            desktop: pb::DesktopKind::Xfce as i32,
            preset: pb::Preset::Basic as i32,
            username: "alice".into(),
            image_mode: mode as i32,
            ..Default::default()
        }
    }

    pub async fn create(&self, req: pb::CreateDesktopRequest) -> pb::Response {
        self.create_as(Role::Admin, req).await
    }

    pub async fn create_as(&self, role: Role, req: pb::CreateDesktopRequest) -> pb::Response {
        self.create_on(&self.h.daemon, role, req).await
    }

    pub async fn create_on(
        &self,
        d: &Arc<hx_agent::privd::daemon::Daemon<FakeIncus>>,
        role: Role,
        req: pb::CreateDesktopRequest,
    ) -> pb::Response {
        let mut r = request(1, Command::CreateDesktop(req));
        r.secret_slots = vec![pb::SecretSlot {
            slot: 0,
            kind: pb::SecretKind::UserPassword as i32,
            length: 32,
            ..Default::default()
        }];
        let mut c = Ctx::new(role);
        c.secrets = vec![Some(Secret::new(PASSWORD.to_vec()))];
        d.handle(r, c).await
    }

    /// Lets the 3-an-hour rate limit of `CreateDesktop` start over.
    pub fn next_hour(&self) {
        self.h.clock.advance_secs(3_601);
    }

    pub fn fetch_dir(&self) -> PathBuf {
        self.h.daemon.cfg.image.fetch_dir.clone()
    }

    pub fn import_dir(&self) -> PathBuf {
        self.h.daemon.cfg.image.import_dir.clone()
    }

    pub fn fetch_dir_names(&self) -> Vec<String> {
        match std::fs::read_dir(self.fetch_dir()) {
            Ok(rd) => rd
                .filter_map(Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}

/// A fetcher hook that runs the **real** fetcher (`run_image`) against `cfg` (a loopback HTTPS
/// server and the fetch directory), as the unit would.
pub fn https_hook(cfg: FetchConfig) -> Hook {
    Arc::new(move |job, _dir, _stop| run_image(job, &cfg).map_err(|e| e.to_string()))
}

/// The `probe.json` an honest fetcher writes for speeds in bytes per second: it reads at most
/// 8 MiB, so a fast host shows as 8 MiB in a short time.
pub fn probe_json(release_bps: Option<u64>, mirror_bps: Option<u64>) -> String {
    let pair = |bps: u64| {
        let bytes = bps.min(8 << 20);
        let ms = (bytes * 1000 / bps.max(1)).max(1);
        (bytes, ms)
    };
    let mut f = Vec::new();
    if let Some(r) = release_bps {
        let (b, ms) = pair(r);
        f.push(format!("\"release_bytes\":{b},\"release_ms\":{ms}"));
    }
    if let Some(m) = mirror_bps {
        let (b, ms) = pair(m);
        f.push(format!("\"mirror_bytes\":{b},\"mirror_ms\":{ms}"));
    }
    format!("{{{}}}", f.join(","))
}

// ----- response helpers ---------------------------------------------------------------------

pub fn ok(r: pb::Response) -> R {
    match r.result {
        Some(R::Error(e)) => panic!(
            "expected success, got {:?} {:?}: {}",
            e.code(),
            e.detail(),
            e.message
        ),
        Some(v) => v,
        None => panic!("empty response"),
    }
}

pub fn created(r: pb::Response) -> pb::CreateDesktopResult {
    match ok(r) {
        R::CreateDesktop(c) => c,
        other => panic!("{other:?}"),
    }
}

pub fn err(r: &pb::Response) -> pb::Error {
    match &r.result {
        Some(R::Error(e)) => e.clone(),
        other => panic!("expected an error, got {other:?}"),
    }
}

/// The offline directory as the installer leaves it: root-only, with the image, the manifest and
/// its signature.
pub fn place_offline(dir: &Path, image_name: &str, image: &[u8], manifest: &[u8], sig: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir).unwrap();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(dir.join(image_name), image).unwrap();
    std::fs::write(dir.join(manifest_file_name(&arch())), manifest).unwrap();
    std::fs::write(
        dir.join(format!("{}.minisig", manifest_file_name(&arch()))),
        sig,
    )
    .unwrap();
}
