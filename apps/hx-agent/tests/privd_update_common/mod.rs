//! Shared support of the `privd_update*` tests: a test signing key generated at run time (it
//! exists only in these tests, never in the library, and is injected through the `test-support`
//! feature), a raw tar writer that can produce archives no honest tool would, a fake release
//! server standing behind the fetcher seam, and a fake systemd and health probe.
//!
//! Nothing here runs a real unit or a real daemon, and nothing needs root.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{Cursor, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use hx_agent::fetcher::{ARTIFACT_FILE, Job, MANIFEST_FILE, MANIFEST_SIG_FILE};
use hx_agent::privd::daemon::{Ctx, Daemon, Deps};
use hx_agent::privd::testing::{FakeIncus, FakeProbe as HostProbe, Harness, request};
use hx_agent::privd::update::manifest::{Manifest, artifact_name};
use hx_agent::privd::update::switch::{Layout, REQUIRED_BINARIES, VERSION_FILE};
use hx_agent::privd::update::system::{BoxFut, HealthProbe, Systemd, Unit, UnitState};
use hx_agent::privd::update::verify::sha256_hex;
use hx_agent::privd::update::{UpdateDeps, UpdateKeys};
use hx_ipc::privd::pb::{self, Role, request::Command, response::Result as R};

// ----- signing ------------------------------------------------------------------------------

/// A minisign key pair made for one test.
pub struct Signer {
    kp: minisign::KeyPair,
}

impl Signer {
    /// A fresh key pair.
    pub fn new() -> Self {
        Self {
            kp: minisign::KeyPair::generate_unencrypted_keypair().expect("keypair"),
        }
    }

    /// The public key as the embedded key files hold it (the base64 line).
    pub fn public(&self) -> String {
        self.kp.pk.to_base64()
    }

    /// A prehashed minisign signature file over `data`.
    pub fn sign(&self, data: &[u8]) -> String {
        minisign::sign(
            Some(&self.kp.pk),
            &self.kp.sk,
            Cursor::new(data),
            Some("hx test release"),
            None,
        )
        .expect("sign")
        .into_string()
    }
}

// ----- a raw tar writer ---------------------------------------------------------------------

/// One archive entry, written as given (no sanitising).
#[derive(Clone)]
pub struct TarEntry {
    pub path: Vec<u8>,
    pub kind: u8,
    pub data: Vec<u8>,
    pub link: Vec<u8>,
    pub mode: u32,
    /// A pax `path` record (so that a name can hold a NUL or exceed 100 bytes).
    pub pax_path: Option<Vec<u8>>,
}

impl TarEntry {
    fn new(path: &str, kind: u8, mode: u32) -> Self {
        Self {
            path: path.as_bytes().to_vec(),
            kind,
            data: Vec::new(),
            link: Vec::new(),
            mode,
            pax_path: None,
        }
    }
    pub fn file(path: &str, data: &[u8], mode: u32) -> Self {
        let mut e = Self::new(path, b'0', mode);
        e.data = data.to_vec();
        e
    }
    pub fn dir(path: &str) -> Self {
        Self::new(path, b'5', 0o755)
    }
    pub fn symlink(path: &str, target: &str) -> Self {
        let mut e = Self::new(path, b'2', 0o777);
        e.link = target.as_bytes().to_vec();
        e
    }
    pub fn hardlink(path: &str, target: &str) -> Self {
        let mut e = Self::new(path, b'1', 0o644);
        e.link = target.as_bytes().to_vec();
        e
    }
    /// A special entry: `b'3'` char device, `b'4'` block device, `b'6'` fifo, `b's'` socket.
    pub fn special(path: &str, kind: u8) -> Self {
        Self::new(path, kind, 0o666)
    }
    pub fn with_pax_path(mut self, p: &[u8]) -> Self {
        self.pax_path = Some(p.to_vec());
        self
    }
}

fn octal(buf: &mut [u8], v: u64) {
    let s = format!("{:0width$o}\0", v, width = buf.len() - 1);
    buf.copy_from_slice(s.as_bytes());
}

fn header(path: &[u8], kind: u8, mode: u32, size: u64, link: &[u8]) -> [u8; 512] {
    let mut h = [0u8; 512];
    let n = path.len().min(100);
    h[..n].copy_from_slice(&path[..n]);
    octal(&mut h[100..108], u64::from(mode));
    octal(&mut h[108..116], 0);
    octal(&mut h[116..124], 0);
    octal(&mut h[124..136], size);
    octal(&mut h[136..148], 0);
    h[148..156].fill(b' ');
    h[156] = kind;
    let l = link.len().min(100);
    h[157..157 + l].copy_from_slice(&link[..l]);
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    let sum: u64 = h.iter().map(|b| u64::from(*b)).sum();
    let s = format!("{sum:06o}\0 ");
    h[148..156].copy_from_slice(s.as_bytes());
    h
}

fn pad(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
}

/// The bytes of a tar archive holding `entries`, in order.
pub fn tar_bytes(entries: &[TarEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    for e in entries {
        if let Some(p) = &e.pax_path {
            // "<len> path=<value>\n" where len counts the whole record including itself.
            let body_len = " path=".len() + p.len() + 1;
            let mut len = body_len + 1;
            while len.to_string().len() + body_len != len {
                len = len.to_string().len() + body_len;
            }
            let mut rec = format!("{len} path=").into_bytes();
            rec.extend_from_slice(p);
            rec.push(b'\n');
            out.extend_from_slice(&header(b"PaxHeader", b'x', 0o644, rec.len() as u64, b""));
            out.extend_from_slice(&rec);
            pad(&mut out);
        }
        let size = if e.kind == b'0' {
            e.data.len() as u64
        } else {
            0
        };
        out.extend_from_slice(&header(&e.path, e.kind, e.mode, size, &e.link));
        if e.kind == b'0' {
            out.extend_from_slice(&e.data);
            pad(&mut out);
        }
    }
    out.extend_from_slice(&[0u8; 1024]);
    out
}

/// gzip.
pub fn gz(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// `tar.gz` of `entries`.
pub fn archive(entries: &[TarEntry]) -> Vec<u8> {
    gz(&tar_bytes(entries))
}

/// The entries of a complete, honest release of `version`.
pub fn good_files(version: &str) -> Vec<TarEntry> {
    let mut v = vec![TarEntry::dir("./")];
    for b in REQUIRED_BINARIES {
        v.push(TarEntry::file(b, b"#!/bin/true\n", 0o755));
    }
    v.push(TarEntry::file("hx-backup-worker", b"#!/bin/true\n", 0o755));
    v.push(TarEntry::file(
        VERSION_FILE,
        format!("{version}\n").as_bytes(),
        0o644,
    ));
    v.push(TarEntry::dir("session"));
    v.push(TarEntry::dir("session/ubuntu-24.04"));
    v.push(TarEntry::file(
        "session/ubuntu-24.04/hx-session.deb",
        b"!<arch>\ndeb",
        0o644,
    ));
    v
}

// ----- a complete release directory ---------------------------------------------------------

/// Installs a complete release directory `version` under `dir` (as a finished update would).
pub fn install_release(dir: &Path, version: &str) {
    let v = dir.join(version);
    std::fs::create_dir_all(&v).unwrap();
    for b in REQUIRED_BINARIES {
        std::fs::write(v.join(b), b"#!/bin/true\n").unwrap();
        std::fs::set_permissions(v.join(b), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::fs::write(v.join(VERSION_FILE), format!("{version}\n")).unwrap();
}

// ----- the fake release server and systemd ---------------------------------------------------

/// A hook that may replace the default behaviour of one fetch (plant hostile files).
pub type FetchHook = Box<dyn Fn(&Job, &Path) -> Option<Result<(), String>> + Send>;

/// What the "release host" serves.
#[derive(Default)]
pub struct Server {
    pub manifest: Option<(Vec<u8>, String)>,
    pub artifacts: HashMap<String, Vec<u8>>,
    pub hook: Option<FetchHook>,
    pub fail: bool,
    pub jobs: Vec<String>,
}

fn write_new(path: &Path, bytes: &[u8]) {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)
        .expect("the fetch directory must be clean before a fetch");
    f.write_all(bytes).unwrap();
}

/// A fake systemd: the fetcher unit writes what `server` serves into `fetch_dir`; restarts are
/// recorded; the gatewayd state is scripted.
pub struct FakeSystemd {
    pub fetch_dir: PathBuf,
    pub server: Arc<Mutex<Server>>,
    pub restarts: Mutex<Vec<Unit>>,
    pub gateway_active: AtomicBool,
    pub gateway_pid: AtomicU32,
    /// Each state query bumps the pid (a crash loop).
    pub gateway_flapping: AtomicBool,
    pub fail_privd_restart: AtomicBool,
}

impl FakeSystemd {
    pub fn restarted(&self) -> Vec<Unit> {
        self.restarts.lock().unwrap().clone()
    }
}

impl Systemd for FakeSystemd {
    fn fetch<'a>(&'a self, job: &'a Job) -> BoxFut<'a, Result<(), String>> {
        Box::pin(async move {
            let mut s = self.server.lock().unwrap();
            s.jobs.push(job.instance());
            if s.fail {
                return Err("the update fetcher failed".into());
            }
            if let Some(h) = &s.hook
                && let Some(r) = h(job, &self.fetch_dir)
            {
                return r;
            }
            match job {
                Job::Manifest(_) => {
                    let (m, sig) = s.manifest.clone().ok_or("no release published")?;
                    write_new(&self.fetch_dir.join(MANIFEST_FILE), &m);
                    write_new(&self.fetch_dir.join(MANIFEST_SIG_FILE), sig.as_bytes());
                }
                Job::Artifact(v) => {
                    let a = s.artifacts.get(v).cloned().ok_or("no such artifact")?;
                    write_new(&self.fetch_dir.join(ARTIFACT_FILE), &a);
                }
            }
            Ok(())
        })
    }

    fn restart<'a>(&'a self, unit: Unit) -> BoxFut<'a, Result<(), String>> {
        Box::pin(async move {
            self.restarts.lock().unwrap().push(unit);
            if unit == Unit::Privd && self.fail_privd_restart.load(Ordering::SeqCst) {
                return Err("systemctl restart hx-privd.service failed".into());
            }
            Ok(())
        })
    }

    fn state<'a>(&'a self, _unit: Unit) -> BoxFut<'a, Result<UnitState, String>> {
        Box::pin(async move {
            let pid = if self.gateway_flapping.load(Ordering::SeqCst) {
                self.gateway_pid.fetch_add(1, Ordering::SeqCst) + 1
            } else {
                self.gateway_pid.load(Ordering::SeqCst)
            };
            Ok(UnitState {
                active: self.gateway_active.load(Ordering::SeqCst),
                main_pid: pid,
            })
        })
    }
}

/// A fake health probe.
pub struct FakeHealth {
    pub privd_ok: AtomicBool,
    pub status_ok: AtomicBool,
    pub status_calls: AtomicU32,
}

impl HealthProbe for FakeHealth {
    fn privd_answers(&self) -> BoxFut<'_, bool> {
        Box::pin(async move { self.privd_ok.load(Ordering::SeqCst) })
    }
    fn gatewayd_status(&self) -> BoxFut<'_, bool> {
        Box::pin(async move {
            self.status_calls.fetch_add(1, Ordering::SeqCst);
            self.status_ok.load(Ordering::SeqCst)
        })
    }
}

// ----- the environment ----------------------------------------------------------------------

/// A published release: what the server serves and what the tests compare against.
pub struct Published {
    pub version: String,
    pub artifact: Vec<u8>,
    pub manifest: Vec<u8>,
    pub sig: String,
}

/// The daemon on fakes, with a test key, a fake release server and a `1.0.0` installation.
pub struct Env {
    pub h: Harness,
    pub signer: Signer,
    pub server: Arc<Mutex<Server>>,
    pub systemd: Arc<FakeSystemd>,
    pub health: Arc<FakeHealth>,
}

pub const NOW: u64 = 1_800_000_000;

impl Env {
    /// Must be called inside a tokio runtime (the harness spawns the server).
    pub fn new() -> Self {
        let h = Harness::start(rustix::process::getuid().as_raw());
        let u = &h.daemon.cfg.update;
        std::fs::create_dir_all(&u.versions_dir).unwrap();
        std::fs::set_permissions(&u.versions_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        install_release(&u.versions_dir, "1.0.0");
        Layout::new(&u.versions_dir).switch_to("1.0.0").unwrap();
        let signer = Signer::new();
        let server = Arc::new(Mutex::new(Server::default()));
        let systemd = Arc::new(FakeSystemd {
            fetch_dir: u.fetch_dir.clone(),
            server: server.clone(),
            restarts: Mutex::new(Vec::new()),
            gateway_active: AtomicBool::new(true),
            gateway_pid: AtomicU32::new(4242),
            gateway_flapping: AtomicBool::new(false),
            fail_privd_restart: AtomicBool::new(false),
        });
        let health = Arc::new(FakeHealth {
            privd_ok: AtomicBool::new(true),
            status_ok: AtomicBool::new(true),
            status_calls: AtomicU32::new(0),
        });
        let env = Self {
            h,
            signer,
            server,
            systemd,
            health,
        };
        env.h
            .daemon
            .set_update_deps(env.deps(&[&env.signer.public()]));
        env
    }

    /// Update collaborators with `keys` embedded.
    pub fn deps(&self, keys: &[&str]) -> UpdateDeps {
        UpdateDeps {
            keys: UpdateKeys::from_public_keys(keys).expect("keys"),
            systemd: self.systemd.clone(),
            probe: self.health.clone(),
        }
    }

    pub fn layout(&self) -> Layout {
        Layout::new(&self.h.daemon.cfg.update.versions_dir)
    }

    pub fn arch(&self) -> String {
        self.h.daemon.cfg.update.arch.clone()
    }

    /// Builds, signs and "publishes" `version` on the stable channel.
    pub fn publish(&self, version: &str, timestamp: u64) -> Published {
        self.publish_with(version, timestamp, &good_files(version), None)
    }

    /// Like [`Env::publish`] with chosen archive entries and `min_previous`.
    pub fn publish_with(
        &self,
        version: &str,
        timestamp: u64,
        files: &[TarEntry],
        min_previous: Option<&str>,
    ) -> Published {
        let artifact = archive(files);
        let p = self.sign_release(version, timestamp, artifact, min_previous, &self.signer);
        self.serve(&p);
        p
    }

    /// Builds and signs (with `signer`) without serving.
    pub fn sign_release(
        &self,
        version: &str,
        timestamp: u64,
        artifact: Vec<u8>,
        min_previous: Option<&str>,
        signer: &Signer,
    ) -> Published {
        let m = Manifest {
            schema: 1,
            channel: "stable".into(),
            version: version.into(),
            arch: self.arch(),
            artifact: artifact_name(version, &self.arch()),
            size: artifact.len() as u64,
            sha256: sha256_hex(&artifact),
            timestamp,
            min_previous: min_previous.map(str::to_string),
        };
        let manifest = serde_json::to_vec(&m).unwrap();
        let sig = signer.sign(&manifest);
        Published {
            version: version.into(),
            artifact,
            manifest,
            sig,
        }
    }

    /// Makes the server serve `p`.
    pub fn serve(&self, p: &Published) {
        let mut s = self.server.lock().unwrap();
        s.manifest = Some((p.manifest.clone(), p.sig.clone()));
        s.artifacts.insert(p.version.clone(), p.artifact.clone());
    }

    pub async fn call(&self, role: Role, command: Command) -> pb::Response {
        self.h
            .daemon
            .handle(request(1, command), Ctx::new(role))
            .await
    }

    pub async fn check(&self) -> pb::Response {
        self.call(Role::Admin, Command::CheckUpdate(pb::CheckUpdateRequest {}))
            .await
    }

    pub async fn apply(&self, version: &str) -> pb::Response {
        self.call(
            Role::Admin,
            Command::ApplyUpdate(pb::ApplyUpdateRequest {
                version: version.into(),
            }),
        )
        .await
    }

    /// `ApplyUpdate` with a day's worth of rate-limit allowance restored first (tests that apply
    /// more than twice).
    pub async fn apply_fresh(&self, version: &str) -> pb::Response {
        self.h.clock.advance_secs(86_401);
        self.apply(version).await
    }

    /// A second daemon over the same state, as the process that starts after the re-exec, running
    /// `running` and wired to the same fakes.
    pub fn new_process(&self, running: &str) -> Arc<Daemon<FakeIncus>> {
        let mut cfg = self.h.daemon.cfg.clone();
        cfg.update.running_version = running.into();
        let d = Daemon::new(
            cfg,
            self.h.incus.client(),
            Deps {
                runner: self.h.runner.clone(),
                probe: Arc::new(HostProbe::default()),
                clock: self.h.clock.clone(),
                audit: self.h.audit.clone(),
            },
        )
        .expect("daemon");
        d.set_update_deps(self.deps(&[&self.signer.public()]));
        d
    }

    /// Waits until the scheduled restarts (gatewayd, then privd) have been requested.
    pub async fn wait_restarts(&self, n: usize) {
        for _ in 0..200 {
            if self.systemd.restarted().len() >= n {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("expected {n} restarts, got {:?}", self.systemd.restarted());
    }
}

// ----- response helpers ---------------------------------------------------------------------

pub fn ok(r: pb::Response) -> R {
    match r.result {
        Some(R::Error(e)) => panic!("expected success, got {:?}: {}", e.code(), e.message),
        Some(v) => v,
        None => panic!("empty response"),
    }
}

pub fn err(r: &pb::Response) -> (pb::ErrorCode, String) {
    match &r.result {
        Some(R::Error(e)) => (e.code(), e.message.clone()),
        other => panic!("expected an error, got {other:?}"),
    }
}

pub fn check_result(r: pb::Response) -> pb::CheckUpdateResult {
    match ok(r) {
        R::CheckUpdate(c) => c,
        other => panic!("{other:?}"),
    }
}
