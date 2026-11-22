//! The image template of the fetcher (docs/ipc.md 6.12, "Prebuilt images (1D)"): the jobs of
//! `hx-image-fetcher@.service`, which download the signed images manifest, probe the download
//! speed and copy a prebuilt desktop image into a small tmpfs, chunk by chunk, for root `hx-privd`
//! to take over.
//!
//! The fetcher is exactly as untrusted here as in the update path: it verifies nothing, and privd
//! treats whatever it leaves as hostile (`privd::image`).
//!
//! # Jobs
//!
//! The unit instance is the whole argument vector. [`ImageJob::parse`] accepts exactly:
//!
//! | Instance | Downloads | Writes into the directory |
//! |---|---|---|
//! | `images-manifest` | `images-manifest-<arch>.json` and `.minisig` from the release `images` (1 MiB each, 45 s) | `images.json`, `images.json.minisig` |
//! | `probe-<recipe>-<build_id>` | the first 8 MiB (or 6 s) of the image file of release `images-<build_id>`, then the same of the distro's mirror probe URL; bodies are discarded | `probe.json` |
//! | `image-<recipe>-<build_id>-<nparts>` | the image file (`nparts` = 1) or its parts `.p0` to `.p<n-1>`, 20 minutes, 4 GiB | `c-%06d` chunks, `r-%06d` markers, `end` |
//!
//! `<recipe>` is matched as a prefix from the closed list of recipes, `<build_id>` is
//! `^[0-9]{8}\.[0-9]{1,2}$` and `<nparts>` is one digit from 1 to 4: nothing else parses.
//!
//! # The chunk protocol
//!
//! The image is cut into chunks of exactly [`CHUNK_BYTES`] (32 MiB; the last one is shorter) over
//! the concatenation of its parts. Chunk `k` is written to `c-%06d`, flushed and fsynced; only then
//! is the empty marker `r-%06d` created, so a reader that sees the marker sees a complete chunk.
//! After the last chunk the file `end` is created. **Back-pressure:** before the fetcher writes
//! chunk `k+2` it polls `stat(c-k)` every 100 ms until it is gone (privd unlinks `c-k` and `r-k`
//! once it has copied the chunk), so at most two chunks are on the 80 MiB tmpfs (`16` inodes).
//! A consumer that does not take a chunk within [`STALL_TIMEOUT`] fails the job.
//!
//! # The template
//!
//! The same binary serves both templates; which one it runs under is told by the unit, not the
//! job: `hx-image-fetcher@.service` sets `HX_FETCH_TEMPLATE=image`, the update template sets
//! nothing. An image job under the update template, and an update job under the image template,
//! fail closed ([`Template`]).

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use hx_provision::catalog::{Distro, RecipeId};
use hx_provision::images::{
    MAX_IMAGE_BYTES, MAX_PART_BYTES, MAX_PARTS, file_name, manifest_file_name, part_file_name,
    recipe_name,
};

use super::http::{self, GetOpts, Url};
use super::{Config, FetchError, MAX_MANIFEST_BYTES};

/// Where the image fetcher unit bind-mounts privd's `/var/lib/hx/imagein`.
pub const IMAGE_OUT_DIR: &str = "/var/lib/hx-image";
/// The environment variable the image template sets (`image`).
pub const TEMPLATE_ENV: &str = "HX_FETCH_TEMPLATE";
/// The value of [`TEMPLATE_ENV`] under the image template.
pub const TEMPLATE_IMAGE: &str = "image";

/// The images manifest as the fetcher stores it.
pub const IMAGES_FILE: &str = "images.json";
/// Its detached minisign signature.
pub const IMAGES_SIG_FILE: &str = "images.json.minisig";
/// What a probe job writes.
pub const PROBE_FILE: &str = "probe.json";
/// Created after the last chunk and its marker.
pub const END_FILE: &str = "end";

/// Size of a chunk: 32 MiB (the unit's `LimitFSIZE`).
pub const CHUNK_BYTES: u64 = 32 * 1024 * 1024;
/// Largest `probe.json` privd reads.
pub const MAX_PROBE_BYTES: u64 = 4096;
/// Most bytes a probe reads from either host.
pub const PROBE_BYTES: u64 = 8 * 1024 * 1024;
/// Longest a probe reads a body.
pub const PROBE_BODY_TIME: Duration = Duration::from_secs(6);
/// Overall limit of a probe job.
pub const PROBE_OVERALL: Duration = Duration::from_secs(30);
/// Connect timeout of a probe.
pub const PROBE_CONNECT: Duration = Duration::from_secs(10);
/// Overall limit of an image job.
pub const IMAGE_TIMEOUT: Duration = Duration::from_secs(20 * 60);
/// How long the fetcher waits for the consumer to free a chunk.
pub const STALL_TIMEOUT: Duration = Duration::from_secs(120);
/// How often the back-pressure poll looks.
pub const POLL: Duration = Duration::from_millis(100);

/// The hosts a mirror probe may name (HTTPS only, bodies never written).
pub const MIRROR_PROBE_HOSTS: &[&str] = &["deb.debian.org", "archive.ubuntu.com"];

/// Name of chunk `index`.
pub fn chunk_name(index: u32) -> String {
    format!("c-{index:06}")
}

/// Name of the marker of chunk `index`.
pub fn marker_name(index: u32) -> String {
    format!("r-{index:06}")
}

/// The mirror probe URL (host and path) of a distro: the default mirror of its base image, not
/// the host's apt sources.
pub fn mirror_target(distro: Distro) -> (&'static str, &'static str) {
    match distro {
        Distro::Debian12 => (
            "deb.debian.org",
            "/debian/dists/bookworm/main/binary-amd64/Packages.xz",
        ),
        Distro::Debian13 => (
            "deb.debian.org",
            "/debian/dists/trixie/main/binary-amd64/Packages.xz",
        ),
        Distro::Ubuntu2404 => (
            "archive.ubuntu.com",
            "/ubuntu/dists/noble/universe/binary-amd64/Packages.xz",
        ),
        Distro::Ubuntu2604 => (
            "archive.ubuntu.com",
            "/ubuntu/dists/resolute/universe/binary-amd64/Packages.xz",
        ),
    }
}

/// `^[0-9]{8}\.[0-9]{1,2}$`.
pub fn is_valid_build_id(s: &str) -> bool {
    match s.split_once('.') {
        Some((d, n)) => {
            d.len() == 8
                && d.bytes().all(|b| b.is_ascii_digit())
                && (1..=2).contains(&n.len())
                && n.bytes().all(|b| b.is_ascii_digit())
        }
        None => false,
    }
}

/// Which template the process runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Template {
    /// `hx-update-fetcher@.service`: update jobs only.
    Update,
    /// `hx-image-fetcher@.service`: image jobs only.
    Image,
}

impl Template {
    /// From the value of [`TEMPLATE_ENV`]: unset is the update template, `image` the image
    /// template, anything else is refused (`None`).
    pub fn from_env_value(v: Option<&str>) -> Option<Self> {
        match v {
            None => Some(Self::Update),
            Some(TEMPLATE_IMAGE) => Some(Self::Image),
            Some(_) => None,
        }
    }
}

/// What the image fetcher is asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageJob {
    /// The signed images manifest and its signature.
    Manifest,
    /// The speed probe of a recipe's image and of the distro mirror.
    Probe {
        /// The recipe.
        recipe: RecipeId,
        /// Its build id.
        build_id: String,
    },
    /// The image itself, in chunks.
    Image {
        /// The recipe.
        recipe: RecipeId,
        /// Its build id.
        build_id: String,
        /// Number of parts of the file (1 to 4).
        nparts: usize,
    },
}

/// The recipe and the rest of `s`, where `s` starts with `<recipe>-`.
fn split_recipe(s: &str) -> Option<(RecipeId, &str)> {
    RecipeId::all().into_iter().find_map(|r| {
        s.strip_prefix(recipe_name(r).as_str())?
            .strip_prefix('-')
            .map(|rest| (r, rest))
    })
}

impl ImageJob {
    /// Parses a unit instance name; anything but the three shapes is refused.
    pub fn parse(instance: &str) -> Option<Self> {
        if instance == "images-manifest" {
            return Some(Self::Manifest);
        }
        if let Some(rest) = instance.strip_prefix("probe-") {
            let (recipe, build_id) = split_recipe(rest)?;
            return is_valid_build_id(build_id).then(|| Self::Probe {
                recipe,
                build_id: build_id.to_string(),
            });
        }
        let rest = instance.strip_prefix("image-")?;
        let (recipe, rest) = split_recipe(rest)?;
        let (build_id, n) = rest.rsplit_once('-')?;
        let nparts = match n {
            "1" => 1,
            "2" => 2,
            "3" => 3,
            "4" => 4,
            _ => return None,
        };
        is_valid_build_id(build_id).then(|| Self::Image {
            recipe,
            build_id: build_id.to_string(),
            nparts,
        })
    }

    /// The unit instance name (inverse of [`ImageJob::parse`]).
    pub fn instance(&self) -> String {
        match self {
            Self::Manifest => "images-manifest".into(),
            Self::Probe { recipe, build_id } => {
                format!("probe-{}-{build_id}", recipe_name(*recipe))
            }
            Self::Image {
                recipe,
                build_id,
                nparts,
            } => format!("image-{}-{build_id}-{nparts}", recipe_name(*recipe)),
        }
    }
}

/// The limits of the image jobs. [`ImageLimits::production`] is what the binary uses; tests
/// shrink them.
#[derive(Clone)]
pub struct ImageLimits {
    /// Overall timeout of an image job.
    pub timeout: Duration,
    /// Overall timeout of the manifest job.
    pub manifest_timeout: Duration,
    /// Overall timeout of a probe job.
    pub probe_overall: Duration,
    /// Most bytes a probe reads from one host.
    pub probe_bytes: u64,
    /// Longest a probe reads one body.
    pub probe_body_time: Duration,
    /// Connect timeout of a probe.
    pub probe_connect: Duration,
    /// Chunk size.
    pub chunk_bytes: u64,
    /// Largest image in total.
    pub max_total: u64,
    /// Largest single part (and of an unsplit image).
    pub max_part: u64,
    /// How long to wait for the consumer to free a chunk.
    pub stall: Duration,
    /// Mirror probe hosts.
    pub mirror_hosts: Vec<String>,
    /// Replaces the per-distro mirror URL (tests aim it at a loopback server).
    pub mirror_override: Option<Url>,
}

impl ImageLimits {
    /// The production values.
    pub fn production() -> Self {
        Self {
            timeout: IMAGE_TIMEOUT,
            manifest_timeout: super::MANIFEST_TIMEOUT,
            probe_overall: PROBE_OVERALL,
            probe_bytes: PROBE_BYTES,
            probe_body_time: PROBE_BODY_TIME,
            probe_connect: PROBE_CONNECT,
            chunk_bytes: CHUNK_BYTES,
            max_total: MAX_IMAGE_BYTES,
            max_part: MAX_PART_BYTES,
            stall: STALL_TIMEOUT,
            mirror_hosts: MIRROR_PROBE_HOSTS
                .iter()
                .map(|h| (*h).to_string())
                .collect(),
            mirror_override: None,
        }
    }
}

fn create_out(dir: &Path, name: &str) -> io::Result<std::fs::File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(dir.join(name))
}

/// Runs an image job into `cfg.out_dir`.
pub fn run_image(job: &ImageJob, cfg: &Config) -> Result<(), FetchError> {
    let entry_host = cfg
        .hosts
        .first()
        .ok_or_else(|| FetchError::Refused("no release host configured".into()))?
        .clone();
    match job {
        ImageJob::Manifest => manifest(cfg, &entry_host),
        ImageJob::Probe { recipe, build_id } => probe(cfg, &entry_host, *recipe, build_id),
        ImageJob::Image {
            recipe,
            build_id,
            nparts,
        } => image(cfg, &entry_host, *recipe, build_id, *nparts),
    }
}

fn manifest(cfg: &Config, host: &str) -> Result<(), FetchError> {
    let deadline = Instant::now() + cfg.image.manifest_timeout;
    let name = manifest_file_name(&cfg.arch);
    let dir = format!("{}/images", cfg.releases_path);
    let mut done: Vec<&str> = Vec::new();
    for (url_name, out, cap) in [
        (name.clone(), IMAGES_FILE, MAX_MANIFEST_BYTES),
        (
            format!("{name}.minisig"),
            IMAGES_SIG_FILE,
            MAX_MANIFEST_BYTES,
        ),
    ] {
        let mut f = create_out(&cfg.out_dir, out)?;
        let url = Url::https(host, cfg.port, &format!("{dir}/{url_name}"));
        let r = http::get(cfg, &url, deadline, cap, &mut f).and_then(|n| {
            f.flush()?;
            f.sync_all()?;
            Ok(n)
        });
        drop(f);
        match r {
            Ok(_) => done.push(out),
            Err(e) => {
                let _ = std::fs::remove_file(cfg.out_dir.join(out));
                for d in done {
                    let _ = std::fs::remove_file(cfg.out_dir.join(d));
                }
                return Err(e);
            }
        }
    }
    Ok(())
}

/// A sink that counts and discards.
struct Count(u64);

impl Write for Count {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 += buf.len() as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Reads the first bytes of the first of `paths` that exists on `host`, and returns what was read
/// and how long it took (connection included). `None` when it failed.
fn measure(
    cfg: &Config,
    hosts: &[String],
    host: &str,
    paths: &[String],
    deadline: Instant,
) -> Option<(u64, u64)> {
    let mut cfg = cfg.clone();
    cfg.connect_timeout = cfg.connect_timeout.min(cfg.image.probe_connect);
    for path in paths {
        let started = Instant::now();
        let mut sink = Count(0);
        let opts = GetOpts {
            hosts,
            max_body: u64::MAX,
            prefix: Some((cfg.image.probe_bytes, cfg.image.probe_body_time)),
        };
        let url = Url::https(host, cfg.port, path);
        match http::get_with(&cfg, &url, deadline, &opts, &mut sink) {
            Ok(g) if g.bytes > 0 => {
                let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                return Some((g.bytes, ms.max(1)));
            }
            Err(FetchError::Response(m)) if m == "status 404" => {}
            _ => return None,
        }
    }
    None
}

fn probe(cfg: &Config, host: &str, recipe: RecipeId, build_id: &str) -> Result<(), FetchError> {
    let deadline = Instant::now() + cfg.image.probe_overall;
    let file = file_name(recipe, build_id);
    let base = format!("{}/images-{build_id}", cfg.releases_path);
    // A split image has no unsplit file: its first part is the same kind of bytes.
    let rel = measure(
        cfg,
        &cfg.hosts,
        host,
        &[
            format!("{base}/{file}"),
            format!("{base}/{}", part_file_name(&file, 0)),
        ],
        deadline,
    );
    let (mirror_host, mirror_path) = match &cfg.image.mirror_override {
        Some(u) => (u.host.clone(), u.path.clone()),
        None => {
            let (h, p) = mirror_target(recipe.distro);
            (h.to_string(), p.to_string())
        }
    };
    let mir = measure(
        cfg,
        &cfg.image.mirror_hosts,
        &mirror_host,
        &[mirror_path],
        deadline,
    );
    let mut fields = Vec::new();
    if let Some((b, ms)) = rel {
        fields.push(format!("\"release_bytes\":{b},\"release_ms\":{ms}"));
    }
    if let Some((b, ms)) = mir {
        fields.push(format!("\"mirror_bytes\":{b},\"mirror_ms\":{ms}"));
    }
    let json = format!("{{{}}}", fields.join(","));
    let mut f = create_out(&cfg.out_dir, PROBE_FILE)?;
    f.write_all(json.as_bytes())?;
    f.sync_all()?;
    Ok(())
}

/// Writes the chunks and markers of the chunk protocol.
struct Chunker {
    dir: PathBuf,
    chunk: u64,
    max_total: u64,
    stall: Duration,
    deadline: Instant,
    index: u32,
    cur: Option<std::fs::File>,
    cur_len: u64,
    total: u64,
}

impl Chunker {
    fn new(cfg: &Config, deadline: Instant) -> Self {
        Self {
            dir: cfg.out_dir.clone(),
            chunk: cfg.image.chunk_bytes,
            max_total: cfg.image.max_total,
            stall: cfg.image.stall,
            deadline,
            index: 0,
            cur: None,
            cur_len: 0,
            total: 0,
        }
    }

    /// Waits until chunk `k` has been taken (its name is gone).
    fn wait_taken(&self, k: u32) -> io::Result<()> {
        let started = Instant::now();
        loop {
            match std::fs::symlink_metadata(self.dir.join(chunk_name(k))) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e),
                Ok(_) => {}
            }
            if Instant::now() >= self.deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "overall deadline while waiting for the consumer",
                ));
            }
            if started.elapsed() >= self.stall {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the consumer did not take a chunk",
                ));
            }
            std::thread::sleep(POLL);
        }
    }

    fn open_next(&mut self) -> io::Result<()> {
        if self.index >= 2 {
            self.wait_taken(self.index - 2)?;
        }
        self.cur = Some(create_out(&self.dir, &chunk_name(self.index))?);
        self.cur_len = 0;
        Ok(())
    }

    /// Flushes and fsyncs the current chunk, then creates its marker.
    fn seal(&mut self) -> io::Result<()> {
        if let Some(mut f) = self.cur.take() {
            f.flush()?;
            f.sync_all()?;
            drop(f);
            let m = create_out(&self.dir, &marker_name(self.index))?;
            m.sync_all()?;
            self.index += 1;
            self.cur_len = 0;
        }
        Ok(())
    }

    /// Seals the last, shorter chunk and creates `end`.
    fn finish(&mut self) -> io::Result<()> {
        if self.cur_len > 0 {
            self.seal()?;
        }
        create_out(&self.dir, END_FILE)?.sync_all()
    }
}

impl Write for Chunker {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.total + buf.len() as u64 > self.max_total {
            return Err(io::Error::other("the image is larger than 4 GiB"));
        }
        if self.cur.is_none() {
            self.open_next()?;
        }
        let room = usize::try_from(self.chunk - self.cur_len).unwrap_or(usize::MAX);
        let take = buf.len().min(room);
        if let Some(f) = self.cur.as_mut() {
            f.write_all(&buf[..take])?;
        }
        self.cur_len += take as u64;
        self.total += take as u64;
        if self.cur_len == self.chunk {
            self.seal()?;
        }
        Ok(take)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn image(
    cfg: &Config,
    host: &str,
    recipe: RecipeId,
    build_id: &str,
    nparts: usize,
) -> Result<(), FetchError> {
    if !(1..=MAX_PARTS).contains(&nparts) {
        return Err(FetchError::Refused("number of parts".into()));
    }
    let deadline = Instant::now() + cfg.image.timeout;
    let file = file_name(recipe, build_id);
    let base = format!("{}/images-{build_id}", cfg.releases_path);
    let mut sink = Chunker::new(cfg, deadline);
    for i in 0..nparts {
        let name = if nparts == 1 {
            file.clone()
        } else {
            part_file_name(&file, i)
        };
        let url = Url::https(host, cfg.port, &format!("{base}/{name}"));
        // The cap is per request; the chunker enforces the total.
        http::get(cfg, &url, deadline, cfg.image.max_part, &mut sink)?;
    }
    sink.finish()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rid(name: &str) -> RecipeId {
        hx_provision::images::recipe_by_name(name).unwrap()
    }

    #[test]
    fn image_jobs_round_trip_and_nothing_else_parses() {
        for j in [
            ImageJob::Manifest,
            ImageJob::Probe {
                recipe: rid("ubuntu-24.04-xfce-basic"),
                build_id: "20261123.1".into(),
            },
            ImageJob::Probe {
                recipe: rid("debian-13-xfce-developer"),
                build_id: "20261123.12".into(),
            },
            ImageJob::Image {
                recipe: rid("ubuntu-26.04-xfce-basic"),
                build_id: "20261123.1".into(),
                nparts: 1,
            },
            ImageJob::Image {
                recipe: rid("debian-12-xfce-developer"),
                build_id: "20261123.2".into(),
                nparts: 4,
            },
        ] {
            assert_eq!(ImageJob::parse(&j.instance()).as_ref(), Some(&j), "{j:?}");
        }
        for r in RecipeId::all() {
            let j = ImageJob::Image {
                recipe: r,
                build_id: "20260101.9".into(),
                nparts: 2,
            };
            assert_eq!(ImageJob::parse(&j.instance()), Some(j));
        }
        for bad in [
            "",
            "images-manifest ",
            "images-manifest-x",
            "image-",
            "images",
            "probe-",
            "probe-ubuntu-24.04-xfce-basic",
            "probe-ubuntu-24.04-xfce-basic-",
            "probe-ubuntu-24.04-xfce-basic-2026112.1",
            "probe-ubuntu-24.04-xfce-basic-20261123.100",
            "probe-ubuntu-24.04-xfce-basic-20261123.1/../x",
            "probe-ubuntu-24.04-xfce-basic-20261123.1\n",
            "probe-ubuntu-24.04-xfce-nope-20261123.1",
            "probe-ubuntu-22.04-xfce-basic-20261123.1",
            "image-ubuntu-24.04-xfce-basic-20261123.1",
            "image-ubuntu-24.04-xfce-basic-20261123.1-0",
            "image-ubuntu-24.04-xfce-basic-20261123.1-5",
            "image-ubuntu-24.04-xfce-basic-20261123.1-10",
            "image-ubuntu-24.04-xfce-basic-20261123.1-01",
            "image-ubuntu-24.04-xfce-basic-20261123.1--1",
            "image-ubuntu-24.04-xfce-basic-20261123.1-1-1",
            "image-ubuntu-24.04-xfce-basic-x-1",
            "image-ubuntu-24.04-xfce-basic--1",
            "manifest-stable",
            "artifact-1.2.3",
            "../etc",
        ] {
            assert!(ImageJob::parse(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn update_and_image_jobs_do_not_parse_as_each_other() {
        for j in [
            "images-manifest",
            "probe-ubuntu-24.04-xfce-basic-20261123.1",
        ] {
            assert!(super::super::Job::parse(j).is_none(), "{j}");
        }
        for j in ["manifest-stable", "artifact-1.2.3"] {
            assert!(ImageJob::parse(j).is_none(), "{j}");
        }
    }

    #[test]
    fn the_template_comes_from_the_unit_environment_only() {
        assert_eq!(Template::from_env_value(None), Some(Template::Update));
        assert_eq!(
            Template::from_env_value(Some("image")),
            Some(Template::Image)
        );
        for bad in ["", "Image", "update", "image ", "1"] {
            assert_eq!(Template::from_env_value(Some(bad)), None, "{bad:?}");
        }
    }

    #[test]
    fn every_distro_has_a_https_mirror_probe_url_on_a_probe_host() {
        for d in Distro::ALL {
            let (host, path) = mirror_target(d);
            assert!(MIRROR_PROBE_HOSTS.contains(&host), "{host}");
            assert!(
                path.starts_with('/') && path.ends_with("/Packages.xz"),
                "{path}"
            );
        }
    }

    #[test]
    fn chunk_names_are_fixed_width() {
        assert_eq!(chunk_name(0), "c-000000");
        assert_eq!(marker_name(12), "r-000012");
        assert_eq!(chunk_name(1_234_567), "c-1234567");
    }
}
