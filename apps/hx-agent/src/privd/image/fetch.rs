//! Running the image fetcher jobs and reading what they leave (docs/ipc.md 6.12, "privd's side").
//!
//! The directory the fetcher writes is **hostile**: a compromised fetcher can plant symlinks, hard
//! links and fifos, rewrite a file after announcing it, stall, and flood names. privd therefore
//!
//! 1. sweeps the directory (`unlinkat` relative to a directory descriptor) before every job and
//!    after every failed one, then `systemctl start --no-block` the job;
//! 2. for each chunk `k` waits for the marker `r-k`, the unit failing, a timeout or a cancel, opens
//!    `c-k` through the directory descriptor with `openat2(RESOLVE_BENEATH|NO_SYMLINKS|
//!    NO_MAGICLINKS)`, requires a regular file with link count 1 and **exactly** the size the
//!    signed `size` implies (`min(chunk, size - k * chunk)`);
//! 3. copies the chunk once into **one** `O_TMPFILE` in the staging directory, hashing the whole
//!    stream and each part as it goes, then unlinks `c-k` and `r-k` (which lets the fetcher write
//!    chunk `k + 2`);
//! 4. at the end compares size and SHA-256 with the signed entry, and requires the unit to have
//!    ended successfully, `end` to exist and no chunk beyond the announced count.
//!
//! Only the staged descriptor is used afterwards; the fetcher's files are never reopened.
//! Everything that can stall is bounded: a job by its wait, a chunk by the idle limit, the whole
//! download by the `IMAGE_FETCH` sub-deadline, and every wait ends at a cancel.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hx_ipc::privd::pb::{ErrorDetail, ProgressStage};
use hx_provision::images::{ImageEntry, Part};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{ImageConfig, ImageDeps};
use crate::fetcher::MAX_MANIFEST_BYTES;
use crate::fetcher::images::{
    END_FILE, IMAGES_FILE, IMAGES_SIG_FILE, ImageJob, MAX_PROBE_BYTES, PROBE_FILE, chunk_name,
    marker_name,
};
use crate::privd::cancel::CancelToken;
use crate::privd::error::CmdError;
use crate::privd::log;
use crate::privd::progress::ProgressSender;
use crate::privd::update::fetchdir::{self, FetchDir, ReadError, Staged};
use crate::privd::update::system::{JobState, Systemd};
use crate::privd::update::verify::{digest_eq, hex};

/// Largest signature file.
const MAX_SIG_BYTES: u64 = 16 * 1024;
/// Most bytes a probe may claim to have read (it reads at most 8 MiB).
const PROBE_MAX_BYTES: u64 = 16 * 1024 * 1024;
/// Longest a probe may claim to have taken.
const PROBE_MAX_MS: u64 = 60_000;
/// Copy buffer.
const BUF: usize = 256 * 1024;

/// Why a fetch did not give what was asked for.
#[derive(Debug)]
pub enum ImgErr {
    /// The job did not produce its output: it failed, timed out or could not be started.
    Job(String),
    /// What the fetcher left was refused (hostile, wrong size or digest).
    Refused(String),
    /// The request was cancelled; the error to answer with.
    Cancelled(CmdError),
    /// privd's own problem (a directory, the staging disk).
    Internal(String),
}

impl ImgErr {
    /// The command error, failing at `stage`.
    pub fn into_cmd(self, stage: ProgressStage) -> CmdError {
        match self {
            Self::Job(m) => CmdError::unavailable(m),
            Self::Refused(m) => CmdError::precondition(ErrorDetail::Image, m),
            Self::Cancelled(e) => return e,
            Self::Internal(m) => CmdError::internal(m),
        }
        .at_stage(stage)
    }

    /// A short text for a reason string (never fetcher-controlled bytes).
    pub fn text(&self) -> String {
        match self {
            Self::Job(m) | Self::Refused(m) | Self::Internal(m) => m.clone(),
            Self::Cancelled(e) => e.message.clone(),
        }
    }
}

fn read_err(e: ReadError) -> ImgErr {
    match e {
        ReadError::Missing(n) => ImgErr::Job(format!("the image fetcher produced no `{n}`")),
        other => ImgErr::Refused(format!("the fetcher's output was refused: {other}")),
    }
}

fn io_internal(what: &str, e: &io::Error) -> ImgErr {
    log::error(&format!("image fetch: {what}: {e}"));
    ImgErr::Internal(format!("{what} failed"))
}

/// The stops a dropped [`JobGuard`] started. A guard cannot wait in `drop`, so it spawns the stop
/// and leaves the handle here; a request that was cancelled while a fetcher job ran waits for
/// them (`wait`) before it answers and releases the image-directory lock, so the unit has stopped
/// before the next request sweeps the directory.
#[derive(Debug, Default)]
pub struct PendingStops(std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>);

impl PendingStops {
    fn push(&self, h: tokio::task::JoinHandle<()>) {
        if let Ok(mut v) = self.0.lock() {
            v.retain(|h| !h.is_finished());
            v.push(h);
        }
    }

    /// Waits for every stop started so far.
    pub async fn wait(&self) {
        let handles = match self.0.lock() {
            Ok(mut v) => std::mem::take(&mut *v),
            Err(_) => return,
        };
        for h in handles {
            let _ = h.await;
        }
    }
}

/// Stops the job when dropped while armed (the request was dropped mid-fetch, so the unit must not
/// keep downloading into a directory the next request sweeps).
struct JobGuard {
    systemd: Arc<dyn Systemd>,
    pending: Arc<PendingStops>,
    job: ImageJob,
    armed: bool,
}

impl JobGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for JobGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(h) = tokio::runtime::Handle::try_current() {
            let (s, j) = (self.systemd.clone(), self.job.clone());
            self.pending
                .push(h.spawn(async move { s.stop_image_job(&j).await }));
        }
    }
}

/// The probe's result: bytes per second of the release host and of the apt mirror, `None` when the
/// probe of that host failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProbeResult {
    /// Speed of the release host.
    pub release_bps: Option<u64>,
    /// Speed of the distro mirror.
    pub mirror_bps: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProbe {
    release_bytes: Option<u64>,
    release_ms: Option<u64>,
    mirror_bytes: Option<u64>,
    mirror_ms: Option<u64>,
}

/// Bytes per second from a claimed byte count and time; `Err` for numbers no honest probe writes.
fn bps(bytes: Option<u64>, ms: Option<u64>) -> Result<Option<u64>, ()> {
    match (bytes, ms) {
        (None, None) => Ok(None),
        (Some(b), Some(m))
            if (1..=PROBE_MAX_BYTES).contains(&b) && (1..=PROBE_MAX_MS).contains(&m) =>
        {
            Ok(Some(
                u64::try_from(u128::from(b) * 1000 / u128::from(m)).unwrap_or(u64::MAX),
            ))
        }
        _ => Err(()),
    }
}

/// Parses `probe.json` strictly. Anything unexpected is a failed probe.
pub fn parse_probe(bytes: &[u8]) -> ProbeResult {
    let Ok(raw) = serde_json::from_slice::<RawProbe>(bytes) else {
        return ProbeResult::default();
    };
    match (
        bps(raw.release_bytes, raw.release_ms),
        bps(raw.mirror_bytes, raw.mirror_ms),
    ) {
        (Ok(release_bps), Ok(mirror_bps)) => ProbeResult {
            release_bps,
            mirror_bps,
        },
        _ => ProbeResult::default(),
    }
}

/// Copies and hashes the staged image as it arrives.
struct StageWriter {
    dst: File,
    whole: Sha256,
    parts: Vec<PartHash>,
    cur: usize,
    total: u64,
}

struct PartHash {
    size: u64,
    expect: String,
    hasher: Sha256,
    done: u64,
}

impl StageWriter {
    fn new(dst: File, parts: &[Part]) -> Self {
        Self {
            dst,
            whole: Sha256::new(),
            parts: parts
                .iter()
                .map(|p| PartHash {
                    size: p.size,
                    expect: p.sha256.clone(),
                    hasher: Sha256::new(),
                    done: 0,
                })
                .collect(),
            cur: 0,
            total: 0,
        }
    }

    fn write(&mut self, mut buf: &[u8]) -> io::Result<()> {
        self.dst.write_all(buf)?;
        self.whole.update(buf);
        self.total += buf.len() as u64;
        while !buf.is_empty() {
            let Some(p) = self.parts.get_mut(self.cur) else {
                return Err(io::Error::other("more bytes than the parts announce"));
            };
            let take = usize::try_from((p.size - p.done).min(buf.len() as u64)).unwrap_or(0);
            p.hasher.update(&buf[..take]);
            p.done += take as u64;
            buf = &buf[take..];
            if p.done == p.size {
                self.cur += 1;
            }
        }
        Ok(())
    }

    /// Checks the total, the hash of each part and of the whole against the signed entry.
    fn finish(mut self, entry: &ImageEntry) -> Result<Staged, ImgErr> {
        if self.total != entry.size {
            return Err(ImgErr::Refused(
                "the image is not as long as announced".into(),
            ));
        }
        for p in self.parts {
            if p.done != p.size || !digest_eq(&hex(&p.hasher.finalize()), &p.expect) {
                return Err(ImgErr::Refused(
                    "a part of the image does not match its signed digest".into(),
                ));
            }
        }
        let sha = hex(&self.whole.finalize());
        if !digest_eq(&sha, &entry.sha256) {
            return Err(ImgErr::Refused(
                "the image does not match its signed digest".into(),
            ));
        }
        self.dst
            .flush()
            .and_then(|()| self.dst.seek(SeekFrom::Start(0)).map(drop))
            .map_err(|e| io_internal("the staging copy", &e))?;
        Ok(Staged {
            file: self.dst,
            len: self.total,
            sha256: sha,
        })
    }
}

/// Copies exactly `expected` bytes of `src` into `w`; a file that is shorter or longer is refused.
fn copy_chunk(
    mut src: File,
    expected: u64,
    w: &mut StageWriter,
    cancel: &CancelToken,
) -> Result<(), ImgErr> {
    let mut buf = vec![0u8; BUF];
    let mut total = 0u64;
    loop {
        if let Some(r) = cancel.reason() {
            return Err(ImgErr::Cancelled(r.error()));
        }
        // Never read past the announced size: a growing file is oversize, not a longer image.
        let want = usize::try_from((expected + 1 - total).min(buf.len() as u64)).unwrap_or(BUF);
        let n = match src.read(&mut buf[..want]) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(io_internal("reading a chunk", &e)),
        };
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > expected {
            return Err(ImgErr::Refused("a chunk is larger than announced".into()));
        }
        w.write(&buf[..n])
            .map_err(|e| io_internal("writing the staging copy", &e))?;
    }
    if total < expected {
        return Err(ImgErr::Refused("a chunk is shorter than announced".into()));
    }
    Ok(())
}

/// One use of the fetch directory: the directory descriptor, the collaborators and the request's
/// cancel token. The caller holds the daemon's image-directory lock for as long as it lives.
pub struct Fetch<'a> {
    cfg: &'a ImageConfig,
    deps: Arc<ImageDeps>,
    cancel: CancelToken,
    progress: ProgressSender,
    dir: FetchDir,
}

impl<'a> Fetch<'a> {
    /// Creates (if missing) and opens the directories and sweeps the fetch directory.
    pub fn open(
        cfg: &'a ImageConfig,
        deps: Arc<ImageDeps>,
        cancel: CancelToken,
        progress: ProgressSender,
    ) -> Result<Self, ImgErr> {
        // 1733: the fetcher's dynamic user reaches it only through the unit's bind mount (the state
        // directory above is 0700), may create files in it but not list or remove others'.
        fetchdir::ensure_dir(&cfg.fetch_dir, 0o1733)
            .and_then(|()| fetchdir::ensure_dir(&cfg.staging_dir, 0o700))
            .map_err(|e| io_internal("preparing the image directories", &e))?;
        let dir = FetchDir::open(&cfg.fetch_dir)
            .map_err(|e| io_internal("opening the fetch directory", &e))?;
        dir.require_tmpfs(cfg.fetch_tmpfs_cap)
            .map_err(|e| io_internal("checking the fetch directory", &e))?;
        let me = Self {
            cfg,
            deps,
            cancel,
            progress,
            dir,
        };
        me.sweep()?;
        Ok(me)
    }

    fn sweep(&self) -> Result<(), ImgErr> {
        self.dir
            .sweep(&[IMAGES_FILE, IMAGES_SIG_FILE, PROBE_FILE, END_FILE])
            .map_err(|e| {
                log::error(&format!("image fetch directory: {e}"));
                if e.kind() == io::ErrorKind::DirectoryNotEmpty {
                    ImgErr::Internal(format!(
                        "the image fetch directory holds entries that cannot be removed; an administrator must clear {}",
                        self.cfg.fetch_dir.display()
                    ))
                } else {
                    ImgErr::Internal("the image fetch directory cannot be cleared".into())
                }
            })
    }

    async fn pause(&self, d: Duration) -> Result<(), ImgErr> {
        tokio::select! {
            reason = self.cancel.cancelled() => Err(ImgErr::Cancelled(reason.error())),
            () = tokio::time::sleep(d) => Ok(()),
        }
    }

    async fn start(&self, job: &ImageJob) -> Result<JobGuard, ImgErr> {
        self.sweep()?;
        let systemd = self.deps.systemd.clone();
        // Armed before the start returns, so a cancel during the start still stops the unit.
        let guard = JobGuard {
            systemd: systemd.clone(),
            pending: self.deps.pending_stops.clone(),
            job: job.clone(),
            armed: true,
        };
        tokio::select! {
            reason = self.cancel.cancelled() => return Err(ImgErr::Cancelled(reason.error())),
            r = systemd.start_image_job(job) => {
                r.map_err(|e| {
                    log::error(&format!("image fetcher: {e}"));
                    ImgErr::Job("the image fetcher could not be started".into())
                })?;
            }
        }
        Ok(guard)
    }

    async fn stop(&self, job: &ImageJob, mut guard: JobGuard) {
        self.deps.systemd.stop_image_job(job).await;
        guard.disarm();
    }

    /// Runs a small job (`images-manifest`, probe) to its end within `wait`.
    async fn run_to_end(&self, job: &ImageJob, wait: Duration) -> Result<(), ImgErr> {
        let mut guard = self.start(job).await?;
        let started = Instant::now();
        loop {
            match self.deps.systemd.image_job_state(job).await {
                Ok(JobState::Succeeded) => {
                    guard.disarm();
                    return Ok(());
                }
                Ok(JobState::Failed) => {
                    self.stop(job, guard).await;
                    return Err(ImgErr::Job("the image fetcher failed".into()));
                }
                Err(e) => {
                    log::error(&format!("image fetcher state: {e}"));
                    self.stop(job, guard).await;
                    return Err(ImgErr::Job("the image fetcher's state is unknown".into()));
                }
                Ok(JobState::Running) => {}
            }
            if started.elapsed() >= wait {
                self.stop(job, guard).await;
                return Err(ImgErr::Job(
                    "the image fetcher did not finish in time".into(),
                ));
            }
            if let Err(e) = self.pause(self.cfg.state_poll).await {
                self.stop(job, guard).await;
                return Err(e);
            }
        }
    }

    /// The signed images manifest and its signature, as the fetcher left them (not yet verified).
    pub async fn manifest(&self) -> Result<(Vec<u8>, String), ImgErr> {
        self.run_to_end(&ImageJob::Manifest, self.cfg.manifest_wait)
            .await?;
        let bytes = self
            .dir
            .read_small(IMAGES_FILE, MAX_MANIFEST_BYTES)
            .map_err(read_err)?;
        let sig = self
            .dir
            .read_small(IMAGES_SIG_FILE, MAX_SIG_BYTES)
            .map_err(read_err)?;
        let sig = String::from_utf8(sig)
            .map_err(|_| ImgErr::Refused("the signature file is not text".into()))?;
        let r = (bytes, sig);
        self.sweep()?;
        Ok(r)
    }

    /// The speed probe of one image. Any failure of the job or of its output is a failed probe
    /// (`ProbeResult::default()`), never an error; only a cancel is one.
    pub async fn probe(&self, job: &ImageJob) -> Result<ProbeResult, ImgErr> {
        match self.run_to_end(job, self.cfg.probe_wait).await {
            Ok(()) => {}
            Err(e @ ImgErr::Cancelled(_)) => return Err(e),
            Err(e) => {
                log::warn(&format!("image probe: {}", e.text()));
                return Ok(ProbeResult::default());
            }
        }
        let r = match self.dir.read_small(PROBE_FILE, MAX_PROBE_BYTES) {
            Ok(b) => parse_probe(&b),
            Err(e) => {
                log::warn(&format!("image probe output: {e}"));
                ProbeResult::default()
            }
        };
        let _ = self.sweep();
        Ok(r)
    }

    /// Downloads the image of `entry` through the chunk protocol into one staged file, verified
    /// against the signed size and digests.
    pub async fn image(&self, entry: &ImageEntry) -> Result<Staged, ImgErr> {
        let recipe = entry
            .recipe_id()
            .ok_or_else(|| ImgErr::Refused("the entry names no known recipe".into()))?;
        let job = ImageJob::Image {
            recipe,
            build_id: entry.build_id.clone(),
            nparts: entry.parts.len(),
        };
        let mut guard = self.start(&job).await?;
        let r = self.image_inner(entry, &job).await;
        match &r {
            Ok(_) => guard.disarm(),
            Err(_) => {
                self.stop(&job, guard).await;
                let _ = self.sweep();
            }
        }
        r
    }

    /// Where the job stands, asked at most every `state_poll`.
    async fn check_job(&self, job: &ImageJob, last: &mut Instant) -> Result<JobState, ImgErr> {
        if last.elapsed() < self.cfg.state_poll {
            return Ok(JobState::Running);
        }
        *last = Instant::now();
        match self.deps.systemd.image_job_state(job).await {
            Ok(JobState::Failed) => Err(ImgErr::Job("the image download failed".into())),
            Ok(s) => Ok(s),
            Err(e) => {
                log::error(&format!("image fetcher state: {e}"));
                Err(ImgErr::Job("the image fetcher's state is unknown".into()))
            }
        }
    }

    async fn image_inner(&self, entry: &ImageEntry, job: &ImageJob) -> Result<Staged, ImgErr> {
        let chunk = self.cfg.chunk_bytes.max(1);
        let size = entry.size;
        let n_chunks = size.div_ceil(chunk);
        let dst = fetchdir::anonymous_file(&self.cfg.staging_dir)
            .map_err(|e| io_internal("creating the staging copy", &e))?;
        let mut w = StageWriter::new(dst, &entry.parts);
        let started = Instant::now();
        let mut progress_at = Instant::now();
        let mut state_at = Instant::now();
        let mut unit_done = false;
        for k in 0..n_chunks {
            let k32 = u32::try_from(k).map_err(|_| ImgErr::Refused("too many chunks".into()))?;
            let expected = chunk.min(size - k * chunk);
            // Wait for the marker of chunk k.
            loop {
                if self
                    .dir
                    .exists(&marker_name(k32))
                    .map_err(|e| io_internal("looking at the fetch directory", &e))?
                {
                    break;
                }
                if unit_done {
                    return Err(ImgErr::Refused(
                        "the fetcher ended with fewer chunks than announced".into(),
                    ));
                }
                if self.check_job(job, &mut state_at).await? == JobState::Succeeded {
                    // Everything it will ever write exists now: look once more, then give up.
                    unit_done = true;
                    continue;
                }
                if started.elapsed() >= self.cfg.fetch_wait {
                    return Err(ImgErr::Job(
                        "the image download did not finish in time".into(),
                    ));
                }
                if progress_at.elapsed() >= self.cfg.chunk_idle {
                    return Err(ImgErr::Job("the image download stalled".into()));
                }
                self.pause(self.cfg.poll).await?;
            }
            progress_at = Instant::now();
            let (file, len) = self
                .dir
                .open_checked(&chunk_name(k32), expected)
                .map_err(read_err)?;
            if len != expected {
                return Err(ImgErr::Refused(
                    "a chunk does not have the announced size".into(),
                ));
            }
            let cancel = self.cancel.clone();
            let (back, r) = tokio::task::spawn_blocking(move || {
                let r = copy_chunk(file, expected, &mut w, &cancel);
                (w, r)
            })
            .await
            .map_err(|_| ImgErr::Internal("the copy task failed".into()))?;
            w = back;
            r?;
            let _ = self.dir.unlink(&marker_name(k32));
            let _ = self.dir.unlink(&chunk_name(k32));
            let pct = u32::try_from((k + 1) * 100 / n_chunks).unwrap_or(100);
            self.progress.emit(
                ProgressStage::ImageFetch,
                k32 + 1,
                u32::try_from(n_chunks).unwrap_or(u32::MAX),
                "downloading the desktop image",
                pct,
                true,
            );
        }
        // The unit ends after the last marker: wait for it, then check what else is there.
        let ended = Instant::now();
        if !unit_done {
            loop {
                match self.deps.systemd.image_job_state(job).await {
                    Ok(JobState::Succeeded) => break,
                    Ok(JobState::Failed) | Err(_) => {
                        return Err(ImgErr::Job("the image download failed".into()));
                    }
                    Ok(JobState::Running) => {}
                }
                if ended.elapsed() >= self.cfg.end_wait {
                    return Err(ImgErr::Job("the image fetcher did not end".into()));
                }
                self.pause(self.cfg.poll.max(Duration::from_millis(5)))
                    .await?;
            }
        }
        let k_end =
            u32::try_from(n_chunks).map_err(|_| ImgErr::Refused("too many chunks".into()))?;
        let io_look = |e: io::Error| io_internal("looking at the fetch directory", &e);
        if !self.dir.exists(END_FILE).map_err(io_look)? {
            return Err(ImgErr::Refused("the fetcher left no end marker".into()));
        }
        if self.dir.exists(&chunk_name(k_end)).map_err(io_look)?
            || self.dir.exists(&marker_name(k_end)).map_err(io_look)?
        {
            return Err(ImgErr::Refused("the image is longer than announced".into()));
        }
        let staged = w.finish(entry)?;
        let _ = self.sweep();
        Ok(staged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_output_is_parsed_strictly() {
        let p = parse_probe(
            br#"{"release_bytes":8388608,"release_ms":1000,"mirror_bytes":1000,"mirror_ms":500}"#,
        );
        assert_eq!(p.release_bps, Some(8_388_608));
        assert_eq!(p.mirror_bps, Some(2000));
        // Absent pairs are failed probes.
        let p = parse_probe(br#"{"release_bytes":1000,"release_ms":10}"#);
        assert_eq!((p.release_bps, p.mirror_bps), (Some(100_000), None));
        assert_eq!(parse_probe(b"{}"), ProbeResult::default());
        // Everything else is a failed probe: unknown fields, halves of a pair, silly numbers,
        // garbage.
        for bad in [
            &br#"{"release_bytes":1000}"#[..],
            br#"{"release_ms":10}"#,
            br#"{"release_bytes":0,"release_ms":10}"#,
            br#"{"release_bytes":1000,"release_ms":0}"#,
            br#"{"release_bytes":99999999999,"release_ms":10}"#,
            br#"{"release_bytes":1000,"release_ms":99999999}"#,
            br#"{"release_bytes":-1,"release_ms":10}"#,
            br#"{"release_bytes":1000,"release_ms":10,"extra":1}"#,
            br#"{"release_bytes":"1000","release_ms":10}"#,
            b"[]",
            b"",
            b"\xff\xfe",
        ] {
            assert_eq!(parse_probe(bad), ProbeResult::default(), "{bad:?}");
        }
    }

    #[test]
    fn the_stage_writer_hashes_parts_across_chunk_boundaries() {
        use crate::privd::update::verify::sha256_hex;
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let parts = [
            Part {
                size: 300,
                sha256: sha256_hex(&data[..300]),
            },
            Part {
                size: 700,
                sha256: sha256_hex(&data[300..]),
            },
        ];
        let mk = || {
            let t = tempfile::tempfile().unwrap();
            StageWriter::new(t, &parts)
        };
        let entry = |sha: String| ImageEntry {
            recipe: "ubuntu-24.04-xfce-basic".into(),
            distro: "ubuntu-24.04".into(),
            desktop: "xfce".into(),
            preset: "basic".into(),
            recipe_digest: "d".repeat(64),
            build_id: "20261123.1".into(),
            created: 1,
            min_agent: "0.9.0".into(),
            format: "incus-unified".into(),
            compression: "zstd".into(),
            base_alias: "x".into(),
            file: "f".into(),
            size: 1000,
            sha256: sha,
            unpacked_size: 2000,
            parts: parts.to_vec(),
        };
        let mut w = mk();
        for c in data.chunks(77) {
            w.write(c).unwrap();
        }
        let staged = w.finish(&entry(sha256_hex(&data))).unwrap();
        assert_eq!(staged.len, 1000);
        let mut back = Vec::new();
        let mut f = staged.file;
        f.read_to_end(&mut back).unwrap();
        assert_eq!(back, data);
        // A flipped byte fails whichever digest covers it.
        let mut bad = data.clone();
        bad[650] ^= 1;
        let mut w = mk();
        w.write(&bad).unwrap();
        assert!(matches!(
            w.finish(&entry(sha256_hex(&data))),
            Err(ImgErr::Refused(_))
        ));
        // Too long: more bytes than the parts announce.
        let mut w = mk();
        w.write(&data).unwrap();
        assert!(w.write(b"x").is_err());
        // Too short.
        let mut w = mk();
        w.write(&data[..999]).unwrap();
        assert!(matches!(
            w.finish(&entry(sha256_hex(&data))),
            Err(ImgErr::Refused(_))
        ));
    }
}
