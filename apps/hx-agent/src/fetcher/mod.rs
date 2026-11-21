//! The sandboxed update fetcher (docs/ipc.md 6.12): the only code of the update path that speaks
//! HTTP. It runs as `hx-update-fetcher@<job>.service` under a dynamic user with no capabilities
//! and no `AF_UNIX` (`apps/hx-agent/systemd/hx-update-fetcher@.service`), downloads **bytes** into
//! one directory and exits. It does not verify, parse, unpack or trust anything: root `hx-privd`
//! treats whatever it left as hostile and verifies it (`privd::update`).
//!
//! # Jobs
//!
//! The unit instance is the whole argument vector (`systemctl start hx-update-fetcher@<job>`), so
//! privd never builds a command line from data: [`Job::parse`] accepts exactly
//! `manifest-<channel>` and `artifact-<version>` and nothing else (the version through the strict
//! regex of ipc.md 6.12 rule 1).
//!
//! | Job | Downloads | Into |
//! |---|---|---|
//! | `manifest-stable`, `manifest-beta` | `manifest-<arch>.json` and its `.minisig` from the channel's release | `manifest.json`, `manifest.json.minisig` |
//! | `artifact-<version>` | `hx-<version>-<arch>.tar.gz` from the release `v<version>` | `artifact.tar.gz` |
//!
//! # Network rules
//!
//! HTTPS only, TLS 1.3 only (rustls without `tls12`), roots from the system store. A request
//! goes only to a host of [`RELEASE_HOSTS`]; a redirect is followed (at most 4) only to another
//! host of the list, over HTTPS. Every address the name resolves to must be a global unicast
//! address (loopback, private, link-local, CGNAT, multicast and documentation ranges are
//! refused), so a poisoned name cannot aim the fetcher at the machine's own services. 15 s to
//! connect; 45 s overall for a manifest and 10 minutes for an artifact; at most 1 MiB per
//! manifest file and 256 MiB per artifact; 5 GiB for the directory as a whole.

mod http;

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub use http::{Url, parse_url};

/// The hosts a download may come from (and be redirected to).
pub const RELEASE_HOSTS: &[&str] = &[
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
];
/// Path prefix of the project's releases on `github.com`.
pub const RELEASES_PATH: &str = "/Omakidx/hash-xcreen/releases/download";
/// Where the fetcher unit bind-mounts privd's update directory.
pub const OUT_DIR: &str = "/var/lib/hx-update";

/// File names privd reads (the fetcher writes nothing else).
pub const MANIFEST_FILE: &str = "manifest.json";
/// The detached minisign signature of [`MANIFEST_FILE`].
pub const MANIFEST_SIG_FILE: &str = "manifest.json.minisig";
/// The release artifact.
pub const ARTIFACT_FILE: &str = "artifact.tar.gz";

/// Largest manifest or signature file.
pub const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
/// Largest agent release artifact.
pub const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
/// Largest total written to the directory.
pub const MAX_DIR_BYTES: u64 = 5 * 1024 * 1024 * 1024;
/// Connect timeout.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Overall timeout of a manifest job.
pub const MANIFEST_TIMEOUT: Duration = Duration::from_secs(45);
/// Overall timeout of an artifact job.
pub const ARTIFACT_TIMEOUT: Duration = Duration::from_secs(600);
/// Most redirects followed.
pub const MAX_REDIRECTS: usize = 4;

/// A release channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// Tested releases.
    Stable,
    /// Pre-releases.
    Beta,
}

impl Channel {
    /// The name used in unit instances and URLs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
        }
    }

    /// Parses `stable` or `beta` exactly.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "stable" => Some(Self::Stable),
            "beta" => Some(Self::Beta),
            _ => None,
        }
    }
}

/// What the fetcher is asked to download.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Job {
    /// The signed manifest of a channel and its signature.
    Manifest(Channel),
    /// The artifact of a version (already validated).
    Artifact(String),
}

impl Job {
    /// Parses a unit instance name. Anything but the two shapes is refused.
    pub fn parse(instance: &str) -> Option<Self> {
        if let Some(c) = instance.strip_prefix("manifest-") {
            return Channel::parse(c).map(Self::Manifest);
        }
        let v = instance.strip_prefix("artifact-")?;
        hx_ipc::privd::is_valid_update_version(v).then(|| Self::Artifact(v.to_string()))
    }

    /// The unit instance name (inverse of [`Job::parse`]).
    pub fn instance(&self) -> String {
        match self {
            Self::Manifest(c) => format!("manifest-{}", c.as_str()),
            Self::Artifact(v) => format!("artifact-{v}"),
        }
    }
}

/// Why a job failed. The text goes to the journal of the fetcher unit; privd only sees the exit
/// status.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// The name or a redirect target is not a release host, or the URL is not HTTPS.
    #[error("refused: {0}")]
    Refused(String),
    /// Name resolution failed or gave no acceptable address.
    #[error("cannot resolve `{0}`")]
    Resolve(String),
    /// A time limit ran out.
    #[error("timed out: {0}")]
    Timeout(&'static str),
    /// A size quota would be exceeded.
    #[error("over quota: {0}")]
    Quota(&'static str),
    /// The server answered something other than a clean 200.
    #[error("bad response: {0}")]
    Response(String),
    /// TLS failed (certificate, protocol).
    #[error("tls: {0}")]
    Tls(String),
    /// Reading or writing failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Everything the fetcher needs. [`Config::production`] is what the binary uses; tests build
/// their own (a loopback server and its own root).
#[derive(Clone)]
pub struct Config {
    /// Hosts a request or redirect may name.
    pub hosts: Vec<String>,
    /// TCP port of every request (443).
    pub port: u16,
    /// Path prefix of the releases (`/Omakidx/hash-xcreen/releases/download`).
    pub releases_path: String,
    /// The architecture in the artifact names (`x86_64`, `aarch64`).
    pub arch: String,
    /// The trust anchors.
    pub roots: Arc<rustls::RootCertStore>,
    /// Where files are written.
    pub out_dir: PathBuf,
    /// Accept loopback, private and other non-global addresses. Only the tests set it; the
    /// production configuration never does.
    pub allow_non_global: bool,
    /// Connect timeout.
    pub connect_timeout: Duration,
    /// Overall timeout of a manifest job.
    pub manifest_timeout: Duration,
    /// Overall timeout of an artifact job.
    pub artifact_timeout: Duration,
    /// Largest manifest or signature.
    pub max_manifest: u64,
    /// Largest artifact.
    pub max_artifact: u64,
}

impl Config {
    /// The production configuration: the release hosts, port 443, the system trust store, this
    /// binary's architecture, the unit's bind-mounted directory.
    pub fn production() -> Result<Self, FetchError> {
        let loaded = rustls_native_certs::load_native_certs();
        let mut roots = rustls::RootCertStore::empty();
        let (added, _ignored) = roots.add_parsable_certificates(loaded.certs);
        if added == 0 {
            return Err(FetchError::Tls("the system trust store is empty".into()));
        }
        Ok(Self {
            hosts: RELEASE_HOSTS.iter().map(|h| (*h).to_string()).collect(),
            port: 443,
            releases_path: RELEASES_PATH.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            roots: Arc::new(roots),
            out_dir: OUT_DIR.into(),
            allow_non_global: false,
            connect_timeout: CONNECT_TIMEOUT,
            manifest_timeout: MANIFEST_TIMEOUT,
            artifact_timeout: ARTIFACT_TIMEOUT,
            max_manifest: MAX_MANIFEST_BYTES,
            max_artifact: MAX_ARTIFACT_BYTES,
        })
    }

    fn host_allowed(&self, host: &str) -> bool {
        self.hosts.iter().any(|h| h == host)
    }

    /// The `(url path, output file name)` pairs of a job and the byte cap of each.
    fn plan(&self, job: &Job) -> Vec<(String, &'static str, u64)> {
        let base = &self.releases_path;
        let arch = &self.arch;
        match job {
            Job::Manifest(c) => {
                let dir = format!("{base}/channel-{}", c.as_str());
                vec![
                    (
                        format!("{dir}/manifest-{arch}.json"),
                        MANIFEST_FILE,
                        self.max_manifest,
                    ),
                    (
                        format!("{dir}/manifest-{arch}.json.minisig"),
                        MANIFEST_SIG_FILE,
                        self.max_manifest,
                    ),
                ]
            }
            Job::Artifact(v) => vec![(
                format!("{base}/v{v}/hx-{v}-{arch}.tar.gz"),
                ARTIFACT_FILE,
                self.max_artifact,
            )],
        }
    }
}

/// Runs a job: downloads each file of the plan from `github.com` (the first host of the list)
/// into `cfg.out_dir`. A file is created exclusively, mode 0644 (privd reads it without
/// `CAP_DAC_OVERRIDE`), and removed again if its download fails.
pub fn run(job: &Job, cfg: &Config) -> Result<(), FetchError> {
    let entry_host = cfg
        .hosts
        .first()
        .ok_or_else(|| FetchError::Refused("no release host configured".into()))?
        .clone();
    let overall = match job {
        Job::Manifest(_) => cfg.manifest_timeout,
        Job::Artifact(_) => cfg.artifact_timeout,
    };
    let deadline = Instant::now() + overall;
    let mut written_total = 0u64;
    let mut done: BTreeMap<&'static str, u64> = BTreeMap::new();
    for (path, name, cap) in cfg.plan(job) {
        let dest = cfg.out_dir.join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&dest)?;
        let budget = cap.min(MAX_DIR_BYTES.saturating_sub(written_total));
        let url = Url::https(&entry_host, cfg.port, &path);
        let result = http::get(cfg, &url, deadline, budget, &mut file).and_then(|n| {
            file.flush()?;
            file.sync_all()?;
            Ok(n)
        });
        drop(file);
        match result {
            Ok(n) => {
                written_total += n;
                done.insert(name, n);
            }
            Err(e) => {
                remove_quietly(&dest);
                for done_name in done.keys() {
                    remove_quietly(&cfg.out_dir.join(done_name));
                }
                return Err(e);
            }
        }
    }
    Ok(())
}

fn remove_quietly(p: &Path) {
    let _ = std::fs::remove_file(p);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jobs_round_trip_and_nothing_else_parses() {
        for j in [
            Job::Manifest(Channel::Stable),
            Job::Manifest(Channel::Beta),
            Job::Artifact("1.2.3".into()),
            Job::Artifact("10.0.9999-rc.12".into()),
        ] {
            assert_eq!(Job::parse(&j.instance()).as_ref(), Some(&j));
        }
        for bad in [
            "",
            "manifest-",
            "manifest-nightly",
            "manifest-stable ",
            "artifact-",
            "artifact-1.2",
            "artifact-1.2.3/../../x",
            "artifact-1.2.3\n",
            "artifact--1.2.3",
            "../etc",
            "manifest-stable-extra",
        ] {
            assert!(Job::parse(bad).is_none(), "{bad:?}");
        }
    }
}
