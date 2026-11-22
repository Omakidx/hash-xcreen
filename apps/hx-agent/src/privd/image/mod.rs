//! Prebuilt desktop images in `hx-privd` (docs/ipc.md 6.5 and 6.12, "Prebuilt images (1D)";
//! architecture 4.3).
//!
//! `CreateDesktop` can install from a signed prebuilt image, online (through the sandboxed image
//! fetcher) or from an offline file the administrator placed in `/var/lib/hx/import/`, and
//! `--image auto` chooses between that and building on the server, with a reason.
//!
//! # Modules
//!
//! | Module | Role |
//! |---|---|
//! | [`keys`] | the embedded image key pair, the release-build compile gate, the trusted-comment rule |
//! | [`state`] | `images-state`: the highest online manifest timestamp, the imported images |
//! | [`fetch`] | running the fetcher jobs and reading what they leave, chunk by chunk, into one staged file |
//! | [`offline`] | the administrator's file and signed manifest in `/var/lib/hx/import/`, read with `openat2` |
//! | [`cache`] | import into Incus, the `hx-img-*` aliases, reuse, deletion |
//! | [`choose`] | the algorithm of ipc.md 6.5 step 3 with a reason code for every outcome |
//!
//! # Trust
//!
//! privd has no IP networking: every probe and download is a fetcher job (`crate::fetcher`). What
//! the fetcher leaves is hostile (ipc.md 6.12 rules): privd opens each file once through a
//! directory descriptor with `openat2(RESOLVE_BENEATH | NO_SYMLINKS | NO_MAGICLINKS)`, requires a
//! regular file with link count 1 and exactly the size the **signed** manifest implies, copies it
//! once into a single `O_TMPFILE` of the root-only staging directory while hashing, and compares
//! the SHA-256 of the whole image (and of each part) with the signed entry. Only that staged
//! descriptor reaches Incus, so root Incus never unpacks unverified bytes.

pub mod cache;
pub mod choose;
pub mod fetch;
pub mod keys;
pub mod offline;
pub mod state;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::fetcher::images::CHUNK_BYTES;
use crate::privd::runner::CommandRunner;
use crate::privd::update::system::{Systemd, SystemdCtl};

pub use keys::{ImageKeys, ImageVerifyError};

/// One GiB.
pub const GIB: u64 = 1 << 30;

/// The manifest file name inside the offline import directory (`manifest_file_name(arch)`).
pub use hx_provision::images::manifest_file_name;

/// Paths and timings of the image path, fixed at construction like the rest of
/// [`PrivdConfig`](crate::privd::PrivdConfig).
#[derive(Debug, Clone)]
pub struct ImageConfig {
    /// Where the image fetcher writes (`/var/lib/hx/imagein`, an 80 MiB tmpfs, bind-mounted into
    /// its unit).
    pub fetch_dir: PathBuf,
    /// The offline import directory (`/var/lib/hx/import`, root 0700).
    pub import_dir: PathBuf,
    /// privd's verified copies (`/var/lib/hx/staging`).
    pub staging_dir: PathBuf,
    /// privd's state directory: the file system whose free space the staging copy needs.
    pub state_dir: PathBuf,
    /// Incus's data directory: the file system whose free space Incus's copy needs.
    pub incus_dir: PathBuf,
    /// Size of a chunk of the hand-off (32 MiB; tests use small ones).
    pub chunk_bytes: u64,
    /// How often a running job's marker files are looked at.
    pub poll: Duration,
    /// How often the unit state of a running job is asked (a `systemctl show` each time).
    pub state_poll: Duration,
    /// Longest wait for the `images-manifest` job.
    pub manifest_wait: Duration,
    /// Longest wait for a probe job (the fetcher stops itself after 30 s).
    pub probe_wait: Duration,
    /// The `IMAGE_FETCH` sub-deadline (20 minutes).
    pub fetch_wait: Duration,
    /// Longest wait for the next chunk to appear.
    pub chunk_idle: Duration,
    /// Longest wait for the unit to end after the last chunk.
    pub end_wait: Duration,
    /// Longest wait for Incus to import and unpack the image.
    pub import_wait: Duration,
    /// The deadline of `CreateDesktop` (45 minutes).
    pub create_deadline: Duration,
    /// A failed prebuilt attempt falls back to a build only when at least this much of
    /// [`ImageConfig::create_deadline`] remains (25 minutes).
    pub fallback_min_remaining: Duration,
}

impl ImageConfig {
    /// The production values.
    pub fn production(state_dir: &Path, incus_dir: &Path) -> Self {
        Self {
            fetch_dir: state_dir.join("imagein"),
            import_dir: state_dir.join("import"),
            staging_dir: state_dir.join("staging"),
            state_dir: state_dir.to_path_buf(),
            incus_dir: incus_dir.to_path_buf(),
            chunk_bytes: CHUNK_BYTES,
            poll: Duration::from_millis(100),
            state_poll: Duration::from_secs(1),
            manifest_wait: Duration::from_secs(60),
            probe_wait: Duration::from_secs(50),
            fetch_wait: Duration::from_secs(20 * 60),
            chunk_idle: Duration::from_secs(5 * 60),
            end_wait: Duration::from_secs(60),
            import_wait: Duration::from_secs(15 * 60),
            create_deadline: Duration::from_secs(45 * 60),
            fallback_min_remaining: Duration::from_secs(25 * 60),
        }
    }

    /// Values for tests, rooted in `dir`: small chunks and fast timings.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_tests(dir: &Path) -> Self {
        let state = dir.join("state");
        Self {
            fetch_dir: state.join("imagein"),
            import_dir: state.join("import"),
            staging_dir: state.join("staging"),
            state_dir: state,
            incus_dir: dir.join("incus"),
            chunk_bytes: 64 * 1024,
            poll: Duration::from_millis(5),
            state_poll: Duration::from_millis(20),
            manifest_wait: Duration::from_secs(5),
            probe_wait: Duration::from_secs(5),
            fetch_wait: Duration::from_secs(20),
            chunk_idle: Duration::from_secs(5),
            end_wait: Duration::from_secs(5),
            import_wait: Duration::from_secs(20),
            create_deadline: Duration::from_secs(45 * 60),
            fallback_min_remaining: Duration::from_secs(25 * 60),
        }
    }
}

/// The replaceable collaborators of the image path.
pub struct ImageDeps {
    /// The embedded image keys.
    pub keys: ImageKeys,
    /// systemd (the image fetcher units).
    pub systemd: Arc<dyn Systemd>,
}

impl ImageDeps {
    /// The real collaborators: the embedded keys and `systemctl` through `runner`.
    pub fn system(runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            keys: ImageKeys::embedded(),
            systemd: Arc::new(SystemdCtl::new(runner)),
        }
    }
}
