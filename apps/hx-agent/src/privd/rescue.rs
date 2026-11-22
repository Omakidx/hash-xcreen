//! The logic of `hx-privd-rescue`, the rollback helper that `hx-privd.service` names in
//! `OnFailure=` (ipc.md 6.12; the installer puts the binary at `/usr/lib/hx-rescue/`, outside
//! `/usr/lib/hx`, so that pruning old versions never removes it).
//!
//! # When it runs and why
//!
//! A new privd that cannot start at all (a bad ELF, a missing library) never reaches
//! [`Daemon::resume_update`](crate::privd::Daemon), so nothing rolls the update back. systemd
//! gives up on the unit after `StartLimitBurst` starts and starts this helper through
//! `OnFailure=`. The helper:
//!
//! 1. reads `pending.version` and `pending.previous` from `updates-state`, and nothing else;
//! 2. does nothing if there is no `pending` (privd failed for another reason);
//! 3. otherwise restores `current` to `previous` with [`Layout::restore`] (the same call
//!    `rollback_now` makes), **never writing `updates-state`**: an older helper must not drop
//!    fields a newer privd added;
//! 4. runs `systemctl reset-failed` and `systemctl start` for privd's socket and service.
//!
//! The restarted old privd then finds `pending` with `running_version != pending.version` and
//! runs `rollback_now`, which does the bookkeeping (`rolled_back`, `UPDATE_ROLLED_BACK`) and
//! restarts both units (`cmd/update_resume.rs`).
//!
//! # Trust
//!
//! The helper is root and `updates-state` lives in privd's root-only directory, but it still
//! refuses anything unexpected: the directory and the file are opened `O_NOFOLLOW`, the file must
//! be a regular file owned by root with mode exactly 0600, at most 1 MiB, and both versions must
//! match the release-version syntax before they reach a path. The environment is never read, there
//! are no arguments, and `systemctl` runs with a fixed argument vector and a cleared environment.

use std::io::{self, Read};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rustix::fs::{FileType, Mode, OFlags};
use serde::Deserialize;

use crate::privd::update::switch::Layout;

/// Most bytes of `updates-state` the helper reads.
pub const MAX_STATE_BYTES: u64 = 1 << 20;
/// File name in the state directory.
pub const STATE_FILE: &str = "updates-state";
/// How long one `systemctl` may run.
pub const CTL_TIMEOUT: Duration = Duration::from_secs(60);

/// `systemctl reset-failed ...`: clears the start-limit counter so that `start` is allowed.
pub const RESET_ARGS: &[&str] = &["reset-failed", "hx-privd.service", "hx-privd.socket"];
/// `systemctl start ...`: the socket first, then the service.
pub const START_ARGS: &[&str] = &["start", "hx-privd.socket", "hx-privd.service"];

/// Where the helper reads and writes.
#[derive(Debug, Clone)]
pub struct Paths {
    /// privd's state directory (`/var/lib/hx`).
    pub state_dir: PathBuf,
    /// The release directory (`/usr/lib/hx`).
    pub releases_dir: PathBuf,
    /// The uid that must own the state directory and file (0 in production).
    pub owner_uid: u32,
}

impl Paths {
    /// The production paths.
    pub fn production() -> Self {
        Self {
            state_dir: crate::privd::config::STATE_DIR.into(),
            releases_dir: crate::privd::update::VERSIONS_DIR.into(),
            owner_uid: 0,
        }
    }
}

/// What the helper does to units (a seam so that tests never run `systemctl`).
pub trait Ctl {
    /// Runs `systemctl` with `args`; `Ok(true)` on exit status 0.
    fn systemctl(&self, args: &[&str]) -> io::Result<bool>;
}

/// The real `systemctl`: an absolute path, a fixed argument vector, a cleared environment, no
/// stdin, and a timeout after which the child is killed.
pub struct SystemCtl;

impl Ctl for SystemCtl {
    fn systemctl(&self, args: &[&str]) -> io::Result<bool> {
        let path = ["/usr/bin/systemctl", "/bin/systemctl"]
            .into_iter()
            .map(PathBuf::from)
            .find(|p| p.is_file())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "systemctl is not installed"))?;
        let mut child = Command::new(path)
            .args(args)
            .env_clear()
            .stdin(Stdio::null())
            .spawn()?;
        let deadline = Instant::now() + CTL_TIMEOUT;
        loop {
            if let Some(status) = child.try_wait()? {
                return Ok(status.success());
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "systemctl timed out",
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// What a run did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// No `pending` update (or no `updates-state`): nothing was changed.
    NoPending,
    /// `pending` was found. `restored` says whether `current` moved; `links_untouched` is the
    /// case where `current` was neither the failed version nor its predecessor, so it was left
    /// alone. privd was then restarted.
    Restarted {
        /// `current` was moved back to `previous`.
        restored: bool,
        /// `current` named an unrelated version and was not touched.
        links_untouched: bool,
    },
}

/// Why the helper stopped.
#[derive(Debug)]
pub enum RescueError {
    /// A system call failed.
    Io(io::Error),
    /// The state directory or file is not what privd writes (a symlink, wrong owner or mode,
    /// not a regular file, too large).
    Untrusted(&'static str),
    /// `updates-state` is not valid JSON of the expected shape.
    Corrupt,
    /// A version in `pending` does not match the release-version syntax.
    BadVersion(&'static str),
    /// `pending` records no predecessor, so there is nothing to restore.
    NoPrevious,
    /// `Layout::restore` or reading the links failed.
    Layout(io::Error),
    /// `systemctl start` failed.
    Start(io::Error),
    /// `systemctl start` exited non-zero.
    StartFailed,
}

impl std::fmt::Display for RescueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "cannot read updates-state: {e}"),
            Self::Untrusted(why) => write!(f, "refusing updates-state: {why}"),
            Self::Corrupt => write!(f, "updates-state is corrupt"),
            Self::BadVersion(which) => write!(f, "pending.{which} is not a release version"),
            Self::NoPrevious => write!(f, "the pending update recorded no previous version"),
            Self::Layout(e) => write!(f, "cannot restore the previous version: {e}"),
            Self::Start(e) => write!(f, "cannot run systemctl start: {e}"),
            Self::StartFailed => write!(f, "systemctl start hx-privd failed"),
        }
    }
}

impl std::error::Error for RescueError {}

impl From<rustix::io::Errno> for RescueError {
    fn from(e: rustix::io::Errno) -> Self {
        Self::Io(e.into())
    }
}

/// The two fields of `pending` the helper reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// The version that was switched in (the failed one).
    pub version: String,
    /// The version `current` pointed at before.
    pub previous: Option<String>,
}

#[derive(Deserialize)]
struct StateLite {
    #[serde(default)]
    pending: Option<PendingLite>,
}

#[derive(Deserialize)]
struct PendingLite {
    version: String,
    #[serde(default)]
    previous: Option<String>,
}

/// Reads `pending.version` and `pending.previous`, after checking the directory and the file.
/// `Ok(None)` when there is no state file or no `pending` in it.
pub fn read_pending(paths: &Paths) -> Result<Option<Pending>, RescueError> {
    let dir = match rustix::fs::open(
        &paths.state_dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(d) => d,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        // `O_DIRECTORY | O_NOFOLLOW` on a symlink: ELOOP or ENOTDIR depending on the kernel path.
        Err(rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) => {
            return Err(RescueError::Untrusted(
                "the state directory is a symlink or not a directory",
            ));
        }
        Err(e) => return Err(e.into()),
    };
    let st = rustix::fs::fstat(&dir)?;
    if st.st_uid != paths.owner_uid || st.st_mode & 0o022 != 0 {
        return Err(RescueError::Untrusted(
            "the state directory is not owned by root or is writable by others",
        ));
    }
    let fd = match rustix::fs::openat(
        &dir,
        STATE_FILE,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(rustix::io::Errno::LOOP) => {
            return Err(RescueError::Untrusted("updates-state is a symlink"));
        }
        Err(e) => return Err(e.into()),
    };
    let st = rustix::fs::fstat(&fd)?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(RescueError::Untrusted(
            "updates-state is not a regular file",
        ));
    }
    if st.st_uid != paths.owner_uid {
        return Err(RescueError::Untrusted("updates-state is not owned by root"));
    }
    if st.st_mode & 0o7777 != 0o600 {
        return Err(RescueError::Untrusted("updates-state is not mode 0600"));
    }
    let mut bytes = Vec::new();
    std::fs::File::from(fd)
        .take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(RescueError::Io)?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(RescueError::Untrusted("updates-state is too large"));
    }
    let lite: StateLite = serde_json::from_slice(&bytes).map_err(|_| RescueError::Corrupt)?;
    let Some(p) = lite.pending else {
        return Ok(None);
    };
    if !hx_ipc::privd::is_valid_update_version(&p.version) {
        return Err(RescueError::BadVersion("version"));
    }
    if let Some(prev) = &p.previous
        && !hx_ipc::privd::is_valid_update_version(prev)
    {
        return Err(RescueError::BadVersion("previous"));
    }
    Ok(Some(Pending {
        version: p.version,
        previous: p.previous,
    }))
}

/// The helper: see the module documentation. Never writes `updates-state`.
pub fn run(paths: &Paths, ctl: &dyn Ctl) -> Result<Outcome, RescueError> {
    let Some(p) = read_pending(paths)? else {
        return Ok(Outcome::NoPending);
    };
    let previous = p.previous.ok_or(RescueError::NoPrevious)?;
    let layout = Layout::new(&paths.releases_dir);
    let current = layout.current().map_err(RescueError::Layout)?;
    // `pending` describes the latest switch, so `current` is the failed version, or already the
    // predecessor (an interrupted rollback, or a switch that never happened). Anything else was
    // changed by someone since; restoring `previous` could move it backwards, so leave it.
    let related = current
        .as_deref()
        .is_none_or(|c| c == p.version || c == previous);
    let restored = if related {
        layout
            .restore(&previous, &p.version)
            .map_err(RescueError::Layout)?
    } else {
        false
    };
    // A failed reset only means there was nothing to reset.
    let _ = ctl.systemctl(RESET_ARGS);
    match ctl.systemctl(START_ARGS) {
        Ok(true) => Ok(Outcome::Restarted {
            restored,
            links_untouched: !related,
        }),
        Ok(false) => Err(RescueError::StartFailed),
        Err(e) => Err(RescueError::Start(e)),
    }
}
