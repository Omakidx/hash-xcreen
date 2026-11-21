//! The on-disk layout of installed releases and the switch between them (ipc.md 6.12).
//!
//! ```text
//! /usr/lib/hx/
//!   1.4.2/                 one directory per retained version (at most two besides a new one)
//!     hx-privd hx-gatewayd hx-agent hx-update-fetcher hx-backup-worker   the agent binaries
//!     session/<distro>/hx-session.deb                                   per-distro guest packages
//!     VERSION                                                           the version, as text
//!   1.4.1/
//!   current  -> 1.4.2      relative symlinks; the units run /usr/lib/hx/current/<binary>
//!   previous -> 1.4.1
//! ```
//!
//! **Why symlinks, not `RENAME_EXCHANGE` of directories.** The units say
//! `ExecStart=/usr/lib/hx/current/hx-gatewayd`, so `current` must be a path that resolves to a
//! directory. A symlink is switched atomically with `symlinkat` of a temporary name and `renameat`
//! over the old one (rename replaces the destination in one step, so a reader sees the old target
//! or the new one, never neither). Switching `current` and `previous` are two such steps; the
//! order (`previous` first, then `current`) means that a crash between them leaves both pointing
//! at the running version, which is harmless.
//!
//! A new release is unpacked into `.incoming-<version>-<rand>` and renamed to `<version>` only
//! when complete and checked, so a half-extracted tree is never reachable under a version name.
//! Everything is done relative to a descriptor of `/usr/lib/hx`, opened `O_NOFOLLOW`, which must be
//! owned by the effective uid and not writable by anyone else.

use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, FileType, Mode, OFlags, ResolveFlags};

use super::verify::hex;
use super::version::Version;

/// Files a release must contain to be switched to.
pub const REQUIRED_BINARIES: &[&str] =
    &["hx-privd", "hx-gatewayd", "hx-agent", "hx-update-fetcher"];
/// The text file holding the version.
pub const VERSION_FILE: &str = "VERSION";

/// The release directory `/usr/lib/hx` (or a test's).
#[derive(Debug, Clone)]
pub struct Layout {
    dir: PathBuf,
}

/// Whether `name` is a version directory name.
pub fn is_version_dir(name: &str) -> bool {
    Version::parse(name).is_some()
}

fn rand_hex() -> io::Result<String> {
    let mut b = [0u8; 6];
    getrandom::fill(&mut b).map_err(io::Error::other)?;
    Ok(hex(&b))
}

impl Layout {
    /// A layout rooted at `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The root directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Opens the root directory and checks it is ours alone: a directory (not a symlink) owned
    /// by the effective uid and writable by nobody else.
    fn open(&self) -> io::Result<OwnedFd> {
        let fd = rustix::fs::open(
            &self.dir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let st = rustix::fs::fstat(&fd)?;
        if st.st_uid != rustix::process::geteuid().as_raw() || st.st_mode & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the release directory is not owned by privd or is writable by others",
            ));
        }
        Ok(fd)
    }

    fn read_link(&self, root: &OwnedFd, name: &str) -> io::Result<Option<String>> {
        match rustix::fs::readlinkat(root, name, Vec::new()) {
            Ok(t) => {
                let t = t.into_string().map_err(|_| bad_link(name))?;
                if is_version_dir(&t) {
                    Ok(Some(t))
                } else {
                    Err(bad_link(name))
                }
            }
            Err(rustix::io::Errno::NOENT) => Ok(None),
            Err(rustix::io::Errno::INVAL) => Err(bad_link(name)),
            Err(e) => Err(e.into()),
        }
    }

    /// The version `current` points at.
    pub fn current(&self) -> io::Result<Option<String>> {
        self.read_link(&self.open()?, "current")
    }

    /// The version `previous` points at.
    pub fn previous(&self) -> io::Result<Option<String>> {
        self.read_link(&self.open()?, "previous")
    }

    /// Replaces the symlink `name` with one to `target`, atomically.
    fn set_link(&self, root: &OwnedFd, name: &str, target: &str) -> io::Result<()> {
        debug_assert!(is_version_dir(target));
        let tmp = format!(".{name}.new-{}", rand_hex()?);
        rustix::fs::symlinkat(target, root, tmp.as_str())?;
        if let Err(e) = rustix::fs::renameat(root, tmp.as_str(), root, name) {
            let _ = rustix::fs::unlinkat(root, tmp.as_str(), AtFlags::empty());
            return Err(e.into());
        }
        std::fs::File::from(rustix::io::fcntl_dupfd_cloexec(root, 0)?).sync_all()
    }

    /// Creates the directory a release is unpacked into and returns its name and descriptor. The
    /// directory is mode 0755 whatever the umask.
    pub fn begin(&self, version: &str) -> io::Result<(String, OwnedFd)> {
        if !is_version_dir(version) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a version"));
        }
        let root = self.open()?;
        let name = format!(".incoming-{version}-{}", rand_hex()?);
        rustix::fs::mkdirat(&root, name.as_str(), Mode::from_raw_mode(0o700))?;
        let fd = rustix::fs::openat2(
            &root,
            name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )?;
        rustix::fs::fchmod(&fd, Mode::from_raw_mode(0o755))?;
        Ok((name, fd))
    }

    /// Removes an unpacking directory that is not going to be used (best effort).
    pub fn discard(&self, incoming: &str) {
        if incoming.starts_with(".incoming-") && !incoming.contains('/') {
            let _ = std::fs::remove_dir_all(self.dir.join(incoming));
        }
    }

    /// Moves a finished unpacking directory to its version name. An existing directory of that
    /// version is replaced unless it is `current`.
    pub fn publish(&self, incoming: &str, version: &str) -> io::Result<()> {
        if !is_version_dir(version) || !incoming.starts_with(".incoming-") || incoming.contains('/')
        {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad name"));
        }
        let root = self.open()?;
        // The running version is never replaced. `previous` may be: after a rollback it is the
        // version that failed, and the same release is offered again.
        if self.read_link(&root, "current")?.as_deref() == Some(version) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "that version is current",
            ));
        }
        match rustix::fs::statat(&root, version, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => std::fs::remove_dir_all(self.dir.join(version))?,
            Err(rustix::io::Errno::NOENT) => {}
            Err(e) => return Err(e.into()),
        }
        rustix::fs::renameat(&root, incoming, &root, version)?;
        Ok(())
    }

    /// Checks that a version directory holds a complete release: the required binaries as
    /// executable regular files, and a `VERSION` file naming this version.
    pub fn verify_dir(&self, version: &str) -> Result<(), String> {
        self.verify_named(version, version)
    }

    /// [`Layout::verify_dir`] for the unpacking directory `incoming` that will become `version`.
    pub fn verify_incoming(&self, incoming: &str, version: &str) -> Result<(), String> {
        if !incoming.starts_with(".incoming-") || incoming.contains('/') {
            return Err("not an unpacking directory".into());
        }
        self.verify_named(incoming, version)
    }

    fn verify_named(&self, dir_name: &str, version: &str) -> Result<(), String> {
        if !is_version_dir(version) {
            return Err("not a version".into());
        }
        let root = self.open().map_err(|e| e.to_string())?;
        let vdir = rustix::fs::openat2(
            &root,
            dir_name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|_| format!("version {version} is not installed"))?;
        let beneath =
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS;
        for name in REQUIRED_BINARIES.iter().copied().chain([VERSION_FILE]) {
            let fd = rustix::fs::openat2(
                &vdir,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
                beneath,
            )
            .map_err(|_| format!("`{name}` is missing from version {version}"))?;
            let st = rustix::fs::fstat(&fd).map_err(|e| e.to_string())?;
            if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
                return Err(format!("`{name}` is not a regular file"));
            }
            if name != VERSION_FILE && st.st_mode & 0o111 == 0 {
                return Err(format!("`{name}` is not executable"));
            }
            if name == VERSION_FILE {
                use std::io::Read;
                let mut text = String::new();
                std::fs::File::from(fd)
                    .take(64)
                    .read_to_string(&mut text)
                    .map_err(|e| e.to_string())?;
                if text.trim() != version {
                    return Err(format!("VERSION does not say {version}"));
                }
            }
        }
        Ok(())
    }

    /// Switches `current` to `new` (and `previous` to the version that was current). The new
    /// version must already be published and complete. Returns the version that was current.
    pub fn switch_to(&self, new: &str) -> io::Result<Option<String>> {
        self.verify_dir(new)
            .map_err(|m| io::Error::new(io::ErrorKind::InvalidData, m))?;
        let root = self.open()?;
        let old = self.read_link(&root, "current")?;
        if old.as_deref() == Some(new) {
            return Ok(old);
        }
        if let Some(o) = &old {
            self.set_link(&root, "previous", o)?;
        }
        self.set_link(&root, "current", new)?;
        Ok(old)
    }

    /// Restores `to` as `current` (the version a pending update recorded as its predecessor) and
    /// parks `bad` as `previous`. Idempotent and never older than `to`: if `current` already is
    /// `to` nothing moves (a second call after a crash, or an update that was never switched in).
    /// Returns whether `current` changed.
    pub fn restore(&self, to: &str, bad: &str) -> io::Result<bool> {
        self.verify_dir(to)
            .map_err(|m| io::Error::new(io::ErrorKind::InvalidData, m))?;
        let root = self.open()?;
        if self.read_link(&root, "current")?.as_deref() == Some(to) {
            return Ok(false);
        }
        self.set_link(&root, "current", to)?;
        let bad_exists = is_version_dir(bad)
            && bad != to
            && rustix::fs::statat(&root, bad, AtFlags::SYMLINK_NOFOLLOW).is_ok();
        if bad_exists {
            self.set_link(&root, "previous", bad)?;
        }
        Ok(true)
    }

    /// Points `current` at `previous` and `previous` at the old `current`. Returns
    /// `(from, to)`: the version that was current and the one that is now.
    pub fn swap_back(&self) -> io::Result<(String, String)> {
        let root = self.open()?;
        let none =
            |what: &str| io::Error::new(io::ErrorKind::NotFound, format!("no {what} version"));
        let cur = self
            .read_link(&root, "current")?
            .ok_or_else(|| none("current"))?;
        let prev = self
            .read_link(&root, "previous")?
            .ok_or_else(|| none("previous"))?;
        self.verify_dir(&prev)
            .map_err(|m| io::Error::new(io::ErrorKind::InvalidData, m))?;
        self.set_link(&root, "current", &prev)?;
        self.set_link(&root, "previous", &cur)?;
        Ok((cur, prev))
    }

    /// Removes every version directory except those in `keep`, and stale unpacking directories.
    /// Returns what was removed. (`remove_dir_all` never follows a symlink.)
    pub fn prune(&self, keep: &[&str]) -> io::Result<Vec<String>> {
        let root = self.open()?;
        let names: Vec<String> = rustix::fs::Dir::read_from(root.as_fd())?
            .filter_map(Result::ok)
            .filter_map(|e| e.file_name().to_str().ok().map(str::to_string))
            .collect();
        let mut removed = Vec::new();
        for n in names {
            let stale = n.starts_with(".incoming-");
            if !(stale || (is_version_dir(&n) && !keep.contains(&n.as_str()))) {
                continue;
            }
            let is_dir = rustix::fs::statat(&root, n.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                .is_ok_and(|st| FileType::from_raw_mode(st.st_mode) == FileType::Directory);
            if is_dir && std::fs::remove_dir_all(self.dir.join(&n)).is_ok() {
                removed.push(n);
            }
        }
        removed.sort();
        Ok(removed)
    }
}

fn bad_link(name: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("`{name}` is not a link to a version directory"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A complete release directory `version` under `dir`.
    pub(crate) fn install(dir: &Path, version: &str) {
        let v = dir.join(version);
        std::fs::create_dir_all(&v).unwrap();
        for b in REQUIRED_BINARIES {
            std::fs::write(v.join(b), b"#!/bin/true\n").unwrap();
            std::fs::set_permissions(v.join(b), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::write(v.join(VERSION_FILE), format!("{version}\n")).unwrap();
    }

    fn layout() -> (tempfile::TempDir, Layout) {
        let t = tempfile::tempdir().unwrap();
        std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let l = Layout::new(t.path());
        (t, l)
    }

    #[test]
    fn switching_moves_current_and_previous() {
        let (t, l) = layout();
        install(t.path(), "1.0.0");
        install(t.path(), "1.1.0");
        assert_eq!(l.current().unwrap(), None);
        assert_eq!(l.switch_to("1.0.0").unwrap(), None);
        assert_eq!(l.current().unwrap().as_deref(), Some("1.0.0"));
        assert_eq!(l.switch_to("1.1.0").unwrap().as_deref(), Some("1.0.0"));
        assert_eq!(l.current().unwrap().as_deref(), Some("1.1.0"));
        assert_eq!(l.previous().unwrap().as_deref(), Some("1.0.0"));
        // Switching to what is already current is a no-op.
        assert_eq!(l.switch_to("1.1.0").unwrap().as_deref(), Some("1.1.0"));
        assert_eq!(l.previous().unwrap().as_deref(), Some("1.0.0"));
        let (from, to) = l.swap_back().unwrap();
        assert_eq!((from.as_str(), to.as_str()), ("1.1.0", "1.0.0"));
        assert_eq!(l.current().unwrap().as_deref(), Some("1.0.0"));
        assert_eq!(l.previous().unwrap().as_deref(), Some("1.1.0"));
        // The binaries resolve through the link.
        assert!(t.path().join("current/hx-gatewayd").is_file());
    }

    #[test]
    fn an_incomplete_version_cannot_be_switched_to() {
        let (t, l) = layout();
        install(t.path(), "1.0.0");
        l.switch_to("1.0.0").unwrap();
        std::fs::create_dir(t.path().join("1.1.0")).unwrap();
        assert!(l.switch_to("1.1.0").is_err());
        install(t.path(), "1.2.0");
        std::fs::write(t.path().join("1.2.0/VERSION"), "9.9.9\n").unwrap();
        assert!(l.switch_to("1.2.0").is_err());
        install(t.path(), "1.3.0");
        std::fs::set_permissions(
            t.path().join("1.3.0/hx-privd"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(l.switch_to("1.3.0").is_err());
        install(t.path(), "1.4.0");
        std::fs::remove_file(t.path().join("1.4.0/hx-agent")).unwrap();
        std::os::unix::fs::symlink("/bin/sh", t.path().join("1.4.0/hx-agent")).unwrap();
        assert!(
            l.switch_to("1.4.0").is_err(),
            "a symlinked binary is refused"
        );
        assert_eq!(l.current().unwrap().as_deref(), Some("1.0.0"));
    }

    #[test]
    fn a_reader_never_sees_current_missing_while_it_is_switched() {
        let (t, l) = layout();
        install(t.path(), "1.0.0");
        install(t.path(), "1.1.0");
        l.switch_to("1.0.0").unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reader = {
            let stop = stop.clone();
            let cur = t.path().join("current");
            std::thread::spawn(move || {
                let mut seen = std::collections::BTreeSet::new();
                while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                    let target = std::fs::read_link(&cur).expect("current always exists");
                    seen.insert(target.to_string_lossy().into_owned());
                    assert!(std::fs::metadata(cur.join("hx-gatewayd")).is_ok());
                }
                seen
            })
        };
        for i in 0..300 {
            l.switch_to(if i % 2 == 0 { "1.1.0" } else { "1.0.0" })
                .unwrap();
        }
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let seen = reader.join().unwrap();
        assert!(
            seen.iter().all(|s| s == "1.0.0" || s == "1.1.0"),
            "{seen:?}"
        );
        // No temporary link is left behind.
        let leftovers: Vec<_> = std::fs::read_dir(t.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with('.'))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn a_failed_rename_leaves_the_old_link_and_no_temporary() {
        let (t, l) = layout();
        install(t.path(), "1.0.0");
        l.switch_to("1.0.0").unwrap();
        // `previous` exists as a non-empty directory: the rename over it fails, and `current`
        // must stay where it was.
        install(t.path(), "1.1.0");
        std::fs::create_dir_all(t.path().join("previous/x")).unwrap();
        assert!(l.switch_to("1.1.0").is_err());
        assert_eq!(l.current().unwrap().as_deref(), Some("1.0.0"));
        assert!(
            std::fs::read_dir(t.path())
                .unwrap()
                .filter_map(Result::ok)
                .all(|e| !e.file_name().to_string_lossy().contains(".new-"))
        );
    }

    #[test]
    fn publish_prune_and_the_two_version_rule() {
        let (t, l) = layout();
        for v in ["1.0.0", "1.1.0", "1.2.0"] {
            install(t.path(), v);
        }
        l.switch_to("1.0.0").unwrap();
        l.switch_to("1.1.0").unwrap();
        std::fs::create_dir(t.path().join(".incoming-9.9.9-dead")).unwrap();
        let removed = l.prune(&["1.1.0", "1.0.0"]).unwrap();
        assert_eq!(removed, [".incoming-9.9.9-dead", "1.2.0"]);
        assert!(t.path().join("1.0.0").is_dir() && t.path().join("1.1.0").is_dir());
        // The running version cannot be replaced by a publish.
        let (name, _fd) = l.begin("1.1.0").unwrap();
        assert!(l.publish(&name, "1.1.0").is_err());
        l.discard(&name);
        let (name, fd) = l.begin("1.5.0").unwrap();
        drop(fd);
        l.publish(&name, "1.5.0").unwrap();
        assert!(t.path().join("1.5.0").is_dir());
        let mode = std::fs::metadata(t.path().join("1.5.0"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755);
    }

    #[test]
    fn the_release_directory_must_be_private_to_privd() {
        let (t, l) = layout();
        std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(l.current().is_err());
        std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(l.current().is_ok());
        // A symlinked release directory is not followed.
        let link = t.path().join("elsewhere");
        std::os::unix::fs::symlink(t.path(), &link).unwrap();
        assert!(Layout::new(&link).current().is_err());
    }
}
