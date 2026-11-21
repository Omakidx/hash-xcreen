//! `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)` with a fallback.
//!
//! # Why a fallback
//!
//! `hx-privd.service` and `hx-privd-rescue.service` set `RestrictSUIDSGID=yes`. systemd cannot
//! inspect the mode inside `openat2`'s `struct open_how`, so under that option every `openat2`
//! call answers `ENOSYS` (found by running the units for the first time, in the nested-Incus
//! installer harness: `InstallSession` died with "Function not implemented" and the rescue
//! helper could not restore a release). Dropping the option would give up a real hardening (the
//! root daemon could create set-user-ID files), so the code keeps `openat2` where the kernel
//! offers it and, on `ENOSYS` only, walks the path one component at a time.
//!
//! # Why the walk is as strict
//!
//! Every caller opens a path **below a directory descriptor it holds**, with `O_NOFOLLOW`. The
//! walk refuses what `RESOLVE_BENEATH` refuses (an absolute path, a `..` component), opens each
//! intermediate component with `O_DIRECTORY | O_NOFOLLOW` (so a symlink in the middle fails, like
//! `RESOLVE_NO_SYMLINKS`) and the last one with the caller's flags plus `O_NOFOLLOW`. Nothing is
//! ever resolved through a symlink, so there is no magic link to refuse either. Between two
//! components a racing writer can only swap a component for another entry *inside* the same
//! directory descriptor chain, which is what `openat2` allows as well.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use rustix::fs::{Mode, OFlags, ResolveFlags};
use rustix::io::Errno;

/// Opens `path` below `dir` like `openat2` with `resolve`, falling back to a component walk when
/// the system call answers `ENOSYS`.
pub fn open_beneath(
    dir: impl AsFd,
    path: &str,
    oflags: OFlags,
    mode: Mode,
    resolve: ResolveFlags,
) -> rustix::io::Result<OwnedFd> {
    open_beneath_with(dir.as_fd(), path, oflags, mode, |d, p, o, m| {
        rustix::fs::openat2(d, p, o, m, resolve)
    })
}

/// [`open_beneath`] with the `openat2` call injected (tests make it answer `ENOSYS`).
pub fn open_beneath_with(
    dir: BorrowedFd<'_>,
    path: &str,
    oflags: OFlags,
    mode: Mode,
    openat2: impl Fn(BorrowedFd<'_>, &str, OFlags, Mode) -> rustix::io::Result<OwnedFd>,
) -> rustix::io::Result<OwnedFd> {
    match openat2(dir, path, oflags, mode) {
        Err(Errno::NOSYS) => walk(dir, path, oflags, mode),
        other => other,
    }
}

/// The component walk: no `openat2`, never a symlink followed.
fn walk(
    dir: BorrowedFd<'_>,
    path: &str,
    oflags: OFlags,
    mode: Mode,
) -> rustix::io::Result<OwnedFd> {
    // What RESOLVE_BENEATH answers for an escape is EXDEV.
    if path.is_empty() || path.starts_with('/') {
        return Err(Errno::XDEV);
    }
    let comps: Vec<&str> = path
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect();
    if comps.is_empty() || comps.contains(&"..") {
        return Err(if comps.is_empty() {
            Errno::INVAL
        } else {
            Errno::XDEV
        });
    }
    let mut cur = rustix::io::fcntl_dupfd_cloexec(dir, 0)?;
    let last = comps.len() - 1;
    for (i, c) in comps.iter().enumerate() {
        if i == last {
            return rustix::fs::openat(&cur, *c, oflags | OFlags::NOFOLLOW, mode);
        }
        cur = rustix::fs::openat(
            &cur,
            *c,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
    }
    unreachable!("the loop returns on its last component")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn beneath() -> ResolveFlags {
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS
    }

    fn dirfd(p: &std::path::Path) -> OwnedFd {
        rustix::fs::open(
            p,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }

    fn fixture() -> tempfile::TempDir {
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(t.path().join("a/b")).unwrap();
        std::fs::write(t.path().join("a/b/file"), b"x").unwrap();
        std::fs::write(t.path().join("top"), b"y").unwrap();
        symlink("a", t.path().join("link")).unwrap();
        symlink("top", t.path().join("flink")).unwrap();
        t
    }

    fn ro() -> OFlags {
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC
    }

    /// An `openat2` that answers like a process under `RestrictSUIDSGID=yes`.
    fn enosys(_: BorrowedFd<'_>, _: &str, _: OFlags, _: Mode) -> rustix::io::Result<OwnedFd> {
        Err(Errno::NOSYS)
    }

    #[test]
    fn under_enosys_the_walk_opens_what_openat2_would() {
        let t = fixture();
        let d = dirfd(t.path());
        for p in ["top", "a/b/file", "./a/b/file", "a//b/file"] {
            let fd = open_beneath_with(d.as_fd(), p, ro(), Mode::empty(), enosys)
                .unwrap_or_else(|e| panic!("{p}: {e}"));
            assert!(rustix::fs::fstat(&fd).is_ok());
        }
        assert_eq!(
            open_beneath_with(d.as_fd(), "nope", ro(), Mode::empty(), enosys).unwrap_err(),
            Errno::NOENT
        );
    }

    #[test]
    fn under_enosys_the_walk_refuses_symlinks_dotdot_and_absolute_paths() {
        let t = fixture();
        let d = dirfd(t.path());
        let refuse = |p: &str| {
            open_beneath_with(d.as_fd(), p, ro(), Mode::empty(), enosys)
                .expect_err(&format!("{p} must be refused"))
        };
        // The last component is a symlink: not followed (ELOOP under O_NOFOLLOW).
        assert_eq!(refuse("flink"), Errno::LOOP);
        // A symlink in the middle of the path.
        assert!(matches!(refuse("link/b/file"), Errno::LOOP | Errno::NOTDIR));
        // Escapes.
        assert_eq!(refuse("../x"), Errno::XDEV);
        assert_eq!(refuse("a/../top"), Errno::XDEV);
        assert_eq!(refuse("/etc/passwd"), Errno::XDEV);
        assert!(open_beneath_with(d.as_fd(), "", ro(), Mode::empty(), enosys).is_err());
    }

    #[test]
    fn under_enosys_the_walk_creates_exclusively_with_the_given_mode() {
        let t = fixture();
        let d = dirfd(t.path());
        let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC;
        let fd = open_beneath_with(
            d.as_fd(),
            "a/new",
            flags,
            Mode::from_raw_mode(0o600),
            enosys,
        )
        .unwrap();
        drop(fd);
        let meta = std::fs::metadata(t.path().join("a/new")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(meta.permissions().mode() & 0o7777, 0o600);
        assert_eq!(
            open_beneath_with(
                d.as_fd(),
                "a/new",
                flags,
                Mode::from_raw_mode(0o600),
                enosys
            )
            .unwrap_err(),
            Errno::EXIST
        );
    }

    #[test]
    fn when_openat2_works_it_is_used_and_its_errors_are_not_retried() {
        let t = fixture();
        let d = dirfd(t.path());
        // Real openat2 (kernel 5.6 or newer): same results, and a symlink is refused with ELOOP.
        assert!(open_beneath(&d, "a/b/file", ro(), Mode::empty(), beneath()).is_ok());
        assert!(open_beneath(&d, "link/b/file", ro(), Mode::empty(), beneath()).is_err());
        assert!(open_beneath(&d, "../x", ro(), Mode::empty(), beneath()).is_err());
        // Any other errno from the injected call passes through, with no walk.
        let calls = std::cell::Cell::new(0);
        let r = open_beneath_with(d.as_fd(), "top", ro(), Mode::empty(), |_, _, _, _| {
            calls.set(calls.get() + 1);
            Err(Errno::PERM)
        });
        assert_eq!(r.unwrap_err(), Errno::PERM);
        assert_eq!(calls.get(), 1);
    }
}
