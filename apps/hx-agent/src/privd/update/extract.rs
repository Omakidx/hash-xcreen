//! Safe extraction of a release artifact (ipc.md 6.12 rule 4).
//!
//! The artifact is a `.tar.gz` (gzip through `flate2` with its pure-Rust `miniz_oxide` backend:
//! a root daemon should not decode with a C library, and a signed 40 MB tarball does not need
//! zstd's ratio; the compressed bytes were authenticated by the manifest's SHA-256 **before** this
//! code sees them). privd unpacks it itself, in process, from its staging copy. Nothing is ever
//! handed to `tar(1)`.
//!
//! Every entry is checked, then created **relative to a directory descriptor** with
//! `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS)`, one path component at a
//! time, so a symlink planted by an earlier entry (or a name that resolves through one) cannot
//! redirect a later write. What is refused, each as its own [`Refusal`]:
//!
//! * absolute paths, any `..` component, a NUL in a name, empty, `.` or over-long components,
//!   non-UTF-8 names, more than 24 levels;
//! * a duplicate entry (the same normalised path twice);
//! * **any symlink entry** (the layout has none; a lexical "stays inside" check is not enough,
//!   because two inside-looking links can chain out of the root); a hard link whose target is not
//!   a regular file already extracted (so it cannot name anything outside, nor a symlink);
//! * GNU long-name, long-link and pax headers (names are the 255 bytes of ustar's name and
//!   prefix fields; the archive reader would otherwise read such a header whole into memory);
//! * device nodes, fifos, sockets, sparse files, global pax headers and every other entry type;
//! * a write whose parent path passes through a symlink.
//!
//! Modes are **masked**, not trusted: setuid, setgid and sticky bits are dropped and the result is
//! `0755` for directories and anything executable, `0644` otherwise; every file is owned by the
//! extracting uid (root), whatever the archive says. At most 4 096 entries and 1 GiB of
//! uncompressed data in total (declared sizes are checked before a byte is written, and the
//! decompressed stream is cut off at the limit plus a header allowance, so a decompression bomb
//! stops there).

use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::os::fd::{BorrowedFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rustix::fs::{AtFlags, Mode, OFlags, ResolveFlags};

/// Most entries (files, directories and links together).
pub const MAX_ENTRIES: usize = 4096;
/// Most uncompressed bytes of file data.
pub const MAX_BYTES: u64 = 1024 * 1024 * 1024;
/// Allowance for tar headers and padding on top of [`MAX_BYTES`] in the decompressed stream.
const HEADER_ALLOWANCE: u64 = 16 * 1024 * 1024;
const MAX_DEPTH: usize = 24;
const MAX_PATH: usize = 1024;
const MAX_COMPONENT: usize = 255;

/// Extraction limits (tests lower them).
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Most entries.
    pub max_entries: usize,
    /// Most uncompressed bytes of file data.
    pub max_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: MAX_ENTRIES,
            max_bytes: MAX_BYTES,
        }
    }
}

/// What was refused about an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The path is absolute.
    AbsolutePath,
    /// A `..` component.
    ParentComponent,
    /// A NUL byte in a name or link target.
    NulInName,
    /// Non-UTF-8, empty, `.`, over-long or too deep.
    BadName,
    /// The same path appears twice.
    Duplicate,
    /// A symlink or hard link that leaves the extraction root, or a hard link to something that
    /// is not an already extracted regular file.
    LinkEscapes,
    /// A device node, fifo or socket.
    SpecialFile,
    /// An entry type this extractor does not create (sparse files, global headers, ...).
    UnsupportedType,
    /// The parent path passes through a symlink.
    ThroughSymlink,
    /// A symlink entry (none is allowed).
    SymlinkEntry,
    /// A GNU long-name, long-link or pax header (refused unread).
    LongHeader,
    /// A file where a directory is needed, or the reverse.
    Conflict,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AbsolutePath => "absolute path",
            Self::ParentComponent => "`..` component",
            Self::NulInName => "NUL in a name",
            Self::BadName => "unacceptable name",
            Self::Duplicate => "duplicate entry",
            Self::LinkEscapes => "link leaves the extraction root",
            Self::SpecialFile => "device node, fifo or socket",
            Self::UnsupportedType => "unsupported entry type",
            Self::ThroughSymlink => "path passes through a symlink",
            Self::SymlinkEntry => "symlink entry",
            Self::LongHeader => "long-name or pax header",
            Self::Conflict => "a file and a directory share a path",
        })
    }
}

/// Why extraction stopped.
#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    /// An entry was refused.
    #[error("the archive was refused: {0}")]
    Refused(Refusal),
    /// More entries than allowed.
    #[error("the archive has too many entries")]
    TooManyEntries,
    /// More uncompressed data than allowed.
    #[error("the archive is too large uncompressed")]
    TooLarge,
    /// Not a valid gzip stream or tar archive.
    #[error("the archive is malformed")]
    Malformed,
    /// The caller cancelled.
    #[error("cancelled")]
    Cancelled,
    /// A file system error while creating something.
    #[error("cannot create a file: {0}")]
    Io(#[from] io::Error),
}

/// What an extraction created.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Entries processed.
    pub entries: usize,
    /// Regular files created.
    pub files: usize,
    /// Bytes of file data written.
    pub bytes: u64,
}

/// Caps the decompressed stream and records that the cap was hit.
struct Capped<R> {
    inner: R,
    left: u64,
    hit: Arc<AtomicBool>,
}

impl<R: Read> Read for Capped<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 {
            // Distinguish "the archive ended" from "the archive goes on past the cap".
            let mut one = [0u8; 1];
            return match self.inner.read(&mut one)? {
                0 => Ok(0),
                _ => {
                    self.hit.store(true, Ordering::SeqCst);
                    Err(io::Error::other("decompressed size limit"))
                }
            };
        }
        let max = usize::try_from(self.left).map_or(buf.len(), |l| l.min(buf.len()));
        let n = self.inner.read(&mut buf[..max])?;
        self.left -= n as u64;
        Ok(n)
    }
}

/// Splits a tar path into clean components. An empty result is the root itself.
fn components(raw: &[u8]) -> Result<Vec<String>, Refusal> {
    if raw.contains(&0) {
        return Err(Refusal::NulInName);
    }
    let s = std::str::from_utf8(raw).map_err(|_| Refusal::BadName)?;
    if s.starts_with('/') {
        return Err(Refusal::AbsolutePath);
    }
    let mut s = s;
    while let Some(rest) = s.strip_prefix("./") {
        s = rest;
    }
    let s = s.strip_suffix('/').unwrap_or(s);
    if s.is_empty() || s == "." {
        return Ok(Vec::new());
    }
    if s.len() > MAX_PATH {
        return Err(Refusal::BadName);
    }
    let mut out = Vec::new();
    for c in s.split('/') {
        match c {
            ".." => return Err(Refusal::ParentComponent),
            "" | "." => return Err(Refusal::BadName),
            c if c.len() > MAX_COMPONENT => return Err(Refusal::BadName),
            c => out.push(c.to_string()),
        }
    }
    if out.len() > MAX_DEPTH {
        return Err(Refusal::BadName);
    }
    Ok(out)
}

fn resolve_flags() -> ResolveFlags {
    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS
}

fn dir_oflags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

/// Opens (creating, with mode 0755) the directory `comps` below `root`, one component at a time.
fn open_dir(root: BorrowedFd<'_>, comps: &[String], create: bool) -> Result<OwnedFd, ExtractError> {
    let mut cur = rustix::io::fcntl_dupfd_cloexec(root, 0).map_err(io::Error::from)?;
    for c in comps {
        let open = |fd: &OwnedFd| {
            super::beneath::open_beneath(
                fd,
                c.as_str(),
                dir_oflags(),
                Mode::empty(),
                resolve_flags(),
            )
        };
        cur = match open(&cur) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) if create => {
                rustix::fs::mkdirat(&cur, c.as_str(), Mode::from_raw_mode(0o700))
                    .map_err(io::Error::from)?;
                let fd = open(&cur).map_err(io::Error::from)?;
                // The daemon's umask is 077; the tree must be readable by the services.
                rustix::fs::fchmod(&fd, Mode::from_raw_mode(0o755)).map_err(io::Error::from)?;
                fd
            }
            Err(rustix::io::Errno::LOOP) => {
                return Err(ExtractError::Refused(Refusal::ThroughSymlink));
            }
            // `O_DIRECTORY|O_NOFOLLOW` on a symlink says ENOTDIR, like a plain file does: look.
            Err(rustix::io::Errno::NOTDIR) => {
                let is_link = rustix::fs::statat(&cur, c.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                    .is_ok_and(|st| {
                        rustix::fs::FileType::from_raw_mode(st.st_mode)
                            == rustix::fs::FileType::Symlink
                    });
                return Err(ExtractError::Refused(if is_link {
                    Refusal::ThroughSymlink
                } else {
                    Refusal::Conflict
                }));
            }
            Err(e) => return Err(io::Error::from(e).into()),
        };
    }
    Ok(cur)
}

fn masked_mode(header_mode: u32, dir: bool) -> u32 {
    if dir || header_mode & 0o111 != 0 {
        0o755
    } else {
        0o644
    }
}

fn map_stream_error(e: &io::Error, hit: &AtomicBool) -> ExtractError {
    if hit.load(Ordering::SeqCst) {
        ExtractError::TooLarge
    } else {
        let _ = e;
        ExtractError::Malformed
    }
}

/// Extracts a gzip-compressed tar stream into the directory `root` (an empty directory the caller
/// created). `cancelled` is polled between entries and between 64 KiB writes.
pub fn extract_tar_gz(
    archive: impl Read,
    root: BorrowedFd<'_>,
    limits: &Limits,
    cancelled: &dyn Fn() -> bool,
) -> Result<Stats, ExtractError> {
    let hit = Arc::new(AtomicBool::new(false));
    let stream = Capped {
        inner: flate2::read::GzDecoder::new(archive),
        left: limits.max_bytes.saturating_add(HEADER_ALLOWANCE),
        hit: hit.clone(),
    };
    let mut ar = tar::Archive::new(stream);
    // Raw: the reader does no preprocessing, so a long-name or pax header comes back as an entry
    // that is refused below without its body being read into memory.
    let entries = ar
        .entries()
        .map_err(|e| map_stream_error(&e, &hit))?
        .raw(true);
    let mut seen: HashSet<Vec<String>> = HashSet::new();
    let mut regular: HashSet<Vec<String>> = HashSet::new();
    let mut stats = Stats::default();
    let mut buf = vec![0u8; 64 * 1024];
    for entry in entries {
        if cancelled() {
            return Err(ExtractError::Cancelled);
        }
        let mut entry = entry.map_err(|e| map_stream_error(&e, &hit))?;
        stats.entries += 1;
        if stats.entries > limits.max_entries {
            return Err(ExtractError::TooManyEntries);
        }
        let kind = entry.header().entry_type();
        if kind.is_gnu_longname()
            || kind.is_gnu_longlink()
            || kind.is_pax_local_extensions()
            || kind.is_pax_global_extensions()
        {
            return Err(ExtractError::Refused(Refusal::LongHeader));
        }
        let comps = components(&entry.path_bytes()).map_err(ExtractError::Refused)?;
        let mode = entry.header().mode().unwrap_or(0o644);
        // The root itself ("./") is a no-op; any other path may appear once only.
        if comps.is_empty() {
            if kind.is_dir() {
                continue;
            }
            return Err(ExtractError::Refused(Refusal::BadName));
        }
        if !seen.insert(comps.clone()) {
            return Err(ExtractError::Refused(Refusal::Duplicate));
        }
        let Some((name, parents)) = comps.split_last() else {
            return Err(ExtractError::Refused(Refusal::BadName));
        };
        let name = name.as_str();
        match kind {
            t if t.is_dir() => {
                let dir = open_dir(root, &comps, true)?;
                rustix::fs::fchmod(&dir, Mode::from_raw_mode(masked_mode(mode, true)))
                    .map_err(io::Error::from)?;
            }
            t if t.is_file() => {
                let size = entry.size();
                stats.bytes = stats.bytes.saturating_add(size);
                if stats.bytes > limits.max_bytes {
                    return Err(ExtractError::TooLarge);
                }
                let parent = open_dir(root, parents, true)?;
                let fd = super::beneath::open_beneath(
                    &parent,
                    name,
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o600),
                    resolve_flags(),
                )
                .map_err(|e| match e {
                    rustix::io::Errno::EXIST => ExtractError::Refused(Refusal::Conflict),
                    rustix::io::Errno::LOOP => ExtractError::Refused(Refusal::ThroughSymlink),
                    e => io::Error::from(e).into(),
                })?;
                let mut out = std::fs::File::from(fd);
                let mut left = size;
                while left > 0 {
                    if cancelled() {
                        return Err(ExtractError::Cancelled);
                    }
                    let want = usize::try_from(left).map_or(buf.len(), |l| l.min(buf.len()));
                    let n = entry
                        .read(&mut buf[..want])
                        .map_err(|e| map_stream_error(&e, &hit))?;
                    if n == 0 {
                        return Err(ExtractError::Malformed);
                    }
                    out.write_all(&buf[..n])?;
                    left -= n as u64;
                }
                rustix::fs::fchmod(&out, Mode::from_raw_mode(masked_mode(mode, false)))
                    .map_err(io::Error::from)?;
                regular.insert(comps.clone());
                stats.files += 1;
            }
            t if t.is_symlink() => return Err(ExtractError::Refused(Refusal::SymlinkEntry)),
            t if t.is_hard_link() => {
                let target = entry
                    .link_name_bytes()
                    .ok_or(ExtractError::Refused(Refusal::LinkEscapes))?;
                let tcomps = components(&target).map_err(|r| {
                    ExtractError::Refused(match r {
                        Refusal::NulInName => Refusal::NulInName,
                        _ => Refusal::LinkEscapes,
                    })
                })?;
                if !regular.contains(&tcomps) {
                    return Err(ExtractError::Refused(Refusal::LinkEscapes));
                }
                let Some((tname, tparents)) = tcomps.split_last() else {
                    return Err(ExtractError::Refused(Refusal::LinkEscapes));
                };
                let tparent = open_dir(root, tparents, false)?;
                let parent = open_dir(root, parents, true)?;
                rustix::fs::linkat(&tparent, tname.as_str(), &parent, name, AtFlags::empty())
                    .map_err(|e| match e {
                        rustix::io::Errno::EXIST => ExtractError::Refused(Refusal::Conflict),
                        e => io::Error::from(e).into(),
                    })?;
                regular.insert(comps.clone());
            }
            t if t.is_character_special() || t.is_block_special() || t.is_fifo() => {
                return Err(ExtractError::Refused(Refusal::SpecialFile));
            }
            t if t.as_byte() == b's' => {
                return Err(ExtractError::Refused(Refusal::SpecialFile));
            }
            _ => return Err(ExtractError::Refused(Refusal::UnsupportedType)),
        }
    }
    // One flush for the whole tree (not an fsync per file) before the caller switches to it.
    rustix::fs::syncfs(root).map_err(io::Error::from)?;
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn comps(s: &str) -> Result<Vec<String>, Refusal> {
        components(s.as_bytes())
    }

    #[test]
    fn names_are_normalised_or_refused() {
        assert_eq!(comps("a/b/c").unwrap(), ["a", "b", "c"]);
        assert_eq!(comps("./a/b/").unwrap(), ["a", "b"]);
        assert_eq!(comps("././a").unwrap(), ["a"]);
        assert!(comps("./").unwrap().is_empty());
        assert!(comps(".").unwrap().is_empty());
        assert_eq!(comps("/etc/passwd"), Err(Refusal::AbsolutePath));
        assert_eq!(comps("../x"), Err(Refusal::ParentComponent));
        assert_eq!(comps("a/../x"), Err(Refusal::ParentComponent));
        assert_eq!(comps("./../x"), Err(Refusal::ParentComponent));
        assert_eq!(comps("a//b"), Err(Refusal::BadName));
        assert_eq!(comps("a/./b"), Err(Refusal::BadName));
        assert_eq!(comps(&"x".repeat(256)), Err(Refusal::BadName));
        assert_eq!(comps(&"a/".repeat(25)), Err(Refusal::BadName));
        assert_eq!(components(b"a\0b"), Err(Refusal::NulInName));
        assert_eq!(components(b"a\xffb"), Err(Refusal::BadName));
    }

    #[test]
    fn modes_are_masked() {
        assert_eq!(masked_mode(0o4755, false), 0o755);
        assert_eq!(masked_mode(0o2644, false), 0o644);
        assert_eq!(masked_mode(0o1777, true), 0o755);
        assert_eq!(masked_mode(0o666, false), 0o644);
        assert_eq!(masked_mode(0o700, false), 0o755);
    }
}
