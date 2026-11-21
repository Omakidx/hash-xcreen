//! Clipboard policy for the session: what may cross, how it is validated, and the interface
//! the session link plugs the network side into.
//!
//! The X11 mechanics live in [`hx_capture::clipboard`]; this module adds the rules from the
//! protocol (limits, MIME and file-name validation, text must be UTF-8, images must be PNG)
//! and models files as a **transfer list**:
//!
//! * **Local to client.** A local application takes the clipboard: the link gets a
//!   [`ClipboardEvent::LocalOffer`] with the formats. When the client wants one, the link
//!   calls [`ClipboardManager::read_text`], [`ClipboardManager::read_image`] or
//!   [`ClipboardManager::read_files`]. Files come back as a [`TransferList`]: validated
//!   names and sizes, and [`FileEntry::open`] for the link to stream each one as its own
//!   file transfer (protocol 5.5). Nothing is read before the client asks.
//! * **Client to local.** The link receives an offer from the client and calls
//!   [`ClipboardManager::offer`] with a [`ClientOffer`] and a [`ClientSource`] that fetches
//!   the bytes over the clipboard and file channels *when a local application pastes*. For
//!   files the source downloads into a [`StagingDir`] (paths chosen by the session, never
//!   taken from the wire) and the paste hands the application `file://` URIs of those paths.
//!
//! Everything that arrives from the client is untrusted: formats, names, sizes and bytes
//! are checked here before they reach an X application.

use hx_capture::clipboard::{
    Clipboard, ClipboardConfig, ClipboardError, MIME_PNG, MIME_TEXT, MIME_URI_LIST, RemoteProvider,
    Selection,
};
use hx_proto::channel::MAX_CLIPBOARD_SIZE;
use hx_proto::message::{file_name_problem, mime_problem};
use rustix::fs::{Mode, OFlags, open};
use std::fs::{DirBuilder, File};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Duration;
use thiserror::Error;

pub use hx_capture::clipboard::{ClipboardEvent, Selection as ClipSelection};

/// Files in one offer.
pub const MAX_FILES: usize = 1000;
/// Total bytes in one file offer (the protocol sets no limit for files; this bounds disk
/// use in the staging directory).
pub const MAX_FILE_BYTES_TOTAL: u64 = 16 * 1024 * 1024 * 1024;
const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";

#[derive(Debug, Error)]
pub enum ClipboardPolicyError {
    #[error("clipboard sharing is switched off for this device")]
    Disabled,
    #[error("clipboard: {0}")]
    Engine(#[from] ClipboardError),
    #[error("invalid {what}: {reason}")]
    Invalid { what: &'static str, reason: String },
    #[error("staging directory: {0}")]
    Staging(#[from] std::io::Error),
}

fn invalid(what: &'static str, reason: impl Into<String>) -> ClipboardPolicyError {
    ClipboardPolicyError::Invalid {
        what,
        reason: reason.into(),
    }
}

#[derive(Clone, Debug)]
pub struct ClipboardSettings {
    /// The per-device switch. Off: no X connection is made and every call refuses.
    pub enabled: bool,
    /// Also share PRIMARY (select-to-copy). Off by default.
    pub primary: bool,
    pub display: Option<String>,
    /// The directory under which each manager makes a staging directory of its own for pasted
    /// client files. It must exist, be owned by this user and not be a symlink; there is no
    /// fallback (not `$XDG_RUNTIME_DIR`, which `ProtectSystem=strict` makes read-only, and not
    /// the shared temp dir): `None` makes [`ClipboardManager::start`] fail.
    pub staging_base: Option<PathBuf>,
    pub step_timeout: Duration,
}

impl Default for ClipboardSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            primary: false,
            display: None,
            staging_base: None,
            step_timeout: Duration::from_secs(5),
        }
    }
}

/// A file the client already sent: it is in the received-files directory under `name`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedEntry {
    /// The name the file was given in the directory (the session's choice, not the wire's).
    pub name: String,
    pub size: u64,
}

/// A file the client offers: only a display name and a size; contents arrive later.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteFile {
    pub name: String,
    pub size: u64,
}

/// What the client says it has on its clipboard.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientOffer {
    /// MIME types: [`MIME_TEXT`] and [`MIME_PNG`] are accepted; others are ignored.
    pub formats: Vec<String>,
    /// Files, offered as [`MIME_URI_LIST`] to local applications.
    pub files: Vec<RemoteFile>,
}

#[derive(Debug, Error)]
#[error("{0}")]
pub struct SourceError(pub String);

/// The network side of a client offer, implemented by the session link.
///
/// Called on the clipboard worker thread when a local application pastes, so it blocks
/// that paste (and nothing else) until it returns: it must use its own timeout and fail
/// rather than wait forever.
pub trait ClientSource: Send + Sync {
    /// The bytes of a clipboard format (text or PNG), at most `max` bytes.
    fn fetch(&self, mime: &str, max: u64) -> Result<Vec<u8>, SourceError>;
    /// Download `files` (in order) into paths allocated with [`StagingDir::alloc`] and
    /// return those paths, one per file.
    fn stage_files(
        &self,
        files: &[RemoteFile],
        staging: &StagingDir,
    ) -> Result<Vec<PathBuf>, SourceError>;
}

/// A directory the session owns for pasted files. Names on the wire are hints only: every
/// path is chosen here and stays inside it.
#[derive(Debug)]
pub struct StagingDir {
    root: PathBuf,
    generation: AtomicU64,
    next: AtomicU64,
}

/// Staging directories made by this process so far (the name of the next one).
static STAGING_SEQ: AtomicU64 = AtomicU64::new(0);
const STAGING_PREFIX: &str = "clip-";

fn staging_err(why: &str) -> std::io::Error {
    std::io::Error::other(why.to_owned())
}

impl StagingDir {
    /// Creates a staging directory of its own under `base`: `<base>/clip-<pid>-<n>`, mode 0700,
    /// created with `mkdir` (so an existing path, a symlink included, is refused, never reused)
    /// and checked to be owned by this user. `base` must be an existing directory that is not a
    /// symlink, owned by this user and not world-writable. Directories left by
    /// processes that no longer run are removed; a live manager's directory is never touched
    /// by another.
    pub fn create(base: &Path) -> std::io::Result<Self> {
        let me = rustix::process::geteuid().as_raw();
        let md = std::fs::symlink_metadata(base)?;
        if md.file_type().is_symlink() || !md.is_dir() {
            return Err(staging_err("the staging base is not a plain directory"));
        }
        if md.uid() != me || md.mode() & 0o002 != 0 {
            return Err(staging_err(
                "the staging base is not owned by this user or is world-writable",
            ));
        }
        sweep_stale(base);
        let root = base.join(format!(
            "{STAGING_PREFIX}{}-{}",
            std::process::id(),
            STAGING_SEQ.fetch_add(1, Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&root)?;
        let md = std::fs::symlink_metadata(&root)?;
        if md.file_type().is_symlink() || md.uid() != me {
            let _ = std::fs::remove_dir(&root);
            return Err(staging_err("the staging directory is not ours"));
        }
        Ok(Self {
            root,
            generation: AtomicU64::new(0),
            next: AtomicU64::new(0),
        })
    }

    pub fn path(&self) -> &Path {
        &self.root
    }

    /// A fresh path for a file whose announced name is `hint`. The directory holding it is
    /// created (mode 0700); the file is not. Only the sanitised final component of the hint
    /// is used, for the user's benefit when the application shows the name.
    pub fn alloc(&self, hint: &str) -> std::io::Result<PathBuf> {
        let dir = self.root.join(format!(
            "{}-{}",
            self.generation.load(Relaxed),
            self.next.fetch_add(1, Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&dir)?;
        Ok(dir.join(safe_name(hint)))
    }

    /// Delete everything staged so far and start a new generation.
    pub fn clear(&self) {
        self.generation.fetch_add(1, Relaxed);
        if let Ok(rd) = std::fs::read_dir(&self.root) {
            for e in rd.flatten() {
                let p = e.path();
                let _ = std::fs::remove_dir_all(&p).or_else(|_| std::fs::remove_file(&p));
            }
        }
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Removes `clip-<pid>-<n>` directories of other processes that are gone (a crash leaves them).
/// Only plain directories owned by this user are touched; the pid of a live process never is.
fn sweep_stale(base: &Path) {
    let me = rustix::process::geteuid().as_raw();
    let Ok(rd) = std::fs::read_dir(base) else {
        return;
    };
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(pid) = name
            .to_str()
            .and_then(|n| n.strip_prefix(STAGING_PREFIX))
            .and_then(|n| n.split('-').next())
            .and_then(|p| p.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == std::process::id() || Path::new("/proc").join(pid.to_string()).exists() {
            continue;
        }
        let path = e.path();
        if let Ok(md) = std::fs::symlink_metadata(&path)
            && md.is_dir()
            && md.uid() == me
        {
            let _ = std::fs::remove_dir_all(&path);
        }
    }
}

/// A name that is safe to create: validated like on the wire, otherwise replaced.
fn safe_name(hint: &str) -> String {
    let base = hint.rsplit(['/', '\\']).next().unwrap_or("");
    if !base.is_empty() && base.len() <= 255 && file_name_problem(base).is_none() {
        return base.to_owned();
    }
    let cleaned: String = base
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, ':' | '/' | '\\') {
                '_'
            } else {
                c
            }
        })
        .take(100)
        .collect();
    let cleaned = cleaned.trim_end_matches(['.', ' ']);
    if !cleaned.is_empty() && file_name_problem(cleaned).is_none() {
        cleaned.to_owned()
    } else {
        "file".to_owned()
    }
}

/// A local file offered to the client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileEntry {
    /// Canonical absolute path.
    pub path: PathBuf,
    /// The display name for the transfer header (validated).
    pub name: String,
    pub size: u64,
}

impl FileEntry {
    /// Open for streaming. Refuses anything that is no longer the regular file listed
    /// (replaced by a symlink, resized, no longer readable).
    pub fn open(&self) -> std::io::Result<File> {
        let fd = open(
            &self.path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )?;
        let file = File::from(fd);
        let md = file.metadata()?;
        if !md.is_file() || md.len() != self.size {
            return Err(std::io::Error::other(
                "the file changed since it was listed",
            ));
        }
        Ok(file)
    }
}

/// Why a URI from a local application was not offered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skipped {
    pub uri: String,
    pub reason: &'static str,
}

/// The files of a local clipboard, as a transfer list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransferList {
    pub files: Vec<FileEntry>,
    pub skipped: Vec<Skipped>,
}

impl TransferList {
    pub fn total_bytes(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }
}

/// Parse and validate a `text/uri-list`.
pub fn transfer_list_from_uri_list(list: &[u8]) -> TransferList {
    let mut out = TransferList::default();
    let text = String::from_utf8_lossy(list);
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if out.files.len() >= MAX_FILES {
            out.skipped.push(Skipped {
                uri: truncate(line),
                reason: "too many files",
            });
            continue;
        }
        match entry_from_uri(line) {
            Ok(f) => {
                if out.total_bytes().saturating_add(f.size) > MAX_FILE_BYTES_TOTAL {
                    out.skipped.push(Skipped {
                        uri: truncate(line),
                        reason: "offer too large",
                    });
                } else {
                    out.files.push(f);
                }
            }
            Err(reason) => out.skipped.push(Skipped {
                uri: truncate(line),
                reason,
            }),
        }
    }
    out
}

fn truncate(s: &str) -> String {
    s.chars().take(200).collect()
}

fn entry_from_uri(uri: &str) -> Result<FileEntry, &'static str> {
    let rest = uri.strip_prefix("file://").ok_or("not a file: URI")?;
    // file://host/path: only the local host is acceptable.
    let path = match rest.split_once('/') {
        Some(("" | "localhost", p)) => format!("/{p}"),
        _ => return Err("not a local file"),
    };
    let bytes = percent_decode(&path).ok_or("bad percent-encoding")?;
    if bytes.contains(&0) {
        return Err("contains a NUL");
    }
    let path = PathBuf::from(std::ffi::OsString::from(
        String::from_utf8(bytes).map_err(|_| "not UTF-8")?,
    ));
    let path = std::fs::canonicalize(&path).map_err(|_| "cannot be read")?;
    let md = std::fs::metadata(&path).map_err(|_| "cannot be read")?;
    if md.is_dir() {
        return Err("directories are not supported");
    }
    if !md.is_file() {
        return Err("not a regular file");
    }
    // The display name must pass the same rule as on the wire; the file stays reachable
    // by its real path regardless.
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("name is not UTF-8")?
        .to_owned();
    if name.len() > 255 {
        return Err("name too long");
    }
    if file_name_problem(&name).is_some() {
        return Err("name not allowed");
    }
    Ok(FileEntry {
        path,
        name,
        size: md.size(),
    })
}

fn percent_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Some(out)
}

fn percent_encode_path(p: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    let mut s = String::from("file://");
    for &c in p.as_os_str().as_bytes() {
        if c.is_ascii_alphanumeric() || b"/-_.~".contains(&c) {
            s.push(char::from(c));
        } else {
            s.push_str(&format!("%{c:02X}"));
        }
    }
    s
}

/// Bridges a [`ClientSource`] to the X side.
struct Provider {
    offer: ClientOffer,
    source: Arc<dyn ClientSource>,
    staging: Arc<StagingDir>,
    /// A second directory whose files may be handed to applications: the received-files
    /// directory, for files the client sent before anything was pasted.
    trusted_root: Option<PathBuf>,
}

impl Provider {
    fn inside(&self, canonical: &Path) -> bool {
        canonical.starts_with(self.staging.path())
            || self
                .trusted_root
                .as_deref()
                .is_some_and(|r| canonical.starts_with(r))
    }
}

/// Files that were already received: pasting hands out their paths in the received directory.
struct ReceivedFiles {
    paths: Vec<PathBuf>,
}

impl ClientSource for ReceivedFiles {
    fn fetch(&self, _mime: &str, _max: u64) -> Result<Vec<u8>, SourceError> {
        Err(SourceError("only files are offered".into()))
    }

    fn stage_files(
        &self,
        files: &[RemoteFile],
        _staging: &StagingDir,
    ) -> Result<Vec<PathBuf>, SourceError> {
        if files.len() != self.paths.len() {
            return Err(SourceError("the offer changed".into()));
        }
        // Each must still be the regular file that was received (not replaced by a link).
        for (p, f) in self.paths.iter().zip(files) {
            let md = std::fs::symlink_metadata(p)
                .map_err(|_| SourceError("a received file is gone".into()))?;
            if !md.is_file() || md.len() != f.size {
                return Err(SourceError("a received file changed".into()));
            }
        }
        Ok(self.paths.clone())
    }
}

impl RemoteProvider for Provider {
    fn fetch(&self, mime: &str, max: u64) -> Option<Vec<u8>> {
        let max = max.min(MAX_CLIPBOARD_SIZE);
        match mime {
            MIME_TEXT => {
                let data = self.source.fetch(MIME_TEXT, max).ok()?;
                if data.len() as u64 > max {
                    return None;
                }
                // Text must be UTF-8 and free of NUL; bad bytes are replaced, not trusted.
                let s = String::from_utf8_lossy(&data).replace('\0', "");
                Some(s.into_bytes())
            }
            MIME_PNG => {
                let data = self.source.fetch(MIME_PNG, max).ok()?;
                (data.len() as u64 <= max && data.starts_with(PNG_SIGNATURE)).then_some(data)
            }
            MIME_URI_LIST => {
                let paths = self
                    .source
                    .stage_files(&self.offer.files, &self.staging)
                    .ok()?;
                if paths.len() != self.offer.files.len() {
                    return None;
                }
                let mut out = String::new();
                for p in paths {
                    // Only paths inside our own directories may be handed to applications.
                    let inside = std::fs::canonicalize(&p)
                        .ok()
                        .is_some_and(|c| self.inside(&c));
                    if !inside {
                        return None;
                    }
                    out.push_str(&percent_encode_path(&std::fs::canonicalize(&p).ok()?));
                    out.push_str("\r\n");
                }
                Some(out.into_bytes())
            }
            _ => None,
        }
    }
}

/// Clipboard sharing for one session.
pub struct ClipboardManager {
    engine: Option<Clipboard>,
    staging: Option<Arc<StagingDir>>,
}

impl ClipboardManager {
    pub fn start(settings: ClipboardSettings) -> Result<Self, ClipboardPolicyError> {
        if !settings.enabled {
            return Ok(Self {
                engine: None,
                staging: None,
            });
        }
        let base = settings
            .staging_base
            .clone()
            .ok_or_else(|| staging_err("no staging directory is configured"))?;
        let staging = Arc::new(StagingDir::create(&base)?);
        let engine = Clipboard::start(ClipboardConfig {
            display: settings.display,
            primary: settings.primary,
            max_bytes: MAX_CLIPBOARD_SIZE,
            step_timeout: settings.step_timeout,
            provider_timeout: settings.step_timeout,
        })?;
        Ok(Self {
            engine: Some(engine),
            staging: Some(staging),
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.engine.is_some()
    }

    fn engine(&self) -> Result<&Clipboard, ClipboardPolicyError> {
        self.engine.as_ref().ok_or(ClipboardPolicyError::Disabled)
    }

    /// Offers and ownership changes of the local clipboard. A disabled manager has no
    /// events (the receiver is always empty and disconnected).
    pub fn events(&self) -> crossbeam_channel::Receiver<ClipboardEvent> {
        match &self.engine {
            Some(e) => e.events().clone(),
            None => crossbeam_channel::never(),
        }
    }

    /// The local text, as UTF-8 (invalid sequences replaced, NUL removed).
    pub fn read_text(&self, selection: Selection) -> Result<String, ClipboardPolicyError> {
        let raw = self.engine()?.fetch_local(selection, MIME_TEXT)?;
        Ok(String::from_utf8_lossy(&raw).replace('\0', ""))
    }

    /// The local image as PNG bytes. Anything that is not a PNG is refused.
    pub fn read_image(&self, selection: Selection) -> Result<Vec<u8>, ClipboardPolicyError> {
        let raw = self.engine()?.fetch_local(selection, MIME_PNG)?;
        if !raw.starts_with(PNG_SIGNATURE) {
            return Err(invalid("image", "not a PNG"));
        }
        Ok(raw)
    }

    /// The local files as a transfer list.
    pub fn read_files(&self, selection: Selection) -> Result<TransferList, ClipboardPolicyError> {
        let raw = self.engine()?.fetch_local(selection, MIME_URI_LIST)?;
        Ok(transfer_list_from_uri_list(&raw))
    }

    /// Make the client the owner of the clipboard. Returns the formats actually offered.
    pub fn offer(
        &self,
        selection: Selection,
        offer: ClientOffer,
        source: Arc<dyn ClientSource>,
    ) -> Result<Vec<String>, ClipboardPolicyError> {
        let engine = self.engine()?;
        let staging = self.staging.clone().ok_or(ClipboardPolicyError::Disabled)?;
        let mut formats = Vec::new();
        for f in &offer.formats {
            if mime_problem(f).is_some() {
                return Err(invalid("format", format!("{f:?} is not a media type")));
            }
            let essence = f.split(';').next().unwrap_or("").trim();
            let canonical = match essence.to_ascii_lowercase().as_str() {
                "text/plain" => MIME_TEXT,
                "image/png" => MIME_PNG,
                _ => continue, // unsupported formats are ignored, not an error
            };
            if !formats.iter().any(|x| x == canonical) {
                formats.push(canonical.to_owned());
            }
        }
        if !offer.files.is_empty() {
            if offer.files.len() > MAX_FILES {
                return Err(invalid("files", "too many files"));
            }
            let mut total = 0u64;
            for f in &offer.files {
                if f.name.len() > 255 {
                    return Err(invalid("file name", "longer than 255 bytes"));
                }
                if let Some(reason) = file_name_problem(&f.name) {
                    return Err(invalid("file name", reason));
                }
                total = total.saturating_add(f.size);
            }
            if total > MAX_FILE_BYTES_TOTAL {
                return Err(invalid("files", "offer too large"));
            }
            formats.push(MIME_URI_LIST.to_owned());
        }
        if formats.is_empty() {
            return Err(invalid("offer", "no format this session can serve"));
        }
        // A new offer replaces the old one: drop the files staged for it.
        staging.clear();
        engine.offer_remote(
            selection,
            formats.clone(),
            Arc::new(Provider {
                offer,
                source,
                staging,
                trusted_root: None,
            }),
        )?;
        Ok(formats)
    }

    /// Offers files the client already sent as a file-list clipboard (`text/uri-list`, and the
    /// GNOME/XFCE copied-files target the engine derives from it), pointing into `root`, the
    /// received-files directory: a user can paste them in the file manager. The names are the
    /// ones the files have in `root`. Replaces the current offer.
    pub fn offer_received_files(
        &self,
        selection: Selection,
        root: &Path,
        files: &[ReceivedEntry],
    ) -> Result<(), ClipboardPolicyError> {
        let engine = self.engine()?;
        let staging = self.staging.clone().ok_or(ClipboardPolicyError::Disabled)?;
        if files.is_empty() || files.len() > MAX_FILES {
            return Err(invalid("files", "no files, or too many"));
        }
        let root = std::fs::canonicalize(root)?;
        let mut remote = Vec::with_capacity(files.len());
        let mut paths = Vec::with_capacity(files.len());
        for f in files {
            if f.name.is_empty() || f.name.contains(['/', '\\', '\0']) || f.name.len() > 255 {
                return Err(invalid("file name", "not a plain name"));
            }
            if let Some(reason) = file_name_problem(&f.name) {
                return Err(invalid("file name", reason));
            }
            paths.push(root.join(&f.name));
            remote.push(RemoteFile {
                name: f.name.clone(),
                size: f.size,
            });
        }
        staging.clear();
        engine.offer_remote(
            selection,
            vec![MIME_URI_LIST.to_owned()],
            Arc::new(Provider {
                offer: ClientOffer {
                    formats: Vec::new(),
                    files: remote,
                },
                source: Arc::new(ReceivedFiles { paths }),
                staging,
                trusted_root: Some(root),
            }),
        )?;
        Ok(())
    }

    /// The client's clipboard is gone (or the client disconnected): stop offering it and
    /// delete staged files.
    pub fn withdraw(&self, selection: Selection) -> Result<(), ClipboardPolicyError> {
        self.engine()?.clear_remote(selection)?;
        if let Some(s) = &self.staging {
            s.clear();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_round_trip() {
        assert_eq!(
            percent_decode("/a%20b%C3%A9").unwrap(),
            "/a b\u{e9}".as_bytes()
        );
        assert!(percent_decode("/a%2").is_none());
        assert!(percent_decode("/a%zz").is_none());
        let p = Path::new("/tmp/a b/\u{e9}#.txt");
        let uri = percent_encode_path(p);
        assert_eq!(uri, "file:///tmp/a%20b/%C3%A9%23.txt");
        assert_eq!(
            percent_decode(uri.strip_prefix("file://").unwrap()).unwrap(),
            p.to_str().unwrap().as_bytes()
        );
    }

    #[test]
    fn uris_that_are_not_local_files_are_skipped() {
        for (uri, why) in [
            ("http://example.com/a", "not a file: URI"),
            ("file://otherhost/etc/passwd", "not a local file"),
            ("file:///etc/%00passwd", "contains a NUL"),
            ("file:///etc/%zz", "bad percent-encoding"),
            ("file:///definitely/not/here", "cannot be read"),
            ("file:///", "directories are not supported"),
        ] {
            assert_eq!(entry_from_uri(uri).unwrap_err(), why, "{uri}");
        }
    }

    #[test]
    fn safe_names_never_escape() {
        assert_eq!(safe_name("report.pdf"), "report.pdf");
        assert_eq!(safe_name("../../etc/passwd"), "passwd");
        assert_eq!(safe_name("a\\b\\c.txt"), "c.txt");
        assert_eq!(safe_name(".."), "file");
        assert_eq!(safe_name(""), "file");
        assert_eq!(safe_name("CON"), "file");
        assert_eq!(safe_name("bad:name"), "bad_name");
        assert_eq!(safe_name("trailing."), "trailing");
        assert!(safe_name(&"x".repeat(1000)).len() <= 255);
    }

    #[test]
    fn staging_allocates_inside_and_clears() {
        let base = std::env::temp_dir().join(format!("hx-stage-test-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        {
            let s = StagingDir::create(&base).unwrap();
            let a = s.alloc("../../x.txt").unwrap();
            let b = s.alloc("x.txt").unwrap();
            assert_ne!(a, b);
            assert!(a.starts_with(s.path()) && b.starts_with(s.path()));
            assert_eq!(a.file_name().unwrap(), "x.txt");
            std::fs::write(&a, b"hi").unwrap();
            s.clear();
            assert!(!a.exists());
            assert!(s.alloc("y").unwrap().starts_with(s.path()));
        }
        std::fs::remove_dir_all(&base).unwrap();
    }

    fn base(tag: &str) -> PathBuf {
        let b = std::env::temp_dir().join(format!("hx-stage-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&b);
        std::fs::create_dir_all(&b).unwrap();
        b
    }

    #[test]
    fn every_manager_gets_a_staging_directory_of_its_own_and_never_removes_another() {
        let b = base("own");
        let one = StagingDir::create(&b).unwrap();
        let two = StagingDir::create(&b).unwrap();
        assert_ne!(one.path(), two.path());
        assert!(one.path().starts_with(&b) && two.path().starts_with(&b));
        let mode = std::fs::metadata(one.path()).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o700);
        let staged = two.alloc("f.txt").unwrap();
        std::fs::write(&staged, b"x").unwrap();
        // An older manager going away (a superseded link) leaves the newer one's files alone.
        drop(one);
        assert!(staged.exists());
        drop(two);
        assert!(!staged.exists());
        let _ = std::fs::remove_dir_all(&b);
    }

    #[test]
    fn the_staging_base_is_checked_and_there_is_no_fallback() {
        use std::os::unix::fs::PermissionsExt;
        let b = base("sym");
        // Missing.
        assert!(StagingDir::create(&b.join("missing")).is_err());
        // A symlink.
        let link = b.join("link");
        std::os::unix::fs::symlink(&b, &link).unwrap();
        assert!(StagingDir::create(&link).is_err());
        // Writable by others.
        let open = b.join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(StagingDir::create(&open).is_err());
        // Read-only (what ProtectSystem=strict makes of /run/user/<uid>): fails.
        let ro = b.join("ro");
        std::fs::create_dir(&ro).unwrap();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o500)).unwrap();
        if rustix::process::geteuid().as_raw() != 0 {
            assert!(StagingDir::create(&ro).is_err());
        }
        // No base configured: the manager does not start (nothing falls back to the temp dir).
        let r = ClipboardManager::start(ClipboardSettings {
            staging_base: None,
            ..ClipboardSettings::default()
        });
        assert!(matches!(r, Err(ClipboardPolicyError::Staging(_))));
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o700)).unwrap();
        let _ = std::fs::remove_dir_all(&b);
    }

    #[test]
    fn directories_of_dead_processes_are_swept_and_live_ones_are_not() {
        let b = base("sweep");
        let dead = b.join("clip-4000000000-0");
        let live = b.join("clip-1-0"); // pid 1 runs
        let other = b.join("keep-me");
        for d in [&dead, &live, &other] {
            std::fs::create_dir(d).unwrap();
        }
        let _s = StagingDir::create(&b).unwrap();
        assert!(!dead.exists(), "a dead process's directory goes");
        assert!(live.exists() && other.exists());
        let _ = std::fs::remove_dir_all(&b);
    }

    #[test]
    fn disabled_manager_refuses_everything() {
        let m = ClipboardManager::start(ClipboardSettings {
            enabled: false,
            ..ClipboardSettings::default()
        })
        .unwrap();
        assert!(!m.is_enabled());
        assert!(matches!(
            m.read_text(Selection::Clipboard),
            Err(ClipboardPolicyError::Disabled)
        ));
        assert!(m.events().try_recv().is_err());
        assert!(matches!(
            m.withdraw(Selection::Clipboard),
            Err(ClipboardPolicyError::Disabled)
        ));
    }
}
