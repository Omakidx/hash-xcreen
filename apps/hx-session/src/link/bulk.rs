//! The `bulk` lane at the session end: clipboard and file transfers in both directions
//! (`docs/ipc.md` section 16).
//!
//! * **Gateway to session.** [`reader_loop`] reads `TransferOpen`/`Data`/`End`/`Abort`. A file
//!   is written into the received-files directory under a name the session picks (the
//!   announced name is a hint): created with `O_EXCL | O_NOFOLLOW`, mode 0600, never
//!   overwriting. A clipboard transfer is held in memory (at most 64 MiB, counted as it arrives)
//!   and, once complete, offered to local applications through the clipboard manager.
//! * **Session to gateway.** [`clipboard_loop`] watches the local clipboard and sends text,
//!   an image or the files of a copy through [`send_clipboard`] and [`send_file`].
//!
//! Limits: at most 4 concurrent transfers per direction, one clipboard transfer per direction (a
//! new one aborts the previous), a file at most `max_file_bytes`, chunks at most 64 KiB, and
//! 4 clipboard transfers per second from the session. Ids: the gateway's are odd, the session's
//! even; an id already in use is a violation.

use super::io::{LaneError, LaneReader};
use super::received::{ReceivedError, ReceivedFile};
use super::runtime::LinkCtx;
use hx_capture::clipboard::{ClipboardEvent, MIME_PNG, MIME_TEXT, MIME_URI_LIST, Selection};
use hx_ipc::link::budget::{RateWindow, limits};
use hx_ipc::link::frames::{
    LinkFrame, encode_transfer_abort, encode_transfer_data_prefix, encode_transfer_end,
    encode_transfer_open, parse,
};
use hx_ipc::link::{MAX_TRANSFER_CHUNK, Role, pb};
use hx_proto::channel::{MAX_CLIPBOARD_SIZE, RESET_TRANSFER_ERROR, STOP_TRANSFER_REJECTED};
use hx_proto::pb::TransferHeader;
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;

/// Concurrent transfers per direction.
const MAX_CONCURRENT: usize = 4;
/// Ids remembered after the session aborted a transfer, so the gateway's frames that were
/// already in flight are ignored instead of being taken for a violation.
const RECENT_ABORTS: usize = 64;
/// Files pushed from one local copy.
const MAX_PUSHED_FILES: usize = 16;

enum Kind {
    Clipboard { mime: String, buf: Vec<u8> },
    File { file: ReceivedFile },
}

struct Incoming {
    kind: Kind,
    size: u64,
    got: u64,
}

impl Incoming {
    /// Drops what was written so far (a partial file is deleted).
    fn discard(self) {
        if let Kind::File { file } = self.kind {
            // Through the directory descriptor, never by path.
            file.discard();
        }
    }
}

/// Writes one whole frame on the bulk lane. Frames are atomic under the lock, so the reader
/// thread can interleave an abort between the chunks of a transfer being sent.
fn write_frames(ctx: &LinkCtx, parts: &[&[u8]]) -> std::io::Result<()> {
    let mut tx = ctx
        .bulk_tx
        .lock()
        .map_err(|_| std::io::Error::other("bulk writer poisoned"))?;
    for p in parts {
        tx.write_all(p)?;
    }
    Ok(())
}

fn send_abort(ctx: &LinkCtx, id: u32, code: u32) {
    if let Ok(f) = encode_transfer_abort(id, code)
        && write_frames(ctx, &[&f]).is_err()
    {
        ctx.close("bulk write failed");
    }
}

/// The reader thread of the `bulk` lane.
pub(crate) fn reader_loop(ctx: &Arc<LinkCtx>, mut reader: LaneReader) {
    let mut incoming: HashMap<u32, Incoming> = HashMap::new();
    let mut recent: VecDeque<u32> = VecDeque::new();
    loop {
        let raw = match reader.next(&ctx.closed) {
            Ok(r) => r,
            Err(LaneError::Closed) => break,
            Err(e) => {
                ctx.close(&format!("bulk lane: {}", e.text()));
                break;
            }
        };
        // The size limit is applied below (a refusal, not a violation).
        let frame = match parse(reader.policy(), raw, u64::MAX) {
            Ok(f) => f,
            Err(e) => {
                ctx.close(&format!("bulk lane violation: {e}"));
                break;
            }
        };
        if let Err(why) = handle(ctx, &mut incoming, &mut recent, frame) {
            ctx.close(&format!("bulk lane violation: {why}"));
            break;
        }
    }
    // Link loss aborts transfers: nothing half-written stays behind.
    for (_, t) in incoming.drain() {
        t.discard();
    }
}

fn remember(recent: &mut VecDeque<u32>, id: u32) {
    if recent.len() >= RECENT_ABORTS {
        recent.pop_front();
    }
    recent.push_back(id);
}

/// `Err` is a violation (the link closes).
fn handle(
    ctx: &Arc<LinkCtx>,
    incoming: &mut HashMap<u32, Incoming>,
    recent: &mut VecDeque<u32>,
    frame: LinkFrame,
) -> Result<(), &'static str> {
    match frame {
        LinkFrame::TransferOpen(open) => on_open(ctx, incoming, recent, open),
        LinkFrame::TransferData { id, data } => {
            let Some(t) = incoming.get_mut(&id) else {
                return if recent.contains(&id) {
                    Ok(())
                } else {
                    Err("data for an unknown transfer")
                };
            };
            t.got = t.got.saturating_add(data.len() as u64);
            let fail = t.got > t.size
                || match &mut t.kind {
                    Kind::Clipboard { buf, .. } => {
                        buf.extend_from_slice(&data);
                        false
                    }
                    Kind::File { file } => file.file.write_all(&data).is_err(),
                };
            if fail && let Some(t) = incoming.remove(&id) {
                t.discard();
                remember(recent, id);
                send_abort(ctx, id, RESET_TRANSFER_ERROR);
            }
            Ok(())
        }
        LinkFrame::TransferEnd { id } => {
            let Some(t) = incoming.remove(&id) else {
                return if recent.contains(&id) {
                    Ok(())
                } else {
                    Err("end of an unknown transfer")
                };
            };
            if t.got != t.size {
                t.discard();
                remember(recent, id);
                send_abort(ctx, id, RESET_TRANSFER_ERROR);
                return Ok(());
            }
            finish(ctx, t);
            Ok(())
        }
        LinkFrame::TransferAbort { id, .. } => {
            // The id is free again: nothing more arrives for it.
            if let Some(t) = incoming.remove(&id) {
                t.discard();
            } else if id % 2 == 0
                && let Ok(mut a) = ctx.aborted_out.lock()
            {
                // One of the session's own outgoing transfers (even ids).
                note_aborted(&mut a, id);
            }
            Ok(())
        }
        _ => Err("frame not valid on the bulk lane"),
    }
}

fn on_open(
    ctx: &Arc<LinkCtx>,
    incoming: &mut HashMap<u32, Incoming>,
    recent: &mut VecDeque<u32>,
    open: pb::TransferOpen,
) -> Result<(), &'static str> {
    if incoming.contains_key(&open.id) {
        return Err("transfer id already in use");
    }
    recent.retain(|r| *r != open.id);
    let header = open.header.unwrap_or_default();
    let reject = |code| send_abort(ctx, open.id, code);
    match pb::TransferChannel::try_from(open.channel) {
        Ok(pb::TransferChannel::Clipboard) => {
            if !ctx.clipboard_on.load(Relaxed) || ctx.manager.is_none() {
                reject(STOP_TRANSFER_REJECTED);
                remember(recent, open.id);
                return Ok(());
            }
            // A new clipboard transfer aborts the previous one.
            let old: Vec<u32> = incoming
                .iter()
                .filter(|(_, t)| matches!(t.kind, Kind::Clipboard { .. }))
                .map(|(id, _)| *id)
                .collect();
            for id in old {
                if let Some(t) = incoming.remove(&id) {
                    t.discard();
                    remember(recent, id);
                    send_abort(ctx, id, RESET_TRANSFER_ERROR);
                }
            }
            if incoming.len() >= MAX_CONCURRENT {
                reject(STOP_TRANSFER_REJECTED);
                remember(recent, open.id);
                return Ok(());
            }
            incoming.insert(
                open.id,
                Incoming {
                    kind: Kind::Clipboard {
                        mime: header.mime,
                        // Never sized from the announced length: it grows as bytes arrive.
                        buf: Vec::new(),
                    },
                    size: header.size.min(MAX_CLIPBOARD_SIZE),
                    got: 0,
                },
            );
        }
        Ok(pb::TransferChannel::File) => {
            if !ctx.files_on.load(Relaxed)
                || header.size > ctx.cfg.max_file_bytes
                || incoming.len() >= MAX_CONCURRENT
            {
                reject(STOP_TRANSFER_REJECTED);
                remember(recent, open.id);
                return Ok(());
            }
            match ctx.received.create(&header.name, header.size) {
                Ok(file) => {
                    incoming.insert(
                        open.id,
                        Incoming {
                            kind: Kind::File { file },
                            size: header.size,
                            got: 0,
                        },
                    );
                }
                // The directory's quota or the free space does not allow it: refused, not broken.
                Err(ReceivedError::NoRoom) => {
                    reject(STOP_TRANSFER_REJECTED);
                    remember(recent, open.id);
                }
                Err(ReceivedError::Io(e)) => {
                    ctx.event(
                        pb::EventKind::ClipboardError,
                        &format!("cannot store a received file: {e}"),
                    );
                    reject(RESET_TRANSFER_ERROR);
                    remember(recent, open.id);
                }
            }
        }
        _ => return Err("unknown transfer channel"),
    }
    Ok(())
}

/// A completed transfer. A file is already on disk; a clipboard becomes the local selection.
fn finish(ctx: &Arc<LinkCtx>, t: Incoming) {
    let (mime, buf) = match t.kind {
        Kind::Clipboard { mime, buf } => (mime, buf),
        Kind::File { file } => {
            file.finish();
            return;
        }
    };
    let canonical = match mime.split(';').next().unwrap_or("").trim() {
        m if m.eq_ignore_ascii_case("text/plain") => MIME_TEXT,
        m if m.eq_ignore_ascii_case("image/png") => MIME_PNG,
        _ => {
            ctx.event(
                pb::EventKind::ClipboardError,
                "unsupported clipboard format",
            );
            return;
        }
    };
    let Some(mgr) = &ctx.manager else { return };
    let source = Arc::new(MemorySource {
        mime: canonical,
        data: buf,
    });
    let offer = hx_session_offer(canonical);
    if let Err(e) = mgr.offer(Selection::Clipboard, offer, source) {
        ctx.event(pb::EventKind::ClipboardError, &e.to_string());
    }
}

fn hx_session_offer(mime: &str) -> crate::clipboard::ClientOffer {
    crate::clipboard::ClientOffer {
        formats: vec![mime.to_owned()],
        files: Vec::new(),
    }
}

/// A client clipboard that was received in full: pasting hands out the held bytes.
struct MemorySource {
    mime: &'static str,
    data: Vec<u8>,
}

impl crate::clipboard::ClientSource for MemorySource {
    fn fetch(&self, mime: &str, max: u64) -> Result<Vec<u8>, crate::clipboard::SourceError> {
        if mime == self.mime && self.data.len() as u64 <= max {
            Ok(self.data.clone())
        } else {
            Err(crate::clipboard::SourceError("format not offered".into()))
        }
    }

    fn stage_files(
        &self,
        _files: &[crate::clipboard::RemoteFile],
        _staging: &crate::clipboard::StagingDir,
    ) -> Result<Vec<PathBuf>, crate::clipboard::SourceError> {
        Err(crate::clipboard::SourceError("no files offered".into()))
    }
}

// ----- session to gateway -----

fn next_id(ctx: &LinkCtx) -> u32 {
    // Even ids, never 0, wrapping before the u32 maximum.
    let mut id = ctx.next_tid.fetch_add(2, Relaxed);
    if id == 0 || id % 2 == 1 {
        id = 2;
        ctx.next_tid.store(4, Relaxed);
    }
    id
}

fn aborted(ctx: &LinkCtx, id: u32) -> bool {
    ctx.aborted_out
        .lock()
        .map(|mut a| take_aborted(&mut a, id))
        .unwrap_or(true)
}

/// Remembers that the gateway aborted outgoing transfer `id`. The oldest entry goes when the
/// list is full, so a stale id (a transfer that already ended) can never make a later abort get
/// lost.
fn note_aborted(a: &mut VecDeque<u32>, id: u32) {
    if a.len() >= 16 {
        a.pop_front();
    }
    a.push_back(id);
}

fn take_aborted(a: &mut VecDeque<u32>, id: u32) -> bool {
    match a.iter().position(|x| *x == id) {
        Some(i) => {
            a.remove(i);
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_aborted_ids_never_cause_a_later_abort_to_be_lost() {
        // Review: the list used to stop accepting at 16 entries, none of which was ever
        // removed for transfers that had already ended.
        let mut a = VecDeque::new();
        for id in (2..=400).step_by(2) {
            note_aborted(&mut a, id);
        }
        assert!(a.len() <= 16);
        note_aborted(&mut a, 1_000);
        assert!(take_aborted(&mut a, 1_000), "the newest abort is found");
        assert!(!take_aborted(&mut a, 1_000), "and consumed once");
        assert!(
            !take_aborted(&mut a, 2),
            "an old one was evicted, not kept for ever"
        );
    }
}

/// Why an outgoing transfer did not complete.
#[derive(Debug)]
pub(crate) enum SendError {
    /// The gateway aborted it (or refused the header): not an error of the link.
    Aborted,
    /// The lane failed.
    Io(std::io::Error),
    Invalid(String),
}

fn send_open(
    ctx: &LinkCtx,
    channel: pb::TransferChannel,
    mime: &str,
    name: &str,
    size: u64,
) -> Result<u32, SendError> {
    let id = next_id(ctx);
    let open = pb::TransferOpen {
        id,
        channel: channel as i32,
        header: Some(TransferHeader {
            mime: mime.to_owned(),
            name: name.to_owned(),
            size,
        }),
    };
    let frame = encode_transfer_open(Role::Session, &open, ctx.cfg.max_file_bytes)
        .map_err(|e| SendError::Invalid(e.to_string()))?;
    write_frames(ctx, &[&frame]).map_err(SendError::Io)?;
    Ok(id)
}

fn send_chunks(ctx: &LinkCtx, id: u32, mut src: impl Read, size: u64) -> Result<(), SendError> {
    let mut buf = vec![0u8; MAX_TRANSFER_CHUNK];
    let mut sent = 0u64;
    while sent < size {
        if ctx.is_closed() {
            return Err(SendError::Io(std::io::ErrorKind::BrokenPipe.into()));
        }
        if aborted(ctx, id) {
            return Err(SendError::Aborted);
        }
        let want = usize::try_from((size - sent).min(MAX_TRANSFER_CHUNK as u64))
            .unwrap_or(MAX_TRANSFER_CHUNK);
        let n = src.read(&mut buf[..want]).map_err(SendError::Io)?;
        if n == 0 {
            // The file shrank under us: tell the gateway the body is short.
            send_abort(ctx, id, RESET_TRANSFER_ERROR);
            return Err(SendError::Invalid("source shorter than announced".into()));
        }
        let prefix =
            encode_transfer_data_prefix(id, n).map_err(|e| SendError::Invalid(e.to_string()))?;
        write_frames(ctx, &[&prefix, &buf[..n]]).map_err(SendError::Io)?;
        sent += n as u64;
    }
    let end = encode_transfer_end(id).map_err(|e| SendError::Invalid(e.to_string()))?;
    write_frames(ctx, &[&end]).map_err(SendError::Io)
}

/// Sends `data` as one clipboard transfer.
pub(crate) fn send_clipboard(ctx: &LinkCtx, mime: &str, data: &[u8]) -> Result<(), SendError> {
    if data.is_empty() || data.len() as u64 > MAX_CLIPBOARD_SIZE {
        return Err(SendError::Invalid("clipboard size".into()));
    }
    let id = send_open(
        ctx,
        pb::TransferChannel::Clipboard,
        mime,
        "",
        data.len() as u64,
    )?;
    send_chunks(ctx, id, data, data.len() as u64)
}

/// Sends the file at `path` (opened without following symlinks) as one file transfer under
/// the display name `name`. `size` is checked against the file as it is opened.
pub(crate) fn send_file(
    ctx: &LinkCtx,
    entry: &crate::clipboard::FileEntry,
) -> Result<(), SendError> {
    if entry.size > ctx.cfg.max_file_bytes {
        return Err(SendError::Invalid("file above the size limit".into()));
    }
    let file = entry.open().map_err(SendError::Io)?;
    let id = send_open(
        ctx,
        pb::TransferChannel::File,
        "application/octet-stream",
        &entry.name,
        entry.size,
    )?;
    send_chunks(ctx, id, file, entry.size)
}

/// Sends a local file by path (the test and tooling entry point; the clipboard watcher uses
/// the validated [`crate::clipboard::TransferList`]).
pub(crate) fn send_path(ctx: &LinkCtx, path: &Path) -> Result<(), SendError> {
    let path = std::fs::canonicalize(path).map_err(SendError::Io)?;
    let md = std::fs::metadata(&path).map_err(SendError::Io)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| SendError::Invalid("file name".into()))?
        .to_owned();
    send_file(
        ctx,
        &crate::clipboard::FileEntry {
            path,
            name,
            size: std::os::unix::fs::MetadataExt::size(&md),
        },
    )
}

/// Watches the local clipboard and pushes what a local application copies to the gateway.
pub(crate) fn clipboard_loop(ctx: &Arc<LinkCtx>) {
    let Some(mgr) = ctx.manager.clone() else {
        return;
    };
    let rx = mgr.events();
    let mut rate = RateWindow::per_second(limits::CLIPBOARD_TRANSFERS);
    while !ctx.is_closed() {
        let ev = match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(ev) => ev,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        };
        let ClipboardEvent::LocalOffer {
            selection: Selection::Clipboard,
            formats,
        } = ev
        else {
            continue;
        };
        if !ctx.clipboard_on.load(Relaxed) || !rate.allow(std::time::Instant::now()) {
            continue;
        }
        push_local(ctx, &mgr, &formats);
    }
}

fn push_local(ctx: &Arc<LinkCtx>, mgr: &crate::clipboard::ClipboardManager, formats: &[String]) {
    let has = |m: &str| formats.iter().any(|f| f == m);
    let result = if has(MIME_URI_LIST) && ctx.files_on.load(Relaxed) && ctx.cfg.push_local_files {
        match mgr.read_files(Selection::Clipboard) {
            Ok(list) => list
                .files
                .iter()
                .take(MAX_PUSHED_FILES)
                .filter(|f| f.size <= ctx.cfg.max_file_bytes)
                .try_for_each(|f| send_file(ctx, f)),
            Err(e) => {
                ctx.event(pb::EventKind::ClipboardError, &e.to_string());
                return;
            }
        }
    } else if has(MIME_TEXT) {
        match mgr.read_text(Selection::Clipboard) {
            Ok(t) if !t.is_empty() => send_clipboard(ctx, MIME_TEXT, t.as_bytes()),
            Ok(_) => return,
            Err(e) => {
                ctx.event(pb::EventKind::ClipboardError, &e.to_string());
                return;
            }
        }
    } else if has(MIME_PNG) {
        match mgr.read_image(Selection::Clipboard) {
            Ok(img) => send_clipboard(ctx, MIME_PNG, &img),
            Err(e) => {
                ctx.event(pb::EventKind::ClipboardError, &e.to_string());
                return;
            }
        }
    } else {
        return;
    };
    match result {
        Ok(()) | Err(SendError::Aborted) => {}
        Err(SendError::Io(e)) => ctx.close(&format!("bulk write failed: {e}")),
        Err(SendError::Invalid(why)) => ctx.event(pb::EventKind::ClipboardError, &why),
    }
}
