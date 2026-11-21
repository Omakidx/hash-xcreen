//! `logs [--follow] [-n N] [--journal] [--audit]`.
//!
//! Two sources, both treated as hostile text:
//!
//! * **the journal of the hx units**, read with `journalctl` and an argv built only from
//!   constants and the line count (no operator text, no shell, a cleared environment). The match
//!   uses the trusted journal fields that only journald sets (`_SYSTEMD_UNIT`, `_UID`): privd's
//!   lines must come from uid 0, so an unprivileged user that writes to journald cannot make a
//!   line look like privd's (`docs/ipc.md` section 8);
//! * **the audit log** (`/var/log/hx/audit.log`), opened with `O_NOFOLLOW` and used only if the
//!   file and its directory are owned by root and not writable by group or others.
//!
//! Every line is cut to a bounded length and sanitized before it is printed: a line is data, and
//! must never be able to move the cursor, retitle the window or forge a second line.

use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;

use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::Duration;

use serde_json::json;

use crate::cli::error::CliError;
use crate::cli::text::{peer, scrub_json, scrub_output};
use crate::cli::{Config, Env, Outcome};

/// Longest line kept; the rest of a longer line is dropped.
const MAX_LINE: usize = 4096;
/// Longest journal entry (one JSON object) read; a longer one is shown as unreadable.
const MAX_ENTRY: usize = 65_536;
/// Most journal lines read in one non-follow call.
const MAX_JOURNAL_LINES: usize = 20_000;
/// Most journal text collected into one `--json` object.
const MAX_JSON_BYTES: usize = 16 << 20;
/// Entries queued between the journalctl reader thread and the printer while following.
const QUEUE: usize = 1024;
/// How much of the end of the audit file is looked at for a tail.
const TAIL_WINDOW: u64 = 1 << 20;
/// Poll interval for the audit file while following.
const POLL: Duration = Duration::from_millis(250);

/// The argv of `journalctl` (after the program): constants and the line count only.
pub fn journal_argv(lines: u32, follow: bool) -> Vec<String> {
    let mut a: Vec<String> = ["--no-pager", "--output=json", "--lines"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    a.push(lines.to_string());
    if follow {
        a.push("--follow".into());
    }
    // (_SYSTEMD_UNIT=privd AND _UID=0) OR (_SYSTEMD_UNIT=gatewayd): the gateway is not root.
    for m in [
        "_SYSTEMD_UNIT=hx-privd.service",
        "_UID=0",
        "+",
        "_SYSTEMD_UNIT=hx-gatewayd.service",
    ] {
        a.push(m.into());
    }
    a
}

/// Reads lines of at most [`MAX_LINE`] bytes from a reader, without ever buffering a longer one.
struct Lines<R: Read> {
    r: R,
    max: usize,
    buf: Vec<u8>,
    chunk: [u8; 8192],
    pos: usize,
    len: usize,
    eof: bool,
}

impl<R: Read> Lines<R> {
    fn new(r: R, max: usize) -> Self {
        Self {
            r,
            max,
            buf: Vec::new(),
            chunk: [0; 8192],
            pos: 0,
            len: 0,
            eof: false,
        }
    }

    /// The next line, sanitized. `None` at end of stream.
    fn next_line(&mut self) -> std::io::Result<Option<String>> {
        loop {
            while self.pos < self.len {
                let b = self.chunk[self.pos];
                self.pos += 1;
                if b == b'\n' {
                    let line = String::from_utf8_lossy(&self.buf).into_owned();
                    self.buf.clear();
                    return Ok(Some(peer(&line, self.max)));
                }
                if self.buf.len() < self.max {
                    self.buf.push(b);
                }
            }
            if self.eof {
                if self.buf.is_empty() {
                    return Ok(None);
                }
                let line = String::from_utf8_lossy(&self.buf).into_owned();
                self.buf.clear();
                return Ok(Some(peer(&line, self.max)));
            }
            match self.r.read(&mut self.chunk) {
                Ok(0) => self.eof = true,
                Ok(n) => {
                    self.pos = 0;
                    self.len = n;
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
}

/// One journal entry (a JSON object from `journalctl --output=json`) as one safe line:
/// `<time> <unit> [pid] message`. The unit, pid and time are fields only journald sets
/// (`_SYSTEMD_UNIT`, `_PID`, `__REALTIME_TIMESTAMP`); the sender-controlled `SYSLOG_IDENTIFIER`
/// is never shown, so a line cannot claim to come from another program. The message is folded
/// onto one line and sanitized.
fn render_entry(line: &str) -> String {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
        return "(unreadable journal entry)".into();
    };
    let text = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_owned);
    let time = text("__REALTIME_TIMESTAMP")
        .and_then(|t| t.parse::<u64>().ok())
        .map(|us| crate::cli::text::time(us / 1_000_000))
        .unwrap_or_else(|| "-".into());
    let unit = text("_SYSTEMD_UNIT").unwrap_or_else(|| "-".into());
    let pid = text("_PID")
        .map(|p| format!(" [{}]", peer(&p, 12)))
        .unwrap_or_default();
    // A message that is not valid UTF-8 (or has control bytes) comes as an array of numbers.
    let message = match v.get("MESSAGE") {
        Some(serde_json::Value::String(m)) => m.clone(),
        Some(serde_json::Value::Array(a)) => {
            let bytes: Vec<u8> = a
                .iter()
                .filter_map(|n| n.as_u64())
                .map(|n| n as u8)
                .collect();
            String::from_utf8_lossy(&bytes).into_owned()
        }
        _ => String::new(),
    };
    let folded = message.replace(['\n', '\r'], " ");
    format!(
        "{} {}{} {}",
        time,
        peer(&unit, 64),
        pid,
        peer(&folded, MAX_LINE)
    )
}

fn spawn_journal(cfg: &Config, lines: u32, follow: bool) -> Result<Child, CliError> {
    Command::new(&cfg.journalctl)
        .args(journal_argv(lines, follow))
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            CliError::Unavailable(format!(
                "cannot run journalctl ({}): {}",
                cfg.journalctl.display(),
                e.kind()
            ))
        })
}

/// Reads the journal entries and hands each rendered line to `sink`, one at a time, so nothing
/// accumulates here. `sink` returns false to stop (the reader of our output went away).
fn each_journal(
    cfg: &Config,
    lines: u32,
    sink: &mut dyn FnMut(String) -> bool,
) -> Result<(), CliError> {
    let mut child = spawn_journal(cfg, lines, false)?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| CliError::failed("journalctl has no output"))?;
    let mut rd = Lines::new(stdout, MAX_ENTRY);
    let mut count = 0usize;
    let mut failed = None;
    while count < MAX_JOURNAL_LINES {
        match rd.next_line() {
            Ok(Some(l)) => {
                count += 1;
                if !sink(render_entry(&l)) {
                    break;
                }
            }
            Ok(None) => break,
            Err(e) => {
                failed = Some(CliError::Unavailable(format!(
                    "reading journalctl: {}",
                    e.kind()
                )));
                break;
            }
        }
    }
    let _ = child.kill();
    let status = child
        .wait()
        .map_err(|e| CliError::Unavailable(format!("journalctl: {}", e.kind())))?;
    if let Some(e) = failed {
        return Err(e);
    }
    // A kill after a complete read is our own; an exit with an error before any line is not.
    if count == 0 && !status.success() && status.code().is_some() {
        return Err(CliError::Unavailable(format!(
            "journalctl failed (exit {})",
            status.code().unwrap_or(-1)
        )));
    }
    Ok(())
}

/// The audit log's directory, held open. The file is only ever opened **relative to this
/// descriptor**, so nothing can be swapped between the check of the directory and the open of
/// the file (on Ubuntu `/var/log` is group-writable by `syslog`, whose members can rename
/// `/var/log/hx`), and a rotation is followed under the same directory, never through the path.
struct AuditDir {
    dir: OwnedFd,
    name: OsString,
    owner: u32,
}

fn refused(m: &str) -> CliError {
    CliError::Failed(format!("refusing to read the audit log: {m}"))
}

/// Opens the audit directory (`O_DIRECTORY|O_NOFOLLOW`) and checks it by `fstat`: owned by
/// `owner`, not writable by group or others. `None` if it does not exist yet.
fn audit_dir(path: &Path, owner: u32) -> Result<Option<AuditDir>, CliError> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(CliError::failed("the audit log path has no directory"));
    };
    let dir = match rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(e) => {
            return Err(refused(&format!(
                "its directory cannot be opened (a symlink or a non-directory is refused): {e}"
            )));
        }
    };
    let st = rustix::fs::fstat(&dir)
        .map_err(|e| CliError::Failed(format!("audit log directory: {e}")))?;
    if st.st_uid != owner || (st.st_mode as u32) & 0o022 != 0 {
        return Err(refused(
            "its directory is not a root-owned directory closed to others",
        ));
    }
    Ok(Some(AuditDir {
        dir,
        name: name.to_owned(),
        owner,
    }))
}

impl AuditDir {
    /// Opens the file relative to the directory: `O_NOFOLLOW` (no symlink), `O_NONBLOCK` (a FIFO
    /// cannot hang the open) and then `fstat` of what was opened: a regular file owned by the
    /// expected uid and not writable by group or others. `None` if it does not exist.
    fn open(&self) -> Result<Option<File>, CliError> {
        let fd = match rustix::fs::openat(
            &self.dir,
            self.name.as_os_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(e) => {
                return Err(refused(&format!(
                    "the file cannot be opened (a symlink is refused): {e}"
                )));
            }
        };
        let st = rustix::fs::fstat(&fd).map_err(|e| CliError::Failed(format!("audit log: {e}")))?;
        let regular = FileType::from_raw_mode(st.st_mode as _) == FileType::RegularFile;
        if !regular || st.st_uid != self.owner || (st.st_mode as u32) & 0o022 != 0 {
            return Err(refused(
                "the file is not a root-owned regular file closed to others",
            ));
        }
        Ok(Some(File::from(fd)))
    }

    /// Device and inode of what the name refers to now (without following a symlink).
    #[allow(clippy::unnecessary_cast)] // st_dev and st_ino are not u64 on every target
    fn ident(&self) -> Option<(u64, u64)> {
        rustix::fs::statat(&self.dir, self.name.as_os_str(), AtFlags::SYMLINK_NOFOLLOW)
            .ok()
            .map(|st| (st.st_dev as u64, st.st_ino as u64))
    }
}

/// The audit log opened safely: `None` if it does not exist yet.
fn open_audit(path: &Path, owner: u32) -> Result<Option<File>, CliError> {
    match audit_dir(path, owner)? {
        Some(d) => d.open(),
        None => Ok(None),
    }
}

/// The last `n` lines of the file, sanitized.
fn audit_tail(f: &mut File, n: usize) -> Result<Vec<String>, CliError> {
    let io = |e: std::io::Error| CliError::Failed(format!("audit log: {}", e.kind()));
    let len = f.metadata().map_err(io)?.len();
    let start = len.saturating_sub(TAIL_WINDOW);
    f.seek(SeekFrom::Start(start)).map_err(io)?;
    let mut data = Vec::new();
    f.take(TAIL_WINDOW).read_to_end(&mut data).map_err(io)?;
    // A window that starts inside a line drops that partial line.
    let slice = if start > 0 {
        data.iter()
            .position(|b| *b == b'\n')
            .map(|i| &data[i + 1..])
            .unwrap_or(&[])
    } else {
        &data[..]
    };
    let mut rd = Lines::new(slice, MAX_LINE);
    let mut all = Vec::new();
    while let Some(l) = rd.next_line().map_err(io)? {
        all.push(l);
    }
    let skip = all.len().saturating_sub(n);
    Ok(all.split_off(skip))
}

pub(super) fn run(
    env: &mut Env<'_>,
    follow: bool,
    lines: u32,
    journal: bool,
    audit: bool,
) -> Result<Option<Outcome>, CliError> {
    if follow {
        follow_logs(env, lines, journal, audit)?;
        return Ok(None);
    }
    if !env.json {
        // Streamed: every line is written as it is read, nothing is built in memory.
        if journal {
            put(env.out, "== journal (hx-privd, hx-gatewayd) ==\n");
            let out = &mut *env.out;
            each_journal(&env.config, lines, &mut |l| {
                put(out, &scrub_output(&format!("{l}\n")))
            })?;
        }
        if audit {
            put(env.out, "== audit log ==\n");
            let tail = match open_audit(&env.config.audit_log, env.config.audit_owner_uid)? {
                Some(mut f) => audit_tail(&mut f, lines as usize)?,
                None => Vec::new(),
            };
            if tail.is_empty() {
                put(env.out, "(no entries)\n");
            }
            for l in tail {
                if !put(env.out, &scrub_output(&format!("{l}\n"))) {
                    break;
                }
            }
        }
        return Ok(None);
    }
    // JSON: one object holds everything, so it is bounded by bytes as well as by lines.
    let j = if journal {
        let mut v = Vec::new();
        let mut bytes = 0usize;
        each_journal(&env.config, lines, &mut |l| {
            bytes += l.len();
            v.push(l);
            bytes < MAX_JSON_BYTES
        })?;
        Some(v)
    } else {
        None
    };
    let a = if audit {
        match open_audit(&env.config.audit_log, env.config.audit_owner_uid)? {
            Some(mut f) => Some(audit_tail(&mut f, lines as usize)?),
            None => Some(Vec::new()),
        }
    } else {
        None
    };
    Ok(Some(Outcome::ok(
        String::new(),
        json!({"journal": j, "audit": a}),
    )))
}

/// Writes text; false when the reader of our output is gone (a closed pipe).
fn put(w: &mut dyn std::io::Write, s: &str) -> bool {
    w.write_all(s.as_bytes()).and_then(|()| w.flush()).is_ok()
}

/// Writes one followed line; false when the reader of our output is gone.
fn emit(env: &mut Env<'_>, source: &str, line: &str) -> bool {
    let s = if env.json {
        let mut v = json!({"source": source, "line": line});
        scrub_json(&mut v);
        let mut s = v.to_string();
        s.push('\n');
        s
    } else {
        scrub_output(&format!("{source:<7}| {line}\n"))
    };
    put(env.out, &s)
}

fn follow_logs(env: &mut Env<'_>, lines: u32, journal: bool, audit: bool) -> Result<(), CliError> {
    let (tx, rx) = mpsc::sync_channel::<String>(QUEUE);
    let mut child: Option<Child> = None;
    if journal {
        let mut c = spawn_journal(&env.config, lines, true)?;
        let stdout = c
            .stdout
            .take()
            .ok_or_else(|| CliError::failed("journalctl has no output"))?;
        std::thread::spawn(move || {
            let mut rd = Lines::new(stdout, MAX_ENTRY);
            while let Ok(Some(l)) = rd.next_line() {
                if tx.send(render_entry(&l)).is_err() {
                    break;
                }
            }
        });
        child = Some(c);
    } else {
        drop(tx);
    }
    let result = follow_loop(env, lines, journal, audit, &rx);
    // However the loop ended (stop flag, journalctl gone, a closed pipe, an error), journalctl
    // is ended too; dropping `rx` ends the reader thread.
    drop(rx);
    if let Some(mut c) = child {
        let _ = c.kill();
        let _ = c.wait();
    }
    result
}

/// The printing loop of `--follow`. Ends on the first failed write (including a closed pipe).
fn follow_loop(
    env: &mut Env<'_>,
    lines: u32,
    journal: bool,
    audit: bool,
    rx: &mpsc::Receiver<String>,
) -> Result<(), CliError> {
    // The audit log: the last lines first, then whatever is appended.
    let mut follow = AuditFollow::default();
    if audit {
        follow.dir = audit_dir(&env.config.audit_log, env.config.audit_owner_uid)?;
        if let Some(d) = &follow.dir
            && let Some(mut f) = d.open()?
        {
            for l in audit_tail(&mut f, lines as usize)? {
                if !emit(env, "audit", &l) {
                    return Ok(());
                }
            }
            let m = f
                .metadata()
                .map_err(|e| CliError::Failed(format!("audit log: {}", e.kind())))?;
            follow.offset = m.len();
            follow.ident = Some((m.dev(), m.ino()));
            follow.file = Some(f);
        }
    }
    loop {
        if env.stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        match rx.recv_timeout(POLL) {
            Ok(l) => {
                if !emit(env, "journal", &l) {
                    return Ok(());
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if journal {
                    // journalctl ended: nothing more to follow.
                    return Ok(());
                }
                std::thread::sleep(POLL);
            }
        }
        if audit && !poll_audit(env, &mut follow)? {
            return Ok(());
        }
    }
}

/// What `--follow` remembers of the audit log.
#[derive(Default)]
struct AuditFollow {
    dir: Option<AuditDir>,
    file: Option<File>,
    offset: u64,
    ident: Option<(u64, u64)>,
    partial: Vec<u8>,
}

/// Emits lines appended to the audit log since the last poll, following a rotation. The file is
/// always (re)opened relative to the directory descriptor held since the start. On a rotation
/// the old file is read to its end first, so what was appended just before the rename is not lost.
fn poll_audit(env: &mut Env<'_>, st: &mut AuditFollow) -> Result<bool, CliError> {
    if st.dir.is_none() {
        // The directory did not exist when following began.
        st.dir = audit_dir(&env.config.audit_log, env.config.audit_owner_uid)?;
    }
    let Some(dir) = st.dir.as_ref() else {
        return Ok(true);
    };
    // Look at the name (not the open file): a rotation replaces the file under the same name.
    if dir.ident() != st.ident {
        let next = dir.open()?;
        if st.file.is_some() {
            if !drain(env, st)? {
                return Ok(false);
            }
            // A last line without its newline is complete now: the file will not grow.
            let rest = std::mem::take(&mut st.partial);
            if !rest.is_empty() {
                let text = peer(&String::from_utf8_lossy(&rest), MAX_LINE);
                if !emit(env, "audit", &text) {
                    return Ok(false);
                }
            }
        }
        st.file = next;
        st.offset = 0;
        st.partial.clear();
        st.ident = st
            .file
            .as_ref()
            .and_then(|f| f.metadata().ok())
            .map(|m| (m.dev(), m.ino()));
    }
    drain(env, st)
}

/// Reads the open audit file from the remembered offset to its end and emits the complete
/// lines. False when the reader of our output is gone.
fn drain(env: &mut Env<'_>, st: &mut AuditFollow) -> Result<bool, CliError> {
    let Some(f) = st.file.as_mut() else {
        return Ok(true);
    };
    let io = |e: std::io::Error| CliError::Failed(format!("audit log: {}", e.kind()));
    let len = f.metadata().map_err(io)?.len();
    if len < st.offset {
        // Truncated in place.
        st.offset = 0;
        st.partial.clear();
    }
    loop {
        f.seek(SeekFrom::Start(st.offset)).map_err(io)?;
        let mut data = Vec::new();
        f.take(TAIL_WINDOW).read_to_end(&mut data).map_err(io)?;
        if data.is_empty() {
            return Ok(true);
        }
        st.offset += data.len() as u64;
        st.partial.extend_from_slice(&data);
        while let Some(i) = st.partial.iter().position(|b| *b == b'\n') {
            let rest = st.partial.split_off(i + 1);
            let line = std::mem::replace(&mut st.partial, rest);
            let text = peer(&String::from_utf8_lossy(&line[..line.len() - 1]), MAX_LINE);
            if !emit(env, "audit", &text) {
                return Ok(false);
            }
        }
        // A partial line that grows without a newline is cut, not accumulated.
        st.partial.truncate(MAX_LINE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_journal_argv_is_constants_and_a_number() {
        let a = journal_argv(50, false);
        assert_eq!(
            a,
            [
                "--no-pager",
                "--output=json",
                "--lines",
                "50",
                "_SYSTEMD_UNIT=hx-privd.service",
                "_UID=0",
                "+",
                "_SYSTEMD_UNIT=hx-gatewayd.service"
            ]
        );
        assert!(journal_argv(5, true).contains(&"--follow".to_string()));
    }

    #[test]
    fn long_lines_are_cut_and_sanitized_without_buffering_them() {
        let mut input = Vec::new();
        input.extend_from_slice(b"ok\x1b[31m line\n");
        input.extend(std::iter::repeat_n(b'x', MAX_LINE * 3));
        input.extend_from_slice(b"\nlast");
        let mut rd = Lines::new(&input[..], MAX_LINE);
        assert_eq!(rd.next_line().unwrap().unwrap(), "ok[31m line");
        assert_eq!(rd.next_line().unwrap().unwrap().len(), MAX_LINE);
        assert_eq!(rd.next_line().unwrap().unwrap(), "last");
        assert!(rd.next_line().unwrap().is_none());
    }
}
