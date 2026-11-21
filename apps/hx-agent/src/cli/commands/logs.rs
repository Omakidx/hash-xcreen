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

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
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

fn read_journal(cfg: &Config, lines: u32) -> Result<Vec<String>, CliError> {
    let mut child = spawn_journal(cfg, lines, false)?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| CliError::failed("journalctl has no output"))?;
    let mut rd = Lines::new(stdout, MAX_ENTRY);
    let mut out = Vec::new();
    while out.len() < MAX_JOURNAL_LINES {
        match rd.next_line() {
            Ok(Some(l)) => out.push(render_entry(&l)),
            Ok(None) => break,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(CliError::Unavailable(format!(
                    "reading journalctl: {}",
                    e.kind()
                )));
            }
        }
    }
    let _ = child.kill();
    let status = child
        .wait()
        .map_err(|e| CliError::Unavailable(format!("journalctl: {}", e.kind())))?;
    // A kill after a complete read is our own; an exit with an error before any line is not.
    if out.is_empty() && !status.success() && status.code().is_some() {
        return Err(CliError::Unavailable(format!(
            "journalctl failed (exit {})",
            status.code().unwrap_or(-1)
        )));
    }
    Ok(out)
}

/// The audit log opened safely: `None` if it does not exist yet.
fn open_audit(path: &Path, owner: u32) -> Result<Option<File>, CliError> {
    let bad = |m: &str| CliError::Failed(format!("refusing to read the audit log: {m}"));
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        match std::fs::symlink_metadata(dir) {
            Ok(m) => {
                if !m.is_dir() || m.uid() != owner || m.mode() & 0o022 != 0 {
                    return Err(bad(
                        "its directory is not a root-owned directory closed to others",
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(CliError::Failed(format!(
                    "audit log directory: {}",
                    e.kind()
                )));
            }
        }
    }
    let f = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(CliError::Failed(format!(
                "cannot open the audit log (a symlink is refused): {}",
                e.kind()
            )));
        }
    };
    let m = f
        .metadata()
        .map_err(|e| CliError::Failed(format!("audit log: {}", e.kind())))?;
    if !m.is_file() || m.uid() != owner || m.mode() & 0o022 != 0 {
        return Err(bad(
            "the file is not a root-owned regular file closed to others",
        ));
    }
    Ok(Some(f))
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
    let j = if journal {
        Some(read_journal(&env.config, lines)?)
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
    let mut text = String::new();
    if let Some(j) = &j {
        text.push_str("== journal (hx-privd, hx-gatewayd) ==\n");
        for l in j {
            text.push_str(l);
            text.push('\n');
        }
    }
    if let Some(a) = &a {
        text.push_str("== audit log ==\n");
        if a.is_empty() {
            text.push_str("(no entries)\n");
        }
        for l in a {
            text.push_str(l);
            text.push('\n');
        }
    }
    Ok(Some(Outcome::ok(text, json!({"journal": j, "audit": a}))))
}

fn emit(env: &mut Env<'_>, source: &str, line: &str) {
    let s = if env.json {
        let mut v = json!({"source": source, "line": line});
        scrub_json(&mut v);
        let mut s = v.to_string();
        s.push('\n');
        s
    } else {
        scrub_output(&format!("{source:<7}| {line}\n"))
    };
    let _ = env.out.write_all(s.as_bytes());
    let _ = env.out.flush();
}

fn follow_logs(env: &mut Env<'_>, lines: u32, journal: bool, audit: bool) -> Result<(), CliError> {
    let (tx, rx) = mpsc::channel::<String>();
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
    // The audit log: the last lines first, then whatever is appended.
    let mut file: Option<File> = None;
    let mut offset = 0u64;
    let mut ident: Option<(u64, u64)> = None;
    let mut partial: Vec<u8> = Vec::new();
    if audit && let Some(mut f) = open_audit(&env.config.audit_log, env.config.audit_owner_uid)? {
        for l in audit_tail(&mut f, lines as usize)? {
            emit(env, "audit", &l);
        }
        let m = f
            .metadata()
            .map_err(|e| CliError::Failed(format!("audit log: {}", e.kind())))?;
        offset = m.len();
        ident = Some((m.dev(), m.ino()));
        file = Some(f);
    }
    loop {
        if env.stop.load(Ordering::Relaxed) {
            break;
        }
        match rx.recv_timeout(POLL) {
            Ok(l) => emit(env, "journal", &l),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if journal {
                    // journalctl ended: nothing more to follow.
                    break;
                }
                std::thread::sleep(POLL);
            }
        }
        if audit {
            poll_audit(env, &mut file, &mut offset, &mut ident, &mut partial)?;
        }
    }
    if let Some(mut c) = child {
        let _ = c.kill();
        let _ = c.wait();
    }
    Ok(())
}

/// Emits lines appended to the audit log since the last poll, following a rotation.
fn poll_audit(
    env: &mut Env<'_>,
    file: &mut Option<File>,
    offset: &mut u64,
    ident: &mut Option<(u64, u64)>,
    partial: &mut Vec<u8>,
) -> Result<(), CliError> {
    let path = env.config.audit_log.clone();
    let owner = env.config.audit_owner_uid;
    // Re-stat the path (not the open file): a rotation replaces the file under the same name.
    let now = std::fs::symlink_metadata(&path)
        .ok()
        .map(|m| (m.dev(), m.ino()));
    if now != *ident {
        *file = open_audit(&path, owner)?;
        *offset = 0;
        partial.clear();
        *ident = file
            .as_ref()
            .and_then(|f| f.metadata().ok())
            .map(|m| (m.dev(), m.ino()));
    }
    let Some(f) = file.as_mut() else {
        return Ok(());
    };
    let len = f
        .metadata()
        .map_err(|e| CliError::Failed(format!("audit log: {}", e.kind())))?
        .len();
    if len < *offset {
        // Truncated in place.
        *offset = 0;
        partial.clear();
    }
    if len == *offset {
        return Ok(());
    }
    let io = |e: std::io::Error| CliError::Failed(format!("audit log: {}", e.kind()));
    f.seek(SeekFrom::Start(*offset)).map_err(io)?;
    let mut data = Vec::new();
    f.take(TAIL_WINDOW).read_to_end(&mut data).map_err(io)?;
    *offset += data.len() as u64;
    partial.extend_from_slice(&data);
    while let Some(i) = partial.iter().position(|b| *b == b'\n') {
        let rest = partial.split_off(i + 1);
        let line = std::mem::replace(partial, rest);
        let text = peer(&String::from_utf8_lossy(&line[..line.len() - 1]), MAX_LINE);
        emit(env, "audit", &text);
    }
    // A partial line that grows without a newline is cut, not accumulated.
    partial.truncate(MAX_LINE);
    Ok(())
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
