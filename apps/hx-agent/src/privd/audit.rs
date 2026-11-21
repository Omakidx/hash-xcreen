//! The audit log (ipc.md 8): one line per completed request and per `RecordEvent`, in a root-owned
//! append-only file (`/var/log/hx/audit.log`, 0640) that gatewayd cannot edit.
//!
//! Lines are `key=value` pairs. Values are limited to what privd itself controls (command and
//! role names, error code names, numbers), a validated desktop id, hex, or text that went through
//! `sanitize_text` and is quoted. Argument values are never logged, secrets and container-originated
//! text never reach this module.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Mutex;

use hx_ipc::privd::pb::{self, ErrorCode, Role};
use hx_ipc::text::sanitize_text;
use rustix::fs::OFlags;

use super::timefmt::rfc3339;

/// Where audit lines go.
pub trait AuditSink: Send + Sync {
    /// Appends one line (no trailing newline). Never fails the caller: a write error is logged.
    fn append(&self, line: &str);
}

/// The append-only file sink.
pub struct FileAudit {
    file: Mutex<File>,
}

impl FileAudit {
    /// Opens `path` for append (creating it 0640; the directory 0750). A symlink at the path is
    /// refused.
    pub fn open(path: &Path) -> io::Result<Self> {
        if let Some(dir) = path.parent() {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o750)
                .create(dir)?;
        }
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o640)
            .custom_flags(OFlags::NOFOLLOW.bits() as i32)
            .open(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }
}

impl AuditSink for FileAudit {
    fn append(&self, line: &str) {
        let Ok(mut f) = self.file.lock() else { return };
        let mut buf = String::with_capacity(line.len() + 1);
        buf.push_str(line);
        buf.push('\n');
        // One write call per line, so lines from different connections never interleave.
        if let Err(e) = f.write_all(buf.as_bytes()) {
            super::log::error(&format!("cannot write the audit log: {e}"));
        }
    }
}

/// An in-memory sink (tests).
#[derive(Default)]
pub struct MemoryAudit(Mutex<Vec<String>>);

impl MemoryAudit {
    /// Every line written so far.
    pub fn lines(&self) -> Vec<String> {
        self.0.lock().map(|v| v.clone()).unwrap_or_default()
    }
}

impl AuditSink for MemoryAudit {
    fn append(&self, line: &str) {
        if let Ok(mut v) = self.0.lock() {
            v.push(line.to_string());
        }
    }
}

/// `PERMISSION_DENIED` for an error code (the wire name without its prefix), `OK` for success.
pub fn outcome_name(code: Option<ErrorCode>) -> &'static str {
    match code {
        None => "OK",
        Some(c) => c
            .as_str_name()
            .strip_prefix("ERROR_CODE_")
            .unwrap_or("UNKNOWN"),
    }
}

/// Role as written in the log.
pub fn role_name(r: Role) -> &'static str {
    match r {
        Role::Gateway => "gateway",
        Role::Admin => "admin",
        Role::Unspecified => "unknown",
    }
}

/// One completed request.
pub struct RequestRecord<'a> {
    /// The caller's request id.
    pub request_id: u64,
    /// Role derived from the peer uid.
    pub role: Role,
    /// Peer uid.
    pub peer_uid: u32,
    /// Peer pid when the kernel gave one (diagnostics only).
    pub peer_pid: u32,
    /// Command name (`CommandInfo::name`).
    pub command: &'a str,
    /// The desktop id, if the command has one (already validated).
    pub desktop_id: Option<&'a str>,
    /// `OK` or an error code name.
    pub outcome: &'a str,
    /// Wall time of the request.
    pub duration_ms: u64,
}

/// The audit line of a request.
pub fn request_line(now_unix: u64, r: &RequestRecord<'_>) -> String {
    let desktop = r
        .desktop_id
        .filter(|d| super::is_safe_desktop_id(d))
        .map(|d| format!(" desktop={d}"))
        .unwrap_or_default();
    format!(
        "ts={} kind=request request_id={} role={} uid={} pid={} command={}{} outcome={} duration_ms={}",
        rfc3339(now_unix),
        r.request_id,
        role_name(r.role),
        r.peer_uid,
        r.peer_pid,
        r.command,
        desktop,
        r.outcome,
        r.duration_ms
    )
}

/// The audit line of a `RecordEvent`: the label is sanitized, limited to 64 bytes and quoted.
pub fn event_line(
    now_unix: u64,
    role: Role,
    peer_uid: u32,
    event: pb::AuditEvent,
    device_id: Option<&[u8]>,
    label: &str,
) -> String {
    let device = device_id
        .map(|d| {
            let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
            format!(" device={hex}")
        })
        .unwrap_or_default();
    let label = sanitize_text(label, 64).replace(['"', '\\'], "_");
    format!(
        "ts={} kind=event role={} uid={} event={}{} label=\"{}\"",
        rfc3339(now_unix),
        role_name(role),
        peer_uid,
        event
            .as_str_name()
            .strip_prefix("AUDIT_EVENT_")
            .unwrap_or("UNKNOWN"),
        device,
        label
    )
}

/// A plain notice by privd itself (window opened, lockout, self-check failure, ...). `text` must
/// be built from constants and non-secret values.
pub fn notice_line(now_unix: u64, what: &str) -> String {
    format!(
        "ts={} kind=notice text=\"{}\"",
        rfc3339(now_unix),
        sanitize_text(what, 200).replace(['"', '\\'], "_")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_line_has_no_argument_values_and_names_the_outcome() {
        let l = request_line(
            0,
            &RequestRecord {
                request_id: 7,
                role: Role::Gateway,
                peer_uid: 998,
                peer_pid: 12,
                command: "CreateDesktop",
                desktop_id: Some("main"),
                outcome: outcome_name(Some(ErrorCode::PermissionDenied)),
                duration_ms: 3,
            },
        );
        assert_eq!(
            l,
            "ts=1970-01-01T00:00:00Z kind=request request_id=7 role=gateway uid=998 pid=12 command=CreateDesktop desktop=main outcome=PERMISSION_DENIED duration_ms=3"
        );
        assert_eq!(outcome_name(None), "OK");
    }

    #[test]
    fn a_hostile_label_cannot_forge_a_line() {
        let l = event_line(
            0,
            Role::Gateway,
            998,
            pb::AuditEvent::DeviceAdded,
            Some(&[0xab; 16]),
            "x\"\nts=1 kind=request outcome=OK\u{1b}[31m",
        );
        assert!(!l.contains('\n') && !l.contains('\u{1b}'));
        assert_eq!(l.lines().count(), 1);
        // The hostile text stays inside the quoted label, with its quote neutralised.
        assert!(l.contains("label=\"x_"));
        assert!(l.contains("event=DEVICE_ADDED device=abababab"));
    }

    #[test]
    fn the_file_sink_appends_and_refuses_a_symlink() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("log/audit.log");
        let a = FileAudit::open(&p).unwrap();
        a.append("one");
        a.append("two");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "one\ntwo\n");
        let link = d.path().join("link.log");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert!(FileAudit::open(&link).is_err());
    }
}
