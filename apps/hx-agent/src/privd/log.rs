//! A minimal operational log: one sanitized line per event on stderr (journald captures it).
//!
//! Not the audit log (that is `audit`): this is for diagnostics, and like the audit log it never
//! receives secrets. Every text passes through `sanitize_text`, so a peer-controlled value cannot
//! forge a line.

use std::io::Write;

use hx_ipc::text::sanitize_text;

fn emit(level: &str, msg: &str) {
    let line = sanitize_text(msg, 1000);
    let _ = writeln!(std::io::stderr().lock(), "hx-privd {level}: {line}");
}

/// Informational line.
pub fn info(msg: &str) {
    emit("info", msg);
}

/// Warning line (refusals, probes of the command set, recoverable faults).
pub fn warn(msg: &str) {
    emit("warn", msg);
}

/// Error line.
pub fn error(msg: &str) {
    emit("error", msg);
}
