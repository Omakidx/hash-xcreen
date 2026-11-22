//! `/var/log/hx-install.log` (0600): the argv and exit code of every tool and the stage events.
//!
//! **Never a secret.** Nothing secret is ever an argument (see [`super::runner`]), tool output is
//! not logged at all, only its exit status and a sanitized tail of standard error on failure.
//! Every line goes through [`crate::cli::text::peer`].

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::cli::text::peer;

/// The log file, or nothing when it cannot be opened (logging never stops an install).
#[derive(Debug, Default)]
pub struct InstallLog {
    file: Option<File>,
}

impl InstallLog {
    /// Opens (creating, 0600, append) the log at `path`.
    pub fn open(path: &Path) -> Self {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(path)
            .ok();
        Self { file }
    }

    /// A log that writes nowhere.
    pub fn none() -> Self {
        Self { file: None }
    }

    /// Appends one line with the time.
    pub fn line(&mut self, now: u64, text: &str) {
        if let Some(f) = self.file.as_mut() {
            let l = format!(
                "{} {}\n",
                crate::privd::timefmt::rfc3339(now),
                peer(text, 1000)
            );
            let _ = f.write_all(l.as_bytes());
        }
    }
}
