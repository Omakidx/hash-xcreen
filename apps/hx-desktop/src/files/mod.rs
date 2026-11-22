//! File transfers: the limit check before sending, the safe name for received files and the
//! activity list of the Transfers popover.

use std::path::{Path, PathBuf};

/// Protocol ceiling (docs/protocol.md 5.6).
pub const MAX_FILE: u64 = hx_proto::channel::MAX_FILE_SIZE;

/// Decision before opening a file transfer.
#[derive(Debug, PartialEq, Eq)]
pub enum SendCheck {
    /// Send it.
    Ok,
    /// Refuse and tell the user why.
    TooLarge {
        /// The effective limit.
        limit: u64,
    },
}

/// A sender must not open a transfer above the effective limit.
pub fn check_send(size: u64, limit: u64) -> SendCheck {
    let limit = if limit == 0 { MAX_FILE } else { limit.min(MAX_FILE) };
    if size > limit {
        SendCheck::TooLarge { limit }
    } else {
        SendCheck::Ok
    }
}

/// "4 GiB", "1.3 GB" style text.
pub fn human_size(n: u64) -> String {
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    let f = n as f64;
    if f >= GIB {
        format!("{:.1} GiB", f / GIB)
    } else if f >= MIB {
        format!("{:.1} MiB", f / MIB)
    } else if n >= 1024 {
        format!("{} KiB", n / 1024)
    } else {
        format!("{n} B")
    }
}

/// The refusal sentence of the mockup ("installer.iso was not sent: file too large, the limit is 4 GiB.").
pub fn refusal_text(name: &str, limit: u64) -> String {
    let lim = if limit.is_multiple_of(1 << 30) {
        format!("{} GiB", limit >> 30)
    } else {
        human_size(limit)
    };
    format!("{name} was not sent: file too large, the limit is {lim}.")
}

/// A name that is safe as one path component, chosen by us from the peer's display hint.
pub fn safe_file_name(hint: &str) -> String {
    let leaf = hint.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = leaf
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{200b}'..='\u{200f}'))
        .collect();
    let cleaned = cleaned.trim().trim_start_matches('.').to_owned();
    let mut out: String = cleaned.chars().take(120).collect();
    if out.is_empty() {
        out = "file".into();
    }
    out
}

/// A path under `dir` that does not exist yet (`name`, `name (1)`, ...).
pub fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let name = safe_file_name(name);
    let first = dir.join(&name);
    if !first.exists() {
        return first;
    }
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s.to_owned(), format!(".{e}")),
        _ => (name.clone(), String::new()),
    };
    (1..10_000)
        .map(|i| dir.join(format!("{stem} ({i}){ext}")))
        .find(|p| !p.exists())
        .unwrap_or_else(|| dir.join(format!("{stem}-{}{ext}", crate::servers::new_id())))
}

/// Where received files go: `$XDG_DOWNLOAD_DIR`, else `~/Downloads`, else the temp directory.
pub fn download_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("XDG_DOWNLOAD_DIR").filter(|p| Path::new(p).is_absolute()) {
        return PathBuf::from(p);
    }
    std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join("Downloads"))
        .unwrap_or_else(std::env::temp_dir)
}

/// Direction of one activity row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// To the desktop.
    Up,
    /// From the desktop.
    Down,
}

/// State of one transfer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransferState {
    /// In progress.
    Running,
    /// Finished.
    Done,
    /// Refused or failed, with the sentence to show.
    Failed(String),
}

/// One row of the Transfers popover.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Activity {
    /// Display name (a hint only).
    pub name: String,
    /// Direction.
    pub dir: Direction,
    /// Bytes moved.
    pub done: u64,
    /// Total bytes.
    pub total: u64,
    /// State.
    pub state: TransferState,
}

impl Activity {
    /// Percent 0..=100.
    pub fn percent(&self) -> u32 {
        if self.total == 0 {
            return 100;
        }
        ((self.done.min(self.total) * 100) / self.total) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limit_check_uses_the_lower_value_and_the_ceiling() {
        assert_eq!(check_send(10, 0), SendCheck::Ok);
        assert_eq!(check_send(MAX_FILE, 0), SendCheck::Ok);
        assert_eq!(check_send(MAX_FILE + 1, 0), SendCheck::TooLarge { limit: MAX_FILE });
        assert_eq!(check_send(101, 100), SendCheck::TooLarge { limit: 100 });
        assert_eq!(check_send(1, u64::MAX), SendCheck::Ok);
        assert_eq!(check_send(0, 1), SendCheck::Ok);
    }

    #[test]
    fn refusal_sentence_matches_the_mockup() {
        assert_eq!(
            refusal_text("installer.iso", MAX_FILE),
            "installer.iso was not sent: file too large, the limit is 4 GiB."
        );
    }

    #[test]
    fn names_are_never_paths() {
        assert_eq!(safe_file_name("../../etc/passwd"), "passwd");
        assert_eq!(safe_file_name("C:\\x\\y.txt"), "y.txt");
        assert_eq!(safe_file_name(".bashrc"), "bashrc");
        assert_eq!(safe_file_name("a\u{202e}b.txt"), "ab.txt");
        assert_eq!(safe_file_name(""), "file");
        assert_eq!(safe_file_name("/"), "file");
    }

    #[test]
    fn unique_names_do_not_overwrite() {
        let d = std::env::temp_dir().join(format!("hx-files-{}", crate::servers::new_id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("a.txt"), b"x").unwrap();
        assert_eq!(unique_path(&d, "a.txt"), d.join("a (1).txt"));
        assert_eq!(unique_path(&d, "b.txt"), d.join("b.txt"));
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn percent_is_bounded() {
        let a = Activity {
            name: "x".into(),
            dir: Direction::Up,
            done: 62,
            total: 100,
            state: TransferState::Running,
        };
        assert_eq!(a.percent(), 62);
    }
}
