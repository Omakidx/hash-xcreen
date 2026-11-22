//! Clipboard sync policy: what is sent, what is accepted, and no echo.
//!
//! The local clipboard is reached through Slint (a hidden text input in `AppWindow`), which
//! carries text only. Images and files from the desktop are kept for a native clipboard
//! implementation; the transfer layer already receives them.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use hx_proto::channel::MAX_CLIPBOARD_SIZE;

/// The three switches of App settings, "Clipboard on this device".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Send my clipboard to the desktop.
    pub send: bool,
    /// Receive the desktop's clipboard.
    pub receive: bool,
    /// Include files.
    pub files: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            send: true,
            receive: true,
            files: true,
        }
    }
}

/// What to do with something that arrived from the desktop.
#[derive(Debug, PartialEq, Eq)]
pub enum Incoming {
    /// Put text on the local clipboard.
    Text,
    /// A link request: ask before opening.
    Link,
    /// An image: keep it.
    Image,
    /// Do nothing (policy or unknown type).
    Ignore,
}

/// Decides for a MIME type.
pub fn classify_incoming(p: &Policy, mime: &str) -> Incoming {
    let m = mime
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    match m.as_str() {
        "text/uri-list" => Incoming::Link,
        "text/plain" if p.receive => Incoming::Text,
        "image/png" if p.receive && p.files => Incoming::Image,
        _ => Incoming::Ignore,
    }
}

/// Remembers what was last exchanged so the same text is not bounced back and forth.
#[derive(Debug, Default)]
pub struct Sync {
    last: Option<u64>,
}

fn digest(s: &str) -> u64 {
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

impl Sync {
    /// Text arrived from the desktop and was put on the local clipboard.
    pub fn received(&mut self, text: &str) {
        self.last = Some(digest(text));
    }

    /// Whether the local clipboard `text` should be sent now (policy, size, not an echo, new).
    pub fn should_send(&mut self, p: &Policy, text: &str) -> bool {
        if !p.send || text.is_empty() || text.len() as u64 > MAX_CLIPBOARD_SIZE {
            return false;
        }
        let d = digest(text);
        if self.last == Some(d) {
            return false;
        }
        self.last = Some(d);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_gates_incoming() {
        let p = Policy::default();
        assert_eq!(
            classify_incoming(&p, "text/plain;charset=utf-8"),
            Incoming::Text
        );
        assert_eq!(classify_incoming(&p, "image/png"), Incoming::Image);
        assert_eq!(classify_incoming(&p, "text/uri-list"), Incoming::Link);
        assert_eq!(
            classify_incoming(&p, "application/x-evil"),
            Incoming::Ignore
        );
        let off = Policy {
            receive: false,
            ..p
        };
        assert_eq!(classify_incoming(&off, "text/plain"), Incoming::Ignore);
        assert_eq!(classify_incoming(&off, "image/png"), Incoming::Ignore);
        // A link still gets its confirmation even when clipboard receive is off: nothing opens
        // without it, and nothing is put on the clipboard.
        assert_eq!(classify_incoming(&off, "text/uri-list"), Incoming::Link);
        let nofiles = Policy { files: false, ..p };
        assert_eq!(classify_incoming(&nofiles, "image/png"), Incoming::Ignore);
    }

    #[test]
    fn no_echo_and_no_repeat() {
        let p = Policy::default();
        let mut s = Sync::default();
        assert!(s.should_send(&p, "hello"));
        assert!(!s.should_send(&p, "hello"), "unchanged");
        s.received("from desktop");
        assert!(
            !s.should_send(&p, "from desktop"),
            "echo of what the desktop sent"
        );
        assert!(s.should_send(&p, "new text"));
        assert!(!s.should_send(&Policy { send: false, ..p }, "other"));
        assert!(!s.should_send(&p, ""));
    }
}
