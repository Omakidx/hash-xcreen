//! Sanitising of peer-supplied text for logs and the admin API. Available in every feature
//! build: privd needs it for `RecordEvent.label`, `Hello.software` and `Progress.step`, the
//! gateway for session text (`docs/ipc.md` section 19.1, rule 3).

/// True for characters that must never reach a log line or a terminal: the Unicode general
/// categories `Cc` (controls, which includes the ANSI escape introducer), `Cf` (format
/// characters: zero-width, bidirectional controls, soft hyphen, tag characters, BOM), `Zl` and
/// `Zp` (U+2028, U+2029).
pub fn is_unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{2028}' | '\u{2029}'
            // Cf, per the Unicode character database
            | '\u{00AD}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}' | '\u{06DD}' | '\u{070F}'
            | '\u{0890}'..='\u{0891}' | '\u{08E2}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}' | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}' | '\u{E0020}'..='\u{E007F}')
}

/// Removes every [`is_unsafe_char`] character and truncates to at most `max_bytes` bytes on a
/// character boundary. Text that went through this is safe to log; it is still untrusted and is
/// never shown in a client UI.
pub fn sanitize_text(s: &str, max_bytes: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max_bytes));
    for c in s.chars() {
        if is_unsafe_char(c) {
            continue;
        }
        if out.len() + c.len_utf8() > max_bytes {
            break;
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_controls_line_separators_zero_width_bidi_and_tags() {
        assert_eq!(sanitize_text("a\x1b[31mb\u{202E}c\n", 64), "a[31mbc");
        assert_eq!(sanitize_text("a\u{2028}b\u{2029}c", 64), "abc");
        assert_eq!(sanitize_text("a\u{200B}b\u{200D}c\u{2060}d\u{FEFF}e\u{180E}f", 64), "abcdef");
        assert_eq!(sanitize_text("x\u{E0041}y\u{E007F}z", 64), "xyz");
        assert_eq!(sanitize_text("a\u{206A}b\u{00AD}c\u{061C}d", 64), "abcd");
    }

    #[test]
    fn truncates_on_a_character_boundary() {
        assert_eq!(sanitize_text("ééé", 5), "éé");
        assert_eq!(sanitize_text("", 5), "");
        assert_eq!(sanitize_text("abcdef", 0), "");
        assert_eq!(sanitize_text("日本語", 7), "日本");
    }

    #[test]
    fn ordinary_text_is_kept() {
        let s = "Report 2026 – café ünï 日本語 emoji 🙂";
        assert_eq!(sanitize_text(s, 200), s);
    }
}
