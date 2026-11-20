//! Sanitising of peer-supplied text (`Hello.software`, `Hello.device_name`, pairing names).

/// Characters that hide or reorder text: bidi controls and zero-width characters.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{061C}'
            | '\u{00AD}'
            | '\u{E0000}'..='\u{E007F}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{180E}'
            | '\u{FEFF}'
    )
}

/// Make untrusted text safe to log, store and show: control and invisible characters are
/// dropped, surrounding space is trimmed, and the result is cut to at most `max_bytes` on a
/// character boundary. Never empty: an empty result becomes `fallback`.
pub fn sanitize_label(raw: &str, max_bytes: usize, fallback: &str) -> String {
    let mut out = String::new();
    for c in raw.chars().filter(|c| !c.is_control() && !is_invisible(*c)) {
        if out.len() + c.len_utf8() > max_bytes {
            break;
        }
        out.push(c);
    }
    let trimmed = out.trim();
    if trimmed.is_empty() {
        fallback.to_owned()
    } else {
        trimmed.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_controls_and_bidi() {
        assert_eq!(sanitize_label("my\u{1b}[31m pc\n", 64, "x"), "my[31m pc");
        assert_eq!(sanitize_label("a\u{202E}b\u{200B}c", 64, "x"), "abc");
    }

    #[test]
    fn drops_line_separators_soft_hyphens_tags_and_annotations() {
        let raw = "a\u{2028}b\u{2029}c\u{AD}d\u{E0041}e\u{FFF9}f\u{FFFB}";
        assert_eq!(sanitize_label(raw, 64, "x"), "abcdef");
    }

    proptest::proptest! {
        #[test]
        fn output_is_idempotent_bounded_and_clean(raw in ".{0,200}", max in 1usize..80) {
            let once = sanitize_label(&raw, max, "x");
            proptest::prop_assert!(once.len() <= max.max(1));
            proptest::prop_assert!(!once.is_empty());
            proptest::prop_assert!(!once.chars().any(|c| c.is_control() || is_invisible(c)));
            proptest::prop_assert_eq!(sanitize_label(&once, max, "x"), once);
        }
    }

    #[test]
    fn truncates_on_char_boundary_and_falls_back() {
        assert_eq!(sanitize_label("ééééé", 5, "x"), "éé");
        assert_eq!(sanitize_label("  \u{7}  ", 64, "unnamed"), "unnamed");
        assert_eq!(sanitize_label("", 64, "unnamed"), "unnamed");
    }
}
