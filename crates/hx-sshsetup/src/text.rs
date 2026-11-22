//! Text from the server is untrusted: it is cleaned before the app shows it, and anything put
//! into a remote command line is quoted.

use crate::error::{Result, SshSetupError};

/// Removes control characters (newlines and tabs become spaces), bidirectional controls,
/// zero-width characters and line/paragraph separators, collapses nothing else, and cuts the
/// result to at most `max_bytes` on a character boundary.
pub fn sanitize(s: &str, max_bytes: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max_bytes));
    for c in s.chars() {
        let c = if c == '\n' || c == '\t' || c == '\r' {
            ' '
        } else {
            c
        };
        if is_unsafe(c) {
            continue;
        }
        if out.len() + c.len_utf8() > max_bytes {
            break;
        }
        out.push(c);
    }
    out
}

fn is_unsafe(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
                | '\u{E0000}'..='\u{E007F}'
        )
}

/// Quotes one argument for a POSIX shell (`'...'`, with `'` written as `'\''`). The remote
/// command line is parsed by the account's login shell, so every argument goes through this.
/// NUL and line breaks are refused rather than quoted.
pub fn quote(arg: &str) -> Result<String> {
    if arg.bytes().any(|b| b == 0 || b == b'\n' || b == b'\r') {
        return Err(SshSetupError::InvalidInput(
            "a command argument holds a NUL or a line break".into(),
        ));
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('\'');
    for c in arg.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_controls_bidi_and_cuts() {
        assert_eq!(
            sanitize("a\u{1b}[31mb\nc\u{202E}d\u{200B}", 100),
            "a[31mb cd"
        );
        assert_eq!(sanitize("héllo", 2), "h");
    }

    #[test]
    fn quote_is_shell_safe() {
        assert_eq!(quote("plain").unwrap(), "'plain'");
        assert_eq!(quote("it's").unwrap(), "'it'\\''s'");
        assert_eq!(quote("$(rm -rf /); `x`").unwrap(), "'$(rm -rf /); `x`'");
        assert!(quote("a\nb").is_err());
        assert!(quote("a\0b").is_err());
    }
}
