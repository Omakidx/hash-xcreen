//! "Open this link on your computer?": the remote side never opens anything locally without a
//! confirmation (architecture 8.7).
//!
//! There is no dedicated wire message for a link yet. The app treats a clipboard transfer from
//! the desktop with MIME `text/uri-list` as a link request. Only `http` and `https` are offered;
//! anything else is refused without a prompt. There is no "always allow".

/// A link that passed validation, split so the host can be shown in bold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    /// The whole address, as it will be opened.
    pub url: String,
    /// `https://`, shown before the host.
    pub prefix: String,
    /// The host (and port), shown in bold.
    pub host: String,
    /// Path, query and fragment, shown after the host.
    pub rest: String,
}

/// Why a candidate was not offered.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Not http or https.
    Scheme,
    /// Empty, too long, or with characters that must not appear in an address.
    Malformed,
    /// Credentials in the address (`user@host`), a look-alike trick.
    UserInfo,
}

/// Longest link accepted.
pub const MAX_LINK: usize = 2048;

/// Validates one link.
pub fn classify(raw: &str) -> Result<Link, Refusal> {
    let s = raw.trim();
    if s.is_empty() || s.len() > MAX_LINK {
        return Err(Refusal::Malformed);
    }
    if s.chars()
        .any(|c| c.is_control() || c.is_whitespace() || !c.is_ascii())
    {
        return Err(Refusal::Malformed);
    }
    let lower = s.to_ascii_lowercase();
    let prefix_len = if lower.starts_with("https://") {
        8
    } else if lower.starts_with("http://") {
        7
    } else {
        return Err(Refusal::Scheme);
    };
    let after = &s[prefix_len..];
    let host_end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let host = &after[..host_end];
    if host.is_empty() || host.starts_with('-') {
        return Err(Refusal::Malformed);
    }
    if host.contains('@') {
        return Err(Refusal::UserInfo);
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
    {
        return Err(Refusal::Malformed);
    }
    Ok(Link {
        url: s.to_owned(),
        prefix: s[..prefix_len].to_owned(),
        host: host.to_owned(),
        rest: after[host_end..].to_owned(),
    })
}

/// The first acceptable link of a `text/uri-list` body (comment lines start with `#`).
pub fn from_uri_list(body: &[u8]) -> Result<Link, Refusal> {
    let text = String::from_utf8_lossy(body);
    let first = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .ok_or(Refusal::Malformed)?;
    classify(first)
}

/// Opens a validated link with the desktop's default handler. The address is one argument, never
/// a shell string.
pub fn open_in_browser(link: &Link) -> std::io::Result<()> {
    std::process::Command::new("xdg-open")
        .arg(&link.url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_host_from_the_rest() {
        let l = classify("https://docs.example.test/guide/getting-started?ref=desktop").unwrap();
        assert_eq!(l.host, "docs.example.test");
        assert_eq!(l.rest, "/guide/getting-started?ref=desktop");
        assert_eq!(l.prefix, "https://");
    }

    #[test]
    fn only_http_and_https() {
        for bad in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "ssh://host",
            "ftp://h/",
            "xdg-open",
        ] {
            assert_eq!(classify(bad), Err(Refusal::Scheme), "{bad}");
        }
        assert!(classify("HTTP://Example.test/").is_ok());
    }

    #[test]
    fn rejects_lookalikes_and_junk() {
        assert_eq!(
            classify("https://docs.example.test@evil.test/"),
            Err(Refusal::UserInfo)
        );
        assert_eq!(classify("https://exa mple.test/"), Err(Refusal::Malformed));
        assert_eq!(classify("https://h\u{202e}x/"), Err(Refusal::Malformed));
        assert_eq!(classify("https://-oProxy/"), Err(Refusal::Malformed));
        assert_eq!(classify("https:///x"), Err(Refusal::Malformed));
        assert_eq!(
            classify(&format!("https://a/{}", "x".repeat(MAX_LINK))),
            Err(Refusal::Malformed)
        );
    }

    #[test]
    fn uri_list_skips_comments() {
        let l = from_uri_list(b"# c\r\nhttps://a.test/x\r\n").unwrap();
        assert_eq!(l.host, "a.test");
        assert!(from_uri_list(b"# only comment\n").is_err());
    }
}
