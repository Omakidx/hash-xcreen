//! A deliberately small HTTP/1.1 client over rustls: one `GET` per connection, `Connection:
//! close`, `identity` encoding, a response framed by `Content-Length` or `chunked` (an unframed
//! body is refused, because a body that ends at connection close cannot be told from a truncated
//! one), redirects only to release hosts, bounded in time and bytes at every step.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

use super::{Config, FetchError, MAX_REDIRECTS};

/// Most bytes of a response head.
const MAX_HEAD: usize = 16 * 1024;
/// Longest chunk-size line.
const MAX_LINE: usize = 256;
/// Longest single wait on the socket (the overall deadline bounds the sum).
const IO_SLICE: Duration = Duration::from_secs(20);

/// An HTTPS URL, reduced to what the fetcher uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    /// Host name (lowercase ASCII, no port).
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// Absolute path and query, starting with `/`.
    pub path: String,
}

impl Url {
    /// An HTTPS URL for `host`, `port` and `path`.
    pub fn https(host: &str, port: u16, path: &str) -> Self {
        Self {
            host: host.to_ascii_lowercase(),
            port,
            path: path.to_string(),
        }
    }
}

fn path_ok(p: &str) -> bool {
    p.starts_with('/') && p.len() <= 2048 && p.bytes().all(|b| b.is_ascii_graphic() && b != b'#')
}

fn host_ok(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && !h.starts_with('.')
        && !h.starts_with('-')
}

/// Parses an absolute `https://host[:port]/path` URL. Any other scheme, userinfo, an IP literal
/// in brackets or a malformed authority is refused.
pub fn parse_url(s: &str) -> Result<Url, FetchError> {
    let refused = |why: &str| FetchError::Refused(format!("url: {why}"));
    let rest = s
        .strip_prefix("https://")
        .ok_or_else(|| refused("not https"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().map_err(|_| refused("port"))?),
        None => (authority, 443),
    };
    if !host_ok(host) || !path_ok(path) {
        return Err(refused("malformed"));
    }
    Ok(Url::https(host, port, path))
}

/// Whether an address is one the fetcher may connect to: global unicast only.
pub(super) fn is_global(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => is_global_v4(a),
        IpAddr::V6(a) => is_global_v6(a),
    }
}

fn is_global_v4(a: &Ipv4Addr) -> bool {
    let o = a.octets();
    !(a.is_unspecified()
        || a.is_loopback()
        || a.is_private()
        || a.is_link_local()
        || a.is_broadcast()
        || a.is_multicast()
        || a.is_documentation()
        || o[0] == 0
        || o[0] >= 240
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 CGNAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24
        || (o[0] == 198 && (o[1] & 0xfe) == 18)) // 198.18.0.0/15
}

fn is_global_v6(a: &Ipv6Addr) -> bool {
    if let Some(v4) = a.to_ipv4_mapped() {
        return is_global_v4(&v4);
    }
    let s = a.segments();
    !(a.is_unspecified()
        || a.is_loopback()
        || a.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
        || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 link local
        || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
        || (s[0] == 0x0064 && s[1] == 0xff9b) // NAT64 prefix: reaches v4 space unchecked
        || (s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 1) // 64:ff9b:1::/48 local-use NAT64
        || s[0] == 0x2002 // 2002::/16 6to4: embeds an arbitrary IPv4 address
        || s[..6].iter().all(|x| *x == 0) // ::/96 IPv4-compatible (deprecated)
        || (s[0] & 0xffc0) == 0xfec0) // fec0::/10 site-local (deprecated)
}

fn resolve(
    cfg: &Config,
    host: &str,
    port: u16,
    deadline: Instant,
) -> Result<Vec<SocketAddr>, FetchError> {
    // getaddrinfo has no timeout of its own: ask from a thread and stop waiting at the deadline.
    let (tx, rx) = std::sync::mpsc::channel();
    let h = host.to_string();
    std::thread::spawn(move || {
        let r = (h.as_str(), port)
            .to_socket_addrs()
            .map(Iterator::collect::<Vec<_>>);
        let _ = tx.send(r);
    });
    let wait = remaining(deadline)?.min(Duration::from_secs(10));
    let found = rx
        .recv_timeout(wait)
        .map_err(|_| FetchError::Resolve(host.into()))?
        .map_err(|_| FetchError::Resolve(host.into()))?;
    let ok: Vec<SocketAddr> = found
        .into_iter()
        .filter(|a| cfg.allow_non_global || is_global(&a.ip()))
        .collect();
    if ok.is_empty() {
        return Err(FetchError::Resolve(host.into()));
    }
    Ok(ok)
}

fn remaining(deadline: Instant) -> Result<Duration, FetchError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(FetchError::Timeout("overall deadline"))
}

fn tls_config(cfg: &Config) -> Result<Arc<ClientConfig>, FetchError> {
    // TLS 1.3 only: the workspace builds rustls without `tls12`, so the default protocol set is
    // 1.3 alone (cargo-deny fails the build if a crate turns `tls12` on).
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let c = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| FetchError::Tls(e.to_string()))?
        .with_root_certificates(cfg.roots.clone())
        .with_no_client_auth();
    Ok(Arc::new(c))
}

type Tls = StreamOwned<ClientConnection, TcpStream>;

fn connect(cfg: &Config, url: &Url, deadline: Instant) -> Result<Tls, FetchError> {
    let addrs = resolve(cfg, &url.host, url.port, deadline)?;
    let mut last: Option<io::Error> = None;
    for a in addrs.into_iter().take(4) {
        let t = cfg.connect_timeout.min(remaining(deadline)?);
        match TcpStream::connect_timeout(&a, t) {
            Ok(tcp) => {
                let _ = tcp.set_nodelay(true);
                // The TLS handshake happens inside the first write: bound it too.
                let slice = remaining(deadline)?.min(IO_SLICE);
                let _ = tcp.set_read_timeout(Some(slice));
                let _ = tcp.set_write_timeout(Some(slice));
                let name = ServerName::try_from(url.host.clone())
                    .map_err(|e| FetchError::Tls(e.to_string()))?;
                let conn = ClientConnection::new(tls_config(cfg)?, name)
                    .map_err(|e| FetchError::Tls(e.to_string()))?;
                return Ok(StreamOwned::new(conn, tcp));
            }
            Err(e) => last = Some(e),
        }
    }
    Err(last.map_or_else(
        || FetchError::Resolve(url.host.clone()),
        |e| {
            if e.kind() == io::ErrorKind::TimedOut {
                FetchError::Timeout("connect")
            } else {
                FetchError::Io(e)
            }
        },
    ))
}

/// A buffered, deadline-checked reader over the TLS stream.
struct Rd {
    tls: Tls,
    buf: Vec<u8>,
    pos: usize,
    deadline: Instant,
}

impl Rd {
    fn fill(&mut self) -> Result<(), FetchError> {
        if self.pos < self.buf.len() {
            return Ok(());
        }
        let slice = remaining(self.deadline)?.min(IO_SLICE);
        let _ = self.tls.sock.set_read_timeout(Some(slice));
        self.buf.resize(16 * 1024, 0);
        self.pos = 0;
        loop {
            match self.tls.read(&mut self.buf) {
                Ok(0) => {
                    self.buf.clear();
                    return Err(FetchError::Response("connection closed early".into()));
                }
                Ok(n) => {
                    self.buf.truncate(n);
                    return Ok(());
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    self.buf.clear();
                    // The slice ended; the overall deadline decides whether to wait again.
                    remaining(self.deadline)?;
                    return Err(FetchError::Timeout("read"));
                }
                Err(e) => {
                    self.buf.clear();
                    return Err(tls_or_io(e));
                }
            }
        }
    }

    fn byte(&mut self) -> Result<u8, FetchError> {
        self.fill()?;
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(b)
    }

    /// A line up to `max` bytes, without its CRLF.
    fn line(&mut self, max: usize) -> Result<String, FetchError> {
        let mut out = Vec::new();
        loop {
            let b = self.byte()?;
            if b == b'\n' {
                if out.last() == Some(&b'\r') {
                    out.pop();
                }
                return String::from_utf8(out)
                    .map_err(|_| FetchError::Response("non-UTF-8 line".into()));
            }
            out.push(b);
            if out.len() > max {
                return Err(FetchError::Response("line too long".into()));
            }
        }
    }

    /// Copies exactly `n` body bytes to `sink`.
    fn copy(&mut self, mut n: u64, sink: &mut dyn Write) -> Result<(), FetchError> {
        while n > 0 {
            self.fill()?;
            let avail = &self.buf[self.pos..];
            let take = usize::try_from(n).map_or(avail.len(), |n| n.min(avail.len()));
            sink.write_all(&avail[..take])?;
            self.pos += take;
            n -= take as u64;
        }
        Ok(())
    }
}

fn tls_or_io(e: io::Error) -> FetchError {
    // rustls reports certificate and protocol failures as `InvalidData`/`Other` io errors.
    match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => FetchError::Timeout("network"),
        io::ErrorKind::InvalidData | io::ErrorKind::Other => FetchError::Tls(e.to_string()),
        _ => FetchError::Io(e),
    }
}

struct Head {
    status: u16,
    content_length: Option<u64>,
    chunked: bool,
    location: Option<String>,
}

fn read_head(rd: &mut Rd) -> Result<Head, FetchError> {
    let bad = |m: &str| FetchError::Response(m.to_string());
    let status_line = rd.line(MAX_LINE)?;
    let mut parts = status_line.split(' ');
    let (Some(version), Some(code)) = (parts.next(), parts.next()) else {
        return Err(bad("malformed status line"));
    };
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(bad("not HTTP/1.x"));
    }
    let status: u16 = code.parse().map_err(|_| bad("malformed status code"))?;
    let mut head = Head {
        status,
        content_length: None,
        chunked: false,
        location: None,
    };
    let mut total = status_line.len();
    loop {
        let line = rd.line(MAX_LINE * 8)?;
        total += line.len() + 2;
        if total > MAX_HEAD {
            return Err(bad("response head too large"));
        }
        if line.is_empty() {
            return Ok(head);
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(bad("malformed header"));
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => {
                let n: u64 = value.parse().map_err(|_| bad("malformed content-length"))?;
                if head.content_length.is_some_and(|old| old != n) {
                    return Err(bad("conflicting content-length"));
                }
                head.content_length = Some(n);
            }
            "transfer-encoding" => {
                if value.eq_ignore_ascii_case("chunked") {
                    head.chunked = true;
                } else {
                    return Err(bad("unsupported transfer-encoding"));
                }
            }
            "content-encoding" if !value.eq_ignore_ascii_case("identity") => {
                return Err(bad("content-encoding is not identity"));
            }
            "location" => head.location = Some(value.to_string()),
            _ => {}
        }
    }
}

/// `GET url` into `sink`, following redirects to release hosts, at most `max_body` bytes.
/// Returns the number of body bytes written.
pub(super) fn get(
    cfg: &Config,
    url: &Url,
    deadline: Instant,
    max_body: u64,
    sink: &mut dyn Write,
) -> Result<u64, FetchError> {
    let mut url = url.clone();
    for _ in 0..=MAX_REDIRECTS {
        if !cfg.host_allowed(&url.host) {
            return Err(FetchError::Refused(format!(
                "`{}` is not a release host",
                url.host
            )));
        }
        if url.port != cfg.port || !path_ok(&url.path) {
            return Err(FetchError::Refused("unexpected port or path".into()));
        }
        let mut tls = connect(cfg, &url, deadline)?;
        let host_header = if url.port == 443 {
            url.host.clone()
        } else {
            format!("{}:{}", url.host, url.port)
        };
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: hx-update-fetcher\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
            url.path
        );
        let _ = tls.sock.set_write_timeout(Some(IO_SLICE));
        tls.write_all(req.as_bytes()).map_err(tls_or_io)?;
        tls.flush().map_err(tls_or_io)?;
        let mut rd = Rd {
            tls,
            buf: Vec::new(),
            pos: 0,
            deadline,
        };
        let head = read_head(&mut rd)?;
        match head.status {
            200 => return read_body(&mut rd, &head, max_body, sink),
            301 | 302 | 303 | 307 | 308 => {
                let loc = head
                    .location
                    .ok_or_else(|| FetchError::Response("redirect without Location".into()))?;
                url = if loc.starts_with('/') {
                    Url::https(&url.host, url.port, &loc)
                } else {
                    let mut next = parse_url(&loc)?;
                    // A redirect names a host; the port is always the configured one.
                    if next.port == 443 {
                        next.port = cfg.port;
                    }
                    next
                };
            }
            other => {
                return Err(FetchError::Response(format!("status {other}")));
            }
        }
    }
    Err(FetchError::Refused("too many redirects".into()))
}

fn read_body(
    rd: &mut Rd,
    head: &Head,
    max_body: u64,
    sink: &mut dyn Write,
) -> Result<u64, FetchError> {
    if head.chunked {
        let mut total = 0u64;
        loop {
            let line = rd.line(MAX_LINE)?;
            let hex = line.split(';').next().unwrap_or("").trim();
            if hex.is_empty() || hex.len() > 16 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(FetchError::Response("malformed chunk size".into()));
            }
            let size = u64::from_str_radix(hex, 16)
                .map_err(|_| FetchError::Response("malformed chunk size".into()))?;
            if size == 0 {
                // Trailers, up to a blank line.
                for _ in 0..32 {
                    if rd.line(MAX_LINE)?.is_empty() {
                        return Ok(total);
                    }
                }
                return Err(FetchError::Response("too many trailers".into()));
            }
            total = total
                .checked_add(size)
                .filter(|t| *t <= max_body)
                .ok_or(FetchError::Quota("response body"))?;
            rd.copy(size, sink)?;
            if !rd.line(MAX_LINE)?.is_empty() {
                return Err(FetchError::Response("missing chunk terminator".into()));
            }
        }
    }
    let Some(n) = head.content_length else {
        return Err(FetchError::Response(
            "the body is not framed (no Content-Length, not chunked)".into(),
        ));
    };
    if n > max_body {
        return Err(FetchError::Quota("response body"));
    }
    rd.copy(n, sink)?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_https_with_a_plain_host() {
        let u = parse_url("https://objects.githubusercontent.com/a/b?x=1").unwrap();
        assert_eq!(u.host, "objects.githubusercontent.com");
        assert_eq!(u.port, 443);
        assert_eq!(u.path, "/a/b?x=1");
        assert_eq!(parse_url("https://github.com:8443").unwrap().port, 8443);
        for bad in [
            "http://github.com/x",
            "ftp://github.com/x",
            "https://user@github.com/x",
            "https://[::1]/x",
            "https://github.com:99999/x",
            "https://git hub.com/x",
            "https:///x",
            "https://github.com/a b",
            "//github.com/x",
        ] {
            assert!(parse_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn only_global_addresses_are_acceptable() {
        let no = [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "198.18.0.1",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd12::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::7f00:1",
            "64:ff9b:1::1",
            "2002:7f00:1::1",
            "2002::1",
            "::7f00:1",
            "::10.0.0.1",
            "fec0::1",
            "febf::1",
            "2001:db8::1",
        ];
        for a in no {
            assert!(!is_global(&a.parse().unwrap()), "{a}");
        }
        for a in ["140.82.112.3", "8.8.8.8", "2606:4700::1111", "2a00:1450::1", "2001:4860::1"] {
            assert!(is_global(&a.parse().unwrap()), "{a}");
        }
    }
}
