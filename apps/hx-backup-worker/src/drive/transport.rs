//! The helper's one HTTP path (ipc.md §29 c, g and "Permanent delete").
//!
//! OpenDAL's `gdrive` service builds the requests; every one of them passes [`GoogleTransport`]:
//!
//! 1. [`check_uri`] refuses anything but `https` to `www.googleapis.com` or `oauth2.googleapis.com`
//!    on the default port, without user information;
//! 2. the one request of OpenDAL's deleter that moves a file to the trash
//!    (`PATCH /drive/v3/files/{id}` with `{"trashed":true}`) becomes `DELETE /drive/v3/files/{id}`;
//! 3. the body of an upload is released in chunks of at most 64 KiB at the pace of the shared
//!    [`UploadRate`];
//! 4. what Drive really answered (status, `reason`, `Retry-After`, the token endpoint's `error`)
//!    is recorded for [`super::retry`]; the body of an error is read (at most 64 KiB) for that and
//!    never kept.
//!
//! The client (`hyper-util`, on the connector of [`super::connector`]) follows no redirect, has no
//! proxy and speaks HTTP/1.1 over TLS 1.3 only (`rustls`, `ring`) to global unicast addresses of the
//! two names. Nothing here logs or returns a URL: OpenDAL's token request carries the refresh token
//! in its query string.

use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use opendal::{Buffer, HttpBody, HttpTransport};

use super::connector::Connector;
pub use super::connector::{BuildError, HttpConfig};
use super::rate::{CHUNK, UploadRate};
use super::retry::{Observed, Timing, record};

/// The Drive API host.
pub const API_HOST: &str = "www.googleapis.com";
/// The OAuth token host.
pub const TOKEN_HOST: &str = "oauth2.googleapis.com";

/// Which of the two hosts a request is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Host {
    /// `www.googleapis.com`.
    Api,
    /// `oauth2.googleapis.com`.
    Token,
}

/// Why a request was refused before it left the process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("request refused: {0}")]
pub struct Refused(pub &'static str);

/// The host restriction of the binary (ipc.md §24, §29 c).
///
/// # Errors
/// [`Refused`] for anything but `https://www.googleapis.com/...` or `https://oauth2.googleapis.com/...`
/// on the default port, with no user information.
pub fn check_uri(uri: &http::Uri) -> Result<Host, Refused> {
    if uri.scheme_str() != Some("https") {
        return Err(Refused("scheme is not https"));
    }
    let Some(auth) = uri.authority() else {
        return Err(Refused("no authority"));
    };
    if auth.as_str().contains('@') {
        return Err(Refused("user information"));
    }
    if auth.port().is_some_and(|p| p.as_u16() != 443) {
        return Err(Refused("port"));
    }
    match auth.host() {
        API_HOST => Ok(Host::Api),
        TOKEN_HOST => Ok(Host::Token),
        _ => Err(Refused("host is not allowed")),
    }
}

/// Is `ip` a global unicast address (the only kind the helper connects to)?
#[must_use]
pub fn is_global_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(a.is_unspecified()
                || a.is_loopback()
                || a.is_private()
                || a.is_link_local()
                || a.is_multicast()
                || a.is_broadcast()
                || a.is_documentation()
                || (o[0] == 100 && (64..128).contains(&o[1]))
                || o[0] == 0
                || o[0] >= 240
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19)))
        }
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return is_global_unicast(IpAddr::V4(v4));
            }
            let s = a.segments();
            !(a.is_unspecified()
                || a.is_loopback()
                || a.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local
                || (s[0] & 0xffc0) == 0xfe80 // link local
                || (s[0] == 0x64 && s[1] == 0xff9b) // NAT64
                || (s[0] == 0x2001 && s[1] == 0x0db8)) // documentation
                && (s[0] & 0xe000) == 0x2000 // 2000::/3 is what is allocated as global unicast
        }
    }
}

/// A piece of an upload body: at most [`CHUNK`] bytes, released at the shared rate.
pub struct UploadBody {
    chunks: Buffer,
    current: Bytes,
    pending: Option<Bytes>,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    remaining: u64,
    rate: Option<Arc<UploadRate>>,
}

impl UploadBody {
    fn new(body: Buffer, rate: Option<Arc<UploadRate>>) -> Self {
        Self {
            remaining: body.len() as u64,
            chunks: body,
            current: Bytes::new(),
            pending: None,
            sleep: None,
            rate,
        }
    }
}

impl Body for UploadBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = &mut *self;
        loop {
            if let Some(s) = this.sleep.as_mut() {
                ready!(s.as_mut().poll(cx));
                this.sleep = None;
                if let Some(piece) = this.pending.take() {
                    return Poll::Ready(Some(Ok(Frame::data(piece))));
                }
            }
            if this.current.is_empty() {
                match this.chunks.next() {
                    Some(b) => this.current = b,
                    None => return Poll::Ready(None),
                }
                continue;
            }
            let n = this.current.len().min(CHUNK);
            let piece = this.current.split_to(n);
            this.remaining = this.remaining.saturating_sub(n as u64);
            let wait = this.rate.as_ref().map_or(Duration::ZERO, |r| r.reserve(n));
            if wait.is_zero() {
                return Poll::Ready(Some(Ok(Frame::data(piece))));
            }
            this.pending = Some(piece);
            this.sleep = Some(Box::pin(tokio::time::sleep(wait)));
        }
    }

    fn size_hint(&self) -> SizeHint {
        let pending = self.pending.as_ref().map_or(0, |p| p.len() as u64);
        SizeHint::with_exact(self.remaining + pending + self.current.len() as u64)
    }
}

type Client = hyper_util::client::legacy::Client<Connector, UploadBody>;

/// The transport OpenDAL runs on. Cheap to clone.
#[derive(Clone)]
pub struct GoogleTransport {
    client: Client,
    rate: Arc<UploadRate>,
    timing: Timing,
    #[cfg(feature = "test-hooks")]
    api_addr: Option<String>,
}

impl std::fmt::Debug for GoogleTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoogleTransport").finish_non_exhaustive()
    }
}

fn refuse(r: Refused) -> opendal::Error {
    // Not temporary: a refused request is never retried.
    record(Observed {
        status: 400,
        ..Observed::default()
    });
    opendal::Error::new(opendal::ErrorKind::Unexpected, r.to_string())
}

fn network_error(what: &'static str) -> opendal::Error {
    record(Observed::default());
    opendal::Error::new(opendal::ErrorKind::Unexpected, what).set_temporary()
}

fn sanitized(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(64)
        .collect()
}

/// `reason` of a Drive error body and `error` of an OAuth one, sanitized.
fn parse_error_body(body: &[u8]) -> (String, String) {
    let v: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    let reason = v["error"]["errors"][0]["reason"]
        .as_str()
        .or_else(|| v["error"]["status"].as_str())
        .map(sanitized)
        .unwrap_or_default();
    let oauth = v["error"].as_str().map(sanitized).unwrap_or_default();
    (reason, oauth)
}

fn is_trash_request(req: &Request<Buffer>) -> bool {
    if req.method() != http::Method::PATCH {
        return false;
    }
    let Some(id) = req.uri().path().strip_prefix("/drive/v3/files/") else {
        return false;
    };
    if id.is_empty()
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return false;
    }
    let body = req.body().to_bytes();
    serde_json::from_slice::<serde_json::Value>(&body)
        .is_ok_and(|v| v == serde_json::json!({"trashed": true}))
}

fn single_buffer_body(bytes: Bytes) -> HttpBody {
    let buf = Buffer::from(bytes);
    let len = buf.len() as u64;
    HttpBody::new(
        futures_util::stream::iter(vec![Ok::<Buffer, opendal::Error>(buf)]),
        Some(len),
    )
}

impl GoogleTransport {
    /// Builds the client.
    ///
    /// # Errors
    /// [`BuildError`] when TLS cannot be set up (for example no root certificates).
    pub fn new(
        cfg: &HttpConfig,
        rate: Arc<UploadRate>,
        timing: Timing,
    ) -> Result<Self, BuildError> {
        let connector = Connector::new(cfg, timing.attempt_base)?;
        // No redirect following, no proxy and no HTTP/2: this client has none of them to turn off.
        let client = hyper_util::client::legacy::Client::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(2)
            .build::<_, UploadBody>(connector);
        Ok(Self {
            client,
            rate,
            timing,
            #[cfg(feature = "test-hooks")]
            api_addr: cfg.api_addr.clone(),
        })
    }

    /// The URI to connect to: the request's own, or the test override.
    fn target(&self, uri: &http::Uri) -> Result<http::Uri, opendal::Error> {
        #[cfg(feature = "test-hooks")]
        if let Some(addr) = &self.api_addr {
            let pq = uri
                .path_and_query()
                .map_or("/", http::uri::PathAndQuery::as_str);
            return format!("https://{addr}{pq}")
                .parse()
                .map_err(|_| opendal::Error::new(opendal::ErrorKind::Unexpected, "bad url"));
        }
        Ok(uri.clone())
    }
}

/// Reads at most `cap` bytes of a body (the rest is read and dropped), or fails.
async fn read_capped(mut body: Incoming, cap: usize) -> Result<Vec<u8>, ()> {
    let mut buf = Vec::new();
    while let Some(frame) = body.frame().await {
        if let Ok(d) = frame.map_err(|_| ())?.into_data()
            && buf.len() < cap
        {
            let room = cap - buf.len();
            buf.extend_from_slice(&d[..d.len().min(room)]);
        }
    }
    Ok(buf)
}

impl HttpTransport for GoogleTransport {
    async fn fetch(&self, mut req: Request<Buffer>) -> opendal::Result<Response<HttpBody>> {
        let host = check_uri(req.uri()).map_err(refuse)?;
        let trash = is_trash_request(&req);
        let uri = req.uri().clone();
        let is_upload = uri.path().starts_with("/upload/");
        let target = self.target(&uri)?;
        let method = if trash {
            http::Method::DELETE
        } else {
            req.method().clone()
        };
        let mut headers = std::mem::take(req.headers_mut());
        headers.remove(http::header::HOST);
        headers.insert(
            http::header::USER_AGENT,
            http::HeaderValue::from_static("hx-drive"),
        );
        let body = if trash {
            headers.remove(http::header::CONTENT_TYPE);
            headers.remove(http::header::CONTENT_LENGTH);
            Buffer::new()
        } else {
            std::mem::take(req.body_mut())
        };
        let body_len = body.len();
        let rate = (is_upload && !body.is_empty()).then(|| self.rate.clone());
        let mut hreq = hyper::Request::builder()
            .method(method)
            .uri(target)
            .body(UploadBody::new(body, rate))
            .map_err(|_| opendal::Error::new(opendal::ErrorKind::Unexpected, "bad request"))?;
        *hreq.headers_mut() = headers;
        let timeout = self.timing.attempt_timeout(body_len as u64);
        let resp = match tokio::time::timeout(timeout, self.client.request(hreq)).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => return Err(network_error("send failed")),
            Err(_) => return Err(network_error("no response in time")),
        };
        let status = resp.status();
        let mut obs = Observed {
            status: status.as_u16(),
            token_endpoint: host == Host::Token,
            retry_after: resp
                .headers()
                .get(http::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map(|s| Duration::from_secs(s.min(3600))),
            ..Observed::default()
        };
        let (parts, incoming) = resp.into_parts();
        if status.as_u16() >= 400 {
            // Read the error body (bounded) for its reason; it is rebuilt for OpenDAL, which maps
            // the status itself.
            let Ok(buf) = read_capped(incoming, 64 * 1024).await else {
                return Err(network_error("error body"));
            };
            let (reason, oauth) = parse_error_body(&buf);
            obs.reason = reason;
            obs.oauth_error = oauth;
            record(obs);
            let mut out = Response::builder()
                .status(status)
                .version(parts.version)
                .extension(uri);
            *out.headers_mut().expect("builder is valid") = parts.headers;
            return Ok(out
                .body(single_buffer_body(Bytes::from(buf)))
                .expect("static parts"));
        }
        record(obs);
        if trash {
            // DELETE answers 204 with no body; OpenDAL waits for the 200 of its PATCH.
            return Ok(Response::builder()
                .status(http::StatusCode::OK)
                .extension(uri)
                .body(single_buffer_body(Bytes::from_static(b"{}")))
                .expect("static parts"));
        }
        let content_length = parts
            .headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        let mut out = Response::builder()
            .status(status)
            .version(parts.version)
            .extension(uri);
        *out.headers_mut().expect("builder is valid") = parts.headers;
        // OpenDAL wants a `Sync` stream and hyper's body is not: a task relays it, two chunks
        // ahead at most. It ends when the stream is dropped or the body ends.
        let (tx, rx) = tokio::sync::mpsc::channel::<opendal::Result<Buffer>>(2);
        tokio::spawn(async move {
            let mut body = incoming;
            while let Some(frame) = body.frame().await {
                let item = match frame {
                    Ok(f) => match f.into_data() {
                        Ok(d) if !d.is_empty() => Ok(Buffer::from(d)),
                        _ => continue,
                    },
                    Err(_) => Err(opendal::Error::new(
                        opendal::ErrorKind::Unexpected,
                        "read from the response",
                    )
                    .set_temporary()),
                };
                let failed = item.is_err();
                if tx.send(item).await.is_err() || failed {
                    return;
                }
            }
        });
        Ok(out
            .body(HttpBody::new(RelayStream(rx), content_length))
            .expect("static parts"))
    }
}

/// The receiving end of the body relay, as a `Stream`.
struct RelayStream(tokio::sync::mpsc::Receiver<opendal::Result<Buffer>>);

impl futures_util::Stream for RelayStream {
    type Item = opendal::Result<Buffer>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.poll_recv(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(s: &str) -> http::Uri {
        s.parse().unwrap()
    }

    #[test]
    fn only_the_two_google_hosts_over_https_on_the_default_port() {
        assert_eq!(
            check_uri(&uri("https://www.googleapis.com/drive/v3/files")),
            Ok(Host::Api)
        );
        assert_eq!(
            check_uri(&uri("https://oauth2.googleapis.com/token?x=1")),
            Ok(Host::Token)
        );
        assert_eq!(
            check_uri(&uri("https://www.googleapis.com:443/drive/v3/files")),
            Ok(Host::Api)
        );
        for bad in [
            "http://www.googleapis.com/x",
            "https://www.googleapis.com:8443/x",
            "https://evil.example/x",
            "https://www.googleapis.com.evil.example/x",
            "https://evil.example@www.googleapis.com/x",
            "https://user:pw@www.googleapis.com/x",
            "https://accounts.google.com/x",
            "https://googleapis.com/x",
            "https://WWW.EVIL.com/x",
            "https://127.0.0.1/x",
            "https://[::1]/x",
            "/relative",
        ] {
            assert!(check_uri(&uri(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn only_global_unicast_addresses_pass() {
        for ok in ["142.250.74.10", "2a00:1450:4001:80b::200a", "8.8.8.8"] {
            assert!(is_global_unicast(ok.parse().unwrap()), "{ok}");
        }
        for bad in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "fe80::1",
            "fc00::1",
            "fd12::1",
            "::ffff:10.0.0.1",
            "::",
            "ff02::1",
            "64:ff9b::1",
        ] {
            assert!(!is_global_unicast(bad.parse().unwrap()), "{bad}");
        }
    }

    #[test]
    fn exactly_the_trash_request_is_recognised() {
        let trash = |m: &str, path: &str, body: &str| {
            let r = Request::builder()
                .method(m)
                .uri(format!("https://www.googleapis.com{path}"))
                .body(Buffer::from(Bytes::from(body.to_owned())))
                .unwrap();
            is_trash_request(&r)
        };
        assert!(trash(
            "PATCH",
            "/drive/v3/files/1AbC_-x",
            r#"{"trashed":true}"#
        ));
        assert!(trash(
            "PATCH",
            "/drive/v3/files/1AbC",
            r#"{ "trashed" : true }"#
        ));
        assert!(!trash(
            "PATCH",
            "/drive/v3/files/1AbC",
            r#"{"trashed":false}"#
        ));
        assert!(!trash(
            "PATCH",
            "/drive/v3/files/1AbC",
            r#"{"trashed":true,"name":"x"}"#
        ));
        assert!(!trash(
            "PATCH",
            "/drive/v3/files/1AbC/copy",
            r#"{"trashed":true}"#
        ));
        assert!(!trash("PATCH", "/drive/v3/files/", r#"{"trashed":true}"#));
        assert!(!trash(
            "POST",
            "/drive/v3/files/1AbC",
            r#"{"trashed":true}"#
        ));
        assert!(!trash(
            "PATCH",
            "/upload/drive/v3/files/1AbC",
            r#"{"trashed":true}"#
        ));
    }

    #[test]
    fn error_bodies_yield_only_sanitized_reasons() {
        let drive = br#"{"error":{"code":403,"message":"secret text","errors":[{"reason":"dailyLimitExceeded"}]}}"#;
        assert_eq!(
            parse_error_body(drive),
            ("dailyLimitExceeded".to_owned(), String::new())
        );
        let oauth = br#"{"error":"invalid_grant","error_description":"Token has been revoked"}"#;
        assert_eq!(
            parse_error_body(oauth),
            (String::new(), "invalid_grant".to_owned())
        );
        let hostile = br#"{"error":{"errors":[{"reason":"a b\n<script>c"}]}}"#;
        assert_eq!(parse_error_body(hostile).0, "abscriptc");
        assert_eq!(
            parse_error_body(b"not json"),
            (String::new(), String::new())
        );
    }
}
