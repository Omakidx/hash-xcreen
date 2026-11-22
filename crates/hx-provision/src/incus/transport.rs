//! HTTP over the Incus unix socket.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::channel::Channel;
use http_body_util::{BodyExt, Full, Limited};
use hyper::Method;
use hyper::body::Frame;
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;

use super::error::IncusError;

/// Largest response body accepted (exec output files and image metadata stay far below this).
pub const MAX_BODY: usize = 32 * 1024 * 1024;

/// One HTTP request to the daemon.
///
/// `Debug` prints only the body length: bodies carry secrets (the stdin file of `chpasswd`).
#[derive(Clone)]
pub struct Request {
    /// HTTP method.
    pub method: Method,
    /// Path and query, e.g. `/1.0/instances?recursion=1`.
    pub path: String,
    /// Extra headers (file API metadata).
    pub headers: Vec<(&'static str, String)>,
    /// Body; JSON unless `content_type` says otherwise.
    pub body: Bytes,
    /// Content type of the body, when there is one.
    pub content_type: Option<&'static str>,
    /// Give up after this long (connect, send and read the whole response).
    pub timeout: Duration,
    /// Refuse response bodies larger than this ([`MAX_BODY`] when `None`).
    pub max_response: Option<usize>,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("headers", &self.headers)
            .field("body", &format_args!("<{} bytes>", self.body.len()))
            .field("content_type", &self.content_type)
            .field("timeout", &self.timeout)
            .field("max_response", &self.max_response)
            .finish()
    }
}

/// The daemon's reply.
#[derive(Debug, Clone)]
pub struct Response {
    /// HTTP status.
    pub status: u16,
    /// Whole body.
    pub body: Bytes,
    /// Response headers, names lower-cased.
    pub headers: std::collections::BTreeMap<String, String>,
}

/// Something that can carry a [`Request`] to Incus. The real implementation is [`UnixTransport`];
/// tests use scripted fakes.
pub trait Transport: Send + Sync {
    /// Send one request and read the whole response.
    fn send(&self, request: Request) -> impl Future<Output = Result<Response, IncusError>> + Send;

    /// Send `head` with the first `len` bytes of `body` as its body, streamed: the file is read
    /// in [`UPLOAD_FRAME`]-sized pieces and never held in memory as a whole. `head.body` is
    /// ignored. The default refuses, so scripted fakes need not implement it.
    fn send_file(
        &self,
        head: Request,
        body: std::fs::File,
        len: u64,
    ) -> impl Future<Output = Result<Response, IncusError>> + Send {
        async move {
            let _ = (head, body, len);
            Err(IncusError::Unsupported("streaming upload".into()))
        }
    }
}

/// Size of one frame of a streamed upload: 1 MiB.
pub const UPLOAD_FRAME: usize = 1024 * 1024;

/// Talks to the Incus daemon over its unix socket (`/var/lib/incus/unix.socket`).
///
/// One connection per request: simple, and immune to idle-connection resets.
#[derive(Debug, Clone)]
pub struct UnixTransport {
    path: PathBuf,
}

impl UnixTransport {
    /// Default socket path of the distro packages.
    pub const DEFAULT_SOCKET: &'static str = "/var/lib/incus/unix.socket";

    /// Use the socket at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The socket path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    async fn exchange(&self, request: Request) -> Result<Response, IncusError> {
        let body = Full::new(request.body.clone());
        self.exchange_with(request, body, None).await
    }

    /// Stream `len` bytes of `file` as the request body, reading with `pread` (`read_at`, so the
    /// file offset is never shared) in [`UPLOAD_FRAME`] pieces on the blocking pool, two frames
    /// ahead of the socket at most.
    async fn exchange_file(
        &self,
        request: Request,
        file: std::fs::File,
        len: u64,
    ) -> Result<Response, IncusError> {
        let (mut tx, body) = Channel::<Bytes, std::io::Error>::new(2);
        let file = std::sync::Arc::new(file);
        let reader = tokio::spawn(async move {
            let mut offset: u64 = 0;
            while offset < len {
                let want = usize::try_from((len - offset).min(UPLOAD_FRAME as u64))
                    .unwrap_or(UPLOAD_FRAME);
                let f = file.clone();
                let read = tokio::task::spawn_blocking(move || {
                    use std::os::unix::fs::FileExt;
                    let mut buf = vec![0u8; want];
                    let mut got = 0;
                    while got < want {
                        match f.read_at(&mut buf[got..], offset + got as u64) {
                            Ok(0) => break,
                            Ok(n) => got += n,
                            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                            Err(e) => return Err(e),
                        }
                    }
                    buf.truncate(got);
                    Ok(buf)
                })
                .await;
                let buf = match read {
                    Ok(Ok(b)) if !b.is_empty() => b,
                    Ok(Ok(_)) => {
                        tx.abort(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "the file is shorter than its declared length",
                        ));
                        return;
                    }
                    Ok(Err(e)) => {
                        tx.abort(e);
                        return;
                    }
                    Err(e) => {
                        tx.abort(std::io::Error::other(e.to_string()));
                        return;
                    }
                };
                offset += buf.len() as u64;
                if tx.send(Frame::data(Bytes::from(buf))).await.is_err() {
                    return; // the exchange ended; nobody is reading
                }
            }
        });
        let result = self.exchange_with(request, body, Some(len)).await;
        reader.abort();
        result
    }

    async fn exchange_with<B>(
        &self,
        request: Request,
        body: B,
        content_length: Option<u64>,
    ) -> Result<Response, IncusError>
    where
        B: hyper::body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let stream = UnixStream::connect(&self.path)
            .await
            .map_err(|e| IncusError::Connect {
                path: self.path.display().to_string(),
                message: e.to_string(),
            })?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| IncusError::Http(e.to_string()))?;
        let driver = tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut builder = hyper::Request::builder()
            .method(request.method)
            .uri(&request.path)
            .header("Host", "incus")
            .header("Accept", "application/json, */*");
        if let Some(ct) = request.content_type {
            builder = builder.header("Content-Type", ct);
        }
        if let Some(n) = content_length {
            builder = builder.header("Content-Length", n);
        }
        for (k, v) in &request.headers {
            builder = builder.header(*k, v.as_str());
        }
        let req = builder
            .body(body)
            .map_err(|e| IncusError::InvalidArgument(format!("bad request: {e}")))?;
        let limit = request.max_response.unwrap_or(MAX_BODY);
        let result = async {
            let resp = sender
                .send_request(req)
                .await
                .map_err(|e| IncusError::Http(e.to_string()))?;
            let status = resp.status().as_u16();
            let headers = resp
                .headers()
                .iter()
                .filter_map(|(k, v)| {
                    v.to_str()
                        .ok()
                        .map(|v| (k.as_str().to_ascii_lowercase(), v.to_string()))
                })
                .collect();
            let body = Limited::new(resp.into_body(), limit)
                .collect()
                .await
                .map_err(|e| {
                    if e.downcast_ref::<http_body_util::LengthLimitError>()
                        .is_some()
                    {
                        IncusError::TooLarge { limit }
                    } else {
                        IncusError::Http(format!("reading response body: {e}"))
                    }
                })?
                .to_bytes();
            Ok(Response {
                status,
                body,
                headers,
            })
        }
        .await;
        driver.abort();
        result
    }
}

impl Transport for UnixTransport {
    async fn send(&self, request: Request) -> Result<Response, IncusError> {
        let timeout = request.timeout;
        let what = format!("{} {}", request.method, request.path);
        match tokio::time::timeout(timeout, self.exchange(request)).await {
            Ok(r) => r,
            Err(_) => Err(IncusError::Timeout {
                what,
                after: timeout,
            }),
        }
    }

    async fn send_file(
        &self,
        head: Request,
        body: std::fs::File,
        len: u64,
    ) -> Result<Response, IncusError> {
        let timeout = head.timeout;
        let what = format!("{} {}", head.method, head.path);
        match tokio::time::timeout(timeout, self.exchange_file(head, body, len)).await {
            Ok(r) => r,
            Err(_) => Err(IncusError::Timeout {
                what,
                after: timeout,
            }),
        }
    }
}
