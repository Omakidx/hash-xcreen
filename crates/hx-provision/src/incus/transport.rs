//! HTTP over the Incus unix socket.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::Method;
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;

use super::error::IncusError;

/// Largest response body accepted (exec output files and image metadata stay far below this).
pub const MAX_BODY: usize = 32 * 1024 * 1024;

/// One HTTP request to the daemon.
#[derive(Debug, Clone)]
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
}

/// The daemon's reply.
#[derive(Debug, Clone)]
pub struct Response {
    /// HTTP status.
    pub status: u16,
    /// Whole body.
    pub body: Bytes,
}

/// Something that can carry a [`Request`] to Incus. The real implementation is [`UnixTransport`];
/// tests use scripted fakes.
pub trait Transport: Send + Sync {
    /// Send one request and read the whole response.
    fn send(&self, request: Request) -> impl Future<Output = Result<Response, IncusError>> + Send;
}

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
        for (k, v) in &request.headers {
            builder = builder.header(*k, v.as_str());
        }
        let req = builder
            .body(Full::new(request.body))
            .map_err(|e| IncusError::InvalidArgument(format!("bad request: {e}")))?;
        let result = async {
            let resp = sender
                .send_request(req)
                .await
                .map_err(|e| IncusError::Http(e.to_string()))?;
            let status = resp.status().as_u16();
            let body = Limited::new(resp.into_body(), MAX_BODY)
                .collect()
                .await
                .map_err(|e| IncusError::Http(format!("reading response body: {e}")))?
                .to_bytes();
            Ok(Response { status, body })
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
}
