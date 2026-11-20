//! hx Google Drive backend: OpenDAL's `gdrive` service behind an instrumented HTTP transport and a
//! retry/rate-limit wrapper.
//!
//! Why this exists (S4 Drive run): OpenDAL marks only 5xx, 405 and one exact message as retryable and
//! `rustic_backend` additionally swallows listing errors, so HTTP 429 and 403 `rateLimitExceeded` /
//! `userRateLimitExceeded` / `dailyLimitExceeded` would abort a backup. This module owns:
//!
//! * [`Transport`]: wraps OpenDAL's reqwest transport; counts API calls and bytes per request category,
//!   records real non-2xx replies (status and Drive `reason`, never headers or tokens), bounds every request
//!   with a timeout, and injects faults for tests ([`Faults`]).
//! * [`classify`] + [`Retrier`]: HTTP 429 and 403 rate-limit replies retry with exponential backoff and
//!   jitter (honouring `Retry-After`), `dailyLimitExceeded` pauses all callers and probes again, quota and
//!   permission errors are fatal.
//! * [`HxDrive`]: rustic's `ReadBackend`/`WriteBackend` over the blocking OpenDAL operator, retrying each
//!   operation as a whole and propagating listing errors instead of returning a truncated list.

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use futures::TryStreamExt;
use http::{Request, Response};
use opendal::options::{ListOptions, ReadOptions};
use opendal::{Buffer, HttpBody, HttpTransport, HttpTransporter, OperationContext, blocking};
use opendal_http_transport_reqwest::ReqwestTransport;
use rustic_core::{
    ALL_FILE_TYPES, BytesList, ErrorKind, FileType, Id, ReadBackend, RusticError, RusticResult,
    WriteBackend,
};
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------------------------

/// OAuth client id/secret and refresh token. `Debug` never prints the values.
#[derive(Clone)]
pub struct DriveCreds {
    client_id: String,
    client_secret: String,
    refresh_token: String,
}

impl fmt::Debug for DriveCreds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DriveCreds").finish_non_exhaustive()
    }
}

impl DriveCreds {
    /// Read `client_id`, `client_secret` and `refresh_token` from a JSON file, in-process.
    pub fn from_file(path: &Path) -> Result<Self> {
        let raw = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        let v: serde_json::Value =
            serde_json::from_slice(&raw).context("token file is not JSON")?;
        let get = |k: &str| -> Result<String> {
            Ok(v[k]
                .as_str()
                .ok_or_else(|| anyhow!("token file lacks `{k}`"))?
                .to_string())
        };
        Ok(Self {
            client_id: get("client_id")?,
            client_secret: get("client_secret")?,
            refresh_token: get("refresh_token")?,
        })
    }

    fn options(&self, root: &str) -> Vec<(String, String)> {
        vec![
            ("root".into(), root.into()),
            ("client_id".into(), self.client_id.clone()),
            ("client_secret".into(), self.client_secret.clone()),
            ("refresh_token".into(), self.refresh_token.clone()),
        ]
    }
}

// ---------------------------------------------------------------------------------------------
// Statistics and fault injection
// ---------------------------------------------------------------------------------------------

/// A real (or injected) non-2xx Drive reply. No headers, no credentials.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ApiError {
    pub category: String,
    pub status: u16,
    pub reason: String,
    pub message: String,
    pub injected: bool,
}

#[derive(Default)]
pub struct Stats {
    /// Requests that reached the transport (including injected ones).
    pub calls: AtomicU64,
    pub injected: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub retries: AtomicU64,
    pub slept_ms: AtomicU64,
    pub daily_pauses: AtomicU64,
    by_category: Mutex<BTreeMap<String, u64>>,
    by_status: Mutex<BTreeMap<u16, u64>>,
    retry_by_class: Mutex<BTreeMap<String, u64>>,
    errors: Mutex<Vec<ApiError>>,
}

impl Stats {
    pub fn snapshot(&self) -> serde_json::Value {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let errs = self.errors.lock().unwrap();
        serde_json::json!({
            "api_calls": g(&self.calls), "injected_faults": g(&self.injected),
            "bytes_up": g(&self.bytes_up), "bytes_down": g(&self.bytes_down),
            "retries": g(&self.retries), "retry_sleep_ms": g(&self.slept_ms),
            "daily_pauses": g(&self.daily_pauses),
            "by_category": *self.by_category.lock().unwrap(),
            "by_status": *self.by_status.lock().unwrap(),
            "retries_by_class": *self.retry_by_class.lock().unwrap(),
            "real_api_errors": errs.iter().filter(|e| !e.injected).collect::<Vec<_>>(),
            "injected_error_count": errs.iter().filter(|e| e.injected).count(),
        })
    }
    #[cfg(test)]
    pub fn count_category(&self, cat: &str) -> u64 {
        *self.by_category.lock().unwrap().get(cat).unwrap_or(&0)
    }
    #[cfg(test)]
    pub fn retries_for(&self, class: &str) -> u64 {
        *self.retry_by_class.lock().unwrap().get(class).unwrap_or(&0)
    }
}

/// One scripted fault: let `skip` matching requests pass, then answer `times` requests with `status`.
#[derive(Debug, Clone)]
pub struct FaultRule {
    pub category: String, // "*" matches every category
    pub skip: u32,
    pub times: u32,
    pub status: u16,
    pub reason: String,
    pub retry_after: Option<u32>,
}

#[derive(Default)]
pub struct Faults(Mutex<Vec<FaultRule>>);

impl Faults {
    pub fn new(rules: Vec<FaultRule>) -> Self {
        Self(Mutex::new(rules))
    }

    /// `category:status:reason:times[:skip[:retry_after]]`, comma separated, e.g.
    /// `upload.create:429:rateLimitExceeded:3,list:403:dailyLimitExceeded:1:50`.
    pub fn parse(spec: &str) -> Result<Self> {
        let mut rules = vec![];
        for r in spec.split(',').filter(|s| !s.trim().is_empty()) {
            let p: Vec<&str> = r.trim().split(':').collect();
            if p.len() < 4 {
                bail!("fault rule `{r}` needs category:status:reason:times[:skip[:retry_after]]");
            }
            rules.push(FaultRule {
                category: p[0].into(),
                status: p[1].parse()?,
                reason: p[2].into(),
                times: p[3].parse()?,
                skip: p.get(4).map(|x| x.parse()).transpose()?.unwrap_or(0),
                retry_after: p.get(5).map(|x| x.parse()).transpose()?,
            });
        }
        Ok(Self::new(rules))
    }

    fn take(&self, category: &str) -> Option<FaultRule> {
        let mut rules = self.0.lock().unwrap();
        for r in rules.iter_mut() {
            if r.times == 0 || !(r.category == "*" || r.category == category) {
                continue;
            }
            if r.skip > 0 {
                r.skip -= 1;
                return None;
            }
            r.times -= 1;
            return Some(r.clone());
        }
        None
    }
}

/// Message text of the documented Drive error payloads, used for injected faults. These strings follow
/// the Drive API error documentation; real replies seen during the run are listed in the S4 report.
fn fault_message(status: u16, reason: &str) -> String {
    match reason {
        "rateLimitExceeded" => "Rate Limit Exceeded".into(),
        "userRateLimitExceeded" => "User Rate Limit Exceeded".into(),
        "dailyLimitExceeded" => "Daily Limit Exceeded".into(),
        "storageQuotaExceeded" => "The user's Drive storage quota has been exceeded.".into(),
        "appNotAuthorizedToFile" => "The user has not granted the app access to the file.".into(),
        "backendError" => "Internal Error".into(),
        _ if status == 429 => "Too Many Requests".into(),
        _ => reason.to_string(),
    }
}

fn fault_response(rule: &FaultRule, uri: &http::Uri) -> Response<HttpBody> {
    let msg = fault_message(rule.status, &rule.reason);
    let body = serde_json::json!({"error": {"code": rule.status, "message": msg,
        "errors": [{"message": msg, "domain": "usageLimits", "reason": rule.reason}]}})
    .to_string();
    let mut b = Response::builder()
        .status(rule.status)
        .header("content-type", "application/json; charset=UTF-8")
        .extension(uri.clone());
    if let Some(ra) = rule.retry_after {
        b = b.header("retry-after", ra.to_string());
    }
    let buf = Buffer::from(Bytes::from(body));
    let len = buf.len() as u64;
    b.body(HttpBody::new(
        futures::stream::iter(vec![Ok::<Buffer, opendal::Error>(buf)]),
        Some(len),
    ))
    .expect("static response parts are valid")
}

/// Request category from method and path, for call accounting and fault matching.
pub fn categorize(method: &http::Method, uri: &http::Uri) -> &'static str {
    let host = uri.host().unwrap_or("");
    let path = uri.path();
    let q = uri.query().unwrap_or("");
    if host.contains("oauth2") {
        return "token";
    }
    if let Some(rest) = path.strip_prefix("/upload/drive/v3/files") {
        return if rest.is_empty() {
            "upload.create"
        } else {
            "upload.overwrite"
        };
    }
    match (method.as_str(), path.strip_prefix("/drive/v3/files")) {
        ("GET", Some("")) => "list",
        ("GET", Some(_)) if q.contains("alt=media") => "get.media",
        ("GET", Some(_)) => "get.meta",
        ("POST", Some("")) => "create.folder",
        ("PATCH", Some(_)) => "patch",
        ("DELETE", Some(_)) => "delete",
        ("POST", Some(_)) => "copy",
        _ => "other",
    }
}

// ---------------------------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------------------------

/// Instrumented transport around any inner transport (reqwest in production, a fake in tests).
pub struct Transport<T: HttpTransport + Clone> {
    inner: T,
    stats: Arc<Stats>,
    faults: Arc<Faults>,
}

impl<T: HttpTransport + Clone> Transport<T> {
    pub fn new(inner: T, stats: Arc<Stats>, faults: Arc<Faults>) -> Self {
        Self {
            inner,
            stats,
            faults,
        }
    }
}

/// Upper bound for one HTTP request until response headers arrive: 60 s plus 4 s per MiB sent (a link
/// slower than 256 KiB/s is treated as dead). Body reads are bounded by OpenDAL's `TimeoutLayer`.
fn request_timeout(body_len: usize) -> Duration {
    Duration::from_secs(60 + (body_len as u64 >> 20) * 4)
}

fn count(map: &Mutex<BTreeMap<String, u64>>, k: &str) {
    *map.lock().unwrap().entry(k.to_string()).or_default() += 1;
}

fn parse_drive_error(bytes: &[u8]) -> (String, String) {
    let v: serde_json::Value = serde_json::from_slice(bytes).unwrap_or_default();
    let reason = v["error"]["errors"][0]["reason"]
        .as_str()
        .or_else(|| v["error"]["status"].as_str())
        .unwrap_or("")
        .to_string();
    let message = v["error"]["message"]
        .as_str()
        .unwrap_or("")
        .chars()
        .take(200)
        .collect();
    (reason, message)
}

impl<T: HttpTransport + Clone> HttpTransport for Transport<T> {
    async fn fetch(&self, req: Request<Buffer>) -> opendal::Result<Response<HttpBody>> {
        let cat = categorize(req.method(), req.uri());
        let uri = req.uri().clone();
        self.stats.calls.fetch_add(1, Ordering::Relaxed);
        count(&self.stats.by_category, cat);
        if let Some(rule) = self.faults.take(cat) {
            self.stats.injected.fetch_add(1, Ordering::Relaxed);
            *self
                .stats
                .by_status
                .lock()
                .unwrap()
                .entry(rule.status)
                .or_default() += 1;
            self.stats.errors.lock().unwrap().push(ApiError {
                category: cat.into(),
                status: rule.status,
                reason: rule.reason.clone(),
                message: fault_message(rule.status, &rule.reason),
                injected: true,
            });
            return Ok(fault_response(&rule, &uri));
        }
        let up = req.body().len();
        self.stats.bytes_up.fetch_add(up as u64, Ordering::Relaxed);
        let resp = tokio::time::timeout(request_timeout(up), self.inner.fetch(req))
            .await
            .map_err(|_| {
                opendal::Error::new(opendal::ErrorKind::Unexpected, "request timed out")
                    .with_context("category", cat)
                    .set_temporary()
            })??;
        let status = resp.status();
        *self
            .stats
            .by_status
            .lock()
            .unwrap()
            .entry(status.as_u16())
            .or_default() += 1;
        let (parts, mut body) = resp.into_parts();
        if status.as_u16() >= 400 {
            let buf = body.to_buffer().await?;
            let (reason, message) = parse_drive_error(&buf.to_bytes());
            self.stats.errors.lock().unwrap().push(ApiError {
                category: cat.into(),
                status: status.as_u16(),
                reason,
                message,
                injected: false,
            });
            let len = buf.len() as u64;
            let body = HttpBody::new(
                futures::stream::iter(vec![Ok::<Buffer, opendal::Error>(buf)]),
                Some(len),
            );
            return Ok(Response::from_parts(parts, body));
        }
        let stats = self.stats.clone();
        let body = body.map_inner(move |s| {
            Box::new(s.inspect_ok(move |b| {
                stats
                    .bytes_down
                    .fetch_add(b.len() as u64, Ordering::Relaxed);
            }))
        });
        Ok(Response::from_parts(parts, body))
    }
}

// ---------------------------------------------------------------------------------------------
// Classification and retry
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FatalKind {
    StorageQuota,
    Auth,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Class {
    /// 5xx, 408, 405 (Drive abuse detection), network errors: exponential backoff.
    Transient,
    /// 429 and 403 rate-limit reasons: exponential backoff, honour `Retry-After`.
    RateLimited {
        retry_after: Option<Duration>,
    },
    /// 403 `dailyLimitExceeded`: pause every caller, probe again later.
    DailyLimit,
    Fatal(FatalKind),
}

impl Class {
    fn label(&self) -> &'static str {
        match self {
            Class::Transient => "transient",
            Class::RateLimited { .. } => "rate_limited",
            Class::DailyLimit => "daily_limit",
            Class::Fatal(_) => "fatal",
        }
    }
}

/// HTTP status carried in the error context (`response: Parts { status: 429, ...`).
fn status_of(text: &str) -> Option<u16> {
    let i = text.find("Parts { status: ")? + "Parts { status: ".len();
    text[i..]
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

fn retry_after_of(text: &str) -> Option<Duration> {
    let i = text.find("\"retry-after\": \"")? + "\"retry-after\": \"".len();
    let secs: u64 = text[i..].split('"').next()?.trim().parse().ok()?;
    Some(Duration::from_secs(secs.min(3600)))
}

/// Map an OpenDAL error from the gdrive service to a retry class. OpenDAL puts Drive's `message` in the
/// error and the HTTP status in the `response` context; the Drive `reason` is not carried, so the message
/// text is matched (case-insensitive) as well as the reason names in case a future version adds them.
pub fn classify(e: &opendal::Error) -> Class {
    let text = format!("{e:?}");
    let low = text.to_lowercase();
    let status = status_of(&text);
    let msg_has = |s: &str| low.contains(s);
    if msg_has("daily limit") || msg_has("dailylimitexceeded") {
        return Class::DailyLimit;
    }
    let rate_text =
        msg_has("rate limit") || msg_has("ratelimitexceeded") || msg_has("too many requests");
    if status == Some(429)
        || (status == Some(403) && rate_text)
        || e.kind() == opendal::ErrorKind::RateLimited
    {
        return Class::RateLimited {
            retry_after: retry_after_of(&text),
        };
    }
    if status == Some(403) && (msg_has("storage quota") || msg_has("storagequotaexceeded")) {
        return Class::Fatal(FatalKind::StorageQuota);
    }
    if status == Some(401) {
        return Class::Fatal(FatalKind::Auth);
    }
    if matches!(status, Some(500..=599) | Some(408) | Some(405)) || e.is_temporary() {
        return Class::Transient;
    }
    Class::Fatal(FatalKind::Other)
}

pub trait Sleeper: Send + Sync {
    fn sleep(&self, d: Duration);
}

pub struct RealSleeper;
impl Sleeper for RealSleeper {
    fn sleep(&self, d: Duration) {
        std::thread::sleep(d)
    }
}

#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Retries per operation for transient and rate-limit errors.
    pub max_retries: u32,
    pub base: Duration,
    pub cap: Duration,
    /// How long to pause after `dailyLimitExceeded` before probing again.
    pub daily_pause: Duration,
    /// Give up after this many consecutive daily-limit pauses for one operation.
    pub max_daily_pauses: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 8,
            base: Duration::from_secs(1),
            cap: Duration::from_secs(64),
            daily_pause: Duration::from_secs(3600),
            max_daily_pauses: 26,
        }
    }
}

impl RetryPolicy {
    /// Exponential backoff with "equal jitter": half of `min(cap, base * 2^(attempt-1))` plus a random
    /// share of the other half, so concurrent uploaders spread out but the delay never collapses to zero.
    /// `u` is a uniform sample in `[0, 1)`.
    pub fn delay(&self, attempt: u32, u: f64) -> Duration {
        let exp = self.base.saturating_mul(1u32 << (attempt - 1).min(20));
        let d = exp.min(self.cap);
        d.mul_f64(0.5 + 0.5 * u.clamp(0.0, 1.0))
    }
}

fn xorshift_unit() -> f64 {
    use std::sync::atomic::AtomicU64;
    static S: AtomicU64 = AtomicU64::new(0);
    let mut x = S.load(Ordering::Relaxed);
    if x == 0 {
        x = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(88172645463325252)
            | 1;
    }
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    S.store(x, Ordering::Relaxed);
    (x >> 11) as f64 / (1u64 << 53) as f64
}

/// Runs operations with the retry policy. Shared by all threads of one backend so a daily-limit pause
/// stops every uploader, not only the one that saw the error.
pub struct Retrier {
    pub policy: RetryPolicy,
    sleeper: Arc<dyn Sleeper>,
    rng: Box<dyn Fn() -> f64 + Send + Sync>,
    gate: Mutex<Option<Instant>>,
    stats: Arc<Stats>,
}

impl Retrier {
    pub fn new(policy: RetryPolicy, stats: Arc<Stats>) -> Self {
        Self::with_parts(
            policy,
            stats,
            Arc::new(RealSleeper),
            Box::new(xorshift_unit),
        )
    }

    pub fn with_parts(
        policy: RetryPolicy,
        stats: Arc<Stats>,
        sleeper: Arc<dyn Sleeper>,
        rng: Box<dyn Fn() -> f64 + Send + Sync>,
    ) -> Self {
        Self {
            policy,
            sleeper,
            rng,
            gate: Mutex::new(None),
            stats,
        }
    }

    fn wait_gate(&self) {
        loop {
            let until = *self.gate.lock().unwrap();
            match until {
                Some(t) if t > Instant::now() => self.sleeper.sleep(t - Instant::now()),
                _ => return,
            }
        }
    }

    fn note(&self, class: &Class, what: &str, attempt: u32, d: Duration) {
        self.stats.retries.fetch_add(1, Ordering::Relaxed);
        self.stats
            .slept_ms
            .fetch_add(d.as_millis() as u64, Ordering::Relaxed);
        count(&self.stats.retry_by_class, class.label());
        log::warn!(
            "drive {what}: {} (attempt {attempt}), retrying in {d:?}",
            class.label()
        );
    }

    pub fn run<T>(
        &self,
        what: &str,
        mut f: impl FnMut() -> opendal::Result<T>,
    ) -> opendal::Result<T> {
        let (mut retries, mut daily) = (0u32, 0u32);
        loop {
            self.wait_gate();
            let e = match f() {
                Ok(v) => return Ok(v),
                Err(e) => e,
            };
            let class = classify(&e);
            match &class {
                Class::Fatal(_) => return Err(e),
                Class::DailyLimit => {
                    daily += 1;
                    if daily > self.policy.max_daily_pauses {
                        return Err(e);
                    }
                    let d = self.policy.daily_pause;
                    *self.gate.lock().unwrap() = Some(Instant::now() + d);
                    self.stats.daily_pauses.fetch_add(1, Ordering::Relaxed);
                    self.note(&class, what, daily, d);
                    // the next loop iteration waits at the gate shared with all other callers
                }
                Class::Transient | Class::RateLimited { .. } => {
                    retries += 1;
                    if retries > self.policy.max_retries {
                        return Err(e);
                    }
                    let mut d = self.policy.delay(retries, (self.rng)());
                    if let Class::RateLimited {
                        retry_after: Some(ra),
                    } = &class
                    {
                        d = d.max(*ra);
                    }
                    self.note(&class, what, retries, d);
                    self.sleeper.sleep(d);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------------------------

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
    })
}

pub struct HxDrive {
    op: blocking::Operator,
    retrier: Arc<Retrier>,
    root: String,
}

fn be_err(msg: &'static str, path: String, e: opendal::Error) -> Box<RusticError> {
    RusticError::with_source(ErrorKind::Backend, msg, e).attach_context("path", path)
}

impl HxDrive {
    /// Production constructor: reqwest transport, real sleeper, faults from `faults`.
    pub fn new(
        creds: &DriveCreds,
        root: &str,
        policy: RetryPolicy,
        faults: Arc<Faults>,
        stats: Arc<Stats>,
    ) -> Result<Self> {
        let _g = runtime().enter();
        let retrier = Arc::new(Retrier::new(policy, stats.clone()));
        Self::build(
            creds.options(root),
            ReqwestTransport::default(),
            faults,
            stats,
            retrier,
            root,
        )
    }

    /// Generic constructor, used by tests with a fake inner transport and a recording sleeper.
    pub fn build<T: HttpTransport + Clone>(
        options: Vec<(String, String)>,
        inner: T,
        faults: Arc<Faults>,
        stats: Arc<Stats>,
        retrier: Arc<Retrier>,
        root: &str,
    ) -> Result<Self> {
        let _g = runtime().enter();
        let ctx = OperationContext::new().with_http_transport(HttpTransporter::new(
            Transport::new(inner, stats.clone(), faults),
        ));
        let op = opendal::Operator::via_iter("gdrive", options)
            .map_err(|e| anyhow!("gdrive operator: {e}"))?
            .with_context(ctx)
            // no RetryLayer: every retry decision is made by `Retrier`
            .layer(
                opendal::layers::TimeoutLayer::new()
                    .with_timeout(Duration::from_secs(120))
                    .with_io_timeout(Duration::from_secs(300)),
            );
        let op = blocking::Operator::new(op).map_err(|e| anyhow!("blocking operator: {e}"))?;
        Ok(Self {
            op,
            retrier,
            root: root.to_string(),
        })
    }

    fn path(tpe: FileType, id: &Id) -> String {
        let hex = id.to_hex();
        match tpe {
            FileType::Config => "config".to_string(),
            FileType::Pack => format!("data/{}/{}", &hex[0..2], &hex[..]),
            _ => format!("{}/{}", tpe.dirname(), &hex[..]),
        }
    }
}

impl ReadBackend for HxDrive {
    fn location(&self) -> String {
        format!("hxdrive:{}", self.root)
    }

    fn list_with_size(&self, tpe: FileType) -> RusticResult<Vec<(Id, u32)>> {
        if tpe == FileType::Config {
            return match self.retrier.run("stat config", || self.op.stat("config")) {
                Ok(m) => Ok(vec![(Id::default(), m.content_length() as u32)]),
                Err(e) if e.kind() == opendal::ErrorKind::NotFound => Ok(vec![]),
                Err(e) => Err(be_err(
                    "Checking for `config` failed in the backend",
                    "config".into(),
                    e,
                )),
            };
        }
        let path = format!("{}/", tpe.dirname());
        // The whole listing is retried and any error is propagated: a partial listing would make
        // `repair index` and prune act on an incomplete view of the repository.
        self.retrier
            .run(&format!("list {path}"), || {
                let lister = self.op.lister_options(
                    &path,
                    ListOptions {
                        recursive: true,
                        ..Default::default()
                    },
                )?;
                let mut out = vec![];
                for entry in lister {
                    let entry = entry?;
                    let md = entry.metadata();
                    if !md.is_file() {
                        continue;
                    }
                    if let Some(id) = Id::parse_some(entry.name(), tpe) {
                        out.push((id, md.content_length().try_into().unwrap_or(u32::MAX)));
                    }
                }
                Ok(out)
            })
            .map_err(|e| be_err("Listing failed in the backend", path, e))
    }

    fn read_full(&self, tpe: FileType, id: &Id) -> RusticResult<Bytes> {
        let path = Self::path(tpe, id);
        self.retrier
            .run(&format!("read {path}"), || {
                self.op.read(&path).map(|b| b.to_bytes())
            })
            .map_err(|e| be_err("Reading file failed in the backend", path, e))
    }

    fn read_partial(
        &self,
        tpe: FileType,
        id: &Id,
        _c: bool,
        offset: u32,
        length: u32,
    ) -> RusticResult<Bytes> {
        let path = Self::path(tpe, id);
        let range = u64::from(offset)..u64::from(offset) + u64::from(length);
        self.retrier
            .run(&format!("read_range {path}"), || {
                let o = ReadOptions {
                    range: range.clone().into(),
                    ..Default::default()
                };
                self.op.read_options(&path, o).map(|b| b.to_bytes())
            })
            .map_err(|e| be_err("Partial read failed in the backend", path, e))
    }

    fn warmup_path(&self, tpe: FileType, id: &Id) -> String {
        Self::path(tpe, id)
    }
}

impl WriteBackend for HxDrive {
    fn create(&self) -> RusticResult<()> {
        let mut dirs: Vec<String> = ALL_FILE_TYPES
            .iter()
            .map(|t| format!("{}/", t.dirname()))
            .collect();
        dirs.extend((0u8..=255).map(|i| format!("data/{}/", hex::encode([i]))));
        // Folder creation is a rate-limited write on Drive: a few workers, each retrying with backoff.
        let next = AtomicU64::new(0);
        let first_err: Mutex<Option<Box<RusticError>>> = Mutex::new(None);
        std::thread::scope(|s| {
            for _ in 0..4 {
                s.spawn(|| {
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed) as usize;
                        let Some(d) = dirs.get(i) else { return };
                        if first_err.lock().unwrap().is_some() {
                            return;
                        }
                        if let Err(e) = self
                            .retrier
                            .run(&format!("create_dir {d}"), || self.op.create_dir(d))
                        {
                            first_err.lock().unwrap().get_or_insert_with(|| {
                                be_err("Creating directory failed in the backend", d.clone(), e)
                            });
                        }
                    }
                });
            }
        });
        match first_err.into_inner().unwrap() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn write_bytes(
        &self,
        tpe: FileType,
        id: &Id,
        _c: bool,
        content: BytesList,
    ) -> RusticResult<()> {
        let path = Self::path(tpe, id);
        let chunks = content.into_vec();
        self.retrier
            .run(&format!("write {path}"), || {
                // OpenDAL resolves the path first and overwrites an existing file, so a retry after an
                // ambiguous failure (timeout after the server stored the object) does not duplicate it.
                self.op
                    .write(&path, Buffer::from(chunks.clone()))
                    .map(|_| ())
            })
            .map_err(|e| be_err("Writing file failed in the backend", path, e))
    }

    fn remove(&self, tpe: FileType, id: &Id, _c: bool) -> RusticResult<()> {
        let path = Self::path(tpe, id);
        self.retrier
            .run(&format!("remove {path}"), || self.op.delete(&path))
            .map_err(|e| be_err("Deleting file failed in the backend", path, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as M;

    /// Minimal fake of the three Drive calls a write needs; everything else is a 404 `{}`.
    #[derive(Clone, Default)]
    struct FakeDrive;

    impl HttpTransport for FakeDrive {
        async fn fetch(&self, req: Request<Buffer>) -> opendal::Result<Response<HttpBody>> {
            let cat = categorize(req.method(), req.uri());
            let (status, body) = match cat {
                "list" => (200, r#"{"files":[]}"#.to_string()),
                "create.folder" => (
                    200,
                    r#"{"id":"folder-id","name":"x","mimeType":"application/vnd.google-apps.folder"}"#.into(),
                ),
                "upload.create" | "upload.overwrite" => {
                    (200, r#"{"id":"file-id","name":"x","mimeType":"application/octet-stream","size":"3"}"#.into())
                }
                _ => (404, "{}".into()),
            };
            let buf = Buffer::from(Bytes::from(body));
            let len = buf.len() as u64;
            Ok(Response::builder()
                .status(status)
                .body(HttpBody::new(
                    futures::stream::iter(vec![Ok::<Buffer, opendal::Error>(buf)]),
                    Some(len),
                ))
                .unwrap())
        }
    }

    #[derive(Default)]
    struct Recorder(M<Vec<Duration>>);
    impl Sleeper for Recorder {
        fn sleep(&self, d: Duration) {
            self.0.lock().unwrap().push(d)
        }
    }

    struct Rig {
        be: HxDrive,
        sleeps: Arc<Recorder>,
        stats: Arc<Stats>,
    }

    fn rig(faults: &str, policy: RetryPolicy) -> Rig {
        let stats = Arc::new(Stats::default());
        let sleeps = Arc::new(Recorder::default());
        // u = 1.0 -> full (un-jittered) delay, so the schedule is exactly 1, 2, 4, ... seconds
        let retrier = Arc::new(Retrier::with_parts(
            policy,
            stats.clone(),
            sleeps.clone(),
            Box::new(|| 1.0),
        ));
        let be = HxDrive::build(
            vec![
                ("root".into(), "/".into()),
                ("access_token".into(), "test".into()),
            ],
            FakeDrive,
            Arc::new(Faults::parse(faults).unwrap()),
            stats.clone(),
            retrier,
            "/",
        )
        .unwrap();
        Rig { be, sleeps, stats }
    }

    fn secs(r: &Rig) -> Vec<u64> {
        r.sleeps
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|d| d.as_millis() as u64)
            .collect()
    }

    fn id() -> Id {
        "ab".repeat(32).parse::<Id>().unwrap()
    }

    fn write(r: &Rig) -> RusticResult<()> {
        r.be.write_bytes(
            FileType::Pack,
            &id(),
            false,
            BytesList::from(vec![1u8, 2, 3]),
        )
    }

    #[test]
    fn upload_429_is_retried_with_exponential_backoff() {
        let r = rig(
            "upload.create:429:tooManyRequests:3",
            RetryPolicy::default(),
        );
        write(&r).expect("write succeeds after three 429");
        assert_eq!(secs(&r), vec![1000, 2000, 4000]);
        assert_eq!(r.stats.count_category("upload.create"), 4);
        assert_eq!(r.stats.retries_for("rate_limited"), 3);
    }

    #[test]
    fn rate_limit_403_reasons_are_retried() {
        for reason in ["rateLimitExceeded", "userRateLimitExceeded"] {
            let r = rig(
                &format!("upload.create:403:{reason}:2"),
                RetryPolicy::default(),
            );
            write(&r).unwrap_or_else(|e| panic!("{reason}: {e:?}"));
            assert_eq!(secs(&r), vec![1000, 2000], "{reason}");
            assert_eq!(r.stats.retries_for("rate_limited"), 2, "{reason}");
        }
    }

    #[test]
    fn retry_after_header_wins_over_a_shorter_backoff() {
        let r = rig(
            "upload.create:429:rateLimitExceeded:1:0:30",
            RetryPolicy::default(),
        );
        write(&r).unwrap();
        assert_eq!(secs(&r), vec![30_000]);
    }

    #[test]
    fn backoff_caps_and_gives_up_after_max_retries() {
        let p = RetryPolicy {
            max_retries: 8,
            ..RetryPolicy::default()
        };
        let r = rig("upload.create:429:rateLimitExceeded:100", p);
        assert!(write(&r).is_err());
        assert_eq!(
            secs(&r),
            vec![1000, 2000, 4000, 8000, 16000, 32000, 64000, 64000]
        );
        assert_eq!(r.stats.count_category("upload.create"), 9);
    }

    #[test]
    fn server_errors_are_transient_and_retried() {
        let r = rig("upload.create:503:backendError:2", RetryPolicy::default());
        write(&r).unwrap();
        assert_eq!(r.stats.retries_for("transient"), 2);
    }

    #[test]
    fn jitter_stays_within_half_to_full_delay() {
        let p = RetryPolicy::default();
        for attempt in 1..=10 {
            let full = p.base.saturating_mul(1 << (attempt - 1)).min(p.cap);
            assert_eq!(p.delay(attempt, 1.0), full);
            assert_eq!(p.delay(attempt, 0.0), full / 2);
            let mid = p.delay(attempt, 0.5);
            assert!(mid > full / 2 && mid < full);
        }
    }

    #[test]
    fn daily_limit_pauses_then_resumes() {
        let p = RetryPolicy {
            daily_pause: Duration::from_millis(5),
            ..RetryPolicy::default()
        };
        let r = rig("upload.create:403:dailyLimitExceeded:1", p);
        write(&r).expect("probe after the pause succeeds");
        assert_eq!(r.stats.daily_pauses.load(Ordering::Relaxed), 1);
        assert_eq!(r.stats.retries_for("daily_limit"), 1);
        // the pause is taken at the shared gate, not as a backoff sleep
        assert_eq!(r.stats.retries_for("rate_limited"), 0);
        assert!(
            r.sleeps
                .0
                .lock()
                .unwrap()
                .iter()
                .any(|d| *d <= Duration::from_millis(5))
        );
    }

    #[test]
    fn daily_limit_gives_up_after_max_pauses() {
        let p = RetryPolicy {
            daily_pause: Duration::from_millis(1),
            max_daily_pauses: 2,
            ..RetryPolicy::default()
        };
        let r = rig("upload.create:403:dailyLimitExceeded:100", p);
        assert!(write(&r).is_err());
        assert_eq!(r.stats.daily_pauses.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn daily_limit_pause_stops_other_callers_too() {
        let p = RetryPolicy {
            daily_pause: Duration::from_millis(150),
            ..RetryPolicy::default()
        };
        let stats = Arc::new(Stats::default());
        let retrier = Arc::new(Retrier::new(p, stats.clone()));
        let hit = std::sync::atomic::AtomicBool::new(false);
        let t0 = Instant::now();
        let op = |first: bool| {
            let retrier = retrier.clone();
            let hit = &hit;
            move || {
                retrier.run("x", || {
                    if first && !hit.swap(true, Ordering::SeqCst) {
                        Err(opendal::Error::new(
                            opendal::ErrorKind::PermissionDenied,
                            "GdriveError { error: GdriveInnerError { message: \"Daily Limit Exceeded\" } }",
                        )
                        .with_context("response", "Parts { status: 403, headers: {} }"))
                    } else {
                        Ok(Instant::now())
                    }
                })
            }
        };
        let (a, b) = std::thread::scope(|s| {
            let h1 = s.spawn(op(true));
            std::thread::sleep(Duration::from_millis(30));
            let h2 = s.spawn(op(false));
            (h1.join().unwrap().unwrap(), h2.join().unwrap().unwrap())
        });
        assert!(a.duration_since(t0) >= Duration::from_millis(150));
        assert!(
            b.duration_since(t0) >= Duration::from_millis(150),
            "second caller waited at the gate"
        );
    }

    #[test]
    fn storage_quota_and_permission_errors_are_fatal() {
        for (status, reason, calls) in [
            (403, "storageQuotaExceeded", 1),
            (403, "appNotAuthorizedToFile", 1),
            (401, "authError", 1),
        ] {
            let r = rig(
                &format!("upload.create:{status}:{reason}:5"),
                RetryPolicy::default(),
            );
            assert!(write(&r).is_err(), "{reason}");
            assert_eq!(r.stats.count_category("upload.create"), calls, "{reason}");
            assert!(secs(&r).is_empty(), "{reason}: no retry sleeps");
        }
    }

    #[test]
    fn listing_errors_are_retried_and_never_truncated_silently() {
        let r = rig("list:429:rateLimitExceeded:2", RetryPolicy::default());
        let v = r.be.list_with_size(FileType::Snapshot);
        // the fake has no `snapshots/` folder, so the retried listing ends as a clean empty list
        assert!(v.expect("listing succeeds after the retries").is_empty());
        assert_eq!(secs(&r), vec![1000, 2000]);
        assert_eq!(r.stats.retries_for("rate_limited"), 2);
        let r = rig(
            "list:403:dailyLimitExceeded:100",
            RetryPolicy {
                daily_pause: Duration::from_millis(1),
                max_daily_pauses: 1,
                ..RetryPolicy::default()
            },
        );
        assert!(
            r.be.list_with_size(FileType::Index).is_err(),
            "an exhausted listing is an error, not an empty list"
        );
    }

    #[test]
    fn classification_table() {
        let mk = |kind, status: u16, msg: &str| {
            opendal::Error::new(
                kind,
                format!("GdriveError {{ error: GdriveInnerError {{ message: {msg:?} }} }}"),
            )
            .with_context(
                "response",
                format!("Parts {{ status: {status}, headers: {{}} }}"),
            )
        };
        use opendal::ErrorKind::*;
        assert_eq!(
            classify(&mk(Unexpected, 429, "Too Many Requests")),
            Class::RateLimited { retry_after: None }
        );
        assert_eq!(
            classify(&mk(PermissionDenied, 403, "Rate Limit Exceeded")),
            Class::RateLimited { retry_after: None }
        );
        assert_eq!(
            classify(&mk(PermissionDenied, 403, "User Rate Limit Exceeded")),
            Class::RateLimited { retry_after: None }
        );
        assert_eq!(
            classify(&mk(PermissionDenied, 403, "User rate limit exceeded.")),
            Class::RateLimited { retry_after: None }
        );
        assert_eq!(
            classify(&mk(PermissionDenied, 403, "Daily Limit Exceeded")),
            Class::DailyLimit
        );
        assert_eq!(
            classify(&mk(
                PermissionDenied,
                403,
                "The user's Drive storage quota has been exceeded."
            )),
            Class::Fatal(FatalKind::StorageQuota)
        );
        assert_eq!(
            classify(&mk(
                PermissionDenied,
                403,
                "The user has not granted the app access to the file."
            )),
            Class::Fatal(FatalKind::Other)
        );
        assert_eq!(
            classify(&mk(Unexpected, 500, "Internal Error")),
            Class::Transient
        );
        assert_eq!(
            classify(&mk(Unexpected, 503, "Backend Error")),
            Class::Transient
        );
        assert_eq!(classify(&mk(Unexpected, 405, "")), Class::Transient);
        assert_eq!(
            classify(&mk(NotFound, 404, "File not found")),
            Class::Fatal(FatalKind::Other)
        );
        assert_eq!(
            classify(&mk(Unexpected, 401, "Invalid Credentials")),
            Class::Fatal(FatalKind::Auth)
        );
        assert_eq!(
            classify(&opendal::Error::new(Unexpected, "send http request").set_temporary()),
            Class::Transient
        );
    }

    #[test]
    fn fault_spec_parsing_and_consumption() {
        let f = Faults::parse("upload.create:429:x:2:1,*:503:y:1").unwrap();
        assert!(
            f.take("upload.create").is_none(),
            "first request is skipped"
        );
        assert!(f.take("upload.create").is_some());
        assert!(f.take("upload.create").is_some());
        assert_eq!(f.take("list").unwrap().status, 503);
        assert!(f.take("list").is_none());
        assert!(Faults::parse("bad").is_err());
    }

    #[test]
    fn creds_debug_does_not_leak() {
        let c = DriveCreds {
            client_id: "id-secret-1".into(),
            client_secret: "secret-2".into(),
            refresh_token: "refresh-3".into(),
        };
        let d = format!("{c:?}");
        assert!(!d.contains("secret") && !d.contains("refresh-3") && !d.contains("id-secret"));
    }
}
