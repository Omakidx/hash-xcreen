//! The repository on Google Drive: S4's `HxDrive` ported to the helper's raw object operations
//! (ipc.md §27, §29). OpenDAL's `gdrive` service does the Drive calls through [`GoogleTransport`];
//! this module adds the layout, the retries ([`Retrier`]), the lease, the lazy `data/xx` folders,
//! the streamed reads with their memory budget, and the quota.
//!
//! Layout below `OpenRepo.folder` (a folder under My Drive): `config`, `keys/<hex>`,
//! `snapshots/<hex>`, `index/<hex>`, `data/<xx>/<hex>` and `hx-lease.json`.

use std::collections::HashSet;
use std::future::Future;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::TryStreamExt;
use hx_ipc::repo::{self, pb};
use opendal::options::{ListOptions, ReadOptions};
use opendal::services::Gdrive;
use opendal::{Buffer, HttpTransport, HttpTransporter, OperationContext, Operator};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

use super::creds::{ClientConfig, Token};
use super::lease::{
    self, Found, LEASE_FILE, Lease, LeaseGuard, MAX_LEASE_BYTES, Mutation, OpenDecision, Unreadable,
};
use super::retry::{Cancel, DriveError, Retrier, set_body_limit};
use super::transport::GoogleTransport;

use pb::ErrorClass as EC;

/// The largest piece of an object read from Drive at once (ipc.md §29, "Reads").
pub const READ_CHUNK: usize = 4 * 1024 * 1024;

/// A 32-byte object id.
pub type Id = [u8; 32];

/// What `Quota` answers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QuotaInfo {
    /// `storageQuota.limit`, 0 when the account has none.
    pub limit: u64,
    /// `storageQuota.usage`: counts the trash.
    pub usage: u64,
    /// `storageQuota.usageInDriveTrash`.
    pub usage_in_trash: u64,
}

/// `OpenRepo`.
#[derive(Debug, Clone)]
pub struct OpenParams {
    /// The folder below My Drive.
    pub folder: String,
    /// Create it if absent.
    pub create: bool,
    /// This server's id, 16 bytes.
    pub server_id: [u8; 16],
    /// Take the lease over.
    pub takeover: bool,
}

/// The session's Drive context: credentials, transport, retrier. One per link session.
pub struct Drive {
    retrier: Arc<Retrier>,
    api: Arc<Api>,
    hint: String,
    read_budget: Arc<Semaphore>,
    read_budget_kib: usize,
}

type MakeOperator = Arc<dyn Fn() -> Result<Operator, DriveError> + Send + Sync>;

/// OpenDAL's operator for the repository folder. The credentials go in percent-encoded: OpenDAL
/// puts them in the query of its token request unencoded, and the transport moves that query into
/// a form body as it is.
fn build_operator(api: &Api, folder: &str) -> Result<Operator, DriveError> {
    let builder = Gdrive::default()
        .root(&format!("/{folder}/"))
        .client_id(&percent(api.client.id()))
        .client_secret(&percent(api.client.secret()))
        .refresh_token(&percent(api.token.expose()));
    let ctx =
        OperationContext::new().with_http_transport(HttpTransporter::new(api.transport.clone()));
    Operator::new(builder)
        .map(|op| op.with_context(ctx))
        .map_err(|_| DriveError::new(EC::Internal))
}

impl Drive {
    /// A context for one session.
    #[must_use]
    pub fn new(
        retrier: Arc<Retrier>,
        transport: GoogleTransport,
        client: ClientConfig,
        token: Token,
        hostname: &[u8],
    ) -> Self {
        let read_budget_kib = retrier.timing().read_budget_kib;
        Self {
            api: Arc::new(Api {
                retrier: retrier.clone(),
                transport,
                client,
                token,
                access: Mutex::new(None),
            }),
            retrier,
            hint: lease::sanitize_hint(hostname),
            read_budget_kib,
            read_budget: Arc::new(Semaphore::new(read_budget_kib)),
        }
    }

    /// OpenDAL's operator for `folder` (the tests of the token request use it directly).
    ///
    /// # Errors
    /// `INTERNAL` when OpenDAL refuses the options.
    pub fn operator(&self, folder: &str) -> Result<Operator, DriveError> {
        build_operator(&self.api, folder)
    }

    /// `OpenRepo` (§29): finds or creates the folder and settles the lease.
    ///
    /// # Errors
    /// `NOT_FOUND` (no folder and no `create`), `LEASE_HELD`, `INTERNAL` (unreadable lease), or the
    /// class of a Drive failure.
    pub async fn open(&self, p: &OpenParams, cancel: &Cancel) -> Result<Repo, DriveError> {
        // The codec has checked this already; it is also what keeps the folder out of a query.
        let b = p.folder.as_bytes();
        if b.is_empty()
            || b.len() > repo::MAX_FOLDER_LEN
            || !b[0].is_ascii_alphanumeric()
            || !b
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(c))
        {
            return Err(DriveError::new(EC::Internal));
        }
        let make_op: MakeOperator = {
            let api = self.api.clone();
            let folder = p.folder.clone();
            Arc::new(move || build_operator(&api, &folder))
        };
        let ours = lease::hex_id(&p.server_id);
        let mut repo = Repo {
            op: RwLock::new(make_op()?),
            make_op,
            retrier: self.retrier.clone(),
            api: self.api.clone(),
            folders: Mutex::new(HashSet::new()),
            read_budget: self.read_budget.clone(),
            read_budget_kib: self.read_budget_kib,
            lease: LeaseGuard::new(ours.clone(), 0, self.retrier.timing().lease_cache),
            ours,
        };
        // OpenDAL answers a stat of its root without asking Drive, so the folder is asked for
        // directly.
        if !self.api.folder_exists(&p.folder, cancel).await? {
            if !p.create {
                return Err(DriveError::new(EC::NotFound));
            }
            repo.run(cancel, 0, "create folder", || {
                let op = repo.op();
                async move { op.create_dir("/").await }
            })
            .await?;
        }
        let found = repo.read_lease(cancel).await?;
        let generation = match lease::decide_open(&found, &repo.ours, p.takeover) {
            OpenDecision::Accept(g) => g,
            OpenDecision::Write(g) => {
                let l = Lease::new(&repo.ours, g, unix_secs(), &self.hint);
                let bytes = l.to_bytes();
                repo.run(cancel, bytes.len() as u64, "write lease", || {
                    let op = repo.op();
                    let bytes = bytes.clone();
                    async move { op.write(LEASE_FILE, Buffer::from(Bytes::from(bytes))).await }
                })
                .await?;
                g
            }
            OpenDecision::Held => return Err(DriveError::new(EC::LeaseHeld)),
            OpenDecision::Unreadable => return Err(DriveError::new(EC::Internal)),
        };
        repo.lease = LeaseGuard::new(
            repo.ours.clone(),
            generation,
            self.retrier.timing().lease_cache,
        );
        Ok(repo)
    }
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The path of an object below the repository folder; `None` for [`pb::ObjectType::Unspecified`],
/// which names no object.
#[must_use]
pub fn object_path(ty: pb::ObjectType, id: &Id) -> Option<String> {
    let hex = lease::hex_id(id);
    Some(match ty {
        pb::ObjectType::Unspecified => return None,
        pb::ObjectType::Config => "config".to_owned(),
        pb::ObjectType::Key => format!("keys/{hex}"),
        pb::ObjectType::Snapshot => format!("snapshots/{hex}"),
        pb::ObjectType::Index => format!("index/{hex}"),
        pb::ObjectType::Pack => format!("data/{}/{hex}", &hex[..2]),
    })
}

fn path_of(ty: pb::ObjectType, id: &Id) -> Result<String, DriveError> {
    object_path(ty, id).ok_or(DriveError::new(EC::Internal))
}

fn parse_id(name: &str) -> Option<Id> {
    if name.len() != 64 || !name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut id = [0u8; 32];
    for (i, b) in id.iter_mut().enumerate() {
        *b = u8::from_str_radix(&name[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(id)
}

fn kib(bytes: usize) -> u32 {
    u32::try_from(bytes.div_ceil(1024).max(1)).unwrap_or(u32::MAX)
}

fn percent(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

struct Access {
    token: Zeroizing<String>,
    until: Instant,
}

/// The few Drive calls that OpenDAL has no operation for (an existence check of the repository
/// folder, `about`), with the access token they need: a refresh of its own, through the same
/// transport and retrier.
struct Api {
    retrier: Arc<Retrier>,
    transport: GoogleTransport,
    client: ClientConfig,
    token: Token,
    access: Mutex<Option<Access>>,
}

impl Api {
    /// One authorised GET of `url` with the access token. A 401 drops the cached token and the
    /// request is made once more with a fresh one (ipc.md §29).
    async fn get(
        &self,
        url: &str,
        what: &'static str,
        cancel: &Cancel,
    ) -> Result<Bytes, DriveError> {
        for round in 0..2 {
            let token = self.access_token(cancel).await?;
            let r = self
                .retrier
                .run(cancel, 0, what, || async {
                    let req = http::Request::get(url)
                        .header(
                            http::header::AUTHORIZATION,
                            format!("Bearer {}", token.as_str()),
                        )
                        .body(Buffer::new())
                        .map_err(|_| {
                            opendal::Error::new(opendal::ErrorKind::Unexpected, "request")
                        })?;
                    let resp = self.transport.fetch(req).await?;
                    if resp.status() != http::StatusCode::OK {
                        return Err(opendal::Error::new(opendal::ErrorKind::Unexpected, what));
                    }
                    Ok(resp.into_body().to_buffer().await?.to_bytes())
                })
                .await;
            match r {
                Err(e) if e.unauthorized && round == 0 => {
                    *self.access.lock().await = None;
                }
                Err(e) => {
                    return Err(DriveError {
                        unauthorized: false,
                        ..e
                    });
                }
                Ok(b) => return Ok(b),
            }
        }
        Err(DriveError::new(EC::AuthRevoked))
    }

    /// Is there a live folder `name` directly under My Drive?
    async fn folder_exists(&self, name: &str, cancel: &Cancel) -> Result<bool, DriveError> {
        let q = format!(
            "name = '{name}' and 'root' in parents and mimeType = 'application/vnd.google-apps.folder' and trashed = false"
        );
        let url = format!(
            "https://www.googleapis.com/drive/v3/files?q={}&pageSize=1&fields=files(id)",
            percent(&q)
        );
        let body = self.get(&url, "find folder", cancel).await?;
        let v: serde_json::Value =
            serde_json::from_slice(&body).map_err(|_| DriveError::new(EC::Internal))?;
        Ok(v["files"].as_array().is_some_and(|a| !a.is_empty()))
    }

    async fn access_token(&self, cancel: &Cancel) -> Result<Zeroizing<String>, DriveError> {
        let mut slot = cancel.guard(self.access.lock()).await?;
        if let Some(a) = slot.as_ref()
            && a.until > Instant::now()
        {
            return Ok(a.token.clone());
        }
        let form = Zeroizing::new(format!(
            "client_id={}&client_secret={}&refresh_token={}&grant_type=refresh_token",
            percent(self.client.id()),
            percent(self.client.secret()),
            percent(self.token.expose())
        ));
        let (token, expires_in) = self
            .retrier
            .run_token(cancel, "refresh token", || async {
                let req = http::Request::post("https://oauth2.googleapis.com/token")
                    .header(
                        http::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(Buffer::from(Bytes::from(form.as_bytes().to_vec())))
                    .map_err(|_| opendal::Error::new(opendal::ErrorKind::Unexpected, "request"))?;
                let resp = self.transport.fetch(req).await?;
                if resp.status() != http::StatusCode::OK {
                    return Err(opendal::Error::new(opendal::ErrorKind::Unexpected, "token"));
                }
                let body = resp.into_body().to_buffer().await?.to_bytes();
                let v: serde_json::Value = serde_json::from_slice(&body).map_err(|_| {
                    opendal::Error::new(opendal::ErrorKind::Unexpected, "token body")
                })?;
                let t = v["access_token"].as_str().ok_or_else(|| {
                    opendal::Error::new(opendal::ErrorKind::Unexpected, "token body")
                })?;
                Ok((
                    Zeroizing::new(t.to_owned()),
                    v["expires_in"].as_u64().unwrap_or(0),
                ))
            })
            .await?;
        let until = Instant::now() + Duration::from_secs(expires_in.saturating_sub(120));
        *slot = Some(Access {
            token: token.clone(),
            until,
        });
        Ok(token)
    }

    async fn quota(&self, cancel: &Cancel) -> Result<QuotaInfo, DriveError> {
        let body = self
            .get(
                "https://www.googleapis.com/drive/v3/about?fields=storageQuota",
                "about",
                cancel,
            )
            .await?;
        let v: serde_json::Value =
            serde_json::from_slice(&body).map_err(|_| DriveError::new(EC::Internal))?;
        let num = |k: &str| {
            let q = &v["storageQuota"][k];
            q.as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .or_else(|| q.as_u64())
                .unwrap_or(0)
        };
        Ok(QuotaInfo {
            limit: num("limit"),
            usage: num("usage"),
            usage_in_trash: num("usageInDriveTrash"),
        })
    }
}

/// One chunk of an object in hand: its parts (not copied from what OpenDAL read) and the permit of
/// the read budget, which is given back when the chunk is dropped, that is, when its frames are
/// queued on the link.
pub struct Chunk {
    /// The bytes, in order.
    pub parts: Vec<Bytes>,
    _permit: OwnedSemaphorePermit,
}

impl Chunk {
    /// Its length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.parts.iter().map(Bytes::len).sum()
    }

    /// Is it empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.parts.iter().all(Bytes::is_empty)
    }
}

/// A read in progress: the size is known before the first byte is sent, and the data comes one
/// chunk at a time (ipc.md §29, "Reads").
pub struct ReadStream {
    repo: Arc<Repo>,
    path: String,
    size: u32,
    offset: u64,
    end: u64,
    first: Option<Chunk>,
}

impl ReadStream {
    /// The size `ReadBegin` announces.
    #[must_use]
    pub fn size(&self) -> u32 {
        self.size
    }

    /// The next chunk, or `None` at the end. Each chunk is read (and retried) as a whole.
    ///
    /// # Errors
    /// The class of a Drive failure, `INTERNAL` for a short or long answer.
    pub async fn next_chunk(&mut self, cancel: &Cancel) -> Result<Option<Chunk>, DriveError> {
        if let Some(c) = self.first.take() {
            return Ok(Some(c));
        }
        if self.offset >= self.end {
            return Ok(None);
        }
        let len = (self.end - self.offset).min(READ_CHUNK as u64) as usize;
        let c = self
            .repo
            .read_range(&self.path, self.offset, len, cancel)
            .await?;
        self.offset += len as u64;
        Ok(Some(c))
    }
}

/// One opened repository (a folder, a lease, an operator).
pub struct Repo {
    op: RwLock<Operator>,
    make_op: MakeOperator,
    retrier: Arc<Retrier>,
    api: Arc<Api>,
    folders: Mutex<HashSet<u8>>,
    read_budget: Arc<Semaphore>,
    read_budget_kib: usize,
    lease: LeaseGuard,
    ours: String,
}

impl Repo {
    fn op(&self) -> Operator {
        self.op.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Builds a fresh operator, which makes a fresh token exchange (after a 401).
    fn reauth(&self) -> Result<(), DriveError> {
        *self.op.write().unwrap_or_else(|e| e.into_inner()) = (self.make_op)()?;
        Ok(())
    }

    /// [`Retrier::run`] with the one repeat that a 401 earns: the access token may have expired, so
    /// the operator is rebuilt and the call made once more. A second 401 is `AUTH_REVOKED`.
    async fn run<T, F, Fut>(
        &self,
        cancel: &Cancel,
        size: u64,
        what: &'static str,
        mut f: F,
    ) -> Result<T, DriveError>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = opendal::Result<T>>,
    {
        match self.retrier.run(cancel, size, what, &mut f).await {
            Err(e) if e.unauthorized => {
                self.reauth()?;
                self.retrier.run(cancel, size, what, &mut f).await
            }
            r => r,
        }
        .map_err(|e| DriveError {
            unauthorized: false,
            ..e
        })
    }

    async fn read_lease(&self, cancel: &Cancel) -> Result<Found, DriveError> {
        // A ranged read of a file shorter than the range is an error in OpenDAL, so the size is
        // asked first: a lease object over the cap is never downloaded.
        let got = self
            .run(cancel, 0, "read lease", || {
                let op = self.op();
                async move {
                    let m = op.stat(LEASE_FILE).await?;
                    if m.content_length() > MAX_LEASE_BYTES as u64 {
                        return Ok(None);
                    }
                    set_body_limit(MAX_LEASE_BYTES as u64);
                    op.read(LEASE_FILE).await.map(Some)
                }
            })
            .await;
        match got {
            Ok(Some(b)) => Ok(Some(Lease::parse(&b.to_bytes()))),
            Ok(None) => Ok(Some(Err(Unreadable))),
            Err(e) if e.class == EC::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn check_lease(&self, m: Mutation, cancel: &Cancel) -> Result<(), DriveError> {
        self.lease
            .check(m, cancel, || self.read_lease(cancel))
            .await
    }

    /// `stat` of an object: its size and whether it is a file; `None` when absent.
    async fn stat(
        &self,
        path: &str,
        what: &'static str,
        cancel: &Cancel,
    ) -> Result<Option<(u64, bool)>, DriveError> {
        let r = self
            .run(cancel, 0, what, || {
                let op = self.op();
                let path = path.to_owned();
                async move { op.stat(&path).await }
            })
            .await;
        match r {
            Ok(m) => Ok(Some((m.content_length(), m.is_file()))),
            Err(e) if e.class == EC::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Lists the objects of `ty`. The whole listing is collected before anything is returned: a
    /// failed page is an error, never a short list. Entries and requests are counted as Drive
    /// pages, so an endless listing ends in `INTERNAL`.
    ///
    /// # Errors
    /// The class of a Drive failure; `INTERNAL` for an object over its type's cap or a listing over
    /// the limits.
    pub async fn list(
        &self,
        ty: pb::ObjectType,
        cancel: &Cancel,
    ) -> Result<Vec<(Id, u32)>, DriveError> {
        let cap = repo::max_object_size(ty).ok_or(DriveError::new(EC::Internal))?;
        if ty == pb::ObjectType::Config {
            return match self.stat("config", "stat config", cancel).await? {
                Some((len, _)) => {
                    let size = u32::try_from(len)
                        .ok()
                        .filter(|s| *s <= cap)
                        .ok_or(DriveError::new(EC::Internal))?;
                    Ok(vec![([0u8; 32], size)])
                }
                None => Ok(vec![]),
            };
        }
        let dir = match ty {
            pb::ObjectType::Key => "keys/",
            pb::ObjectType::Snapshot => "snapshots/",
            pb::ObjectType::Index => "index/",
            _ => "data/",
        };
        let max = self.retrier.timing().max_list_entries;
        let r = self
            .run(cancel, 0, "list", || {
                let op = self.op();
                async move {
                    let opts = ListOptions {
                        recursive: ty == pb::ObjectType::Pack,
                        ..ListOptions::default()
                    };
                    let mut lister = op.lister_options(dir, opts).await?;
                    let mut seen = HashSet::new();
                    let mut out = Vec::new();
                    let mut counted = 0usize;
                    while let Some(entry) = lister.try_next().await? {
                        counted += 1;
                        if counted > max {
                            return Err(opendal::Error::new(
                                opendal::ErrorKind::Unexpected,
                                "listing is longer than the limit",
                            ));
                        }
                        let md = entry.metadata();
                        if !md.is_file() {
                            continue;
                        }
                        let Some(id) = parse_id(entry.name()) else {
                            continue;
                        };
                        if id == [0u8; 32]
                            || object_path(ty, &id).as_deref() != Some(entry.path())
                            || !seen.insert(id)
                        {
                            continue;
                        }
                        let size = u32::try_from(md.content_length())
                            .ok()
                            .filter(|s| *s <= cap)
                            .ok_or_else(|| {
                                opendal::Error::new(
                                    opendal::ErrorKind::Unexpected,
                                    "a listed object is larger than its type's cap",
                                )
                            })?;
                        out.push((id, size));
                    }
                    Ok(out)
                }
            })
            .await;
        match r {
            Err(e) if e.class == EC::NotFound => Ok(vec![]),
            r => r,
        }
    }

    /// Reads `len` bytes at `offset` as one chunk: a permit of the read budget first, then the
    /// ranged read, whose body may not exceed `len`. Anything but exactly `len` is `INTERNAL`.
    async fn read_range(
        &self,
        path: &str,
        offset: u64,
        len: usize,
        cancel: &Cancel,
    ) -> Result<Chunk, DriveError> {
        let n = kib(len).min(self.read_budget_kib as u32);
        let permit = cancel
            .guard(self.read_budget.clone().acquire_many_owned(n))
            .await?
            .map_err(|_| DriveError::new(EC::Internal))?;
        let buf = self
            .run(cancel, len as u64, "read range", || {
                let op = self.op();
                let path = path.to_owned();
                async move {
                    set_body_limit(len as u64);
                    let opts = ReadOptions {
                        range: (offset..offset + len as u64).into(),
                        ..ReadOptions::default()
                    };
                    op.read_options(&path, opts).await
                }
            })
            .await?;
        if buf.len() != len {
            tracing::warn!("a ranged read answered a different length");
            return Err(DriveError::new(EC::Internal));
        }
        Ok(Chunk {
            parts: buf.into_iter().collect(),
            _permit: permit,
        })
    }

    /// Starts a read of a whole object (`range` is `None`) or of `(offset, length)` of it.
    ///
    /// An object of at most one chunk is read here and now, so that its failure is an ordinary
    /// answer. A larger one is `stat`ed first (a size over the type's cap, or a range past the end,
    /// is `INTERNAL`) and its first chunk is read; the rest comes from
    /// [`ReadStream::next_chunk`].
    ///
    /// # Errors
    /// `NOT_FOUND`, `INTERNAL` for a size that is wrong, or the class of a Drive failure.
    pub async fn open_read(
        self: &Arc<Self>,
        ty: pb::ObjectType,
        id: &Id,
        range: Option<(u32, u32)>,
        cancel: &Cancel,
    ) -> Result<ReadStream, DriveError> {
        let cap = repo::max_object_size(ty).ok_or(DriveError::new(EC::Internal))? as usize;
        let path = path_of(ty, id)?;
        let internal = || DriveError::new(EC::Internal);
        let (offset, end) = match range {
            Some((off, len)) if (len as usize) <= READ_CHUNK => {
                let c = self
                    .read_range(&path, u64::from(off), len as usize, cancel)
                    .await?;
                return Ok(ReadStream {
                    repo: self.clone(),
                    path,
                    size: len,
                    offset: u64::from(off) + u64::from(len),
                    end: u64::from(off) + u64::from(len),
                    first: Some(c),
                });
            }
            None if cap <= READ_CHUNK => {
                // CONFIG, KEY, SNAPSHOT: one read of an unknown length, at most the cap.
                let n = kib(cap).min(self.read_budget_kib as u32);
                let permit = cancel
                    .guard(self.read_budget.clone().acquire_many_owned(n))
                    .await?
                    .map_err(|_| internal())?;
                let buf = self
                    .run(cancel, cap as u64, "read", || {
                        let op = self.op();
                        let path = path.clone();
                        async move {
                            set_body_limit(cap as u64);
                            op.read(&path).await
                        }
                    })
                    .await?;
                let len = buf.len();
                if len > cap {
                    return Err(internal());
                }
                return Ok(ReadStream {
                    repo: self.clone(),
                    path,
                    size: u32::try_from(len).map_err(|_| internal())?,
                    offset: len as u64,
                    end: len as u64,
                    first: Some(Chunk {
                        parts: buf.into_iter().collect(),
                        _permit: permit,
                    }),
                });
            }
            Some((off, len)) => (u64::from(off), u64::from(off) + u64::from(len)),
            None => (0, 0),
        };
        // Larger than one chunk: the size first.
        let Some((size, is_file)) = self.stat(&path, "stat object", cancel).await? else {
            return Err(DriveError::new(EC::NotFound));
        };
        if !is_file {
            return Err(internal());
        }
        let (offset, end) = match range {
            None => {
                if size > cap as u64 {
                    return Err(internal());
                }
                (0, size)
            }
            Some(_) => {
                if end > size {
                    return Err(internal());
                }
                (offset, end)
            }
        };
        let total = u32::try_from(end - offset).map_err(|_| internal())?;
        let mut rs = ReadStream {
            repo: self.clone(),
            path,
            size: total,
            offset,
            end,
            first: None,
        };
        if total > 0 {
            rs.first = rs.next_chunk(cancel).await?;
        }
        Ok(rs)
    }

    async fn ensure_pack_folder(&self, xx: u8, cancel: &Cancel) -> Result<(), DriveError> {
        let mut ready = cancel.guard(self.folders.lock()).await?;
        if ready.contains(&xx) {
            return Ok(());
        }
        let dir = format!("data/{xx:02x}/");
        self.run(cancel, 0, "create data folder", || {
            let op = self.op();
            let dir = dir.clone();
            async move { op.create_dir(&dir).await }
        })
        .await?;
        ready.insert(xx);
        Ok(())
    }

    /// Writes an object (a retry overwrites, so an ambiguous failure does not duplicate it).
    /// A `CONFIG` is refused when one exists, and so is a `SNAPSHOT` that exists.
    ///
    /// # Errors
    /// `LEASE_HELD`, `PERMISSION` (config exists), or the class of a Drive failure.
    pub async fn write(
        &self,
        ty: pb::ObjectType,
        id: &Id,
        chunks: Vec<Bytes>,
        cancel: &Cancel,
    ) -> Result<(), DriveError> {
        let path = path_of(ty, id)?;
        self.check_lease(Mutation::Write, cancel).await?;
        if ty == pb::ObjectType::Config
            && self.stat("config", "stat config", cancel).await?.is_some()
        {
            return Err(DriveError::new(EC::Permission));
        }
        // A snapshot is create-only (ipc.md section 29, v0.8): a worker cannot re-write one it
        // did not make and report it as its own. The check is before the first attempt, so the
        // retries of this request still overwrite.
        if ty == pb::ObjectType::Snapshot
            && self.stat(&path, "stat snapshot", cancel).await?.is_some()
        {
            return Err(DriveError::new(EC::Permission));
        }
        if ty == pb::ObjectType::Pack {
            self.ensure_pack_folder(id[0], cancel).await?;
        }
        let size: usize = chunks.iter().map(Bytes::len).sum();
        self.run(cancel, size as u64, "write", || {
            let op = self.op();
            let path = path.clone();
            let chunks = chunks.clone();
            async move { op.write(&path, Buffer::from(chunks)).await }
        })
        .await
        .map(|_| ())
    }

    /// Removes an object permanently (`DELETE files/{id}`); an absent object is not an error. Only
    /// a file is removed: a folder at an object's path is refused, because deleting it would delete
    /// its subtree.
    ///
    /// # Errors
    /// `LEASE_HELD`, `INTERNAL` for a folder, or the class of a Drive failure.
    pub async fn remove(
        &self,
        ty: pb::ObjectType,
        id: &Id,
        cancel: &Cancel,
    ) -> Result<(), DriveError> {
        let path = path_of(ty, id)?;
        self.check_lease(Mutation::Remove, cancel).await?;
        match self.stat(&path, "stat object", cancel).await? {
            None => return Ok(()),
            Some((_, false)) => {
                tracing::warn!("a folder is at an object's path: not removed");
                return Err(DriveError::new(EC::Internal));
            }
            Some((_, true)) => {}
        }
        self.run(cancel, 0, "remove", || {
            let op = self.op();
            let path = path.clone();
            async move { op.delete(&path).await }
        })
        .await
    }

    /// Creates `keys`, `snapshots`, `index` and `data` (never the `data/xx` folders).
    ///
    /// # Errors
    /// `LEASE_HELD`, or the class of a Drive failure.
    pub async fn create(&self, cancel: &Cancel) -> Result<(), DriveError> {
        self.check_lease(Mutation::Create, cancel).await?;
        for dir in ["keys/", "snapshots/", "index/", "data/"] {
            self.run(cancel, 0, "create folder", || {
                let op = self.op();
                async move { op.create_dir(dir).await }
            })
            .await?;
        }
        Ok(())
    }

    /// Deletes everything below the repository folder, and the folder, leaves first (Drive
    /// refuses a folder that has children). Not reachable from the link in v1 (ipc.md §29).
    ///
    /// # Errors
    /// `LEASE_HELD`, or the class of a Drive failure.
    pub async fn purge_tree(&self, cancel: &Cancel) -> Result<(), DriveError> {
        self.check_lease(Mutation::Remove, cancel).await?;
        let mut entries = self
            .run(cancel, 0, "list tree", || {
                let op = self.op();
                async move {
                    let opts = ListOptions {
                        recursive: true,
                        ..ListOptions::default()
                    };
                    op.list_options("/", opts).await
                }
            })
            .await?;
        // Deepest first; files before the folders that hold them.
        entries.sort_by_key(|e| {
            std::cmp::Reverse(e.path().trim_end_matches('/').matches('/').count())
        });
        for e in entries.iter().filter(|e| e.path() != "/") {
            let path = e.path().to_owned();
            self.run(cancel, 0, "delete", || {
                let op = self.op();
                let path = path.clone();
                async move { op.delete(&path).await }
            })
            .await?;
        }
        self.run(cancel, 0, "delete root", || {
            let op = self.op();
            async move { op.delete("/").await }
        })
        .await
    }

    /// `about.storageQuota` (counts the trash).
    ///
    /// # Errors
    /// The class of a Drive failure; `AUTH_REVOKED` for a revoked token.
    pub async fn quota(&self, cancel: &Cancel) -> Result<QuotaInfo, DriveError> {
        self.api.quota(cancel).await
    }

    /// This server's id (hex), as written in the lease.
    #[must_use]
    pub fn server_id(&self) -> &str {
        &self.ours
    }

    /// Whether the lease has been seen to be lost.
    pub async fn lease_lost(&self) -> bool {
        self.lease.is_lost().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_paths_follow_the_restic_layout() {
        let mut id = [0xab; 32];
        id[0] = 0x0f;
        let hex = lease::hex_id(&id);
        let p = |t| object_path(t, &id).unwrap();
        assert_eq!(p(pb::ObjectType::Config), "config");
        assert_eq!(p(pb::ObjectType::Key), format!("keys/{hex}"));
        assert_eq!(p(pb::ObjectType::Snapshot), format!("snapshots/{hex}"));
        assert_eq!(p(pb::ObjectType::Index), format!("index/{hex}"));
        assert_eq!(p(pb::ObjectType::Pack), format!("data/0f/{hex}"));
    }

    #[test]
    fn an_unspecified_type_names_no_object() {
        assert_eq!(object_path(pb::ObjectType::Unspecified, &[1; 32]), None);
        assert_eq!(
            path_of(pb::ObjectType::Unspecified, &[1; 32])
                .unwrap_err()
                .class,
            EC::Internal,
            "never the config object"
        );
    }

    #[test]
    fn ids_are_64_lower_hex_digits() {
        assert_eq!(parse_id(&"ab".repeat(32)), Some([0xab; 32]));
        assert_eq!(parse_id(&"AB".repeat(32)), None);
        assert_eq!(parse_id(&"ab".repeat(31)), None);
        assert_eq!(parse_id(&format!("{}.tmp", "ab".repeat(30))), None);
        assert_eq!(parse_id("config"), None);
    }

    #[test]
    fn form_values_are_percent_encoded() {
        assert_eq!(percent("1//a+b=c~d-e_f.g"), "1%2F%2Fa%2Bb%3Dc~d-e_f.g");
        assert_eq!(percent("a b&c"), "a%20b%26c");
    }
}
