//! The repository on Google Drive: S4's `HxDrive` ported to the helper's raw object operations
//! (ipc.md §27, §29). OpenDAL's `gdrive` service does the Drive calls through [`GoogleTransport`];
//! this module adds the layout, the retries ([`Retrier`]), the lease, the lazy `data/xx` folders,
//! the read-memory budget and the quota.
//!
//! Layout below `OpenRepo.folder` (a folder under My Drive): `config`, `keys/<hex>`,
//! `snapshots/<hex>`, `index/<hex>`, `data/<xx>/<hex>` and `hx-lease.json`.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use hx_ipc::repo::{self, pb};
use opendal::options::{ListOptions, ReadOptions};
use opendal::services::Gdrive;
use opendal::{Buffer, HttpTransport, HttpTransporter, OperationContext, Operator};
use tokio::sync::{Mutex, Semaphore};
use zeroize::Zeroizing;

use super::creds::{ClientConfig, Token};
use super::lease::{
    self, Found, LEASE_FILE, Lease, LeaseGuard, MAX_LEASE_BYTES, Mutation, OpenDecision, Unreadable,
};
use super::retry::{Cancel, DriveError, Retrier};
use super::transport::GoogleTransport;

use pb::ErrorClass as EC;

/// The read budget in KiB: reads reserve their size from this (ipc.md §29, "Memory").
const READ_BUDGET_KIB: usize = 96 * 1024;

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
            read_budget: Arc::new(Semaphore::new(READ_BUDGET_KIB)),
        }
    }

    fn operator(&self, folder: &str) -> Result<Operator, DriveError> {
        let builder = Gdrive::default()
            .root(&format!("/{folder}/"))
            .client_id(self.api.client.id())
            .client_secret(self.api.client.secret())
            .refresh_token(self.api.token.expose());
        let ctx = OperationContext::new()
            .with_http_transport(HttpTransporter::new(self.api.transport.clone()));
        Operator::new(builder)
            .map(|op| op.with_context(ctx))
            .map_err(|_| DriveError::new(EC::Internal))
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
        let op = self.operator(&p.folder)?;
        let r = &self.retrier;
        // OpenDAL answers a stat of its root without asking Drive, so the folder is asked for
        // directly.
        if !self.api.folder_exists(&p.folder, cancel).await? {
            if !p.create {
                return Err(DriveError::new(EC::NotFound));
            }
            r.run(cancel, 0, "create folder", || op.create_dir("/"))
                .await?;
        }
        let repo = Repo {
            op,
            retrier: self.retrier.clone(),
            api: self.api.clone(),
            folders: Mutex::new(HashSet::new()),
            read_budget: self.read_budget.clone(),
            lease: LeaseGuard::new(
                lease::hex_id(&p.server_id),
                0,
                self.retrier.timing().lease_cache,
            ),
            ours: lease::hex_id(&p.server_id),
        };
        let found = repo.read_lease(cancel).await?;
        let generation = match lease::decide_open(&found, &repo.ours, p.takeover) {
            OpenDecision::Accept(g) => g,
            OpenDecision::Write(g) => {
                let l = Lease::new(&repo.ours, g, unix_secs(), &self.hint);
                let bytes = l.to_bytes();
                r.run(cancel, bytes.len() as u64, "write lease", || {
                    repo.op
                        .write(LEASE_FILE, Buffer::from(Bytes::from(bytes.clone())))
                })
                .await?;
                g
            }
            OpenDecision::Held => return Err(DriveError::new(EC::LeaseHeld)),
            OpenDecision::Unreadable => return Err(DriveError::new(EC::Internal)),
        };
        Ok(Repo {
            lease: LeaseGuard::new(
                repo.ours.clone(),
                generation,
                self.retrier.timing().lease_cache,
            ),
            ..repo
        })
    }
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The path of an object below the repository folder.
#[must_use]
pub fn object_path(ty: pb::ObjectType, id: &Id) -> String {
    let hex = lease::hex_id(id);
    match ty {
        pb::ObjectType::Config | pb::ObjectType::Unspecified => "config".to_owned(),
        pb::ObjectType::Key => format!("keys/{hex}"),
        pb::ObjectType::Snapshot => format!("snapshots/{hex}"),
        pb::ObjectType::Index => format!("index/{hex}"),
        pb::ObjectType::Pack => format!("data/{}/{hex}", &hex[..2]),
    }
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
    /// Is there a live folder `name` directly under My Drive?
    async fn folder_exists(&self, name: &str, cancel: &Cancel) -> Result<bool, DriveError> {
        let token = self.access_token(cancel).await?;
        let q = format!(
            "name = '{name}' and 'root' in parents and mimeType = 'application/vnd.google-apps.folder' and trashed = false"
        );
        let url = format!(
            "https://www.googleapis.com/drive/v3/files?q={}&pageSize=1&fields=files(id)",
            percent(&q)
        );
        let body = self
            .retrier
            .run(cancel, 0, "find folder", || async {
                let req = http::Request::get(url.as_str())
                    .header(
                        http::header::AUTHORIZATION,
                        format!("Bearer {}", token.as_str()),
                    )
                    .body(Buffer::new())
                    .map_err(|_| opendal::Error::new(opendal::ErrorKind::Unexpected, "request"))?;
                let resp = self.transport.fetch(req).await?;
                if resp.status() != http::StatusCode::OK {
                    return Err(opendal::Error::new(
                        opendal::ErrorKind::Unexpected,
                        "find folder",
                    ));
                }
                Ok(resp.into_body().to_buffer().await?.to_bytes())
            })
            .await?;
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
            .run(cancel, 0, "refresh token", || async {
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
        let token = self.access_token(cancel).await?;
        let body = self
            .retrier
            .run(cancel, 0, "about", || async {
                let req = http::Request::get(
                    "https://www.googleapis.com/drive/v3/about?fields=storageQuota",
                )
                .header(
                    http::header::AUTHORIZATION,
                    format!("Bearer {}", token.as_str()),
                )
                .body(Buffer::new())
                .map_err(|_| opendal::Error::new(opendal::ErrorKind::Unexpected, "request"))?;
                let resp = self.transport.fetch(req).await?;
                if resp.status() != http::StatusCode::OK {
                    return Err(opendal::Error::new(opendal::ErrorKind::Unexpected, "about"));
                }
                Ok(resp.into_body().to_buffer().await?.to_bytes())
            })
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

/// One opened repository (a folder, a lease, an operator).
pub struct Repo {
    op: Operator,
    retrier: Arc<Retrier>,
    api: Arc<Api>,
    folders: Mutex<HashSet<u8>>,
    read_budget: Arc<Semaphore>,
    lease: LeaseGuard,
    ours: String,
}

impl Repo {
    async fn read_lease(&self, cancel: &Cancel) -> Result<Found, DriveError> {
        // A ranged read of a file shorter than the range is an error in OpenDAL, so the size is
        // asked first: a lease object over the cap is never downloaded.
        let got = self
            .retrier
            .run(cancel, 0, "read lease", || async {
                let m = self.op.stat(LEASE_FILE).await?;
                if m.content_length() > MAX_LEASE_BYTES as u64 {
                    return Ok(None);
                }
                self.op.read(LEASE_FILE).await.map(Some)
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
        self.lease.check(m, || self.read_lease(cancel)).await
    }

    /// Lists the objects of `ty`. The whole listing is collected before anything is returned: a
    /// failed page is an error, never a short list.
    ///
    /// # Errors
    /// The class of a Drive failure; `INTERNAL` for an object over its type's cap.
    pub async fn list(
        &self,
        ty: pb::ObjectType,
        cancel: &Cancel,
    ) -> Result<Vec<(Id, u32)>, DriveError> {
        let cap = repo::max_object_size(ty).ok_or(DriveError::new(EC::Internal))?;
        if ty == pb::ObjectType::Config {
            return match self
                .retrier
                .run(cancel, 0, "stat config", || self.op.stat("config"))
                .await
            {
                Ok(m) => {
                    let size = u32::try_from(m.content_length())
                        .ok()
                        .filter(|s| *s <= cap)
                        .ok_or(DriveError::new(EC::Internal))?;
                    Ok(vec![([0u8; 32], size)])
                }
                Err(e) if e.class == EC::NotFound => Ok(vec![]),
                Err(e) => Err(e),
            };
        }
        let dir = match ty {
            pb::ObjectType::Key => "keys/",
            pb::ObjectType::Snapshot => "snapshots/",
            pb::ObjectType::Index => "index/",
            _ => "data/",
        };
        let opts = ListOptions {
            recursive: ty == pb::ObjectType::Pack,
            ..ListOptions::default()
        };
        let entries = match self
            .retrier
            .run(cancel, 0, "list", || {
                self.op.list_options(dir, opts.clone())
            })
            .await
        {
            Ok(v) => v,
            Err(e) if e.class == EC::NotFound => return Ok(vec![]),
            Err(e) => return Err(e),
        };
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for entry in entries {
            let md = entry.metadata();
            if !md.is_file() {
                continue;
            }
            let Some(id) = parse_id(entry.name()) else {
                continue;
            };
            if id == [0u8; 32] || entry.path() != object_path(ty, &id) {
                continue;
            }
            if !seen.insert(id) {
                continue;
            }
            let size = u32::try_from(md.content_length())
                .ok()
                .filter(|s| *s <= cap)
                .ok_or_else(|| {
                    tracing::warn!("a listed object is larger than its type's cap");
                    DriveError::new(EC::Internal)
                })?;
            out.push((id, size));
            if out.len() > repo::MAX_LIST_ENTRIES as usize {
                return Err(DriveError::new(EC::Internal));
            }
        }
        Ok(out)
    }

    async fn reserve(
        &self,
        bytes: usize,
        cancel: &Cancel,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, DriveError> {
        let n = kib(bytes).min(READ_BUDGET_KIB as u32);
        cancel
            .guard(self.read_budget.clone().acquire_many_owned(n))
            .await?
            .map_err(|_| DriveError::new(EC::Internal))
    }

    /// Reads a whole object.
    ///
    /// # Errors
    /// `NOT_FOUND`, or the class of a Drive failure.
    pub async fn read_full(
        &self,
        ty: pb::ObjectType,
        id: &Id,
        cancel: &Cancel,
    ) -> Result<Bytes, DriveError> {
        let cap = repo::max_object_size(ty).ok_or(DriveError::new(EC::Internal))? as usize;
        let _permit = self.reserve(cap, cancel).await?;
        let path = object_path(ty, id);
        let buf = self
            .retrier
            .run(cancel, cap as u64, "read", || self.op.read(&path))
            .await?;
        if buf.len() > cap {
            return Err(DriveError::new(EC::Internal));
        }
        Ok(buf.to_bytes())
    }

    /// Reads `length` bytes at `offset`; anything shorter is `INTERNAL`.
    ///
    /// # Errors
    /// `NOT_FOUND`, `INTERNAL` for a short answer, or the class of a Drive failure.
    pub async fn read_partial(
        &self,
        ty: pb::ObjectType,
        id: &Id,
        offset: u32,
        length: u32,
        cancel: &Cancel,
    ) -> Result<Bytes, DriveError> {
        let _permit = self.reserve(length as usize, cancel).await?;
        let path = object_path(ty, id);
        let range = u64::from(offset)..u64::from(offset) + u64::from(length);
        let buf = self
            .retrier
            .run(cancel, u64::from(length), "read range", || {
                let opts = ReadOptions {
                    range: range.clone().into(),
                    ..ReadOptions::default()
                };
                self.op.read_options(&path, opts)
            })
            .await?;
        let bytes = buf.to_bytes();
        if bytes.len() != length as usize {
            tracing::warn!("a ranged read answered a different length");
            return Err(DriveError::new(EC::Internal));
        }
        Ok(bytes)
    }

    async fn ensure_pack_folder(&self, xx: u8, cancel: &Cancel) -> Result<(), DriveError> {
        let mut ready = cancel.guard(self.folders.lock()).await?;
        if ready.contains(&xx) {
            return Ok(());
        }
        let dir = format!("data/{xx:02x}/");
        self.retrier
            .run(cancel, 0, "create data folder", || self.op.create_dir(&dir))
            .await?;
        ready.insert(xx);
        Ok(())
    }

    /// Writes an object (a retry overwrites, so an ambiguous failure does not duplicate it).
    /// A `CONFIG` is refused when one exists.
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
        self.check_lease(Mutation::Write, cancel).await?;
        let path = object_path(ty, id);
        if ty == pb::ObjectType::Config {
            match self
                .retrier
                .run(cancel, 0, "stat config", || self.op.stat("config"))
                .await
            {
                Ok(_) => return Err(DriveError::new(EC::Permission)),
                Err(e) if e.class == EC::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        if ty == pb::ObjectType::Pack {
            self.ensure_pack_folder(id[0], cancel).await?;
        }
        let size: usize = chunks.iter().map(Bytes::len).sum();
        self.retrier
            .run(cancel, size as u64, "write", || {
                self.op.write(&path, Buffer::from(chunks.clone()))
            })
            .await
            .map(|_| ())
    }

    /// Removes an object permanently (`DELETE files/{id}`); an absent object is not an error.
    ///
    /// # Errors
    /// `LEASE_HELD`, or the class of a Drive failure.
    pub async fn remove(
        &self,
        ty: pb::ObjectType,
        id: &Id,
        cancel: &Cancel,
    ) -> Result<(), DriveError> {
        self.check_lease(Mutation::Remove, cancel).await?;
        let path = object_path(ty, id);
        self.retrier
            .run(cancel, 0, "remove", || self.op.delete(&path))
            .await
    }

    /// Creates `keys`, `snapshots`, `index` and `data` (never the `data/xx` folders).
    ///
    /// # Errors
    /// `LEASE_HELD`, or the class of a Drive failure.
    pub async fn create(&self, cancel: &Cancel) -> Result<(), DriveError> {
        self.check_lease(Mutation::Create, cancel).await?;
        for dir in ["keys/", "snapshots/", "index/", "data/"] {
            self.retrier
                .run(cancel, 0, "create folder", || self.op.create_dir(dir))
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
        let opts = ListOptions {
            recursive: true,
            ..ListOptions::default()
        };
        let mut entries = self
            .retrier
            .run(cancel, 0, "list tree", || {
                self.op.list_options("/", opts.clone())
            })
            .await?;
        // Deepest first; files before the folders that hold them.
        entries.sort_by_key(|e| {
            std::cmp::Reverse(e.path().trim_end_matches('/').matches('/').count())
        });
        for e in entries.iter().filter(|e| e.path() != "/") {
            let path = e.path().to_owned();
            self.retrier
                .run(cancel, 0, "delete", || self.op.delete(&path))
                .await?;
        }
        self.retrier
            .run(cancel, 0, "delete root", || self.op.delete("/"))
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
        assert_eq!(object_path(pb::ObjectType::Config, &[0; 32]), "config");
        assert_eq!(object_path(pb::ObjectType::Key, &id), format!("keys/{hex}"));
        assert_eq!(
            object_path(pb::ObjectType::Snapshot, &id),
            format!("snapshots/{hex}")
        );
        assert_eq!(
            object_path(pb::ObjectType::Index, &id),
            format!("index/{hex}")
        );
        assert_eq!(
            object_path(pb::ObjectType::Pack, &id),
            format!("data/0f/{hex}")
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
