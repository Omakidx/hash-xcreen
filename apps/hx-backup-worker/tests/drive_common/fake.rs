//! A fake Google: the OAuth token endpoint and exactly the Drive v3 subset that OpenDAL's `gdrive`
//! service calls (files.list with `q`, `pageSize` and `pageToken`; files.create for folders;
//! multipart and media upload; get with `alt=media` and `Range`; get metadata; `PATCH trashed`;
//! `DELETE`; about.storageQuota), served over TLS from a certificate made at test time.
//!
//! It models folders and files (ids, names, parents, trash), refuses to delete a folder that has
//! children as the real Drive does for `drive.file` (403 `appNotAuthorizedToChild`), records every
//! request, and injects faults by request category.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

pub const FOLDER: &str = "application/vnd.google-apps.folder";
/// The only refresh token the fake accepts.
pub const REFRESH_TOKEN: &str = "1//fake-refresh-token-for-tests";
pub const CLIENT_ID: &str = "fake-client-id.apps.test";
pub const CLIENT_SECRET: &str = "fake-client-secret-for-tests";

#[derive(Clone, Debug)]
pub struct File {
    pub id: String,
    pub name: String,
    pub parent: String,
    pub folder: bool,
    pub data: Vec<u8>,
    pub trashed: bool,
    pub mtime: u64,
}

/// What a fault does to the request it matches.
#[derive(Clone, Debug)]
pub enum Action {
    /// Answer with this status and Drive error body.
    Status {
        status: u16,
        reason: &'static str,
        retry_after: Option<u32>,
    },
    /// Answer with a raw body (for example an OAuth error).
    Raw { status: u16, body: &'static str },
    /// Never answer.
    Hang,
    /// Answer 302 with this `Location` (the helper must not follow it).
    Redirect(&'static str),
    /// Close the connection without answering.
    Drop,
    /// Answer 200 with no `Content-Length` and this many body bytes, then close (a body of
    /// unknown length that is far longer than what was asked for).
    Unbounded(usize),
    /// Like `Unbounded`, but with status 500 (an error body that never ends).
    UnboundedError(usize),
    /// Send the headers, wait this many milliseconds, then send the whole body.
    SlowBody(u64),
    /// Send the headers and a little of the body, then keep the connection open (and read until
    /// the client closes it).
    StallBody,
    /// Send the headers and half of the body, then close.
    TruncateBody,
    /// Read this many bytes of the request body, then close.
    DropAfterBody(usize),
}

#[derive(Clone, Debug)]
pub struct Fault {
    /// A category (`list`, `get.media`, `upload`, `create`, `delete`, `trash`, `about`, `token`,
    /// `meta`) or `*`.
    pub category: &'static str,
    /// Let this many matching requests pass first.
    pub skip: u32,
    /// Then fail this many.
    pub times: u32,
    pub action: Action,
}

impl Fault {
    pub fn status(category: &'static str, times: u32, status: u16, reason: &'static str) -> Self {
        Self {
            category,
            skip: 0,
            times,
            action: Action::Status {
                status,
                reason,
                retry_after: None,
            },
        }
    }
}

#[derive(Clone, Debug)]
pub struct Req {
    pub method: String,
    pub path: String,
    pub category: &'static str,
    pub at: std::time::Instant,
    pub has_query: bool,
}

#[derive(Default)]
pub struct Model {
    files: HashMap<String, File>,
    next: u64,
    clock: u64,
    pub log: Vec<Req>,
    faults: Vec<Fault>,
    pub quota: (u64, u64, u64),
    pub tokens_issued: u32,
    pub bad_refresh_tokens: u32,
    pub unauthorized: u32,
    pub list_pages: u32,
    /// Fail the n-th page of a listing with a page token (0 = never).
    pub fail_list_page: u32,
    /// Fail every request for a page after the first one of a listing.
    pub fail_continuations: bool,
    /// Answer every list with one file and the same `nextPageToken` for ever.
    pub repeat_token: bool,
    /// The refresh token the token endpoint accepts (default [`REFRESH_TOKEN`]).
    pub expected_refresh: Option<String>,
    /// An `Unbounded` body was written to the end (the client did not stop reading).
    pub big_written_ok: bool,
    /// Bytes of media bodies served so far.
    pub media_bytes: u64,
    /// Answer every list with at most this many files per page (0 = the requested size).
    pub force_page_size: usize,
    /// Delay before answering each request in these categories.
    pub delay: HashMap<&'static str, Duration>,
    /// Max request bodies seen at once is not modelled; uploads seen:
    pub uploads: Vec<(String, usize)>,
}

pub struct FakeGoogle {
    pub addr: SocketAddr,
    pub cert_pem: String,
    pub model: Arc<Mutex<Model>>,
    stop: Arc<AtomicBool>,
    rt: Option<tokio::runtime::Runtime>,
}

impl Drop for FakeGoogle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

fn pem(label: &str, der: &[u8]) -> String {
    use std::fmt::Write;
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = String::new();
    for c in der.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                b64.push(char::from(T[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                b64.push('=');
            }
        }
    }
    let mut out = String::new();
    let _ = writeln!(out, "-----BEGIN {label}-----");
    for line in b64.as_bytes().chunks(64) {
        let _ = writeln!(out, "{}", std::str::from_utf8(line).unwrap());
    }
    let _ = writeln!(out, "-----END {label}-----");
    out
}

pub fn category(method: &str, path: &str, query: &str) -> &'static str {
    if path == "/token" {
        return "token";
    }
    if path.starts_with("/upload/") {
        return "upload";
    }
    if path == "/drive/v3/about" {
        return "about";
    }
    let Some(rest) = path.strip_prefix("/drive/v3/files") else {
        return "other";
    };
    match (method, rest) {
        ("GET", "") => "list",
        ("GET", _) if query.contains("alt=media") => "get.media",
        ("GET", _) => "meta",
        ("POST", "") => "create",
        ("PATCH", _) => "trash",
        ("DELETE", _) => "delete",
        _ => "other",
    }
}

pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == key).then(|| percent_decode(v))
    })
}

fn json_escape(s: &str) -> String {
    serde_json::to_string(s).unwrap()
}

impl Model {
    fn new_id(&mut self) -> String {
        self.next += 1;
        format!("id{:06}", self.next)
    }

    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    fn file_json(f: &File) -> String {
        let mtime = format!(
            "2026-01-01T00:{:02}:{:02}.000Z",
            (f.mtime / 60) % 60,
            f.mtime % 60
        );
        if f.folder {
            format!(
                r#"{{"id":"{}","name":{},"mimeType":"{FOLDER}","modifiedTime":"{mtime}","parents":["{}"]}}"#,
                f.id,
                json_escape(&f.name),
                f.parent
            )
        } else {
            format!(
                r#"{{"id":"{}","name":{},"mimeType":"application/octet-stream","size":"{}","modifiedTime":"{mtime}","parents":["{}"]}}"#,
                f.id,
                json_escape(&f.name),
                f.data.len(),
                f.parent
            )
        }
    }

    pub fn create(&mut self, name: &str, parent: &str, folder: bool, data: Vec<u8>) -> String {
        let id = self.new_id();
        let mtime = self.tick();
        self.files.insert(
            id.clone(),
            File {
                id: id.clone(),
                name: name.to_owned(),
                parent: parent.to_owned(),
                folder,
                data,
                trashed: false,
                mtime,
            },
        );
        id
    }

    fn find_child(&self, parent: &str, name: &str) -> Option<&File> {
        self.files
            .values()
            .find(|f| f.parent == parent && f.name == name && !f.trashed)
    }

    /// Creates the folders of `path` (below `root`) and returns the id of the last.
    pub fn mkdirs(&mut self, path: &str) -> String {
        let mut parent = "root".to_owned();
        for part in path.split('/').filter(|p| !p.is_empty()) {
            parent = match self.find_child(&parent, part) {
                Some(f) => f.id.clone(),
                None => self.create(part, &parent, true, vec![]),
            };
        }
        parent
    }

    pub fn put(&mut self, path: &str, data: &[u8]) {
        let (dir, name) = path.rsplit_once('/').unwrap_or(("", path));
        let parent = self.mkdirs(dir);
        if let Some(id) = self.find_child(&parent, name).map(|f| f.id.clone()) {
            let mtime = self.tick();
            let f = self.files.get_mut(&id).unwrap();
            f.data = data.to_vec();
            f.mtime = mtime;
        } else {
            self.create(name, &parent, false, data.to_vec());
        }
    }

    fn resolve(&self, path: &str) -> Option<&File> {
        let mut parent = "root".to_owned();
        let mut last = None;
        for part in path.split('/').filter(|p| !p.is_empty()) {
            let f = self.find_child(&parent, part)?;
            parent = f.id.clone();
            last = Some(f);
        }
        last
    }

    pub fn get(&self, path: &str) -> Option<Vec<u8>> {
        self.resolve(path)
            .filter(|f| !f.folder)
            .map(|f| f.data.clone())
    }

    pub fn exists(&self, path: &str) -> bool {
        self.resolve(path).is_some()
    }

    pub fn id_of(&self, path: &str) -> Option<String> {
        self.resolve(path).map(|f| f.id.clone())
    }

    pub fn is_folder(&self, path: &str) -> bool {
        self.resolve(path).is_some_and(|f| f.folder)
    }

    /// Paths of all live files and folders, folders with a trailing slash, sorted.
    pub fn paths(&self) -> Vec<String> {
        fn path_of(m: &Model, f: &File) -> String {
            let mut parts = vec![f.name.clone()];
            let mut p = f.parent.clone();
            while let Some(parent) = m.files.get(&p) {
                parts.push(parent.name.clone());
                p = parent.parent.clone();
            }
            parts.reverse();
            parts.join("/")
        }
        let mut v: Vec<String> = self
            .files
            .values()
            .filter(|f| !f.trashed)
            .map(|f| {
                let p = path_of(self, f);
                if f.folder { format!("{p}/") } else { p }
            })
            .collect();
        v.sort();
        v
    }

    pub fn trashed_count(&self) -> usize {
        self.files.values().filter(|f| f.trashed).count()
    }

    pub fn count(&self, category: &str) -> usize {
        self.log.iter().filter(|r| r.category == category).count()
    }

    pub fn inject(&mut self, f: Fault) {
        self.faults.push(f);
    }

    pub fn clear_faults(&mut self) {
        self.faults.clear();
    }

    /// A `DropAfterBody` fault for this request, consumed at the head (before the body is read).
    fn take_head_fault(&mut self, category: &str) -> Option<usize> {
        for f in &mut self.faults {
            let Action::DropAfterBody(n) = f.action else {
                continue;
            };
            if f.times == 0 || !(f.category == "*" || f.category == category) {
                continue;
            }
            if f.skip > 0 {
                f.skip -= 1;
                return None;
            }
            f.times -= 1;
            return Some(n);
        }
        None
    }

    fn take_fault(&mut self, category: &str) -> Option<Action> {
        for f in &mut self.faults {
            if matches!(f.action, Action::DropAfterBody(_))
                || f.times == 0
                || !(f.category == "*" || f.category == category)
            {
                continue;
            }
            if f.skip > 0 {
                f.skip -= 1;
                return None;
            }
            f.times -= 1;
            return Some(f.action.clone());
        }
        None
    }

    fn matches_q(&self, f: &File, q: &str) -> bool {
        for term in q.split(" and ") {
            let term = term.trim();
            if term == "trashed = false" {
                if f.trashed {
                    return false;
                }
            } else if let Some(v) = term.strip_prefix("name = '") {
                let name = v.strip_suffix('\'').unwrap_or(v).replace("\\'", "'");
                if f.name != name {
                    return false;
                }
            } else if let Some(v) = term.strip_prefix("mimeType = '") {
                let m = v.strip_suffix('\'').unwrap_or(v);
                if (m == FOLDER) != f.folder {
                    return false;
                }
            } else if term.contains("in parents") {
                let inner = term.trim_start_matches('(').trim_end_matches(')');
                let any = inner.split(" or ").any(|t| {
                    t.trim()
                        .strip_prefix('\'')
                        .and_then(|r| r.split_once('\''))
                        .is_some_and(|(id, _)| id == f.parent)
                });
                if !any {
                    return false;
                }
            } else {
                panic!("fake Drive: unsupported query term {term:?}");
            }
        }
        true
    }
}

struct Request {
    method: String,
    path: String,
    query: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

struct Response {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

fn json(status: u16, body: String) -> Response {
    Response {
        status,
        headers: vec![("Content-Type", "application/json; charset=UTF-8".into())],
        body: body.into_bytes(),
    }
}

fn drive_error(status: u16, reason: &str, retry_after: Option<u32>) -> Response {
    let msg = match reason {
        "dailyLimitExceeded" => "Daily Limit Exceeded",
        "rateLimitExceeded" => "Rate Limit Exceeded",
        "userRateLimitExceeded" => "User Rate Limit Exceeded",
        "storageQuotaExceeded" => "The user's Drive storage quota has been exceeded.",
        _ => "error",
    };
    let mut r = json(
        status,
        format!(
            r#"{{"error":{{"code":{status},"message":"{msg}","errors":[{{"message":"{msg}","domain":"usageLimits","reason":"{reason}"}}]}}}}"#
        ),
    );
    if let Some(s) = retry_after {
        r.headers.push(("Retry-After", s.to_string()));
    }
    r
}

fn not_found() -> Response {
    drive_error(404, "notFound", None)
}

fn handle(m: &mut Model, req: &Request) -> Response {
    let r = handle_inner(m, req);
    if category(&req.method, &req.path, &req.query) == "get.media" && r.status < 300 {
        m.media_bytes += r.body.len() as u64;
    }
    r
}

fn handle_inner(m: &mut Model, req: &Request) -> Response {
    let cat = category(&req.method, &req.path, &req.query);
    m.log.push(Req {
        method: req.method.clone(),
        path: req.path.clone(),
        category: cat,
        at: std::time::Instant::now(),
        has_query: !req.query.is_empty(),
    });
    if cat == "token" {
        let form = String::from_utf8_lossy(&req.body).into_owned();
        let all = format!("{}&{}", req.query, form);
        let rt = query_param(&all, "refresh_token").unwrap_or_default();
        if rt != m.expected_refresh.as_deref().unwrap_or(REFRESH_TOKEN)
            || query_param(&all, "client_id").as_deref() != Some(CLIENT_ID)
            || query_param(&all, "client_secret").as_deref() != Some(CLIENT_SECRET)
        {
            m.bad_refresh_tokens += 1;
            return json(
                400,
                r#"{"error":"invalid_grant","error_description":"Bad Request"}"#.into(),
            );
        }
        m.tokens_issued += 1;
        return json(
            200,
            format!(
                r#"{{"access_token":"fake-access-{}","expires_in":3600,"token_type":"Bearer"}}"#,
                m.tokens_issued
            ),
        );
    }
    let authorized = req
        .headers
        .get("authorization")
        .is_some_and(|a| a.starts_with("Bearer fake-access-"));
    if !authorized {
        m.unauthorized += 1;
        return json(401, r#"{"error":{"code":401,"message":"Invalid Credentials","errors":[{"reason":"authError"}]}}"#.into());
    }
    let p = &req.path;
    let q = &req.query;
    match (req.method.as_str(), cat) {
        (_, "about") => {
            let (limit, usage, trash) = m.quota;
            let limit = if limit == 0 {
                String::new()
            } else {
                format!(r#""limit":"{limit}","#)
            };
            json(
                200,
                format!(
                    r#"{{"storageQuota":{{{limit}"usage":"{usage}","usageInDriveTrash":"{trash}"}}}}"#
                ),
            )
        }
        (_, "list") => {
            let qs = query_param(q, "q").unwrap_or_default();
            let page_size: usize = query_param(q, "pageSize")
                .and_then(|s| s.parse().ok())
                .unwrap_or(100);
            let page_size = if m.force_page_size > 0 {
                m.force_page_size.min(page_size)
            } else {
                page_size
            };
            if m.repeat_token && !qs.contains("name = ") {
                let first = m.files.values().find(|f| m.matches_q(f, &qs)).cloned();
                let page = first.map(|f| Model::file_json(&f)).unwrap_or_default();
                return json(
                    200,
                    format!(r#"{{"files":[{page}],"nextPageToken":"again"}}"#).replace("[,", "["),
                );
            }
            let start: usize = query_param(q, "pageToken")
                .and_then(|t| t.parse().ok())
                .unwrap_or(0);
            if start > 0 {
                m.list_pages += 1;
                if m.fail_continuations
                    || (m.fail_list_page != 0 && m.list_pages == m.fail_list_page)
                {
                    return drive_error(500, "backendError", None);
                }
            }
            let mut files: Vec<&File> = m.files.values().filter(|f| m.matches_q(f, &qs)).collect();
            files.sort_by(|a, b| b.mtime.cmp(&a.mtime).then(a.id.cmp(&b.id)));
            let page: Vec<String> = files
                .iter()
                .skip(start)
                .take(page_size)
                .map(|f| Model::file_json(f))
                .collect();
            let next = if start + page.len() < files.len() {
                format!(r#","nextPageToken":"{}""#, start + page.len())
            } else {
                String::new()
            };
            json(200, format!(r#"{{"files":[{}]{next}}}"#, page.join(",")))
        }
        (_, "create") => {
            let v: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
            let name = v["name"].as_str().unwrap_or("").to_owned();
            let parent = v["parents"][0].as_str().unwrap_or("root").to_owned();
            let folder = v["mimeType"] == FOLDER;
            let id = m.create(&name, &parent, folder, vec![]);
            json(200, Model::file_json(&m.files[&id]))
        }
        (_, "upload") => {
            let ct = req.headers.get("content-type").cloned().unwrap_or_default();
            if req.method == "POST" {
                let boundary = ct
                    .split("boundary=")
                    .nth(1)
                    .unwrap_or("")
                    .trim_matches('"')
                    .to_owned();
                let (meta, data) = parse_multipart(&req.body, &boundary);
                let v: serde_json::Value = serde_json::from_slice(&meta).unwrap_or_default();
                let name = v["name"].as_str().unwrap_or("").to_owned();
                let parent = v["parents"][0].as_str().unwrap_or("root").to_owned();
                m.uploads.push((name.clone(), data.len()));
                let id = m.create(&name, &parent, false, data);
                json(200, Model::file_json(&m.files[&id]))
            } else {
                let id = p.rsplit('/').next().unwrap_or("").to_owned();
                let mtime = m.tick();
                m.uploads.push((id.clone(), req.body.len()));
                match m.files.get_mut(&id) {
                    Some(f) if !f.trashed => {
                        f.data = req.body.clone();
                        f.mtime = mtime;
                        json(200, Model::file_json(f))
                    }
                    _ => not_found(),
                }
            }
        }
        (_, "meta") => {
            let id = p.rsplit('/').next().unwrap_or("");
            match m.files.get(id) {
                Some(f) if !f.trashed => json(200, Model::file_json(f)),
                _ => not_found(),
            }
        }
        (_, "get.media") => {
            let id = p.rsplit('/').next().unwrap_or("");
            let Some(f) = m.files.get(id).filter(|f| !f.trashed) else {
                return not_found();
            };
            let total = f.data.len();
            if let Some(r) = req
                .headers
                .get("range")
                .and_then(|r| r.strip_prefix("bytes="))
            {
                let (a, b) = r.split_once('-').unwrap_or(("0", ""));
                let start: usize = a.parse().unwrap_or(0);
                let end: usize = b
                    .parse::<usize>()
                    .map_or(total.saturating_sub(1), |e| e.min(total.saturating_sub(1)));
                if start >= total {
                    return drive_error(416, "requestedRangeNotSatisfiable", None);
                }
                return Response {
                    status: 206,
                    headers: vec![
                        ("Content-Type", "application/octet-stream".into()),
                        ("Content-Range", format!("bytes {start}-{end}/{total}")),
                    ],
                    body: f.data[start..=end].to_vec(),
                };
            }
            Response {
                status: 200,
                headers: vec![("Content-Type", "application/octet-stream".into())],
                body: f.data.clone(),
            }
        }
        (_, "trash") => {
            let id = p.rsplit('/').next().unwrap_or("").to_owned();
            match m.files.get_mut(&id) {
                Some(f) => {
                    f.trashed = true;
                    json(200, Model::file_json(f))
                }
                None => not_found(),
            }
        }
        (_, "delete") => {
            let id = p.rsplit('/').next().unwrap_or("").to_owned();
            if !m.files.contains_key(&id) {
                return not_found();
            }
            if m.files.values().any(|c| c.parent == id) {
                return drive_error(403, "appNotAuthorizedToChild", None);
            }
            m.files.remove(&id);
            Response {
                status: 204,
                headers: vec![],
                body: vec![],
            }
        }
        _ => json(
            400,
            r#"{"error":{"code":400,"message":"fake: unsupported"}}"#.into(),
        ),
    }
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|i| i + from)
}

fn parse_multipart(body: &[u8], boundary: &str) -> (Vec<u8>, Vec<u8>) {
    let delim = format!("--{boundary}").into_bytes();
    let mut parts: Vec<Vec<u8>> = vec![];
    let mut at = find(body, &delim, 0).expect("multipart start") + delim.len();
    while let Some(next) = find(body, &delim, at) {
        // a part is between "\r\n" after the delimiter and "\r\n" before the next
        let part = &body[at + 2..next - 2];
        let split = find(part, b"\r\n\r\n", 0).expect("part header end");
        parts.push(part[split + 4..].to_vec());
        at = next + delim.len();
    }
    assert!(parts.len() >= 2, "multipart with metadata and file");
    (parts.remove(0), parts.remove(0))
}

async fn read_request<S: AsyncReadExt + Unpin>(s: &mut S, model: &Mutex<Model>) -> Option<Request> {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 16384];
    let head_end = loop {
        if let Some(i) = find(&buf, b"\r\n\r\n", 0) {
            break i;
        }
        let n = s.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let method = first.next()?.to_owned();
    let target = first.next()?.to_owned();
    let (path, query) = target
        .split_once('?')
        .map_or((target.clone(), String::new()), |(a, b)| {
            (a.to_owned(), b.to_owned())
        });
    let mut headers = HashMap::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
        }
    }
    let mut body = buf[head_end + 4..].to_vec();
    let cat = category(&method, &path, &query);
    let drop_after = model.lock().unwrap().take_head_fault(cat);
    if headers
        .get("transfer-encoding")
        .is_some_and(|t| t.contains("chunked"))
    {
        loop {
            // decode complete chunks from `body`
            let mut out = Vec::new();
            let mut at = 0;
            let mut complete = false;
            while let Some(e) = find(&body, b"\r\n", at) {
                let size =
                    usize::from_str_radix(String::from_utf8_lossy(&body[at..e]).trim(), 16).ok()?;
                if size == 0 {
                    complete = true;
                    break;
                }
                if body.len() < e + 2 + size + 2 {
                    break;
                }
                out.extend_from_slice(&body[e + 2..e + 2 + size]);
                at = e + 2 + size + 2;
            }
            if complete {
                body = out;
                break;
            }
            let n = s.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            body.extend_from_slice(&chunk[..n]);
        }
    } else {
        let want: usize = headers
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        while body.len() < want {
            if let Some(limit) = drop_after
                && body.len() >= limit
            {
                return None;
            }
            let n = s.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            body.extend_from_slice(&chunk[..n]);
        }
    }
    Some(Request {
        method,
        path,
        query,
        headers,
        body,
    })
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        302 => "Found",
        206 => "Partial Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

async fn serve_conn(tcp: TcpStream, acceptor: TlsAcceptor, model: Arc<Mutex<Model>>) {
    let _ = tcp.set_nodelay(true);
    let Ok(mut tls) = acceptor.accept(tcp).await else {
        return;
    };
    loop {
        let Some(req) = read_request(&mut tls, &model).await else {
            return;
        };
        let cat = category(&req.method, &req.path, &req.query);
        let (action, delay) = {
            let mut m = model.lock().unwrap();
            (m.take_fault(cat), m.delay.get(cat).copied())
        };
        if let Some(d) = delay {
            tokio::time::sleep(d).await;
        }
        let note = |m: &mut Model| {
            m.log.push(Req {
                method: req.method.clone(),
                path: req.path.clone(),
                category: cat,
                at: std::time::Instant::now(),
                has_query: !req.query.is_empty(),
            });
        };
        let mut truncate = false;
        let mut slow: Option<u64> = None;
        let action_kind = action.clone();
        let resp = match action {
            Some(Action::SlowBody(ms)) => {
                slow = Some(ms);
                handle(&mut model.lock().unwrap(), &req)
            }
            Some(Action::Hang) => {
                note(&mut model.lock().unwrap());
                tokio::time::sleep(Duration::from_secs(3600)).await;
                return;
            }
            Some(Action::StallBody) => {
                note(&mut model.lock().unwrap());
                let _ = tls
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                    )
                    .await;
                let _ = tls.flush().await;
                let mut buf = [0u8; 256];
                while matches!(tls.read(&mut buf).await, Ok(n) if n > 0) {}
                return;
            }
            Some(Action::Unbounded(n) | Action::UnboundedError(n)) => {
                note(&mut model.lock().unwrap());
                let head: &[u8] = if matches!(action_kind, Some(Action::UnboundedError(_))) {
                    b"HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n"
                } else {
                    b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"
                };
                let mut ok = tls.write_all(head).await.is_ok();
                let block = vec![0u8; 64 * 1024];
                let mut left = n;
                while ok && left > 0 {
                    let k = left.min(block.len());
                    ok = tls.write_all(&block[..k]).await.is_ok();
                    left -= k;
                }
                if ok && tls.flush().await.is_ok() {
                    model.lock().unwrap().big_written_ok = true;
                }
                return;
            }
            Some(Action::Drop | Action::DropAfterBody(_)) => {
                note(&mut model.lock().unwrap());
                return;
            }
            Some(Action::Status {
                status,
                reason,
                retry_after,
            }) => {
                note(&mut model.lock().unwrap());
                drive_error(status, reason, retry_after)
            }
            Some(Action::Redirect(to)) => {
                note(&mut model.lock().unwrap());
                let mut r = json(302, String::new());
                r.headers.push(("Location", to.to_owned()));
                r
            }
            Some(Action::Raw { status, body }) => {
                note(&mut model.lock().unwrap());
                json(status, body.to_owned())
            }
            Some(Action::TruncateBody) => {
                truncate = true;
                handle(&mut model.lock().unwrap(), &req)
            }
            None => handle(&mut model.lock().unwrap(), &req),
        };
        let mut head = format!(
            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\n",
            resp.status,
            reason(resp.status),
            resp.body.len()
        );
        for (k, v) in &resp.headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str("\r\n");
        let mut out = head.into_bytes();
        if let Some(ms) = slow {
            let _ = tls.write_all(&out).await;
            let _ = tls.flush().await;
            tokio::time::sleep(Duration::from_millis(ms)).await;
            out = resp.body.clone();
        }
        if truncate {
            out.extend_from_slice(&resp.body[..resp.body.len() / 2]);
            let _ = tls.write_all(&out).await;
            let _ = tls.flush().await;
            return;
        }
        out.extend_from_slice(&resp.body);
        if tls.write_all(&out).await.is_err() {
            return;
        }
        let _ = tls.flush().await;
    }
}

impl FakeGoogle {
    pub fn start() -> Self {
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names = vec![rcgen::SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST,
        ))];
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let cert_der: CertificateDer<'static> = cert.der().clone();
        let key_der = PrivatePkcs8KeyDer::from(key.serialize_der());
        let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let cfg = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der.into())
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(cfg));
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let listener = rt.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
        let addr = listener.local_addr().unwrap();
        let model = Arc::new(Mutex::new(Model::default()));
        let stop = Arc::new(AtomicBool::new(false));
        {
            let model = model.clone();
            rt.spawn(async move {
                loop {
                    let Ok((tcp, _)) = listener.accept().await else {
                        return;
                    };
                    tokio::spawn(serve_conn(tcp, acceptor.clone(), model.clone()));
                }
            });
        }
        Self {
            addr,
            cert_pem: pem("CERTIFICATE", cert_der.as_ref()),
            model,
            stop,
            rt: Some(rt),
        }
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut Model) -> R) -> R {
        f(&mut self.model.lock().unwrap())
    }
}
