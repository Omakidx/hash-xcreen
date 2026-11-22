//! The typed Incus REST client.
//!
//! Follows the API's background-operation model: mutating calls return an `async` envelope with
//! an operation, which the client waits for (`GET /1.0/operations/<id>/wait`) up to a deadline and
//! cancels when the deadline passes.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use hyper::Method;
use serde::Serialize;
use serde_json::{Value, json};

use super::error::IncusError;
use super::limits::{LimitsApplied, LimitsUpdate};
use super::link::{LinkOutcome, SESSION_LINK_DEVICE, SessionLink};
use super::marker::{NETWORK_DESCRIPTION, POOL_DESCRIPTION};
use super::operation::{OperationEnd, OperationId};
use super::transport::{Request, Response, Transport, UnixTransport};
use super::types::{
    Acl, ExecResult, ExecSpec, ImageInfo, ImageUpload, Instance, InstanceCreate, InstanceState,
    Network, ObjectInfo, Operation, ProfileSpec, ServerInfo, Snapshot, StateAction, StoragePool,
};

/// Default timeout of a plain request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// How long reading one file out of an instance may take.
const READ_FILE_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest single `/wait` poll; the client loops until its own deadline.
const WAIT_SLICE: Duration = Duration::from_secs(30);

/// Allowed in names of instances, pools, networks, ACLs and profiles (single path segment).
pub(crate) fn valid_name(s: &str) -> bool {
    let mut c = s.chars();
    matches!(c.next(), Some(f) if f.is_ascii_alphanumeric())
        && s.len() <= 63
        && c.all(|x| x.is_ascii_alphanumeric() || matches!(x, '-' | '_' | '.'))
}

/// Prefix of the local aliases this product puts on the images it imports. Only images with such
/// an alias are ever deleted by [`Client::delete_image`].
pub const IMAGE_ALIAS_PREFIX: &str = "hx-img-";

fn check_fingerprint(s: &str) -> Result<(), IncusError> {
    if s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(IncusError::InvalidArgument(
            "an image fingerprint is 64 lower-case hex digits".into(),
        ))
    }
}

fn check_image_alias(name: &str) -> Result<(), IncusError> {
    if valid_name(name) && name.starts_with(IMAGE_ALIAS_PREFIX) {
        Ok(())
    } else {
        Err(IncusError::InvalidName {
            what: "image alias (must start with `hx-img-`)",
            name: name.to_string(),
        })
    }
}

fn checked<'a>(what: &'static str, name: &'a str) -> Result<&'a str, IncusError> {
    if valid_name(name) {
        Ok(name)
    } else {
        Err(IncusError::InvalidName {
            what,
            name: name.to_string(),
        })
    }
}

/// Incus 6.0.0 answers a `/wait?timeout=N` that runs out with `500 context deadline exceeded`
/// instead of the still-running operation (found with the real-container test, which is the first
/// to wait longer than one slice). That means "not finished yet", not a failure.
pub(crate) fn is_wait_timeout(e: &IncusError) -> bool {
    matches!(e, IncusError::Api { code: 500, message } if message.contains("context deadline exceeded"))
}

/// Percent-encode a query value (keeps `/` readable).
pub(crate) fn encode_query(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A decoded Incus response envelope.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Envelope {
    pub kind: String,
    pub operation: String,
    pub metadata: Value,
}

/// Decode a response body into an envelope, turning API errors into [`IncusError::Api`].
pub(crate) fn parse_envelope(status: u16, body: &[u8]) -> Result<Envelope, IncusError> {
    let snippet = || {
        let t = String::from_utf8_lossy(&body[..body.len().min(200)])
            .trim()
            .to_string();
        if t.is_empty() {
            "(empty body)".to_string()
        } else {
            t
        }
    };
    let v: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) if status >= 400 => {
            return Err(IncusError::Api {
                code: status,
                message: snippet(),
            });
        }
        Err(e) => {
            return Err(IncusError::Protocol(format!(
                "response is not JSON ({e}): {}",
                snippet()
            )));
        }
    };
    let kind = v.get("type").and_then(Value::as_str).unwrap_or_default();
    if kind == "error" || status >= 400 {
        let code = v
            .get("error_code")
            .and_then(Value::as_u64)
            .filter(|c| *c != 0)
            .and_then(|c| u16::try_from(c).ok())
            .unwrap_or(status);
        let message = v
            .get("error")
            .and_then(Value::as_str)
            .filter(|m| !m.is_empty())
            .map(str::to_string)
            .unwrap_or_else(snippet);
        return Err(IncusError::Api { code, message });
    }
    if kind != "sync" && kind != "async" {
        return Err(IncusError::Protocol(format!(
            "unknown response type `{kind}`"
        )));
    }
    Ok(Envelope {
        kind: kind.to_string(),
        operation: v
            .get("operation")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        metadata: v.get("metadata").cloned().unwrap_or(Value::Null),
    })
}

fn op_path(env: &Envelope) -> Result<String, IncusError> {
    let from_meta = env
        .metadata
        .get("id")
        .and_then(Value::as_str)
        .map(|id| format!("/1.0/operations/{id}"));
    let path = if env.operation.is_empty() {
        from_meta
    } else {
        Some(env.operation.clone())
    }
    .ok_or_else(|| IncusError::Protocol("async response without an operation".into()))?;
    let id = path.strip_prefix("/1.0/operations/").unwrap_or_default();
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(IncusError::Protocol(format!(
            "unexpected operation path `{path}`"
        )));
    }
    Ok(path)
}

/// Typed client for the parts of the Incus API that provisioning uses.
///
/// A client remembers the background operations it is currently waiting for (see
/// [`Client::in_flight_operations`]); clones share that memory, [`Client::scoped`] starts a new one.
#[derive(Debug, Clone)]
pub struct Client<T: Transport> {
    transport: T,
    in_flight: Arc<Mutex<BTreeSet<String>>>,
}

impl Client<UnixTransport> {
    /// Connect to the daemon's unix socket (default `/var/lib/incus/unix.socket`).
    pub fn unix(path: impl Into<std::path::PathBuf>) -> Self {
        Self::new(UnixTransport::new(path))
    }

    /// Connect to the default socket.
    pub fn default_socket() -> Self {
        Self::unix(UnixTransport::DEFAULT_SOCKET)
    }
}

impl<T: Transport> Client<T> {
    /// Use any transport (tests).
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            in_flight: Arc::default(),
        }
    }

    /// A client for the same daemon with its **own** set of in-flight operations. `hx-privd`
    /// makes one per request, so that cancelling a request cancels only the operations that
    /// request started.
    pub fn scoped(&self) -> Self
    where
        T: Clone,
    {
        Self::new(self.transport.clone())
    }

    // --- operations (cancel and wait; ipc.md 4) ------------------------------------------------

    fn track(&self, id: &str) {
        if let Ok(mut s) = self.in_flight.lock() {
            s.insert(id.to_string());
        }
    }

    fn untrack(&self, id: &str) {
        if let Ok(mut s) = self.in_flight.lock() {
            s.remove(id);
        }
    }

    /// The background operations this client (and its clones) started and has not seen end.
    ///
    /// Dropping a future from this crate does **not** stop its Incus operation, and does not
    /// remove it from this list: that is the point. After a cancel, call
    /// [`Client::cancel_in_flight`] (or [`Client::cancel_operation`] and
    /// [`Client::wait_operation_end`] per id). An operation is listed from the moment its id is
    /// known; one that the daemon created while the request was still on the wire when the future
    /// was dropped is not known to the client (check the instance state during cleanup).
    pub fn in_flight_operations(&self) -> Vec<OperationId> {
        self.in_flight
            .lock()
            .map(|s| s.iter().cloned().map(OperationId).collect())
            .unwrap_or_default()
    }

    /// Ask the daemon to cancel an operation (`DELETE /1.0/operations/<id>`). `Ok(false)`: it no
    /// longer exists (already finished). The operation may take a moment to end; follow with
    /// [`Client::wait_operation_end`].
    pub async fn cancel_operation(&self, id: &OperationId) -> Result<bool, IncusError> {
        match self
            .envelope(
                Method::DELETE,
                format!("/1.0/operations/{}", id.0),
                None::<&Value>,
                Duration::from_secs(10),
            )
            .await
        {
            Ok(_) => Ok(true),
            Err(e) if e.is_not_found() => {
                self.untrack(&id.0);
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// Wait until an operation has ended, for at most `timeout` (`IncusError::Timeout` if it has
    /// not). An operation the daemon no longer knows has ended ([`OperationEnd::Gone`]).
    pub async fn wait_operation_end(
        &self,
        id: &OperationId,
        timeout: Duration,
    ) -> Result<OperationEnd, IncusError> {
        let started = Instant::now();
        loop {
            let left = timeout.saturating_sub(started.elapsed());
            if left.is_zero() {
                return Err(IncusError::Timeout {
                    what: format!("operation {} to end", id.0),
                    after: timeout,
                });
            }
            let secs = (left.as_secs_f64().ceil() as u64).clamp(1, WAIT_SLICE.as_secs());
            match self
                .envelope(
                    Method::GET,
                    format!("/1.0/operations/{}/wait?timeout={secs}", id.0),
                    None::<&Value>,
                    Duration::from_secs(secs) + Duration::from_secs(20),
                )
                .await
            {
                Ok(env) => {
                    let op = Operation::from_value(&env.metadata)?;
                    if op.is_terminal() {
                        self.untrack(&id.0);
                        return Ok(match op.status_code {
                            200 => OperationEnd::Success,
                            401 => OperationEnd::Cancelled,
                            _ => OperationEnd::Failed(op.err),
                        });
                    }
                }
                Err(e) if is_wait_timeout(&e) => {}
                Err(e) if e.is_not_found() => {
                    self.untrack(&id.0);
                    return Ok(OperationEnd::Gone);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Cancel every in-flight operation of this client and wait until all have ended, for at most
    /// `wait` in total (ipc.md 4 uses 30 s). Returns how many were cancelled. `Err` carries the
    /// operations that did not end in time: the caller must not start new work on the same
    /// instance (`STUCK_OPERATION`).
    pub async fn cancel_in_flight(&self, wait: Duration) -> Result<usize, Vec<OperationId>> {
        let ids = self.in_flight_operations();
        let deadline = Instant::now() + wait;
        for id in &ids {
            // An operation that cannot be cancelled is still waited for below.
            let _ = self.cancel_operation(id).await;
        }
        let mut stuck = Vec::new();
        for id in &ids {
            let left = deadline.saturating_duration_since(Instant::now());
            if self.wait_operation_end(id, left).await.is_err() {
                stuck.push(id.clone());
            }
        }
        if stuck.is_empty() {
            Ok(ids.len())
        } else {
            Err(stuck)
        }
    }

    // --- plumbing ------------------------------------------------------------------------

    async fn send_json(
        &self,
        method: Method,
        path: String,
        body: Option<&impl Serialize>,
        timeout: Duration,
        headers: Vec<(&'static str, String)>,
    ) -> Result<Response, IncusError> {
        let (body, content_type) = match body {
            Some(b) => (
                Bytes::from(
                    serde_json::to_vec(b)
                        .map_err(|e| IncusError::InvalidArgument(e.to_string()))?,
                ),
                Some("application/json"),
            ),
            None => (Bytes::new(), None),
        };
        self.transport
            .send(Request {
                method,
                path,
                headers,
                body,
                content_type,
                max_response: None,
                timeout,
            })
            .await
    }

    async fn envelope(
        &self,
        method: Method,
        path: String,
        body: Option<&impl Serialize>,
        timeout: Duration,
    ) -> Result<Envelope, IncusError> {
        let r = self
            .send_json(method, path, body, timeout, Vec::new())
            .await?;
        parse_envelope(r.status, &r.body)
    }

    /// The instance and its `ETag`, for a conditional write (`If-Match`).
    async fn instance_with_etag(
        &self,
        name: &str,
    ) -> Result<Option<(Instance, Option<String>)>, IncusError> {
        let r = self
            .send_json(
                Method::GET,
                format!("/1.0/instances/{name}"),
                None::<&Value>,
                REQUEST_TIMEOUT,
                Vec::new(),
            )
            .await?;
        match parse_envelope(r.status, &r.body) {
            Ok(env) => Ok(Some((
                decode("instance", env.metadata)?,
                r.headers.get("etag").cloned(),
            ))),
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Replace an instance's device set (`PUT` of the whole definition, which is the only way to
    /// delete or fully replace a device: `PATCH` merges device options key by key). The write is
    /// conditional on the `ETag` of the definition it was computed from, so a concurrent change
    /// (for example `disable_docker`) is not overwritten: on `412` the definition is read again and
    /// `edit` re-applied, up to three times.
    async fn put_instance_devices(
        &self,
        name: &str,
        what: &str,
        edit: impl Fn(
            &mut std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
        ) -> bool,
    ) -> Result<bool, IncusError> {
        for _ in 0..3 {
            let Some((inst, etag)) = self.instance_with_etag(name).await? else {
                return Err(IncusError::Api {
                    code: 404,
                    message: format!("instance `{name}` not found"),
                });
            };
            let mut devices = inst.devices.clone();
            if !edit(&mut devices) {
                return Ok(false);
            }
            let body = json!({
                "architecture": inst.architecture,
                "config": inst.config,
                "description": inst.description,
                "devices": devices,
                "profiles": inst.profiles,
                "ephemeral": false,
            });
            let headers: Vec<(&'static str, String)> =
                etag.into_iter().map(|e| ("If-Match", e)).collect();
            let r = self
                .send_json(
                    Method::PUT,
                    format!("/1.0/instances/{name}"),
                    Some(&body),
                    REQUEST_TIMEOUT,
                    headers,
                )
                .await?;
            match parse_envelope(r.status, &r.body) {
                Ok(env) if env.kind == "async" => {
                    match self
                        .wait_operation(&op_path(&env)?, Duration::from_secs(60), what)
                        .await
                    {
                        Ok(_) => return Ok(true),
                        // Settled by the caller's re-read.
                        Err(IncusError::Purged(_)) => return Ok(true),
                        Err(e) => return Err(e),
                    }
                }
                Ok(_) => return Ok(true),
                Err(IncusError::Api { code: 412, .. }) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(IncusError::Operation(format!(
            "{what}: the instance kept changing underneath (412 three times)"
        )))
    }

    /// A call whose answer is the metadata itself.
    async fn sync(
        &self,
        method: Method,
        path: String,
        body: Option<&Value>,
    ) -> Result<Value, IncusError> {
        let env = self.envelope(method, path, body, REQUEST_TIMEOUT).await?;
        if env.kind == "async" {
            // Some endpoints are async on some versions; wait for them as usual.
            let op = self
                .wait_operation(&op_path(&env)?, REQUEST_TIMEOUT * 2, "an operation")
                .await?;
            return Ok(op.metadata);
        }
        Ok(env.metadata)
    }

    async fn get_optional(&self, path: String) -> Result<Option<Value>, IncusError> {
        match self.sync(Method::GET, path, None).await {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Issue a mutating call and wait for its operation.
    async fn run(
        &self,
        method: Method,
        path: String,
        body: Option<&Value>,
        deadline: Duration,
        what: &str,
    ) -> Result<Operation, IncusError> {
        let env = self.envelope(method, path, body, REQUEST_TIMEOUT).await?;
        if env.kind != "async" {
            return Ok(Operation {
                status: "Success".into(),
                status_code: 200,
                metadata: env.metadata,
                ..Operation::default()
            });
        }
        self.wait_operation(&op_path(&env)?, deadline, what).await
    }

    /// [`Client::run`] for a call whose intended result can be read back. When the daemon has
    /// already purged the operation ([`IncusError::Purged`]) its outcome is unknown, so `verify`
    /// re-reads the state and says whether the intended result is in place; if not, the call is
    /// an error. Nothing is ever assumed to have succeeded.
    async fn run_verified(
        &self,
        method: Method,
        path: String,
        body: Option<&Value>,
        deadline: Duration,
        what: &str,
        verify: impl AsyncFnOnce() -> Result<bool, IncusError>,
    ) -> Result<(), IncusError> {
        match self.run(method, path, body, deadline, what).await {
            Ok(_) => Ok(()),
            Err(IncusError::Purged(w)) => {
                if verify().await? {
                    Ok(())
                } else {
                    Err(IncusError::Purged(w))
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Wait for an operation to finish. On timeout the operation is cancelled (best effort).
    pub(crate) async fn wait_operation(
        &self,
        path: &str,
        deadline: Duration,
        what: &str,
    ) -> Result<Operation, IncusError> {
        let started = Instant::now();
        let tracked = path.strip_prefix("/1.0/operations/").unwrap_or_default();
        if !tracked.is_empty() {
            self.track(tracked);
        }
        loop {
            let elapsed = started.elapsed();
            if elapsed >= deadline {
                let _ = self
                    .transport
                    .send(Request {
                        method: Method::DELETE,
                        path: path.to_string(),
                        headers: Vec::new(),
                        body: Bytes::new(),
                        content_type: None,
                        max_response: None,
                        timeout: Duration::from_secs(10),
                    })
                    .await;
                return Err(IncusError::Timeout {
                    what: what.to_string(),
                    after: deadline,
                });
            }
            let slice = (deadline - elapsed).min(WAIT_SLICE);
            let secs = (slice.as_secs_f64().ceil() as u64).max(1);
            let env = self
                .envelope(
                    Method::GET,
                    format!("{path}/wait?timeout={secs}"),
                    None::<&Value>,
                    Duration::from_secs(secs) + Duration::from_secs(20),
                )
                .await;
            let env = match env {
                Ok(e) => e,
                Err(e) if is_wait_timeout(&e) => continue,
                Err(e) if e.is_not_found() => {
                    // The daemon no longer knows the operation: it ended and was purged before we
                    // asked (seen on a real daemon for an instance restart), or it failed and was
                    // purged. Its result is gone and is NOT assumed to be success: this is a
                    // distinct error, and every mutating call re-reads the state it changed
                    // (`run_verified`).
                    self.untrack(tracked);
                    return Err(IncusError::Purged(what.to_string()));
                }
                // Other errors keep the operation tracked.
                Err(e) => return Err(e),
            };
            let op = Operation::from_value(&env.metadata)?;
            if op.is_terminal() {
                self.untrack(tracked);
                return match op.status_code {
                    200 => Ok(op),
                    401 => Err(IncusError::Operation(format!("{what}: cancelled"))),
                    _ => Err(IncusError::Operation(if op.err.is_empty() {
                        format!("{what}: {}", op.status)
                    } else {
                        op.err
                    })),
                };
            }
        }
    }

    // --- server ---------------------------------------------------------------------------

    /// `GET /1.0`: server and environment information.
    pub async fn server_info(&self) -> Result<ServerInfo, IncusError> {
        ServerInfo::from_metadata(&self.sync(Method::GET, "/1.0".into(), None).await?)
    }

    // --- storage pools ---------------------------------------------------------------------

    /// The pool, or `None` when it does not exist.
    pub async fn get_storage_pool(&self, name: &str) -> Result<Option<StoragePool>, IncusError> {
        let name = checked("storage pool", name)?;
        self.get_optional(format!("/1.0/storage-pools/{name}"))
            .await?
            .map(|v| decode("storage pool", v))
            .transpose()
    }

    /// Create a pool. `config` carries `size` (loop file) or `source` (device).
    pub async fn create_storage_pool(
        &self,
        name: &str,
        driver: &str,
        config: &std::collections::BTreeMap<String, String>,
    ) -> Result<(), IncusError> {
        checked("storage pool", name)?;
        let body = json!({"name": name, "driver": driver, "config": config, "description": POOL_DESCRIPTION});
        self.sync(Method::POST, "/1.0/storage-pools".into(), Some(&body))
            .await
            .map(drop)
    }

    /// Delete an unused pool.
    pub async fn delete_storage_pool(&self, name: &str) -> Result<(), IncusError> {
        let name = checked("storage pool", name)?;
        self.sync(Method::DELETE, format!("/1.0/storage-pools/{name}"), None)
            .await
            .map(drop)
    }

    // --- networks and ACLs -----------------------------------------------------------------

    /// The network, or `None`.
    pub async fn get_network(&self, name: &str) -> Result<Option<Network>, IncusError> {
        let name = checked("network", name)?;
        self.get_optional(format!("/1.0/networks/{name}"))
            .await?
            .map(|v| decode("network", v))
            .transpose()
    }

    /// Create a managed bridge network.
    pub async fn create_network(
        &self,
        name: &str,
        config: &std::collections::BTreeMap<String, String>,
    ) -> Result<(), IncusError> {
        checked("network", name)?;
        let body = json!({"name": name, "type": "bridge", "config": config, "description": NETWORK_DESCRIPTION});
        self.sync(Method::POST, "/1.0/networks".into(), Some(&body))
            .await
            .map(drop)
    }

    /// Merge keys into a network's configuration (`PATCH`).
    pub async fn patch_network_config(
        &self,
        name: &str,
        config: &std::collections::BTreeMap<String, String>,
    ) -> Result<(), IncusError> {
        let name = checked("network", name)?;
        // Incus 6.0.0 resets the description to empty on a PATCH that does not repeat it, which
        // would drop the hash-xcreen marker: send the current one back.
        let description = self
            .get_network(name)
            .await?
            .map(|n| n.description)
            .unwrap_or_default();
        self.sync(
            Method::PATCH,
            format!("/1.0/networks/{name}"),
            Some(&json!({"config": config, "description": description})),
        )
        .await
        .map(drop)
    }

    /// Delete a network that nothing uses.
    pub async fn delete_network(&self, name: &str) -> Result<(), IncusError> {
        let name = checked("network", name)?;
        self.sync(Method::DELETE, format!("/1.0/networks/{name}"), None)
            .await
            .map(drop)
    }

    /// The ACL (name, description, users), or `None`.
    pub async fn get_acl(&self, name: &str) -> Result<Option<ObjectInfo>, IncusError> {
        let name = checked("network ACL", name)?;
        self.get_optional(format!("/1.0/network-acls/{name}"))
            .await?
            .map(|v| decode("network ACL", v))
            .transpose()
    }

    /// Whether the ACL exists.
    pub async fn acl_exists(&self, name: &str) -> Result<bool, IncusError> {
        let name = checked("network ACL", name)?;
        Ok(self
            .get_optional(format!("/1.0/network-acls/{name}"))
            .await?
            .is_some())
    }

    /// Create an ACL.
    pub async fn create_acl(&self, acl: &Acl) -> Result<(), IncusError> {
        checked("network ACL", &acl.name)?;
        let body =
            serde_json::to_value(acl).map_err(|e| IncusError::InvalidArgument(e.to_string()))?;
        self.sync(Method::POST, "/1.0/network-acls".into(), Some(&body))
            .await
            .map(drop)
    }

    /// Replace an existing ACL's description and rules.
    pub async fn update_acl(&self, acl: &Acl) -> Result<(), IncusError> {
        let name = checked("network ACL", &acl.name)?;
        let body =
            json!({"description": acl.description, "egress": acl.egress, "ingress": acl.ingress});
        self.sync(
            Method::PUT,
            format!("/1.0/network-acls/{name}"),
            Some(&body),
        )
        .await
        .map(drop)
    }

    /// Delete an ACL that no network uses.
    pub async fn delete_acl(&self, name: &str) -> Result<(), IncusError> {
        let name = checked("network ACL", name)?;
        self.sync(Method::DELETE, format!("/1.0/network-acls/{name}"), None)
            .await
            .map(drop)
    }

    // --- profiles --------------------------------------------------------------------------

    /// The profile (name, description, users), or `None`.
    pub async fn get_profile(&self, name: &str) -> Result<Option<ObjectInfo>, IncusError> {
        let name = checked("profile", name)?;
        self.get_optional(format!("/1.0/profiles/{name}"))
            .await?
            .map(|v| decode("profile", v))
            .transpose()
    }

    /// Whether the profile exists.
    pub async fn profile_exists(&self, name: &str) -> Result<bool, IncusError> {
        let name = checked("profile", name)?;
        Ok(self
            .get_optional(format!("/1.0/profiles/{name}"))
            .await?
            .is_some())
    }

    /// Create a profile.
    pub async fn create_profile(&self, profile: &ProfileSpec) -> Result<(), IncusError> {
        checked("profile", &profile.name)?;
        let body = serde_json::to_value(profile)
            .map_err(|e| IncusError::InvalidArgument(e.to_string()))?;
        self.sync(Method::POST, "/1.0/profiles".into(), Some(&body))
            .await
            .map(drop)
    }

    /// Delete an unused profile.
    pub async fn delete_profile(&self, name: &str) -> Result<(), IncusError> {
        let name = checked("profile", name)?;
        self.sync(Method::DELETE, format!("/1.0/profiles/{name}"), None)
            .await
            .map(drop)
    }

    // --- images ----------------------------------------------------------------------------

    /// Import an image file into the local store (`POST /1.0/images`, body streamed from the
    /// file, never buffered). Sends `X-Incus-fingerprint` and `X-Incus-public: 0`, waits for the
    /// unpacking operation within what is left of `deadline`, and returns the fingerprint Incus
    /// reports, which it checks equals `upload.fingerprint`: an image Incus stored under another
    /// fingerprint is an error (and is left in place for the caller to look at, not deleted).
    ///
    /// Importing an image that is already in the store is an API error (409).
    pub async fn import_image(
        &self,
        upload: ImageUpload,
        deadline: Duration,
    ) -> Result<String, IncusError> {
        let expected = upload.fingerprint;
        check_fingerprint(&expected)?;
        if upload.len == 0 {
            return Err(IncusError::InvalidArgument("empty image file".into()));
        }
        let started = Instant::now();
        let r = self
            .transport
            .send_file(
                Request {
                    method: Method::POST,
                    path: "/1.0/images".into(),
                    headers: vec![
                        ("X-Incus-fingerprint", expected.clone()),
                        ("X-Incus-public", "0".into()),
                    ],
                    body: Bytes::new(),
                    content_type: Some("application/octet-stream"),
                    max_response: None,
                    timeout: deadline,
                },
                upload.file,
                upload.len,
            )
            .await?;
        let env = parse_envelope(r.status, &r.body)?;
        let metadata = if env.kind == "async" {
            let left = deadline.saturating_sub(started.elapsed());
            match self
                .wait_operation(&op_path(&env)?, left, "the image import")
                .await
            {
                Ok(op) => op.metadata,
                Err(IncusError::Purged(w)) => {
                    // The result is gone; the store says whether the image is there.
                    if self.get_image(&expected).await?.is_some() {
                        return Ok(expected);
                    }
                    return Err(IncusError::Purged(w));
                }
                Err(e) => return Err(e),
            }
        } else {
            env.metadata
        };
        let got = metadata
            .get("fingerprint")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if got != expected {
            return Err(IncusError::Protocol(format!(
                "Incus stored the image as `{}`, not the expected `{expected}`",
                if check_fingerprint(got).is_ok() {
                    got
                } else {
                    "(no valid fingerprint)"
                }
            )));
        }
        Ok(expected)
    }

    /// Point the alias `name` (which must start with `hx-img-`) at an image.
    /// An alias that already exists is an API error (409).
    pub async fn create_image_alias(
        &self,
        name: &str,
        fingerprint: &str,
    ) -> Result<(), IncusError> {
        check_image_alias(name)?;
        check_fingerprint(fingerprint)?;
        let body = json!({
            "name": name,
            "target": fingerprint,
            "description": "hash-xcreen prebuilt desktop image",
        });
        self.sync(Method::POST, "/1.0/images/aliases".into(), Some(&body))
            .await
            .map(drop)
    }

    /// The image with this fingerprint, or `None`.
    pub async fn get_image(&self, fingerprint: &str) -> Result<Option<ImageInfo>, IncusError> {
        check_fingerprint(fingerprint)?;
        self.get_optional(format!("/1.0/images/{fingerprint}"))
            .await?
            .map(|v| decode("image", v))
            .transpose()
    }

    /// Every image in the local store (`recursion=1`).
    pub async fn list_images(&self) -> Result<Vec<ImageInfo>, IncusError> {
        decode(
            "image list",
            self.sync(Method::GET, "/1.0/images?recursion=1".into(), None)
                .await?,
        )
    }

    /// Delete an image, **only** if it carries an alias starting with `hx-img-` (that is, one this
    /// product created): any other image is refused with [`IncusError::InvalidArgument`], so a
    /// bug upstream cannot remove an image the administrator imported. `Ok(false)`: no such image.
    pub async fn delete_image(&self, fingerprint: &str) -> Result<bool, IncusError> {
        let Some(img) = self.get_image(fingerprint).await? else {
            return Ok(false);
        };
        if !img
            .aliases
            .iter()
            .any(|a| a.starts_with(IMAGE_ALIAS_PREFIX))
        {
            return Err(IncusError::InvalidArgument(format!(
                "image {fingerprint} has no `{IMAGE_ALIAS_PREFIX}` alias; refusing to delete it"
            )));
        }
        self.run_verified(
            Method::DELETE,
            format!("/1.0/images/{fingerprint}"),
            None,
            Duration::from_secs(120),
            "the image delete",
            async || Ok(self.get_image(fingerprint).await?.is_none()),
        )
        .await?;
        Ok(true)
    }

    // --- instances -------------------------------------------------------------------------

    /// The instance, or `None`.
    pub async fn get_instance(&self, name: &str) -> Result<Option<Instance>, IncusError> {
        let name = checked("instance", name)?;
        self.get_optional(format!("/1.0/instances/{name}"))
            .await?
            .map(|v| decode("instance", v))
            .transpose()
    }

    /// Create (but do not start) an instance. `deadline` bounds image download and unpacking.
    pub async fn create_instance(
        &self,
        spec: &InstanceCreate,
        deadline: Duration,
    ) -> Result<(), IncusError> {
        checked("instance", &spec.name)?;
        self.run_verified(
            Method::POST,
            "/1.0/instances".into(),
            Some(&spec.to_json()),
            deadline,
            "instance creation",
            async || Ok(self.get_instance(&spec.name).await?.is_some()),
        )
        .await
    }

    /// Merge keys into an instance's configuration (`PATCH`). Some keys need a restart.
    pub async fn patch_instance_config(
        &self,
        name: &str,
        config: &std::collections::BTreeMap<String, String>,
    ) -> Result<(), IncusError> {
        let name = checked("instance", name)?;
        self.run_verified(
            Method::PATCH,
            format!("/1.0/instances/{name}"),
            Some(&json!({"config": config})),
            Duration::from_secs(60),
            "instance update",
            async || {
                Ok(self
                    .get_instance(name)
                    .await?
                    .is_some_and(|i| config.iter().all(|(k, v)| i.config.get(k) == Some(v))))
            },
        )
        .await
    }

    /// Change CPU, memory and root-disk limits of an instance, running or not (ipc.md 6.8).
    ///
    /// Only `limits.cpu`, `limits.memory` and the `size` of the instance's root disk are written.
    /// The root device is taken from the instance's effective devices and written back with the
    /// new `size` as an instance-level override, so the pool, path and any other option stay as
    /// they are; an instance without a root disk device is refused. Idempotent (same values, same
    /// result). Host-dependent bounds are the caller's job, see [`LimitsUpdate`].
    pub async fn set_limits(
        &self,
        instance: &str,
        update: &LimitsUpdate,
    ) -> Result<LimitsApplied, IncusError> {
        let name = checked("instance", instance)?;
        update.validate()?;
        let mut applied = LimitsApplied::default();
        let mut config = std::collections::BTreeMap::new();
        if let Some(c) = update.cpu {
            config.insert("limits.cpu".to_string(), c.to_string());
            applied.changed.push("limits.cpu");
        }
        if let Some(m) = update.memory_mib {
            config.insert("limits.memory".to_string(), format!("{m}MiB"));
            applied.changed.push("limits.memory");
        }
        let mut body = json!({});
        if !config.is_empty() {
            body["config"] = json!(config);
        }
        if let Some(d) = update.disk_gib {
            let inst = self
                .get_instance(name)
                .await?
                .ok_or_else(|| IncusError::Api {
                    code: 404,
                    message: format!("instance `{name}` not found"),
                })?;
            let mut root = inst
                .devices
                .get("root")
                .or_else(|| inst.expanded_devices.get("root"))
                .cloned()
                .ok_or_else(|| {
                    IncusError::InvalidArgument("the instance has no root disk device".into())
                })?;
            if root.get("type").map(String::as_str) != Some("disk")
                || root.get("path").map(String::as_str) != Some("/")
            {
                return Err(IncusError::InvalidArgument(
                    "the `root` device is not the root disk".into(),
                ));
            }
            root.insert("size".into(), format!("{d}GiB"));
            body["devices"] = json!({"root": root});
            applied.changed.push("devices.root.size");
        }
        let want_root_size = update.disk_gib.map(|d| format!("{d}GiB"));
        self.run_verified(
            Method::PATCH,
            format!("/1.0/instances/{name}"),
            Some(&body),
            Duration::from_secs(120),
            "applying limits",
            async || {
                Ok(self.get_instance(name).await?.is_some_and(|i| {
                    config.iter().all(|(k, v)| i.config.get(k) == Some(v))
                        && want_root_size.as_ref().is_none_or(|s| {
                            i.devices.get("root").and_then(|r| r.get("size")) == Some(s)
                        })
                }))
            },
        )
        .await?;
        // Memory and the root disk quota take effect at once on a running container, verified on
        // Incus 6.0.0 (cgroup memory.max changed, a 13 GiB allocation hit "Disk quota exceeded"
        // under a 12 GiB quota). A changed CPU count did not change the running container's
        // cpuset on that version: it applies at the next start.
        if update.cpu.is_some() && self.instance_state(name).await?.is_running() {
            applied.restart_required = true;
        }
        Ok(applied)
    }

    /// Add the session-link proxy device ([`SessionLink`], ipc.md 6.11) to an instance.
    ///
    /// This is the only device-add call of the client and it takes only a [`SessionLink`], whose
    /// constructor validates its inputs and fixes every other property, so the caller cannot add
    /// anything else (a disk, a nic, another proxy, a unix socket pass-through).
    ///
    /// Converges: an identical device is left alone ([`LinkOutcome::Unchanged`]); a proxy device
    /// of the same name with other options is replaced ([`LinkOutcome::Replaced`]); a device of
    /// that name that is not a proxy device is refused rather than overwritten. The device
    /// persists across restarts; Incus starts the proxy with the instance.
    pub async fn add_session_link(
        &self,
        instance: &str,
        link: &SessionLink,
    ) -> Result<LinkOutcome, IncusError> {
        let name = checked("instance", instance)?;
        let want = link.device();
        let current = self
            .get_instance(name)
            .await?
            .ok_or_else(|| IncusError::Api {
                code: 404,
                message: format!("instance `{name}` not found"),
            })?;
        let outcome = match current.devices.get(SESSION_LINK_DEVICE) {
            Some(d) if *d == want => return Ok(LinkOutcome::Unchanged),
            Some(d) if d.get("type").map(String::as_str) != Some("proxy") => {
                return Err(IncusError::InvalidArgument(format!(
                    "device `{SESSION_LINK_DEVICE}` exists and is not a proxy device"
                )));
            }
            Some(_) => LinkOutcome::Replaced,
            None => LinkOutcome::Added,
        };
        let in_place = async || {
            Ok(self
                .get_instance(name)
                .await?
                .is_some_and(|i| i.devices.get(SESSION_LINK_DEVICE) == Some(&want)))
        };
        if outcome == LinkOutcome::Replaced {
            // Replace the whole device: a PATCH merges option by option and would keep a stale
            // key (say `proxy_protocol`) of the old device.
            self.put_instance_devices(name, "replacing the session link device", |d| {
                d.insert(SESSION_LINK_DEVICE.to_string(), want.clone());
                true
            })
            .await?;
            if !in_place().await? {
                return Err(IncusError::Purged(
                    "replacing the session link device".into(),
                ));
            }
        } else {
            self.run_verified(
                Method::PATCH,
                format!("/1.0/instances/{name}"),
                Some(&json!({"devices": {SESSION_LINK_DEVICE: want}})),
                Duration::from_secs(60),
                "adding the session link device",
                in_place,
            )
            .await?;
        }
        Ok(outcome)
    }

    /// Remove the session-link device if present (teardown). Returns whether it was removed.
    /// Nothing else on the instance is touched.
    pub async fn remove_session_link(&self, instance: &str) -> Result<bool, IncusError> {
        let name = checked("instance", instance)?;
        let Some(current) = self.get_instance(name).await? else {
            return Ok(false);
        };
        if !current.devices.contains_key(SESSION_LINK_DEVICE) {
            return Ok(false);
        }
        // PATCH merges device maps and cannot delete a key, so write the instance's definition
        // back with the device left out (what `incus config device remove` does), conditional on
        // its ETag so that a concurrent change is not lost.
        let wrote = self
            .put_instance_devices(name, "removing the session link device", |d| {
                d.remove(SESSION_LINK_DEVICE).is_some()
            })
            .await?;
        if wrote
            && self
                .get_instance(name)
                .await?
                .is_some_and(|i| i.devices.contains_key(SESSION_LINK_DEVICE))
        {
            return Err(IncusError::Purged(
                "removing the session link device".into(),
            ));
        }
        Ok(wrote)
    }

    /// Start, stop or restart. `force` kills instead of asking init to shut down.
    pub async fn set_state(
        &self,
        name: &str,
        action: StateAction,
        force: bool,
        timeout: Duration,
    ) -> Result<(), IncusError> {
        let name = checked("instance", name)?;
        let body = json!({"action": action.as_str(), "timeout": timeout.as_secs(), "force": force, "stateful": false});
        self.run_verified(
            Method::PUT,
            format!("/1.0/instances/{name}/state"),
            Some(&body),
            timeout + Duration::from_secs(60),
            action.as_str(),
            async || {
                let running = self.instance_state(name).await?.is_running();
                Ok(match action {
                    StateAction::Start | StateAction::Restart => running,
                    StateAction::Stop => !running,
                })
            },
        )
        .await
    }

    /// Run state of an instance.
    pub async fn instance_state(&self, name: &str) -> Result<InstanceState, IncusError> {
        let name = checked("instance", name)?;
        Ok(InstanceState::from_metadata(
            &self
                .sync(Method::GET, format!("/1.0/instances/{name}/state"), None)
                .await?,
        ))
    }

    /// Delete a stopped instance.
    pub async fn delete_instance(&self, name: &str) -> Result<(), IncusError> {
        let name = checked("instance", name)?;
        self.run_verified(
            Method::DELETE,
            format!("/1.0/instances/{name}"),
            None,
            Duration::from_secs(180),
            "instance deletion",
            async || Ok(self.get_instance(name).await?.is_none()),
        )
        .await
    }

    // --- files -----------------------------------------------------------------------------

    async fn file_request(
        &self,
        name: &str,
        path: &str,
        kind: &'static str,
        mode: u32,
        content: Bytes,
    ) -> Result<(), IncusError> {
        let name = checked("instance", name)?;
        if !path.starts_with('/') || path.contains('\0') {
            return Err(IncusError::InvalidArgument(format!(
                "file path `{path}` must be absolute"
            )));
        }
        let r = self
            .transport
            .send(Request {
                method: Method::POST,
                path: format!("/1.0/instances/{name}/files?path={}", encode_query(path)),
                headers: vec![
                    ("X-Incus-type", kind.to_string()),
                    ("X-Incus-mode", format!("{mode:04o}")),
                    ("X-Incus-uid", "0".into()),
                    ("X-Incus-gid", "0".into()),
                    ("X-Incus-write", "overwrite".into()),
                ],
                body: content,
                content_type: Some("application/octet-stream"),
                max_response: None,
                timeout: Duration::from_secs(120),
            })
            .await?;
        parse_envelope(r.status, &r.body).map(drop)
    }

    /// Write a file owned by root with `mode`. The parent directory must exist. Confidentiality of
    /// a secret written this way comes from the 0700 directory it is placed in (see
    /// [`crate::orchestrate::IncusExecutor`]); the file is also created with `mode`.
    pub async fn push_file(
        &self,
        instance: &str,
        path: &str,
        content: &[u8],
        mode: u32,
    ) -> Result<(), IncusError> {
        self.file_request(
            instance,
            path,
            "file",
            mode,
            Bytes::copy_from_slice(content),
        )
        .await
    }

    /// [`Client::push_file`] for a secret. The request body is held by a zeroizing owner
    /// (`Bytes::from_owner`), so the one copy this makes is wiped when the body is dropped, instead
    /// of leaving an ordinary heap copy of the password behind. (The socket and hyper's write
    /// buffer still see the bytes in transit; that is unavoidable, and why the file is 0600 in a
    /// 0700 directory and deleted at once.)
    pub async fn push_secret_file(
        &self,
        instance: &str,
        path: &str,
        content: &crate::exec::Secret,
        mode: u32,
    ) -> Result<(), IncusError> {
        self.file_request(instance, path, "file", mode, secret_body(content))
            .await
    }

    /// Create a directory owned by root with `mode` (existing directories are left alone).
    pub async fn push_dir(&self, instance: &str, path: &str, mode: u32) -> Result<(), IncusError> {
        self.file_request(instance, path, "directory", mode, Bytes::new())
            .await
    }

    /// Read a file out of an instance, refusing bodies larger than `max_bytes`.
    ///
    /// `Ok(None)` when the file does not exist. The content is untrusted when the instance has run
    /// user code: treat it as data.
    pub async fn read_file(
        &self,
        instance: &str,
        path: &str,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, IncusError> {
        let name = checked("instance", instance)?;
        if !path.starts_with('/') || path.contains('\0') {
            return Err(IncusError::InvalidArgument(format!(
                "file path `{path}` must be absolute"
            )));
        }
        let r = self
            .transport
            .send(Request {
                method: Method::GET,
                path: format!("/1.0/instances/{name}/files?path={}", encode_query(path)),
                headers: Vec::new(),
                body: Bytes::new(),
                content_type: None,
                max_response: Some(max_bytes),
                // Short: a FIFO or similar planted by the container makes the daemon's read block
                // (the headers arrive only after it opens the file), and must not hold us for long.
                timeout: READ_FILE_TIMEOUT,
            })
            .await?;
        if r.status >= 400 {
            return match parse_envelope(r.status, &r.body) {
                Err(e) if e.is_not_found() => Ok(None),
                Err(e) => Err(e),
                Ok(_) => Err(IncusError::Protocol(
                    "error status with a success body".into(),
                )),
            };
        }
        // Only regular files: directories and symlinks come back with another X-Incus-Type.
        match r.headers.get("x-incus-type").map(String::as_str) {
            Some("file") => Ok(Some(r.body.to_vec())),
            other => Err(IncusError::Protocol(format!(
                "`{path}` is not a regular file (type {})",
                other.unwrap_or("missing")
            ))),
        }
    }

    /// Owner, mode and type of a path in an instance (`GET .../files`, the `X-Incus-*` headers),
    /// without reading its content. `Ok(None)` when it does not exist.
    pub async fn stat_path(
        &self,
        instance: &str,
        path: &str,
    ) -> Result<Option<PathStat>, IncusError> {
        let name = checked("instance", instance)?;
        if !path.starts_with('/') || path.contains('\0') {
            return Err(IncusError::InvalidArgument(format!(
                "file path `{path}` must be absolute"
            )));
        }
        let r = self
            .transport
            .send(Request {
                method: Method::GET,
                path: format!("/1.0/instances/{name}/files?path={}", encode_query(path)),
                headers: Vec::new(),
                body: Bytes::new(),
                content_type: None,
                // Only the headers matter, but for a directory the body is its listing: allow a
                // modest one. Anything larger is reported as `kind: "unknown"` (fail closed for
                // the caller that wants a private directory).
                max_response: Some(64 * 1024),
                timeout: READ_FILE_TIMEOUT,
            })
            .await;
        let r = match r {
            Ok(r) => r,
            Err(IncusError::TooLarge { .. }) => {
                return Ok(Some(PathStat {
                    kind: "unknown".into(),
                    uid: u32::MAX,
                    gid: u32::MAX,
                    mode: 0,
                }));
            }
            Err(e) => return Err(e),
        };
        if r.status >= 400 {
            return match parse_envelope(r.status, &r.body) {
                Err(e) if e.is_not_found() => Ok(None),
                Err(e) => Err(e),
                Ok(_) => Err(IncusError::Protocol(
                    "error status with a success body".into(),
                )),
            };
        }
        let num = |k: &str| r.headers.get(k).and_then(|v| v.trim().parse::<u32>().ok());
        let (Some(uid), Some(gid), Some(mode)) = (
            num("x-incus-uid"),
            num("x-incus-gid"),
            r.headers
                .get("x-incus-mode")
                .and_then(|v| u32::from_str_radix(v.trim(), 8).ok()),
        ) else {
            return Err(IncusError::Protocol(format!(
                "no owner or mode headers for `{path}`"
            )));
        };
        Ok(Some(PathStat {
            kind: r.headers.get("x-incus-type").cloned().unwrap_or_default(),
            uid,
            gid,
            mode: mode & 0o7777,
        }))
    }

    /// Delete a file in an instance (a missing file is not an error).
    pub async fn delete_file(&self, instance: &str, path: &str) -> Result<(), IncusError> {
        let name = checked("instance", instance)?;
        if !path.starts_with('/') || path.contains('\0') {
            return Err(IncusError::InvalidArgument(format!(
                "file path `{path}` must be absolute"
            )));
        }
        match self
            .envelope(
                Method::DELETE,
                format!("/1.0/instances/{name}/files?path={}", encode_query(path)),
                None::<&Value>,
                Duration::from_secs(30),
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(e) if e.is_not_found() => Ok(()),
            Err(e) => Err(e),
        }
    }

    // --- exec ------------------------------------------------------------------------------

    /// Run a command and return only its exit status. **Output is never recorded** (`record-output`
    /// is false, so nothing is written to the host's `/var/log/incus`), and `stdout`/`stderr` of
    /// the result are empty. For output, see
    /// [`crate::orchestrate::exec_captured`], which routes it through a size-capped file.
    pub async fn exec(&self, instance: &str, spec: &ExecSpec) -> Result<ExecResult, IncusError> {
        let name = checked("instance", instance)?;
        if spec.command.is_empty() {
            return Err(IncusError::InvalidArgument("empty command".into()));
        }
        let op = self
            .run(
                Method::POST,
                format!("/1.0/instances/{name}/exec"),
                Some(&spec.to_json()),
                spec.timeout,
                "a command",
            )
            .await?;
        let exit_code = op
            .metadata
            .get("return")
            .and_then(Value::as_i64)
            .and_then(|c| i32::try_from(c).ok())
            .ok_or_else(|| IncusError::Protocol("exec result has no `return` code".into()))?;
        Ok(ExecResult {
            exit_code,
            stdout: String::new(),
            stderr: String::new(),
        })
    }

    // --- snapshots -------------------------------------------------------------------------

    /// Create a (stateless, copy-on-write) snapshot of an instance.
    pub async fn create_snapshot(&self, instance: &str, snapshot: &str) -> Result<(), IncusError> {
        let name = checked("instance", instance)?;
        checked("snapshot", snapshot)?;
        let body = json!({"name": snapshot, "stateful": false});
        self.run_verified(
            Method::POST,
            format!("/1.0/instances/{name}/snapshots"),
            Some(&body),
            Duration::from_secs(300),
            "snapshot creation",
            async || {
                Ok(self
                    .list_snapshots(name)
                    .await?
                    .iter()
                    .any(|s| s.name == snapshot))
            },
        )
        .await
    }

    /// Delete a snapshot.
    pub async fn delete_snapshot(&self, instance: &str, snapshot: &str) -> Result<(), IncusError> {
        let name = checked("instance", instance)?;
        let snap = checked("snapshot", snapshot)?;
        self.run_verified(
            Method::DELETE,
            format!("/1.0/instances/{name}/snapshots/{snap}"),
            None,
            Duration::from_secs(300),
            "snapshot deletion",
            async || {
                Ok(!self
                    .list_snapshots(name)
                    .await?
                    .iter()
                    .any(|s| s.name == snap))
            },
        )
        .await
    }

    /// List an instance's snapshots.
    pub async fn list_snapshots(&self, instance: &str) -> Result<Vec<Snapshot>, IncusError> {
        let name = checked("instance", instance)?;
        let v = self
            .sync(
                Method::GET,
                format!("/1.0/instances/{name}/snapshots?recursion=1"),
                None,
            )
            .await?;
        let Value::Array(items) = v else {
            return Err(IncusError::Protocol("snapshot list is not an array".into()));
        };
        items
            .into_iter()
            .map(|mut s| {
                // With recursion the name is `instance/snapshot`.
                if let Some(Value::String(n)) = s.get_mut("name")
                    && let Some((_, short)) = n.rsplit_once('/')
                {
                    *n = short.to_string();
                }
                decode("snapshot", s)
            })
            .collect()
    }
}

/// Owner, mode and type of a path in an instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathStat {
    /// `file`, `directory` or `symlink`.
    pub kind: String,
    /// Owner uid as seen inside the instance (`u32::MAX` when not read).
    pub uid: u32,
    /// Owner gid as seen inside the instance (`u32::MAX` when not read).
    pub gid: u32,
    /// Permission bits (`0o7777` mask).
    pub mode: u32,
}

/// Owner of a secret request body: zeroized when the last `Bytes` that refers to it is dropped.
pub(crate) struct SecretBody(zeroize::Zeroizing<Vec<u8>>);

impl AsRef<[u8]> for SecretBody {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl zeroize::ZeroizeOnDrop for SecretBody {}

pub(crate) fn secret_body(secret: &crate::exec::Secret) -> Bytes {
    Bytes::from_owner(SecretBody(zeroize::Zeroizing::new(
        secret.expose().to_vec(),
    )))
}

fn decode<D: serde::de::DeserializeOwned>(what: &str, v: Value) -> Result<D, IncusError> {
    serde_json::from_value(v).map_err(|e| IncusError::Protocol(format!("cannot read {what}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

    #[test]
    fn a_secret_body_is_zeroized_on_drop_and_carries_the_bytes() {
        assert_zeroize_on_drop::<SecretBody>();
        let s = crate::exec::Secret::from_slice(b"user:pw\n");
        let b = secret_body(&s);
        assert_eq!(&b[..], b"user:pw\n");
        // A clone shares the same owner (no second, unwiped copy), and the owner outlives both.
        let c = b.clone();
        assert_eq!(b.as_ptr(), c.as_ptr());
    }
}
