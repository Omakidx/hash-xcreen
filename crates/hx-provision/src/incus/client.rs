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
use super::operation::{OperationEnd, OperationId};
use super::transport::{Request, Response, Transport, UnixTransport};
use super::types::{
    Acl, ExecResult, ExecSpec, Instance, InstanceCreate, InstanceState, Network, Operation,
    ProfileSpec, ServerInfo, Snapshot, StateAction, StoragePool,
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
                headers: Vec::new(),
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
        let r = self.send_json(method, path, body, timeout).await?;
        parse_envelope(r.status, &r.body)
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
                Err(e) => {
                    // An operation the daemon no longer knows has ended; keep other errors tracked.
                    if e.is_not_found() {
                        self.untrack(tracked);
                    }
                    return Err(e);
                }
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
        let body = json!({"name": name, "driver": driver, "config": config});
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
        let body = json!({"name": name, "type": "bridge", "config": config});
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
        self.sync(
            Method::PATCH,
            format!("/1.0/networks/{name}"),
            Some(&json!({"config": config})),
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
        self.run(
            Method::POST,
            "/1.0/instances".into(),
            Some(&spec.to_json()),
            deadline,
            "instance creation",
        )
        .await
        .map(drop)
    }

    /// Merge keys into an instance's configuration (`PATCH`). Some keys need a restart.
    pub async fn patch_instance_config(
        &self,
        name: &str,
        config: &std::collections::BTreeMap<String, String>,
    ) -> Result<(), IncusError> {
        let name = checked("instance", name)?;
        self.run(
            Method::PATCH,
            format!("/1.0/instances/{name}"),
            Some(&json!({"config": config})),
            Duration::from_secs(60),
            "instance update",
        )
        .await
        .map(drop)
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
        self.run(
            Method::PATCH,
            format!("/1.0/instances/{name}"),
            Some(&body),
            Duration::from_secs(120),
            "applying limits",
        )
        .await?;
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
        self.run(
            Method::PATCH,
            format!("/1.0/instances/{name}"),
            Some(&json!({"devices": {SESSION_LINK_DEVICE: want}})),
            Duration::from_secs(60),
            "adding the session link device",
        )
        .await?;
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
        let mut devices = current.devices.clone();
        devices.remove(SESSION_LINK_DEVICE);
        // PATCH merges device maps and cannot delete a key, so write the instance's definition
        // back with the device left out (what `incus config device remove` does).
        let body = json!({
            "architecture": current.architecture,
            "config": current.config,
            "devices": devices,
            "profiles": current.profiles,
            "ephemeral": false,
        });
        self.run(
            Method::PUT,
            format!("/1.0/instances/{name}"),
            Some(&body),
            Duration::from_secs(60),
            "removing the session link device",
        )
        .await?;
        Ok(true)
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
        self.run(
            Method::PUT,
            format!("/1.0/instances/{name}/state"),
            Some(&body),
            timeout + Duration::from_secs(60),
            action.as_str(),
        )
        .await
        .map(drop)
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
        self.run(
            Method::DELETE,
            format!("/1.0/instances/{name}"),
            None,
            Duration::from_secs(180),
            "instance deletion",
        )
        .await
        .map(drop)
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
        self.run(
            Method::POST,
            format!("/1.0/instances/{name}/snapshots"),
            Some(&body),
            Duration::from_secs(300),
            "snapshot creation",
        )
        .await
        .map(drop)
    }

    /// Delete a snapshot.
    pub async fn delete_snapshot(&self, instance: &str, snapshot: &str) -> Result<(), IncusError> {
        let name = checked("instance", instance)?;
        let snap = checked("snapshot", snapshot)?;
        self.run(
            Method::DELETE,
            format!("/1.0/instances/{name}/snapshots/{snap}"),
            None,
            Duration::from_secs(300),
            "snapshot deletion",
        )
        .await
        .map(drop)
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

fn decode<D: serde::de::DeserializeOwned>(what: &str, v: Value) -> Result<D, IncusError> {
    serde_json::from_value(v).map_err(|e| IncusError::Protocol(format!("cannot read {what}: {e}")))
}
