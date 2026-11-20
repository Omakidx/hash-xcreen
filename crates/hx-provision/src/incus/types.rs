//! Request and response shapes of the Incus REST API that provisioning needs.
//!
//! Requests are built from typed structs. Responses are read leniently (every field optional,
//! unknown fields ignored) so that a newer or odd daemon cannot make us panic; missing pieces
//! surface as [`IncusError::Protocol`](super::IncusError::Protocol) where they matter.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::error::IncusError;
use super::version::IncusVersion;

/// The official Incus image server.
pub const IMAGES_SERVER: &str = "https://images.linuxcontainers.org";

/// Digest of `GET /1.0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInfo {
    /// REST API version, e.g. `1.0`.
    pub api_version: String,
    /// Authentication state of this connection (`trusted` over the unix socket as root/admin).
    pub auth: String,
    /// Daemon version string as reported.
    pub server_version: String,
    /// Storage drivers the server supports.
    pub storage_drivers: Vec<String>,
    /// Firewall backend in use (`nftables` / `xtables`).
    pub firewall: String,
    /// Host kernel version.
    pub kernel_version: String,
}

impl ServerInfo {
    pub(crate) fn from_metadata(m: &Value) -> Result<Self, IncusError> {
        let s = |v: &Value, k: &str| {
            v.get(k)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let env = m
            .get("environment")
            .ok_or_else(|| IncusError::Protocol("GET /1.0 has no `environment`".into()))?;
        let info = ServerInfo {
            api_version: s(m, "api_version"),
            auth: s(m, "auth"),
            server_version: s(env, "server_version"),
            storage_drivers: env
                .get("storage_supported_drivers")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|d| d.get("Name").and_then(Value::as_str))
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
            firewall: s(env, "firewall"),
            kernel_version: s(env, "kernel_version"),
        };
        if info.server_version.is_empty() {
            return Err(IncusError::Protocol(
                "GET /1.0 has no `environment.server_version`".into(),
            ));
        }
        Ok(info)
    }

    /// The parsed daemon version.
    pub fn version(&self) -> Result<IncusVersion, IncusError> {
        self.server_version
            .parse()
            .map_err(|e| IncusError::Protocol(format!("{e}")))
    }
}

/// A storage pool as reported by the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
pub struct StoragePool {
    /// Pool name.
    #[serde(default)]
    pub name: String,
    /// Driver (`btrfs`, `zfs`, `dir`, ...).
    #[serde(default)]
    pub driver: String,
    /// Pool configuration.
    #[serde(default)]
    pub config: BTreeMap<String, String>,
    /// Pool status (`Created`).
    #[serde(default)]
    pub status: String,
}

/// A network as reported by the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
pub struct Network {
    /// Network name.
    #[serde(default)]
    pub name: String,
    /// Network type (`bridge`).
    #[serde(default, rename = "type")]
    pub kind: String,
    /// Network configuration.
    #[serde(default)]
    pub config: BTreeMap<String, String>,
    /// Network status.
    #[serde(default)]
    pub status: String,
}

/// An instance as reported by the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
pub struct Instance {
    /// Instance name.
    #[serde(default)]
    pub name: String,
    /// Run state text (`Running`, `Stopped`, ...).
    #[serde(default)]
    pub status: String,
    /// `container` or `virtual-machine`.
    #[serde(default, rename = "type")]
    pub kind: String,
    /// Profiles applied.
    #[serde(default)]
    pub profiles: Vec<String>,
    /// Instance-level configuration.
    #[serde(default)]
    pub config: BTreeMap<String, String>,
}

/// Run state of an instance (`GET /1.0/instances/<name>/state`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InstanceState {
    /// `Running`, `Stopped`, ...
    pub status: String,
    /// PID of init on the host, 0 when stopped.
    pub pid: i64,
    /// Global IPv4 addresses per interface name.
    pub ipv4: BTreeMap<String, Vec<String>>,
}

impl InstanceState {
    pub(crate) fn from_metadata(m: &Value) -> Self {
        let mut ipv4 = BTreeMap::new();
        if let Some(net) = m.get("network").and_then(Value::as_object) {
            for (name, nic) in net {
                let addrs: Vec<String> = nic
                    .get("addresses")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter(|x| x.get("family").and_then(Value::as_str) == Some("inet"))
                            .filter(|x| x.get("scope").and_then(Value::as_str) == Some("global"))
                            .filter_map(|x| x.get("address").and_then(Value::as_str))
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                if !addrs.is_empty() {
                    ipv4.insert(name.clone(), addrs);
                }
            }
        }
        Self {
            status: m
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            pid: m.get("pid").and_then(Value::as_i64).unwrap_or(0),
            ipv4,
        }
    }

    /// Whether the instance is running.
    pub fn is_running(&self) -> bool {
        self.status.eq_ignore_ascii_case("running")
    }
}

/// A snapshot of an instance.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
pub struct Snapshot {
    /// Snapshot name (without the `instance/` prefix).
    #[serde(default)]
    pub name: String,
    /// Creation time as reported (RFC 3339).
    #[serde(default)]
    pub created_at: String,
    /// Whether it includes memory state.
    #[serde(default)]
    pub stateful: bool,
}

/// An asynchronous Incus operation.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Operation {
    /// UUID.
    pub id: String,
    /// Status text (`Running`, `Success`, `Failure`, `Cancelled`).
    pub status: String,
    /// Numeric status (103 running, 200 success, 400 failure, 401 cancelled).
    pub status_code: i64,
    /// Error message of a failed operation.
    pub err: String,
    /// Operation-specific result metadata (exec: `return`, `output`).
    pub metadata: Value,
}

impl Operation {
    pub(crate) fn from_value(v: &Value) -> Result<Self, IncusError> {
        let s = |k: &str| {
            v.get(k)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let op = Operation {
            id: s("id"),
            status: s("status"),
            status_code: v.get("status_code").and_then(Value::as_i64).unwrap_or(0),
            err: s("err"),
            metadata: v.get("metadata").cloned().unwrap_or(Value::Null),
        };
        if op.status_code == 0 && op.status.is_empty() {
            return Err(IncusError::Protocol(
                "operation object has neither status nor status_code".into(),
            ));
        }
        Ok(op)
    }

    /// Finished, successfully or not.
    pub fn is_terminal(&self) -> bool {
        self.status_code >= 200
    }

    /// Finished successfully.
    pub fn is_success(&self) -> bool {
        self.status_code == 200
    }
}

// ---------------------------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------------------------

/// Action of an ACL rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AclAction {
    /// Let traffic through.
    Allow,
    /// Silently discard.
    Drop,
    /// Discard and tell the sender.
    Reject,
}

/// One network ACL rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AclRule {
    /// What to do with matching traffic.
    pub action: AclAction,
    /// Destination CIDR (egress rules); `None` matches any destination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    /// Source CIDR (ingress rules); `None` matches any source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Free text.
    pub description: String,
    /// Always `enabled`.
    pub state: &'static str,
}

impl AclRule {
    /// A rule matching one destination.
    pub fn to(
        action: AclAction,
        destination: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            action,
            destination: Some(destination.into()),
            source: None,
            description: description.into(),
            state: "enabled",
        }
    }

    /// A rule matching everything.
    pub fn any(action: AclAction, description: impl Into<String>) -> Self {
        Self {
            action,
            destination: None,
            source: None,
            description: description.into(),
            state: "enabled",
        }
    }
}

/// A network ACL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Acl {
    /// ACL name.
    pub name: String,
    /// Free text.
    pub description: String,
    /// Rules for traffic leaving instances, evaluated in order.
    pub egress: Vec<AclRule>,
    /// Rules for traffic entering instances.
    pub ingress: Vec<AclRule>,
}

/// A profile to create.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProfileSpec {
    /// Profile name.
    pub name: String,
    /// Free text.
    pub description: String,
    /// Instance configuration keys.
    pub config: BTreeMap<String, String>,
    /// Devices by name, each a map of device options.
    pub devices: BTreeMap<String, BTreeMap<String, String>>,
}

/// Where an instance's image comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageSource {
    /// An alias on a remote simplestreams server.
    Remote {
        /// Server URL.
        server: String,
        /// Alias, e.g. `debian/13`.
        alias: String,
    },
    /// An alias in the local image store.
    LocalAlias(String),
    /// A fingerprint in the local image store.
    LocalFingerprint(String),
}

impl ImageSource {
    /// The official image server and `alias`.
    pub fn official(alias: impl Into<String>) -> Self {
        Self::Remote {
            server: IMAGES_SERVER.to_string(),
            alias: alias.into(),
        }
    }

    pub(crate) fn to_json(&self) -> Value {
        match self {
            Self::Remote { server, alias } => {
                json!({"type": "image", "mode": "pull", "protocol": "simplestreams", "server": server, "alias": alias})
            }
            Self::LocalAlias(a) => json!({"type": "image", "alias": a}),
            Self::LocalFingerprint(f) => json!({"type": "image", "fingerprint": f}),
        }
    }
}

/// An instance (container) to create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceCreate {
    /// Instance name.
    pub name: String,
    /// Image to create it from.
    pub image: ImageSource,
    /// Profiles, in application order.
    pub profiles: Vec<String>,
    /// Instance configuration.
    pub config: BTreeMap<String, String>,
    /// Instance-level devices (overrides of profile devices).
    pub devices: BTreeMap<String, BTreeMap<String, String>>,
}

impl InstanceCreate {
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "type": "container",
            "source": self.image.to_json(),
            "profiles": self.profiles,
            "config": self.config,
            "devices": self.devices,
            "ephemeral": false,
        })
    }
}

/// A command to run in an instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecSpec {
    /// Program and arguments.
    pub command: Vec<String>,
    /// Environment.
    pub env: Vec<(String, String)>,
    /// Working directory.
    pub cwd: Option<String>,
    /// How long to wait for it before giving up.
    pub timeout: std::time::Duration,
}

impl ExecSpec {
    pub(crate) fn to_json(&self) -> Value {
        let env: serde_json::Map<String, Value> = self
            .env
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();
        let mut v = json!({
            "command": self.command,
            "environment": env,
            "wait-for-websocket": false,
            "interactive": false,
            "record-output": false,
        });
        if let (Some(cwd), Some(o)) = (&self.cwd, v.as_object_mut()) {
            o.insert("cwd".into(), Value::String(cwd.clone()));
        }
        v
    }
}

/// Result of a command run through the API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecResult {
    /// Exit status (128 + signal when killed, as Incus reports it).
    pub exit_code: i32,
    /// Captured stdout (tail, at most [`MAX_OUTPUT`] bytes).
    pub stdout: String,
    /// Captured stderr (tail, at most [`MAX_OUTPUT`] bytes).
    pub stderr: String,
}

/// Largest amount of stdout or stderr kept per command by the bounded capture path.
pub const MAX_OUTPUT: usize = 64 * 1024;

/// Instance state actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateAction {
    /// Start.
    Start,
    /// Stop.
    Stop,
    /// Restart.
    Restart,
}

impl StateAction {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
        }
    }
}
