//! The flat, ordered, validated result of resolving a recipe.

use std::collections::BTreeMap;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::manifest::Manifest;

/// Where the container's root filesystem comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ImageRef {
    /// An alias on the official Incus image server (`images:debian/13`).
    Remote {
        /// Alias without the remote prefix, e.g. `debian/13`.
        alias: String,
    },
    /// An image already in the local Incus image store (`local:hx-desktop`).
    Local {
        /// Local alias.
        alias: String,
    },
}

impl ImageRef {
    /// Recipe notation: `images:<alias>` or `local:<alias>`.
    pub fn notation(&self) -> String {
        match self {
            Self::Remote { alias } => format!("images:{alias}"),
            Self::Local { alias } => format!("local:{alias}"),
        }
    }
}

/// An apt repository, pinned by the fingerprint of its signing key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AptRepo {
    /// Short name; used for the keyring, `.sources` and preferences file names.
    pub name: String,
    /// HTTPS URL of the (armored or binary) key.
    pub key_url: String,
    /// Upper-case 40-hex-digit primary key fingerprint the downloaded key must match exactly.
    pub key_fingerprint: String,
    /// Repository base URI.
    pub uri: String,
    /// Suite (codename).
    pub suite: String,
    /// Space-separated components.
    pub components: String,
    /// Optional `apt_preferences` body.
    pub pin: Option<String>,
}

/// The desktop user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserSpec {
    /// Login name.
    pub name: String,
    /// Numeric uid, if pinned.
    pub uid: Option<u32>,
    /// Login shell.
    pub shell: String,
    /// Supplementary groups (created when missing).
    pub groups: Vec<String>,
    /// Whether to enable systemd lingering so the user manager starts at boot.
    pub linger: bool,
}

/// A file to write into the container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileSpec {
    /// Absolute path.
    pub path: String,
    /// Octal mode as written in the recipe, e.g. `0644`.
    pub mode: String,
    /// `user[:group]`.
    pub owner: String,
    /// File content (never a secret).
    pub content: String,
}

impl FileSpec {
    /// SHA-256 of the content, lower-case hex.
    pub fn sha256(&self) -> String {
        hex(&Sha256::digest(self.content.as_bytes()))
    }
}

/// Services to enable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct ServiceSpec {
    /// `systemctl enable <unit>`.
    pub system_enable: Vec<String>,
    /// `systemctl --global enable <unit>`.
    pub user_enable_global: Vec<String>,
}

/// A shell command from a recipe `pre_step`, `step` or `post_step`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CommandSpec {
    /// Step name.
    pub name: String,
    /// Script text, executed with `bash -euo pipefail -c`.
    pub run: String,
    /// Run as this user instead of root.
    pub as_user: Option<String>,
    /// A failure is reported as a warning instead of failing the stage.
    pub optional: bool,
    /// Wall-clock limit.
    pub timeout_secs: u64,
}

/// One unit of work in a plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum Step {
    /// Wait until DNS works inside the container.
    WaitNetwork,
    /// `apt-get update` and install the tools needed to fetch repository keys.
    AptBootstrap,
    /// Verify and install one apt repository.
    AptRepo(AptRepo),
    /// A recipe command.
    Command(CommandSpec),
    /// Update the package index and install packages.
    AptInstall {
        /// Package names, in recipe order, without duplicates.
        packages: Vec<String>,
    },
    /// Create the user (idempotent) and its groups.
    EnsureUser(UserSpec),
    /// Write a file.
    WriteFile(FileSpec),
    /// Enable services and lingering.
    EnableServices {
        /// Units to enable.
        services: ServiceSpec,
        /// User to enable lingering for.
        linger_user: Option<String>,
    },
    /// Rename the image's build user to the account the caller chose (post stage; a no-op when
    /// `from` does not exist or `to` already does). Home directory and primary group move too.
    RenameUser {
        /// The user baked into the image.
        from: String,
        /// The chosen login name.
        to: String,
    },
    /// Set the user's password from the run-time secret (post stage only).
    SetPassword {
        /// Login name.
        user: String,
    },
    /// `apt-get update && apt-get upgrade`.
    SecurityUpdates,
}

impl Step {
    /// Stable one-line description (no file contents, no scripts).
    pub fn describe(&self) -> String {
        match self {
            Self::WaitNetwork => "wait-network".into(),
            Self::AptBootstrap => "apt-bootstrap".into(),
            Self::AptRepo(r) => format!("apt-repo {} fingerprint={}", r.name, r.key_fingerprint),
            Self::Command(c) => format!(
                "command {}{}{}",
                c.name,
                c.as_user
                    .as_ref()
                    .map(|u| format!(" as={u}"))
                    .unwrap_or_default(),
                if c.optional { " optional" } else { "" }
            ),
            Self::AptInstall { packages } => format!("apt-install {}", packages.join(" ")),
            Self::EnsureUser(u) => format!(
                "ensure-user {} uid={} groups={}",
                u.name,
                u.uid.map(|x| x.to_string()).unwrap_or_else(|| "-".into()),
                u.groups.join(",")
            ),
            Self::WriteFile(f) => format!(
                "write-file {} mode={} owner={} sha256={}",
                f.path,
                f.mode,
                f.owner,
                f.sha256()
            ),
            Self::EnableServices {
                services,
                linger_user,
            } => format!(
                "enable-services system=[{}] user-global=[{}] linger={}",
                services.system_enable.join(","),
                services.user_enable_global.join(","),
                linger_user.as_deref().unwrap_or("-")
            ),
            Self::RenameUser { from, to } => format!("rename-user {from} -> {to}"),
            Self::SetPassword { user } => format!("set-password {user}"),
            Self::SecurityUpdates => "security-updates".into(),
        }
    }
}

/// The only instance configuration keys a recipe or add-on may set (the Docker add-on's).
pub const ALLOWED_INSTANCE_CONFIG: [&str; 3] = [
    "security.nesting",
    "security.syscalls.intercept.mknod",
    "security.syscalls.intercept.setxattr",
];

/// Check recipe-supplied instance configuration against the exact allowlist
/// [`ALLOWED_INSTANCE_CONFIG`], with `"true"`/`"false"` values. Returns the offending key and why.
/// Used by recipe validation, `DesktopSpec::to_create` and `enable_docker`, so no path can pass
/// `raw.lxc`, `raw.idmap`, `linux.kernel_modules`, `security.privileged`, or other intercepts such
/// as `security.syscalls.intercept.bpf*`.
pub fn check_instance_config(cfg: &BTreeMap<String, String>) -> Result<(), (String, String)> {
    for (k, v) in cfg {
        if k == "security.privileged" {
            return Err((
                k.clone(),
                "desktops are always unprivileged; this key is not allowed".into(),
            ));
        }
        if !ALLOWED_INSTANCE_CONFIG.contains(&k.as_str()) {
            return Err((
                k.clone(),
                "only `security.nesting`, `security.syscalls.intercept.mknod` and `security.syscalls.intercept.setxattr` may be set from a recipe".into(),
            ));
        }
        if v != "true" && v != "false" {
            return Err((k.clone(), "must be \"true\" or \"false\"".into()));
        }
    }
    Ok(())
}

/// Which half of the plan to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Everything that goes into a prebuilt image.
    Build,
    /// What runs after a prebuilt import, and after a server build.
    Post,
}

/// A resolved recipe: flat, ordered, deterministic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Plan {
    /// Recipe name.
    pub name: String,
    /// Base image for a build on the server (and for the image CI).
    pub base_image: ImageRef,
    /// Variables after merging (distro, codename, preset, ...).
    pub vars: BTreeMap<String, String>,
    /// Instance configuration the recipe asks for (Docker add-on: nesting and interception).
    pub incus_config: BTreeMap<String, String>,
    /// Build-stage steps in execution order.
    pub build: Vec<Step>,
    /// Post-stage steps in execution order.
    pub post: Vec<Step>,
}

impl Plan {
    /// Steps of one stage.
    pub fn stage(&self, stage: Stage) -> &[Step] {
        match stage {
            Stage::Build => &self.build,
            Stage::Post => &self.post,
        }
    }

    /// The desktop user, if the recipe defines one.
    pub fn user(&self) -> Option<&UserSpec> {
        self.build.iter().find_map(|s| match s {
            Step::EnsureUser(u) => Some(u),
            _ => None,
        })
    }

    /// Packages, files, services and repositories the plan results in, for the CI comparison of
    /// the prebuilt and the server-built desktop.
    pub fn manifest(&self) -> Manifest {
        Manifest::from_plan(self)
    }

    /// Deterministic text rendering of the whole plan (used by golden tests and `--dry-run`
    /// style tooling). Scripts and file contents are summarised by hash, never printed.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "recipe {}\nbase_image {}\n",
            self.name,
            self.base_image.notation()
        ));
        for (k, v) in &self.vars {
            out.push_str(&format!("var {k}={v}\n"));
        }
        for (k, v) in &self.incus_config {
            out.push_str(&format!("incus_config {k}={v}\n"));
        }
        for (label, steps) in [("build", &self.build), ("post", &self.post)] {
            out.push_str(&format!("[{label}]\n"));
            for (i, s) in steps.iter().enumerate() {
                out.push_str(&format!("{:02} {}\n", i + 1, s.describe()));
            }
        }
        out
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}
