//! Creating a desktop container and running a plan in it.
//!
//! [`IncusExecutor`] implements [`Executor`] on top of the Incus client. Incus can only feed
//! stdin to a command over a websocket, which the REST client does not use; instead, stdin is
//! written to a root-only (0600) file in a root-only (0700) directory inside the container and
//! redirected into the command, and the file is removed when the command ends. The secret is
//! never in argv, in the environment, or visible to other users in the container.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::exec::{
    ApplyError, ExecError, ExecOutput, ExecRequest, Executor, FilePush, Progress, Secrets,
    StageReport, apply_stage,
};
use crate::host::{Naming, needs_compat_profile};
use crate::incus::{
    Client, ExecSpec, ImageSource, IncusError, InstanceCreate, StateAction, Transport,
};
use crate::plan::{ImageRef, Plan, Stage};

/// Directory inside the container for stdin files.
const STDIN_DIR: &str = "/run/hx-provision";

/// Runs commands in one container through the Incus API.
#[derive(Debug)]
pub struct IncusExecutor<'a, T: Transport> {
    client: &'a Client<T>,
    instance: String,
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

impl<'a, T: Transport> IncusExecutor<'a, T> {
    /// Executor for `instance`.
    pub fn new(client: &'a Client<T>, instance: impl Into<String>) -> Self {
        Self {
            client,
            instance: instance.into(),
        }
    }

    fn unique_name() -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        format!(
            "stdin-{}-{}-{nanos}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        )
    }
}

/// The in-container command for a request: bounded by `timeout(1)` so that the process dies
/// inside the container even if the API-side operation cannot be cancelled.
pub(crate) fn wrap_command(req: &ExecRequest, stdin_file: Option<&str>) -> Vec<String> {
    let mut v = vec![
        "timeout".to_string(),
        "--kill-after=15".into(),
        req.timeout.as_secs().max(1).to_string(),
    ];
    v.extend(req.argv.iter().cloned());
    match stdin_file {
        None => v,
        Some(file) => {
            let mut w = vec![
                "sh".to_string(),
                "-c".into(),
                // Redirect the secret file into the command, then remove it, keeping the exit status.
                r#"f=$1; shift; "$@" < "$f"; rc=$?; rm -f -- "$f"; exit $rc"#.into(),
                "sh".into(),
                file.to_string(),
            ];
            w.extend(v);
            w
        }
    }
}

impl<T: Transport> Executor for IncusExecutor<'_, T> {
    async fn exec(&self, req: &ExecRequest) -> Result<ExecOutput, ExecError> {
        let backend = |e: IncusError| match e {
            IncusError::Timeout { after, .. } => ExecError::Timeout(after),
            other => ExecError::Backend(other.to_string()),
        };
        let stdin_file = match &req.stdin {
            Some(secret) => {
                self.client
                    .push_dir(&self.instance, STDIN_DIR, 0o700)
                    .await
                    .map_err(backend)?;
                let path = format!("{STDIN_DIR}/{}", Self::unique_name());
                self.client
                    .push_file(&self.instance, &path, secret.expose(), 0o600)
                    .await
                    .map_err(backend)?;
                Some(path)
            }
            None => None,
        };
        let spec = ExecSpec {
            command: wrap_command(req, stdin_file.as_deref()),
            env: req.env.clone(),
            cwd: req.cwd.clone(),
            // Leave room for `timeout`'s own kill-after grace so the in-container limit fires first.
            timeout: req.timeout + Duration::from_secs(60),
        };
        let result = self.client.exec(&self.instance, &spec).await;
        if let (Some(path), Err(_)) = (&stdin_file, &result) {
            // The command may not have run to its cleanup: best-effort removal of the secret file.
            let rm = ExecSpec {
                command: vec!["rm".into(), "-f".into(), "--".into(), path.clone()],
                env: Vec::new(),
                cwd: None,
                timeout: Duration::from_secs(30),
            };
            let _ = self.client.exec(&self.instance, &rm).await;
        }
        let out = result.map_err(backend)?;
        if out.exit_code == 124 {
            return Err(ExecError::Timeout(req.timeout));
        }
        Ok(ExecOutput {
            exit_code: out.exit_code,
            stdout: out.stdout,
            stderr: out.stderr,
        })
    }

    async fn push_file(&self, file: &FilePush) -> Result<(), ExecError> {
        self.client
            .push_file(&self.instance, &file.path, &file.content, file.mode)
            .await
            .map_err(|e| ExecError::Backend(e.to_string()))
    }
}

// ---------------------------------------------------------------------------------------------
// Readiness
// ---------------------------------------------------------------------------------------------

/// Why the desktop did not reach `running`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReadyError {
    /// Still not running when the time was up.
    #[error("`systemctl is-system-running` was `{last}` after {after:?}")]
    Timeout {
        /// Last state seen (or the last error).
        last: String,
        /// How long we waited.
        after: Duration,
    },
    /// Boot finished but units failed (`degraded`).
    #[error("the system is degraded; failed units: {failed}")]
    Degraded {
        /// Output of `systemctl --failed`.
        failed: String,
    },
    /// The API failed in a way that waiting will not fix.
    #[error(transparent)]
    Incus(#[from] IncusError),
}

/// How to wait for boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadyOptions {
    /// Give up after this long.
    pub timeout: Duration,
    /// Accept `degraded` as ready (default `false`: the architecture requires `running`).
    pub allow_degraded: bool,
}

impl Default for ReadyOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(180),
            allow_degraded: false,
        }
    }
}

/// Poll `systemctl is-system-running` in the container until it prints `running`.
///
/// `starting`, a stopped instance and exec errors during boot count as "not yet". `degraded` is
/// final (boot is over, units failed) and returns [`ReadyError::Degraded`] with the failed units
/// unless `allow_degraded` is set.
pub async fn wait_system_running<T: Transport>(
    client: &Client<T>,
    instance: &str,
    opts: ReadyOptions,
) -> Result<(), ReadyError> {
    let started = Instant::now();
    let mut last: String;
    let probe = |cmd: &[&str]| ExecSpec {
        command: cmd.iter().map(|s| s.to_string()).collect(),
        env: Vec::new(),
        cwd: None,
        timeout: Duration::from_secs(20),
    };
    loop {
        match client
            .exec(instance, &probe(&["systemctl", "is-system-running"]))
            .await
        {
            Ok(r) => {
                let state = r.stdout.trim().to_string();
                match state.as_str() {
                    "running" => return Ok(()),
                    "degraded" => {
                        if opts.allow_degraded {
                            return Ok(());
                        }
                        let failed = client
                            .exec(
                                instance,
                                &probe(&["systemctl", "--failed", "--no-legend", "--plain"]),
                            )
                            .await
                            .map(|f| f.stdout.trim().replace('\n', "; "))
                            .unwrap_or_else(|e| format!("(could not list: {e})"));
                        return Err(ReadyError::Degraded { failed });
                    }
                    _ => {
                        last = if state.is_empty() {
                            format!("(empty, exit {})", r.exit_code)
                        } else {
                            state
                        }
                    }
                }
            }
            // The instance is still booting or not yet running: retry.
            Err(IncusError::Api { message, .. }) => last = message,
            Err(IncusError::Operation(m)) => last = m,
            Err(IncusError::Timeout { .. }) => last = "systemctl did not answer".into(),
            Err(e) => return Err(e.into()),
        }
        if started.elapsed() >= opts.timeout {
            return Err(ReadyError::Timeout {
                last,
                after: opts.timeout,
            });
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

// ---------------------------------------------------------------------------------------------
// Desktop creation
// ---------------------------------------------------------------------------------------------

/// CPU, memory and disk limits from the setup wizard. `None` means unlimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Limits {
    /// Number of CPUs (`limits.cpu`).
    pub cpu: Option<u32>,
    /// Memory in MiB (`limits.memory`).
    pub memory_mib: Option<u64>,
    /// Root disk quota in GiB (the root device's `size`).
    pub disk_gib: Option<u64>,
}

/// A desktop container to create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopSpec {
    /// Instance name.
    pub name: String,
    /// Object names (pool, profiles).
    pub naming: Naming,
    /// Image to create it from.
    pub image: ImageSource,
    /// Resource limits.
    pub limits: Limits,
    /// Whether to attach the Debian 13 compatibility profile.
    pub compat_profile: bool,
    /// Extra instance configuration (the plan's `incus_config`, e.g. Docker's nesting keys).
    pub extra_config: BTreeMap<String, String>,
}

/// Map a recipe image to an Incus image source.
pub fn image_source(image: &ImageRef) -> ImageSource {
    match image {
        ImageRef::Remote { alias } => ImageSource::official(alias.clone()),
        ImageRef::Local { alias } => ImageSource::LocalAlias(alias.clone()),
    }
}

impl DesktopSpec {
    /// A spec for building `plan` on the server, from the recipe's base image.
    pub fn for_plan(name: impl Into<String>, naming: Naming, plan: &Plan, limits: Limits) -> Self {
        Self {
            name: name.into(),
            naming,
            image: image_source(&plan.base_image),
            limits,
            compat_profile: needs_compat_profile(plan),
            extra_config: plan.incus_config.clone(),
        }
    }

    /// Use another image, for example the imported prebuilt image.
    pub fn with_image(mut self, image: ImageSource) -> Self {
        self.image = image;
        self
    }

    /// The Incus request. The instance is always unprivileged (`security.privileged=false`) and
    /// starts at boot.
    pub fn to_create(&self) -> InstanceCreate {
        let mut config: BTreeMap<String, String> = BTreeMap::new();
        config.insert("security.privileged".into(), "false".into());
        config.insert("boot.autostart".into(), "true".into());
        if let Some(c) = self.limits.cpu {
            config.insert("limits.cpu".into(), c.to_string());
        }
        if let Some(m) = self.limits.memory_mib {
            config.insert("limits.memory".into(), format!("{m}MiB"));
        }
        for (k, v) in &self.extra_config {
            // A recipe can never lift the unprivileged setting.
            if k != "security.privileged" {
                config.insert(k.clone(), v.clone());
            }
        }
        let mut devices = BTreeMap::new();
        if let Some(d) = self.limits.disk_gib {
            let root: BTreeMap<String, String> = [
                ("type", "disk".to_string()),
                ("path", "/".to_string()),
                ("pool", self.naming.pool.clone()),
                ("size", format!("{d}GiB")),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
            devices.insert("root".to_string(), root);
        }
        let mut profiles = vec![self.naming.desktop_profile.clone()];
        if self.compat_profile {
            profiles.push(self.naming.compat_profile.clone());
        }
        InstanceCreate {
            name: self.name.clone(),
            image: self.image.clone(),
            profiles,
            config,
            devices,
        }
    }
}

/// Failure of a provisioning run.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProvisionError {
    /// Incus API failure.
    #[error(transparent)]
    Incus(#[from] IncusError),
    /// The container did not reach `running`.
    #[error("the desktop did not finish booting: {0}")]
    NotReady(#[from] ReadyError),
    /// A plan step failed.
    #[error(transparent)]
    Apply(#[from] ApplyError),
    /// Bad input.
    #[error("invalid request: {0}")]
    Invalid(String),
}

/// What a provisioning run did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProvisionReport {
    /// Build stage report; `None` for the prebuilt path.
    pub build: Option<StageReport>,
    /// Post stage report.
    pub post: Option<StageReport>,
}

/// Longest wait for image download and unpacking.
const CREATE_DEADLINE: Duration = Duration::from_secs(20 * 60);

async fn launch<T: Transport>(
    client: &Client<T>,
    spec: &DesktopSpec,
    ready: ReadyOptions,
) -> Result<(), ProvisionError> {
    client
        .create_instance(&spec.to_create(), CREATE_DEADLINE)
        .await?;
    client
        .set_state(
            &spec.name,
            StateAction::Start,
            false,
            Duration::from_secs(60),
        )
        .await?;
    wait_system_running(client, &spec.name, ready).await?;
    Ok(())
}

/// Build path: create the container from the recipe's base image, start it, wait for `running`,
/// run the build stage and then the post stage.
///
/// On failure the container is left in place for inspection; use [`destroy_instance`] to remove it.
pub async fn build_on_server<T: Transport>(
    client: &Client<T>,
    plan: &Plan,
    spec: &DesktopSpec,
    secrets: &Secrets,
    on_progress: &mut (dyn FnMut(&Progress) + Send),
) -> Result<ProvisionReport, ProvisionError> {
    launch(client, spec, ReadyOptions::default()).await?;
    let exec = IncusExecutor::new(client, spec.name.clone());
    let build = apply_stage(&exec, plan, Stage::Build, &Secrets::none(), on_progress).await?;
    let post = apply_stage(&exec, plan, Stage::Post, secrets, on_progress).await?;
    Ok(ProvisionReport {
        build: Some(build),
        post: Some(post),
    })
}

/// Prebuilt path: create the container from an already imported image (set with
/// [`DesktopSpec::with_image`]), start it and run the post stage only.
pub async fn finish_prebuilt<T: Transport>(
    client: &Client<T>,
    plan: &Plan,
    spec: &DesktopSpec,
    secrets: &Secrets,
    on_progress: &mut (dyn FnMut(&Progress) + Send),
) -> Result<ProvisionReport, ProvisionError> {
    if matches!(spec.image, ImageSource::Remote { .. }) {
        return Err(ProvisionError::Invalid(
            "the prebuilt path needs a local image, not a remote alias".into(),
        ));
    }
    launch(client, spec, ReadyOptions::default()).await?;
    let exec = IncusExecutor::new(client, spec.name.clone());
    let post = apply_stage(&exec, plan, Stage::Post, secrets, on_progress).await?;
    Ok(ProvisionReport {
        build: None,
        post: Some(post),
    })
}

/// Stop (forcibly) and delete an instance. Succeeds when it is already gone.
pub async fn destroy_instance<T: Transport>(
    client: &Client<T>,
    name: &str,
) -> Result<(), IncusError> {
    match client.get_instance(name).await? {
        None => return Ok(()),
        Some(i) if !i.status.eq_ignore_ascii_case("stopped") => {
            client
                .set_state(name, StateAction::Stop, true, Duration::from_secs(30))
                .await?;
        }
        Some(_) => {}
    }
    client.delete_instance(name).await
}
