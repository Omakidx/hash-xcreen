//! Creating a desktop container and running a plan in it.
//!
//! [`IncusExecutor`] implements [`Executor`] on top of the Incus client.
//!
//! # Output and stdin without websockets or host-side logs
//!
//! Incus can feed stdin to a command, or record its output, only through websockets or log files
//! that the *host* writes under `/var/log/incus` without any size limit. A container that has run
//! user code could use that to fill the host disk. So no exec in this crate sets `record-output`.
//! Instead [`exec_captured`] runs the command under a small `sh` wrapper that writes stdout and
//! stderr to files in a root-only (0700) directory inside the container, truncated to their last
//! 64 KiB, and reads them back through the file API with a hard size cap. The exit status comes
//! from the exec operation itself. Whatever the container writes there is *untrusted data*
//! (sanitized before it reaches an error or outcome).
//!
//! Stdin works the same way: the bytes are written to a 0600 file in that directory, redirected
//! into the command, and removed afterwards (also when the push or the command fails, and by a
//! sweep around the post stage). The secret is never in argv, in the environment, or in a URL.
//!
//! Which functions may run on a container that has executed user code: [`wait_system_running`],
//! [`IncusExecutor`] and `enable_docker` all use the bounded path, so all of them may.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::exec::{
    ApplyError, ExecError, ExecOutput, ExecRequest, Executor, FilePush, Progress, Secrets,
    StageReport, apply_stage, sanitize,
};
use crate::host::{Naming, needs_compat_profile};
use crate::incus::{
    Client, ExecResult, ExecSpec, ImageSource, IncusError, InstanceCreate, MAX_OUTPUT, StateAction,
    Transport,
};
use crate::plan::{ImageRef, Plan, Stage};

/// Root-only directory inside the container for stdin and captured-output files.
pub const WORK_DIR: &str = "/run/hx-provision";

/// Runs the command given as `"$@"` with optional stdin file `$f`, output to `$o.out`/`$o.err`
/// (kept to their last 64 KiB); exits with the command's status.
const CAPTURE_SCRIPT: &str = r#"o=$1; f=$2; shift 2
if [ -n "$f" ]; then "$@" <"$f" >"$o.out" 2>"$o.err"; else "$@" </dev/null >"$o.out" 2>"$o.err"; fi
rc=$?
if [ -n "$f" ]; then rm -f -- "$f"; fi
for s in out err; do tail -c 65536 "$o.$s" >"$o.$s.t" 2>/dev/null && mv -f "$o.$s.t" "$o.$s"; done
exit $rc"#;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_name(kind: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!(
        "{kind}-{}-{}-{nanos}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

async fn read_capture<T: Transport>(client: &Client<T>, instance: &str, path: &str) -> String {
    match client.read_file(instance, path, 2 * MAX_OUTPUT).await {
        Ok(Some(bytes)) => sanitize(&String::from_utf8_lossy(&bytes), MAX_OUTPUT),
        Ok(None) => String::new(),
        Err(IncusError::TooLarge { .. }) => "(output too large, discarded)".into(),
        Err(e) => format!("(output unavailable: {e})"),
    }
}

/// Run a command and capture its output through the bounded file path (see the module docs).
///
/// `stdin_file` is a path inside the container to redirect into the command; the wrapper deletes
/// it. The command is also bounded by `timeout(1)` inside the container. Output files are always
/// deleted, including after errors and timeouts.
pub async fn exec_captured<T: Transport>(
    client: &Client<T>,
    instance: &str,
    argv: &[String],
    env: &[(String, String)],
    cwd: Option<&str>,
    stdin_file: Option<&str>,
    timeout: Duration,
) -> Result<ExecResult, IncusError> {
    client.push_dir(instance, WORK_DIR, 0o700).await?;
    let base = format!("{WORK_DIR}/o-{}", unique_name("o"));
    let mut command: Vec<String> = vec![
        "sh".into(),
        "-c".into(),
        CAPTURE_SCRIPT.into(),
        "sh".into(),
        base.clone(),
        stdin_file.unwrap_or("").to_string(),
        "timeout".into(),
        "--kill-after=15".into(),
        timeout.as_secs().max(1).to_string(),
    ];
    command.extend(argv.iter().cloned());
    let spec = ExecSpec {
        command,
        env: env.to_vec(),
        cwd: cwd.map(str::to_string),
        // Leave room for `timeout`'s own kill-after grace so the in-container limit fires first.
        timeout: timeout + Duration::from_secs(60),
    };
    let status = client.exec(instance, &spec).await;
    let stdout = read_capture(client, instance, &format!("{base}.out")).await;
    let stderr = read_capture(client, instance, &format!("{base}.err")).await;
    for suffix in [".out", ".err", ".out.t", ".err.t"] {
        let _ = client
            .delete_file(instance, &format!("{base}{suffix}"))
            .await;
    }
    let status = status?;
    Ok(ExecResult {
        exit_code: status.exit_code,
        stdout,
        stderr,
    })
}

/// Runs commands in one container through the Incus API.
#[derive(Debug)]
pub struct IncusExecutor<'a, T: Transport> {
    client: &'a Client<T>,
    instance: String,
}

impl<'a, T: Transport> IncusExecutor<'a, T> {
    /// Executor for `instance`.
    pub fn new(client: &'a Client<T>, instance: impl Into<String>) -> Self {
        Self {
            client,
            instance: instance.into(),
        }
    }

    /// Remove everything in [`WORK_DIR`]: leftover stdin files and captured output. Call it before
    /// and after a stage that handles secrets ([`run_post_stage`] does). Non-zero exit (for
    /// example the directory does not exist yet) is not an error.
    pub async fn sweep(&self) -> Result<(), IncusError> {
        let spec = ExecSpec {
            command: vec![
                "find".into(),
                WORK_DIR.into(),
                "-mindepth".into(),
                "1".into(),
                "-delete".into(),
            ],
            env: Vec::new(),
            cwd: None,
            timeout: Duration::from_secs(30),
        };
        self.client.exec(&self.instance, &spec).await.map(drop)
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
                    .push_dir(&self.instance, WORK_DIR, 0o700)
                    .await
                    .map_err(backend)?;
                let path = format!("{WORK_DIR}/{}", unique_name("stdin"));
                if let Err(e) = self
                    .client
                    .push_secret_file(&self.instance, &path, secret, 0o600)
                    .await
                {
                    // The daemon may have stored the file before failing: remove it.
                    let _ = self.client.delete_file(&self.instance, &path).await;
                    return Err(backend(e));
                }
                Some(path)
            }
            None => None,
        };
        let result = exec_captured(
            self.client,
            &self.instance,
            &req.argv,
            &req.env,
            req.cwd.as_deref(),
            stdin_file.as_deref(),
            req.timeout,
        )
        .await;
        if let (Some(path), Err(_)) = (&stdin_file, &result) {
            // The command may not have run to its cleanup.
            let _ = self.client.delete_file(&self.instance, path).await;
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

/// Run the post stage (the only stage that handles the password) with the work directory swept
/// before and after.
pub async fn run_post_stage<T: Transport>(
    client: &Client<T>,
    instance: &str,
    plan: &Plan,
    secrets: &Secrets,
    on_progress: &mut (dyn FnMut(&Progress) + Send),
) -> Result<StageReport, ProvisionError> {
    let exec = IncusExecutor::new(client, instance);
    let _ = exec.sweep().await;
    let result = apply_stage(&exec, plan, Stage::Post, secrets, on_progress).await;
    let _ = exec.sweep().await;
    Ok(result?)
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
    let probe = async |cmd: &[&str]| {
        let argv: Vec<String> = cmd.iter().map(|s| s.to_string()).collect();
        exec_captured(
            client,
            instance,
            &argv,
            &[],
            None,
            None,
            Duration::from_secs(20),
        )
        .await
    };
    loop {
        match probe(&["systemctl", "is-system-running"]).await {
            Ok(r) => {
                let state = r.stdout.trim().to_string();
                match state.as_str() {
                    "running" => return Ok(()),
                    "degraded" => {
                        if opts.allow_degraded {
                            return Ok(());
                        }
                        let failed = probe(&["systemctl", "--failed", "--no-legend", "--plain"])
                            .await
                            .map(|f| sanitize(&f.stdout, 2000).replace('\n', "; "))
                            .unwrap_or_else(|e| format!("(could not list: {e})"));
                        return Err(ReadyError::Degraded { failed });
                    }
                    _ => {
                        last = if state.is_empty() {
                            format!("(empty, exit {})", r.exit_code)
                        } else {
                            sanitize(&state, 200)
                        }
                    }
                }
            }
            // The instance is still booting or not yet running: retry.
            Err(IncusError::Api { message, .. }) => last = sanitize(&message, 200),
            Err(IncusError::Operation(m)) => last = sanitize(&m, 200),
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
    /// Maximum number of processes and threads (`limits.processes`). `None` means
    /// [`DEFAULT_PROCESSES`]; there is no unlimited setting, so a fork bomb cannot exhaust the host.
    pub processes: Option<u32>,
}

/// Default `limits.processes` of a desktop.
pub const DEFAULT_PROCESSES: u32 = 8192;

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
    ///
    /// Hardening on every desktop: `security.guestapi=false` (no guest API socket),
    /// `security.idmap.isolated=true` (own uid/gid range, so desktops cannot share ids with each
    /// other or the host), and `limits.processes`. Fails when `extra_config` holds a key outside
    /// the recipe allowlist ([`crate::plan::check_instance_config`]).
    pub fn to_create(&self) -> Result<InstanceCreate, IncusError> {
        crate::plan::check_instance_config(&self.extra_config).map_err(|(k, why)| {
            IncusError::InvalidArgument(format!("instance config `{k}`: {why}"))
        })?;
        if self.limits.cpu == Some(0)
            || self.limits.memory_mib == Some(0)
            || self.limits.disk_gib == Some(0)
            || self.limits.processes == Some(0)
        {
            return Err(IncusError::InvalidArgument(
                "limits must not be zero".into(),
            ));
        }
        let mut config: BTreeMap<String, String> = BTreeMap::new();
        config.insert("security.privileged".into(), "false".into());
        config.insert("security.guestapi".into(), "false".into());
        config.insert("security.idmap.isolated".into(), "true".into());
        config.insert("boot.autostart".into(), "true".into());
        // The hash-xcreen marker (ipc.md 7, rule 8): teardown deletes only instances that have a
        // `user.hx.*` key. `hx-privd` moves the state on to `ready` (or `failed`) later.
        config.insert(crate::incus::INSTANCE_STATE_KEY.into(), "creating".into());
        config.insert(
            "limits.processes".into(),
            self.limits
                .processes
                .unwrap_or(DEFAULT_PROCESSES)
                .to_string(),
        );
        if let Some(c) = self.limits.cpu {
            config.insert("limits.cpu".into(), c.to_string());
        }
        if let Some(m) = self.limits.memory_mib {
            config.insert("limits.memory".into(), format!("{m}MiB"));
        }
        for (k, v) in &self.extra_config {
            config.insert(k.clone(), v.clone());
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
        Ok(InstanceCreate {
            name: self.name.clone(),
            image: self.image.clone(),
            profiles,
            config,
            devices,
        })
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
    /// A destructive call was refused because the object does not carry the hash-xcreen marker
    /// (privd: `PERMISSION_DENIED` or `FAILED_PRECONDITION`).
    #[error("`{0}` does not carry the hash-xcreen marker; refusing to delete it")]
    NotOurs(String),
    /// The requested mode or feature is named but not implemented (privd: `UNIMPLEMENTED`).
    #[error("not implemented: {0}")]
    Unimplemented(String),
    /// The operation needs a running desktop and it is not running (privd: `FAILED_PRECONDITION`).
    #[error("the desktop is not running")]
    NotRunning,
    /// A shielded section's task died (panic or runtime shutdown) before it could report.
    #[error("an internal task failed: {0}")]
    Task(String),
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
        .create_instance(&spec.to_create()?, CREATE_DEADLINE)
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
    let post = run_post_stage(client, &spec.name, plan, secrets, on_progress).await?;
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
    let post = run_post_stage(client, &spec.name, plan, secrets, on_progress).await?;
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
