//! The Docker opt-in: nesting and syscall interception on the container, Docker Engine from
//! Docker's apt repository, the desktop user in the `docker` group, a restart, and a self-test.
//!
//! The Incus version is only a gate (6.0.5 or newer); what decides success is the self-test
//! `docker run --rm hello-world` on Docker's default bridge (architecture 4.3). A failed
//! self-test is a normal, structured result, not an error, so the caller can offer the fallbacks.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::exec::{ExecRequest, Executor, Progress, Secrets, apply_stage};
use crate::incus::{Client, DOCKER_MIN_INCUS, IncusVersion, StateAction, Transport};
use crate::orchestrate::{IncusExecutor, ProvisionError, ReadyOptions, wait_system_running};
use crate::plan::{Plan, Stage};

/// What to do when the self-test fails (architecture 4.3), in the order to offer them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DockerFallback {
    /// Upgrade Incus from the Zabbly repository and try again.
    UpgradeIncusFromZabbly,
    /// Docker with `--network host` only (worked on every version tested; no port isolation
    /// inside the desktop, and Compose files need `network_mode: host`).
    HostNetworkOnly,
    /// Run the desktop as an Incus VM (needs `/dev/kvm`; not for v1).
    IncusVm,
}

/// What the self-test output tells us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfTestHint {
    /// runc could not set `net.ipv4.ip_unprivileged_port_start`: the known Incus 6.0.0 failure.
    RuncSysctlDenied,
    /// The Docker daemon is not running.
    DaemonNotRunning,
    /// Docker Hub could not be reached.
    RegistryUnreachable,
    /// Anything else.
    Unknown,
}

/// Result of [`enable_docker`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DockerOutcome {
    /// Installed and the self-test passed.
    Enabled {
        /// `docker --version` output.
        docker_version: String,
    },
    /// Incus is older than 6.0.5; nothing was changed.
    UnsupportedIncus {
        /// Installed version.
        found: IncusVersion,
        /// Required version.
        required: IncusVersion,
        /// Options to offer.
        fallbacks: Vec<DockerFallback>,
    },
    /// Installed, but `docker run --rm hello-world` did not work. Nesting and the syscall
    /// interception were rolled back (see `isolation_restored`).
    SelfTestFailed {
        /// Whether `security.nesting` and the intercepts were switched back off (and the desktop
        /// restarted). When `false` the desktop keeps the reduced isolation; the caller must retry
        /// the rollback or warn the user.
        isolation_restored: bool,
        /// Diagnosis.
        hint: SelfTestHint,
        /// Tail of the output.
        output_tail: String,
        /// Options to offer, in order.
        fallbacks: Vec<DockerFallback>,
    },
}

/// Options for [`enable_docker`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DockerOptions {
    /// Try even when Incus is older than 6.0.5 (the self-test still decides).
    pub allow_old_incus: bool,
    /// Time allowed for `docker run` including the pull.
    pub selftest_timeout: Duration,
}

impl Default for DockerOptions {
    fn default() -> Self {
        Self {
            allow_old_incus: false,
            selftest_timeout: Duration::from_secs(300),
        }
    }
}

/// The fallbacks, most preferred first.
pub fn fallbacks() -> Vec<DockerFallback> {
    vec![
        DockerFallback::UpgradeIncusFromZabbly,
        DockerFallback::HostNetworkOnly,
        DockerFallback::IncusVm,
    ]
}

/// Interpret the self-test output.
pub fn classify_selftest(output: &str) -> SelfTestHint {
    let o = output.to_ascii_lowercase();
    if o.contains("ip_unprivileged_port_start") {
        SelfTestHint::RuncSysctlDenied
    } else if o.contains("cannot connect to the docker daemon")
        || o.contains("is the docker daemon running")
    {
        SelfTestHint::DaemonNotRunning
    } else if o.contains("toomanyrequests")
        || o.contains("no such host")
        || o.contains("i/o timeout")
        || o.contains("tls handshake timeout")
        || o.contains("connection refused") && o.contains("registry")
    {
        SelfTestHint::RegistryUnreachable
    } else {
        SelfTestHint::Unknown
    }
}

/// Whether the self-test passed.
pub fn selftest_passed(exit_code: i32, stdout: &str) -> bool {
    exit_code == 0 && stdout.contains("Hello from Docker!")
}

/// Whether `found` can be used for Docker without override.
pub fn incus_supports_docker(found: IncusVersion) -> bool {
    found >= DOCKER_MIN_INCUS
}

const SELFTEST_SCRIPT: &str = "for i in $(seq 1 60); do systemctl is-active --quiet docker && break; sleep 1; done; docker run --rm hello-world";

async fn restart<T: Transport>(client: &Client<T>, name: &str) -> Result<(), ProvisionError> {
    client
        .set_state(name, StateAction::Restart, false, Duration::from_secs(60))
        .await?;
    wait_system_running(client, name, ReadyOptions::default()).await?;
    Ok(())
}

/// Turn Docker on in an existing desktop.
///
/// `addon_plan` is the Docker add-on resolved against the desktop's recipe
/// ([`Catalog::resolve_addon`](crate::Catalog::resolve_addon)). Steps:
/// 1. check the Incus version (nothing is changed when too old, unless `allow_old_incus`);
/// 2. set the add-on's instance config (nesting, `mknod` and `setxattr` interception) and restart;
/// 3. install Docker Engine from Docker's repository, add the user to `docker`;
/// 4. restart so the user manager sees the new group;
/// 5. run the self-test and report a structured result.
///
/// On an install error or a failed self-test, `security.nesting` and the intercepts are switched
/// back off and the desktop restarted (a failing self-test reports `isolation_restored`).
///
/// Errors (`Err`) are failures to carry out a step; a failing self-test is `Ok(SelfTestFailed)`.
pub async fn enable_docker<T: Transport>(
    client: &Client<T>,
    instance: &str,
    addon_plan: &Plan,
    opts: DockerOptions,
    on_progress: &mut (dyn FnMut(&Progress) + Send),
) -> Result<DockerOutcome, ProvisionError> {
    if addon_plan.incus_config.is_empty() {
        return Err(ProvisionError::Invalid(
            "the plan has no incus_config: it is not the Docker add-on".into(),
        ));
    }
    crate::plan::check_instance_config(&addon_plan.incus_config)
        .map_err(|(k, why)| ProvisionError::Invalid(format!("instance config `{k}`: {why}")))?;
    let found = client.server_info().await?.version()?;
    if !incus_supports_docker(found) && !opts.allow_old_incus {
        return Ok(DockerOutcome::UnsupportedIncus {
            found,
            required: DOCKER_MIN_INCUS,
            fallbacks: fallbacks(),
        });
    }

    let config: BTreeMap<String, String> = addon_plan.incus_config.clone();
    client.patch_instance_config(instance, &config).await?;
    let result = install_and_test(client, instance, addon_plan, opts, on_progress).await;
    match result {
        Ok(DockerOutcome::SelfTestFailed {
            hint,
            output_tail,
            fallbacks,
            ..
        }) => {
            let isolation_restored = rollback(client, instance, &config).await;
            Ok(DockerOutcome::SelfTestFailed {
                isolation_restored,
                hint,
                output_tail,
                fallbacks,
            })
        }
        Ok(other) => Ok(other),
        Err(e) => {
            // Do not leave nesting and syscall interception on for a desktop without working Docker.
            let _ = rollback(client, instance, &config).await;
            Err(e)
        }
    }
}

/// Switch the add-on's instance config back off and restart. `true` when it worked.
async fn rollback<T: Transport>(
    client: &Client<T>,
    instance: &str,
    config: &BTreeMap<String, String>,
) -> bool {
    let off: BTreeMap<String, String> = config
        .keys()
        .map(|k| (k.clone(), "false".to_string()))
        .collect();
    if client.patch_instance_config(instance, &off).await.is_err() {
        return false;
    }
    restart(client, instance).await.is_ok()
}

async fn install_and_test<T: Transport>(
    client: &Client<T>,
    instance: &str,
    addon_plan: &Plan,
    opts: DockerOptions,
    on_progress: &mut (dyn FnMut(&Progress) + Send),
) -> Result<DockerOutcome, ProvisionError> {
    restart(client, instance).await?;

    let exec = IncusExecutor::new(client, instance);
    apply_stage(
        &exec,
        addon_plan,
        Stage::Build,
        &Secrets::none(),
        on_progress,
    )
    .await?;
    restart(client, instance).await?;

    let version = exec
        .exec(&ExecRequest {
            label: "docker-version".into(),
            argv: vec!["docker".into(), "--version".into()],
            env: Vec::new(),
            cwd: None,
            stdin: None,
            timeout: Duration::from_secs(30),
        })
        .await
        .map(|o| tail(&o.stdout, 200))
        .unwrap_or_default();

    let test = exec
        .exec(&ExecRequest {
            label: "docker-selftest".into(),
            argv: vec!["bash".into(), "-c".into(), SELFTEST_SCRIPT.into()],
            env: Vec::new(),
            cwd: None,
            stdin: None,
            timeout: opts.selftest_timeout,
        })
        .await;
    match test {
        Ok(o) if selftest_passed(o.exit_code, &o.stdout) => Ok(DockerOutcome::Enabled {
            docker_version: version,
        }),
        Ok(o) => {
            let all = format!("{}\n{}", o.stderr.trim(), o.stdout.trim());
            Ok(DockerOutcome::SelfTestFailed {
                isolation_restored: false,
                hint: classify_selftest(&all),
                output_tail: tail(&all, 2000),
                fallbacks: fallbacks(),
            })
        }
        Err(e) => Ok(DockerOutcome::SelfTestFailed {
            isolation_restored: false,
            hint: SelfTestHint::Unknown,
            output_tail: tail(&e.to_string(), 2000),
            fallbacks: fallbacks(),
        }),
    }
}

fn tail(s: &str, max: usize) -> String {
    crate::exec::sanitize(s, max)
}
