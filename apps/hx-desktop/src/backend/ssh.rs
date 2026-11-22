//! The real [`InstallEngine`]: an adapter over `hx-sshsetup`.
//!
//! `probe_host_key` shows the fingerprint for confirmation, `preflight` connects against the
//! confirmed key and judges the server, `install` connects again, runs `install.sh --ssh` with the
//! secret frames and maps the engine's events onto [`InstallEvent`]. The installer script is
//! bundled with the app (`installer/install.sh`, which verifies the release itself).

use std::path::PathBuf;
use std::time::Duration;

use hx_sshsetup as ssh;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use super::*;

/// `installer/install.sh`, bundled at build time.
const INSTALL_SH: &[u8] = include_bytes!("../../../../installer/install.sh");

/// The port the requirement checks look at when the wizard has not chosen one yet.
const DEFAULT_PORT: u16 = 443;

/// The SSH install over `hx-sshsetup`.
#[derive(Default)]
pub struct SshInstallEngine {
    opts: ssh::ConnectOptions,
    /// A script to use instead of the bundled one (tests).
    pub script: Option<Vec<u8>>,
}

impl SshInstallEngine {
    /// An engine that uploads `script` instead of the bundled `install.sh` (tests).
    pub fn with_script(script: Vec<u8>) -> Self {
        Self {
            script: Some(script),
            ..Self::default()
        }
    }
}

fn algo_label(a: &str) -> String {
    let l = a.to_ascii_lowercase();
    if l.contains("ed25519") {
        "ED25519".into()
    } else if l.contains("rsa") {
        "RSA".into()
    } else if l.contains("ecdsa") {
        "ECDSA".into()
    } else {
        a.to_ascii_uppercase()
    }
}

/// `SshSetupError` to the screen's error.
pub fn engine_error(e: &ssh::SshSetupError) -> EngineError {
    use ssh::SshSetupError as E;
    match e {
        E::Connect(m) => EngineError::Unreachable(m.clone()),
        E::Timeout(w) => EngineError::Unreachable(format!("timed out: {w}")),
        E::AuthFailed => EngineError::AuthFailed,
        E::KeyPassphraseRequired => EngineError::KeyPassphraseRequired,
        E::HostKeyChanged { expected, actual } => EngineError::HostKeyChanged {
            expected: expected.clone(),
            actual: actual.clone(),
        },
        E::SudoPasswordRequired => EngineError::Other(
            "This account needs a sudo password. Use the root account, an account with passwordless sudo, or the password option.".into(),
        ),
        E::SudoPasswordWrong => EngineError::Other("The sudo password was not accepted.".into()),
        E::SudoUnavailable => EngineError::Other("This account is not root and cannot use sudo.".into()),
        other => EngineError::Other(other.to_string()),
    }
}

fn first_default_key() -> Option<PathBuf> {
    let home = PathBuf::from(std::env::var_os("HOME")?);
    ["id_ed25519", "id_ecdsa", "id_rsa"]
        .iter()
        .map(|n| home.join(".ssh").join(n))
        .find(|p| p.is_file())
}

fn credentials(auth: &SshAuth) -> Result<ssh::Credentials, EngineError> {
    Ok(match auth {
        SshAuth::Password { user, password } => ssh::Credentials {
            user: user.clone(),
            auth: ssh::Auth::Password(Zeroizing::new(password.expose().to_owned())),
        },
        SshAuth::KeyFile {
            user,
            path,
            passphrase,
        } => ssh::Credentials {
            user: user.clone(),
            auth: ssh::Auth::Key {
                source: ssh::KeySource::Path(PathBuf::from(path)),
                passphrase: passphrase
                    .as_ref()
                    .map(|p| Zeroizing::new(p.expose().to_owned())),
            },
        },
        SshAuth::DefaultKeys { user } => {
            let auth = if std::env::var_os("SSH_AUTH_SOCK").is_some() {
                ssh::Auth::Agent
            } else if let Some(p) = first_default_key() {
                ssh::Auth::Key {
                    source: ssh::KeySource::Path(p),
                    passphrase: None,
                }
            } else {
                return Err(EngineError::Other(
                    "No SSH key was found in ~/.ssh and no SSH agent is running. Choose a key file or use a password.".into(),
                ));
            };
            ssh::Credentials {
                user: user.clone(),
                auth,
            }
        }
    })
}

/// Rows of the requirement screen from the engine's report.
pub fn preflight_view(user: &str, r: &ssh::PreflightReport) -> Preflight {
    let f = &r.facts;
    let rows = r
        .checks
        .iter()
        .map(|c| {
            let status = match c.status {
                ssh::Status::Pass => CheckStatus::Pass,
                ssh::Status::Fail => CheckStatus::Fail,
                ssh::Status::Unknown => CheckStatus::Unknown,
            };
            let gb = |mib: u64| format!("{:.1} GB", mib as f64 / 1024.0);
            let title = match (c.id, c.status) {
                ("os", ssh::Status::Pass) => format!("{} is supported", f.os_pretty),
                ("memory", _) => format!("{} memory", f.mem_mib.map_or("Unknown".into(), gb)),
                ("cpus", _) => format!(
                    "{} vCPU",
                    f.cpus.map_or("Unknown".into(), |n| n.to_string())
                ),
                ("disk", _) => format!(
                    "{} free disk",
                    f.disk_free_gib
                        .map_or("Unknown".into(), |n| format!("{n} GB"))
                ),
                ("port", ssh::Status::Pass) => format!("Port {} is free for TCP and UDP", f.port),
                _ => format!("{}: {}", c.label, c.actual),
            };
            let detail = match c.status {
                ssh::Status::Pass => {
                    if c.id == "port" {
                        "Change it later under Resources, Advanced".to_owned()
                    } else if c.required.is_empty() {
                        String::new()
                    } else {
                        format!("{} needed", c.required)
                    }
                }
                ssh::Status::Fail => format!(
                    "Missing: this server has {}, the minimum is {}",
                    c.actual, c.required
                ),
                ssh::Status::Unknown => "Could not be checked".to_owned(),
            };
            CheckRow {
                key: c.id.to_owned(),
                title,
                detail,
                status,
            }
        })
        .collect();
    Preflight {
        connected_as: format!("Connected over SSH as {user}"),
        rows,
        cpus: f.cpus.unwrap_or(1) as u32,
        memory_mib: f.mem_mib.unwrap_or(0),
        disk_free_gib: f.disk_free_gib.unwrap_or(0),
    }
}

fn ssh_options(o: &InstallOptions) -> ssh::InstallOptions {
    ssh::InstallOptions {
        distro: Some(o.distro.clone()),
        desktop: Some(o.desktop.clone()),
        user: Some(o.username.clone()),
        apps: Some(o.apps.clone()),
        docker: o.docker,
        backup: Some(o.backup.clone()),
        cpu: Some(o.cpu),
        memory: Some(format!("{}G", o.memory_gb)),
        disk: Some(o.disk_gb),
        port: Some(o.port),
        domain: (!o.domain.is_empty()).then(|| o.domain.clone()),
        ..Default::default()
    }
}

/// One engine event as zero or more app events.
pub fn convert(e: ssh::InstallEvent) -> Vec<InstallEvent> {
    use ssh::InstallEvent as E;
    match e {
        E::Phase(p) => vec![InstallEvent::Log(
            match p {
                ssh::Phase::SudoCheck => "checking sudo",
                ssh::Phase::Upload => "uploading the installer",
                ssh::Phase::Run => "running the installer",
                ssh::Phase::Cleanup => "removing the uploaded installer",
            }
            .to_owned(),
        )],
        E::Stage { id, state, ms, .. } => {
            let st = match state {
                ssh::StageState::Start => Some(StageState::Start),
                ssh::StageState::Done => Some(StageState::Done),
                ssh::StageState::Skip => Some(StageState::Skipped),
                ssh::StageState::Deferred => Some(StageState::Deferred),
                _ => None,
            };
            match st {
                Some(state) => vec![InstallEvent::Stage { id, state, ms }],
                None => vec![InstallEvent::Log(format!("stage {id}: {state:?}"))],
            }
        }
        E::Step {
            id,
            index,
            total,
            step,
            percent,
            ..
        } => {
            vec![InstallEvent::Step {
                stage: id,
                index,
                total,
                text: step,
                percent,
            }]
        }
        E::Warn { message, .. } => vec![InstallEvent::Warn(message)],
        E::Log { text, .. } => vec![InstallEvent::Log(text)],
    }
}

/// The final result as the events that end the run.
pub fn finished(r: &ssh::InstallResult, elapsed_secs: u64) -> Vec<InstallEvent> {
    let mut v = Vec::new();
    let image = match &r.desktop {
        Some(d) => {
            v.push(InstallEvent::ImagePath {
                prebuilt: d.path_taken == "PREBUILT",
                reason: d.reason.clone(),
            });
            if d.path_taken == "PREBUILT" {
                "Prebuilt image"
            } else {
                "Built on the server"
            }
        }
        None => "",
    };
    for w in &r.warnings {
        v.push(InstallEvent::Warn(w.clone()));
    }
    v.push(InstallEvent::Finished(InstallOutcome {
        server_key_hex: r.server_public_key.clone(),
        addresses: r.addresses.clone(),
        port: r.port,
        agent_version: r.agent_version.clone(),
        image_path: image.to_owned(),
        elapsed_secs,
    }));
    v
}

/// The error that ended a run as the events the screen understands.
pub fn failed(e: &ssh::SshSetupError) -> InstallEvent {
    use ssh::SshSetupError as E;
    match e {
        E::ConnectionLost { last_stage } => InstallEvent::ConnectionLost {
            stage: last_stage.clone().unwrap_or_else(|| "unknown".into()),
        },
        E::InstallerFailed(f) => InstallEvent::Failed(InstallFailure {
            stage: f.stage.clone(),
            code: f.code.clone(),
            message: f.message.clone(),
            retryable: f.retryable,
        }),
        other => InstallEvent::Failed(InstallFailure {
            stage: "preflight".into(),
            code: format!("{:?}", other.kind()).to_ascii_uppercase(),
            message: other.to_string(),
            retryable: other.is_retryable(),
        }),
    }
}

struct SshRun {
    rx: mpsc::Receiver<InstallEvent>,
    task: tokio::task::JoinHandle<()>,
}

impl InstallRun for SshRun {
    fn next_event(&mut self) -> BoxFuture<'_, Option<InstallEvent>> {
        Box::pin(self.rx.recv())
    }
    fn cancel(&mut self) {
        // Dropping the connection ends the installer safely; the next run resumes.
        self.task.abort();
    }
}

impl InstallEngine for SshInstallEngine {
    fn probe_host_key(&self, t: &SshTarget) -> BoxFuture<'_, Result<HostKey, EngineError>> {
        let target = ssh::SshTarget::new(t.host.clone(), t.port);
        Box::pin(async move {
            let k = ssh::probe_host_key(&target, &self.opts)
                .await
                .map_err(|e| engine_error(&e))?;
            Ok(HostKey {
                algorithm: algo_label(&k.algorithm),
                fingerprint: k.fingerprint,
            })
        })
    }

    fn preflight(
        &self,
        t: &SshTarget,
        auth: &SshAuth,
        trusted: &HostKey,
    ) -> BoxFuture<'_, Result<Preflight, EngineError>> {
        let target = ssh::SshTarget::new(t.host.clone(), t.port);
        let creds = credentials(auth);
        let fp = trusted.fingerprint.clone();
        let user = auth.user().to_owned();
        Box::pin(async move {
            let creds = creds?;
            let conn = ssh::Connection::connect(&target, &fp, &creds, &self.opts)
                .await
                .map_err(|e| engine_error(&e))?;
            let report = ssh::preflight(&conn, DEFAULT_PORT).await;
            conn.disconnect().await;
            Ok(preflight_view(
                &user,
                &report.map_err(|e| engine_error(&e))?,
            ))
        })
    }

    fn install(
        &self,
        req: InstallRequest,
    ) -> BoxFuture<'_, Result<Box<dyn InstallRun>, EngineError>> {
        Box::pin(async move {
            let target = ssh::SshTarget::new(req.target.host.clone(), req.target.port);
            let creds = credentials(&req.auth)?;
            let conn =
                ssh::Connection::connect(&target, &req.host_key.fingerprint, &creds, &self.opts)
                    .await
                    .map_err(|e| engine_error(&e))?;
            let sudo_pw = match &req.auth {
                SshAuth::Password { password, .. } => {
                    Some(Zeroizing::new(password.expose().to_owned()))
                }
                _ => None,
            };
            let mut secrets = ssh::Secrets::new(
                Zeroizing::new(req.password.expose().to_owned()),
                Zeroizing::new(req.pin.expose().to_owned()),
            )
            .and_then(|s| {
                s.with_pairing_token(Zeroizing::new(req.pairing_token.expose().to_owned()))
            })
            .map_err(|e| engine_error(&e))?;
            if let Some(p) = sudo_pw {
                secrets = secrets
                    .with_sudo_password(p)
                    .map_err(|e| engine_error(&e))?;
            }
            let script = ssh::InstallScript::Bytes(
                self.script.clone().unwrap_or_else(|| INSTALL_SH.to_vec()),
            );
            let request = ssh::InstallRequest::new(script, ssh_options(&req.options));
            let (out_tx, rx) = mpsc::channel::<InstallEvent>(256);
            let task = tokio::spawn(async move {
                let (ev_tx, mut ev_rx) = mpsc::channel::<ssh::InstallEvent>(256);
                let started = std::time::Instant::now();
                let run = async { ssh::install(&conn, &request, &secrets, &ev_tx).await };
                tokio::pin!(run);
                let result = loop {
                    tokio::select! {
                        Some(e) = ev_rx.recv() => {
                            for a in convert(e) {
                                let _ = out_tx.send(a).await;
                            }
                        }
                        r = &mut run => break r,
                    }
                };
                while let Ok(e) = ev_rx.try_recv() {
                    for a in convert(e) {
                        let _ = out_tx.send(a).await;
                    }
                }
                let last = match result {
                    Ok(r) => finished(&r, started.elapsed().as_secs()),
                    Err(e) => vec![failed(&e)],
                };
                for a in last {
                    let _ = out_tx.send(a).await;
                }
                conn.disconnect().await;
            });
            Ok(Box::new(SshRun { rx, task }) as Box<dyn InstallRun>)
        })
    }

    fn uninstall(&self, req: UninstallRequest) -> BoxFuture<'_, Result<(), EngineError>> {
        Box::pin(async move {
            let target = ssh::SshTarget::new(req.target.host.clone(), req.target.port);
            let creds = credentials(&req.auth)?;
            let conn =
                ssh::Connection::connect(&target, &req.host_key.fingerprint, &creds, &self.opts)
                    .await
                    .map_err(|e| engine_error(&e))?;
            let flag = if req.keep_desktop {
                "--keep-desktop"
            } else {
                "--destroy-desktop"
            };
            // The installer places the CLI only here; sudo may not have it on its PATH.
            let agent = "/usr/lib/hx/current/hx-agent";
            let (cmd, stdin) = match &req.auth {
                SshAuth::Password { password, user } if user != "root" => (
                    format!("sudo -S -k -p '' {agent} uninstall {flag} --yes"),
                    Some(Zeroizing::new(
                        format!("{}\n", password.expose()).into_bytes(),
                    )),
                ),
                SshAuth::Password { .. }
                | SshAuth::KeyFile { .. }
                | SshAuth::DefaultKeys { .. } => (
                    format!(
                        "if [ \"$(id -u)\" = 0 ]; then {agent} uninstall {flag} --yes; else sudo -n {agent} uninstall {flag} --yes; fi"
                    ),
                    None,
                ),
            };
            let out = conn
                .exec(
                    &cmd,
                    stdin.as_deref().map(|v| v.as_slice()),
                    Duration::from_secs(600),
                )
                .await
                .map_err(|e| engine_error(&e));
            conn.disconnect().await;
            let out = out?;
            if out.success() {
                Ok(())
            } else {
                let e = out.stderr_text();
                let last = e
                    .lines()
                    .rev()
                    .find(|l| !l.trim().is_empty())
                    .unwrap_or("the uninstall failed");
                Err(EngineError::Other(crate::session::connect::sanitize(last)))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(bad: bool) -> ssh::PreflightReport {
        let facts = ssh::ServerFacts {
            os_id: "ubuntu".into(),
            os_version: "24.04".into(),
            os_pretty: "Ubuntu 24.04.2 LTS".into(),
            arch: "x86_64".into(),
            systemd: true,
            systemd_version: Some(255),
            container: None,
            mem_mib: Some(if bad { 1946 } else { 7987 }),
            cpus: Some(4),
            disk_free_gib: Some(if bad { 18 } else { 152 }),
            port_in_use: Some(false),
            port: 443,
            sudo: Some(ssh::SudoMode::Root),
        };
        ssh::preflight::evaluate(&facts)
    }

    #[test]
    fn requirement_rows_read_like_the_mockup() {
        let p = preflight_view("root", &report(false));
        assert!(p.ok());
        let titles: Vec<&str> = p.rows.iter().map(|r| r.title.as_str()).collect();
        assert!(
            titles.contains(&"Ubuntu 24.04.2 LTS is supported"),
            "{titles:?}"
        );
        assert!(
            titles.iter().any(|t| t.starts_with("7.8 GB memory")),
            "{titles:?}"
        );
        assert!(titles.contains(&"152 GB free disk"));
        assert_eq!(p.cpus, 4);
        let bad = preflight_view("root", &report(true));
        assert!(!bad.ok());
        let mem = bad.rows.iter().find(|r| r.key == "memory").unwrap();
        assert!(mem.detail.starts_with("Missing: this server has"));
    }

    #[test]
    fn installer_events_map_to_app_events() {
        let e = convert(ssh::InstallEvent::Stage {
            id: "incus".into(),
            n: Some(3),
            of: Some(19),
            state: ssh::StageState::Skip,
            ms: None,
        });
        assert_eq!(
            e,
            vec![InstallEvent::Stage {
                id: "incus".into(),
                state: StageState::Skipped,
                ms: None
            }]
        );
        let e = convert(ssh::InstallEvent::Step {
            id: "desktop".into(),
            privd_stage: "BUILD".into(),
            index: 5,
            total: 12,
            step: "x".into(),
            percent: None,
        });
        assert!(matches!(
            &e[0],
            InstallEvent::Step {
                percent: None,
                index: 5,
                ..
            }
        ));
    }

    #[test]
    fn errors_map_to_run_ends() {
        let lost = failed(&ssh::SshSetupError::ConnectionLost {
            last_stage: Some("desktop".into()),
        });
        assert_eq!(
            lost,
            InstallEvent::ConnectionLost {
                stage: "desktop".into()
            }
        );
        let f = failed(&ssh::SshSetupError::InstallerFailed(
            ssh::InstallerFailure {
                stage: "incus".into(),
                code: "UNAVAILABLE".into(),
                message: "no".into(),
                retryable: true,
                exit: 1,
            },
        ));
        assert!(matches!(
            f,
            InstallEvent::Failed(InstallFailure {
                retryable: true,
                ..
            })
        ));
        assert_eq!(
            engine_error(&ssh::SshSetupError::AuthFailed),
            EngineError::AuthFailed
        );
    }

    #[test]
    fn app_groups_agree_with_the_engine() {
        for g in GROUPS.iter() {
            for id in g.stages {
                assert_eq!(group_of(id), ssh::group_of(id), "{id}");
            }
        }
        for (i, (title, _)) in ssh::GROUPS.iter().enumerate() {
            assert_eq!(GROUPS[i].title, *title);
        }
    }

    #[test]
    fn the_installer_is_bundled() {
        assert!(INSTALL_SH.starts_with(b"#!"));
    }
}
