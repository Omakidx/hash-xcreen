//! Working fakes for every trait of [`super`]: the app runs end to end with them (`--demo`).
//!
//! Hints in the address or credentials pick a scenario, so every state of the mockups can be
//! reached: a host containing `small` fails the requirement checks, `down` is unreachable,
//! `fail` stops the install at `incus` the first time (Retry then succeeds), `lost` loses the SSH
//! connection the first time; the SSH password `wrong` is refused; the one-liner token is
//! accepted after the third poll; the PIN used for [`DemoServerControl`] is `123456`.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering::SeqCst};
use std::time::Duration;

use hx_crypto::IdentityKey;

use super::*;

/// Fake keys: the demo server's pinned identity.
pub const DEMO_SERVER_KEY: &str =
    "3f9ac1d477be0a52b81e05f7d3906c2a3f9ac1d477be0a52b81e05f7d3906c2a";

/// Delay per scripted event.
#[derive(Clone, Copy, Debug)]
pub struct Pace(pub Duration);

impl Pace {
    /// A pace for people to watch.
    pub fn slow() -> Self {
        Self(Duration::from_millis(350))
    }
    /// No delay (tests).
    pub fn instant() -> Self {
        Self(Duration::ZERO)
    }
}

/// The fakes together.
pub fn backends(pace: Pace) -> Backends {
    Backends {
        install: Arc::new(DemoInstall::new(pace)),
        setup: Arc::new(DemoSetup::new(pace)),
        admin: Arc::new(DemoAdmin::default()),
        control: Arc::new(DemoServerControl),
        connector: Arc::new(crate::backend::demo_desk::DemoConnector::new()),
    }
}

struct Script {
    events: VecDeque<InstallEvent>,
    pace: Pace,
    cancelled: bool,
}

impl InstallRun for Script {
    fn next_event(&mut self) -> BoxFuture<'_, Option<InstallEvent>> {
        Box::pin(async move {
            if self.cancelled {
                return None;
            }
            if !self.pace.0.is_zero() {
                tokio::time::sleep(self.pace.0).await;
            }
            self.events.pop_front()
        })
    }
    fn cancel(&mut self) {
        self.cancelled = true;
    }
}

fn stage(id: &str, state: StageState, ms: Option<u64>) -> InstallEvent {
    InstallEvent::Stage {
        id: id.into(),
        state,
        ms,
    }
}

/// The scripted event list of one install, with the scenario chosen by `scenario`.
pub fn install_script(scenario: Scenario, port: u16) -> VecDeque<InstallEvent> {
    let mut v = VecDeque::new();
    let done = |v: &mut VecDeque<InstallEvent>, id: &str, ms: u64| {
        v.push_back(stage(id, StageState::Start, None));
        v.push_back(stage(id, StageState::Done, Some(ms)));
    };
    done(&mut v, "preflight", 1200);
    v.push_back(InstallEvent::Log(
        "stage preflight .......... done (1.2 s)".into(),
    ));
    done(&mut v, "packages", 38_000);
    v.push_back(stage("incus", StageState::Start, None));
    if scenario == Scenario::FailAtIncus {
        v.push_back(InstallEvent::Warn("retrying package index (1 of 3)".into()));
        v.push_back(InstallEvent::Failed(InstallFailure {
            stage: "incus".into(),
            code: "UNAVAILABLE".into(),
            message: "The package source could not be reached".into(),
            retryable: true,
        }));
        return v;
    }
    v.push_back(stage("incus", StageState::Done, Some(64_000)));
    for (id, ms) in [
        ("release", 2000),
        ("system-files", 1000),
        ("credentials", 1500),
        ("config", 800),
        ("units", 3700),
    ] {
        done(&mut v, id, ms);
    }
    for (id, ms) in [
        ("setup-window", 400),
        ("host", 18_000),
        ("firewall-port", 3600),
    ] {
        done(&mut v, id, ms);
    }
    v.push_back(InstallEvent::ImagePath {
        prebuilt: false,
        reason: "release host unreachable".into(),
    });
    v.push_back(stage("desktop", StageState::Start, None));
    let steps = [
        "Creating the container",
        "Installing base system",
        "Installing XFCE",
        "Installing browser and tools",
        "Installing apps (developer preset)",
        "Setting up the desktop session",
    ];
    for (i, text) in steps.iter().enumerate() {
        v.push_back(InstallEvent::Step {
            stage: "desktop".into(),
            index: i as u32 + 1,
            total: steps.len() as u32,
            text: (*text).into(),
            percent: if i == 3 {
                None
            } else {
                Some(((i as u32 + 1) * 100 / steps.len() as u32) as u8)
            },
        });
        if scenario == Scenario::LoseConnection && i == 2 {
            v.push_back(InstallEvent::ConnectionLost {
                stage: "desktop".into(),
            });
            return v;
        }
    }
    v.push_back(stage("desktop", StageState::Done, Some(238_000)));
    done(&mut v, "verifiers", 3000);
    v.push_back(stage("owner-key", StageState::Skipped, None));
    v.push_back(stage("backup", StageState::Deferred, None));
    done(&mut v, "pairing", 1000);
    done(&mut v, "finish", 2000);
    v.push_back(stage("done", StageState::Done, None));
    v.push_back(InstallEvent::Finished(InstallOutcome {
        server_key_hex: DEMO_SERVER_KEY.into(),
        addresses: vec!["203.0.113.88".into()],
        port,
        agent_version: "0.1.0".into(),
        image_path: "Built on the server".into(),
        elapsed_secs: 374,
    }));
    v
}

/// Which story a fake install tells.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scenario {
    /// Everything works.
    Success,
    /// Fails at `incus` (retryable).
    FailAtIncus,
    /// The SSH connection drops during the desktop build.
    LoseConnection,
}

/// Fake SSH install engine.
pub struct DemoInstall {
    pace: Pace,
    runs: AtomicU32,
}

impl DemoInstall {
    /// New engine.
    pub fn new(pace: Pace) -> Self {
        Self {
            pace,
            runs: AtomicU32::new(0),
        }
    }
}

fn fake_host_key() -> HostKey {
    HostKey {
        algorithm: "ED25519".into(),
        fingerprint: "SHA256:5Gk2xQ0m8vT1uZpJc3W9nLr7aYbHd4eFsIo6KtN2VhE".into(),
    }
}

impl InstallEngine for DemoInstall {
    fn probe_host_key(&self, t: &SshTarget) -> BoxFuture<'_, Result<HostKey, EngineError>> {
        let down = t.host.contains("down");
        let host = t.host.clone();
        Box::pin(async move {
            if down {
                return Err(EngineError::Unreachable(format!("no answer from {host}")));
            }
            Ok(fake_host_key())
        })
    }

    fn preflight(
        &self,
        t: &SshTarget,
        auth: &SshAuth,
        trusted: &HostKey,
    ) -> BoxFuture<'_, Result<Preflight, EngineError>> {
        let small = t.host.contains("small");
        let wrong =
            matches!(auth, SshAuth::Password { password, .. } if password.expose() == "wrong");
        let user = auth.user().to_owned();
        let changed = trusted.fingerprint != fake_host_key().fingerprint;
        Box::pin(async move {
            if changed {
                return Err(EngineError::HostKeyChanged {
                    expected: trusted_fp(),
                    actual: "SHA256:changed".into(),
                });
            }
            if wrong {
                return Err(EngineError::AuthFailed);
            }
            let row = |key: &str, title: &str, detail: &str, status| CheckRow {
                key: key.into(),
                title: title.into(),
                detail: detail.into(),
                status,
            };
            use CheckStatus::{Fail, Pass};
            let rows = if small {
                vec![
                    row("os", "Debian 12 (x86_64) is supported", "", Pass),
                    row("cpus", "2 vCPU", "At least 2 needed", Pass),
                    row(
                        "memory",
                        "1.9 GB memory",
                        "Missing: this server has 1.9 GB, the minimum is 4 GB",
                        Fail,
                    ),
                    row(
                        "disk",
                        "18 GB free disk",
                        "Missing: 12 GB more free space; the minimum is 30 GB",
                        Fail,
                    ),
                    row("port", "Port 443 is free for TCP and UDP", "", Pass),
                ]
            } else {
                vec![
                    row("os", "Ubuntu 24.04.2 LTS (x86_64) is supported", "", Pass),
                    row("cpus", "4 vCPU", "At least 2 needed", Pass),
                    row("memory", "7.8 GB memory", "At least 4 GB needed", Pass),
                    row("disk", "152 GB free disk", "At least 30 GB needed", Pass),
                    row(
                        "port",
                        "Port 443 is free for TCP and UDP",
                        "Change it later under Resources, Advanced",
                        Pass,
                    ),
                ]
            };
            Ok(Preflight {
                connected_as: format!("Connected over SSH as {user}"),
                rows,
                cpus: if small { 2 } else { 4 },
                memory_mib: if small { 1946 } else { 7987 },
                disk_free_gib: if small { 18 } else { 152 },
            })
        })
    }

    fn install(
        &self,
        req: InstallRequest,
    ) -> BoxFuture<'_, Result<Box<dyn InstallRun>, EngineError>> {
        let n = self.runs.fetch_add(1, SeqCst);
        let host = req.target.host.clone();
        let port = req.options.port;
        let pace = self.pace;
        Box::pin(async move {
            let scenario = if host.contains("fail") && n == 0 {
                Scenario::FailAtIncus
            } else if host.contains("lost") && n == 0 {
                Scenario::LoseConnection
            } else {
                Scenario::Success
            };
            Ok(Box::new(Script {
                events: install_script(scenario, port),
                pace,
                cancelled: false,
            }) as Box<dyn InstallRun>)
        })
    }

    fn uninstall(&self, _req: UninstallRequest) -> BoxFuture<'_, Result<(), EngineError>> {
        let pace = self.pace.0;
        Box::pin(async move {
            tokio::time::sleep(pace * 4).await;
            Ok(())
        })
    }
}

fn trusted_fp() -> String {
    fake_host_key().fingerprint
}

/// Fake one-liner client.
pub struct DemoSetup {
    pace: Pace,
    polls: AtomicU32,
}

impl DemoSetup {
    /// New fake.
    pub fn new(pace: Pace) -> Self {
        Self {
            pace,
            polls: AtomicU32::new(0),
        }
    }
}

impl SetupClient for DemoSetup {
    fn pair(
        &self,
        addr: &ServerAddr,
        _device: Arc<IdentityKey>,
        token: &Secret,
    ) -> BoxFuture<'_, Result<PairedInfo, SetupError>> {
        let n = self.polls.fetch_add(1, SeqCst);
        let host = addr.host.clone();
        let expired = token.expose().contains("expired");
        let pace = self.pace.0;
        Box::pin(async move {
            tokio::time::sleep(pace * 2).await;
            if host.contains("down") {
                return Err(SetupError::Unreachable);
            }
            if n < 2 {
                return Err(SetupError::Unreachable);
            }
            if expired {
                return Err(SetupError::PairingFailed);
            }
            Ok(PairedInfo {
                server_key_hex: DEMO_SERVER_KEY.into(),
                server_name: "demo".into(),
                server_version: Some(if host.contains("old") { (1, 2) } else { (1, 3) }),
            })
        })
    }

    fn start_setup(
        &self,
        addr: &ServerAddr,
        _device: Arc<IdentityKey>,
        _paired: &PairedInfo,
        req: SetupRequest,
    ) -> BoxFuture<'_, Result<Box<dyn InstallRun>, SetupError>> {
        let port = addr.port;
        let pace = self.pace;
        let _ = req;
        let old = _paired.server_version.is_some_and(|v| v < (1, 3));
        Box::pin(async move {
            if old {
                return Err(SetupError::UpdateRequired);
            }
            let mut events = install_script(Scenario::Success, port);
            // The agent is already installed on this path: the first stages are not run by the app.
            let done_before = [
                "preflight",
                "packages",
                "incus",
                "release",
                "system-files",
                "credentials",
                "config",
                "units",
                "setup-window",
                "host",
                "firewall-port",
            ];
            events.retain(|e| !matches!(e, InstallEvent::Stage { id, .. } if done_before.contains(&id.as_str())));
            for id in done_before.iter().rev() {
                events.push_front(InstallEvent::Stage {
                    id: (*id).into(),
                    state: StageState::Skipped,
                    ms: None,
                });
            }
            Ok(Box::new(Script {
                events,
                pace,
                cancelled: false,
            }) as Box<dyn InstallRun>)
        })
    }
}

/// Fake pairing codes and reinstate.
#[derive(Default)]
pub struct DemoAdmin {
    codes: AtomicU32,
}

impl DeviceAdmin for DemoAdmin {
    fn create_pairing_code(
        &self,
        _ctx: &AdminContext,
    ) -> BoxFuture<'_, Result<IssuedCode, AdminError>> {
        let n = self.codes.fetch_add(1, SeqCst);
        Box::pin(async move {
            let codes = ["K7QM-4XD2", "R3TN-8WPV", "H9ZC-2LBA"];
            Ok(IssuedCode {
                code: codes[n as usize % codes.len()].into(),
                expires_in_secs: 15 * 60,
                tries: 3,
            })
        })
    }

    fn reinstate(
        &self,
        _ctx: &AdminContext,
        password: &Secret,
    ) -> BoxFuture<'_, Result<(), AdminError>> {
        let ok = password.expose() == "demo-password";
        Box::pin(async move {
            if ok {
                Ok(())
            } else {
                Err(AdminError::Incorrect {
                    attempts_left: Some(4),
                })
            }
        })
    }
}

/// Fake server management with an in-memory state.
#[derive(Default)]
pub struct DemoServerControl;

impl ServerControl for DemoServerControl {
    fn overview(&self, ctx: &AdminContext) -> BoxFuture<'_, Result<Overview, AdminError>> {
        let down = ctx.host.contains("down");
        let sick = ctx.host.contains("sick");
        let update = ctx.host.contains("update");
        Box::pin(async move {
            if down {
                return Err(AdminError::Unreachable);
            }
            Ok(Overview {
                desktop: if sick {
                    DesktopStatus::NotAnswering
                } else {
                    DesktopStatus::Running
                },
                agent_uptime_secs: 12 * 86_400 + 4 * 3600,
                session_active: false,
                setup: "Ubuntu 24.04 · XFCE · Developer · Docker on".into(),
                agent_version: "0.1.0".into(),
                privd_version: "0.1.0".into(),
                channel: "stable".into(),
                update_available: update.then(|| "0.1.1".into()),
                rolled_back: None,
                protocol: "1.3".into(),
                limits: Some(Limits {
                    cpu: 3,
                    memory_gb: 5,
                    disk_gb: 60,
                }),
                host_os: "Ubuntu 24.04.2 LTS, 4 vCPU, 7.8 GB".into(),
                host_cpus: 4,
                host_mem_gb: 5,
                host_disk_gb: 152,
                docker: true,
                attention: if sick {
                    vec!["The desktop is not answering".into()]
                } else {
                    vec![]
                },
            })
        })
    }

    fn change_pin(
        &self,
        _c: &AdminContext,
        current: &Secret,
        _new: &Secret,
    ) -> BoxFuture<'_, Result<(), AdminError>> {
        let ok = current.expose() == "123456";
        Box::pin(async move {
            if ok {
                Ok(())
            } else {
                Err(AdminError::Incorrect {
                    attempts_left: Some(4),
                })
            }
        })
    }

    fn change_password(
        &self,
        _c: &AdminContext,
        current: &Secret,
        _new: &Secret,
    ) -> BoxFuture<'_, Result<(), AdminError>> {
        let ok = current.expose() == "demo-password";
        Box::pin(async move {
            if ok {
                Ok(())
            } else {
                Err(AdminError::Incorrect {
                    attempts_left: None,
                })
            }
        })
    }

    fn restart_desktop(&self, _c: &AdminContext) -> BoxFuture<'_, Result<(), AdminError>> {
        Box::pin(async { Ok(()) })
    }

    fn set_docker(&self, _c: &AdminContext, _on: bool) -> BoxFuture<'_, Result<(), AdminError>> {
        Box::pin(async { Ok(()) })
    }

    fn set_limits(&self, _c: &AdminContext, _l: Limits) -> BoxFuture<'_, Result<(), AdminError>> {
        Box::pin(async { Ok(()) })
    }

    fn update_agent(&self, _c: &AdminContext) -> BoxFuture<'_, Result<String, AdminError>> {
        Box::pin(async { Ok("0.1.1".into()) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_script_ends_with_a_result_and_touches_every_group() {
        let s = install_script(Scenario::Success, 443);
        assert!(matches!(s.back(), Some(InstallEvent::Finished(_))));
        for (i, g) in GROUPS.iter().enumerate() {
            let touched = s
                .iter()
                .any(|e| matches!(e, InstallEvent::Stage { id, .. } if group_of(id) == Some(i)));
            assert!(touched, "group {} ({}) never appears", i, g.title);
        }
    }

    #[test]
    fn failure_script_stops_at_incus() {
        let s = install_script(Scenario::FailAtIncus, 443);
        assert!(
            matches!(s.back(), Some(InstallEvent::Failed(f)) if f.stage == "incus" && f.retryable)
        );
    }

    #[test]
    fn every_stage_id_has_a_group() {
        for e in install_script(Scenario::Success, 443) {
            if let InstallEvent::Stage { id, .. } = e {
                assert!(group_of(&id).is_some(), "{id}");
            }
        }
    }
}
