//! The real post-pairing setup (protocol 1.3, `hx_crypto::setup`): the one-liner path after
//! pairing. Connects with the pinned key, sets the PIN (or proves it), starts the desktop job
//! with the options and the account password, follows the pushes and finishes. The pushes are
//! mapped onto the same [`InstallEvent`]s as the SSH install, so one progress screen serves both.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use hx_crypto::setup::{Password, SetupAuth, SetupConnectOptions, SetupEvent, SetupSession};
use hx_crypto::{IdentityKey, Pin, PinReply};
use hx_proto::pb;
use hx_proto::version::ProtocolVersion;

use super::*;

/// The stage ids the one-liner installer already did before the app connects.
const DONE_BY_INSTALLER: [&str; 13] = [
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
    "pairing-token",
    "pairing",
];

/// The progress row a setup stage belongs to.
pub fn stage_id(s: pb::SetupStage) -> &'static str {
    use pb::SetupStage as S;
    match s {
        S::Verifiers => "verifiers",
        S::Finish => "finish",
        S::Done => "done",
        _ => "desktop",
    }
}

/// `SETUP_ERROR_CODE_UNAVAILABLE` to `UNAVAILABLE`.
fn code_name(c: pb::SetupErrorCode) -> String {
    c.as_str_name()
        .trim_start_matches("SETUP_ERROR_CODE_")
        .to_owned()
}

/// What an ack that is not OK tells the user.
pub fn ack_problem(a: &pb::SetupAck) -> Option<String> {
    use pb::SetupAckStatus as S;
    let wait = if a.retry_after_ms > 0 {
        format!(" Try again in {} s.", a.retry_after_ms.div_ceil(1000))
    } else {
        String::new()
    };
    let m = match a.status() {
        S::Ok => return None,
        S::InvalidArgument => format!(
            "The server did not accept the value for {}.",
            if a.field.is_empty() {
                "one field"
            } else {
                &a.field
            }
        ),
        S::PinRequired => "The server needs the PIN first.".to_owned(),
        S::PinAlreadySet => return None,
        S::Busy => "The server is already creating a desktop.".to_owned(),
        S::NotRunning => "No desktop job is running.".to_owned(),
        S::AlreadyFinished => "Setup was already finished on this server.".to_owned(),
        S::WindowTooShort => {
            "The setup window on the server is about to close. Open a new one with the installer."
                .to_owned()
        }
        S::RateLimited => format!("Too many setup attempts.{wait}"),
        S::Locked => format!("Setup is locked for now.{wait}"),
        S::Unavailable => format!("The server cannot do this right now.{wait}"),
        S::DesktopNotReady => "The desktop is not ready yet.".to_owned(),
        S::Failed | S::Unspecified => "The server could not do that.".to_owned(),
    };
    Some(crate::session::connect::sanitize(&m))
}

fn setup_error(e: hx_crypto::Error) -> SetupError {
    use hx_crypto::Error as E;
    match e {
        E::UpdateRequired => SetupError::UpdateRequired,
        E::SetupClosed => SetupError::Closed,
        E::Transport(_) | E::Timeout(_) => SetupError::Unreachable,
        E::Revoked => SetupError::Other("This device was removed from the server.".into()),
        E::PinNotAvailable => SetupError::Other(
            "The server cannot check PINs right now. Try again in about a minute.".into(),
        ),
        other => SetupError::Other(crate::session::connect::sanitize(&other.to_string())),
    }
}

/// The wire options from the wizard's choices.
pub fn setup_options(o: &InstallOptions) -> pb::SetupOptions {
    use pb::{SetupDistro as D, SetupPreset as P};
    pb::SetupOptions {
        distro: match o.distro.as_str() {
            "ubuntu-24.04" => D::Ubuntu2404,
            "ubuntu-26.04" => D::Ubuntu2604,
            "debian-12" => D::Debian12,
            "debian-13" => D::Debian13,
            _ => D::Unspecified,
        } as i32,
        desktop: pb::SetupDesktop::Xfce as i32,
        preset: if o.apps == "developer" {
            P::Developer
        } else {
            P::Basic
        } as i32,
        username: o.username.clone(),
        image_mode: pb::SetupImageMode::Auto as i32,
        limits: Some(pb::SetupLimits {
            cpu: o.cpu,
            memory_mib: u64::from(o.memory_gb) * 1024,
            disk_gib: u64::from(o.disk_gb),
        }),
        docker: o.docker,
        docker_isolation_acknowledged: o.docker,
        settings: None,
    }
}

/// The events of a setup run.
pub struct SetupRun {
    session: Option<SetupSession>,
    queue: VecDeque<InstallEvent>,
    current: Option<&'static str>,
    server_key_hex: String,
    port: u16,
    started: Instant,
    succeeded: bool,
    done: bool,
}

impl SetupRun {
    fn new(session: SetupSession, server_key_hex: String, port: u16) -> Self {
        let mut queue = VecDeque::new();
        for id in DONE_BY_INSTALLER {
            queue.push_back(InstallEvent::Stage {
                id: id.into(),
                state: StageState::Skipped,
                ms: None,
            });
        }
        Self {
            session: Some(session),
            queue,
            current: None,
            server_key_hex,
            port,
            started: Instant::now(),
            succeeded: false,
            done: false,
        }
    }

    fn progress(&mut self, p: &pb::SetupProgress) {
        let id = stage_id(p.stage());
        if self.current != Some(id) {
            if let Some(prev) = self.current {
                self.queue.push_back(InstallEvent::Stage {
                    id: prev.into(),
                    state: StageState::Done,
                    ms: None,
                });
            }
            self.queue.push_back(InstallEvent::Stage {
                id: id.into(),
                state: StageState::Start,
                ms: None,
            });
            self.current = Some(id);
        }
        if p.total > 0 || !p.step.is_empty() {
            self.queue.push_back(InstallEvent::Step {
                stage: id.into(),
                index: p.index,
                total: p.total,
                text: p.step.clone(),
                percent: (p.percent <= 100).then_some(p.percent as u8),
            });
        }
    }

    /// The events that end a run for a result (the caller finishes the session afterwards).
    pub fn result_events(&mut self, r: &pb::SetupResult) {
        use pb::SetupJobState as J;
        match r.status() {
            J::Succeeded => {
                self.succeeded = true;
                if let Some(c) = self.current.take() {
                    self.queue.push_back(InstallEvent::Stage {
                        id: c.into(),
                        state: StageState::Done,
                        ms: None,
                    });
                }
                for id in ["verifiers", "finish", "done"] {
                    self.queue.push_back(InstallEvent::Stage {
                        id: id.into(),
                        state: StageState::Done,
                        ms: None,
                    });
                }
                self.queue.push_back(InstallEvent::Stage {
                    id: "owner-key".into(),
                    state: StageState::Skipped,
                    ms: None,
                });
                self.queue.push_back(InstallEvent::Stage {
                    id: "backup".into(),
                    state: StageState::Deferred,
                    ms: None,
                });
                let path = r.path_taken();
                if path != pb::SetupPathTaken::Unspecified {
                    self.queue.push_back(InstallEvent::ImagePath {
                        prebuilt: path == pb::SetupPathTaken::Prebuilt,
                        reason: crate::session::connect::sanitize(&r.reason),
                    });
                }
                for w in &r.warnings {
                    self.queue
                        .push_back(InstallEvent::Warn(crate::session::connect::sanitize(w)));
                }
                self.queue.push_back(InstallEvent::Finished(InstallOutcome {
                    server_key_hex: self.server_key_hex.clone(),
                    addresses: Vec::new(),
                    port: self.port,
                    agent_version: String::new(),
                    image_path: match path {
                        pb::SetupPathTaken::Prebuilt => "Prebuilt image",
                        pb::SetupPathTaken::Build => "Built on the server",
                        pb::SetupPathTaken::Existing => "Adopted the existing desktop",
                        pb::SetupPathTaken::Unspecified => "",
                    }
                    .to_owned(),
                    elapsed_secs: self
                        .started
                        .elapsed()
                        .as_secs()
                        .max(u64::from(r.elapsed_ms / 1000)),
                }));
            }
            J::Failed | J::Cancelled => {
                let e = r.error.clone().unwrap_or_default();
                let stage = if e.stage() == pb::SetupStage::Unspecified {
                    self.current.unwrap_or("desktop")
                } else {
                    stage_id(e.stage())
                };
                self.queue.push_back(InstallEvent::Failed(InstallFailure {
                    stage: stage.into(),
                    code: code_name(e.code()),
                    message: crate::session::connect::sanitize(if e.message.is_empty() {
                        "The desktop could not be created"
                    } else {
                        &e.message
                    }),
                    retryable: e.retryable,
                }));
                self.done = true;
            }
            _ => {}
        }
    }
}

impl InstallRun for SetupRun {
    fn next_event(&mut self) -> BoxFuture<'_, Option<InstallEvent>> {
        Box::pin(async move {
            loop {
                if let Some(e) = self.queue.pop_front() {
                    if matches!(e, InstallEvent::Finished(_)) {
                        // The server finishes setup by itself after a successful job; ask
                        // anyway, and accept the close that follows `finished`.
                        if let Some(s) = self.session.as_mut() {
                            let _ = s.finish().await;
                        }
                        self.done = true;
                    }
                    return Some(e);
                }
                if self.done {
                    return None;
                }
                let s = self.session.as_mut()?;
                match s.next_event().await {
                    Ok(SetupEvent::State(_)) => {}
                    Ok(SetupEvent::Progress(p)) => self.progress(&p),
                    Ok(SetupEvent::Result(r)) => self.result_events(&r),
                    Ok(SetupEvent::Closed(_)) | Err(_) => {
                        self.done = true;
                        if !self.succeeded {
                            return Some(InstallEvent::ConnectionLost {
                                stage: self.current.unwrap_or("desktop").into(),
                            });
                        }
                    }
                }
            }
        })
    }

    fn cancel(&mut self) {
        // Dropping the session closes the connection; the job keeps its state on the server.
        self.session = None;
        self.done = true;
        self.queue.clear();
    }
}

/// The real [`SetupClient`]: pairing as before, the setup protocol of 1.3 for `start_setup`.
pub struct RealSetupClient {
    /// Name this device gives itself.
    pub device_name: String,
}

impl SetupClient for RealSetupClient {
    fn pair(
        &self,
        addr: &ServerAddr,
        device: Arc<IdentityKey>,
        token: &Secret,
    ) -> BoxFuture<'_, Result<PairedInfo, SetupError>> {
        let (host, port, cred) = (addr.host.clone(), addr.port, token.expose().to_owned());
        let name = self.device_name.clone();
        Box::pin(async move { crate::session::net::pair(&host, port, &device, &cred, &name).await })
    }

    fn start_setup(
        &self,
        addr: &ServerAddr,
        device: Arc<IdentityKey>,
        paired: &PairedInfo,
        req: SetupRequest,
    ) -> BoxFuture<'_, Result<Box<dyn InstallRun>, SetupError>> {
        let (host, port) = (addr.host.clone(), addr.port);
        let (key_hex, version) = (paired.server_key_hex.clone(), paired.server_version);
        let name = self.device_name.clone();
        Box::pin(async move {
            let key = crate::session::net::parse_key(&key_hex)
                .ok_or_else(|| SetupError::Other("The pinned server key is damaged.".into()))?;
            let target = crate::session::net::target(&host, port)
                .await
                .map_err(|_| SetupError::Unreachable)?;
            let opts = SetupConnectOptions {
                confirmed_server_version: version
                    .map(|(major, minor)| ProtocolVersion { major, minor }),
                device_name: name.chars().take(64).collect(),
                software: concat!("hx-desktop ", env!("CARGO_PKG_VERSION")).into(),
                ..Default::default()
            };
            let pin = Pin::new(req.pin.expose())
                .map_err(|_| SetupError::Other("A PIN is 6 or more digits.".into()))?;
            let pw = Password::new(req.password.expose()).map_err(|_| SetupError::Other("The account password is not acceptable to the server (1 to 511 bytes, no line breaks).".into()))?;
            let mut session = match hx_crypto::setup::connect_setup(&target, &device, key, &opts)
                .await
                .map_err(setup_error)?
            {
                SetupAuth::Ready(mut s) => {
                    let ack = s.set_pin(&pin).await.map_err(setup_error)?;
                    if let Some(p) = ack_problem(&ack) {
                        return Err(SetupError::Other(p));
                    }
                    s
                }
                SetupAuth::NeedsPin(mut a) => {
                    match a.submit_pin(&pin).await.map_err(setup_error)? {
                        PinReply::Accepted => a.into_session().map_err(setup_error)?,
                        PinReply::Wrong { attempts_left, .. } => {
                            return Err(SetupError::Other(format!(
                                "The server already has a PIN and this is not it ({attempts_left} attempts left)."
                            )));
                        }
                        PinReply::Backoff { retry_after } => {
                            return Err(SetupError::Other(format!(
                                "Wait {} s before trying again.",
                                retry_after.as_secs().max(1)
                            )));
                        }
                    }
                }
            };
            let ack = session
                .start(setup_options(&req.options), &pw)
                .await
                .map_err(setup_error)?;
            if let Some(p) = ack_problem(&ack) {
                return Err(SetupError::Other(p));
            }
            Ok(Box::new(SetupRun::new(session, key_hex, port)) as Box<dyn InstallRun>)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_follow_the_wizard() {
        let mut w = crate::wizard::Wizard::new();
        w.username = "alex".into();
        w.docker = true;
        w.cpu = 3;
        w.memory_gb = 5;
        w.disk_gb = 60;
        let o = setup_options(&w.options());
        assert_eq!(o.distro, pb::SetupDistro::Ubuntu2404 as i32);
        assert_eq!(o.preset, pb::SetupPreset::Developer as i32);
        assert_eq!(o.limits.unwrap().memory_mib, 5120);
        assert!(
            o.docker && o.docker_isolation_acknowledged,
            "docker needs the acknowledgement"
        );
        assert_eq!(o.username, "alex");
    }

    #[test]
    fn stages_map_to_rows() {
        assert_eq!(stage_id(pb::SetupStage::Build), "desktop");
        assert_eq!(stage_id(pb::SetupStage::Docker), "desktop");
        assert_eq!(stage_id(pb::SetupStage::Verifiers), "verifiers");
        assert_eq!(stage_id(pb::SetupStage::Done), "done");
        for id in DONE_BY_INSTALLER {
            assert!(group_of(id).is_some(), "{id}");
        }
    }

    #[test]
    fn acks_have_sentences() {
        let ok = pb::SetupAck {
            status: pb::SetupAckStatus::Ok as i32,
            ..Default::default()
        };
        assert!(ack_problem(&ok).is_none());
        let rl = pb::SetupAck {
            status: pb::SetupAckStatus::RateLimited as i32,
            retry_after_ms: 2500,
            ..Default::default()
        };
        assert!(ack_problem(&rl).unwrap().contains("Try again in 3 s"));
        let bad = pb::SetupAck {
            status: pb::SetupAckStatus::InvalidArgument as i32,
            field: "username".into(),
            ..Default::default()
        };
        assert!(ack_problem(&bad).unwrap().contains("username"));
    }
}
