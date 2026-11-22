//! The setup job (`docs/ipc.md` 5.5, "Job steps"): validation of the request, then
//!
//! 1. `PREFLIGHT`: the password verifier record (Argon2id here, `PepperEnrol(PASSWORD)`), kept
//!    in memory only;
//! 2. `GetDesktop`: a usable desktop takes the `EXISTING` path (`StartDesktop` if stopped, then
//!    `SetUserPassword`); otherwise `CreateDesktop` runs on the dedicated lane with the full
//!    deadline and its progress forwarded;
//! 3. `VERIFIERS`: the password verifier is stored only now, so a password that the desktop
//!    never accepted leaves nothing behind;
//! 4. `FINISH`: `FinishSetup`, retried on a transient failure;
//! 5. the `SetupResult`.
//!
//! The password is moved into the lane call and wiped as soon as its secret frame is written.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hx_crypto::PinParams;
use hx_ipc::privd::pb::{self as privd_pb, request::Command};
use hx_ipc::text::sanitize_text;
use hx_proto::message::password_problem;
use hx_proto::pb;
use hx_provision::Username;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use super::coordinator::{Event, FinishOutcome, JobCtl, Shared, usable};
use crate::gateway::privd_client::PrivdError;
use crate::gateway::verifier::{self, VerifierError, VerifierRecord};

/// Progress updates are sent at most this often unless the stage changes.
const PROGRESS_EVERY: Duration = Duration::from_millis(250);
/// How long a stopped desktop may take to start.
const START_TIMEOUT: Duration = Duration::from_secs(90);

/// A validated request: the typed privd command and what the `EXISTING` path compares.
pub struct JobRequest {
    pub(super) create: privd_pb::CreateDesktopRequest,
    username: String,
    distro: i32,
    preset: i32,
    docker: bool,
}

fn printable_ascii(s: &str) -> bool {
    s.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// Semantic validation of a `start` (protocol 5.10): the first problem is named by its field.
/// Values are never echoed. `desktop_id` comes from the gateway's configuration, never from
/// the client, and `image_file`, the pool device and the other Admin-only arguments have no
/// field in the protocol at all.
pub fn validate(
    options: Option<&pb::SetupOptions>,
    desktop_id: &str,
    password: &[u8],
) -> Result<JobRequest, &'static str> {
    let o = options.ok_or("options")?;
    let distro = pb::SetupDistro::try_from(o.distro).map_err(|_| "options.distro")?;
    if distro == pb::SetupDistro::Unspecified {
        return Err("options.distro");
    }
    match pb::SetupDesktop::try_from(o.desktop) {
        Ok(pb::SetupDesktop::Unspecified | pb::SetupDesktop::Xfce) => {}
        Err(_) => return Err("options.desktop"),
    }
    let preset = pb::SetupPreset::try_from(o.preset).map_err(|_| "options.preset")?;
    if preset == pb::SetupPreset::Unspecified {
        return Err("options.preset");
    }
    let username = Username::new(&o.username).map_err(|_| "options.username")?;
    // The setup and privd enums are numbered differently for the image mode.
    let image_mode = match pb::SetupImageMode::try_from(o.image_mode) {
        Ok(pb::SetupImageMode::Unspecified | pb::SetupImageMode::Auto) => privd_pb::ImageMode::Auto,
        Ok(pb::SetupImageMode::Build) => privd_pb::ImageMode::Build,
        Ok(pb::SetupImageMode::Prebuilt) => privd_pb::ImageMode::Prebuilt,
        Err(_) => return Err("options.image_mode"),
    };
    if o.docker && !o.docker_isolation_acknowledged {
        return Err("options.docker_isolation_acknowledged");
    }
    let limits = o.limits.as_ref().map(|l| privd_pb::Limits {
        cpu: l.cpu,
        memory_mib: l.memory_mib,
        disk_gib: l.disk_gib,
    });
    if let Some(l) = &limits
        && (l.cpu > 1024 || l.memory_mib > 16_777_216 || l.disk_gib > 65_536)
    {
        return Err("options.limits");
    }
    let settings = match &o.settings {
        Some(s) => {
            if ![&s.hostname, &s.timezone, &s.locale, &s.keyboard]
                .iter()
                .all(|v| printable_ascii(v))
            {
                return Err("options.settings");
            }
            Some(privd_pb::DesktopSettings {
                hostname: s.hostname.clone(),
                timezone: s.timezone.clone(),
                locale: s.locale.clone(),
                keyboard: s.keyboard.clone(),
            })
        }
        None => None,
    };
    if password_problem(password).is_some() {
        return Err("password");
    }
    let (d, p) = (distro as i32, preset as i32);
    Ok(JobRequest {
        create: privd_pb::CreateDesktopRequest {
            desktop_id: desktop_id.to_owned(),
            distro: d,
            desktop: privd_pb::DesktopKind::Xfce as i32,
            preset: p,
            username: username.as_str().to_owned(),
            image_mode: image_mode as i32,
            limits,
            docker: o.docker,
            docker_isolation_acknowledged: o.docker_isolation_acknowledged,
            settings,
            image_file: None,
        },
        username: username.as_str().to_owned(),
        distro: d,
        preset: p,
        docker: o.docker,
    })
}

/// How a step failed.
pub(super) struct Fail {
    code: pb::SetupErrorCode,
    stage: pb::SetupStage,
    message: String,
    retryable: bool,
    retry_after_ms: u32,
    cancelled: bool,
}

impl Fail {
    fn new(code: pb::SetupErrorCode, stage: pb::SetupStage, message: &str) -> Self {
        Self {
            code,
            stage,
            message: sanitize_text(message, 256),
            retryable: false,
            retry_after_ms: 0,
            cancelled: false,
        }
    }

    fn cancelled(stage: pb::SetupStage) -> Self {
        Self {
            cancelled: true,
            ..Self::new(pb::SetupErrorCode::Cancelled, stage, "cancelled")
        }
    }
}

/// privd's error to the app's (docs/ipc.md 5.5, "Error mapping"). privd's `output_tail` never
/// reaches this point: only its (sanitized) message does.
pub(super) fn map_privd(e: &PrivdError, stage: pb::SetupStage) -> Fail {
    use pb::SetupErrorCode as C;
    use privd_pb::{ErrorCode as E, ErrorDetail as D};
    match e {
        PrivdError::Remote(r) => {
            let (code, retryable) = match (r.code, r.detail) {
                (E::InvalidArgument, _) => (C::InvalidArgument, false),
                (E::FailedPrecondition, D::DesktopExists) => (C::DesktopExists, false),
                (E::FailedPrecondition, D::Pool) => (C::InsufficientSpace, false),
                (E::FailedPrecondition, D::SetupWindowClosed) => (C::WindowClosed, false),
                (E::FailedPrecondition, D::IsolationNotRestored) => {
                    (C::IsolationNotRestored, false)
                }
                (E::ResourceExhausted, D::Locked) => (C::Locked, false),
                (E::ResourceExhausted, _) => (C::RateLimited, true),
                (E::DeadlineExceeded, _) => (C::TimedOut, true),
                (E::Cancelled, _) => (C::Cancelled, false),
                (E::Unavailable, _) => (C::Unavailable, true),
                (E::Unimplemented, _) => (C::Unsupported, false),
                _ => (C::Internal, false),
            };
            Fail {
                code,
                stage,
                message: sanitize_text(&r.message, 256),
                retryable: retryable || r.retryable,
                retry_after_ms: u32::try_from(r.retry_after.as_millis()).unwrap_or(u32::MAX),
                cancelled: code == C::Cancelled,
            }
        }
        PrivdError::Timeout => Fail {
            retryable: true,
            ..Fail::new(C::TimedOut, stage, "the server did not answer in time")
        },
        PrivdError::Unavailable(_) => Fail {
            retryable: true,
            retry_after_ms: 2000,
            ..Fail::new(
                C::Unavailable,
                stage,
                "the server's privileged service is unavailable",
            )
        },
        _ => Fail::new(C::Internal, stage, "an internal error"),
    }
}

fn map_verifier(e: &VerifierError, stage: pb::SetupStage) -> Fail {
    match e {
        VerifierError::Privd(p) => map_privd(p, stage),
        VerifierError::InvalidSecret => Fail::new(
            pb::SetupErrorCode::InvalidArgument,
            stage,
            "the password is not acceptable",
        ),
        _ => Fail::new(
            pb::SetupErrorCode::Internal,
            stage,
            "the password verifier could not be created",
        ),
    }
}

/// Coalesced progress: latest wins, at most 4 per second, a stage change goes out at once.
struct Progress {
    sh: Arc<Shared>,
    job_id: u32,
    started: Instant,
    last: Mutex<Option<(Instant, i32)>>,
}

impl Progress {
    #[allow(clippy::too_many_arguments)]
    fn emit(
        &self,
        stage: pb::SetupStage,
        index: u32,
        total: u32,
        step: &str,
        percent: u32,
        ok: bool,
    ) {
        let p = pb::SetupProgress {
            job_id: self.job_id,
            stage: stage as i32,
            index,
            total,
            step: sanitize_text(step, 128),
            percent: if percent > 100 { 255 } else { percent },
            ok,
            elapsed_ms: u32::try_from(self.started.elapsed().as_millis()).unwrap_or(u32::MAX),
        };
        self.sh.lock().job.progress = Some(p.clone());
        let now = Instant::now();
        let mut last = self.last.lock().unwrap_or_else(|e| e.into_inner());
        let send = match *last {
            Some((at, s)) => s != stage as i32 || now.duration_since(at) >= PROGRESS_EVERY,
            None => true,
        };
        if send {
            *last = Some((now, stage as i32));
            drop(last);
            self.sh.publish(Event::Progress(p));
        }
    }

    fn forward_privd(&self, p: &privd_pb::Progress) {
        use pb::SetupStage as S;
        use privd_pb::ProgressStage as P;
        let stage = match P::try_from(p.stage).unwrap_or(P::Unspecified) {
            P::Preflight | P::Host => S::Preflight,
            P::ImageFetch => S::ImageFetch,
            P::ImageImport => S::ImageImport,
            P::Build => S::Build,
            P::Launch => S::Launch,
            P::Post => S::Post,
            P::Session => S::Session,
            P::Docker => S::Docker,
            P::Done => S::Done,
            // Not part of a setup.
            _ => return,
        };
        self.emit(stage, p.index, p.total, &p.step, p.percent, p.ok);
    }
}

struct Done {
    path: pb::SetupPathTaken,
    reason: String,
    warnings: Vec<String>,
    docker: pb::SetupDocker,
}

fn docker_none(requested: bool) -> pb::SetupDocker {
    pb::SetupDocker {
        status: if requested {
            pb::SetupDockerStatus::NotEnabled
        } else {
            pb::SetupDockerStatus::NotRequested
        } as i32,
        ..Default::default()
    }
}

fn docker_from(requested: bool, o: Option<&privd_pb::DockerOutcome>) -> pb::SetupDocker {
    use privd_pb::docker_outcome::Outcome as O;
    let cut = |s: &str, n| sanitize_text(s, n);
    match o.and_then(|o| o.outcome.as_ref()) {
        Some(O::Enabled(e)) => pb::SetupDocker {
            status: pb::SetupDockerStatus::Enabled as i32,
            docker_version: cut(&e.docker_version, 64),
            ..Default::default()
        },
        Some(O::UnsupportedIncus(u)) => pb::SetupDocker {
            status: pb::SetupDockerStatus::UnsupportedIncus as i32,
            found: cut(&u.found, 64),
            required: cut(&u.required, 64),
            ..Default::default()
        },
        // `output_tail` is deliberately not forwarded.
        Some(O::SelfTestFailed(f)) => pb::SetupDocker {
            status: pb::SetupDockerStatus::SelfTestFailed as i32,
            isolation_restored: f.isolation_restored,
            hint: cut(&f.hint, 256),
            ..Default::default()
        },
        None => docker_none(requested),
    }
}

/// Runs one job to its end and publishes the result.
pub(super) async fn run(
    sh: Arc<Shared>,
    job_id: u32,
    req: JobRequest,
    password: Zeroizing<Vec<u8>>,
    ctl: Arc<JobCtl>,
) {
    let started = Instant::now();
    let prog = Progress {
        sh: sh.clone(),
        job_id,
        started,
        last: Mutex::new(None),
    };
    let outcome = steps(&sh, &prog, req, password, &ctl).await;
    let elapsed_ms = u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX);
    let mut result = pb::SetupResult {
        job_id,
        elapsed_ms,
        ..Default::default()
    };
    match outcome {
        Ok((done, finished)) => {
            result.status = pb::SetupJobState::Succeeded as i32;
            result.path_taken = done.path as i32;
            result.reason = sanitize_text(&done.reason, 256);
            result.warnings = done.warnings;
            result.docker = Some(done.docker);
            result.finished = finished;
        }
        Err(f) if f.cancelled => {
            result.status = pb::SetupJobState::Cancelled as i32;
            result.error = Some(pb::SetupError {
                code: pb::SetupErrorCode::Cancelled as i32,
                stage: f.stage as i32,
                message: "cancelled".into(),
                retryable: true,
                retry_after_ms: 0,
            });
        }
        Err(f) => {
            tracing::warn!(job = job_id, code = ?f.code, stage = ?f.stage, "the setup job failed");
            result.status = pb::SetupJobState::Failed as i32;
            result.error = Some(pb::SetupError {
                code: f.code as i32,
                stage: f.stage as i32,
                message: f.message,
                retryable: f.retryable,
                retry_after_ms: f.retry_after_ms,
            });
        }
    }
    tracing::debug!(
        job = job_id,
        status = result.status,
        "setup job: refreshing the facts"
    );
    sh.refresh_facts().await;
    tracing::debug!(job = job_id, "setup job: publishing the result");
    {
        let mut st = sh.lock();
        st.job.state =
            pb::SetupJobState::try_from(result.status).unwrap_or(pb::SetupJobState::Failed);
        st.job.progress = None;
        st.job.result = Some(result.clone());
        st.job.ctl = None;
    }
    sh.publish(Event::State);
    sh.publish(Event::Result(result));
}

async fn steps(
    sh: &Arc<Shared>,
    prog: &Progress,
    req: JobRequest,
    password: Zeroizing<Vec<u8>>,
    ctl: &Arc<JobCtl>,
) -> Result<(Done, bool), Fail> {
    use pb::SetupStage as S;
    let t = sh.settings.privd_timeout;
    prog.emit(S::Preflight, 1, 3, "Checking the server", 255, false);
    let params: PinParams = sh.settings.params;
    let record: VerifierRecord = verifier::enrol(
        &sh.privd,
        privd_pb::LockoutPurpose::Password,
        &password,
        params,
    )
    .await
    .map_err(|e| map_verifier(&e, S::Preflight))?;
    if ctl.is_cancelled() {
        return Err(Fail::cancelled(S::Preflight));
    }
    prog.emit(
        S::Preflight,
        2,
        3,
        "Looking for an existing desktop",
        255,
        false,
    );
    let existing = tokio::time::timeout(t, sh.privd.get_desktop(&sh.settings.desktop_id))
        .await
        .map_err(|_| map_privd(&PrivdError::Timeout, S::Preflight))?
        .map_err(|e| map_privd(&e, S::Preflight))?;
    if ctl.is_cancelled() {
        return Err(Fail::cancelled(S::Preflight));
    }

    let done = match existing {
        Some(d) if usable(&d) => existing_path(sh, prog, &req, d, password, ctl).await?,
        _ => create_path(sh, prog, req, password, ctl).await?,
    };
    prog.emit(S::Preflight, 3, 3, "Preflight done", 100, true);

    prog.emit(S::Verifiers, 1, 1, "Saving the password check", 255, false);
    sh.verifiers.set_password(record).map_err(|e| {
        tracing::error!(error = %e, "storing the password verifier failed");
        Fail::new(
            pb::SetupErrorCode::Internal,
            S::Verifiers,
            "the password check could not be saved",
        )
    })?;
    sh.bump_version();
    sh.audit(
        hx_ipc::privd::pb::AuditEvent::PasswordVerifierChanged,
        "setup",
    );

    prog.emit(S::Finish, 1, 1, "Finishing setup", 255, false);
    let mut done = done;
    let finished = match sh.finish_with_retries().await {
        FinishOutcome::Done => true,
        FinishOutcome::WindowClosed => {
            done.warnings.push(
                "The setup window had already closed. Run `sudo hx-agent setup begin` and then `sudo hx-agent setup finish` to finish setup."
                    .into(),
            );
            false
        }
        FinishOutcome::Failed(e) => {
            tracing::warn!(error = %e, "FinishSetup failed after retries");
            done.warnings.push(
                "Setup could not be finished yet; try again, or run `sudo hx-agent setup finish`."
                    .into(),
            );
            false
        }
    };
    done.warnings.truncate(16);
    prog.emit(S::Done, 1, 1, "Done", 100, true);
    Ok((done, finished))
}

async fn existing_path(
    sh: &Arc<Shared>,
    prog: &Progress,
    req: &JobRequest,
    d: privd_pb::Desktop,
    password: Zeroizing<Vec<u8>>,
    ctl: &Arc<JobCtl>,
) -> Result<Done, Fail> {
    use pb::SetupStage as S;
    // Options that disagree with what exists are an error, never a silent adoption.
    if d.username != req.username || d.distro != req.distro || d.preset != req.preset {
        return Err(Fail::new(
            pb::SetupErrorCode::DesktopExists,
            S::Preflight,
            "a desktop already exists with a different user, distribution or preset",
        ));
    }
    if d.state == privd_pb::DesktopState::Stopped as i32 {
        prog.emit(S::Launch, 1, 1, "Starting the desktop", 255, false);
        tokio::time::timeout(
            START_TIMEOUT,
            sh.privd.start_desktop(&sh.settings.desktop_id),
        )
        .await
        .map_err(|_| map_privd(&PrivdError::Timeout, S::Launch))?
        .map_err(|e| map_privd(&e, S::Launch))?;
    }
    if ctl.is_cancelled() {
        return Err(Fail::cancelled(S::Launch));
    }
    prog.emit(S::Post, 1, 1, "Setting the password", 255, false);
    let (tx, _rx) = mpsc::channel(1);
    let call = sh.lane.call_streaming(
        Command::SetUserPassword(privd_pb::SetUserPasswordRequest {
            desktop_id: sh.settings.desktop_id.clone(),
        }),
        vec![(privd_pb::SecretKind::UserPassword, password)],
        None,
        tx,
    );
    call.wait().await.map_err(|e| map_privd(&e, S::Post))?;
    let docker = if d.docker == privd_pb::DockerState::On as i32 {
        pb::SetupDocker {
            status: pb::SetupDockerStatus::Enabled as i32,
            ..Default::default()
        }
    } else {
        docker_none(req.docker)
    };
    Ok(Done {
        path: pb::SetupPathTaken::Existing,
        reason: "A desktop already existed; its password was set.".into(),
        warnings: Vec::new(),
        docker,
    })
}

async fn create_path(
    sh: &Arc<Shared>,
    prog: &Progress,
    req: JobRequest,
    password: Zeroizing<Vec<u8>>,
    ctl: &Arc<JobCtl>,
) -> Result<Done, Fail> {
    use pb::SetupStage as S;
    let docker_requested = req.docker;
    {
        sh.lock().desktop = pb::SetupDesktopState::Creating;
        sh.publish(Event::State);
    }
    let (tx, mut rx) = mpsc::channel::<privd_pb::Progress>(64);
    let call = sh.lane.call_streaming(
        Command::CreateDesktop(req.create),
        vec![(privd_pb::SecretKind::UserPassword, password)],
        None,
        tx,
    );
    let request_id = call.request_id;
    let wait = call.wait();
    tokio::pin!(wait);
    let mut cancel_sent = false;
    let result = loop {
        tokio::select! {
            r = &mut wait => break r,
            Some(p) = rx.recv() => prog.forward_privd(&p),
            () = ctl.notify.notified(), if !cancel_sent => {
                cancel_sent = true;
                tracing::debug!(request_id, "setup job: cancelling the privd command");
                sh.lane.cancel(request_id);
            }
        }
    };
    tracing::debug!(
        request_id,
        ok = result.is_ok(),
        "setup job: the privd command ended"
    );
    // Frames that arrived with the answer.
    while let Ok(p) = rx.try_recv() {
        prog.forward_privd(&p);
    }
    match result {
        Ok(privd_pb::response::Result::CreateDesktop(r)) => {
            let path = match privd_pb::PathTaken::try_from(r.path_taken) {
                Ok(privd_pb::PathTaken::Prebuilt) => pb::SetupPathTaken::Prebuilt,
                Ok(privd_pb::PathTaken::Build) => pb::SetupPathTaken::Build,
                _ => pb::SetupPathTaken::Unspecified,
            };
            Ok(Done {
                path,
                reason: r.reason,
                warnings: r
                    .warnings
                    .iter()
                    .take(16)
                    .map(|w| sanitize_text(w, 256))
                    .collect(),
                docker: docker_from(docker_requested, r.docker.as_ref()),
            })
        }
        Ok(_) => Err(Fail::new(
            pb::SetupErrorCode::Internal,
            S::Build,
            "an unexpected answer",
        )),
        Err(e) => {
            let stage = match &e {
                PrivdError::Remote(r) => r
                    .stage
                    .and_then(|s| privd_pb::ProgressStage::try_from(s).ok())
                    .map(|s| match s {
                        privd_pb::ProgressStage::ImageFetch => S::ImageFetch,
                        privd_pb::ProgressStage::ImageImport => S::ImageImport,
                        privd_pb::ProgressStage::Launch => S::Launch,
                        privd_pb::ProgressStage::Post => S::Post,
                        privd_pb::ProgressStage::Docker => S::Docker,
                        privd_pb::ProgressStage::Session => S::Session,
                        privd_pb::ProgressStage::Build => S::Build,
                        _ => S::Preflight,
                    })
                    .unwrap_or(S::Preflight),
                _ => S::Build,
            };
            let mut f = map_privd(&e, stage);
            // A revocation or a cancel that privd answered some other way is still a cancel.
            if ctl.is_cancelled() && matches!(f.code, pb::SetupErrorCode::Cancelled) {
                f.cancelled = true;
            }
            Err(f)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good() -> pb::SetupOptions {
        pb::SetupOptions {
            distro: pb::SetupDistro::Ubuntu2404 as i32,
            preset: pb::SetupPreset::Basic as i32,
            username: "alice".into(),
            ..Default::default()
        }
    }

    fn check(o: pb::SetupOptions, pw: &[u8]) -> Result<JobRequest, &'static str> {
        validate(Some(&o), "main", pw)
    }

    #[test]
    fn a_valid_request_becomes_a_typed_privd_command_without_admin_only_fields() {
        let r = check(good(), b"correct horse").unwrap();
        assert_eq!(r.create.desktop_id, "main");
        assert_eq!(r.create.username, "alice");
        assert!(r.create.image_file.is_none());
        assert_eq!(r.create.image_mode, privd_pb::ImageMode::Auto as i32);
        assert_eq!(r.create.desktop, privd_pb::DesktopKind::Xfce as i32);
    }

    #[test]
    fn image_modes_are_renumbered_not_copied() {
        let mut o = good();
        o.image_mode = pb::SetupImageMode::Build as i32;
        assert_eq!(
            check(o.clone(), b"x").unwrap().create.image_mode,
            privd_pb::ImageMode::Build as i32
        );
        o.image_mode = pb::SetupImageMode::Prebuilt as i32;
        assert_eq!(
            check(o, b"x").unwrap().create.image_mode,
            privd_pb::ImageMode::Prebuilt as i32
        );
    }

    #[test]
    fn invalid_fields_are_named_and_never_echoed() {
        let bad = |f: &dyn Fn(&mut pb::SetupOptions)| {
            let mut o = good();
            f(&mut o);
            check(o, b"pw").err().unwrap()
        };
        assert_eq!(bad(&|o| o.distro = 0), "options.distro");
        assert_eq!(bad(&|o| o.distro = 99), "options.distro");
        assert_eq!(bad(&|o| o.preset = 0), "options.preset");
        assert_eq!(bad(&|o| o.username = String::new()), "options.username");
        assert_eq!(bad(&|o| o.username = "root".into()), "options.username");
        assert_eq!(bad(&|o| o.username = "Alice".into()), "options.username");
        assert_eq!(bad(&|o| o.image_mode = 9), "options.image_mode");
        assert_eq!(
            bad(&|o| o.docker = true),
            "options.docker_isolation_acknowledged"
        );
        assert_eq!(
            bad(&|o| o.settings = Some(pb::SetupDesktopSettings {
                hostname: "bad\nname".into(),
                ..Default::default()
            })),
            "options.settings"
        );
        assert_eq!(check(good(), b"").err(), Some("password"));
        assert_eq!(check(good(), b"a\nb").err(), Some("password"));
        assert_eq!(check(good(), &[0xff, 0xfe]).err(), Some("password"));
        assert_eq!(validate(None, "main", b"pw").err(), Some("options"));
    }

    #[test]
    fn privd_errors_map_as_documented() {
        use pb::SetupErrorCode as C;
        use privd_pb::{ErrorCode as E, ErrorDetail as D};
        let remote = |code, detail| {
            PrivdError::Remote(crate::gateway::privd_client::RemoteError {
                code,
                detail,
                message: "m".into(),
                retryable: false,
                retry_after: Duration::ZERO,
                stage: None,
            })
        };
        let s = pb::SetupStage::Build;
        for (e, want) in [
            (
                remote(E::InvalidArgument, D::Unspecified),
                C::InvalidArgument,
            ),
            (
                remote(E::FailedPrecondition, D::DesktopExists),
                C::DesktopExists,
            ),
            (remote(E::FailedPrecondition, D::Pool), C::InsufficientSpace),
            (
                remote(E::FailedPrecondition, D::SetupWindowClosed),
                C::WindowClosed,
            ),
            (
                remote(E::FailedPrecondition, D::IsolationNotRestored),
                C::IsolationNotRestored,
            ),
            (remote(E::ResourceExhausted, D::Unspecified), C::RateLimited),
            (remote(E::ResourceExhausted, D::Locked), C::Locked),
            (remote(E::DeadlineExceeded, D::Unspecified), C::TimedOut),
            (remote(E::Cancelled, D::Unspecified), C::Cancelled),
            (remote(E::Unavailable, D::Unspecified), C::Unavailable),
            (remote(E::Unimplemented, D::Unspecified), C::Unsupported),
            (remote(E::Internal, D::Unspecified), C::Internal),
            (remote(E::PermissionDenied, D::Unspecified), C::Internal),
        ] {
            assert_eq!(map_privd(&e, s).code, want, "{e:?}");
        }
        assert!(map_privd(&remote(E::Unavailable, D::Unspecified), s).retryable);
    }

    #[test]
    fn docker_output_tail_is_never_forwarded() {
        let o = privd_pb::DockerOutcome {
            outcome: Some(privd_pb::docker_outcome::Outcome::SelfTestFailed(
                privd_pb::DockerSelfTestFailed {
                    isolation_restored: true,
                    hint: "try again".into(),
                    output_tail: "SECRET-LOOKING-OUTPUT".into(),
                    fallbacks: vec![],
                },
            )),
        };
        let d = docker_from(true, Some(&o));
        assert_eq!(d.status, pb::SetupDockerStatus::SelfTestFailed as i32);
        assert!(d.isolation_restored);
        assert!(!format!("{d:?}").contains("SECRET"));
        assert_eq!(
            docker_from(false, None).status,
            pb::SetupDockerStatus::NotRequested as i32
        );
        assert_eq!(
            docker_from(true, None).status,
            pb::SetupDockerStatus::NotEnabled as i32
        );
    }
}
