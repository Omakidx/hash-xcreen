//! The two seams of the update path that touch the running system, behind traits so that the tests
//! never restart a real unit or connect to a real daemon:
//!
//! * [`Systemd`]: run the fetcher unit, restart `hx-gatewayd.service` or `hx-privd.service`, and
//!   read a unit's state. The real [`SystemdCtl`] builds fixed argument vectors for `systemctl`
//!   from constants and a validated job (never from request data) and runs them through privd's
//!   closed-set [`CommandRunner`].
//! * [`HealthProbe`]: ask privd's own socket and gatewayd's admin socket whether they answer. The
//!   real [`SocketProbe`] speaks the framing of ipc.md 4 and 9 through `hx-ipc`.

use std::future::Future;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use hx_ipc::admin::{self, pb as apb};
use hx_ipc::privd::{self, PrivdPolicy, Side, pb as ppb};
use hx_ipc::{Decoder, NoCmsgReader};

use crate::fetcher::{ImageJob, Job};
use crate::privd::runner::{CommandRunner, Program, Tool};

/// A boxed future, so that the traits are usable as `dyn`.
pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The two units the update path restarts (a closed set).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    /// `hx-gatewayd.service`.
    Gatewayd,
    /// `hx-privd.service` (the daemon itself: a re-exec).
    Privd,
}

impl Unit {
    /// The unit name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Gatewayd => "hx-gatewayd.service",
            Self::Privd => "hx-privd.service",
        }
    }
}

/// A unit's state as the health check needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnitState {
    /// `ActiveState=active`.
    pub active: bool,
    /// `MainPID`; 0 when there is none.
    pub main_pid: u32,
}

/// How an image fetcher job stands (`systemctl start --no-block` returns at once).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    /// Started and not finished.
    Running,
    /// Finished with exit status 0.
    Succeeded,
    /// Failed, was killed or timed out.
    Failed,
}

fn no_image_jobs() -> String {
    "image fetcher jobs are not available through this systemd".to_string()
}

/// Talking to systemd.
pub trait Systemd: Send + Sync {
    /// Runs the fetcher for `job` to completion (`Ok`) or failure, bounded by the unit's own
    /// timeouts. The error text is privd's, never the fetcher's output.
    fn fetch<'a>(&'a self, job: &'a Job) -> BoxFut<'a, Result<(), String>>;
    /// Stops the fetcher unit of `job` (the caller was cancelled: killing the client of
    /// `systemctl start` would leave the download running). Best effort.
    fn stop_fetch<'a>(&'a self, job: &'a Job) -> BoxFut<'a, ()>;
    /// Restarts a unit. For [`Unit::Privd`] the call returns without waiting (the caller is
    /// the process being restarted).
    fn restart<'a>(&'a self, unit: Unit) -> BoxFut<'a, Result<(), String>>;
    /// Reads a unit's state.
    fn state<'a>(&'a self, unit: Unit) -> BoxFut<'a, Result<UnitState, String>>;

    /// Starts the image fetcher job without waiting for it (`systemctl start --no-block`): any
    /// earlier run of the same instance is stopped and its failed state cleared first, and the
    /// call returns once the new run exists, so [`Systemd::image_job_state`] cannot report the
    /// previous run's result. The default refuses (fakes that do not run image jobs).
    fn start_image_job<'a>(&'a self, job: &'a ImageJob) -> BoxFut<'a, Result<(), String>> {
        let _ = job;
        Box::pin(async { Err(no_image_jobs()) })
    }
    /// Where a started image job stands.
    fn image_job_state<'a>(&'a self, job: &'a ImageJob) -> BoxFut<'a, Result<JobState, String>> {
        let _ = job;
        Box::pin(async { Err(no_image_jobs()) })
    }
    /// Stops an image job (a cancel, a timeout, a refused directory). Best effort.
    fn stop_image_job<'a>(&'a self, job: &'a ImageJob) -> BoxFut<'a, ()> {
        let _ = job;
        Box::pin(async {})
    }
}

/// Asking the daemons whether they answer.
pub trait HealthProbe: Send + Sync {
    /// Whether privd answers `Hello` and `Ping` on its own socket, and the `privd_version` of
    /// its `HelloAck` (so that an old process still holding the socket is not mistaken for the
    /// new one).
    fn privd_answers(&self) -> BoxFut<'_, Option<String>>;
    /// Whether gatewayd's admin socket answers `Status`, and the `gatewayd_version` it reports.
    fn gatewayd_status(&self) -> BoxFut<'_, Option<String>>;
}

/// `systemctl` through the runner.
pub struct SystemdCtl {
    runner: Arc<dyn CommandRunner>,
}

impl SystemdCtl {
    /// Uses `runner` (the daemon's own).
    pub fn new(runner: Arc<dyn CommandRunner>) -> Self {
        Self { runner }
    }

    /// The unit that runs a fetcher job.
    pub fn fetcher_unit(job: &Job) -> String {
        format!("hx-update-fetcher@{}.service", job.instance())
    }

    /// The unit that runs an image fetcher job.
    pub fn image_unit(job: &ImageJob) -> String {
        format!("hx-image-fetcher@{}.service", job.instance())
    }

    /// `systemctl show --property=P...` of `unit` as `(key, value)` pairs.
    async fn show(&self, unit: &str, props: &[&str]) -> Result<Vec<(String, String)>, String> {
        let mut args: Vec<String> = vec!["show".into()];
        args.extend(props.iter().map(|p| format!("--property={p}")));
        args.push(unit.to_string());
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = self.ctl(&refs, Duration::from_secs(10)).await?;
        if !out.success() {
            return Err(format!("systemctl show {unit} failed"));
        }
        Ok(out
            .stdout
            .lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.to_string(), v.trim().to_string()))
            .collect())
    }

    async fn ctl(
        &self,
        args: &[&str],
        timeout: Duration,
    ) -> Result<crate::privd::runner::RunOutput, String> {
        let out = self
            .runner
            .run(Program::new(Tool::Systemctl, args).with_timeout(timeout))
            .await
            .map_err(|e| format!("cannot run systemctl: {e}"))?;
        Ok(out)
    }
}

impl Systemd for SystemdCtl {
    fn fetch<'a>(&'a self, job: &'a Job) -> BoxFut<'a, Result<(), String>> {
        Box::pin(async move {
            let unit = Self::fetcher_unit(job);
            // A previous failed run keeps the instance in the failed state.
            let _ = self
                .ctl(&["reset-failed", &unit], Duration::from_secs(10))
                .await;
            let limit = match job {
                Job::Manifest(_) => Duration::from_secs(55),
                Job::Artifact(_) => Duration::from_secs(660),
            };
            // `start` of a oneshot unit returns when it has finished, with its exit status.
            let out = self.ctl(&["start", &unit], limit).await?;
            if out.success() {
                return Ok(());
            }
            let _ = self.ctl(&["stop", &unit], Duration::from_secs(20)).await;
            Err(if out.timed_out {
                "the update fetcher did not finish in time".to_string()
            } else {
                format!("the update fetcher failed (journal of {unit})")
            })
        })
    }

    fn stop_fetch<'a>(&'a self, job: &'a Job) -> BoxFut<'a, ()> {
        Box::pin(async move {
            let unit = Self::fetcher_unit(job);
            let _ = self.ctl(&["stop", &unit], Duration::from_secs(20)).await;
        })
    }

    fn start_image_job<'a>(&'a self, job: &'a ImageJob) -> BoxFut<'a, Result<(), String>> {
        Box::pin(async move {
            let unit = Self::image_unit(job);
            // A previous run of this instance (a cancelled request) is stopped, and a failed
            // state cleared, so that `start` begins a new run.
            let _ = self.ctl(&["stop", &unit], Duration::from_secs(30)).await;
            let _ = self
                .ctl(&["reset-failed", &unit], Duration::from_secs(10))
                .await;
            let invocation = |props: Vec<(String, String)>| {
                props
                    .into_iter()
                    .find(|(k, _)| k == "InvocationID")
                    .map(|(_, v)| v)
                    .unwrap_or_default()
            };
            let before = invocation(
                self.show(&unit, &["InvocationID"])
                    .await
                    .unwrap_or_default(),
            );
            let out = self
                .ctl(&["start", "--no-block", &unit], Duration::from_secs(20))
                .await?;
            if !out.success() {
                return Err(format!("systemctl start {unit} failed"));
            }
            // `--no-block` queues the job; the new run has a new invocation id.
            for _ in 0..100 {
                let now = invocation(self.show(&unit, &["InvocationID"]).await?);
                if !now.is_empty() && now != before {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(format!("{unit} did not start"))
        })
    }

    fn image_job_state<'a>(&'a self, job: &'a ImageJob) -> BoxFut<'a, Result<JobState, String>> {
        Box::pin(async move {
            let unit = Self::image_unit(job);
            let props = self.show(&unit, &["ActiveState", "Result"]).await?;
            let get = |k: &str| {
                props
                    .iter()
                    .find(|(key, _)| key == k)
                    .map_or("", |(_, v)| v.as_str())
            };
            Ok(match get("ActiveState") {
                "activating" | "active" | "reloading" | "deactivating" => JobState::Running,
                "failed" => JobState::Failed,
                // A oneshot unit that ran to the end is inactive with Result=success.
                _ if get("Result") == "success" => JobState::Succeeded,
                _ => JobState::Failed,
            })
        })
    }

    fn stop_image_job<'a>(&'a self, job: &'a ImageJob) -> BoxFut<'a, ()> {
        Box::pin(async move {
            let unit = Self::image_unit(job);
            let _ = self.ctl(&["stop", &unit], Duration::from_secs(30)).await;
        })
    }

    fn restart<'a>(&'a self, unit: Unit) -> BoxFut<'a, Result<(), String>> {
        Box::pin(async move {
            let args: &[&str] = match unit {
                // Restarting ourselves: queue the job and return, the process is about to be
                // replaced.
                Unit::Privd => &["restart", "--no-block", unit.name()],
                Unit::Gatewayd => &["restart", unit.name()],
            };
            let out = self.ctl(args, Duration::from_secs(60)).await?;
            if out.success() {
                Ok(())
            } else {
                Err(format!("systemctl restart {} failed", unit.name()))
            }
        })
    }

    fn state<'a>(&'a self, unit: Unit) -> BoxFut<'a, Result<UnitState, String>> {
        Box::pin(async move {
            let out = self
                .ctl(
                    &[
                        "show",
                        "--property=ActiveState",
                        "--property=MainPID",
                        unit.name(),
                    ],
                    Duration::from_secs(10),
                )
                .await?;
            if !out.success() {
                return Err(format!("systemctl show {} failed", unit.name()));
            }
            let mut active = false;
            let mut pid = 0u32;
            for line in out.stdout.lines() {
                match line.split_once('=') {
                    Some(("ActiveState", v)) => active = v.trim() == "active",
                    Some(("MainPID", v)) => pid = v.trim().parse().unwrap_or(0),
                    _ => {}
                }
            }
            Ok(UnitState {
                active,
                main_pid: pid,
            })
        })
    }
}

/// Probes the real sockets.
pub struct SocketProbe {
    /// privd's own socket.
    pub privd_socket: PathBuf,
    /// gatewayd's admin socket.
    pub admin_socket: PathBuf,
}

const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

fn connect(path: &std::path::Path) -> std::io::Result<UnixStream> {
    let s = UnixStream::connect(path)?;
    s.set_read_timeout(Some(PROBE_TIMEOUT))?;
    s.set_write_timeout(Some(PROBE_TIMEOUT))?;
    Ok(s)
}

/// `Hello`, then `Ping` on the privd socket.
fn probe_privd(path: &std::path::Path) -> Option<String> {
    use std::io::Write;
    let mut s = connect(path).ok()?;
    let mut dec = Decoder::new(PrivdPolicy::new(Side::Client));
    let send = |s: &mut UnixStream, f: ppb::frame::Frame| {
        let bytes = privd::encode_message(&ppb::Frame { frame: Some(f) }, Side::Server).ok()?;
        s.write_all(&bytes).ok()
    };
    let mut next = |s: &UnixStream| -> Option<ppb::frame::Frame> {
        let raw = dec.read_from(&mut NoCmsgReader(s)).ok()??;
        match privd::decode(raw, Side::Client).ok()? {
            privd::Incoming::Message(f) => f.frame,
            privd::Incoming::Secret(_) => None,
        }
    };
    send(
        &mut s,
        ppb::frame::Frame::Hello(ppb::Hello {
            major: privd::VERSION_MAJOR,
            minor: privd::VERSION_MINOR,
            software: "hx-privd-update".into(),
        }),
    )?;
    let ppb::frame::Frame::HelloAck(ack) = next(&s)? else {
        return None;
    };
    send(
        &mut s,
        ppb::frame::Frame::Ping(ppb::Ping { nonce: 0x7570_6461 }),
    )?;
    matches!(next(&s)?, ppb::frame::Frame::Pong(p) if p.nonce == 0x7570_6461)
        .then_some(ack.privd_version)
}

/// `Hello`, then `Status` on the admin socket.
fn probe_admin(path: &std::path::Path) -> Option<String> {
    use std::io::Write;
    let mut s = connect(path).ok()?;
    let mut dec = Decoder::new(PrivdPolicy::new(Side::Client));
    let send = |s: &mut UnixStream, f: apb::frame::Frame| {
        let bytes = admin::encode_message(&apb::Frame { frame: Some(f) }, Side::Server).ok()?;
        s.write_all(&bytes).ok()
    };
    let mut next = |s: &UnixStream| -> Option<apb::frame::Frame> {
        let raw = dec.read_from(&mut NoCmsgReader(s)).ok()??;
        match admin::decode(raw, Side::Client).ok()? {
            admin::Incoming::Message(f) => f.frame,
            admin::Incoming::Secret(_) => None,
        }
    };
    send(
        &mut s,
        apb::frame::Frame::Hello(ppb::Hello {
            major: privd::VERSION_MAJOR,
            minor: privd::VERSION_MINOR,
            software: "hx-privd-update".into(),
        }),
    )?;
    matches!(next(&s)?, apb::frame::Frame::HelloAck(_)).then_some(())?;
    send(
        &mut s,
        apb::frame::Frame::Request(apb::Request {
            request_id: 1,
            deadline_ms: 0,
            secret_slots: Vec::new(),
            command: Some(apb::request::Command::Status(apb::StatusRequest {})),
        }),
    )?;
    match next(&s)? {
        apb::frame::Frame::Response(r) if r.request_id == 1 => match r.result {
            Some(apb::response::Result::Status(st)) => Some(st.gatewayd_version),
            _ => None,
        },
        _ => None,
    }
}

impl HealthProbe for SocketProbe {
    fn privd_answers(&self) -> BoxFut<'_, Option<String>> {
        Box::pin(async move {
            let p = self.privd_socket.clone();
            tokio::task::spawn_blocking(move || probe_privd(&p))
                .await
                .unwrap_or(None)
        })
    }

    fn gatewayd_status(&self) -> BoxFut<'_, Option<String>> {
        Box::pin(async move {
            let p = self.admin_socket.clone();
            tokio::task::spawn_blocking(move || probe_admin(&p))
                .await
                .unwrap_or(None)
        })
    }
}
