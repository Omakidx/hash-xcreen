//! The worker end of the repository link, from privd's side: connect, `Hello`, `HelloAck`,
//! `Job` and the secret frames (ipc.md section 24, "Worker end of the link", and section 26,
//! steps 2 and 3).

use std::path::Path;
use std::sync::atomic::Ordering;

use hx_ipc::repo::{self, Endpoint, pb};

use super::link_io::{Link, connect_unix, frame};
use super::relay::Session;
use super::spec::JobSecrets;
use super::{BackupEnv, Failure};

/// Connects to the proxy device's host socket (retrying every 200 ms for at most 30 s after the
/// helper started), exchanges `Hello` and `HelloAck` (the helper must reach `HelloAck` within 30 s
/// of its start), then sends the `Job` and one kind-2 frame per declared secret slot. The secrets
/// are moved in and wiped as soon as their frames are queued.
///
/// `helper_started_ms` is the monotonic time at which the helper was started.
pub async fn open<E: BackupEnv>(
    s: &mut Session<E>,
    socket: &Path,
    helper_started_ms: u64,
    job: pb::Job,
    secrets: JobSecrets,
) -> Result<(), Failure> {
    let window = u64::try_from(s.timing.worker_connect_window.as_millis()).unwrap_or(u64::MAX);
    let retry = s.timing.connect_retry;
    let mono = s.mono.clone();
    // `HelloAck` within 30 s of the start of the helper. The Incus proxy accepts before the
    // worker listens and then closes: such a connection is dropped and tried again.
    let ack_by = helper_started_ms + u64::try_from(s.timing.ack_timeout.as_millis()).unwrap_or(0);
    loop {
        // Each attempt is bounded by the time left to `HelloAck`, not by a fresh window.
        let left = ack_by.saturating_sub(s.mono.now_ms());
        if left == 0 {
            return Err(Failure::HelperFailed(
                "no HelloAck within 30 s of the start".into(),
            ));
        }
        let attempt = window.min(left);
        let stream = s
            .service(connect_unix(socket, attempt, retry, mono.as_ref()))
            .await
            .map_err(|_| Failure::HelperFailed("the worker's socket cannot be reached".into()))?;
        if let Some(f) = s.abort_reason() {
            return Err(f);
        }
        let link = Link::spawn(
            "worker",
            stream,
            Endpoint::PrivdWorkerLink,
            s.worker_q.clone(),
            s.drive_q.clone(),
            &s.parts,
        )
        .map_err(|_| Failure::HelperFailed("cannot start the worker link".into()))?;
        s.worker = Some(link);
        let hello = frame(pb::repo_frame::Frame::Hello(pb::Hello {
            major: repo::VERSION_MAJOR,
            minor: repo::VERSION_MINOR,
            job_id: job.job_id.clone(),
        }));
        if !s.send_worker(&hello) {
            return Err(Failure::HelperFailed(
                "the worker link closed at once".into(),
            ));
        }
        s.pump_until(|s| {
            s.worker.as_ref().is_some_and(|l| l.state.is_open()) || s.mono.now_ms() >= ack_by
        })
        .await;
        if let Some(f) = s.abort_reason() {
            return Err(f);
        }
        if s.worker.as_ref().is_some_and(|l| l.state.is_open()) {
            break;
        }
        let ended = s.worker.as_ref().is_some_and(|l| !l.open);
        if ended && s.mono.now_ms() < ack_by {
            s.reset_worker();
            tokio::time::sleep(retry).await;
            continue;
        }
        return Err(Failure::HelperFailed(if ended {
            "the worker link ended before HelloAck".into()
        } else {
            "no HelloAck within 30 s of the start".into()
        }));
    }
    // The worker has been heard from now: the silence clock starts here, not at the connection.
    if let Some(l) = s.worker.as_ref() {
        l.last_rx.store(s.mono.now_ms(), Ordering::SeqCst);
    }
    let job_frame = frame(pb::repo_frame::Frame::Job(job.clone()));
    if !s.send_worker(&job_frame) {
        return Err(Failure::HelperFailed(
            "the worker link closed before the Job".into(),
        ));
    }
    s.job_msg = Some(job);
    let JobSecrets { slot0, slot1 } = secrets;
    if let Some(l) = s.worker.as_mut() {
        l.send_secret(0, &slot0)
            .map_err(|_| Failure::Internal("cannot queue slot 0".into()))?;
        if let Some(k) = slot1 {
            l.send_secret(1, &k)
                .map_err(|_| Failure::Internal("cannot queue slot 1".into()))?;
        }
    }
    Ok(())
}
