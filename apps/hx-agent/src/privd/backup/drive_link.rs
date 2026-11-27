//! The Drive end of the repository link, from privd's side: connect to `/run/hx/drive.sock`,
//! `Hello`, `HelloAck`, and `OpenRepo` (ipc.md section 24, "Drive link", and section 29).
//!
//! The session is opened right after the job slot is taken, before the snapshot and the helper
//! (ipc.md section 26, v0.8): a revoked token, a lease held elsewhere or an unreachable Drive
//! helper then costs nothing. While the host works on the snapshot and the helper, the loop keeps
//! the link alive ([`Session::service`]).

use std::path::Path;

use hx_ipc::repo::{self, Endpoint, pb};

use super::link_io::{Link, connect_unix, frame};
use super::relay::{OPEN_REPO_ID, Session};
use super::{BackupEnv, Failure};

/// What `OpenRepo` asks for.
#[derive(Debug, Clone)]
pub struct OpenParams {
    /// The folder of the repository in Drive (1 to 128 bytes of `[A-Za-z0-9._-]`, starting with a
    /// letter or digit): a privd constant per server and desktop, never the worker's to know.
    pub folder: String,
    /// Create the folder if it is absent (`INIT`).
    pub create: bool,
    /// The 16 raw bytes of the server id.
    pub server_id: [u8; 16],
    /// Take the lease over (the restore onto a new server, the re-claim).
    pub takeover: bool,
}

/// Opens the Drive session. On `Error` from `OpenRepo` the failure is `Repo(class)` and the
/// class is recorded as the job's repository error.
pub async fn open<E: BackupEnv>(
    s: &mut Session<E>,
    socket: &Path,
    p: &OpenParams,
    job_id: [u8; 16],
) -> Result<(), Failure> {
    let window = u64::try_from(s.timing.drive_connect_window.as_millis()).unwrap_or(u64::MAX);
    let retry = s.timing.connect_retry;
    let mono = s.mono.clone();
    let stream = connect_unix(socket, window, retry, mono.as_ref())
        .await
        .map_err(|_| Failure::Unavailable)?;
    let link = Link::spawn(
        "drive",
        stream,
        Endpoint::PrivdDriveLink,
        s.drive_q.clone(),
        s.worker_q.clone(),
        &s.parts,
    )
    .map_err(|_| Failure::Internal("cannot start the Drive link".into()))?;
    s.drive = Some(link);
    let hello = frame(pb::repo_frame::Frame::Hello(pb::Hello {
        major: repo::VERSION_MAJOR,
        minor: repo::VERSION_MINOR,
        job_id: bytes::Bytes::copy_from_slice(&job_id),
    }));
    if !s.send_drive(&hello) {
        return Err(Failure::Unavailable);
    }
    let ack_by = s.mono.now_ms() + u64::try_from(s.timing.ack_timeout.as_millis()).unwrap_or(0);
    s.pump_until(|s| {
        s.drive.as_ref().is_some_and(|l| l.state.is_open()) || s.mono.now_ms() >= ack_by
    })
    .await;
    if let Some(f) = s.abort_reason() {
        return Err(f);
    }
    if !s.drive.as_ref().is_some_and(|l| l.state.is_open()) {
        return Err(Failure::Unavailable);
    }
    let open = frame(pb::repo_frame::Frame::Request(pb::RepoRequest {
        req_id: OPEN_REPO_ID,
        op: Some(pb::repo_request::Op::OpenRepo(pb::OpenRepo {
            folder: p.folder.clone(),
            create: p.create,
            server_id: bytes::Bytes::copy_from_slice(&p.server_id),
            takeover: p.takeover,
        })),
    }));
    if !s.send_drive(&open) {
        return Err(Failure::Unavailable);
    }
    // The answer is guarded by the loop's own rules (an `Event` is a sign of life, and the link
    // silence of 45 s ends the wait); a job deadline or a cancel ends it too.
    s.pump_until(|s| s.open_repo_answer.is_some()).await;
    if let Some(f) = s.abort_reason() {
        return Err(f);
    }
    match s.open_repo_answer.take() {
        Some(pb::repo_response::Result::Done(_)) => Ok(()),
        Some(pb::repo_response::Result::Error(e)) => {
            let class = pb::ErrorClass::try_from(e.class).unwrap_or(pb::ErrorClass::Internal);
            s.note_repo_error(class);
            Err(Failure::Repo(class))
        }
        _ => Err(Failure::Unavailable),
    }
}
