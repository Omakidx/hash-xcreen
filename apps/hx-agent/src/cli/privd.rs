//! The CLI's client of `hx-privd`, always as the `Admin` role (uid 0, `docs/ipc.md` section 3).
//!
//! One blocking connection per CLI invocation, `Hello` first, one request in flight. Secrets
//! travel only as kind-2 frames written right after the request, from `Zeroizing` buffers.
//! Replies are read through [`super::wire::Wire`] (`recvmsg`, descriptors refused). Progress
//! frames are handed to the caller already sanitized.

use std::path::Path;
use std::time::{Duration, Instant};

use bytes::Bytes;
use hx_ipc::privd::{self, Incoming, Side, pb, pb::request::Command};

use super::error::{CliError, remote};
use super::text::peer;
use super::wire::Wire;

/// How long to wait for `HelloAck`.
const HELLO_WAIT: Duration = Duration::from_secs(5);
/// Slack added to a command's deadline before giving up locally.
const MARGIN: Duration = Duration::from_secs(3);
/// Bound on writing a request.
const WRITE_WAIT: Duration = Duration::from_secs(10);

/// One secret to send after a request.
pub struct OutSecret<'a> {
    /// The declared kind.
    pub kind: pb::SecretKind,
    /// The bytes (the caller keeps them in its own zeroizing buffer).
    pub bytes: &'a [u8],
}

/// One progress report, sanitized.
#[derive(Debug, Clone)]
pub struct ProgressLine {
    /// The stage name (`BUILD`, `DOCKER`, ...).
    pub stage: String,
    /// `index` of `total`.
    pub index: u32,
    /// Steps in the stage.
    pub total: u32,
    /// The step's description, sanitized.
    pub step: String,
    /// Percent, or `None` when unknown.
    pub percent: Option<u32>,
    /// The step finished successfully (only meaningful with `done`).
    pub ok: bool,
}

/// A connection to privd.
pub struct PrivdConn {
    wire: Wire,
    next_id: u64,
    /// privd's version, sanitized.
    pub version: String,
    /// The phase it reported in `HelloAck`.
    pub phase: pb::Phase,
}

impl PrivdConn {
    /// Connects, says `Hello` and checks that privd serves this connection as `Admin`: a CLI
    /// that was served as `Gateway` is not root, and every X-class command would fail in a
    /// confusing way.
    pub fn connect(path: &Path) -> Result<Self, CliError> {
        let mut wire = Wire::connect(path, "hx-privd")?;
        let hello = pb::Frame {
            frame: Some(pb::frame::Frame::Hello(pb::Hello {
                major: privd::VERSION_MAJOR,
                minor: privd::VERSION_MINOR,
                software: format!("hx-agent {}", env!("CARGO_PKG_VERSION")),
            })),
        };
        let bytes = privd::encode_message(&hello, Side::Server)
            .map_err(|e| CliError::failed(format!("cannot encode Hello: {e}")))?;
        wire.send(&bytes, WRITE_WAIT)?;
        let raw = wire.recv(Instant::now() + HELLO_WAIT)?;
        match privd::decode(raw, Side::Client) {
            Ok(Incoming::Message(pb::Frame {
                frame: Some(pb::frame::Frame::HelloAck(ack)),
            })) => {
                if ack.major != privd::VERSION_MAJOR {
                    return Err(CliError::failed(format!(
                        "hx-privd speaks protocol major {}, this hx-agent speaks {} (a half-finished update?)",
                        ack.major,
                        privd::VERSION_MAJOR
                    )));
                }
                if ack.role != pb::Role::Admin as i32 {
                    return Err(CliError::failed(
                        "hx-privd did not serve this connection as the admin role (hx-agent must run as root)",
                    ));
                }
                Ok(Self {
                    wire,
                    next_id: 1,
                    version: peer(&ack.privd_version, privd::MAX_SOFTWARE_LEN),
                    phase: pb::Phase::try_from(ack.phase).unwrap_or(pb::Phase::Unspecified),
                })
            }
            Ok(_) => Err(CliError::failed(
                "hx-privd did not answer Hello with HelloAck",
            )),
            Err(e) => Err(CliError::failed(format!(
                "hx-privd broke the protocol: {e}"
            ))),
        }
    }

    /// Sends `command` with its `secrets` and waits for the result. `on_progress` is called for
    /// every `Progress` frame. An `Error` answer is returned as [`CliError::Remote`].
    pub fn call(
        &mut self,
        command: Command,
        secrets: &[OutSecret<'_>],
        on_progress: &mut dyn FnMut(&ProgressLine),
    ) -> Result<pb::response::Result, CliError> {
        let info = privd::command_info(&command);
        let deadline_ms = info.effective_deadline_ms(0);
        let started = Instant::now();
        let until = started + Duration::from_millis(u64::from(deadline_ms)) + MARGIN;
        let id = self.next_id;
        self.next_id += 1;
        let slots = secrets
            .iter()
            .enumerate()
            .map(|(i, s)| pb::SecretSlot {
                slot: i as u32,
                kind: s.kind as i32,
                sealed: false,
                length: s.bytes.len() as u32,
                upload_nonce: Bytes::new(),
                signer_key_id: 0,
            })
            .collect();
        let frame = pb::Frame {
            frame: Some(pb::frame::Frame::Request(pb::Request {
                request_id: id,
                deadline_ms,
                secret_slots: slots,
                command: Some(command),
            })),
        };
        let bytes = privd::encode_message(&frame, Side::Server)
            .map_err(|e| CliError::failed(format!("cannot encode the request: {e}")))?;
        self.wire.send(&bytes, WRITE_WAIT)?;
        for (i, s) in secrets.iter().enumerate() {
            // A zeroizing buffer: the frame copy of the secret is wiped when this drops.
            let framed = privd::encode_secret(id, i as u8, s.bytes)
                .map_err(|e| CliError::failed(format!("cannot encode a secret: {e}")))?;
            self.wire.send(&framed, WRITE_WAIT)?;
        }
        loop {
            let raw = self.wire.recv(until)?;
            let incoming = privd::decode(raw, Side::Client)
                .map_err(|e| CliError::failed(format!("hx-privd broke the protocol: {e}")))?;
            let Incoming::Message(pb::Frame { frame: Some(f) }) = incoming else {
                return Err(CliError::failed("hx-privd sent an unexpected frame"));
            };
            match f {
                pb::frame::Frame::Response(r) => {
                    if r.request_id != id {
                        return Err(CliError::failed("hx-privd answered another request"));
                    }
                    return match r.result {
                        Some(pb::response::Result::Error(e)) => Err(remote(&e)),
                        Some(ok) => Ok(ok),
                        None => Err(CliError::failed("hx-privd sent an empty response")),
                    };
                }
                pb::frame::Frame::Progress(p) => {
                    let stage = pb::ProgressStage::try_from(p.stage)
                        .map(|s| {
                            s.as_str_name()
                                .strip_prefix("PROGRESS_STAGE_")
                                .unwrap_or("UNKNOWN")
                                .to_owned()
                        })
                        .unwrap_or_else(|_| "UNKNOWN".into());
                    on_progress(&ProgressLine {
                        stage,
                        index: p.index,
                        total: p.total,
                        step: peer(&p.step, privd::MAX_PROGRESS_STEP_LEN),
                        percent: (p.percent <= 100).then_some(p.percent),
                        ok: p.ok,
                    });
                }
                pb::frame::Frame::Ping(p) => {
                    let pong = pb::Frame {
                        frame: Some(pb::frame::Frame::Pong(pb::Pong { nonce: p.nonce })),
                    };
                    let bytes = privd::encode_message(&pong, Side::Server)
                        .map_err(|e| CliError::failed(format!("cannot encode Pong: {e}")))?;
                    self.wire.send(&bytes, WRITE_WAIT)?;
                }
                pb::frame::Frame::Pong(_) => {}
                _ => return Err(CliError::failed("hx-privd sent an unexpected frame")),
            }
        }
    }

    /// [`PrivdConn::call`] without progress or secrets.
    pub fn simple(&mut self, command: Command) -> Result<pb::response::Result, CliError> {
        self.call(command, &[], &mut |_| {})
    }
}

/// The error for a result variant that does not belong to the command that was sent.
pub fn unexpected(what: &str) -> CliError {
    CliError::failed(format!(
        "hx-privd answered {what} with the wrong result type"
    ))
}
