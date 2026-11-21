//! The CLI's client of the `hx-gatewayd` admin socket (`docs/ipc.md` section 9).
//!
//! Blocking, one connection per invocation. The pairing token is the only secret that travels
//! here, as a kind-2 frame from a `Zeroizing` buffer right after its request; the reply of
//! `CreatePairingCode` (which carries the code) is wiped once it has been read.

use std::path::Path;
use std::time::{Duration, Instant};

use hx_ipc::admin::{self, Incoming, pb};
use hx_ipc::privd::{self, Side};
use zeroize::Zeroize;

use super::error::{CliError, remote};
use super::text::peer;
use super::wire::Wire;

const HELLO_WAIT: Duration = Duration::from_secs(5);
const CALL_WAIT: Duration = Duration::from_secs(30);
const WRITE_WAIT: Duration = Duration::from_secs(10);

/// A connection to the admin socket.
pub struct AdminConn {
    wire: Wire,
    next_id: u64,
    /// gatewayd's version, sanitized.
    pub version: String,
}

impl AdminConn {
    /// Connects and says `Hello`.
    pub fn connect(path: &Path, expected_uid: u32) -> Result<Self, CliError> {
        let mut wire = Wire::connect(path, "hx-gatewayd", expected_uid)?;
        let hello = pb::Frame {
            frame: Some(pb::frame::Frame::Hello(privd::pb::Hello {
                major: privd::VERSION_MAJOR,
                minor: privd::VERSION_MINOR,
                software: format!("hx-agent {}", env!("CARGO_PKG_VERSION")),
            })),
        };
        let bytes = admin::encode_message(&hello, Side::Server)
            .map_err(|e| CliError::failed(format!("cannot encode Hello: {e}")))?;
        wire.send(&bytes, WRITE_WAIT)?;
        let raw = wire.recv(Instant::now() + HELLO_WAIT)?;
        match admin::decode(raw, Side::Client) {
            Ok(Incoming::Message(pb::Frame {
                frame: Some(pb::frame::Frame::HelloAck(ack)),
            })) => {
                if ack.major != privd::VERSION_MAJOR {
                    return Err(CliError::failed(format!(
                        "hx-gatewayd speaks protocol major {}, this hx-agent speaks {} (a half-finished update?)",
                        ack.major,
                        privd::VERSION_MAJOR
                    )));
                }
                Ok(Self {
                    wire,
                    next_id: 1,
                    version: peer(&ack.gatewayd_version, privd::MAX_SOFTWARE_LEN),
                })
            }
            Ok(_) => Err(CliError::failed(
                "hx-gatewayd did not answer Hello with HelloAck",
            )),
            Err(e) => Err(CliError::failed(format!(
                "hx-gatewayd broke the protocol: {e}"
            ))),
        }
    }

    /// Sends `command` (with `secret`, the pairing token, as a kind-2 frame) and waits for the
    /// result. An `Error` answer is [`CliError::Remote`].
    pub fn call(
        &mut self,
        command: pb::request::Command,
        secret: Option<&[u8]>,
    ) -> Result<pb::response::Result, CliError> {
        let id = self.next_id;
        self.next_id += 1;
        let slots = secret
            .map(|s| {
                vec![pb::AdminSecretSlot {
                    slot: 0,
                    kind: pb::AdminSecretKind::PairingToken as i32,
                    length: s.len() as u32,
                }]
            })
            .unwrap_or_default();
        let frame = pb::Frame {
            frame: Some(pb::frame::Frame::Request(pb::Request {
                request_id: id,
                deadline_ms: 0,
                secret_slots: slots,
                command: Some(command),
            })),
        };
        let bytes = admin::encode_message(&frame, Side::Server)
            .map_err(|e| CliError::failed(format!("cannot encode the request: {e}")))?;
        self.wire.send(&bytes, WRITE_WAIT)?;
        if let Some(s) = secret {
            let framed = privd::encode_secret(id, 0, s)
                .map_err(|e| CliError::failed(format!("cannot encode the token: {e}")))?;
            self.wire.send(&framed, WRITE_WAIT)?;
        }
        let until = Instant::now() + CALL_WAIT;
        loop {
            let raw = self.wire.recv(until)?;
            let incoming = admin::decode(raw, Side::Client)
                .map_err(|e| CliError::failed(format!("hx-gatewayd broke the protocol: {e}")))?;
            let Incoming::Message(pb::Frame { frame: Some(f) }) = incoming else {
                return Err(CliError::failed("hx-gatewayd sent an unexpected frame"));
            };
            match f {
                pb::frame::Frame::Response(r) => {
                    if r.request_id != id {
                        return Err(CliError::failed("hx-gatewayd answered another request"));
                    }
                    return match r.result {
                        Some(pb::response::Result::Error(e)) => Err(remote(&e)),
                        Some(ok) => Ok(ok),
                        None => Err(CliError::failed("hx-gatewayd sent an empty response")),
                    };
                }
                pb::frame::Frame::Pong(_) => {}
                _ => return Err(CliError::failed("hx-gatewayd sent an unexpected frame")),
            }
        }
    }
}

/// Wipes the code of a `CreatePairingCode` result once the caller has printed it.
pub fn wipe_code(r: &mut pb::CreatePairingCodeResult) {
    r.code.zeroize();
}

/// The error for a result variant that does not belong to the command that was sent.
pub fn unexpected(what: &str) -> CliError {
    CliError::failed(format!(
        "hx-gatewayd answered {what} with the wrong result type"
    ))
}
