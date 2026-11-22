//! Client side of device management on an authorized session (protocol §5.9): today the 1.3
//! `create_pairing_code` call ("pair a new device from the app").
//!
//! A [`DeviceAdmin`] owns the control receive side of an **authorized** `INTENT_SESSION`
//! connection that negotiated `DEVICE_MANAGEMENT` at minor 3 or newer (offer
//! `Features::DEVICE_MANAGEMENT` in [`crate::SessionOptions::capabilities`]). A request waits
//! for the answer with the same `request_id`; other `DeviceMgmt` messages (change notices)
//! that arrive meanwhile are kept for [`DeviceAdmin::take_events`].

use std::{collections::VecDeque, fmt, time::Duration};

use hx_proto::{
    message::{MAX_PAIRING_CODE_TTL_S, MIN_PAIRING_CODE_TTL_S},
    pb::{self, control_message::Message as Ctl},
    version::Features,
};
use hx_transport::Connection;
use zeroize::Zeroizing;

use crate::{
    error::{Error, Result},
    setup::server_supports_setup,
};

/// Notices kept while a request waits.
const MAX_QUEUED: usize = 64;

/// A pairing code issued by the server. Secret: `Debug` shows nothing of the code; show it
/// only while the dialog is open and never log it.
pub struct PairingCodeIssued {
    code: Zeroizing<String>,
    /// When the code expires (Unix seconds). Authoritative: the server may cap the request.
    pub expires_at_unix: u64,
}

impl PairingCodeIssued {
    /// The short code, `XXXX-XXXX`.
    pub fn code(&self) -> &str {
        &self.code
    }
}

impl fmt::Debug for PairingCodeIssued {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingCodeIssued")
            .field("code", &"[redacted]")
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

/// What the server's answer means (`status` and `retry_after_s`, §5.9).
enum Reply {
    Issued,
    RateLimited(Duration),
    InvalidArgument,
    Failed,
}

fn classify(c: &pb::PairingCodeIssued) -> Result<Reply> {
    match pb::PairingCodeStatus::try_from(c.status) {
        Ok(pb::PairingCodeStatus::Ok) => Ok(Reply::Issued),
        Ok(pb::PairingCodeStatus::RateLimited) => Ok(Reply::RateLimited(Duration::from_secs(
            u64::from(c.retry_after_s),
        ))),
        Ok(pb::PairingCodeStatus::InvalidArgument) => Ok(Reply::InvalidArgument),
        Ok(pb::PairingCodeStatus::Failed) => Ok(Reply::Failed),
        Ok(pb::PairingCodeStatus::Unspecified) | Err(_) => {
            Err(Error::Protocol("unknown pairing code status"))
        }
    }
}

/// Device management on an authorized session.
#[derive(Debug)]
pub struct DeviceAdmin {
    connection: Connection,
    next_id: u32,
    other: VecDeque<pb::DeviceMgmt>,
    timeout: Duration,
}

impl DeviceAdmin {
    /// Wrap an authorized connection (get it from [`crate::AwaitingPin::into_connection`],
    /// which refuses until the PIN was accepted: a client cannot see the server's restriction
    /// itself, and a server answers the call on a restricted connection with a
    /// `PROTOCOL_ERROR` close). Fails with [`Error::UpdateRequired`] if the negotiated minor
    /// is below 3 or `DEVICE_MANAGEMENT` was not negotiated, and with a protocol error for a
    /// control-only (setup) connection.
    pub fn new(connection: Connection) -> Result<Self> {
        if connection.is_control_only() {
            return Err(Error::Protocol("not a session connection"));
        }
        let n = connection.negotiated();
        if !server_supports_setup(n.version) || !n.features.contains(Features::DEVICE_MANAGEMENT) {
            return Err(Error::UpdateRequired);
        }
        Ok(Self {
            connection,
            next_id: 1,
            other: VecDeque::new(),
            timeout: Duration::from_secs(20),
        })
    }

    /// Bound on each answer (default 20 s).
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Ask for a pairing code for a new device. `expires_in_s` is 60 to 900 (the server may
    /// cap it; read `expires_at_unix`). Errors: [`Error::RateLimited`] (3 codes per hour per
    /// server), [`Error::ServerFailed`], [`Error::InvalidSecret`] if the server rejected the
    /// expiry. A new code replaces the previous one at once.
    pub async fn create_pairing_code(&mut self, expires_in_s: u32) -> Result<PairingCodeIssued> {
        if !(MIN_PAIRING_CODE_TTL_S..=MAX_PAIRING_CODE_TTL_S).contains(&expires_in_s) {
            return Err(Error::InvalidSecret(
                "pairing code lifetime must be 60 to 900 s",
            ));
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let req = pb::ControlMessage::new(Ctl::DeviceMgmt(pb::DeviceMgmt {
            request_id: id,
            body: Some(pb::device_mgmt::Body::CreatePairingCode(
                pb::CreatePairingCode { expires_in_s },
            )),
        }));
        self.connection.send_control(&req).await?;
        let deadline = tokio::time::Instant::now() + self.timeout;
        loop {
            let m = tokio::time::timeout_at(deadline, self.connection.recv_control())
                .await
                .map_err(|_| Error::Timeout("pairing code"))??;
            let Some(Ctl::DeviceMgmt(d)) = m.message else {
                return Err(Error::Protocol("unexpected message on a session"));
            };
            match d.body {
                Some(pb::device_mgmt::Body::PairingCodeIssued(c)) if d.request_id == id => {
                    return match classify(&c)? {
                        Reply::Issued => Ok(PairingCodeIssued {
                            code: Zeroizing::new(c.code),
                            expires_at_unix: c.expires_at_unix,
                        }),
                        Reply::RateLimited(retry_after) => Err(Error::RateLimited { retry_after }),
                        Reply::InvalidArgument => Err(Error::InvalidSecret(
                            "the server rejected the code lifetime",
                        )),
                        Reply::Failed => Err(Error::ServerFailed),
                    };
                }
                Some(pb::device_mgmt::Body::PairingCodeIssued(_)) => {
                    return Err(Error::Protocol("answer to a request that was not made"));
                }
                _ => {
                    if self.other.len() >= MAX_QUEUED {
                        self.other.pop_front();
                    }
                    self.other.push_back(d);
                }
            }
        }
    }

    /// Change notices (and other `DeviceMgmt` messages) received while a request waited.
    pub fn take_events(&mut self) -> Vec<pb::DeviceMgmt> {
        self.other.drain(..).collect()
    }

    /// Give the connection back.
    pub fn into_connection(self) -> Connection {
        self.connection
    }
}
