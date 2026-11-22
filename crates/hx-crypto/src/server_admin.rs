//! Client side of server management on an authorized session (protocol §5.11, `ServerMgmt`,
//! feature `SERVER_MANAGEMENT`): the server overview, changing the PIN and the account
//! password, restarting the desktop, turning Docker off, resource limits and the agent update.
//!
//! A [`ServerAdmin`] owns the control receive side of an **authorized** `INTENT_SESSION`
//! connection that negotiated `SERVER_MANAGEMENT` at minor 3 or newer (offer
//! `Features::SERVER_MANAGEMENT` in [`crate::SessionOptions::capabilities`]). A request waits
//! for the answer with the same `request_id`; other `ServerMgmt` or `DeviceMgmt` messages that
//! arrive meanwhile (change notices) are kept for [`ServerAdmin::take_events`].
//!
//! Every answer that is a server decision is a [`ServerReply`] (`Ok`): a wrong PIN, a refusal,
//! "admin only" and so on are statuses, **not** errors. Only a failed connection, a timeout or a
//! protocol violation is an `Err`. PINs and passwords live in zeroizing buffers, never reach
//! `Debug`, and the copy inside the outgoing message is wiped after it is sent.

use std::{collections::VecDeque, time::Duration};

use hx_proto::{
    pb::{self, control_message::Message as Ctl, server_mgmt::Body},
    version::Features,
};
use hx_transport::Connection;
use zeroize::Zeroize;

use crate::{
    error::{Error, Result},
    secrets::Pin,
    setup::{Password, server_supports_setup},
};

/// Notices kept while a request waits.
const MAX_QUEUED: usize = 64;

/// The server's answer to a mutation or a check: `status` plus the fields that go with it.
pub type ServerReply = pb::ServerResult;

/// Server management on an authorized session.
#[derive(Debug)]
pub struct ServerAdmin {
    connection: Connection,
    next_id: u32,
    other: VecDeque<pb::ControlMessage>,
    timeout: Duration,
}

fn wipe(b: &mut bytes::Bytes) {
    if let Ok(mut m) = std::mem::take(b).try_into_mut() {
        m.as_mut().zeroize();
    }
}

fn scrub(m: &mut pb::ControlMessage) {
    if let Some(Ctl::ServerMgmt(s)) = &mut m.message {
        match &mut s.body {
            Some(Body::ChangePin(p)) => {
                wipe(&mut p.current);
                wipe(&mut p.new);
            }
            Some(Body::ChangePassword(p)) => {
                wipe(&mut p.current);
                wipe(&mut p.new);
            }
            _ => {}
        }
    }
}

impl ServerAdmin {
    /// Wrap an authorized connection (get it from [`crate::AwaitingPin::into_connection`],
    /// which refuses until the PIN was accepted). Fails with [`Error::UpdateRequired`] if the
    /// negotiated minor is below 3 or `SERVER_MANAGEMENT` was not negotiated, and with a
    /// protocol error for a control-only (setup) connection.
    pub fn new(connection: Connection) -> Result<Self> {
        if connection.is_control_only() {
            return Err(Error::Protocol("not a session connection"));
        }
        let n = connection.negotiated();
        if !server_supports_setup(n.version) || !n.features.contains(Features::SERVER_MANAGEMENT) {
            return Err(Error::UpdateRequired);
        }
        Ok(Self {
            connection,
            next_id: 1,
            other: VecDeque::new(),
            timeout: Duration::from_secs(30),
        })
    }

    /// Bound on each answer (default 30 s). Raise it for `check_update`, which waits for the
    /// server's release check (the server itself gives up after 60 s).
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    async fn request(&mut self, body: Body) -> Result<Body> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let mut msg = pb::ControlMessage::new(Ctl::ServerMgmt(pb::ServerMgmt {
            request_id: id,
            body: Some(body),
        }));
        let sent = self.connection.send_control(&msg).await;
        scrub(&mut msg);
        drop(msg);
        sent?;
        let deadline = tokio::time::Instant::now() + self.timeout;
        loop {
            let m = tokio::time::timeout_at(deadline, self.connection.recv_control())
                .await
                .map_err(|_| Error::Timeout("server management"))??;
            match m.message {
                Some(Ctl::ServerMgmt(s)) => {
                    if s.request_id != id {
                        return Err(Error::Protocol("answer to a request that was not made"));
                    }
                    return match s.body {
                        Some(b @ (Body::Overview(_) | Body::Result(_))) => Ok(b),
                        _ => Err(Error::Protocol("unexpected ServerMgmt body")),
                    };
                }
                Some(other) => {
                    if self.other.len() >= MAX_QUEUED {
                        self.other.pop_front();
                    }
                    self.other.push_back(pb::ControlMessage::new(other));
                }
                None => {}
            }
        }
    }

    async fn result(&mut self, body: Body) -> Result<ServerReply> {
        match self.request(body).await? {
            Body::Result(r) => {
                if pb::ServerStatus::try_from(r.status).is_err()
                    || r.status == pb::ServerStatus::Unspecified as i32
                {
                    return Err(Error::Protocol("unknown server status"));
                }
                Ok(r)
            }
            _ => Err(Error::Protocol("expected a result")),
        }
    }

    /// The overview: agent version, cached update status, the desktop, the host facts and the
    /// server time.
    pub async fn overview(&mut self) -> Result<pb::ServerOverview> {
        match self
            .request(Body::GetOverview(pb::ServerGetOverview {}))
            .await?
        {
            Body::Overview(o) => Ok(o),
            _ => Err(Error::Protocol("expected an overview")),
        }
    }

    /// Change the PIN. The current PIN counts like a login attempt on the server: a wrong one is
    /// `WRONG_PIN` with `attempts_left`, the 5th revokes this device.
    pub async fn change_pin(&mut self, current: &Pin, new: &Pin) -> Result<ServerReply> {
        self.result(Body::ChangePin(pb::ServerChangePin {
            current: bytes::Bytes::copy_from_slice(current.as_bytes()),
            new: bytes::Bytes::copy_from_slice(new.as_bytes()),
        }))
        .await
    }

    /// Change the Linux account password (the server checks the current one against the
    /// desktop user's hash).
    pub async fn change_password(
        &mut self,
        current: &Password,
        new: &Password,
    ) -> Result<ServerReply> {
        self.result(Body::ChangePassword(pb::ServerChangePassword {
            current: bytes::Bytes::copy_from_slice(current.as_bytes()),
            new: bytes::Bytes::copy_from_slice(new.as_bytes()),
        }))
        .await
    }

    /// Restart the desktop (open apps close; the stream ends).
    pub async fn restart_desktop(&mut self, force: bool) -> Result<ServerReply> {
        self.result(Body::RestartDesktop(pb::ServerRestartDesktop { force }))
            .await
    }

    /// Turn Docker off (`enable = false`, restarts the desktop). `enable = true` is answered
    /// `ADMIN_ONLY` with the command to run on the server in `message`.
    pub async fn set_docker(&mut self, enable: bool) -> Result<ServerReply> {
        self.result(Body::SetDocker(pb::ServerSetDocker { enable }))
            .await
    }

    /// Apply resource limits (every field non-zero; `restart_required` in the reply).
    pub async fn set_limits(&mut self, limits: pb::SetupLimits) -> Result<ServerReply> {
        self.result(Body::SetLimits(pb::ServerSetLimits {
            limits: Some(limits),
        }))
        .await
    }

    /// Ask the server to look for a newer release (the reply's `update` field).
    pub async fn check_update(&mut self) -> Result<ServerReply> {
        self.result(Body::CheckUpdate(pb::ServerCheckUpdate {}))
            .await
    }

    /// Update the agent to `version` (the release `check_update` found). `OK` means the server
    /// accepted it and is restarting: **the connection ends**, reconnect and read the new version
    /// from [`ServerAdmin::overview`].
    pub async fn apply_update(&mut self, version: &str) -> Result<ServerReply> {
        self.result(Body::ApplyUpdate(pb::ServerApplyUpdate {
            version: version.to_owned(),
        }))
        .await
    }

    /// Messages that arrived while a request waited (change notices of `DeviceMgmt`, say).
    pub fn take_events(&mut self) -> Vec<pb::ControlMessage> {
        self.other.drain(..).collect()
    }

    /// Give the connection back.
    pub fn into_connection(self) -> Connection {
        self.connection
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_outgoing_secrets_are_wiped_after_sending() {
        let mut m = pb::ControlMessage::new(Ctl::ServerMgmt(pb::ServerMgmt {
            request_id: 1,
            body: Some(Body::ChangePin(pb::ServerChangePin {
                current: bytes::Bytes::copy_from_slice(b"123456"),
                new: bytes::Bytes::copy_from_slice(b"654321"),
            })),
        }));
        scrub(&mut m);
        let Some(Ctl::ServerMgmt(pb::ServerMgmt {
            body: Some(Body::ChangePin(p)),
            ..
        })) = m.message
        else {
            panic!()
        };
        assert!(p.current.is_empty() && p.new.is_empty());
    }

    #[test]
    fn debug_never_shows_a_secret() {
        let p = pb::ServerChangePassword {
            current: bytes::Bytes::copy_from_slice(b"hunter2-current"),
            new: bytes::Bytes::copy_from_slice(b"hunter2-new"),
        };
        let text = format!("{p:?}");
        assert!(!text.contains("hunter") && !text.contains("104"), "{text}");
        let m = pb::ServerMgmt {
            request_id: 4,
            body: Some(Body::ChangePassword(p)),
        };
        assert!(!format!("{m:?}").contains("hunter"));
    }
}
