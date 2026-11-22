//! Client side of the post-pairing setup connection (`INTENT_SETUP`, protocol 1.3, §5.10).
//!
//! The one-liner installer ends at pairing. The app then reconnects with its pinned key and
//! `Hello{intent: SETUP}` ([`connect_setup`]) and, depending on whether the server has a PIN
//! yet, either is admitted on its key alone (**KeyOnly**: it may only [`set_pin`]) or has to
//! prove the PIN first (**NeedsPin**). The authorized [`SetupSession`] then starts the desktop
//! build ([`start`]), follows [`SetupEvent`]s and finishes.
//!
//! Rules this module enforces for the caller:
//!
//! * `INTENT_SETUP` is sent only if `confirmed_server_version` (the version seen on a
//!   **confirmed** pairing, [`crate::PairedServer::server_version`]) is at least 1.3; the setup
//!   `HelloAck` is checked again. Otherwise [`Error::UpdateRequired`]: an older server would
//!   answer an unknown intent with a hard `PROTOCOL_ERROR` close (§4.7).
//! * `SETUP_CLOSED` (a refusal or a close) is [`Error::SetupClosed`]: go to the normal login.
//! * Every request gets a fresh non-zero `request_id`; its answer is matched by id, pushes
//!   that arrive in between are queued for [`SetupSession::next_event`], an answer to an
//!   abandoned request is dropped and any other unsolicited answer is a protocol violation.
//! * Passwords and PINs live in zeroizing buffers, never in `Debug` or errors, and the copy
//!   inside the outgoing message is wiped after it is sent.
//!
//! [`set_pin`]: SetupSession::set_pin
//! [`start`]: SetupSession::start

use std::{collections::VecDeque, fmt, sync::Arc, time::Duration};

use hx_proto::{
    channel::CloseCode,
    message::{self, MgmtDirection},
    pb::{self, Intent, RefuseReason, control_message::Message as Ctl},
    version::{Features, ProtocolVersion, capabilities},
};
use hx_transport::{
    Client, ClientHello, ClientOptions, CloseInfo, Connection, Target, TransportPreference,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    error::{Error, Result},
    keys::{IdentityKey, PublicKey},
    secrets::Pin,
    session::{PinReply, pin_exchange},
    tls,
    wire::{AuthMessage, AuthStatus, auth_message::Body},
};

/// Most pushes kept while a request waits for its answer. A server that floods more than this
/// between a request and its answer is violating the protocol.
const MAX_QUEUED_EVENTS: usize = 256;
/// Answers of abandoned requests that are still tolerated.
const MAX_ABANDONED: usize = 8;

/// Does a server that showed this version (on a confirmed pairing, or on its last successful
/// session) speak the 1.3 features? `major` must be 1 and `minor` at least 3.
pub fn server_supports_setup(v: impl Into<ProtocolVersion>) -> bool {
    let v = v.into();
    v.major == hx_proto::version::PROTOCOL_MAJOR && v.minor >= 3
}

/// The account password of the desktop user chosen in the app (1 to 511 bytes of UTF-8 without
/// NUL, CR or LF: [`hx_proto::message::password_problem`]). Zeroized on drop; `Debug` shows
/// nothing.
pub struct Password(Zeroizing<Vec<u8>>);

impl Password {
    /// Validate what the user typed.
    pub fn new(text: &str) -> Result<Self> {
        Self::from_bytes(text.as_bytes())
    }

    /// Validate bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        match message::password_problem(b) {
            None => Ok(Self(Zeroizing::new(b.to_vec()))),
            Some(p) => Err(Error::InvalidSecret(match p {
                "must not be empty" => "password must not be empty",
                "is longer than 511 bytes" => "password is longer than 511 bytes",
                "contains a NUL, carriage return or newline" => {
                    "password contains a NUL, carriage return or newline"
                }
                _ => "password is not valid UTF-8",
            })),
        }
    }

    /// The bytes (for the wire only).
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password([redacted])")
    }
}

/// Options of [`connect_setup`].
#[derive(Clone, Debug)]
pub struct SetupConnectOptions {
    /// The version the server showed on a **confirmed** pairing
    /// ([`crate::PairedServer::server_version`]). `None` (never confirmed) or below 1.3 makes
    /// [`connect_setup`] fail with [`Error::UpdateRequired`] without connecting.
    pub confirmed_server_version: Option<ProtocolVersion>,
    /// Transport to use.
    pub preference: TransportPreference,
    /// Label shown by the server in its device list (at most 64 bytes).
    pub device_name: String,
    /// Software string for `Hello` (at most 128 bytes).
    pub software: String,
    /// Bound on each reply during the PIN exchange and on the first `SetupState`.
    pub reply_timeout: Duration,
    /// Bound on the answer to one request (`set_pin`, `start`, `cancel`, `finish`). Starting
    /// a job is acknowledged quickly (the build runs on after the ack), so this is short.
    pub request_timeout: Duration,
    /// Transport tunables.
    pub transport: ClientOptions,
}

impl Default for SetupConnectOptions {
    fn default() -> Self {
        Self {
            confirmed_server_version: None,
            preference: TransportPreference::Auto,
            device_name: "device".into(),
            software: concat!("hx-crypto ", env!("CARGO_PKG_VERSION")).into(),
            reply_timeout: Duration::from_secs(20),
            request_timeout: Duration::from_secs(30),
            transport: ClientOptions::default(),
        }
    }
}

/// What [`connect_setup`] produced.
#[derive(Debug)]
pub enum SetupAuth {
    /// Admitted on the pinned key (no PIN exists yet): only `set_pin` works until it succeeds.
    Ready(SetupSession),
    /// A PIN exists: prove it first.
    NeedsPin(AwaitingSetupPin),
}

/// Connect for setup (protocol §5.10). Fails with [`Error::UpdateRequired`] before touching
/// the network unless the server was confirmed to be 1.3 or newer, and with
/// [`Error::SetupClosed`] if setup is not open for this device.
pub async fn connect_setup(
    target: &Target,
    device: &Arc<IdentityKey>,
    server_key: PublicKey,
    opts: &SetupConnectOptions,
) -> Result<SetupAuth> {
    if !opts
        .confirmed_server_version
        .is_some_and(server_supports_setup)
    {
        return Err(Error::UpdateRequired);
    }
    let mut transport = opts.transport.clone();
    transport.preference = opts.preference;
    let client = Client::new(tls::client_config_session(device, server_key)?, transport);
    let hello = ClientHello {
        capabilities: capabilities(&[], Features::SETUP),
        intent: Intent::Setup,
        software: opts.software.clone(),
        device_name: opts.device_name.clone(),
    };
    let connection = client.connect(target, &hello).await.map_err(|e| match e {
        hx_transport::Error::Refused {
            reason: RefuseReason::SetupClosed,
            ..
        } => Error::SetupClosed,
        hx_transport::Error::Refused {
            reason, message, ..
        } => Error::Refused { reason, message },
        other => map_transport(other),
    })?;
    // Belt and braces: the TLS verifier already pinned it.
    if tls::peer_key(connection.peer_certificates())? != server_key {
        connection
            .close(CloseCode::Unauthorized, "unexpected server key")
            .await;
        return Err(Error::InvalidKey);
    }
    // Checked again on the setup HelloAck (the server may be a different, older build now).
    let n = connection.negotiated();
    if !server_supports_setup(n.version) || !n.features.contains(Features::SETUP) {
        connection
            .close(CloseCode::NoError, "server too old for setup")
            .await;
        return Err(Error::UpdateRequired);
    }
    let first = match tokio::time::timeout(opts.reply_timeout, connection.recv_control()).await {
        Ok(Ok(m)) => m,
        Ok(Err(e)) => return Err(map_transport(e)),
        Err(_) => {
            connection.close(CloseCode::NoError, "timed out").await;
            return Err(Error::Timeout("setup authorization"));
        }
    };
    let Some(Body::Result(r)) = AuthMessage::from_control(&first)?.body else {
        connection
            .close(CloseCode::ProtocolError, "unexpected message")
            .await;
        return Err(Error::Protocol("expected an auth result"));
    };
    match AuthStatus::try_from(r.status).unwrap_or(AuthStatus::Unspecified) {
        AuthStatus::Ok => {
            let session = SetupSession::start_reading(connection, opts).await?;
            Ok(SetupAuth::Ready(session))
        }
        AuthStatus::PinRequired => Ok(SetupAuth::NeedsPin(AwaitingSetupPin {
            connection,
            session: None,
            opts: opts.clone(),
        })),
        AuthStatus::Revoked => Err(Error::Revoked),
        AuthStatus::NotAvailable => Err(Error::PinNotAvailable),
        _ => {
            connection
                .close(CloseCode::ProtocolError, "unexpected status")
                .await;
            Err(Error::Protocol("unexpected auth status on setup"))
        }
    }
}

/// A setup connection that waits for the PIN.
#[derive(Debug)]
pub struct AwaitingSetupPin {
    connection: Connection,
    session: Option<SetupSession>,
    opts: SetupConnectOptions,
}

impl AwaitingSetupPin {
    /// Send one PIN attempt (the exchange of §11.4: counted before it is checked, backoff, the
    /// fifth wrong PIN revokes the device). On [`PinReply::Accepted`] the server's first
    /// `SetupState` has been read, so [`into_session`](Self::into_session) can follow.
    pub async fn submit_pin(&mut self, pin: &Pin) -> Result<PinReply> {
        let reply = pin_exchange(&self.connection, pin, self.opts.reply_timeout)
            .await
            .map_err(|e| match e {
                Error::Transport(t) => map_transport(t),
                other => other,
            })?;
        if reply == PinReply::Accepted {
            let s = SetupSession::start_reading(self.connection.clone(), &self.opts).await?;
            self.session = Some(s);
        }
        Ok(reply)
    }

    /// True once the server accepted the PIN.
    pub fn is_accepted(&self) -> bool {
        self.session.is_some()
    }

    /// The authorized session. Fails unless the PIN was accepted.
    pub fn into_session(self) -> Result<SetupSession> {
        self.session
            .ok_or(Error::Protocol("the PIN was not accepted"))
    }

    /// Give up (closes the connection).
    pub async fn abandon(self) {
        self.connection.close(CloseCode::NoError, "cancelled").await;
    }
}

/// What the server pushes (or how the connection ended).
#[derive(Debug, Clone)]
pub enum SetupEvent {
    /// The setup state changed (also sent once on authorization).
    State(pb::SetupState),
    /// A job step.
    Progress(pb::SetupProgress),
    /// A job ended. The server closes the connection after the final one (`finished`).
    Result(pb::SetupResult),
    /// The connection ended. [`CloseInfo::code`] `SetupClosed` means setup is no longer open
    /// for this device: go to the normal login.
    Closed(CloseInfo),
}

/// An authorized setup connection (KeyOnly or after the PIN).
#[derive(Debug)]
pub struct SetupSession {
    connection: Connection,
    state: pb::SetupState,
    have_state: bool,
    next_id: u32,
    pending: Option<u32>,
    last_ack: Option<pb::SetupAck>,
    abandoned: VecDeque<u32>,
    events: VecDeque<SetupEvent>,
    closed: Option<CloseInfo>,
    request_timeout: Duration,
}

impl SetupSession {
    fn new(connection: Connection, opts: &SetupConnectOptions) -> Self {
        Self {
            connection,
            state: pb::SetupState::default(),
            have_state: false,
            next_id: 1,
            pending: None,
            last_ack: None,
            abandoned: VecDeque::new(),
            events: VecDeque::new(),
            closed: None,
            request_timeout: opts.request_timeout,
        }
    }

    /// The server sends `SetupState` right after authorization: read it before handing out
    /// the session, so [`state`](Self::state) is always real.
    async fn start_reading(connection: Connection, opts: &SetupConnectOptions) -> Result<Self> {
        let mut s = Self::new(connection, opts);
        let wait = opts.reply_timeout;
        let got = tokio::time::timeout(wait, async {
            while !s.have_state {
                s.pump().await?;
                if let Some(info) = &s.closed {
                    return Err(closed_error(info));
                }
            }
            Ok::<(), Error>(())
        })
        .await;
        match got {
            Ok(Ok(())) => {
                // That first state is the session's starting point, not news.
                s.events.clear();
                Ok(s)
            }
            Ok(Err(e)) => Err(e),
            Err(_) => {
                s.connection.close(CloseCode::NoError, "timed out").await;
                Err(Error::Timeout("first setup state"))
            }
        }
    }

    /// The latest state the server pushed.
    pub fn state(&self) -> &pb::SetupState {
        &self.state
    }

    /// Choose the PIN (KeyOnly connections must do this first; it also authorizes the rest of
    /// this connection). The returned ack carries the status (`PIN_ALREADY_SET`,
    /// `INVALID_ARGUMENT`, ...).
    pub async fn set_pin(&mut self, pin: &Pin) -> Result<pb::SetupAck> {
        let body = pb::setup_message::Body::SetPin(pb::SetupSetPin {
            pin: bytes::Bytes::copy_from_slice(pin.as_bytes()),
        });
        self.request(body).await
    }

    /// Start the desktop job with these options and the desktop user's password.
    pub async fn start(&mut self, opts: pb::SetupOptions, pw: &Password) -> Result<pb::SetupAck> {
        let body = pb::setup_message::Body::Start(pb::SetupStart {
            options: Some(opts),
            password: bytes::Bytes::copy_from_slice(pw.as_bytes()),
        });
        self.request(body).await
    }

    /// Cancel the running job (takes effect only while a privileged command runs; the result
    /// shows what happened).
    pub async fn cancel(&mut self) -> Result<pb::SetupAck> {
        self.request(pb::setup_message::Body::Cancel(pb::SetupCancel {}))
            .await
    }

    /// Finish setup (normally the server does it automatically after a successful job).
    pub async fn finish(&mut self) -> Result<pb::SetupAck> {
        self.request(pb::setup_message::Body::Finish(pb::SetupFinish {}))
            .await
    }

    /// The next push, or [`SetupEvent::Closed`] (repeatedly) once the connection has ended and
    /// everything it delivered was read. Cancel safe.
    pub async fn next_event(&mut self) -> Result<SetupEvent> {
        loop {
            if let Some(e) = self.events.pop_front() {
                return Ok(e);
            }
            if let Some(info) = &self.closed {
                return Ok(SetupEvent::Closed(info.clone()));
            }
            self.pump().await?;
        }
    }

    /// Close the connection normally (`Goodbye`).
    pub async fn close(self) {
        self.connection.close(CloseCode::NoError, "done").await;
    }

    async fn request(&mut self, body: pb::setup_message::Body) -> Result<pb::SetupAck> {
        if let Some(old) = self.pending.take() {
            // A previous call was dropped before its answer: tolerate that answer.
            if self.abandoned.len() >= MAX_ABANDONED {
                self.abandoned.pop_front();
            }
            self.abandoned.push_back(old);
        }
        if let Some(info) = &self.closed {
            return Err(closed_error(info));
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let mut msg = pb::ControlMessage::new(Ctl::Setup(pb::SetupMessage {
            request_id: id,
            body: Some(body),
        }));
        let sent = self.connection.send_control(&msg).await;
        scrub_control(&mut msg);
        drop(msg);
        if let Err(e) = sent {
            return Err(self.note_error(e));
        }
        self.pending = Some(id);
        let deadline = tokio::time::Instant::now() + self.request_timeout;
        loop {
            if let Some(ack) = self.take_ack(id) {
                return Ok(ack);
            }
            match tokio::time::timeout_at(deadline, self.pump()).await {
                Ok(r) => r?,
                Err(_) => return Err(Error::Timeout("setup request")),
            }
            if let Some(info) = &self.closed
                && self.last_ack.is_none()
            {
                return Err(closed_error(info));
            }
        }
    }

    /// The ack stored by `pump` for the outstanding request `id`.
    fn take_ack(&mut self, id: u32) -> Option<pb::SetupAck> {
        if self.pending == Some(id)
            && let Some(ack) = self.last_ack.take()
        {
            self.pending = None;
            return Some(ack);
        }
        None
    }

    fn push_event(&mut self, e: SetupEvent) -> Result<()> {
        if self.events.len() >= MAX_QUEUED_EVENTS {
            return Err(Error::Protocol("too many unread setup events"));
        }
        self.events.push_back(e);
        Ok(())
    }

    /// Read and dispatch one message. A closed connection is recorded in `closed`, not an
    /// error here: the callers decide what it means to them.
    async fn pump(&mut self) -> Result<()> {
        let m = match self.connection.recv_control().await {
            Ok(m) => m,
            Err(hx_transport::Error::Closed(info)) => {
                self.closed = Some(info);
                return Ok(());
            }
            Err(e) => return Err(map_transport(e)),
        };
        let sm = match m.message {
            Some(Ctl::Setup(sm)) => sm,
            // The server says goodbye before it closes; the close follows.
            Some(Ctl::Goodbye(_)) => return Ok(()),
            _ => return Err(Error::Protocol("unexpected message on a setup connection")),
        };
        if sm.direction() != Some(MgmtDirection::ServerToClient) {
            return Err(Error::Protocol("client-bound setup message expected"));
        }
        match sm.body {
            Some(pb::setup_message::Body::State(s)) => {
                self.state = s.clone();
                self.have_state = true;
                self.push_event(SetupEvent::State(s))
            }
            Some(pb::setup_message::Body::Progress(p)) => self.push_event(SetupEvent::Progress(p)),
            Some(pb::setup_message::Body::Result(r)) => self.push_event(SetupEvent::Result(r)),
            Some(pb::setup_message::Body::Ack(a)) => {
                if self.pending == Some(sm.request_id) {
                    self.last_ack = Some(a);
                    Ok(())
                } else if let Some(i) = self.abandoned.iter().position(|x| *x == sm.request_id) {
                    self.abandoned.remove(i);
                    Ok(())
                } else {
                    Err(Error::Protocol("unsolicited setup answer"))
                }
            }
            _ => Err(Error::Protocol("client-bound setup message expected")),
        }
    }

    fn note_error(&mut self, e: hx_transport::Error) -> Error {
        if let hx_transport::Error::Closed(info) = &e {
            self.closed = Some(info.clone());
        }
        map_transport(e)
    }
}

fn closed_error(info: &CloseInfo) -> Error {
    if info.code == CloseCode::SetupClosed {
        Error::SetupClosed
    } else {
        Error::Transport(hx_transport::Error::Closed(info.clone()))
    }
}

fn map_transport(e: hx_transport::Error) -> Error {
    match e {
        hx_transport::Error::Closed(info) if info.code == CloseCode::SetupClosed => {
            Error::SetupClosed
        }
        other => Error::Transport(other),
    }
}

/// Zero a `Bytes` buffer if this is its only owner (otherwise a clone still holds it and the
/// buffer is merely released).
fn wipe(b: &mut bytes::Bytes) {
    if let Ok(mut m) = std::mem::take(b).try_into_mut() {
        m.as_mut().zeroize();
    }
}

/// Overwrite the secret bytes of a message that was just sent (PIN, password, auth envelope).
pub(crate) fn scrub_control(m: &mut pb::ControlMessage) {
    match &mut m.message {
        Some(Ctl::Setup(s)) => match &mut s.body {
            Some(pb::setup_message::Body::SetPin(p)) => wipe(&mut p.pin),
            Some(pb::setup_message::Body::Start(st)) => wipe(&mut st.password),
            _ => {}
        },
        Some(Ctl::Auth(o) | Ctl::Pairing(o)) => wipe(&mut o.data),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrubbing_empties_the_secret_fields_of_a_sent_message() {
        let mut m = pb::ControlMessage::new(Ctl::Setup(pb::SetupMessage {
            request_id: 3,
            body: Some(pb::setup_message::Body::Start(pb::SetupStart {
                options: None,
                password: bytes::Bytes::copy_from_slice(b"hunter2"),
            })),
        }));
        scrub_control(&mut m);
        let Some(Ctl::Setup(s)) = m.message else {
            panic!("setup")
        };
        let Some(pb::setup_message::Body::Start(st)) = s.body else {
            panic!("start")
        };
        assert!(st.password.is_empty());

        let mut a = pb::ControlMessage::new(Ctl::Setup(pb::SetupMessage {
            request_id: 4,
            body: Some(pb::setup_message::Body::SetPin(pb::SetupSetPin {
                pin: bytes::Bytes::copy_from_slice(b"482913"),
            })),
        }));
        scrub_control(&mut a);
        let Some(Ctl::Setup(s)) = a.message else {
            panic!("setup")
        };
        let Some(pb::setup_message::Body::SetPin(p)) = s.body else {
            panic!("pin")
        };
        assert!(p.pin.is_empty());
    }
}
