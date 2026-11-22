//! Client side of reinstating a device after a PIN lockout (`INTENT_REINSTATE`, protocol 1.3,
//! §11.7).
//!
//! The fifth wrong PIN revokes a device. The owner gets back in from that same device with the
//! desktop account password: [`reinstate`] makes one attempt on a fresh connection, or
//! [`connect_reinstate`] keeps the connection for up to [`MAX_ATTEMPTS`] attempts. On
//! [`ReinstateOutcome::Reinstated`] **no session exists**: the caller then does a normal PIN
//! login (`connect_session`) with the existing PIN.
//!
//! The intent is sent only to a server that showed version 1.3 or newer
//! (`confirmed_server_version`); otherwise [`Error::UpdateRequired`] (an older server would
//! hard-close on the unknown intent, §4.7).

use std::{sync::Arc, time::Duration};

use hx_proto::{
    channel::CloseCode,
    pb::{Intent, RefuseReason},
    version::{Features, ProtocolVersion, capabilities},
};
use hx_transport::{Client, ClientHello, ClientOptions, Connection, Target, TransportPreference};

use crate::{
    error::{Error, Result},
    keys::{IdentityKey, PublicKey},
    setup::{Password, scrub_control, server_supports_setup},
    tls,
    wire::{AuthMessage, AuthStatus, PasswordAttempt, auth_message::Body},
};

/// Attempts the server accepts on one connection (§11.7); the client never sends more.
pub const MAX_ATTEMPTS: u32 = 3;

/// Options of [`reinstate`] and [`connect_reinstate`].
#[derive(Clone, Debug)]
pub struct ReinstateOptions {
    /// The version the server showed on this device's last successful pairing or session
    /// ([`crate::PairedServer::server_version`], [`crate::AwaitingPin::server_version`]).
    /// `None` or below 1.3 makes the calls fail with [`Error::UpdateRequired`] without
    /// connecting.
    pub confirmed_server_version: Option<ProtocolVersion>,
    /// Transport to use.
    pub preference: TransportPreference,
    /// Label shown by the server in its device list (at most 64 bytes).
    pub device_name: String,
    /// Software string for `Hello` (at most 128 bytes).
    pub software: String,
    /// Bound on each reply from the server.
    pub reply_timeout: Duration,
    /// Transport tunables.
    pub transport: ClientOptions,
}

impl Default for ReinstateOptions {
    fn default() -> Self {
        Self {
            confirmed_server_version: None,
            preference: TransportPreference::Auto,
            device_name: "device".into(),
            software: concat!("hx-crypto ", env!("CARGO_PKG_VERSION")).into(),
            reply_timeout: Duration::from_secs(20),
            transport: ClientOptions::default(),
        }
    }
}

/// How an attempt ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReinstateOutcome {
    /// The device is active again (PIN counter reset). Log in with the existing PIN now.
    Reinstated,
    /// Wrong password; `attempts_left` more are allowed in the server's hourly budget.
    WrongPassword {
        /// Attempts left in the server's per-device hourly budget.
        attempts_left: u32,
    },
    /// Over a limit: the password was not checked and nothing was counted.
    Backoff {
        /// Remaining wait.
        retry_after: Duration,
    },
    /// The server cannot check passwords now (privd down or locked, or no password verifier);
    /// the connection ended. Ask the administrator (`hx-agent devices reinstate`) if it
    /// persists.
    NotAvailable {
        /// Wait suggested by the server (zero if it did not say).
        retry_after: Duration,
    },
    /// The server refused the intent: this device does not qualify (not locked out, revoked
    /// by someone else, too long ago, or the server is not set up for it). Deliberately
    /// indistinguishable from an unknown key.
    Refused,
}

/// Result of [`connect_reinstate`].
#[derive(Debug)]
pub enum ReinstateConnect {
    /// The server asked for the password.
    Ready(AwaitingPassword),
    /// Refused uniformly (`UNAUTHORIZED`): see [`ReinstateOutcome::Refused`].
    Refused,
}

/// One attempt on a fresh connection.
pub async fn reinstate(
    target: &Target,
    device: &Arc<IdentityKey>,
    server_key: PublicKey,
    password: &Password,
    opts: &ReinstateOptions,
) -> Result<ReinstateOutcome> {
    match connect_reinstate(target, device, server_key, opts).await? {
        ReinstateConnect::Refused => Ok(ReinstateOutcome::Refused),
        ReinstateConnect::Ready(mut a) => {
            let out = a.submit(password).await;
            a.abandon().await;
            out
        }
    }
}

/// Connect and read the server's request for the password.
pub async fn connect_reinstate(
    target: &Target,
    device: &Arc<IdentityKey>,
    server_key: PublicKey,
    opts: &ReinstateOptions,
) -> Result<ReinstateConnect> {
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
        capabilities: capabilities(&[], Features::NONE),
        intent: Intent::Reinstate,
        software: opts.software.clone(),
        device_name: opts.device_name.clone(),
    };
    let connection = match client.connect(target, &hello).await {
        Ok(c) => c,
        Err(hx_transport::Error::Refused {
            reason: RefuseReason::Unauthorized,
            ..
        }) => return Ok(ReinstateConnect::Refused),
        Err(hx_transport::Error::Refused {
            reason, message, ..
        }) => return Err(Error::Refused { reason, message }),
        Err(e) => return Err(Error::Transport(e)),
    };
    if tls::peer_key(connection.peer_certificates())? != server_key {
        connection
            .close(CloseCode::Unauthorized, "unexpected server key")
            .await;
        return Err(Error::InvalidKey);
    }
    if !server_supports_setup(connection.negotiated().version) {
        connection.close(CloseCode::NoError, "server too old").await;
        return Err(Error::UpdateRequired);
    }
    let first = match tokio::time::timeout(opts.reply_timeout, connection.recv_control()).await {
        Ok(Ok(m)) => m,
        Ok(Err(e)) => return Err(Error::Transport(e)),
        Err(_) => {
            connection.close(CloseCode::NoError, "timed out").await;
            return Err(Error::Timeout("password request"));
        }
    };
    let Some(Body::Result(r)) = AuthMessage::from_control(&first)?.body else {
        connection
            .close(CloseCode::ProtocolError, "unexpected message")
            .await;
        return Err(Error::Protocol("expected an auth result"));
    };
    if AuthStatus::try_from(r.status) != Ok(AuthStatus::PasswordRequired) {
        connection
            .close(CloseCode::ProtocolError, "unexpected status")
            .await;
        return Err(Error::Protocol("expected PASSWORD_REQUIRED"));
    }
    Ok(ReinstateConnect::Ready(AwaitingPassword {
        connection,
        sent: 0,
        done: false,
        attempts_left: r.attempts_left,
        reply_timeout: opts.reply_timeout,
    }))
}

/// A connection whose server asked for the password.
#[derive(Debug)]
pub struct AwaitingPassword {
    connection: Connection,
    sent: u32,
    done: bool,
    attempts_left: u32,
    reply_timeout: Duration,
}

impl AwaitingPassword {
    /// Attempts left in the server's per-device hourly budget, as last reported.
    pub fn attempts_left(&self) -> u32 {
        self.attempts_left
    }

    /// Send one attempt. At most [`MAX_ATTEMPTS`] per connection; `Reinstated` and
    /// `NotAvailable` end the exchange, after which this fails with a protocol error.
    pub async fn submit(&mut self, password: &Password) -> Result<ReinstateOutcome> {
        if self.done {
            return Err(Error::Protocol("the reinstate exchange has ended"));
        }
        if self.sent >= MAX_ATTEMPTS {
            return Err(Error::Protocol("at most 3 attempts per connection"));
        }
        self.sent += 1;
        let mut msg = AuthMessage::new(Body::Password(PasswordAttempt {
            password: password.as_bytes().to_vec(),
        }))
        .into_control()?;
        let sent = self.connection.send_control(&msg).await;
        scrub_control(&mut msg);
        drop(msg);
        sent?;
        let reply = tokio::time::timeout(self.reply_timeout, self.connection.recv_control())
            .await
            .map_err(|_| Error::Timeout("password reply"))??;
        let Some(Body::Result(r)) = AuthMessage::from_control(&reply)?.body else {
            return Err(Error::Protocol("expected an auth result"));
        };
        let wait = Duration::from_millis(u64::from(r.retry_after_ms));
        match AuthStatus::try_from(r.status).unwrap_or(AuthStatus::Unspecified) {
            AuthStatus::Ok => {
                self.done = true;
                Ok(ReinstateOutcome::Reinstated)
            }
            AuthStatus::WrongPassword => {
                self.attempts_left = r.attempts_left;
                Ok(ReinstateOutcome::WrongPassword {
                    attempts_left: r.attempts_left,
                })
            }
            AuthStatus::Backoff => Ok(ReinstateOutcome::Backoff { retry_after: wait }),
            AuthStatus::NotAvailable => {
                self.done = true;
                Ok(ReinstateOutcome::NotAvailable { retry_after: wait })
            }
            AuthStatus::Revoked => {
                self.done = true;
                Err(Error::Revoked)
            }
            _ => Err(Error::Protocol("unknown auth status")),
        }
    }

    /// Close the connection.
    pub async fn abandon(self) {
        self.connection.close(CloseCode::NoError, "done").await;
    }
}
