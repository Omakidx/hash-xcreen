//! Client side of a session: pinned mutual TLS, then the PIN exchange (protocol §11.4).

use std::{sync::Arc, time::Duration};

use hx_proto::{
    channel::CloseCode,
    pb::{self, Intent},
    version::{Features, capabilities},
};
use hx_transport::{Client, ClientHello, ClientOptions, Connection, Target, TransportPreference};

use crate::{
    error::{Error, Result},
    keys::{IdentityKey, PublicKey},
    secrets::Pin,
    tls,
    wire::{AuthMessage, AuthStatus, PinAttempt, auth_message::Body},
};

/// Options of [`connect_session`].
#[derive(Clone, Debug)]
pub struct SessionOptions {
    /// Transport to use.
    pub preference: TransportPreference,
    /// Label shown by the server in its device list (at most 64 bytes).
    pub device_name: String,
    /// Software string for `Hello` (at most 128 bytes).
    pub software: String,
    /// What this client can decode and do.
    pub capabilities: pb::Capabilities,
    /// Bound on each reply from the server during the PIN exchange.
    pub reply_timeout: Duration,
    /// Transport tunables.
    pub transport: ClientOptions,
}

impl Default for SessionOptions {
    fn default() -> Self {
        Self {
            preference: TransportPreference::Auto,
            device_name: "device".into(),
            software: concat!("hx-crypto ", env!("CARGO_PKG_VERSION")).into(),
            capabilities: capabilities(&[], Features::NONE),
            reply_timeout: Duration::from_secs(20),
            transport: ClientOptions::default(),
        }
    }
}

/// The server's answer to one PIN attempt that did not end the exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinReply {
    /// Accepted: the server authorized the connection.
    Accepted,
    /// Wrong PIN; `attempts_left` more wrong ones are allowed before the device is revoked.
    /// Wait `retry_after` before the next attempt (earlier ones are answered `Backoff`).
    Wrong {
        /// Attempts left before revocation.
        attempts_left: u32,
        /// Required wait.
        retry_after: Duration,
    },
    /// Sent too soon after a failure; the PIN was not checked and nothing was counted.
    Backoff {
        /// Remaining wait.
        retry_after: Duration,
    },
}

/// A connection whose server is authenticated (pinned key) and which waits for the PIN.
#[derive(Debug)]
pub struct AwaitingPin {
    connection: Connection,
    accepted: bool,
    reply_timeout: Duration,
}

/// Connect to a paired server (key pinned, protocol §11.1) and return the connection waiting
/// for the PIN. Fails if the server presents any other key: never fall back to another key.
pub async fn connect_session(
    target: &Target,
    device: &Arc<IdentityKey>,
    server_key: PublicKey,
    opts: &SessionOptions,
) -> Result<AwaitingPin> {
    let mut transport = opts.transport.clone();
    transport.preference = opts.preference;
    let client = Client::new(tls::client_config_session(device, server_key)?, transport);
    let hello = ClientHello {
        capabilities: opts.capabilities.clone(),
        intent: Intent::Session,
        software: opts.software.clone(),
        device_name: opts.device_name.clone(),
    };
    let connection = client.connect(target, &hello).await.map_err(|e| match e {
        hx_transport::Error::Refused {
            reason, message, ..
        } => Error::Refused { reason, message },
        other => Error::Transport(other),
    })?;
    // Belt and braces: the TLS verifier already pinned it.
    if tls::peer_key(connection.peer_certificates())? != server_key {
        connection
            .close(CloseCode::Unauthorized, "unexpected server key")
            .await;
        return Err(Error::InvalidKey);
    }
    Ok(AwaitingPin {
        connection,
        accepted: false,
        reply_timeout: opts.reply_timeout,
    })
}

impl AwaitingPin {
    /// Send one PIN attempt and wait for the verdict. A revoked device is an error
    /// ([`Error::Revoked`]) and the connection is closed by the server.
    pub async fn submit(&mut self, pin: &Pin) -> Result<PinReply> {
        let msg = AuthMessage::new(Body::Pin(PinAttempt {
            pin: pin.as_bytes().to_vec(),
        }))
        .into_control()?;
        self.connection.send_control(&msg).await?;
        drop(msg);
        let reply = tokio::time::timeout(self.reply_timeout, self.connection.recv_control())
            .await
            .map_err(|_| Error::Timeout("PIN reply"))??;
        let Some(Body::Result(r)) = AuthMessage::from_control(&reply)?.body else {
            return Err(Error::Protocol("expected an auth result"));
        };
        let status = AuthStatus::try_from(r.status).unwrap_or(AuthStatus::Unspecified);
        let wait = Duration::from_millis(u64::from(r.retry_after_ms));
        match status {
            AuthStatus::Ok => {
                self.accepted = true;
                Ok(PinReply::Accepted)
            }
            AuthStatus::WrongPin => Ok(PinReply::Wrong {
                attempts_left: r.attempts_left,
                retry_after: wait,
            }),
            AuthStatus::Backoff => Ok(PinReply::Backoff { retry_after: wait }),
            AuthStatus::Revoked => Err(Error::Revoked),
            AuthStatus::NotAvailable => Err(Error::PinNotAvailable),
            // Only an INTENT_SETUP server sends it; a session server never does.
            AuthStatus::PinRequired | AuthStatus::Unspecified => {
                Err(Error::Protocol("unknown auth status"))
            }
        }
    }

    /// True once the server accepted the PIN.
    pub fn is_accepted(&self) -> bool {
        self.accepted
    }

    /// The authorized connection. Fails unless the server accepted the PIN: a connection must
    /// not be used for channels before that (protocol §2.1).
    pub fn into_connection(self) -> Result<Connection> {
        if self.accepted {
            Ok(self.connection)
        } else {
            Err(Error::Protocol("the PIN was not accepted"))
        }
    }

    /// Give up (closes the connection).
    pub async fn abandon(self) {
        self.connection.close(CloseCode::NoError, "cancelled").await;
    }
}

/// One-shot convenience: connect, submit `pin` once, return the authorized connection or
/// [`Error::WrongPin`] / [`Error::Backoff`]. UIs that want to retry on the same connection
/// use [`connect_session`] and [`AwaitingPin::submit`].
pub async fn connect_with_pin(
    target: &Target,
    device: &Arc<IdentityKey>,
    server_key: PublicKey,
    pin: &Pin,
    opts: &SessionOptions,
) -> Result<Connection> {
    let mut a = connect_session(target, device, server_key, opts).await?;
    match a.submit(pin).await? {
        PinReply::Accepted => a.into_connection(),
        PinReply::Wrong {
            attempts_left,
            retry_after,
        } => {
            a.abandon().await;
            Err(Error::WrongPin {
                attempts_left,
                retry_after,
            })
        }
        PinReply::Backoff { retry_after } => {
            a.abandon().await;
            Err(Error::Backoff { retry_after })
        }
    }
}
