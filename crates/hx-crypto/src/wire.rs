//! Messages inside the `pairing` (field 100) and `auth` (field 101) envelopes
//! (protocol §11.3, §11.4). prost-derived; field numbers are part of the protocol.

use std::fmt;

use bytes::Bytes;
use hx_proto::{
    channel::MAX_OPAQUE,
    pb::{ControlMessage, Opaque, control_message::Message as Ctl},
};
use prost::Message;
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// Pairing secret kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum PairMode {
    /// Invalid.
    Unspecified = 0,
    /// Long random token.
    Token = 1,
    /// Short human code.
    Code = 2,
}

/// Why a pairing failed (deliberately coarse).
#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum PairFailureReason {
    /// Invalid.
    Unspecified = 0,
    /// Wrong or expired secret, or interception: indistinguishable on purpose.
    Failed = 1,
    /// The server cannot take the attempt now.
    Busy = 2,
    /// Unexpected, repeated or malformed message.
    Protocol = 3,
}

/// Outcome of a PIN attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum AuthStatus {
    /// Invalid.
    Unspecified = 0,
    /// Accepted; the connection is authorized.
    Ok = 1,
    /// Wrong PIN.
    WrongPin = 2,
    /// Too soon after the last failure; not evaluated.
    Backoff = 3,
    /// The device is revoked.
    Revoked = 4,
    /// The server cannot verify PINs.
    NotAvailable = 5,
    /// Protocol 1.3, sent only on an `INTENT_SETUP` connection whose device already has a PIN:
    /// the setup connection needs the PIN first (the exchange is then exactly §11.4).
    PinRequired = 6,
    /// Protocol 1.3, sent only on an `INTENT_REINSTATE` connection: send the account password.
    PasswordRequired = 7,
    /// Protocol 1.3, `INTENT_REINSTATE` only: the password was wrong.
    WrongPassword = 8,
}

/// Envelope body of `ControlMessage.pairing`.
#[derive(Clone, PartialEq, Message)]
pub struct PairingMessage {
    /// The message.
    #[prost(oneof = "pairing_message::Body", tags = "1, 2, 3, 4, 5")]
    pub body: Option<pairing_message::Body>,
}

/// Nested types of [`PairingMessage`].
pub mod pairing_message {
    /// One of the pairing messages.
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Body {
        /// Client opens.
        #[prost(message, tag = "1")]
        Start(super::PairStart),
        /// Server answers.
        #[prost(message, tag = "2")]
        ServerHello(super::PairServerHello),
        /// Client proves.
        #[prost(message, tag = "3")]
        ClientConfirm(super::PairConfirm),
        /// Server proves.
        #[prost(message, tag = "4")]
        ServerConfirm(super::PairConfirm),
        /// Server aborts.
        #[prost(message, tag = "5")]
        Failure(super::PairFailure),
    }
}

/// Client to server: SPAKE2 message and identity.
#[derive(Clone, PartialEq, Message)]
pub struct PairStart {
    /// [`PairMode`].
    #[prost(enumeration = "PairMode", tag = "1")]
    pub mode: i32,
    /// Token id (8 bytes); empty for a code.
    #[prost(bytes = "vec", tag = "2")]
    pub token_id: Vec<u8>,
    /// SPAKE2 message (33 bytes).
    #[prost(bytes = "vec", tag = "3")]
    pub spake: Vec<u8>,
    /// Device label (at most 64 bytes).
    #[prost(string, tag = "4")]
    pub device_name: String,
}

/// Server to client: SPAKE2 message and the server's label.
#[derive(Clone, PartialEq, Message)]
pub struct PairServerHello {
    /// SPAKE2 message (33 bytes).
    #[prost(bytes = "vec", tag = "1")]
    pub spake: Vec<u8>,
    /// Server label (at most 64 bytes).
    #[prost(string, tag = "2")]
    pub server_name: String,
}

/// Confirmation MAC (client's in field 3, server's in field 4 of the envelope).
#[derive(Clone, PartialEq, Message)]
pub struct PairConfirm {
    /// HMAC-SHA-256 (32 bytes).
    #[prost(bytes = "vec", tag = "1")]
    pub mac: Vec<u8>,
}

/// Server aborts the exchange.
#[derive(Clone, PartialEq, Message)]
pub struct PairFailure {
    /// [`PairFailureReason`].
    #[prost(enumeration = "PairFailureReason", tag = "1")]
    pub reason: i32,
}

/// Envelope body of `ControlMessage.auth`.
#[derive(Clone, PartialEq, Message)]
pub struct AuthMessage {
    /// The message.
    #[prost(oneof = "auth_message::Body", tags = "1, 2, 3")]
    pub body: Option<auth_message::Body>,
}

/// Nested types of [`AuthMessage`].
pub mod auth_message {
    /// One of the auth messages.
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Body {
        /// Client sends a PIN.
        #[prost(message, tag = "1")]
        Pin(super::PinAttempt),
        /// Server answers.
        #[prost(message, tag = "2")]
        Result(super::AuthResult),
        /// Client sends the account password (`INTENT_REINSTATE`, protocol 1.3).
        #[prost(message, tag = "3")]
        Password(super::PasswordAttempt),
    }
}

/// A PIN attempt. Hand-written `Message` so that `Debug` never shows the PIN and the bytes
/// are zeroized when the value is dropped. Wire format: `bytes pin = 1`.
#[derive(Clone, PartialEq, Default)]
pub struct PinAttempt {
    /// 6 to 16 ASCII numerals.
    pub pin: Vec<u8>,
}

impl fmt::Debug for PinAttempt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PinAttempt { pin: [redacted] }")
    }
}

impl Drop for PinAttempt {
    fn drop(&mut self) {
        self.pin.zeroize();
    }
}

impl Message for PinAttempt {
    fn encode_raw(&self, buf: &mut impl prost::bytes::BufMut) {
        if !self.pin.is_empty() {
            prost::encoding::bytes::encode(1, &self.pin, buf);
        }
    }

    fn merge_field(
        &mut self,
        tag: u32,
        wire_type: prost::encoding::WireType,
        buf: &mut impl prost::bytes::Buf,
        ctx: prost::encoding::DecodeContext,
    ) -> std::result::Result<(), prost::DecodeError> {
        match tag {
            1 => prost::encoding::bytes::merge(wire_type, &mut self.pin, buf, ctx),
            _ => prost::encoding::skip_field(wire_type, tag, buf, ctx),
        }
    }

    fn encoded_len(&self) -> usize {
        if self.pin.is_empty() {
            0
        } else {
            prost::encoding::bytes::encoded_len(1, &self.pin)
        }
    }

    fn clear(&mut self) {
        self.pin.zeroize();
        self.pin.clear();
    }
}

/// A password attempt (`INTENT_REINSTATE`, protocol 1.3). Hand-written like [`PinAttempt`]:
/// `Debug` never shows the password and the bytes are zeroized on drop. Wire format:
/// `bytes password = 1` (1 to 511 bytes, UTF-8, no NUL, CR or LF; checked by the receiver).
#[derive(Clone, PartialEq, Default)]
pub struct PasswordAttempt {
    /// The account password.
    pub password: Vec<u8>,
}

impl fmt::Debug for PasswordAttempt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PasswordAttempt { password: [redacted] }")
    }
}

impl Drop for PasswordAttempt {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

impl Message for PasswordAttempt {
    fn encode_raw(&self, buf: &mut impl prost::bytes::BufMut) {
        if !self.password.is_empty() {
            prost::encoding::bytes::encode(1, &self.password, buf);
        }
    }

    fn merge_field(
        &mut self,
        tag: u32,
        wire_type: prost::encoding::WireType,
        buf: &mut impl prost::bytes::Buf,
        ctx: prost::encoding::DecodeContext,
    ) -> std::result::Result<(), prost::DecodeError> {
        match tag {
            1 => prost::encoding::bytes::merge(wire_type, &mut self.password, buf, ctx),
            _ => prost::encoding::skip_field(wire_type, tag, buf, ctx),
        }
    }

    fn encoded_len(&self) -> usize {
        if self.password.is_empty() {
            0
        } else {
            prost::encoding::bytes::encoded_len(1, &self.password)
        }
    }

    fn clear(&mut self) {
        self.password.zeroize();
        self.password.clear();
    }
}

/// Server's answer to a PIN attempt.
#[derive(Clone, PartialEq, Message)]
pub struct AuthResult {
    /// [`AuthStatus`].
    #[prost(enumeration = "AuthStatus", tag = "1")]
    pub status: i32,
    /// Wrong PINs still allowed before revocation.
    #[prost(uint32, tag = "2")]
    pub attempts_left: u32,
    /// For `Backoff`: milliseconds to wait.
    #[prost(uint32, tag = "3")]
    pub retry_after_ms: u32,
}

fn opaque<M: Message>(m: &M) -> Result<Opaque> {
    let data = m.encode_to_vec();
    if data.len() > MAX_OPAQUE {
        return Err(Error::Protocol("envelope too large"));
    }
    Ok(Opaque {
        data: Bytes::from(data),
    })
}

fn unwrap_opaque<M: Message + Default>(o: &Opaque) -> Result<M> {
    if o.data.len() > MAX_OPAQUE {
        return Err(Error::Protocol("envelope too large"));
    }
    M::decode(o.data.as_ref()).map_err(|_| Error::Protocol("malformed message"))
}

impl PairingMessage {
    /// Wrap a body.
    pub fn new(body: pairing_message::Body) -> Self {
        Self { body: Some(body) }
    }

    /// As a control message.
    pub fn into_control(self) -> Result<ControlMessage> {
        Ok(ControlMessage::new(Ctl::Pairing(opaque(&self)?)))
    }

    /// Decode a received control message: only `pairing` is accepted.
    pub fn from_control(m: &ControlMessage) -> Result<Self> {
        match &m.message {
            Some(Ctl::Pairing(o)) => unwrap_opaque(o),
            _ => Err(Error::Protocol("expected a pairing message")),
        }
    }
}

impl AuthMessage {
    /// Wrap a body.
    pub fn new(body: auth_message::Body) -> Self {
        Self { body: Some(body) }
    }

    /// As a control message.
    pub fn into_control(self) -> Result<ControlMessage> {
        Ok(ControlMessage::new(Ctl::Auth(opaque(&self)?)))
    }

    /// Decode a received control message: only `auth` is accepted.
    pub fn from_control(m: &ControlMessage) -> Result<Self> {
        match &m.message {
            Some(Ctl::Auth(o)) => unwrap_opaque(o),
            _ => Err(Error::Protocol("expected an auth message")),
        }
    }
}
