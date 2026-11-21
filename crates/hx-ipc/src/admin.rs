//! The `hx-gatewayd` admin socket (`docs/ipc.md` section 9).
//!
//! Same framing, `Hello`, error model, limits and `recvmsg` rule as the privd socket, with its
//! own command set. The framing types ([`crate::privd::PrivdPolicy`], kinds, limits) and the
//! secret frame are shared; the messages are `hx.gatewayd_admin.v1`. The error type
//! ([`crate::privd::pb::Error`]) and the `Hello`, `Cancel`, `Ping` and `Pong` frames are the
//! privd ones.

use prost::Message;

use crate::error::FrameError;
use crate::frame::{RawFrame, encode_frame};
use crate::privd::{
    KIND_MESSAGE, KIND_SECRET, MAX_ERROR_MESSAGE_LEN, MAX_MESSAGE_LENGTH, MAX_SOFTWARE_LEN, Side,
    pb as privd_pb,
};
use crate::secret::{Secret, SecretFrame};

/// Generated `hx.gatewayd_admin.v1` types.
pub use crate::generated_privd::hx::gatewayd_admin::v1 as pb;

/// Largest pairing token accepted in a secret frame.
pub const MAX_PAIRING_TOKEN_BYTES: usize = 1_024;
/// Largest verifier in `SetPinVerifier` / `SetPasswordVerifier` (the format is 1B's).
pub const MAX_VERIFIER_BYTES: usize = 128;
/// Length of a device id.
pub const DEVICE_ID_LEN: usize = 16;

/// A decoded, validated incoming frame.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // one value per received frame; boxing would only add an allocation
pub enum Incoming {
    /// A kind-1 protobuf frame.
    Message(pb::Frame),
    /// A kind-2 raw secret (the pairing token).
    Secret(SecretFrame),
}

type Check = Result<(), FrameError>;

fn require(cond: bool, what: &'static str) -> Check {
    if cond {
        Ok(())
    } else {
        Err(FrameError::Invalid(what))
    }
}

/// Decodes and validates one admin-socket frame received on `side`.
pub fn decode(raw: RawFrame, side: Side) -> Result<Incoming, FrameError> {
    match raw.kind {
        KIND_MESSAGE => {
            crate::prescan::check_admin_frame(&raw.body, 1)?;
            let frame = pb::Frame::decode(raw.body.as_ref())
                .map_err(|e| FrameError::Decode(e.to_string()))?;
            validate_frame(&frame, side)?;
            Ok(Incoming::Message(frame))
        }
        KIND_SECRET if side == Side::Server => {
            Ok(Incoming::Secret(SecretFrame::from_body(raw.body)?))
        }
        KIND_SECRET => Err(FrameError::KindNotAllowed(KIND_SECRET)),
        k => Err(FrameError::UnknownKind(k)),
    }
}

/// Encodes a kind-1 frame for the peer on `to`, after checking it would be accepted there.
pub fn encode_message(frame: &pb::Frame, to: Side) -> Result<Vec<u8>, FrameError> {
    validate_frame(frame, to)?;
    encode_frame(KIND_MESSAGE, &frame.encode_to_vec(), MAX_MESSAGE_LENGTH)
}

/// Structure and field rules of an admin frame headed for `to`.
pub fn validate_frame(frame: &pb::Frame, to: Side) -> Check {
    use pb::frame::Frame as F;
    let Some(variant) = &frame.frame else {
        return Err(FrameError::Invalid("frame: no variant set"));
    };
    let towards_server = matches!(
        variant,
        F::Hello(_) | F::Request(_) | F::Cancel(_) | F::Ping(_) | F::Pong(_)
    );
    let towards_client = matches!(
        variant,
        F::HelloAck(_) | F::Response(_) | F::Ping(_) | F::Pong(_)
    );
    require(
        match to {
            Side::Server => towards_server,
            Side::Client => towards_client,
        },
        "frame: variant not valid in this direction",
    )?;
    match variant {
        F::Hello(h) => require(h.software.len() <= MAX_SOFTWARE_LEN, "hello.software"),
        F::HelloAck(a) => require(
            a.gatewayd_version.len() <= MAX_SOFTWARE_LEN,
            "hello_ack.gatewayd_version",
        ),
        F::Request(r) => validate_request(r),
        F::Response(r) => match &r.result {
            None => Err(FrameError::Invalid("response: no result set")),
            Some(pb::response::Result::Error(e)) => {
                require(
                    e.code != 0 && privd_pb::ErrorCode::try_from(e.code).is_ok(),
                    "error.code",
                )?;
                require(e.message.len() <= MAX_ERROR_MESSAGE_LEN, "error.message")
            }
            Some(_) => Ok(()),
        },
        F::Cancel(_) | F::Ping(_) | F::Pong(_) => Ok(()),
    }
}

/// Checks an admin `Request`: non-zero id, one command, argument rules and secret slots.
pub fn validate_request(req: &pb::Request) -> Check {
    use pb::request::Command as C;
    require(req.request_id != 0, "request.request_id")?;
    let Some(cmd) = &req.command else {
        return Err(FrameError::Invalid("request: no command set"));
    };
    match cmd {
        C::RevokeDevice(r) => require(
            r.device_id.len() == DEVICE_ID_LEN,
            "revoke_device.device_id",
        )?,
        C::ReinstateDevice(r) => require(
            r.device_id.len() == DEVICE_ID_LEN,
            "reinstate_device.device_id",
        )?,
        C::SetPinVerifier(r) => {
            use pb::set_pin_verifier_request::Target;
            match &r.target {
                Some(Target::DeviceId(id)) => {
                    require(id.len() == DEVICE_ID_LEN, "set_pin_verifier.device_id")?
                }
                Some(Target::All(true)) => {}
                _ => return Err(FrameError::Invalid("set_pin_verifier.target")),
            }
            require(
                (1..=MAX_VERIFIER_BYTES).contains(&r.verifier.len()),
                "set_pin_verifier.verifier",
            )?;
        }
        C::SetPasswordVerifier(r) => require(
            (1..=MAX_VERIFIER_BYTES).contains(&r.verifier.len()),
            "set_password_verifier.verifier",
        )?,
        C::CreatePairingToken(r) => require(
            (60..=900).contains(&r.expires_in_s),
            "create_pairing_token.expires_in_s",
        )?,
        C::CreatePairingCode(r) => require(
            (60..=900).contains(&r.expires_in_s),
            "create_pairing_code.expires_in_s",
        )?,
        C::SetupWindow(r) => {
            use pb::SetupWindowAction as A;
            match A::try_from(r.action) {
                Ok(A::Open | A::Extend) => require(
                    (60..=86_400).contains(&r.expires_in_s),
                    "setup_window.expires_in_s",
                )?,
                Ok(A::Close) => {}
                _ => return Err(FrameError::Invalid("setup_window.action")),
            }
        }
        C::Status(_) | C::ListDevices(_) | C::CloseSessions(_) => {}
    }
    validate_slots(&req.secret_slots, cmd)
}

fn validate_slots(slots: &[pb::AdminSecretSlot], cmd: &pb::request::Command) -> Check {
    use pb::request::Command as C;
    let wants_token = matches!(cmd, C::CreatePairingToken(_));
    require(
        slots.len() == usize::from(wants_token),
        "secret_slots: count does not match the command",
    )?;
    if let Some(s) = slots.first() {
        require(s.slot == 0, "secret_slots: slot numbers must be 0, 1, ...")?;
        require(
            s.kind == pb::AdminSecretKind::PairingToken as i32,
            "secret_slots: wrong kind for this slot",
        )?;
        require(
            (1..=MAX_PAIRING_TOKEN_BYTES).contains(&(s.length as usize)),
            "secret_slots.length",
        )?;
    }
    Ok(())
}

/// Checks a received secret against the admin slot that declared it.
pub fn check_secret_against_slot(slot: &pb::AdminSecretSlot, secret: &Secret) -> Check {
    require(
        secret.len() == slot.length as usize,
        "secret: length differs from the declared slot",
    )
}

/// Name of an admin command, for logs.
pub fn command_name(cmd: &pb::request::Command) -> &'static str {
    use pb::request::Command as C;
    match cmd {
        C::Status(_) => "Status",
        C::ListDevices(_) => "ListDevices",
        C::RevokeDevice(_) => "RevokeDevice",
        C::ReinstateDevice(_) => "ReinstateDevice",
        C::SetPinVerifier(_) => "SetPinVerifier",
        C::SetPasswordVerifier(_) => "SetPasswordVerifier",
        C::CreatePairingToken(_) => "CreatePairingToken",
        C::CreatePairingCode(_) => "CreatePairingCode",
        C::SetupWindow(_) => "SetupWindow",
        C::CloseSessions(_) => "CloseSessions",
    }
}
