//! `pin set` and `pin reset-lockout`.
//!
//! * `pin set`: a hidden prompt (twice), Argon2id here, privd `PepperEnrol` (purpose `PIN`),
//!   then gatewayd `SetPinVerifier` for every device or one.
//! * `pin reset-lockout`: privd `ResetLockout`. It clears the **whole** failure history of the
//!   purpose, not only the lock itself, so an attacker's recent guesses stop counting: that is
//!   why it asks for a typed confirmation (or `--yes`) and why privd writes it to the audit log.

use hx_crypto::Pin;
use hx_ipc::admin::pb as apb;
use hx_ipc::privd::pb::{self, LockoutPurpose, request::Command, response::Result as R};
use serde_json::json;
use subtle::ConstantTimeEq;

use super::{admin, confirm, devices, privd};
use crate::cli::error::CliError;
use crate::cli::gatewayd::unexpected as admin_unexpected;
use crate::cli::privd::unexpected;
use crate::cli::verifier;
use crate::cli::{Env, Outcome};

fn purpose_name(p: LockoutPurpose) -> &'static str {
    match p {
        LockoutPurpose::Password => "password",
        _ => "pin",
    }
}

/// Reads a secret twice and checks that both entries agree.
pub(super) fn ask_twice(
    env: &mut Env<'_>,
    first: &str,
    again: &str,
    max: usize,
) -> Result<zeroize::Zeroizing<Vec<u8>>, CliError> {
    let a = env.prompt.secret(first, max)?;
    let b = env.prompt.secret(again, max)?;
    if a.len() != b.len() || a.ct_eq(&b).unwrap_u8() != 1 {
        return Err(CliError::Declined(
            "the two entries differ; nothing was changed".into(),
        ));
    }
    Ok(a)
}

pub(super) fn set(env: &mut Env<'_>, device: Option<&str>) -> Result<Outcome, CliError> {
    let mut a = admin(env)?;
    let target = match device {
        Some(prefix) => Some(devices::resolve(&mut a, prefix)?),
        None => None,
    };
    let pin = ask_twice(
        env,
        "New PIN, 6 to 16 digits (input hidden): ",
        "Repeat the PIN: ",
        32,
    )?;
    // Format check before anything is sent.
    Pin::from_bytes(&pin).map_err(|_| CliError::Usage("a PIN is 6 to 16 digits".into()))?;
    let mut p = privd(env)?;
    let record = verifier::enrol(
        &mut p,
        LockoutPurpose::Pin,
        &pin,
        env.config.verifier_params,
    )?;
    drop(pin);
    let t = match &target {
        Some(d) => apbtarget_device(d),
        None => apb::set_pin_verifier_request::Target::All(true),
    };
    match a.call(
        apb::request::Command::SetPinVerifier(apb::SetPinVerifierRequest {
            target: Some(t),
            verifier: record.into(),
        }),
        None,
    )? {
        apb::response::Result::SetPinVerifier(_) => {}
        _ => return Err(admin_unexpected("SetPinVerifier")),
    }
    let (text, who) = match &target {
        Some(d) => (
            format!("PIN set for {} ({})\n", &d.hex[..12], d.name),
            json!(d.hex),
        ),
        None => ("PIN set for every device\n".to_owned(), json!("all")),
    };
    Ok(Outcome::ok(text, json!({"pin_set": true, "target": who})))
}

fn apbtarget_device(d: &devices::Dev) -> apb::set_pin_verifier_request::Target {
    apb::set_pin_verifier_request::Target::DeviceId(d.id.to_vec().into())
}

pub(super) fn reset_lockout(
    env: &mut Env<'_>,
    purpose: LockoutPurpose,
    yes: bool,
) -> Result<Outcome, CliError> {
    let name = purpose_name(purpose);
    confirm(
        env,
        &format!(
            "This clears the WHOLE failure history of the {name} purpose, not only the lock: every wrong \
guess of the last hours and days stops counting, so an attacker who has been guessing gets a fresh budget. \
Only do it when you are sure the failures were yours. The reset is written to the audit log."
        ),
        "yes",
        yes,
    )?;
    let mut p = privd(env)?;
    match p.simple(Command::ResetLockout(pb::ResetLockoutRequest {
        purpose: purpose as i32,
    }))? {
        R::ResetLockout(_) => {}
        _ => return Err(unexpected("ResetLockout")),
    }
    Ok(Outcome::ok(
        format!(
            "cleared the failure history of the {name} purpose; recorded in the audit log (hx-agent logs --audit)\n"
        ),
        json!({"reset": true, "purpose": name.to_uppercase(), "audited": true}),
    ))
}
