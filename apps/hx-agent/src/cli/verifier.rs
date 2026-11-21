//! Creating a verifier from the CLI: `hx-pv1$m=..,t=..,p=..$<salt>$<mac>`, where the MAC is
//! `HMAC(pepper_purpose, Argon2id(secret, salt))` (`docs/ipc.md` section 5.3).
//!
//! The Argon2id half runs here (the gateway's format and cost parameters, from `hx-crypto`);
//! the pepper half is privd's `PepperEnrol`, where `Admin` is exempt from the daily cap. The
//! secret reaches privd only as the Argon2id output in a `MAC_INPUT` secret frame; the raw
//! secret never leaves this process. The record is then given to gatewayd (`SetPinVerifier`,
//! `SetPasswordVerifier`), which checks the format and the cost floor itself.

use argon2::{Algorithm, Argon2, Params, Version};
use hx_crypto::PinParams;
use hx_ipc::privd::pb::{self, LockoutPurpose, request::Command, response::Result as R};
use zeroize::Zeroizing;

use super::error::CliError;
use super::privd::{OutSecret, PrivdConn, unexpected};
use super::text::hex;
use crate::gateway::verifier::{PREFIX, VerifierRecord};

/// Builds a verifier record for `secret` and returns its ASCII form.
pub fn enrol(
    privd: &mut PrivdConn,
    purpose: LockoutPurpose,
    secret: &[u8],
    params: PinParams,
) -> Result<Vec<u8>, CliError> {
    let mut salt = [0u8; 16];
    rustix::rand::getrandom(&mut salt, rustix::rand::GetRandomFlags::empty())
        .map_err(|e| CliError::failed(format!("no randomness: {e}")))?;
    let p = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|_| CliError::failed("the Argon2id parameters are invalid"))?;
    let mut output = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
        .hash_password_into(secret, &salt, &mut *output)
        .map_err(|_| CliError::failed("hashing failed"))?;
    let mac = match privd.call(
        Command::PepperEnrol(pb::PepperEnrolRequest {
            purpose: purpose as i32,
        }),
        &[OutSecret {
            kind: pb::SecretKind::MacInput,
            bytes: &*output,
        }],
        &mut |_| {},
    )? {
        R::PepperEnrol(r) => r.mac,
        _ => return Err(unexpected("PepperEnrol")),
    };
    if mac.len() != 32 {
        return Err(CliError::failed(
            "hx-privd returned a MAC that is not 32 bytes",
        ));
    }
    let record = format!(
        "{PREFIX}$m={},t={},p={}${}${}",
        params.memory_kib,
        params.iterations,
        params.parallelism,
        hex(&salt),
        hex(&mac)
    )
    .into_bytes();
    // The same parser gatewayd uses: a record it would refuse is never sent.
    VerifierRecord::parse(&record)
        .map_err(|e| CliError::failed(format!("built a malformed verifier: {e}")))?;
    Ok(record)
}
