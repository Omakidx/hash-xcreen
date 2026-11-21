//! `devices list | revoke | reinstate`.
//!
//! Calls: gatewayd `ListDevices`, `RevokeDevice`, `ReinstateDevice`. A device is named by the
//! hex of its 16-byte id or an **unambiguous prefix** of it (at least 4 hex digits): the prefix is
//! resolved against the live registry, zero matches is "not found" and several is "ambiguous",
//! never a guess. Device names are untrusted text and are used for display only; they never
//! select a device.

use hx_ipc::admin::pb::{self, request::Command, response::Result as R};
use serde_json::{Value, json};

use super::{admin, enum_name};
use crate::cli::error::CliError;
use crate::cli::gatewayd::{AdminConn, unexpected};
use crate::cli::text::{hex, peer, time};
use crate::cli::{Env, Outcome};

/// Shortest accepted id prefix, in hex digits.
pub const MIN_PREFIX: usize = 4;
/// Longest device name shown.
const NAME_MAX: usize = 64;

/// A listed device with its id as hex.
#[derive(Debug, Clone)]
pub struct Dev {
    pub id: [u8; 16],
    pub hex: String,
    pub name: String,
    pub created: u64,
    pub last_seen: u64,
    pub state: &'static str,
}

fn list_devices(c: &mut AdminConn) -> Result<Vec<Dev>, CliError> {
    match c.call(Command::ListDevices(pb::ListDevicesRequest {}), None)? {
        R::ListDevices(l) => l
            .devices
            .iter()
            .map(|d| {
                let id: [u8; 16] = d.device_id.as_ref().try_into().map_err(|_| {
                    CliError::failed("hx-gatewayd listed a device id that is not 16 bytes")
                })?;
                Ok(Dev {
                    id,
                    hex: hex(&id),
                    name: peer(&d.name, NAME_MAX),
                    created: d.created_unix_s,
                    last_seen: d.last_seen_unix_s,
                    state: enum_name!(pb::DeviceState, d.state, "DEVICE_STATE_"),
                })
            })
            .collect(),
        _ => Err(unexpected("ListDevices")),
    }
}

/// Resolves `prefix` against `devices`.
pub fn resolve_in(devices: &[Dev], prefix: &str) -> Result<Dev, CliError> {
    let p = prefix.to_ascii_lowercase();
    if p.len() < MIN_PREFIX || p.len() > 32 || !p.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CliError::Usage(format!(
            "a device id is hex; give at least {MIN_PREFIX} and at most 32 hex digits (see: hx-agent devices list)"
        )));
    }
    let hits: Vec<&Dev> = devices.iter().filter(|d| d.hex.starts_with(&p)).collect();
    match hits.as_slice() {
        [one] => Ok((*one).clone()),
        [] => Err(CliError::NotFound(format!(
            "no device id starts with {p} (see: hx-agent devices list)"
        ))),
        many => {
            let mut m = format!("{p} is ambiguous; it matches {} devices:", many.len());
            for d in many.iter().take(8) {
                m.push_str(&format!("\n  {}  {}", d.hex, d.name));
            }
            m.push_str("\ngive more digits of the id");
            Err(CliError::NotFound(m))
        }
    }
}

/// Resolves a prefix against the live registry.
pub fn resolve(c: &mut AdminConn, prefix: &str) -> Result<Dev, CliError> {
    resolve_in(&list_devices(c)?, prefix)
}

fn dev_json(d: &Dev) -> Value {
    json!({
        "id": d.hex,
        "name": d.name,
        "state": d.state,
        "created_unix_s": d.created,
        "last_seen_unix_s": d.last_seen,
    })
}

pub(super) fn list(env: &mut Env<'_>) -> Result<Outcome, CliError> {
    let mut c = admin(env)?;
    let devs = list_devices(&mut c)?;
    let mut t = String::new();
    if devs.is_empty() {
        t.push_str("no paired devices\n");
    } else {
        t.push_str("ID            STATE    LAST SEEN             CREATED               NAME\n");
        for d in &devs {
            t.push_str(&format!(
                "{:<12}  {:<7}  {:<20}  {:<20}  {}\n",
                &d.hex[..12],
                d.state.to_lowercase(),
                time(d.last_seen),
                time(d.created),
                d.name
            ));
        }
    }
    Ok(Outcome::ok(
        t,
        json!({"devices": devs.iter().map(dev_json).collect::<Vec<_>>()}),
    ))
}

pub(super) fn revoke(env: &mut Env<'_>, prefix: &str) -> Result<Outcome, CliError> {
    let mut c = admin(env)?;
    let d = resolve(&mut c, prefix)?;
    let closed = match c.call(
        Command::RevokeDevice(pb::RevokeDeviceRequest {
            device_id: d.id.to_vec().into(),
        }),
        None,
    )? {
        R::RevokeDevice(r) => r.sessions_closed,
        _ => return Err(unexpected("RevokeDevice")),
    };
    Ok(Outcome::ok(
        format!(
            "revoked {} ({}); {closed} live session(s) closed\n",
            &d.hex[..12],
            d.name
        ),
        json!({"device": dev_json(&d), "revoked": true, "sessions_closed": closed}),
    ))
}

pub(super) fn reinstate(env: &mut Env<'_>, prefix: &str) -> Result<Outcome, CliError> {
    let mut c = admin(env)?;
    let d = resolve(&mut c, prefix)?;
    match c.call(
        Command::ReinstateDevice(pb::ReinstateDeviceRequest {
            device_id: d.id.to_vec().into(),
        }),
        None,
    )? {
        R::ReinstateDevice(_) => {}
        _ => return Err(unexpected("ReinstateDevice")),
    }
    Ok(Outcome::ok(
        format!(
            "reinstated {} ({}); its PIN failure counter is reset\n",
            &d.hex[..12],
            d.name
        ),
        json!({"device": dev_json(&d), "reinstated": true}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(hex: &str) -> Dev {
        let mut id = [0u8; 16];
        for (i, b) in id.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        Dev {
            id,
            hex: hex.into(),
            name: "n".into(),
            created: 0,
            last_seen: 0,
            state: "ACTIVE",
        }
    }

    #[test]
    fn prefix_resolution() {
        let a = "aabbccdd00000000000000000000000a";
        let b = "aabbccee00000000000000000000000b";
        let c = "11223344000000000000000000000001";
        let devs = vec![dev(a), dev(b), dev(c)];
        assert_eq!(resolve_in(&devs, "1122").unwrap().hex, c);
        assert_eq!(
            resolve_in(&devs, "AABBCCDD").unwrap().hex,
            a,
            "case does not matter"
        );
        assert_eq!(resolve_in(&devs, b).unwrap().hex, b, "the full id works");
        let amb = resolve_in(&devs, "aabbcc").unwrap_err();
        assert!(amb.message().contains("ambiguous"), "{amb}");
        assert_eq!(amb.exit_code(), crate::cli::exit::NOT_FOUND);
        assert!(
            resolve_in(&devs, "ffff")
                .unwrap_err()
                .message()
                .contains("no device")
        );
        for bad in ["", "aa", "aab", "xyzw", "aabb ccdd", &"a".repeat(33)] {
            assert_eq!(
                resolve_in(&devs, bad).unwrap_err().exit_code(),
                crate::cli::exit::USAGE,
                "{bad:?}"
            );
        }
    }
}
