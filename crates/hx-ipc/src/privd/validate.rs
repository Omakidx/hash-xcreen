//! Validation rules of `docs/ipc.md` sections 4, 5.2 and 6 that depend only on the message.
//!
//! What this checks: structure ("exactly one variant"), string and byte lengths, enum values the
//! receiver knows, fixed-size fields, the syntax of ids, names and versions, and the secret slot
//! layout of each command. What it does not check, because it needs privd's state: roles,
//! phase, rate limits, host-dependent bounds, uniqueness of `request_id` on a connection.
//!
//! Errors name the offending field and never include its value.

use std::net::{IpAddr, Ipv4Addr};

use super::commands::{
    is_valid_desktop_id, is_valid_snapshot_name, is_valid_update_version, is_valid_username_syntax,
};
use super::pb::{self, SecretKind, request::Command};
use super::{
    MAC_LEN, MAX_ERROR_MESSAGE_LEN, MAX_PASSWORD_BYTES, MAX_PROGRESS_STEP_LEN, MAX_SECRET_BYTES,
    MAX_SECRET_SLOTS, MAX_SOFTWARE_LEN, Side, UPLOAD_NONCE_LEN,
};
use crate::error::FrameError;
use crate::secret::Secret;

type Check = Result<(), FrameError>;

fn invalid(what: &'static str) -> Check {
    Err(FrameError::Invalid(what))
}

fn require(cond: bool, what: &'static str) -> Check {
    if cond { Ok(()) } else { invalid(what) }
}

/// `v` must be a defined, non-zero value of enum `E`.
fn known<E: TryFrom<i32>>(v: i32, what: &'static str) -> Check {
    require(v != 0 && E::try_from(v).is_ok(), what)
}

/// `v` must be zero or a defined value of enum `E`.
fn known_or_unset<E: TryFrom<i32>>(v: i32, what: &'static str) -> Check {
    require(v == 0 || E::try_from(v).is_ok(), what)
}

/// Checks one decoded kind-1 frame that is about to be accepted by, or sent to, `to`.
pub fn validate_frame(frame: &pb::Frame, to: Side) -> Check {
    use pb::frame::Frame as F;
    let Some(variant) = &frame.frame else {
        return invalid("frame: no variant set");
    };
    let towards_server = matches!(
        variant,
        F::Hello(_) | F::Request(_) | F::Cancel(_) | F::Ping(_) | F::Pong(_)
    );
    let towards_client = matches!(
        variant,
        F::HelloAck(_) | F::Progress(_) | F::Response(_) | F::Ping(_) | F::Pong(_)
    );
    let allowed = match to {
        Side::Server => towards_server,
        Side::Client => towards_client,
    };
    require(allowed, "frame: variant not valid in this direction")?;
    match variant {
        F::Hello(h) => require(h.software.len() <= MAX_SOFTWARE_LEN, "hello.software"),
        F::HelloAck(a) => {
            require(
                a.privd_version.len() <= MAX_SOFTWARE_LEN,
                "hello_ack.privd_version",
            )?;
            known_or_unset::<pb::Phase>(a.phase, "hello_ack.phase")?;
            known_or_unset::<pb::Role>(a.role, "hello_ack.role")
        }
        F::Request(r) => validate_request(r),
        F::Cancel(_) | F::Ping(_) | F::Pong(_) => Ok(()),
        F::Progress(p) => {
            require(p.step.len() <= MAX_PROGRESS_STEP_LEN, "progress.step")?;
            require(p.percent <= 100 || p.percent == 255, "progress.percent")?;
            known_or_unset::<pb::ProgressStage>(p.stage, "progress.stage")
        }
        F::Response(r) => validate_response(r),
    }
}

fn validate_response(r: &pb::Response) -> Check {
    use pb::response::Result as R;
    match &r.result {
        None => invalid("response: no result set"),
        Some(R::Error(e)) => {
            known::<pb::ErrorCode>(e.code, "error.code")?;
            known_or_unset::<pb::ErrorDetail>(e.detail, "error.detail")?;
            require(e.message.len() <= MAX_ERROR_MESSAGE_LEN, "error.message")?;
            match e.stage {
                Some(s) => known::<pb::ProgressStage>(s, "error.stage"),
                None => Ok(()),
            }
        }
        Some(_) => Ok(()),
    }
}

/// The desktop id carried by a command, if it has one.
fn desktop_id(cmd: &Command) -> Option<&str> {
    Some(match cmd {
        Command::CreateDesktop(r) => &r.desktop_id,
        Command::GetDesktop(r) => &r.desktop_id,
        Command::StartDesktop(r) => &r.desktop_id,
        Command::StopDesktop(r) => &r.desktop_id,
        Command::RestartDesktop(r) => &r.desktop_id,
        Command::SetLimits(r) => &r.desktop_id,
        Command::SetUserPassword(r) => &r.desktop_id,
        Command::EnableDocker(r) => &r.desktop_id,
        Command::DisableDocker(r) => &r.desktop_id,
        Command::CreateSnapshot(r) => &r.desktop_id,
        Command::ListSnapshots(r) => &r.desktop_id,
        Command::DeleteSnapshot(r) => &r.desktop_id,
        Command::ProvisionSessionLink(r) => &r.desktop_id,
        Command::InstallSession(r) => &r.desktop_id,
        Command::RestartSession(r) => &r.desktop_id,
        Command::DestroyDesktop(r) => &r.desktop_id,
        Command::BeginSecretUpload(r) => &r.desktop_id,
        _ => return None,
    })
}

/// Checks a `Request`: non-zero id, one command, argument syntax, and the secret slot layout.
pub fn validate_request(req: &pb::Request) -> Check {
    require(req.request_id != 0, "request.request_id")?;
    let Some(cmd) = &req.command else {
        return invalid("request: no command set");
    };
    if let Some(id) = desktop_id(cmd) {
        require(is_valid_desktop_id(id), "desktop_id")?;
    }
    validate_arguments(cmd)?;
    validate_slots(&req.secret_slots, cmd)
}

fn validate_arguments(cmd: &Command) -> Check {
    match cmd {
        Command::BeginSetup(r) => require(
            r.expires_in_s == 0 || (60..=86_400).contains(&r.expires_in_s),
            "begin_setup.expires_in_s",
        ),
        Command::ExtendSetup(r) => require(
            (60..=86_400).contains(&r.extend_by_s),
            "extend_setup.extend_by_s",
        ),
        Command::SetupHost(r) => validate_setup_host(r),
        Command::CreateDesktop(r) => validate_create_desktop(r),
        Command::SetLimits(r) => {
            let l = r.limits.as_ref();
            require(
                l.is_some_and(|l| l.cpu != 0 && l.memory_mib != 0 && l.disk_gib != 0),
                "set_limits.limits",
            )
        }
        Command::EnableDocker(r) => {
            require(
                r.acknowledged_isolation_warning,
                "enable_docker.acknowledged_isolation_warning",
            )?;
            known_or_unset::<pb::DockerMode>(r.mode, "enable_docker.mode")
        }
        Command::DeleteSnapshot(r) => {
            require(is_valid_snapshot_name(&r.name), "delete_snapshot.name")
        }
        Command::ApplyUpdate(r) => {
            require(is_valid_update_version(&r.version), "apply_update.version")
        }
        Command::DestroyDesktop(r) => require(r.confirm_destroy, "destroy_desktop.confirm_destroy"),
        Command::Uninstall(r) => require(
            r.keep_desktop || r.confirm_destroy,
            "uninstall.confirm_destroy",
        ),
        Command::ResetLockout(r) => known::<pb::LockoutPurpose>(r.purpose, "reset_lockout.purpose"),
        Command::EnrolOwnerKey(r) => {
            require(r.public_key.len() == 32, "enrol_owner_key.public_key")
        }
        Command::PepperVerify(r) => {
            known::<pb::LockoutPurpose>(r.purpose, "pepper_verify.purpose")?;
            require(
                r.expected_verifier.len() == MAC_LEN,
                "pepper_verify.expected_verifier",
            )
        }
        Command::PepperEnrol(r) => known::<pb::LockoutPurpose>(r.purpose, "pepper_enrol.purpose"),
        Command::RecordEvent(r) => {
            known::<pb::AuditEvent>(r.event, "record_event.event")?;
            require(r.label.len() <= 64, "record_event.label")?;
            require(
                r.device_id.as_ref().is_none_or(|d| d.len() == 16),
                "record_event.device_id",
            )
        }
        Command::BeginSecretUpload(r) => require(
            matches!(
                SecretKind::try_from(r.kind),
                Ok(SecretKind::DriveToken | SecretKind::BackupKey)
            ),
            "begin_secret_upload.kind",
        ),
        _ => Ok(()),
    }
}

fn validate_setup_host(r: &pb::SetupHostRequest) -> Check {
    require(
        r.pool_size_gib == 0 || (12..=200).contains(&r.pool_size_gib),
        "setup_host.pool_size_gib",
    )?;
    if let Some(dev) = &r.pool_device {
        require(
            dev.starts_with("/dev/") && dev.len() <= 255 && !dev.bytes().any(|b| b == 0),
            "setup_host.pool_device",
        )?;
    }
    if let Some(list) = &r.extra_host_addresses {
        require(
            list.addresses.len() <= 16
                && list.addresses.iter().all(|a| a.parse::<IpAddr>().is_ok()),
            "setup_host.extra_host_addresses",
        )?;
    }
    if let Some(v4) = &r.ipv4 {
        let ok = v4 == "auto"
            || v4.split_once('/').is_some_and(|(a, n)| {
                a.parse::<Ipv4Addr>().is_ok()
                    && n.len() <= 2
                    && n.parse::<u8>().is_ok_and(|n| (16..=29).contains(&n))
            });
        require(ok, "setup_host.ipv4")?;
    }
    Ok(())
}

fn validate_create_desktop(r: &pb::CreateDesktopRequest) -> Check {
    known::<pb::Distro>(r.distro, "create_desktop.distro")?;
    known::<pb::DesktopKind>(r.desktop, "create_desktop.desktop")?;
    known::<pb::Preset>(r.preset, "create_desktop.preset")?;
    require(
        is_valid_username_syntax(&r.username),
        "create_desktop.username",
    )?;
    known_or_unset::<pb::ImageMode>(r.image_mode, "create_desktop.image_mode")?;
    require(
        !r.docker || r.docker_isolation_acknowledged,
        "create_desktop.docker_isolation_acknowledged",
    )?;
    if let Some(f) = &r.image_file {
        require(
            f.starts_with("/var/lib/hx/import/")
                && f.len() <= 255
                && !f.bytes().any(|b| b == 0)
                && !f.split('/').any(|c| c == ".."),
            "create_desktop.image_file",
        )?;
    }
    Ok(())
}

/// Secret kinds each command expects, by slot position, and how many are required.
fn expected_slots(cmd: &Command) -> (&'static [SecretKind], usize) {
    match cmd {
        Command::CreateDesktop(_) => (&[SecretKind::UserPassword], 1),
        Command::SetUserPassword(_) => {
            (&[SecretKind::UserPassword, SecretKind::CurrentPassword], 1)
        }
        Command::PepperVerify(_) | Command::PepperEnrol(_) => (&[SecretKind::MacInput], 1),
        Command::SetBackupCredentials(_) => (&[SecretKind::DriveToken, SecretKind::BackupKey], 0),
        _ => (&[], 0),
    }
}

fn validate_slots(slots: &[pb::SecretSlot], cmd: &Command) -> Check {
    let (kinds, min) = expected_slots(cmd);
    // A secret of the wrong kind, or outside a declared slot, is INVALID_ARGUMENT (section 7, rule 9).
    require(slots.len() <= MAX_SECRET_SLOTS, "secret_slots: too many")?;
    require(
        slots.len() >= min && slots.len() <= kinds.len(),
        "secret_slots: count does not match the command",
    )?;
    for (i, s) in slots.iter().enumerate() {
        require(
            s.slot as usize == i,
            "secret_slots: slot numbers must be 0, 1, ...",
        )?;
        require(
            SecretKind::try_from(s.kind).ok() == Some(kinds[i]),
            "secret_slots: wrong kind for this slot",
        )?;
        validate_slot(s)?;
    }
    Ok(())
}

/// Structural rules of one declared slot (section 5.2 table): which kinds may be sealed, length
/// bounds, and the nonce.
fn validate_slot(s: &pb::SecretSlot) -> Check {
    let kind =
        SecretKind::try_from(s.kind).map_err(|_| FrameError::Invalid("secret_slots.kind"))?;
    let len = s.length as usize;
    require(len >= 1, "secret_slots.length")?;
    match (kind, s.sealed) {
        (SecretKind::UserPassword, false) => {
            require(len <= MAX_PASSWORD_BYTES, "secret_slots.length")?
        }
        (SecretKind::CurrentPassword, false) => {
            require(len <= MAX_PASSWORD_BYTES, "secret_slots.length")?
        }
        (SecretKind::MacInput, false) => require(len == MAC_LEN, "secret_slots.length")?,
        (SecretKind::UserPassword, true)
        | (SecretKind::DriveToken, true)
        | (SecretKind::BackupKey, true) => require(len <= MAX_SECRET_BYTES, "secret_slots.length")?,
        // CurrentPassword and MacInput are plain only; DriveToken and BackupKey sealed only.
        _ => return invalid("secret_slots.sealed"),
    }
    if s.sealed {
        require(
            s.upload_nonce.len() == UPLOAD_NONCE_LEN,
            "secret_slots.upload_nonce",
        )
    } else {
        require(s.upload_nonce.is_empty(), "secret_slots.upload_nonce")
    }
}

/// Checks a received secret against the slot that declared it: exact length, and for plain
/// passwords no `\n`, `\r` or NUL (the `hx_provision::Secrets::with_user_password` rules).
///
/// Call after the frame arrived; a failure rejects the whole request.
pub fn check_secret_against_slot(slot: &pb::SecretSlot, secret: &Secret) -> Check {
    require(
        secret.len() == slot.length as usize,
        "secret: length differs from the declared slot",
    )?;
    let plain_password = !slot.sealed
        && matches!(
            SecretKind::try_from(slot.kind),
            Ok(SecretKind::UserPassword | SecretKind::CurrentPassword)
        );
    if plain_password {
        require(
            !secret
                .expose()
                .iter()
                .any(|b| matches!(b, b'\n' | b'\r' | 0)),
            "secret: forbidden control character",
        )?;
    }
    Ok(())
}
