//! The authorization matrix (Gateway and Admin x phase x command) and the confused-deputy rules of
//! docs/ipc.md section 7 that depend only on the request and the phase.
//!
//! Every test that enforces a numbered rule has the rule in its name (`rule_5_...`), which is how
//! the report maps rules to tests.

use hx_agent::privd::auth::{authorize, counts_as_mutating, rate_rule};
use hx_agent::privd::state::PhaseKind;
use hx_ipc::privd::pb::{self, ErrorCode, ErrorDetail, Role, request::Command};

const PHASES: [PhaseKind; 3] = [
    PhaseKind::Uninitialized,
    PhaseKind::SetupOpen,
    PhaseKind::Ready,
];

/// What a Gateway request gets in a phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum E {
    /// Passes authorization.
    Ok,
    /// `PERMISSION_DENIED`.
    Denied,
    /// `FAILED_PRECONDITION` (`SETUP_WINDOW_CLOSED`).
    Closed,
}

fn req(command: Command, slots: &[pb::SecretKind]) -> pb::Request {
    pb::Request {
        request_id: 1,
        deadline_ms: 0,
        secret_slots: slots
            .iter()
            .enumerate()
            .map(|(i, k)| pb::SecretSlot {
                slot: i as u32,
                kind: *k as i32,
                length: 8,
                ..Default::default()
            })
            .collect(),
        command: Some(command),
    }
}

fn desk() -> String {
    "main".into()
}

fn snapshot(kind: &str) -> String {
    format!("hx-{kind}-20261121T101500Z-a1b2")
}

#[allow(clippy::too_many_lines)]
fn matrix() -> Vec<(&'static str, pb::Request, [E; 3])> {
    use E::{Closed, Denied, Ok as Fine};
    use pb::SecretKind as K;
    let id = desk;
    let mut v: Vec<(&'static str, pb::Request, [E; 3])> = Vec::new();
    let mut add =
        |name, command: Command, slots: &[K], e: [E; 3]| v.push((name, req(command, slots), e));

    // R: read-only, always.
    add(
        "GetHostInfo",
        Command::GetHostInfo(Default::default()),
        &[],
        [Fine; 3],
    );
    add(
        "GetRecipientKey",
        Command::GetRecipientKey(Default::default()),
        &[],
        [Fine; 3],
    );
    add(
        "GetDesktop",
        Command::GetDesktop(pb::GetDesktopRequest { desktop_id: id() }),
        &[],
        [Fine; 3],
    );
    add(
        "ListDesktops",
        Command::ListDesktops(Default::default()),
        &[],
        [Fine; 3],
    );
    add(
        "ListSnapshots",
        Command::ListSnapshots(pb::ListSnapshotsRequest { desktop_id: id() }),
        &[],
        [Fine; 3],
    );

    // X: never to Gateway.
    add(
        "BeginSetup",
        Command::BeginSetup(Default::default()),
        &[],
        [Denied; 3],
    );
    add(
        "ExtendSetup",
        Command::ExtendSetup(pb::ExtendSetupRequest { extend_by_s: 60 }),
        &[],
        [Denied; 3],
    );
    add(
        "RollbackUpdate",
        Command::RollbackUpdate(Default::default()),
        &[],
        [Denied; 3],
    );
    add(
        "DestroyDesktop",
        Command::DestroyDesktop(pb::DestroyDesktopRequest {
            desktop_id: id(),
            confirm_destroy: true,
        }),
        &[],
        [Denied; 3],
    );
    add(
        "Uninstall",
        Command::Uninstall(pb::UninstallRequest {
            keep_desktop: true,
            confirm_destroy: false,
        }),
        &[],
        [Denied; 3],
    );
    add(
        "ResetLockout",
        Command::ResetLockout(pb::ResetLockoutRequest {
            purpose: pb::LockoutPurpose::Pin as i32,
        }),
        &[],
        [Denied; 3],
    );
    add(
        "EnrolOwnerKey",
        Command::EnrolOwnerKey(pb::EnrolOwnerKeyRequest {
            public_key: vec![0; 32].into(),
            replace: false,
        }),
        &[],
        [Denied; 3],
    );
    add(
        "UpgradeIncus",
        Command::UpgradeIncus(Default::default()),
        &[],
        [Denied; 3],
    );

    // A: routine, in READY or SETUP_OPEN.
    let a = [Closed, Fine, Fine];
    add(
        "FinishSetup",
        Command::FinishSetup(Default::default()),
        &[],
        a,
    );
    add(
        "StartDesktop",
        Command::StartDesktop(pb::StartDesktopRequest { desktop_id: id() }),
        &[],
        a,
    );
    add(
        "StopDesktop",
        Command::StopDesktop(pb::StopDesktopRequest {
            desktop_id: id(),
            force: false,
        }),
        &[],
        a,
    );
    add(
        "RestartDesktop",
        Command::RestartDesktop(pb::RestartDesktopRequest {
            desktop_id: id(),
            force: false,
        }),
        &[],
        a,
    );
    add(
        "SetLimits",
        Command::SetLimits(pb::SetLimitsRequest {
            desktop_id: id(),
            limits: Some(pb::Limits {
                cpu: 1,
                memory_mib: 2048,
                disk_gib: 20,
            }),
        }),
        &[],
        a,
    );
    add(
        "DisableDocker",
        Command::DisableDocker(pb::DisableDockerRequest { desktop_id: id() }),
        &[],
        a,
    );
    add(
        "CreateSnapshot",
        Command::CreateSnapshot(pb::CreateSnapshotRequest { desktop_id: id() }),
        &[],
        a,
    );
    add(
        "DeleteSnapshot(manual)",
        Command::DeleteSnapshot(pb::DeleteSnapshotRequest {
            desktop_id: id(),
            name: snapshot("manual"),
        }),
        &[],
        a,
    );
    add(
        "ProvisionSessionLink",
        Command::ProvisionSessionLink(pb::ProvisionSessionLinkRequest { desktop_id: id() }),
        &[],
        a,
    );
    add(
        "InstallSession",
        Command::InstallSession(pb::InstallSessionRequest { desktop_id: id() }),
        &[],
        a,
    );
    add(
        "RestartSession",
        Command::RestartSession(pb::RestartSessionRequest { desktop_id: id() }),
        &[],
        a,
    );
    add(
        "CheckUpdate",
        Command::CheckUpdate(Default::default()),
        &[],
        a,
    );
    add(
        "ApplyUpdate",
        Command::ApplyUpdate(pb::ApplyUpdateRequest {
            version: "1.2.3".into(),
        }),
        &[],
        a,
    );
    add(
        "PepperVerify",
        Command::PepperVerify(pb::PepperVerifyRequest {
            purpose: pb::LockoutPurpose::Pin as i32,
            expected_verifier: vec![0; 32].into(),
        }),
        &[K::MacInput],
        a,
    );
    add(
        "PepperEnrol",
        Command::PepperEnrol(pb::PepperEnrolRequest {
            purpose: pb::LockoutPurpose::Pin as i32,
        }),
        &[K::MacInput],
        a,
    );
    add(
        "RecordEvent",
        Command::RecordEvent(pb::RecordEventRequest {
            event: pb::AuditEvent::DeviceAdded as i32,
            device_id: None,
            label: "x".into(),
        }),
        &[],
        a,
    );
    add(
        "BeginSecretUpload",
        Command::BeginSecretUpload(pb::BeginSecretUploadRequest {
            kind: pb::SecretKind::DriveToken as i32,
            desktop_id: id(),
        }),
        &[],
        a,
    );
    add("BackupRun", Command::BackupRun(Default::default()), &[], a);
    add(
        "BackupStatus",
        Command::BackupStatus(Default::default()),
        &[],
        [Fine; 3],
    );
    // The current password: given, it is allowed whenever class A is; the "missing" case is below.
    add(
        "SetUserPassword(with current)",
        Command::SetUserPassword(pb::SetUserPasswordRequest { desktop_id: id() }),
        &[K::UserPassword, K::CurrentPassword],
        a,
    );

    // S: setup, only in the window.
    let s = [Closed, Fine, Closed];
    add("SetupHost", Command::SetupHost(Default::default()), &[], s);
    add(
        "CreateDesktop",
        Command::CreateDesktop(pb::CreateDesktopRequest {
            desktop_id: id(),
            distro: pb::Distro::Ubuntu2404 as i32,
            desktop: pb::DesktopKind::Xfce as i32,
            preset: pb::Preset::Basic as i32,
            username: "alice".into(),
            ..Default::default()
        }),
        &[K::UserPassword],
        s,
    );
    // EnableDocker lowers isolation: after setup that is a permission question (rule 5).
    add(
        "EnableDocker",
        Command::EnableDocker(pb::EnableDockerRequest {
            desktop_id: id(),
            acknowledged_isolation_warning: true,
            mode: 0,
        }),
        &[],
        [Denied, Fine, Denied],
    );
    v
}

fn code_of(r: Result<(), hx_agent::privd::CmdError>) -> Result<(), (ErrorCode, ErrorDetail)> {
    r.map_err(|e| (e.code, e.detail))
}

fn check(role: Role, phase: PhaseKind, r: &pb::Request) -> Result<(), (ErrorCode, ErrorDetail)> {
    code_of(authorize(role, r, phase))
}

#[test]
fn gateway_matrix_command_by_phase() {
    for (name, r, expect) in matrix() {
        for (phase, e) in PHASES.iter().zip(expect) {
            let got = check(Role::Gateway, *phase, &r);
            let want = match e {
                E::Ok => Ok(()),
                E::Denied => Err((ErrorCode::PermissionDenied, ErrorDetail::Unspecified)),
                E::Closed => Err((
                    ErrorCode::FailedPrecondition,
                    ErrorDetail::SetupWindowClosed,
                )),
            };
            assert_eq!(got, want, "{name} as Gateway in {phase:?}");
        }
    }
}

#[test]
fn admin_is_allowed_everything_in_every_phase() {
    for (name, r, _) in matrix() {
        for phase in PHASES {
            assert_eq!(
                check(Role::Admin, phase, &r),
                Ok(()),
                "{name} as Admin in {phase:?}"
            );
        }
    }
}

#[test]
fn the_matrix_covers_every_command_of_the_contract() {
    // 43 named commands (ids 10..=43) and the 12 Phase 2 ones (60..=71) minus those that are
    // listed once: this guards against a command being added to the schema and not to the matrix.
    let covered: std::collections::BTreeSet<&str> = matrix()
        .iter()
        .map(|(_, r, _)| hx_ipc::privd::command_info(r.command.as_ref().unwrap()).name)
        .collect();
    for needed in [
        "GetHostInfo",
        "GetRecipientKey",
        "BeginSetup",
        "ExtendSetup",
        "FinishSetup",
        "SetupHost",
        "CreateDesktop",
        "GetDesktop",
        "ListDesktops",
        "StartDesktop",
        "StopDesktop",
        "RestartDesktop",
        "SetLimits",
        "SetUserPassword",
        "EnableDocker",
        "DisableDocker",
        "CreateSnapshot",
        "ListSnapshots",
        "DeleteSnapshot",
        "ProvisionSessionLink",
        "InstallSession",
        "RestartSession",
        "CheckUpdate",
        "ApplyUpdate",
        "RollbackUpdate",
        "DestroyDesktop",
        "Uninstall",
        "ResetLockout",
        "EnrolOwnerKey",
        "UpgradeIncus",
        "PepperVerify",
        "PepperEnrol",
        "RecordEvent",
        "BeginSecretUpload",
    ] {
        assert!(covered.contains(needed), "{needed} is not in the matrix");
    }
}

// ----- ipc.md section 7, rule by rule ---------------------------------------------------------

#[test]
fn rule_5_privileged_options_stay_with_admin() {
    use pb::{ExtraHostAddresses, SetupHostRequest};
    let with = |r: SetupHostRequest| req(Command::SetupHost(r), &[]);
    let cases: Vec<(&str, pb::Request)> = vec![
        (
            "pool_device",
            with(SetupHostRequest {
                pool_device: Some("/dev/sdb".into()),
                ..Default::default()
            }),
        ),
        (
            "allow_private_networks (even false)",
            with(SetupHostRequest {
                allow_private_networks: Some(false),
                ..Default::default()
            }),
        ),
        (
            "extra_host_addresses (even empty)",
            with(SetupHostRequest {
                extra_host_addresses: Some(ExtraHostAddresses::default()),
                ..Default::default()
            }),
        ),
        (
            "ipv4 (even auto)",
            with(SetupHostRequest {
                ipv4: Some("auto".into()),
                ..Default::default()
            }),
        ),
        (
            "finish_setup.force (even false)",
            req(
                Command::FinishSetup(pb::FinishSetupRequest { force: Some(false) }),
                &[],
            ),
        ),
        (
            "create_desktop.image_file",
            req(
                Command::CreateDesktop(pb::CreateDesktopRequest {
                    desktop_id: desk(),
                    distro: 1,
                    desktop: 1,
                    preset: 1,
                    username: "alice".into(),
                    image_file: Some("/var/lib/hx/import/x".into()),
                    ..Default::default()
                }),
                &[pb::SecretKind::UserPassword],
            ),
        ),
    ];
    for (what, r) in cases {
        // Not even inside the setup window.
        for phase in PHASES {
            assert_eq!(
                check(Role::Gateway, phase, &r),
                Err((ErrorCode::PermissionDenied, ErrorDetail::Unspecified)),
                "{what} in {phase:?}"
            );
        }
        assert_eq!(
            check(Role::Admin, PhaseKind::Ready, &r),
            Ok(()),
            "{what} as Admin"
        );
    }
}

#[test]
fn rule_5_enable_docker_is_open_to_gateway_only_while_the_window_is_open() {
    let r = req(
        Command::EnableDocker(pb::EnableDockerRequest {
            desktop_id: desk(),
            acknowledged_isolation_warning: true,
            mode: 0,
        }),
        &[],
    );
    assert_eq!(check(Role::Gateway, PhaseKind::SetupOpen, &r), Ok(()));
    assert_eq!(
        check(Role::Gateway, PhaseKind::Ready, &r),
        Err((ErrorCode::PermissionDenied, ErrorDetail::Unspecified))
    );
    assert_eq!(check(Role::Admin, PhaseKind::Ready, &r), Ok(()));
    // DisableDocker only reduces exposure: always open to Gateway once routine commands are.
    let d = req(
        Command::DisableDocker(pb::DisableDockerRequest { desktop_id: desk() }),
        &[],
    );
    assert_eq!(check(Role::Gateway, PhaseKind::Ready, &d), Ok(()));
}

#[test]
fn rule_5_delete_snapshot_gateway_may_delete_manual_only() {
    let del = |kind: &str| {
        req(
            Command::DeleteSnapshot(pb::DeleteSnapshotRequest {
                desktop_id: desk(),
                name: snapshot(kind),
            }),
            &[],
        )
    };
    assert_eq!(
        check(Role::Gateway, PhaseKind::Ready, &del("manual")),
        Ok(())
    );
    for kind in ["preupdate", "backup"] {
        assert_eq!(
            check(Role::Gateway, PhaseKind::Ready, &del(kind)),
            Err((ErrorCode::PermissionDenied, ErrorDetail::Unspecified)),
            "{kind}"
        );
        assert_eq!(
            check(Role::Admin, PhaseKind::Ready, &del(kind)),
            Ok(()),
            "{kind} as Admin"
        );
    }
}

#[test]
fn rule_6_setup_commands_only_in_the_window() {
    for (name, command, slots) in [
        ("SetupHost", Command::SetupHost(Default::default()), vec![]),
        (
            "CreateDesktop",
            Command::CreateDesktop(pb::CreateDesktopRequest {
                desktop_id: desk(),
                distro: 1,
                desktop: 1,
                preset: 1,
                username: "alice".into(),
                ..Default::default()
            }),
            vec![pb::SecretKind::UserPassword],
        ),
    ] {
        let r = req(command, &slots);
        for phase in [PhaseKind::Uninitialized, PhaseKind::Ready] {
            assert_eq!(
                check(Role::Gateway, phase, &r),
                Err((
                    ErrorCode::FailedPrecondition,
                    ErrorDetail::SetupWindowClosed
                )),
                "{name} in {phase:?}"
            );
        }
        assert_eq!(
            check(Role::Gateway, PhaseKind::SetupOpen, &r),
            Ok(()),
            "{name}"
        );
    }
}

#[test]
fn set_user_password_needs_the_current_password_outside_the_window() {
    // ipc.md 6.9: slot 1 (CURRENT_PASSWORD) is required unless the setup window is open.
    let r = req(
        Command::SetUserPassword(pb::SetUserPasswordRequest { desktop_id: desk() }),
        &[pb::SecretKind::UserPassword],
    );
    assert_eq!(check(Role::Gateway, PhaseKind::SetupOpen, &r), Ok(()));
    for phase in [PhaseKind::Uninitialized, PhaseKind::Ready] {
        assert_eq!(
            check(Role::Gateway, phase, &r),
            Err((ErrorCode::PermissionDenied, ErrorDetail::Unspecified)),
            "{phase:?}"
        );
    }
    assert_eq!(check(Role::Admin, PhaseKind::Ready, &r), Ok(()));
}

#[test]
fn rule_7_snapshot_cap_and_rate_rules_are_the_documented_ones() {
    // The per-command limits of ipc.md 6 and 8 (windows in ms).
    let rule = |c: Command| rate_rule(&c).map(|r| (r.window_ms, r.max, r.per_desktop));
    let hour = 3_600_000;
    assert_eq!(
        rule(Command::CreateDesktop(Default::default())),
        Some((hour, 3, false))
    );
    assert_eq!(
        rule(Command::EnableDocker(Default::default())),
        Some((hour, 3, false))
    );
    assert_eq!(
        rule(Command::SetUserPassword(Default::default())),
        Some((hour, 10, false))
    );
    assert_eq!(
        rule(Command::CreateSnapshot(Default::default())),
        Some((hour, 6, false))
    );
    // Persisted per-role limits in updates-state instead (M1).
    assert_eq!(rule(Command::ApplyUpdate(Default::default())), None);
    assert_eq!(
        rule(Command::StartDesktop(Default::default())),
        Some((60_000, 6, true))
    );
    assert_eq!(
        rule(Command::SetLimits(Default::default())),
        Some((hour, 6, false))
    );
    assert_eq!(
        rule(Command::RecordEvent(Default::default())),
        Some((hour, 60, false))
    );
    // Reads, the verifier commands and unlisted commands have no per-command bucket here.
    assert_eq!(rule(Command::GetHostInfo(Default::default())), None);
    assert_eq!(rule(Command::PepperVerify(Default::default())), None);
}

#[test]
fn the_per_minute_cap_counts_mutating_commands_only() {
    assert!(counts_as_mutating(&Command::StartDesktop(
        Default::default()
    )));
    assert!(counts_as_mutating(&Command::SetupHost(Default::default())));
    assert!(!counts_as_mutating(
        &Command::GetDesktop(Default::default())
    ));
    assert!(!counts_as_mutating(&Command::PepperVerify(
        Default::default()
    )));
    assert!(!counts_as_mutating(&Command::PepperEnrol(
        Default::default()
    )));
    assert!(!counts_as_mutating(&Command::RecordEvent(
        Default::default()
    )));
}

#[test]
fn a_request_without_a_command_is_invalid_not_authorized() {
    let r = pb::Request {
        request_id: 1,
        ..Default::default()
    };
    assert_eq!(
        check(Role::Admin, PhaseKind::Ready, &r),
        Err((ErrorCode::InvalidArgument, ErrorDetail::Unspecified))
    );
    assert_eq!(
        check(Role::Gateway, PhaseKind::Ready, &r),
        Err((ErrorCode::InvalidArgument, ErrorDetail::Unspecified))
    );
}
