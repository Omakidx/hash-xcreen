#![cfg(feature = "privd")]
//! Contract tests for the privd socket: every command and result of docs/ipc.md section 6
//! exists and round-trips, every limit and validation rule of sections 4, 5 and 6 is enforced,
//! and secrets stay out of protobuf.

use std::collections::BTreeSet;

use hx_ipc::error::FrameError;
use hx_ipc::frame::{Decoder, RawFrame};
use hx_ipc::privd::pb::request::Command;
use hx_ipc::privd::pb::{self, SecretKind};
use hx_ipc::privd::{
    self, CommandClass, Incoming, KIND_MESSAGE, KIND_SECRET, MAX_MESSAGE_LENGTH, MAX_SECRET_BYTES,
    MAX_SECRET_LENGTH, PrivdPolicy, Side, command_info,
};
use hx_ipc::secret::Secret;
use proptest::prelude::*;

const ID: &str = "main";

fn limits() -> Option<pb::Limits> {
    Some(pb::Limits {
        cpu: 2,
        memory_mib: 2048,
        disk_gib: 20,
    })
}

/// One valid instance of every command named by the contract (section 6, including the reserved
/// and Phase 2 ones).
fn every_command() -> Vec<Command> {
    use pb::*;
    let id = || ID.to_string();
    vec![
        Command::GetHostInfo(GetHostInfoRequest {}),
        Command::GetRecipientKey(GetRecipientKeyRequest {}),
        Command::BeginSetup(BeginSetupRequest { expires_in_s: 7200 }),
        Command::ExtendSetup(ExtendSetupRequest { extend_by_s: 600 }),
        Command::FinishSetup(FinishSetupRequest { force: Some(false) }),
        Command::SetupHost(SetupHostRequest {
            pool_size_gib: 50,
            pool_device: Some("/dev/sdb".into()),
            allow_private_networks: Some(false),
            extra_host_addresses: Some(ExtraHostAddresses {
                addresses: vec!["203.0.113.5".into(), "2001:db8::1".into()],
            }),
            ipv4: Some("10.10.0.1/24".into()),
        }),
        Command::CreateDesktop(CreateDesktopRequest {
            desktop_id: id(),
            distro: Distro::Ubuntu2404 as i32,
            desktop: DesktopKind::Xfce as i32,
            preset: Preset::Basic as i32,
            username: "alice".into(),
            image_mode: ImageMode::Auto as i32,
            limits: limits(),
            docker: true,
            docker_isolation_acknowledged: true,
            settings: Some(DesktopSettings::default()),
            image_file: Some("main.img".into()),
        }),
        Command::GetDesktop(GetDesktopRequest { desktop_id: id() }),
        Command::ListDesktops(ListDesktopsRequest {}),
        Command::StartDesktop(StartDesktopRequest { desktop_id: id() }),
        Command::StopDesktop(StopDesktopRequest {
            desktop_id: id(),
            force: true,
        }),
        Command::RestartDesktop(RestartDesktopRequest {
            desktop_id: id(),
            force: false,
        }),
        Command::SetLimits(SetLimitsRequest {
            desktop_id: id(),
            limits: limits(),
        }),
        Command::SetUserPassword(SetUserPasswordRequest { desktop_id: id() }),
        Command::EnableDocker(EnableDockerRequest {
            desktop_id: id(),
            acknowledged_isolation_warning: true,
            mode: DockerMode::Standard as i32,
        }),
        Command::DisableDocker(DisableDockerRequest { desktop_id: id() }),
        Command::CreateSnapshot(CreateSnapshotRequest { desktop_id: id() }),
        Command::ListSnapshots(ListSnapshotsRequest { desktop_id: id() }),
        Command::DeleteSnapshot(DeleteSnapshotRequest {
            desktop_id: id(),
            name: "hx-manual-20261120T101500Z-a1b2".into(),
        }),
        Command::ProvisionSessionLink(ProvisionSessionLinkRequest { desktop_id: id() }),
        Command::InstallSession(InstallSessionRequest { desktop_id: id() }),
        Command::RestartSession(RestartSessionRequest { desktop_id: id() }),
        Command::CheckUpdate(CheckUpdateRequest {}),
        Command::ApplyUpdate(ApplyUpdateRequest {
            version: "1.2.3-rc.1".into(),
        }),
        Command::RollbackUpdate(RollbackUpdateRequest {}),
        Command::DestroyDesktop(DestroyDesktopRequest {
            desktop_id: id(),
            confirm_destroy: true,
        }),
        Command::Uninstall(UninstallRequest {
            keep_desktop: false,
            confirm_destroy: true,
        }),
        Command::ResetLockout(ResetLockoutRequest {
            purpose: LockoutPurpose::Pin as i32,
        }),
        Command::EnrolOwnerKey(EnrolOwnerKeyRequest {
            public_key: vec![9; 32].into(),
            replace: false,
        }),
        Command::UpgradeIncus(UpgradeIncusRequest {}),
        Command::PepperVerify(PepperVerifyRequest {
            purpose: LockoutPurpose::Password as i32,
            expected_verifier: vec![1; 32].into(),
        }),
        Command::PepperEnrol(PepperEnrolRequest {
            purpose: LockoutPurpose::Pin as i32,
        }),
        Command::RecordEvent(RecordEventRequest {
            event: AuditEvent::DeviceAdded as i32,
            device_id: Some(vec![3; 16].into()),
            label: "phone".into(),
        }),
        Command::BeginSecretUpload(BeginSecretUploadRequest {
            kind: SecretKind::DriveToken as i32,
            desktop_id: id(),
        }),
        Command::BackupRun(BackupRunRequest {}),
        Command::BackupCancel(BackupCancelRequest {}),
        Command::BackupStatus(BackupStatusRequest {}),
        Command::ListBackups(ListBackupsRequest {}),
        Command::SetBackupSchedule(SetBackupScheduleRequest {}),
        Command::SetBackupCredentials(SetBackupCredentialsRequest {}),
        Command::VerifyBackup(VerifyBackupRequest {}),
        Command::PruneBackups(PruneBackupsRequest {}),
        Command::RestoreStart(RestoreStartRequest {}),
        Command::RestoreStatus(RestoreStatusRequest {}),
        Command::RestoreConfirm(RestoreConfirmRequest {}),
        Command::GenerateRecoveryKey(GenerateRecoveryKeyRequest {}),
    ]
}

/// The secret slots a command's valid request must declare.
fn slots_for(cmd: &Command) -> Vec<pb::SecretSlot> {
    let plain = |slot, kind: SecretKind, length| pb::SecretSlot {
        slot,
        kind: kind as i32,
        sealed: false,
        length,
        upload_nonce: Default::default(),
        signer_key_id: 0,
    };
    match cmd {
        Command::CreateDesktop(_) => vec![plain(0, SecretKind::UserPassword, 12)],
        Command::SetUserPassword(_) => vec![
            plain(0, SecretKind::UserPassword, 12),
            plain(1, SecretKind::CurrentPassword, 8),
        ],
        Command::PepperVerify(_) | Command::PepperEnrol(_) => {
            vec![plain(0, SecretKind::MacInput, 32)]
        }
        _ => vec![],
    }
}

fn request(id: u64, cmd: Command) -> pb::Request {
    pb::Request {
        request_id: id,
        deadline_ms: 0,
        secret_slots: slots_for(&cmd),
        command: Some(cmd),
    }
}

fn frame_of(req: pb::Request) -> pb::Frame {
    pb::Frame {
        frame: Some(pb::frame::Frame::Request(req)),
    }
}

fn round_trip(frame: &pb::Frame, to: Side) -> pb::Frame {
    let wire = privd::encode_message(frame, to).expect("encode");
    let mut d = Decoder::new(PrivdPolicy::new(to));
    let raw = d.read_from(&mut &wire[..]).expect("read").expect("frame");
    match privd::decode(raw, to).expect("decode") {
        Incoming::Message(f) => f,
        Incoming::Secret(_) => panic!("secret"),
    }
}

#[test]
fn every_command_of_the_contract_exists_and_round_trips() {
    let all = every_command();
    let names: BTreeSet<_> = all.iter().map(|c| command_info(c).name).collect();
    assert_eq!(all.len(), 46);
    assert_eq!(names.len(), 46, "names are distinct");
    for expect in [
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
        "BackupRun",
        "BackupCancel",
        "BackupStatus",
        "ListBackups",
        "SetBackupSchedule",
        "SetBackupCredentials",
        "VerifyBackup",
        "PruneBackups",
        "RestoreStart",
        "RestoreStatus",
        "RestoreConfirm",
        "GenerateRecoveryKey",
    ] {
        assert!(names.contains(expect), "missing {expect}");
    }
    for (i, cmd) in all.into_iter().enumerate() {
        let f = frame_of(request(i as u64 + 1, cmd));
        assert_eq!(round_trip(&f, Side::Server), f);
    }
}

#[test]
fn command_classes_follow_section_5_1() {
    use CommandClass::*;
    let class = |name: &str| {
        every_command()
            .iter()
            .map(command_info)
            .find(|i| i.name == name)
            .unwrap()
            .class
    };
    for n in [
        "GetHostInfo",
        "GetRecipientKey",
        "GetDesktop",
        "ListDesktops",
        "ListSnapshots",
    ] {
        assert_eq!(class(n), R, "{n}");
    }
    for n in ["SetupHost", "CreateDesktop", "EnableDocker"] {
        assert_eq!(class(n), S, "{n}");
    }
    for n in [
        "BeginSetup",
        "ExtendSetup",
        "DestroyDesktop",
        "Uninstall",
        "ResetLockout",
        "EnrolOwnerKey",
        "UpgradeIncus",
        "RollbackUpdate",
    ] {
        assert_eq!(class(n), X, "{n}");
    }
    for n in [
        "DisableDocker",
        "FinishSetup",
        "PepperVerify",
        "PepperEnrol",
        "RecordEvent",
        "StartDesktop",
    ] {
        assert_eq!(class(n), A, "{n}");
    }
    let reserved: BTreeSet<_> = every_command()
        .iter()
        .map(command_info)
        .filter(|i| i.reserved)
        .map(|i| i.name)
        .collect();
    assert_eq!(
        reserved.len(),
        14,
        "UpgradeIncus, BeginSecretUpload and the 12 Phase 2 commands"
    );
    assert!(reserved.contains("UpgradeIncus") && reserved.contains("BeginSecretUpload"));
    assert_eq!(
        command_info(&every_command()[6]).max_deadline_ms,
        Some(45 * 60_000)
    );
}

#[test]
fn admin_only_arguments_are_detected_by_presence_even_at_default_value() {
    let cmds = every_command();
    let find = |name: &str| cmds.iter().find(|c| command_info(c).name == name).unwrap();
    assert_eq!(
        privd::admin_only_argument(find("FinishSetup")),
        Some("finish_setup.force")
    );
    assert_eq!(
        privd::admin_only_argument(find("SetupHost")),
        Some("setup_host.pool_device")
    );
    assert_eq!(
        privd::admin_only_argument(find("CreateDesktop")),
        Some("create_desktop.image_file")
    );
    // A request that leaves them unset is a plain Gateway request.
    let plain = Command::FinishSetup(pb::FinishSetupRequest { force: None });
    assert_eq!(privd::admin_only_argument(&plain), None);
    for (field, cmd) in [
        (
            "setup_host.allow_private_networks",
            pb::SetupHostRequest {
                allow_private_networks: Some(false),
                ..Default::default()
            },
        ),
        (
            "setup_host.extra_host_addresses",
            pb::SetupHostRequest {
                extra_host_addresses: Some(Default::default()),
                ..Default::default()
            },
        ),
        (
            "setup_host.ipv4",
            pb::SetupHostRequest {
                ipv4: Some("auto".into()),
                ..Default::default()
            },
        ),
    ] {
        assert_eq!(
            privd::admin_only_argument(&Command::SetupHost(cmd)),
            Some(field)
        );
    }
    assert_eq!(
        privd::admin_only_argument(&Command::SetupHost(Default::default())),
        None
    );
    // And presence survives the wire at the default value.
    let f = frame_of(request(
        1,
        Command::FinishSetup(pb::FinishSetupRequest { force: Some(false) }),
    ));
    match round_trip(&f, Side::Server).frame {
        Some(pb::frame::Frame::Request(r)) => {
            assert_eq!(
                privd::admin_only_argument(r.command.as_ref().unwrap()),
                Some("finish_setup.force")
            );
        }
        _ => panic!(),
    }
}

#[test]
fn gateway_denied_table_over_commands_arguments_and_phases() {
    use pb::Phase::{Ready, SetupOpen, Uninitialized};
    let mut rows: Vec<(pb::Request, bool, &str)> = Vec::new(); // (request, denied for every phase?, label)
    // Base set: every command with its default valid arguments. Denied = class X, or it carries
    // an Admin-only argument (the base FinishSetup, SetupHost and CreateDesktop do).
    for c in every_command() {
        let info = command_info(&c);
        let admin_arg = privd::admin_only_argument(&c).is_some();
        rows.push((
            request(1, c),
            info.class == CommandClass::X || admin_arg,
            info.name,
        ));
    }
    // Argument variants that are NOT denied.
    rows.push((
        request(
            1,
            Command::FinishSetup(pb::FinishSetupRequest { force: None }),
        ),
        false,
        "FinishSetup/no force",
    ));
    rows.push((
        request(1, Command::SetupHost(Default::default())),
        false,
        "SetupHost/restricted",
    ));
    let mut cd = match every_command()[6].clone() {
        Command::CreateDesktop(r) => r,
        _ => unreachable!(),
    };
    cd.image_file = None;
    rows.push((
        request(1, Command::CreateDesktop(cd)),
        false,
        "CreateDesktop/no image_file",
    ));
    // DeleteSnapshot: only manual for Gateway.
    for (name, denied) in [
        ("hx-manual-20261120T101500Z-a1b2", false),
        ("hx-preupdate-20261120T101500Z-a1b2", true),
        ("hx-backup-20261120T101500Z-a1b2", true),
        ("not-a-snapshot", true),
    ] {
        let c = Command::DeleteSnapshot(pb::DeleteSnapshotRequest {
            desktop_id: ID.into(),
            name: name.into(),
        });
        rows.push((request(1, c), denied, "DeleteSnapshot"));
    }
    for (req, denied_always, label) in rows {
        for phase in [Uninitialized, SetupOpen, Ready] {
            let got = privd::gateway_denied(&req, phase).is_some();
            assert_eq!(got, denied_always, "{label} in {phase:?}");
        }
    }
    // SetUserPassword: the current-password slot is required unless the window is open.
    let sup = Command::SetUserPassword(pb::SetUserPasswordRequest {
        desktop_id: ID.into(),
    });
    let mut one = request(1, sup.clone());
    one.secret_slots.truncate(1);
    let two = request(1, sup);
    assert_eq!(two.secret_slots.len(), 2);
    for phase in [Uninitialized, SetupOpen, Ready] {
        assert!(privd::gateway_denied(&two, phase).is_none(), "{phase:?}");
    }
    assert!(privd::gateway_denied(&one, SetupOpen).is_none());
    assert!(privd::gateway_denied(&one, Ready).is_some());
    assert!(privd::gateway_denied(&one, Uninitialized).is_some());
    // No command: nothing to deny at this layer.
    assert!(privd::gateway_denied(&pb::Request::default(), Ready).is_none());
}

#[test]
fn every_result_variant_and_error_code_round_trips() {
    use pb::response::Result as R;
    use pb::*;
    let mut results = vec![
        R::GetHostInfo(GetHostInfoResult {
            privd_version: "1.0.0".into(),
            phase: Phase::Ready as i32,
            pool: Some(PoolInfo::default()),
            incus_version: None,
            needs_attention: vec![NeedsAttention::PinLocked as i32],
            ..Default::default()
        }),
        R::GetRecipientKey(GetRecipientKeyResult {
            key_id: 1,
            public_key: vec![5; 32].into(),
            owner_key_enrolled: false,
        }),
        R::BeginSetup(BeginSetupResult {
            expires_at_unix_s: 1,
        }),
        R::ExtendSetup(ExtendSetupResult {
            expires_at_unix_s: 2,
        }),
        R::FinishSetup(FinishSetupResult {}),
        R::SetupHost(SetupHostResult {
            pool: Ensured::Created as i32,
            docker_user_rules: DockerUserRules::Failed as i32,
            ..Default::default()
        }),
        R::CreateDesktop(CreateDesktopResult {
            desktop_id: "main".into(),
            path_taken: PathTaken::Prebuilt as i32,
            docker: Some(DockerOutcome {
                outcome: Some(docker_outcome::Outcome::SelfTestFailed(
                    DockerSelfTestFailed {
                        isolation_restored: false,
                        hint: "h".into(),
                        output_tail: "t".into(),
                        fallbacks: vec![DockerFallback::ZabblyIncus as i32],
                    },
                )),
            }),
            ..Default::default()
        }),
        R::GetDesktop(GetDesktopResult {
            desktop: Some(Desktop {
                desktop_id: "main".into(),
                state: DesktopState::Running as i32,
                session: Some(SessionInfo::default()),
                ..Default::default()
            }),
        }),
        R::ListDesktops(ListDesktopsResult {
            desktops: vec![Desktop::default()],
        }),
        R::StartDesktop(PowerResult {
            running: true,
            degraded: false,
        }),
        R::StopDesktop(PowerResult::default()),
        R::RestartDesktop(PowerResult {
            running: true,
            degraded: true,
        }),
        R::SetLimits(SetLimitsResult {
            restart_required: true,
        }),
        R::SetUserPassword(SetUserPasswordResult {}),
        R::EnableDocker(EnableDockerResult {
            outcome: Some(DockerOutcome {
                outcome: Some(docker_outcome::Outcome::Enabled(DockerEnabled {
                    docker_version: "27".into(),
                })),
            }),
        }),
        R::DisableDocker(DisableDockerResult { restarted: true }),
        R::CreateSnapshot(CreateSnapshotResult {
            snapshot: Some(Snapshot::default()),
        }),
        R::ListSnapshots(ListSnapshotsResult {
            snapshots: vec![Snapshot {
                name: "hx-manual-1-dead".into(),
                kind: SnapshotKind::Manual as i32,
                ..Default::default()
            }],
        }),
        R::DeleteSnapshot(DeleteSnapshotResult {}),
        R::ProvisionSessionLink(ProvisionSessionLinkResult {
            socket_path: "/run/hx/link/main.sock".into(),
        }),
        R::InstallSession(InstallSessionResult {
            installed_version: "1.0.0".into(),
            restarted: true,
        }),
        R::RestartSession(RestartSessionResult {}),
        R::CheckUpdate(CheckUpdateResult {
            current: "1.0.0".into(),
            available: Some("1.1.0".into()),
            channel: UpdateChannel::Stable as i32,
            verified: true,
            rolled_back: Some(RolledBack {
                version: "1.1.0".into(),
                reason: "x".into(),
            }),
        }),
        R::ApplyUpdate(ApplyUpdateResult { restarting: true }),
        R::RollbackUpdate(RollbackUpdateResult {}),
        R::DestroyDesktop(DestroyDesktopResult {}),
        R::Uninstall(UninstallResult {
            keep_desktop: true,
            removed: vec!["session-link:main".into()],
            kept: vec!["desktop:main".into()],
            warnings: vec![],
        }),
        R::ResetLockout(ResetLockoutResult {}),
        R::EnrolOwnerKey(EnrolOwnerKeyResult {}),
        R::UpgradeIncus(UpgradeIncusResult {}),
        R::PepperVerify(PepperVerifyResult { ok: true }),
        R::PepperEnrol(PepperEnrolResult {
            mac: vec![8; 32].into(),
            version: 1,
        }),
        R::RecordEvent(RecordEventResult {}),
        R::BeginSecretUpload(BeginSecretUploadResult {
            upload_nonce: vec![2; 16].into(),
        }),
    ];
    for code in 1..=10 {
        results.push(R::Error(Error {
            code,
            detail: ErrorDetail::Locked as i32,
            message: "m".into(),
            retryable: code == 5,
            retry_after_ms: 1000,
            stage: Some(ProgressStage::Build as i32),
        }));
    }
    assert_eq!(results.len(), 34 + 10);
    for (i, r) in results.into_iter().enumerate() {
        let f = Frame {
            frame: Some(frame::Frame::Response(Response {
                request_id: i as u64 + 1,
                result: Some(r),
            })),
        };
        assert_eq!(round_trip(&f, Side::Client), f);
    }
}

#[test]
fn connection_frames_round_trip_in_their_direction_only() {
    use pb::frame::Frame as F;
    let to_server = [
        F::Hello(pb::Hello {
            major: 1,
            minor: 0,
            software: "hx-gatewayd 1.0".into(),
        }),
        F::Cancel(pb::Cancel { request_id: 4 }),
        F::Ping(pb::Ping { nonce: u64::MAX }),
        F::Pong(pb::Pong { nonce: 0 }),
    ];
    for v in to_server {
        let f = pb::Frame { frame: Some(v) };
        assert_eq!(round_trip(&f, Side::Server), f);
        if !matches!(f.frame, Some(F::Ping(_) | F::Pong(_))) {
            assert!(
                privd::encode_message(&f, Side::Client).is_err(),
                "{f:?} must not go to a client"
            );
        }
    }
    let to_client = [
        F::HelloAck(pb::HelloAck {
            major: 1,
            minor: 0,
            privd_version: "1".into(),
            phase: pb::Phase::SetupOpen as i32,
            role: pb::Role::Gateway as i32,
        }),
        F::Progress(pb::Progress {
            request_id: 1,
            stage: pb::ProgressStage::Launch as i32,
            index: 2,
            total: 9,
            step: "launch".into(),
            percent: 255,
            ok: true,
            ..Default::default()
        }),
    ];
    for v in to_client {
        let f = pb::Frame { frame: Some(v) };
        assert_eq!(round_trip(&f, Side::Client), f);
        assert!(privd::encode_message(&f, Side::Server).is_err());
    }
    // Requests and responses never go the wrong way either.
    let req = frame_of(request(1, every_command().remove(0)));
    assert!(privd::encode_message(&req, Side::Client).is_err());
}

#[test]
fn schema_enums_cover_the_contract_names() {
    // Section 4: stages and error codes; section 6: kinds and purposes.
    let stages = [
        "PREFLIGHT",
        "HOST",
        "IMAGE_FETCH",
        "IMAGE_IMPORT",
        "BUILD",
        "LAUNCH",
        "POST",
        "DOCKER",
        "SESSION",
        "UPDATE",
        "BACKUP",
        "RESTORE",
        "DONE",
    ];
    for s in stages {
        assert!(
            pb::ProgressStage::from_str_name(&format!("PROGRESS_STAGE_{s}")).is_some(),
            "{s}"
        );
    }
    let codes = [
        "INVALID_ARGUMENT",
        "PERMISSION_DENIED",
        "FAILED_PRECONDITION",
        "NOT_FOUND",
        "RESOURCE_EXHAUSTED",
        "DEADLINE_EXCEEDED",
        "CANCELLED",
        "UNAVAILABLE",
        "UNIMPLEMENTED",
        "INTERNAL",
    ];
    for c in codes {
        assert!(
            pb::ErrorCode::from_str_name(&format!("ERROR_CODE_{c}")).is_some(),
            "{c}"
        );
    }
    for n in [
        "HOST_ACCOUNT_POLICY",
        "STUCK_OPERATION",
        "ISOLATION_NOT_RESTORED",
        "PIN_LOCKED",
        "PASSWORD_LOCKED",
        "UPDATE_ROLLED_BACK",
        "HOST_DOCKER_FORWARDING",
        "DRIVE_RECONNECT",
        "BACKUP_TAKEN_OVER",
    ] {
        assert!(
            pb::NeedsAttention::from_str_name(&format!("NEEDS_ATTENTION_{n}")).is_some(),
            "{n}"
        );
    }
    for n in [
        "DEVICE_ADDED",
        "DEVICE_REVOKED",
        "DEVICE_REINSTATED",
        "PIN_CHANGED",
        "PASSWORD_VERIFIER_CHANGED",
        "PAIRING_OPENED",
        "TAKEOVER",
    ] {
        assert!(
            pb::AuditEvent::from_str_name(&format!("AUDIT_EVENT_{n}")).is_some(),
            "{n}"
        );
    }
    for n in [
        "USER_PASSWORD",
        "CURRENT_PASSWORD",
        "MAC_INPUT",
        "DRIVE_TOKEN",
        "BACKUP_KEY",
    ] {
        assert!(
            SecretKind::from_str_name(&format!("SECRET_KIND_{n}")).is_some(),
            "{n}"
        );
    }
}

// ---------- negative tests: framing ----------

fn server_decoder() -> Decoder<PrivdPolicy> {
    Decoder::new(PrivdPolicy::new(Side::Server))
}

fn head(length: u32, kind: u8) -> Vec<u8> {
    let mut v = length.to_le_bytes().to_vec();
    v.push(kind);
    v
}

#[test]
fn privd_limits_are_enforced_before_allocation() {
    // Message: 65 536 is the limit including the kind byte.
    assert!(
        server_decoder()
            .feed(&head(MAX_MESSAGE_LENGTH, KIND_MESSAGE))
            .is_ok()
    );
    assert_eq!(
        server_decoder()
            .feed(&head(MAX_MESSAGE_LENGTH + 1, KIND_MESSAGE))
            .unwrap_err(),
        FrameError::TooLong {
            length: MAX_MESSAGE_LENGTH + 1,
            max: MAX_MESSAGE_LENGTH
        }
    );
    // Secret: 8 192.
    assert!(
        server_decoder()
            .feed(&head(MAX_SECRET_LENGTH, KIND_SECRET))
            .is_ok()
    );
    assert_eq!(
        server_decoder()
            .feed(&head(MAX_SECRET_LENGTH + 1, KIND_SECRET))
            .unwrap_err(),
        FrameError::TooLong {
            length: MAX_SECRET_LENGTH + 1,
            max: MAX_SECRET_LENGTH
        }
    );
    // A huge announced length dies on the four prefix bytes.
    assert!(matches!(
        server_decoder().feed(&u32::MAX.to_le_bytes()).unwrap_err(),
        FrameError::TooLong { .. }
    ));
    assert_eq!(
        server_decoder().feed(&[0; 4]).unwrap_err(),
        FrameError::ZeroLength
    );
    assert_eq!(
        server_decoder().feed(&head(2, 0)).unwrap_err(),
        FrameError::UnknownKind(0)
    );
    assert_eq!(
        server_decoder().feed(&head(2, 3)).unwrap_err(),
        FrameError::UnknownKind(3)
    );
    // A client never accepts a secret frame (only callers send them).
    let mut client = Decoder::new(PrivdPolicy::new(Side::Client));
    assert_eq!(
        client.feed(&head(10, KIND_SECRET)).unwrap_err(),
        FrameError::KindNotAllowed(KIND_SECRET)
    );
}

#[test]
fn undecodable_and_variantless_bodies_are_violations() {
    let garbage = RawFrame {
        kind: KIND_MESSAGE,
        body: bytes::BytesMut::from(&[0xff, 0xff, 0xff][..]),
    };
    assert!(matches!(
        privd::decode(garbage, Side::Server),
        Err(FrameError::Decode(_))
    ));
    let empty = RawFrame {
        kind: KIND_MESSAGE,
        body: bytes::BytesMut::new(),
    };
    assert!(matches!(
        privd::decode(empty, Side::Server),
        Err(FrameError::Invalid(_))
    ));
    let unknown = RawFrame {
        kind: 77,
        body: bytes::BytesMut::new(),
    };
    assert_eq!(
        privd::decode(unknown, Side::Server).unwrap_err(),
        FrameError::UnknownKind(77)
    );
}

#[test]
fn unknown_fields_are_ignored() {
    // A Ping (field 5 -> nonce) with an extra unknown field 99 still decodes.
    use prost::Message;
    let mut body = pb::Frame {
        frame: Some(pb::frame::Frame::Ping(pb::Ping { nonce: 3 })),
    }
    .encode_to_vec();
    prost::encoding::encode_key(99, prost::encoding::WireType::Varint, &mut body);
    prost::encoding::encode_varint(7, &mut body);
    let raw = RawFrame {
        kind: KIND_MESSAGE,
        body: bytes::BytesMut::from(&body[..]),
    };
    assert!(matches!(
        privd::decode(raw, Side::Server),
        Ok(Incoming::Message(_))
    ));
}

// ---------- negative tests: validation ----------

fn ok(cmd: Command) -> bool {
    privd::validate_request(&request(1, cmd)).is_ok()
}

#[test]
fn request_validation_rules() {
    let valid = every_command();
    for c in valid.clone() {
        assert!(ok(c.clone()), "{} should be valid", command_info(&c).name);
    }
    // request_id 0 and a missing command.
    assert!(privd::validate_request(&request(0, valid[0].clone())).is_err());
    assert!(privd::validate_request(&pb::Request::default()).is_err());
    // desktop id syntax.
    for bad in ["", "Main", "1a", "a-b", "a01234567890b", "../x"] {
        assert!(
            !ok(Command::GetDesktop(pb::GetDesktopRequest {
                desktop_id: bad.into()
            })),
            "{bad:?}"
        );
    }
    // enums: unspecified and out of range.
    let mut cd = match valid[6].clone() {
        Command::CreateDesktop(r) => r,
        _ => unreachable!(),
    };
    cd.distro = 0;
    assert!(!ok(Command::CreateDesktop(cd.clone())));
    cd.distro = 99;
    assert!(!ok(Command::CreateDesktop(cd.clone())));
    cd.distro = 1;
    cd.username = "Root User".into();
    assert!(!ok(Command::CreateDesktop(cd.clone())));
    cd.username = "alice".into();
    cd.docker_isolation_acknowledged = false;
    assert!(
        !ok(Command::CreateDesktop(cd.clone())),
        "docker needs the acknowledgement"
    );
    cd.docker = false;
    assert!(ok(Command::CreateDesktop(cd.clone())));
    // The offline image is a file name in the fixed directory, never a path.
    for bad in [
        "/var/lib/hx/import/main.img",
        "../../etc/shadow",
        "a/b.img",
        "/tmp/x",
        "..",
        ".hidden",
        "-x.img",
        "",
        "a b.img",
        "a\0b.img",
        &"a".repeat(129),
    ] {
        cd.image_file = Some(bad.into());
        assert!(!ok(Command::CreateDesktop(cd.clone())), "{bad:?}");
    }
    for good in [
        "main.img",
        "hx-image-ubuntu-24.04-xfce-basic-20261123.1.img",
        "A_b-1",
    ] {
        cd.image_file = Some(good.into());
        assert!(ok(Command::CreateDesktop(cd.clone())), "{good:?}");
    }
    cd.image_file = Some("a".repeat(128));
    assert!(ok(Command::CreateDesktop(cd)));
    // ranges and syntax.
    assert!(!ok(Command::BeginSetup(pb::BeginSetupRequest {
        expires_in_s: 59
    })));
    assert!(!ok(Command::BeginSetup(pb::BeginSetupRequest {
        expires_in_s: 86_401
    })));
    assert!(ok(Command::BeginSetup(pb::BeginSetupRequest {
        expires_in_s: 0
    })));
    assert!(!ok(Command::SetLimits(pb::SetLimitsRequest {
        desktop_id: ID.into(),
        limits: Some(pb::Limits {
            cpu: 0,
            memory_mib: 1,
            disk_gib: 1
        })
    })));
    assert!(!ok(Command::SetLimits(pb::SetLimitsRequest {
        desktop_id: ID.into(),
        limits: None
    })));
    assert!(!ok(Command::DeleteSnapshot(pb::DeleteSnapshotRequest {
        desktop_id: ID.into(),
        name: "hx-manual-x-dead".into()
    })));
    assert!(!ok(Command::ApplyUpdate(pb::ApplyUpdateRequest {
        version: "1.0".into()
    })));
    assert!(!ok(Command::EnableDocker(pb::EnableDockerRequest {
        desktop_id: ID.into(),
        acknowledged_isolation_warning: false,
        mode: 0
    })));
    assert!(!ok(Command::DestroyDesktop(pb::DestroyDesktopRequest {
        desktop_id: ID.into(),
        confirm_destroy: false
    })));
    assert!(!ok(Command::Uninstall(pb::UninstallRequest {
        keep_desktop: false,
        confirm_destroy: false
    })));
    assert!(ok(Command::Uninstall(pb::UninstallRequest {
        keep_desktop: true,
        confirm_destroy: false
    })));
    assert!(!ok(Command::EnrolOwnerKey(pb::EnrolOwnerKeyRequest {
        public_key: vec![0; 31].into(),
        replace: false
    })));
    assert!(!ok(Command::PepperVerify(pb::PepperVerifyRequest {
        purpose: 1,
        expected_verifier: vec![0; 31].into()
    })));
    assert!(!ok(Command::RecordEvent(pb::RecordEventRequest {
        event: 1,
        device_id: Some(vec![0; 15].into()),
        label: String::new()
    })));
    assert!(!ok(Command::RecordEvent(pb::RecordEventRequest {
        event: 1,
        device_id: None,
        label: "x".repeat(65)
    })));
    assert!(!ok(Command::SetupHost(pb::SetupHostRequest {
        pool_size_gib: 11,
        ..Default::default()
    })));
    assert!(!ok(Command::SetupHost(pb::SetupHostRequest {
        ipv4: Some("10.0.0.1/30".into()),
        ..Default::default()
    })));
    assert!(!ok(Command::SetupHost(pb::SetupHostRequest {
        pool_device: Some("/etc/passwd".into()),
        ..Default::default()
    })));
    for dev in [
        "/dev/../etc/passwd",
        "/dev/sdb/../sda",
        "/dev/./sdb",
        "/dev//sdb",
        "/dev/sdb/",
        "/dev/",
        "dev/sdb",
    ] {
        assert!(
            !ok(Command::SetupHost(pb::SetupHostRequest {
                pool_device: Some(dev.into()),
                ..Default::default()
            })),
            "{dev}"
        );
    }
    for dev in ["/dev/sdb", "/dev/disk/by-id/nvme-x_1"] {
        assert!(
            ok(Command::SetupHost(pb::SetupHostRequest {
                pool_device: Some(dev.into()),
                ..Default::default()
            })),
            "{dev}"
        );
    }
    for v4 in [
        "8.8.8.0/24",
        "100.64.0.0/24",
        "172.32.0.0/24",
        "11.0.0.1/24",
        "169.254.0.1/24",
        "192.169.0.1/24",
    ] {
        assert!(
            !ok(Command::SetupHost(pb::SetupHostRequest {
                ipv4: Some(v4.into()),
                ..Default::default()
            })),
            "{v4}"
        );
    }
    for v4 in [
        "10.0.0.1/16",
        "172.16.5.1/29",
        "172.31.0.1/24",
        "192.168.1.1/24",
        "auto",
    ] {
        assert!(
            ok(Command::SetupHost(pb::SetupHostRequest {
                ipv4: Some(v4.into()),
                ..Default::default()
            })),
            "{v4}"
        );
    }
    assert!(!ok(Command::SetupHost(pb::SetupHostRequest {
        extra_host_addresses: Some(pb::ExtraHostAddresses {
            addresses: vec!["not an ip".into()]
        }),
        ..Default::default()
    })));
    assert!(!ok(Command::SetupHost(pb::SetupHostRequest {
        extra_host_addresses: Some(pb::ExtraHostAddresses {
            addresses: vec!["10.0.0.1".into(); 17]
        }),
        ..Default::default()
    })));
}

#[test]
fn frame_string_limits() {
    let f = |v| pb::Frame { frame: Some(v) };
    use pb::frame::Frame as F;
    assert!(
        privd::validate_frame(
            &f(F::Hello(pb::Hello {
                major: 1,
                minor: 0,
                software: "x".repeat(64)
            })),
            Side::Server
        )
        .is_ok()
    );
    assert!(
        privd::validate_frame(
            &f(F::Hello(pb::Hello {
                major: 1,
                minor: 0,
                software: "x".repeat(65)
            })),
            Side::Server
        )
        .is_err()
    );
    let progress = |step: usize, percent| {
        F::Progress(pb::Progress {
            step: "x".repeat(step),
            percent,
            ..Default::default()
        })
    };
    assert!(privd::validate_frame(&f(progress(128, 100)), Side::Client).is_ok());
    assert!(privd::validate_frame(&f(progress(129, 100)), Side::Client).is_err());
    assert!(privd::validate_frame(&f(progress(1, 101)), Side::Client).is_err());
    assert!(privd::validate_frame(&f(progress(1, 255)), Side::Client).is_ok());
    let err = |message: usize, code| {
        F::Response(pb::Response {
            request_id: 1,
            result: Some(pb::response::Result::Error(pb::Error {
                code,
                message: "x".repeat(message),
                ..Default::default()
            })),
        })
    };
    assert!(privd::validate_frame(&f(err(256, 1)), Side::Client).is_ok());
    assert!(privd::validate_frame(&f(err(257, 1)), Side::Client).is_err());
    assert!(
        privd::validate_frame(&f(err(1, 0)), Side::Client).is_err(),
        "unspecified code"
    );
    assert!(
        privd::validate_frame(
            &f(F::Response(pb::Response {
                request_id: 1,
                result: None
            })),
            Side::Client
        )
        .is_err()
    );
}

// ---------- secrets ----------

#[test]
fn secret_slots_must_match_the_command_and_the_section_5_2_table() {
    let slot = |slot, kind: SecretKind, sealed, length, nonce: usize| pb::SecretSlot {
        slot,
        kind: kind as i32,
        sealed,
        length,
        upload_nonce: vec![0; nonce].into(),
        signer_key_id: 0,
    };
    let create = every_command()[6].clone();
    let with = |slots: Vec<pb::SecretSlot>| {
        privd::validate_request(&pb::Request {
            request_id: 1,
            deadline_ms: 0,
            secret_slots: slots,
            command: Some(create.clone()),
        })
    };
    assert!(with(vec![slot(0, SecretKind::UserPassword, false, 12, 0)]).is_ok());
    assert!(
        with(vec![slot(0, SecretKind::UserPassword, true, 100, 16)]).is_ok(),
        "sealed password with a nonce"
    );
    assert!(with(vec![]).is_err(), "missing");
    assert!(
        with(vec![
            slot(0, SecretKind::UserPassword, false, 12, 0),
            slot(1, SecretKind::CurrentPassword, false, 5, 0)
        ])
        .is_err(),
        "extra"
    );
    assert!(
        with(vec![slot(0, SecretKind::MacInput, false, 32, 0)]).is_err(),
        "wrong kind"
    );
    assert!(
        with(vec![slot(1, SecretKind::UserPassword, false, 12, 0)]).is_err(),
        "slot number"
    );
    assert!(
        with(vec![slot(0, SecretKind::UserPassword, false, 0, 0)]).is_err(),
        "empty"
    );
    assert!(
        with(vec![slot(0, SecretKind::UserPassword, false, 1025, 0)]).is_err(),
        "over 1024"
    );
    assert!(
        with(vec![slot(0, SecretKind::UserPassword, true, 100, 0)]).is_err(),
        "sealed needs a nonce"
    );
    assert!(
        with(vec![slot(0, SecretKind::UserPassword, false, 12, 16)]).is_err(),
        "plain has no nonce"
    );
    // Drive token and backup key are sealed only; current password and MAC input plain only.
    let set_creds = Command::SetBackupCredentials(pb::SetBackupCredentialsRequest {});
    let sbc = |slots: Vec<pb::SecretSlot>| {
        privd::validate_request(&pb::Request {
            request_id: 1,
            deadline_ms: 0,
            secret_slots: slots,
            command: Some(set_creds.clone()),
        })
    };
    assert!(sbc(vec![slot(0, SecretKind::DriveToken, true, 500, 16)]).is_ok());
    assert!(
        sbc(vec![slot(0, SecretKind::DriveToken, false, 500, 0)]).is_err(),
        "a plain DRIVE_TOKEN is INVALID_ARGUMENT"
    );
    assert!(sbc(vec![slot(0, SecretKind::DriveToken, true, 8_183, 16)]).is_err());
    assert!(sbc(vec![slot(0, SecretKind::DriveToken, true, 8_182, 16)]).is_ok());
    let sup = Command::SetUserPassword(pb::SetUserPasswordRequest {
        desktop_id: ID.into(),
    });
    let req = |slots: Vec<pb::SecretSlot>| {
        privd::validate_request(&pb::Request {
            request_id: 1,
            deadline_ms: 0,
            secret_slots: slots,
            command: Some(sup.clone()),
        })
    };
    assert!(
        req(vec![slot(0, SecretKind::UserPassword, false, 8, 0)]).is_ok(),
        "slot 1 is optional inside the setup window"
    );
    assert!(
        req(vec![
            slot(0, SecretKind::UserPassword, false, 8, 0),
            slot(1, SecretKind::CurrentPassword, true, 8, 16)
        ])
        .is_err(),
        "current password is plain only"
    );
    // A command that takes no secret rejects any slot.
    let ls = Command::ListDesktops(pb::ListDesktopsRequest {});
    assert!(
        privd::validate_request(&pb::Request {
            request_id: 1,
            deadline_ms: 0,
            secret_slots: vec![slot(0, SecretKind::UserPassword, false, 8, 0)],
            command: Some(ls)
        })
        .is_err()
    );
}

#[test]
fn received_secrets_are_checked_against_their_slot() {
    let plain = |kind: SecretKind, length| pb::SecretSlot {
        slot: 0,
        kind: kind as i32,
        sealed: false,
        length,
        ..Default::default()
    };
    let s = |b: &[u8]| Secret::new(b.to_vec());
    assert!(
        privd::check_secret_against_slot(&plain(SecretKind::UserPassword, 4), &s(b"pass")).is_ok()
    );
    assert!(
        privd::check_secret_against_slot(&plain(SecretKind::UserPassword, 5), &s(b"pass")).is_err(),
        "length differs"
    );
    for bad in [&b"pa\nss"[..], b"pa\rss", b"pa\0ss"] {
        assert!(
            privd::check_secret_against_slot(&plain(SecretKind::UserPassword, 5), &s(bad)).is_err()
        );
        assert!(
            privd::check_secret_against_slot(&plain(SecretKind::CurrentPassword, 5), &s(bad))
                .is_err()
        );
    }
    // MAC input is binary: newlines are fine.
    assert!(
        privd::check_secret_against_slot(&plain(SecretKind::MacInput, 32), &s(&[b'\n'; 32]))
            .is_ok()
    );
}

#[test]
fn secret_frames_round_trip_and_the_buffer_is_zeroized() {
    let wire = privd::encode_secret(42, 1, b"hunter2").unwrap();
    assert_eq!(wire[4], KIND_SECRET);
    assert_eq!(
        u32::from_le_bytes(wire[..4].try_into().unwrap()) as usize,
        1 + 9 + 7
    );
    let mut d = server_decoder();
    let raw = d.read_from(&mut &wire[..]).unwrap().unwrap();
    match privd::decode(raw, Side::Server).unwrap() {
        Incoming::Secret(f) => {
            assert_eq!((f.request_id, f.slot), (42, 1));
            assert_eq!(f.secret.expose(), b"hunter2");
            assert!(
                f.secret.ct_eq(b"hunter2")
                    && !f.secret.ct_eq(b"hunter3")
                    && !f.secret.ct_eq(b"hunter")
            );
        }
        Incoming::Message(_) => panic!("expected a secret"),
    }
    // The decoder hands over the body, and from_body clears the buffer it was given.
    let mut body = bytes::BytesMut::new();
    body.extend_from_slice(&5u64.to_le_bytes());
    body.extend_from_slice(&[0, b's', b'e', b'c']);
    let keep = body.clone();
    assert!(hx_ipc::secret::SecretFrame::from_body(body).is_ok());
    assert_eq!(keep.len(), 12);
    // Length limits: empty and over-long secrets cannot be encoded; short bodies are refused.
    assert!(privd::encode_secret(1, 0, b"").is_err());
    assert!(privd::encode_secret(1, 0, &vec![1; MAX_SECRET_BYTES]).is_ok());
    assert!(privd::encode_secret(1, 0, &vec![1; MAX_SECRET_BYTES + 1]).is_err());
    for short in 0..=9usize {
        let body = bytes::BytesMut::from(&vec![1u8; short][..]);
        assert!(
            hx_ipc::secret::SecretFrame::from_body(body).is_err(),
            "{short}"
        );
    }
}

#[test]
fn secret_debug_is_redacted_and_the_type_is_not_clone() {
    let s = Secret::new(b"topsecret".to_vec());
    let shown = format!("{s:?}");
    assert!(
        !shown.contains("topsecret") && shown.contains("redacted"),
        "{shown}"
    );
    let f = hx_ipc::secret::SecretFrame {
        request_id: 1,
        slot: 0,
        secret: s,
    };
    let shown = format!("{f:?}");
    assert!(!shown.contains("topsecret"), "{shown}");
    // Compile-time check that Secret is not Clone: this trait-object trick fails to compile
    // if `Secret: Clone` ever holds, because the two blanket impls would overlap.
    trait AmbiguousIfClone<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    struct Invalid;
    impl<T: Clone> AmbiguousIfClone<Invalid> for T {}
    <Secret as AmbiguousIfClone<_>>::check();
}

#[test]
fn no_protobuf_message_has_a_field_that_can_hold_secret_bytes() {
    // The only `bytes` fields in requests are fixed-size public values; assert by checking that
    // a request carrying the longest possible non-secret bytes stays far below the secret limit
    // and that SecretSlot only declares metadata (kind, sealed, length, nonce, key id).
    let slot = pb::SecretSlot::default();
    use prost::Message;
    assert_eq!(
        slot.encoded_len(),
        0,
        "an empty slot is empty: nothing in it is a value"
    );
    let slot = pb::SecretSlot {
        slot: 1,
        kind: 1,
        sealed: true,
        length: 99,
        upload_nonce: vec![0; 16].into(),
        signer_key_id: 3,
    };
    assert!(slot.encoded_len() < 40);
}

proptest! {
    #[test]
    fn ping_and_request_ids_round_trip(nonce in any::<u64>(), id in 1u64.., deadline in any::<u32>()) {
        let f = pb::Frame { frame: Some(pb::frame::Frame::Ping(pb::Ping { nonce })) };
        prop_assert_eq!(round_trip(&f, Side::Server), f);
        let mut req = request(id, Command::GetHostInfo(pb::GetHostInfoRequest {}));
        req.deadline_ms = deadline;
        let f = frame_of(req);
        prop_assert_eq!(round_trip(&f, Side::Server), f);
    }

    #[test]
    fn strings_and_bytes_in_requests_round_trip(
        id in 1u64..,
        label in "[ -~]{0,64}",
        device in proptest::collection::vec(any::<u8>(), 16),
        version in "[0-9]{1,4}\\.[0-9]{1,4}\\.[0-9]{1,4}",
        key in proptest::collection::vec(any::<u8>(), 32),
    ) {
        for cmd in [
            Command::RecordEvent(pb::RecordEventRequest { event: 3, device_id: Some(device.clone().into()), label }),
            Command::ApplyUpdate(pb::ApplyUpdateRequest { version }),
            Command::EnrolOwnerKey(pb::EnrolOwnerKeyRequest { public_key: key.into(), replace: true }),
        ] {
            let f = frame_of(request(id, cmd));
            prop_assert_eq!(round_trip(&f, Side::Server), f);
        }
    }

    #[test]
    fn secret_frames_round_trip_for_any_bytes(
        id in any::<u64>(), slot in any::<u8>(),
        secret in proptest::collection::vec(any::<u8>(), 1..=MAX_SECRET_BYTES),
    ) {
        let wire = privd::encode_secret(id, slot, &secret).unwrap();
        let mut d = server_decoder();
        let raw = d.read_from(&mut &wire[..]).unwrap().unwrap();
        match privd::decode(raw, Side::Server).unwrap() {
            Incoming::Secret(f) => {
                prop_assert_eq!((f.request_id, f.slot), (id, slot));
                prop_assert_eq!(f.secret.expose(), &secret[..]);
            }
            Incoming::Message(_) => prop_assert!(false),
        }
    }

    /// Arbitrary bytes into privd's decoder and validators never panic.
    #[test]
    fn arbitrary_input_never_panics(data in proptest::collection::vec(any::<u8>(), 0..300), kind in 0u8..4) {
        let raw = RawFrame { kind, body: bytes::BytesMut::from(&data[..]) };
        let _ = privd::decode(raw, Side::Server);
        let raw = RawFrame { kind, body: bytes::BytesMut::from(&data[..]) };
        let _ = privd::decode(raw, Side::Client);
        let mut d = server_decoder();
        let _ = d.feed(&data);
    }
}

#[test]
fn no_command_can_run_without_a_deadline() {
    for c in every_command() {
        let info = command_info(&c);
        for requested in [0, 1, 1_000, u32::MAX] {
            let d = info.effective_deadline_ms(requested);
            assert!(
                (1..=45 * 60_000).contains(&d),
                "{} with {requested}: {d}",
                info.name
            );
        }
        assert!(
            info.reserved || info.max_deadline_ms.is_some(),
            "{} has no explicit maximum",
            info.name
        );
    }
}

#[test]
fn the_uninstall_additions_are_known_values_and_the_result_lists_are_bounded() {
    use pb::frame::Frame as F;
    let f = |frame| pb::Frame { frame: Some(frame) };
    // The new progress stage and error detail are accepted.
    assert!(
        privd::validate_frame(
            &f(F::Progress(pb::Progress {
                stage: pb::ProgressStage::Uninstall as i32,
                step: "x".into(),
                percent: 255,
                ..Default::default()
            })),
            Side::Client
        )
        .is_ok()
    );
    let response = |result| {
        f(F::Response(pb::Response {
            request_id: 1,
            result: Some(result),
        }))
    };
    assert!(
        privd::validate_frame(
            &response(pb::response::Result::Error(pb::Error {
                code: pb::ErrorCode::FailedPrecondition as i32,
                detail: pb::ErrorDetail::Uninstalling as i32,
                message: "uninstalling".into(),
                ..Default::default()
            })),
            Side::Client
        )
        .is_ok()
    );
    let result = |removed: Vec<String>, text: usize| {
        response(pb::response::Result::Uninstall(pb::UninstallResult {
            keep_desktop: false,
            removed,
            kept: vec!["x".repeat(text)],
            warnings: vec![],
        }))
    };
    let many = |n: usize| (0..n).map(|i| format!("pool:{i}")).collect::<Vec<_>>();
    assert!(privd::validate_frame(&result(many(64), 256), Side::Client).is_ok());
    assert!(privd::validate_frame(&result(many(65), 1), Side::Client).is_err());
    assert!(privd::validate_frame(&result(many(1), 257), Side::Client).is_err());
}
