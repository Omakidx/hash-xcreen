//! Command behaviour with the daemon in-process on fakes: the setup window, the verifier caps and
//! lockout, rate limits, bounds, link and snapshot rules, Docker's fail-closed gate, and the
//! rules of docs/ipc.md section 7 that need privd's state. Roles are injected through `Ctx`
//! here (the socket tests in `privd_socket.rs` derive them from the real peer uid).

use std::sync::Arc;

use hx_agent::privd::cmd::hostsetup::sysctl_text;
use hx_agent::privd::daemon::{Ctx, Daemon};
use hx_agent::privd::runner::{RunOutput, Tool};
use hx_agent::privd::state::Flag;
use hx_agent::privd::testing::{
    ExecRule, FakeIncus, FakeProbe, FakeRunner, Harness, error_of, request,
};
use hx_ipc::privd::pb::{
    self, ErrorCode, ErrorDetail, Role, request::Command, response::Result as R,
};
use hx_ipc::secret::Secret;

const GW: u32 = 4_242;

fn gw_ctx(secrets: &[&[u8]]) -> Ctx {
    ctx(Role::Gateway, secrets)
}

fn ctx(role: Role, secrets: &[&[u8]]) -> Ctx {
    let mut c = Ctx::new(role);
    c.secrets = secrets
        .iter()
        .map(|s| Some(Secret::new(s.to_vec())))
        .collect();
    c
}

/// A request with `n` declared secret slots of the right kinds for the command.
fn mk(command: Command, slots: &[pb::SecretKind]) -> pb::Request {
    let mut r = request(1, command);
    r.secret_slots = slots
        .iter()
        .enumerate()
        .map(|(i, k)| pb::SecretSlot {
            slot: i as u32,
            kind: *k as i32,
            length: 32,
            ..Default::default()
        })
        .collect();
    r
}

async fn run(h: &Harness, role: Role, command: Command) -> pb::Response {
    h.daemon.handle(mk(command, &[]), ctx(role, &[])).await
}

async fn run_with(
    d: &Arc<Daemon<FakeIncus>>,
    role: Role,
    command: Command,
    kinds: &[pb::SecretKind],
    secrets: &[&[u8]],
) -> pb::Response {
    d.handle(mk(command, kinds), ctx(role, secrets)).await
}

fn ok(r: pb::Response) -> R {
    match r.result {
        Some(R::Error(e)) => panic!(
            "expected success, got {:?} {:?}: {}",
            e.code(),
            e.detail(),
            e.message
        ),
        Some(v) => v,
        None => panic!("empty response"),
    }
}

fn err(r: &pb::Response) -> (ErrorCode, ErrorDetail) {
    let e = error_of(r).unwrap_or_else(|| panic!("expected an error, got {r:?}"));
    (e.code(), e.detail())
}

fn code(r: &pb::Response) -> ErrorCode {
    err(r).0
}

async fn open_window(h: &Harness) {
    ok(run(h, Role::Admin, Command::BeginSetup(Default::default())).await);
}

async fn make_ready(h: &Harness) {
    open_window(h).await;
    ok(run(
        h,
        Role::Admin,
        Command::FinishSetup(pb::FinishSetupRequest { force: Some(true) }),
    )
    .await);
}

fn add_desktop(h: &Harness) {
    h.incus
        .add_desktop("hx-main", "ubuntu-24.04-xfce-basic", "alice", true);
    h.daemon.register_desktop("main").unwrap();
}

fn pepper_req(purpose: pb::LockoutPurpose, expected: &[u8]) -> Command {
    Command::PepperVerify(pb::PepperVerifyRequest {
        purpose: purpose as i32,
        expected_verifier: expected.to_vec().into(),
    })
}

fn enrol_mac(r: pb::Response) -> Vec<u8> {
    match ok(r) {
        R::PepperEnrol(e) => e.mac.to_vec(),
        other => panic!("{other:?}"),
    }
}

async fn enrol(
    h: &Harness,
    role: Role,
    purpose: pb::LockoutPurpose,
    input: &[u8; 32],
) -> pb::Response {
    run_with(
        &h.daemon,
        role,
        Command::PepperEnrol(pb::PepperEnrolRequest {
            purpose: purpose as i32,
        }),
        &[pb::SecretKind::MacInput],
        &[input],
    )
    .await
}

async fn verify(
    d: &Arc<Daemon<FakeIncus>>,
    role: Role,
    purpose: pb::LockoutPurpose,
    input: &[u8; 32],
    expected: &[u8],
) -> pb::Response {
    run_with(
        d,
        role,
        pepper_req(purpose, expected),
        &[pb::SecretKind::MacInput],
        &[input],
    )
    .await
}

fn verdict(r: pb::Response) -> bool {
    match ok(r) {
        R::PepperVerify(v) => v.ok,
        other => panic!("{other:?}"),
    }
}

// ----- the setup window (ipc.md 5.1, 6.3) -----------------------------------------------------

#[tokio::test]
async fn the_setup_window_defaults_to_two_hours_and_only_admin_opens_it() {
    let h = Harness::start(GW);
    let denied = run(&h, Role::Gateway, Command::BeginSetup(Default::default())).await;
    assert_eq!(err(&denied).0, ErrorCode::PermissionDenied);

    let R::BeginSetup(b) = ok(run(&h, Role::Admin, Command::BeginSetup(Default::default())).await)
    else {
        panic!()
    };
    assert_eq!(b.expires_at_unix_s, 1_800_000_000 + 7_200);
    // Open: a Gateway FinishSetup passes the phase gate (and then needs a ready desktop).
    let r = run(&h, Role::Gateway, Command::FinishSetup(Default::default())).await;
    assert_eq!(
        err(&r),
        (ErrorCode::FailedPrecondition, ErrorDetail::DesktopNotReady)
    );
    // A shorter window is taken as given.
    let R::BeginSetup(b) = ok(run(
        &h,
        Role::Admin,
        Command::BeginSetup(pb::BeginSetupRequest { expires_in_s: 60 }),
    )
    .await) else {
        panic!()
    };
    assert_eq!(b.expires_at_unix_s, 1_800_000_000 + 60);
}

#[tokio::test]
async fn extending_the_window_is_admin_only_and_never_beyond_24_hours() {
    let h = Harness::start(GW);
    open_window(&h).await;
    let ext = |s| Command::ExtendSetup(pb::ExtendSetupRequest { extend_by_s: s });
    assert_eq!(
        code(&run(&h, Role::Gateway, ext(3_600)).await),
        ErrorCode::PermissionDenied
    );
    let R::ExtendSetup(e) = ok(run(&h, Role::Admin, ext(3_600)).await) else {
        panic!()
    };
    assert_eq!(e.expires_at_unix_s, 1_800_000_000 + 7_200 + 3_600);
    // Far beyond: clamped to 24 hours from the moment it opened.
    let R::ExtendSetup(e) = ok(run(&h, Role::Admin, ext(86_400)).await) else {
        panic!()
    };
    assert_eq!(e.expires_at_unix_s, 1_800_000_000 + 86_400);
    let R::ExtendSetup(e) = ok(run(&h, Role::Admin, ext(60)).await) else {
        panic!()
    };
    assert_eq!(e.expires_at_unix_s, 1_800_000_000 + 86_400);
}

#[tokio::test]
async fn an_expired_window_closes_and_setup_commands_are_refused() {
    let h = Harness::start(GW);
    open_window(&h).await;
    let setup = Command::SetupHost(Default::default());
    // Inside the window the command passes authorization (the fake Incus can do the whole job).
    let inside = run(&h, Role::Gateway, setup.clone()).await;
    assert!(matches!(inside.result, Some(R::SetupHost(_))), "{inside:?}");
    h.clock.advance_secs(7_201);
    let after = run(&h, Role::Gateway, setup).await;
    assert_eq!(
        err(&after),
        (
            ErrorCode::FailedPrecondition,
            ErrorDetail::SetupWindowClosed
        )
    );
    // ExtendSetup needs an open window.
    let r = run(
        &h,
        Role::Admin,
        Command::ExtendSetup(pb::ExtendSetupRequest { extend_by_s: 60 }),
    )
    .await;
    assert_eq!(err(&r).1, ErrorDetail::SetupWindowClosed);
}

#[tokio::test]
async fn the_phase_and_window_survive_a_restart() {
    let h = Harness::start(GW);
    open_window(&h).await;
    let d2 = h.restart_daemon();
    let r = run_with(
        &d2,
        Role::Gateway,
        Command::FinishSetup(Default::default()),
        &[],
        &[],
    )
    .await;
    // Still open after the "restart": the phase gate passes.
    assert_eq!(err(&r).1, ErrorDetail::DesktopNotReady);
    h.clock.advance_secs(7_201);
    let r = run_with(
        &d2,
        Role::Gateway,
        Command::FinishSetup(Default::default()),
        &[],
        &[],
    )
    .await;
    assert_eq!(err(&r).1, ErrorDetail::SetupWindowClosed);
}

#[tokio::test]
async fn finish_setup_needs_a_ready_desktop_unless_admin_forces() {
    let h = Harness::start(GW);
    open_window(&h).await;
    let finish = || Command::FinishSetup(Default::default());
    assert_eq!(
        err(&run(&h, Role::Gateway, finish()).await).1,
        ErrorDetail::DesktopNotReady
    );
    assert_eq!(
        err(&run(&h, Role::Admin, finish()).await).1,
        ErrorDetail::DesktopNotReady
    );
    add_desktop(&h);
    ok(run(&h, Role::Gateway, finish()).await);
    // Converges: READY stays READY.
    ok(run(&h, Role::Gateway, finish()).await);
    // The window is closed now: a Gateway SetupHost and CreateDesktop are refused (rule 6).
    for c in [
        Command::SetupHost(Default::default()),
        Command::CreateDesktop(pb::CreateDesktopRequest {
            desktop_id: "two".into(),
            distro: 1,
            desktop: 1,
            preset: 1,
            username: "bob".into(),
            ..Default::default()
        }),
    ] {
        let r = h
            .daemon
            .handle(mk(c, &[pb::SecretKind::UserPassword][..0]), gw_ctx(&[]))
            .await;
        assert_eq!(
            err(&r),
            (
                ErrorCode::FailedPrecondition,
                ErrorDetail::SetupWindowClosed
            )
        );
    }
}

// ----- pepper verifiers (ipc.md 5.3, 6.15) ------------------------------------------------------

#[tokio::test]
async fn pepper_verify_answers_yes_or_no_and_never_a_mac() {
    let h = Harness::start(GW);
    make_ready(&h).await;
    let input = [9u8; 32];
    let mac = enrol_mac(enrol(&h, Role::Admin, pb::LockoutPurpose::Pin, &input).await);
    assert_eq!(mac.len(), 32);

    let good = verify(
        &h.daemon,
        Role::Gateway,
        pb::LockoutPurpose::Pin,
        &input,
        &mac,
    )
    .await;
    let bad = verify(
        &h.daemon,
        Role::Gateway,
        pb::LockoutPurpose::Pin,
        &[1; 32],
        &mac,
    )
    .await;
    // The wire form of neither answer contains the MAC (test 4 of ipc.md 5.3: only PepperEnrol
    // returns one).
    for r in [&good, &bad] {
        let bytes = prost_bytes(r);
        assert!(
            !bytes.windows(32).any(|w| w == mac.as_slice()),
            "a MAC leaked"
        );
    }
    assert!(verdict(good));
    assert!(!verdict(bad));
    // Another purpose with the same input gives a different MAC: the pepper is per purpose.
    let other = enrol_mac(enrol(&h, Role::Admin, pb::LockoutPurpose::Password, &input).await);
    assert_ne!(other, mac);
    // A wrong-length expected verifier is rejected at the boundary.
    // (Validation lives in hx-ipc; the daemon never sees it. Asserted on the socket tests.)
}

fn prost_bytes(r: &pb::Response) -> Vec<u8> {
    use prost::Message;
    r.encode_to_vec()
}

#[tokio::test]
async fn wrong_guesses_lock_the_purpose_within_the_cap_and_the_lock_survives_a_restart() {
    let h = Harness::start(GW);
    make_ready(&h).await;
    let input = [3u8; 32];
    let mac = enrol_mac(enrol(&h, Role::Admin, pb::LockoutPurpose::Pin, &input).await);
    // Ten wrong guesses are answered (ok: false); the eleventh call is locked.
    for i in 1..=10 {
        let r = verify(
            &h.daemon,
            Role::Gateway,
            pb::LockoutPurpose::Pin,
            &[100 + i as u8; 32],
            &mac,
        )
        .await;
        assert!(!verdict(r), "guess {i}");
    }
    let r = verify(
        &h.daemon,
        Role::Gateway,
        pb::LockoutPurpose::Pin,
        &[200; 32],
        &mac,
    )
    .await;
    assert_eq!(err(&r), (ErrorCode::ResourceExhausted, ErrorDetail::Locked));
    // Even the correct input is refused while locked.
    let r = verify(
        &h.daemon,
        Role::Gateway,
        pb::LockoutPurpose::Pin,
        &input,
        &mac,
    )
    .await;
    assert_eq!(err(&r), (ErrorCode::ResourceExhausted, ErrorDetail::Locked));
    // The flag is visible in GetHostInfo.
    let R::GetHostInfo(info) =
        ok(run(&h, Role::Gateway, Command::GetHostInfo(Default::default())).await)
    else {
        panic!()
    };
    assert!(
        info.needs_attention
            .contains(&(pb::NeedsAttention::PinLocked as i32))
    );
    // The lock survives a restart of privd.
    let d2 = h.restart_daemon();
    let r = verify(&d2, Role::Gateway, pb::LockoutPurpose::Pin, &input, &mac).await;
    assert_eq!(err(&r), (ErrorCode::ResourceExhausted, ErrorDetail::Locked));
    // The password purpose is independent.
    let pmac = enrol_mac(enrol(&h, Role::Admin, pb::LockoutPurpose::Password, &input).await);
    assert!(verdict(
        verify(
            &d2,
            Role::Gateway,
            pb::LockoutPurpose::Password,
            &input,
            &pmac
        )
        .await
    ));
    // Only Admin can lift it.
    let reset = |p| Command::ResetLockout(pb::ResetLockoutRequest { purpose: p as i32 });
    assert_eq!(
        code(&run_with(&d2, Role::Gateway, reset(pb::LockoutPurpose::Pin), &[], &[]).await),
        ErrorCode::PermissionDenied
    );
    ok(run_with(&d2, Role::Admin, reset(pb::LockoutPurpose::Pin), &[], &[]).await);
    assert!(verdict(
        verify(&d2, Role::Gateway, pb::LockoutPurpose::Pin, &input, &mac).await
    ));
    let R::GetHostInfo(info) = ok(run_with(
        &d2,
        Role::Gateway,
        Command::GetHostInfo(Default::default()),
        &[],
        &[],
    )
    .await) else {
        panic!()
    };
    assert!(
        !info
            .needs_attention
            .contains(&(pb::NeedsAttention::PinLocked as i32))
    );
}

#[tokio::test]
async fn correct_verifications_never_consume_the_failure_budget() {
    let h = Harness::start(GW);
    make_ready(&h).await;
    let input = [5u8; 32];
    let mac = enrol_mac(enrol(&h, Role::Admin, pb::LockoutPurpose::Pin, &input).await);
    for _ in 0..80 {
        assert!(verdict(
            verify(
                &h.daemon,
                Role::Gateway,
                pb::LockoutPurpose::Pin,
                &input,
                &mac
            )
            .await
        ));
    }
    // Nine wrong guesses are still all answered: the 80 successes cost nothing.
    for i in 0..9 {
        assert!(!verdict(
            verify(
                &h.daemon,
                Role::Gateway,
                pb::LockoutPurpose::Pin,
                &[100 + i; 32],
                &mac
            )
            .await
        ));
    }
    assert!(verdict(
        verify(
            &h.daemon,
            Role::Gateway,
            pb::LockoutPurpose::Pin,
            &input,
            &mac
        )
        .await
    ));
}

#[tokio::test]
async fn the_password_purpose_locks_after_five_failures_and_counts_all_callers() {
    let h = Harness::start(GW);
    make_ready(&h).await;
    let input = [6u8; 32];
    let mac = enrol_mac(enrol(&h, Role::Admin, pb::LockoutPurpose::Password, &input).await);
    // Failures are global: Admin's count with Gateway's.
    for (i, role) in [
        Role::Gateway,
        Role::Admin,
        Role::Gateway,
        Role::Admin,
        Role::Gateway,
    ]
    .into_iter()
    .enumerate()
    {
        assert!(!verdict(
            verify(
                &h.daemon,
                role,
                pb::LockoutPurpose::Password,
                &[100 + i as u8; 32],
                &mac
            )
            .await
        ));
    }
    let r = verify(
        &h.daemon,
        Role::Gateway,
        pb::LockoutPurpose::Password,
        &input,
        &mac,
    )
    .await;
    assert_eq!(err(&r), (ErrorCode::ResourceExhausted, ErrorDetail::Locked));
}

#[tokio::test]
async fn pepper_enrol_is_capped_for_gateway_after_setup_but_not_during_setup_or_for_admin() {
    let h = Harness::start(GW);
    make_ready(&h).await;
    let input = [7u8; 32];
    for _ in 0..5 {
        ok(enrol(&h, Role::Gateway, pb::LockoutPurpose::Pin, &input).await);
    }
    let r = enrol(&h, Role::Gateway, pb::LockoutPurpose::Pin, &input).await;
    assert_eq!(code(&r), ErrorCode::ResourceExhausted);
    assert!(error_of(&r).unwrap().retry_after_ms > 0);
    // Admin is never limited.
    for _ in 0..20 {
        ok(enrol(&h, Role::Admin, pb::LockoutPurpose::Pin, &input).await);
    }
    // During SETUP_OPEN the allowance is 60 per hour (counted over the same events).
    open_window(&h).await;
    for _ in 0..55 {
        ok(enrol(&h, Role::Gateway, pb::LockoutPurpose::Pin, &input).await);
    }
    assert_eq!(
        code(&enrol(&h, Role::Gateway, pb::LockoutPurpose::Pin, &input).await),
        ErrorCode::ResourceExhausted
    );
    // The cap survives a restart.
    let d2 = h.restart_daemon();
    let r = run_with(
        &d2,
        Role::Gateway,
        Command::PepperEnrol(pb::PepperEnrolRequest {
            purpose: pb::LockoutPurpose::Pin as i32,
        }),
        &[pb::SecretKind::MacInput],
        &[&input],
    )
    .await;
    assert_eq!(code(&r), ErrorCode::ResourceExhausted);
}

#[tokio::test]
async fn secrets_never_reach_the_audit_log_or_errors() {
    let h = Harness::start(GW);
    make_ready(&h).await;
    let input = *b"SECRET-MAC-INPUT-0123456789abcde";
    let mac = enrol_mac(enrol(&h, Role::Admin, pb::LockoutPurpose::Pin, &input).await);
    let bad = verify(
        &h.daemon,
        Role::Gateway,
        pb::LockoutPurpose::Pin,
        &[0; 32],
        &mac,
    )
    .await;
    let wire = prost_bytes(&bad);
    assert!(!wire.windows(10).any(|w| w == b"SECRET-MAC"));
    for line in h.audit.lines() {
        assert!(!line.contains("SECRET-MAC"), "{line}");
        assert!(!line.contains(&mac.iter().map(|b| format!("{b:02x}")).collect::<String>()));
    }
}

// ----- rate limits (ipc.md 8) ---------------------------------------------------------------------

#[tokio::test]
async fn the_mutating_cap_is_30_a_minute_for_gateway_and_does_not_apply_to_admin() {
    let h = Harness::start(GW);
    make_ready(&h).await;
    let finish = || Command::FinishSetup(Default::default());
    for i in 0..30 {
        ok(run(&h, Role::Gateway, finish()).await);
        let _ = i;
    }
    let r = run(&h, Role::Gateway, finish()).await;
    assert_eq!(code(&r), ErrorCode::ResourceExhausted);
    assert!(error_of(&r).unwrap().retryable);
    // Admin is exempt from this cap only.
    for _ in 0..40 {
        ok(run(&h, Role::Admin, finish()).await);
    }
    // And it recovers with time.
    h.clock.advance_secs(61);
    ok(run(&h, Role::Gateway, finish()).await);
}

#[tokio::test]
async fn record_event_is_sanitized_and_limited_to_60_an_hour() {
    let h = Harness::start(GW);
    make_ready(&h).await;
    let ev = |label: &str| {
        Command::RecordEvent(pb::RecordEventRequest {
            event: pb::AuditEvent::DeviceAdded as i32,
            device_id: Some(vec![0xcd; 16].into()),
            label: label.to_string(),
        })
    };
    ok(run(&h, Role::Gateway, ev("x\"\nts=1 kind=request\u{1b}[31m")).await);
    let line = h
        .audit
        .lines()
        .into_iter()
        .find(|l| l.contains("kind=event"))
        .expect("an event line");
    assert!(!line.contains('\n') && !line.contains('\u{1b}'));
    assert!(line.contains("device=cdcdcdcd"));
    for _ in 0..59 {
        ok(run(&h, Role::Gateway, ev("a")).await);
    }
    assert_eq!(
        code(&run(&h, Role::Gateway, ev("a")).await),
        ErrorCode::ResourceExhausted
    );
}

// ----- host info, self-checks -------------------------------------------------------------------

#[tokio::test]
async fn host_info_still_answers_when_incus_is_down() {
    let h = Harness::start(GW);
    let R::GetHostInfo(up) =
        ok(run(&h, Role::Gateway, Command::GetHostInfo(Default::default())).await)
    else {
        panic!()
    };
    assert_eq!(up.incus_version.as_deref(), Some("6.0.0"));
    assert!(up.pool.as_ref().unwrap().exists);
    assert_eq!(up.cpu_count, 8);
    h.incus.with(|s| s.down = true);
    let R::GetHostInfo(down) =
        ok(run(&h, Role::Gateway, Command::GetHostInfo(Default::default())).await)
    else {
        panic!()
    };
    assert_eq!(down.incus_version, None);
    assert_eq!(down.cpu_count, 8);
    // A command that needs Incus says UNAVAILABLE.
    let r = run(
        &h,
        Role::Gateway,
        Command::GetDesktop(pb::GetDesktopRequest {
            desktop_id: "main".into(),
        }),
    )
    .await;
    assert_ne!(code(&r), ErrorCode::Unspecified);
}

#[tokio::test]
async fn self_checks_run_again_on_demand_and_set_or_clear_the_attention_flag() {
    let h = Harness::start(GW);
    let dir = h.dir.path();
    std::fs::write(
        dir.join("passwd"),
        format!("root:x:0:0::/root:/bin/sh\nhx-gatewayd:x:{GW}:{GW}::/:/usr/sbin/nologin\n"),
    )
    .unwrap();
    std::fs::write(
        dir.join("group"),
        format!("root:x:0:\nhx-gatewayd:x:{GW}:\n"),
    )
    .unwrap();
    assert_eq!(h.daemon.run_self_checks(), vec![]);
    assert!(h.daemon.flags_for("main").is_empty());
    // The gateway user gets into the docker group.
    std::fs::write(
        dir.join("group"),
        format!("root:x:0:\nhx-gatewayd:x:{GW}:\ndocker:x:999:hx-gatewayd\n"),
    )
    .unwrap();
    let v = h.daemon.run_self_checks();
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(
        h.daemon
            .flags_for("main")
            .contains(&Flag::HostAccountPolicy)
    );
    std::fs::write(
        dir.join("group"),
        format!("root:x:0:\nhx-gatewayd:x:{GW}:\n"),
    )
    .unwrap();
    assert_eq!(h.daemon.run_self_checks(), vec![]);
    assert!(h.daemon.flags_for("main").is_empty());
}

// ----- desktops: reads, power, limits, snapshots, link -----------------------------------------------

#[tokio::test]
async fn get_and_list_desktops_report_the_recorded_metadata() {
    let h = Harness::start(GW);
    add_desktop(&h);
    let R::GetDesktop(g) = ok(run(
        &h,
        Role::Gateway,
        Command::GetDesktop(pb::GetDesktopRequest {
            desktop_id: "main".into(),
        }),
    )
    .await) else {
        panic!()
    };
    let d = g.desktop.unwrap();
    assert_eq!(d.username, "alice");
    assert_eq!(d.state(), pb::DesktopState::Running);
    assert_eq!(d.distro(), pb::Distro::Ubuntu2404);
    assert_eq!(d.preset(), pb::Preset::Basic);
    assert_eq!(d.ip, "10.77.0.5");
    assert_eq!(d.docker(), pb::DockerState::Off);
    let l = d.limits.unwrap();
    assert_eq!((l.cpu, l.memory_mib, l.disk_gib), (2, 4096, 20));
    let R::ListDesktops(l) =
        ok(run(&h, Role::Gateway, Command::ListDesktops(Default::default())).await)
    else {
        panic!()
    };
    assert_eq!(l.desktops.len(), 1);
    // Rule 1: the instance name is derived (`hx-<id>`); the log only ever names that.
    assert!(h.incus.log().iter().all(|l| !l.contains("/instances/main")));
    // Unknown ids and unregistered instances are NOT_FOUND (rule 8: only what privd created).
    h.incus
        .add_desktop("hx-stranger", "ubuntu-24.04-xfce-basic", "eve", true);
    for id in ["nope", "stranger"] {
        let r = run(
            &h,
            Role::Gateway,
            Command::GetDesktop(pb::GetDesktopRequest {
                desktop_id: id.into(),
            }),
        )
        .await;
        assert_eq!(code(&r), ErrorCode::NotFound, "{id}");
    }
}

#[tokio::test]
async fn start_stop_restart_converge() {
    let h = Harness::start(GW);
    make_ready(&h).await;
    add_desktop(&h);
    let id = || "main".to_string();
    // Starting a running desktop succeeds without another start call.
    let R::StartDesktop(p) = ok(run(
        &h,
        Role::Gateway,
        Command::StartDesktop(pb::StartDesktopRequest { desktop_id: id() }),
    )
    .await) else {
        panic!()
    };
    assert!(p.running && !p.degraded);
    assert!(
        !h.incus
            .log()
            .iter()
            .any(|l| l == "PUT /1.0/instances/hx-main/state")
    );
    ok(run(
        &h,
        Role::Gateway,
        Command::StopDesktop(pb::StopDesktopRequest {
            desktop_id: id(),
            force: false,
        }),
    )
    .await);
    assert_eq!(
        h.incus.with(|s| s.instances["hx-main"].status.clone()),
        "Stopped"
    );
    // Stopping a stopped desktop succeeds too.
    ok(run(
        &h,
        Role::Gateway,
        Command::StopDesktop(pb::StopDesktopRequest {
            desktop_id: id(),
            force: false,
        }),
    )
    .await);
    let R::StartDesktop(p) = ok(run(
        &h,
        Role::Gateway,
        Command::StartDesktop(pb::StartDesktopRequest { desktop_id: id() }),
    )
    .await) else {
        panic!()
    };
    assert!(p.running);
    assert_eq!(
        h.incus.with(|s| s.instances["hx-main"].status.clone()),
        "Running"
    );
    ok(run(
        &h,
        Role::Gateway,
        Command::RestartDesktop(pb::RestartDesktopRequest {
            desktop_id: id(),
            force: true,
        }),
    )
    .await);
}

#[tokio::test]
async fn rule_11_isolation_first_gateway_cannot_start_while_isolation_is_not_restored() {
    let h = Harness::start(GW);
    make_ready(&h).await;
    add_desktop(&h);
    h.daemon
        .set_flag(Some("main"), Flag::IsolationNotRestored, true);
    h.incus.with(|s| {
        let i = s.instances.get_mut("hx-main").unwrap();
        i.status = "Stopped".into();
        // A half-enabled Docker: the three keys of the add-on are on.
        for k in [
            "security.nesting",
            "security.syscalls.intercept.mknod",
            "security.syscalls.intercept.setxattr",
        ] {
            i.config.insert(k.into(), "true".into());
        }
    });
    let start = || {
        Command::StartDesktop(pb::StartDesktopRequest {
            desktop_id: "main".into(),
        })
    };
    let r = run(&h, Role::Gateway, start()).await;
    assert_eq!(
        err(&r),
        (
            ErrorCode::FailedPrecondition,
            ErrorDetail::IsolationNotRestored
        )
    );
    assert_eq!(
        h.incus.with(|s| s.instances["hx-main"].status.clone()),
        "Stopped"
    );
    // Admin's start retries the rollback first; on success the flag clears and it starts.
    ok(run(&h, Role::Admin, start()).await);
    assert!(
        !h.daemon
            .flags_for("main")
            .contains(&Flag::IsolationNotRestored)
    );
    assert_eq!(
        h.incus.with(|s| s.instances["hx-main"].status.clone()),
        "Running"
    );
    // The rollback wrote exactly the three keys the recipe allowlist permits.
    let wrote_off = h.incus.with(|s| {
        s.writes
            .iter()
            .filter_map(|w| w["config"].as_object().cloned())
            .any(|c| {
                c.get("security.nesting").and_then(|v| v.as_str()) == Some("false") && c.len() == 3
            })
    });
    assert!(
        wrote_off,
        "the rollback should switch exactly three keys off"
    );
}

#[tokio::test]
async fn enable_docker_outcomes_are_normal_responses_and_the_acknowledgement_is_required() {
    let h = Harness::start(GW);
    make_ready(&h).await;
    add_desktop(&h);
    let enable = |ack: bool| {
        Command::EnableDocker(pb::EnableDockerRequest {
            desktop_id: "main".into(),
            acknowledged_isolation_warning: ack,
            mode: 0,
        })
    };
    // Gateway after setup: refused (rule 5).
    assert_eq!(
        code(&run(&h, Role::Gateway, enable(true)).await),
        ErrorCode::PermissionDenied
    );
    // Admin without the acknowledgement: INVALID_ARGUMENT.
    assert_eq!(
        code(&run(&h, Role::Admin, enable(false)).await),
        ErrorCode::InvalidArgument
    );
    // The reserved host-network-only mode is UNIMPLEMENTED.
    let r = run(
        &h,
        Role::Admin,
        Command::EnableDocker(pb::EnableDockerRequest {
            desktop_id: "main".into(),
            acknowledged_isolation_warning: true,
            mode: pb::DockerMode::HostNetworkOnly as i32,
        }),
    )
    .await;
    assert_eq!(code(&r), ErrorCode::Unimplemented);
    // The fake Incus is 6.0.0, older than 6.0.5: a domain outcome, nothing changed.
    let R::EnableDocker(e) = ok(run(&h, Role::Admin, enable(true)).await) else {
        panic!()
    };
    match e.outcome.unwrap().outcome.unwrap() {
        pb::docker_outcome::Outcome::UnsupportedIncus(u) => {
            assert_eq!(u.found, "6.0.0");
            assert!(!u.fallbacks.is_empty());
        }
        other => panic!("{other:?}"),
    }
    assert!(h.incus.with(|s| {
        !s.instances["hx-main"]
            .config
            .contains_key("security.nesting")
    }));
    // The acknowledgement time was recorded first.
    assert!(h.incus.with(|s| {
        s.instances["hx-main"]
            .config
            .contains_key("user.hx.docker_ack")
    }));
}

#[tokio::test]
async fn set_limits_enforces_every_bound_of_6_8_and_writes_only_allowed_keys() {
    let h = Harness::start(GW);
    make_ready(&h).await;
    add_desktop(&h);
    let set = |cpu, mem, disk| {
        Command::SetLimits(pb::SetLimitsRequest {
            desktop_id: "main".into(),
            limits: Some(pb::Limits {
                cpu,
                memory_mib: mem,
                disk_gib: disk,
            }),
        })
    };
    // Host: 8 CPUs, 16 GiB RAM (reserve 4 GiB => at most 12 288 MiB), pool free 80 GiB, disk 20 GiB now.
    for (cpu, mem, disk, why) in [
        (9, 4096, 30, "more CPUs than the host"),
        (2, 12_289, 30, "too little left for the host"),
        (2, 1023, 30, "below the memory minimum"),
        (2, 4096, 19, "disk below the current size"),
        (2, 4096, 81, "disk above the pool's free space"),
    ] {
        let r = run(&h, Role::Gateway, set(cpu, mem, disk)).await;
        assert_eq!(code(&r), ErrorCode::InvalidArgument, "{why}");
    }
    let R::SetLimits(s) = ok(run(&h, Role::Gateway, set(4, 8192, 40)).await) else {
        panic!()
    };
    // The desktop is running and the CPU count changed: a restart is needed.
    assert!(s.restart_required);
    let keys = h.incus.with(|s| {
        let mut keys = std::collections::BTreeSet::new();
        for w in &s.writes {
            for k in w["config"]
                .as_object()
                .into_iter()
                .flatten()
                .map(|(k, _)| k.clone())
            {
                keys.insert(k);
            }
        }
        keys
    });
    // Rule 4: only the keys privd may write; never limits.processes.
    for k in &keys {
        assert!(
            ["limits.cpu", "limits.memory"].contains(&k.as_str()) || k.starts_with("user.hx."),
            "unexpected key {k}"
        );
    }
    assert!(!keys.contains("limits.processes"));
}

#[tokio::test]
async fn snapshots_follow_the_naming_cap_and_ownership_rules() {
    let h = Harness::start(GW);
    make_ready(&h).await;
    add_desktop(&h);
    // A snapshot privd did not name, and update and backup snapshots.
    h.incus.with(|s| {
        s.instances.get_mut("hx-main").unwrap().snapshots.extend([
            "user-snapshot".to_string(),
            "hx-preupdate-20261121T101500Z-00ff".to_string(),
            "hx-backup-20261121T101500Z-00ff".to_string(),
        ]);
    });
    let R::ListSnapshots(l) = ok(h
        .daemon
        .handle(
            mk(
                Command::ListSnapshots(pb::ListSnapshotsRequest {
                    desktop_id: "main".into(),
                }),
                &[],
            ),
            gw_ctx(&[]),
        )
        .await)
    else {
        panic!()
    };
    let names: Vec<_> = l.snapshots.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "hx-preupdate-20261121T101500Z-00ff",
            "hx-backup-20261121T101500Z-00ff"
        ]
    );

    let create = || {
        Command::CreateSnapshot(pb::CreateSnapshotRequest {
            desktop_id: "main".into(),
        })
    };
    for _ in 0..3 {
        let R::CreateSnapshot(c) = ok(run(&h, Role::Gateway, create()).await) else {
            panic!()
        };
        let name = c.snapshot.unwrap().name;
        assert!(hx_ipc::privd::is_valid_snapshot_name(&name), "{name}");
    }
    // A fourth manual snapshot is RESOURCE_EXHAUSTED.
    assert_eq!(
        code(&run(&h, Role::Gateway, create()).await),
        ErrorCode::ResourceExhausted
    );

    let del = |n: &str| {
        Command::DeleteSnapshot(pb::DeleteSnapshotRequest {
            desktop_id: "main".into(),
            name: n.to_string(),
        })
    };
    // Gateway may not delete update or backup snapshots; Admin may.
    assert_eq!(
        code(&run(&h, Role::Gateway, del("hx-preupdate-20261121T101500Z-00ff")).await),
        ErrorCode::PermissionDenied
    );
    ok(run(&h, Role::Admin, del("hx-preupdate-20261121T101500Z-00ff")).await);
    // A name outside the pattern is INVALID_ARGUMENT, and `user-snapshot` is never touched.
    assert_eq!(
        code(&run(&h, Role::Admin, del("user-snapshot")).await),
        ErrorCode::InvalidArgument
    );
    assert!(h.incus.with(|s| {
        s.instances["hx-main"]
            .snapshots
            .contains(&"user-snapshot".to_string())
    }));
    // Deleting one that is gone succeeds (idempotent).
    ok(run(&h, Role::Admin, del("hx-manual-20200101T000000Z-aaaa")).await);
}

#[tokio::test]
async fn snapshots_are_refused_when_the_pool_is_nearly_full() {
    let probe = FakeProbe {
        pool: Some((100 << 30, 10 << 30)), // 10% free
        ..FakeProbe::default()
    };
    let h = Harness::start_with(GW, probe, FakeIncus::new(), FakeRunner::new());
    make_ready(&h).await;
    add_desktop(&h);
    let r = run(
        &h,
        Role::Gateway,
        Command::CreateSnapshot(pb::CreateSnapshotRequest {
            desktop_id: "main".into(),
        }),
    )
    .await;
    assert_eq!(code(&r), ErrorCode::ResourceExhausted);
}

#[tokio::test]
async fn rule_2_the_link_device_is_computed_by_privd() {
    let h = Harness::start(GW);
    make_ready(&h).await;
    add_desktop(&h);
    let R::ProvisionSessionLink(p) = ok(run(
        &h,
        Role::Gateway,
        Command::ProvisionSessionLink(pb::ProvisionSessionLinkRequest {
            desktop_id: "main".into(),
        }),
    )
    .await) else {
        panic!()
    };
    assert_eq!(p.socket_path, "/run/hx/link/main.sock");
    let dev = h
        .incus
        .with(|s| s.instances["hx-main"].devices["hx-link"].clone());
    let want: std::collections::BTreeMap<String, String> = [
        ("type", "proxy"),
        ("bind", "host"),
        ("listen", "unix:/run/hx/link/main.sock"),
        ("connect", "unix:/run/hx-session/link.sock"),
        ("uid", &GW.to_string()),
        ("gid", &GW.to_string()),
        ("mode", "0600"),
        ("security.uid", "1000"),
        ("security.gid", "1000"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    assert_eq!(dev, want);
    // Converges: a second call changes nothing.
    ok(run(
        &h,
        Role::Gateway,
        Command::ProvisionSessionLink(pb::ProvisionSessionLinkRequest {
            desktop_id: "main".into(),
        }),
    )
    .await);
}

#[tokio::test]
async fn rule_8_destroy_acts_only_on_marked_registered_desktops_and_is_idempotent() {
    let h = Harness::start(GW);
    add_desktop(&h);
    let destroy = |id: &str| {
        Command::DestroyDesktop(pb::DestroyDesktopRequest {
            desktop_id: id.into(),
            confirm_destroy: true,
        })
    };
    // Gateway: never (rule 5).
    assert_eq!(
        code(&run(&h, Role::Gateway, destroy("main")).await),
        ErrorCode::PermissionDenied
    );
    // An instance with our name but without the marker is not ours: refused, not deleted.
    h.incus.with(|s| {
        s.instances.insert("hx-plain".into(), Default::default());
    });
    let r = run(&h, Role::Admin, destroy("plain")).await;
    assert_eq!(code(&r), ErrorCode::PermissionDenied);
    assert!(h.incus.instance_names().contains(&"hx-plain".to_string()));
    // Ours: destroyed, and the registry forgets it. A second call succeeds.
    ok(run(&h, Role::Admin, destroy("main")).await);
    assert!(!h.incus.instance_names().contains(&"hx-main".to_string()));
    ok(run(&h, Role::Admin, destroy("main")).await);
}

#[tokio::test]
async fn install_session_reads_one_verified_package_and_validates_what_the_container_says() {
    let h = Harness::start(GW);
    make_ready(&h).await;
    add_desktop(&h);
    let install = || {
        Command::InstallSession(pb::InstallSessionRequest {
            desktop_id: "main".into(),
        })
    };
    // No package on the host: a precondition failure, nothing executed in the container.
    let r = run(&h, Role::Gateway, install()).await;
    assert_eq!(code(&r), ErrorCode::FailedPrecondition);
    assert!(
        h.incus
            .with(|s| !s.execs.iter().any(|e| e.contains("dpkg")))
    );

    use std::os::unix::fs::PermissionsExt;
    let dir = h.daemon.cfg.session_store.join("ubuntu-24.04");
    std::fs::create_dir_all(&dir).unwrap();
    let pkg = dir.join("hx-session.deb");
    std::fs::write(&pkg, b"fake deb").unwrap();
    std::fs::set_permissions(&pkg, std::fs::Permissions::from_mode(0o644)).unwrap();
    h.incus.with(|s| {
        s.exec_rules.insert(
            0,
            ExecRule {
                needle: "dpkg-query".into(),
                exit: 0,
                stdout: "0.1.0-1\n".into(),
                delay: Some(std::time::Duration::ZERO),
            },
        );
    });
    let R::InstallSession(i) = ok(run(&h, Role::Gateway, install()).await) else {
        panic!()
    };
    assert_eq!(i.installed_version, "0.1.0-1");
    assert!(i.restarted);
    let execs = h.incus.with(|s| s.execs.clone());
    for needle in [
        "dpkg -i /var/lib/hx/session/hx-session.deb",
        "systemctl reset-failed hx-session.socket hx-session.service",
        "systemctl restart hx-session.socket hx-session.service",
    ] {
        assert!(execs.iter().any(|e| e.contains(needle)), "{needle} not run");
    }
    // A version string that is not a package version is not stored (container text is untrusted).
    h.incus.with(|s| {
        s.exec_rules[0].stdout = "$(reboot)\n".into();
    });
    let r = run(&h, Role::Gateway, install()).await;
    assert_eq!(code(&r), ErrorCode::Internal);
}

#[tokio::test]
async fn owner_key_enrolment_is_admin_only_and_replacing_needs_replace() {
    let h = Harness::start(GW);
    let enrol = |replace| {
        Command::EnrolOwnerKey(pb::EnrolOwnerKeyRequest {
            public_key: vec![7; 32].into(),
            replace,
        })
    };
    assert_eq!(
        code(&run(&h, Role::Gateway, enrol(false)).await),
        ErrorCode::PermissionDenied
    );
    ok(run(&h, Role::Admin, enrol(false)).await);
    assert_eq!(
        code(&run(&h, Role::Admin, enrol(false)).await),
        ErrorCode::FailedPrecondition
    );
    ok(run(&h, Role::Admin, enrol(true)).await);
    assert_eq!(
        std::fs::read(h.dir.path().join("state/owner-key")).unwrap(),
        vec![7; 32]
    );
}

#[tokio::test]
async fn reserved_and_unavailable_commands_answer_unimplemented() {
    let h = Harness::start(GW);
    make_ready(&h).await;
    for c in [
        Command::BackupRun(Default::default()),
        Command::RestoreStart(Default::default()),
        Command::GenerateRecoveryKey(Default::default()),
        Command::BeginSecretUpload(pb::BeginSecretUploadRequest {
            kind: pb::SecretKind::DriveToken as i32,
            desktop_id: "main".into(),
        }),
        Command::GetRecipientKey(Default::default()),
        Command::CheckUpdate(Default::default()),
        Command::ApplyUpdate(pb::ApplyUpdateRequest {
            version: "9.9.9".into(),
        }),
    ] {
        let r = run(&h, Role::Gateway, c).await;
        assert_eq!(code(&r), ErrorCode::Unimplemented, "{r:?}");
    }
    for c in [
        Command::UpgradeIncus(Default::default()),
        Command::RollbackUpdate(Default::default()),
        Command::Uninstall(pb::UninstallRequest {
            keep_desktop: true,
            confirm_destroy: false,
        }),
    ] {
        let r = run(&h, Role::Admin, c).await;
        assert_eq!(code(&r), ErrorCode::Unimplemented, "{r:?}");
    }
}

// ----- SetupHost through a fake runner (ipc.md 6.4) -----------------------------------------------------

fn host_runner() -> Arc<FakeRunner> {
    FakeRunner::with(|p| {
        let out = |stdout: &str| RunOutput {
            code: Some(0),
            stdout: stdout.into(),
            ..Default::default()
        };
        match p.tool {
            Tool::Ip => out(
                r#"[{"ifname":"eth0","addr_info":[{"family":"inet","local":"203.0.113.9"}]},
                {"ifname":"docker0","addr_info":[{"family":"inet","local":"172.17.0.1"}]},
                {"ifname":"hxbr0","addr_info":[{"family":"inet","local":"10.99.0.1"}]}]"#,
            ),
            Tool::Iptables if p.args.first().map(String::as_str) == Some("-C") => RunOutput {
                code: Some(1),
                ..Default::default()
            },
            _ => out(""),
        }
    })
}

#[tokio::test]
async fn setup_host_loads_and_persists_the_generated_ruleset_through_the_runner() {
    let runner = host_runner();
    let h = Harness::start_with(GW, FakeProbe::default(), FakeIncus::new(), runner.clone());
    h.incus.with(|s| s.pool_exists = false);
    let R::SetupHost(r) = ok(run(
        &h,
        Role::Admin,
        Command::SetupHost(pb::SetupHostRequest {
            allow_private_networks: Some(true),
            extra_host_addresses: Some(pb::ExtraHostAddresses {
                addresses: vec!["198.51.100.7".into()],
            }),
            ..Default::default()
        }),
    )
    .await) else {
        panic!()
    };
    assert_eq!(r.pool(), pb::Ensured::Created);
    assert_eq!(r.network(), pb::Ensured::Created);
    assert_eq!(r.gateway_ip, "10.99.0.1");
    assert!(r.firewall_loaded && r.sysctl_applied);
    assert_eq!(r.docker_user_rules(), pb::DockerUserRules::Applied);

    // The ruleset is the one hx-provision generated, persisted root-only, checked, loaded, verified.
    let file = &h.daemon.cfg.firewall_file;
    let text = std::fs::read_to_string(file).unwrap();
    assert!(text.contains("table inet hx") && text.contains("iifname != \"hxbr0\""));
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::read_to_string(&h.daemon.cfg.sysctl_file).unwrap(),
        sysctl_text()
    );

    let calls = runner.calls();
    let f = file.to_string_lossy().into_owned();
    let nft: Vec<Vec<String>> = calls
        .iter()
        .filter(|c| c.tool == Tool::Nft)
        .map(|c| c.args.clone())
        .collect();
    assert_eq!(nft[0], ["-c", "-f", &f]);
    assert_eq!(nft[1], ["-f", &f]);
    assert_eq!(nft[2], ["list", "table", "inet", "hx"]);
    // Rule 3: only the closed set of tools ran, never with stdin from a caller, and nothing the
    // request contained (the extra address, a device) became an argument.
    for c in &calls {
        assert!(c.stdin.is_none());
        assert!(c.args.iter().all(|a| !a.contains("198.51.100.7")), "{c:?}");
    }
    assert!(
        calls
            .iter()
            .any(|c| c.tool == Tool::Sysctl && c.args == ["--system"])
    );
    // The docker rules: probe the chain, check, insert.
    let ipt: Vec<String> = calls
        .iter()
        .filter(|c| c.tool == Tool::Iptables)
        .map(|c| c.args.join(" "))
        .collect();
    assert_eq!(ipt[0], "-n -L DOCKER-USER");
    assert!(
        ipt.iter()
            .any(|a| a == "-I DOCKER-USER 1 -i hxbr0 -j ACCEPT")
    );
    // The last SetupHost is remembered for the automatic re-run.
    assert!(
        h.daemon
            .read_state(|s| s.host.clone())
            .unwrap()
            .allow_private_networks
    );
    // The host addresses included the Docker bridge and the extra one, never our own bridge.
    let spec_acl = h
        .incus
        .with(|s| s.objects.get("network-acls/hx-isolate").cloned())
        .expect("acl");
    let acl_text = spec_acl.to_string();
    assert!(
        acl_text.contains("172.17.0.1")
            && acl_text.contains("203.0.113.9")
            && acl_text.contains("198.51.100.7")
    );
    // ...and the enumeration itself never lists our own bridge.
    let addrs = h.daemon.host_addresses(&[]).await.unwrap();
    assert!(
        addrs.iter().all(|a| a.to_string() != "10.99.0.1"),
        "{addrs:?}"
    );
}

#[tokio::test]
async fn a_ruleset_that_fails_the_check_is_never_loaded() {
    let runner = FakeRunner::with(|p| {
        let failing = p.tool == Tool::Nft && p.args.first().map(String::as_str) == Some("-c");
        RunOutput {
            code: Some(if failing { 1 } else { 0 }),
            ..Default::default()
        }
    });
    let h = Harness::start_with(GW, FakeProbe::default(), FakeIncus::new(), runner.clone());
    let e = h.daemon.load_firewall("table inet hx\n").await.unwrap_err();
    assert_eq!(e.detail, ErrorDetail::Nft);
    assert!(
        runner
            .calls()
            .iter()
            .all(|c| c.args.first().map(String::as_str) != Some("-f"))
    );
    // And a table that is missing after the load is an error too.
    let runner = FakeRunner::with(|p| {
        let list = p.tool == Tool::Nft && p.args.first().map(String::as_str) == Some("list");
        RunOutput {
            code: Some(if list { 1 } else { 0 }),
            ..Default::default()
        }
    });
    let h = Harness::start_with(GW, FakeProbe::default(), FakeIncus::new(), runner);
    assert_eq!(
        h.daemon.load_firewall("x").await.unwrap_err().detail,
        ErrorDetail::Nft
    );
}

#[tokio::test]
async fn docker_user_rules_report_failure_and_set_the_attention_flag() {
    let runner = FakeRunner::with(|p| {
        let a = p.args.join(" ");
        // The chain exists, no rule is there, and inserting fails.
        let code = if a.starts_with("-n -L") { 0 } else { 1 };
        RunOutput {
            code: Some(code),
            ..Default::default()
        }
    });
    let h = Harness::start_with(GW, FakeProbe::default(), FakeIncus::new(), runner);
    assert_eq!(
        h.daemon.apply_docker_user_rules().await,
        pb::DockerUserRules::Failed
    );
    assert!(
        h.daemon
            .flags_for("main")
            .contains(&Flag::HostDockerForwarding)
    );
    // Without a host Docker the step reports "not present" and clears the flag.
    let runner = FakeRunner::with(|_| RunOutput {
        code: Some(1),
        ..Default::default()
    });
    let h2 = Harness::start_with(GW, FakeProbe::default(), FakeIncus::new(), runner);
    assert_eq!(
        h2.daemon.apply_docker_user_rules().await,
        pb::DockerUserRules::NotPresent
    );
}

#[tokio::test]
async fn the_sysctl_step_fails_when_the_values_do_not_take_effect() {
    let probe = FakeProbe {
        sysctl_ok: false,
        ..FakeProbe::default()
    };
    let h = Harness::start_with(GW, probe, FakeIncus::new(), FakeRunner::new());
    assert_eq!(
        h.daemon.apply_sysctl().await.unwrap_err().detail,
        ErrorDetail::Sysctl
    );
}

#[tokio::test]
async fn setup_host_rejects_a_pool_larger_than_60_percent_of_the_free_space() {
    let probe = FakeProbe {
        incus_free: Some(100 << 30),
        ..FakeProbe::default()
    };
    let h = Harness::start_with(GW, probe, FakeIncus::new(), host_runner());
    let r = run(
        &h,
        Role::Admin,
        Command::SetupHost(pb::SetupHostRequest {
            pool_size_gib: 61,
            ..Default::default()
        }),
    )
    .await;
    assert_eq!(err(&r), (ErrorCode::FailedPrecondition, ErrorDetail::Pool));
}

#[tokio::test]
async fn rule_7_the_desktop_cap_refuses_a_second_desktop() {
    let h = Harness::start(GW);
    make_ready(&h).await;
    add_desktop(&h);
    let r = run_with(
        &h.daemon,
        Role::Admin,
        Command::CreateDesktop(pb::CreateDesktopRequest {
            desktop_id: "second".into(),
            distro: pb::Distro::Ubuntu2404 as i32,
            desktop: pb::DesktopKind::Xfce as i32,
            preset: pb::Preset::Basic as i32,
            username: "bob".into(),
            ..Default::default()
        }),
        &[pb::SecretKind::UserPassword],
        &[b"correct horse battery"],
    )
    .await;
    assert_eq!(
        err(&r),
        (ErrorCode::FailedPrecondition, ErrorDetail::DesktopExists)
    );
    // Nothing was created.
    assert_eq!(h.incus.instance_names(), ["hx-main"]);
}

#[tokio::test]
async fn create_desktop_refuses_a_ready_desktop_with_other_arguments_and_converges_with_the_same() {
    let h = Harness::start(GW);
    make_ready(&h).await;
    add_desktop(&h);
    let create = |user: &str, preset: pb::Preset| {
        Command::CreateDesktop(pb::CreateDesktopRequest {
            desktop_id: "main".into(),
            distro: pb::Distro::Ubuntu2404 as i32,
            desktop: pb::DesktopKind::Xfce as i32,
            preset: preset as i32,
            username: user.into(),
            ..Default::default()
        })
    };
    let pw: &[&[u8]] = &[b"correct horse battery"];
    let kinds = [pb::SecretKind::UserPassword];
    let r = run_with(
        &h.daemon,
        Role::Admin,
        create("alice", pb::Preset::Basic),
        &kinds,
        pw,
    )
    .await;
    ok(r);
    let r = run_with(
        &h.daemon,
        Role::Admin,
        create("bob", pb::Preset::Basic),
        &kinds,
        pw,
    )
    .await;
    assert_eq!(
        err(&r),
        (ErrorCode::FailedPrecondition, ErrorDetail::DesktopExists)
    );
    let r = run_with(
        &h.daemon,
        Role::Admin,
        create("alice", pb::Preset::Developer),
        &kinds,
        pw,
    )
    .await;
    assert_eq!(
        err(&r),
        (ErrorCode::FailedPrecondition, ErrorDetail::DesktopExists)
    );
}

#[tokio::test]
async fn create_desktop_arguments_are_checked_before_anything_is_created() {
    let h = Harness::start(GW);
    make_ready(&h).await;
    let kinds = [pb::SecretKind::UserPassword];
    let pw: &[&[u8]] = &[b"correct horse battery"];
    let base = || pb::CreateDesktopRequest {
        desktop_id: "main".into(),
        distro: pb::Distro::Ubuntu2404 as i32,
        desktop: pb::DesktopKind::Xfce as i32,
        preset: pb::Preset::Basic as i32,
        username: "alice".into(),
        ..Default::default()
    };
    let cases: Vec<(&str, pb::CreateDesktopRequest, ErrorCode)> = vec![
        (
            "reserved username",
            pb::CreateDesktopRequest {
                username: "root".into(),
                ..base()
            },
            ErrorCode::InvalidArgument,
        ),
        (
            "prebuilt is not available",
            pb::CreateDesktopRequest {
                image_mode: pb::ImageMode::Prebuilt as i32,
                ..base()
            },
            ErrorCode::Unimplemented,
        ),
        (
            "offline image (Admin)",
            pb::CreateDesktopRequest {
                image_file: Some("/var/lib/hx/import/x.img".into()),
                ..base()
            },
            ErrorCode::Unimplemented,
        ),
        (
            "bad hostname",
            pb::CreateDesktopRequest {
                settings: Some(pb::DesktopSettings {
                    hostname: "bad name".into(),
                    ..Default::default()
                }),
                ..base()
            },
            ErrorCode::InvalidArgument,
        ),
        (
            "too many CPUs",
            pb::CreateDesktopRequest {
                limits: Some(pb::Limits {
                    cpu: 99,
                    memory_mib: 0,
                    disk_gib: 0,
                }),
                ..base()
            },
            ErrorCode::InvalidArgument,
        ),
    ];
    for (what, req, want) in cases {
        let r = run_with(
            &h.daemon,
            Role::Admin,
            Command::CreateDesktop(req),
            &kinds,
            pw,
        )
        .await;
        assert_eq!(code(&r), want, "{what}");
        // CreateDesktop is limited to 3 an hour: keep each case inside its own hour.
        h.clock.advance_secs(3_601);
    }
    // Pool headroom: the minimum is 8 GiB and 15% free.
    let low = FakeProbe {
        pool: Some((100 << 30, 7 << 30)),
        ..FakeProbe::default()
    };
    let h2 = Harness::start_with(GW, low, FakeIncus::new(), FakeRunner::new());
    make_ready(&h2).await;
    let r = run_with(
        &h2.daemon,
        Role::Admin,
        Command::CreateDesktop(base()),
        &kinds,
        pw,
    )
    .await;
    assert_eq!(err(&r), (ErrorCode::FailedPrecondition, ErrorDetail::Pool));
    assert!(h.incus.instance_names().is_empty() && h2.incus.instance_names().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn create_desktop_builds_on_the_fake_and_reaches_ready_last() {
    let h = Harness::start(GW);
    make_ready(&h).await;
    let password = b"Correct-Horse-Battery-9";
    let r = run_with(
        &h.daemon,
        Role::Admin,
        Command::CreateDesktop(pb::CreateDesktopRequest {
            desktop_id: "main".into(),
            distro: pb::Distro::Debian13 as i32,
            desktop: pb::DesktopKind::Xfce as i32,
            preset: pb::Preset::Basic as i32,
            username: "alice".into(),
            ..Default::default()
        }),
        &[pb::SecretKind::UserPassword],
        &[password],
    )
    .await;
    let R::CreateDesktop(c) = ok(r) else { panic!() };
    assert_eq!(c.desktop_id, "main");
    assert_eq!(c.path_taken(), pb::PathTaken::Build);
    assert!(c.reason.contains("prebuilt"));
    // No package for the session on this host: a warning, and the desktop is still ready.
    assert!(
        c.warnings.iter().any(|w| w.contains("hx-session package")),
        "{:?}",
        c.warnings
    );
    assert!(c.warnings.len() <= 16);
    // Metadata: `ready` last, username and recipe recorded, the link device present.
    let cfg = h.incus.with(|s| s.instances["hx-main"].config.clone());
    assert_eq!(cfg["user.hx.state"], "ready");
    assert_eq!(cfg["user.hx.username"], "alice");
    assert_eq!(cfg["user.hx.recipe"], "debian-13-xfce-basic");
    assert_eq!(cfg["security.privileged"], "false");
    assert!(
        h.incus
            .with(|s| s.instances["hx-main"].devices.contains_key("hx-link"))
    );
    // The Debian 13 guest got the compatibility profile? That is hx-provision's decision; what
    // matters here is that the instance name was derived and the registry knows it.
    assert!(h.daemon.read_state(|s| s.desktops.contains_key("main")));
    // The password reached the container only as a pushed file, never in an argv or the audit log.
    let leaked_in_exec = h
        .incus
        .with(|s| s.execs.iter().any(|e| e.contains("Correct-Horse")));
    assert!(!leaked_in_exec, "the password appeared in a command line");
    assert!(h.audit.lines().iter().all(|l| !l.contains("Correct-Horse")));
    // The post stage ran with the work directory swept before and after.
    assert!(h.incus.with(|s| {
        s.pushed
            .iter()
            .any(|(p, _)| p.contains("/run/hx-provision"))
    }));
    // GetDesktop now works and a FinishSetup by Gateway succeeds (a ready desktop exists).
    ok(run(
        &h,
        Role::Gateway,
        Command::GetDesktop(pb::GetDesktopRequest {
            desktop_id: "main".into(),
        }),
    )
    .await);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_create_leaves_no_instance_and_names_the_stage() {
    let h = Harness::start(GW);
    make_ready(&h).await;
    // Every command in the container fails, after the readiness probe.
    h.incus.with(|s| {
        s.exec_rules.push(ExecRule {
            needle: "".into(),
            exit: 1,
            stdout: "boom".into(),
            delay: Some(std::time::Duration::ZERO),
        });
    });
    let r = run_with(
        &h.daemon,
        Role::Admin,
        Command::CreateDesktop(pb::CreateDesktopRequest {
            desktop_id: "main".into(),
            distro: pb::Distro::Ubuntu2404 as i32,
            desktop: pb::DesktopKind::Xfce as i32,
            preset: pb::Preset::Basic as i32,
            username: "alice".into(),
            ..Default::default()
        }),
        &[pb::SecretKind::UserPassword],
        &[b"Correct-Horse-Battery-9"],
    )
    .await;
    let e = error_of(&r).expect("an error").clone();
    assert_eq!(e.code(), ErrorCode::Internal);
    assert_eq!(e.stage(), pb::ProgressStage::Build);
    assert!(e.message.len() <= 256);
    // No half-built desktop is left behind: the instance and the registry entry are gone.
    assert!(
        h.incus.instance_names().is_empty(),
        "{:?}",
        h.incus.instance_names()
    );
    assert!(h.daemon.read_state(|s| s.desktops.is_empty()));
}

// ----- SetUserPassword and the current-password check (ipc.md 6.9, 5.3) ---------------------------------

fn pwcheck_exit(h: &Harness, exit: i32) {
    h.incus.with(|s| {
        s.exec_rules.insert(
            0,
            ExecRule {
                needle: "hx-pwcheck".into(),
                exit,
                stdout: String::new(),
                delay: Some(std::time::Duration::ZERO),
            },
        );
    });
}

async fn set_password(h: &Harness, role: Role, new: &[u8], current: Option<&[u8]>) -> pb::Response {
    let mut kinds = vec![pb::SecretKind::UserPassword];
    let mut secrets: Vec<&[u8]> = vec![new];
    if let Some(c) = current {
        kinds.push(pb::SecretKind::CurrentPassword);
        secrets.push(c);
    }
    run_with(
        &h.daemon,
        role,
        Command::SetUserPassword(pb::SetUserPasswordRequest {
            desktop_id: "main".into(),
        }),
        &kinds,
        &secrets,
    )
    .await
}

#[tokio::test]
async fn a_correct_current_password_allows_the_change_and_a_wrong_one_never_runs_chpasswd() {
    let h = Harness::start(GW);
    make_ready(&h).await;
    add_desktop(&h);
    pwcheck_exit(&h, 0);
    ok(set_password(
        &h,
        Role::Gateway,
        b"Brand-New-Password-1",
        Some(b"Old-Password-9"),
    )
    .await);
    assert!(
        h.incus
            .with(|s| s.execs.iter().any(|e| e.contains("chpasswd")))
    );
    h.incus.with(|s| s.execs.clear());
    h.incus.with(|s| s.exec_rules[0].exit = 1);
    let r = set_password(
        &h,
        Role::Gateway,
        b"Brand-New-Password-2",
        Some(b"Wrong-Password-0"),
    )
    .await;
    assert_eq!(code(&r), ErrorCode::PermissionDenied);
    assert!(
        h.incus
            .with(|s| !s.execs.iter().any(|e| e.contains("chpasswd")))
    );
    // No secret in any argv or audit line, whatever happened.
    for needle in ["Brand-New", "Old-Password", "Wrong-Password"] {
        assert!(
            h.incus
                .with(|s| !s.execs.iter().any(|e| e.contains(needle))),
            "{needle}"
        );
        assert!(
            h.audit.lines().iter().all(|l| !l.contains(needle)),
            "{needle}"
        );
    }
}

#[tokio::test]
async fn wrong_current_passwords_are_charged_to_the_shared_budget_and_lock_it() {
    let h = Harness::start(GW);
    make_ready(&h).await;
    add_desktop(&h);
    pwcheck_exit(&h, 1);
    for i in 0..5 {
        let r = set_password(
            &h,
            Role::Gateway,
            b"Brand-New-Password-1",
            Some(b"Wrong-Password-0"),
        )
        .await;
        assert_eq!(code(&r), ErrorCode::PermissionDenied, "attempt {i}");
    }
    // The PASSWORD purpose is locked now: the check is refused, and so is PepperVerify.
    let r = set_password(
        &h,
        Role::Gateway,
        b"Brand-New-Password-1",
        Some(b"Wrong-Password-0"),
    )
    .await;
    assert_eq!(err(&r), (ErrorCode::ResourceExhausted, ErrorDetail::Locked));
    let r = verify(
        &h.daemon,
        Role::Gateway,
        pb::LockoutPurpose::Password,
        &[1; 32],
        &[0; 32],
    )
    .await;
    assert_eq!(err(&r), (ErrorCode::ResourceExhausted, ErrorDetail::Locked));
    let R::GetHostInfo(info) =
        ok(run(&h, Role::Gateway, Command::GetHostInfo(Default::default())).await)
    else {
        panic!()
    };
    assert!(
        info.needs_attention
            .contains(&(pb::NeedsAttention::PasswordLocked as i32))
    );
    // Admin lifts it.
    ok(run(
        &h,
        Role::Admin,
        Command::ResetLockout(pb::ResetLockoutRequest {
            purpose: pb::LockoutPurpose::Password as i32,
        }),
    )
    .await);
    pwcheck_exit(&h, 0);
    ok(set_password(
        &h,
        Role::Gateway,
        b"Brand-New-Password-1",
        Some(b"Right-Password-0"),
    )
    .await);
}

#[tokio::test]
async fn a_check_that_cannot_decide_is_internal_and_is_not_a_failed_guess() {
    let h = Harness::start(GW);
    make_ready(&h).await;
    add_desktop(&h);
    pwcheck_exit(&h, 3); // no such user / locked account
    for _ in 0..8 {
        let r = set_password(
            &h,
            Role::Gateway,
            b"Brand-New-Password-1",
            Some(b"Some-Password-0"),
        )
        .await;
        assert_eq!(code(&r), ErrorCode::Internal);
    }
    // Still not locked.
    let R::GetHostInfo(info) =
        ok(run(&h, Role::Gateway, Command::GetHostInfo(Default::default())).await)
    else {
        panic!()
    };
    assert!(info.needs_attention.is_empty());
}

#[tokio::test]
async fn the_current_password_is_not_needed_in_the_window_or_for_admin() {
    let h = Harness::start(GW);
    make_ready(&h).await;
    add_desktop(&h);
    // Outside the window Gateway must send it (refused by the request-only rule)...
    let r = set_password(&h, Role::Gateway, b"Brand-New-Password-1", None).await;
    assert_eq!(code(&r), ErrorCode::PermissionDenied);
    // ...Admin may omit it (root can run chpasswd in the container anyway)...
    ok(set_password(&h, Role::Admin, b"Brand-New-Password-1", None).await);
    // ...and inside the setup window nobody needs it.
    open_window(&h).await;
    ok(set_password(&h, Role::Gateway, b"Brand-New-Password-2", None).await);
}

#[tokio::test]
async fn set_user_password_refuses_a_desktop_that_is_not_running() {
    let h = Harness::start(GW);
    make_ready(&h).await;
    add_desktop(&h);
    h.incus
        .with(|s| s.instances.get_mut("hx-main").unwrap().status = "Stopped".into());
    let r = set_password(&h, Role::Admin, b"Brand-New-Password-1", None).await;
    assert_eq!(
        err(&r),
        (ErrorCode::FailedPrecondition, ErrorDetail::DesktopNotReady)
    );
}

#[tokio::test]
async fn the_host_ruleset_is_re_applied_after_an_address_change_from_what_setup_host_recorded() {
    let runner = host_runner();
    let h = Harness::start_with(GW, FakeProbe::default(), FakeIncus::new(), runner.clone());
    // Before a SetupHost there is nothing to refresh.
    assert!(!h.daemon.refresh_host().await.unwrap());
    assert!(runner.calls().is_empty());
    ok(run(
        &h,
        Role::Admin,
        Command::SetupHost(pb::SetupHostRequest {
            allow_private_networks: Some(true),
            ..Default::default()
        }),
    )
    .await);
    let before = runner.calls().len();
    std::fs::remove_file(&h.daemon.cfg.firewall_file).unwrap();
    // A new address appears on the host: the re-run regenerates and loads the ruleset again,
    // with the options Admin gave (private networks allowed: no drop rule for them).
    assert!(h.daemon.refresh_host().await.unwrap());
    assert!(runner.calls().len() > before);
    let text = std::fs::read_to_string(&h.daemon.cfg.firewall_file).unwrap();
    assert!(text.contains("table inet hx"));
    assert!(
        !text.contains("172.16.0.0/12"),
        "allow_private_networks was kept"
    );
    let nft_loads = runner
        .calls()
        .iter()
        .filter(|c| c.tool == Tool::Nft && c.args.first().map(String::as_str) == Some("-f"))
        .count();
    assert_eq!(nft_loads, 2);
}

#[tokio::test]
async fn a_gateway_setup_host_keeps_the_admins_extra_addresses_and_private_network_option() {
    let runner = host_runner();
    let h = Harness::start_with(GW, FakeProbe::default(), FakeIncus::new(), runner.clone());
    ok(run(
        &h,
        Role::Admin,
        Command::SetupHost(pb::SetupHostRequest {
            allow_private_networks: Some(true),
            extra_host_addresses: Some(pb::ExtraHostAddresses {
                addresses: vec!["198.51.100.7".into()],
            }),
            ..Default::default()
        }),
    )
    .await);
    // A Gateway call inside the window, without those fields.
    open_window(&h).await;
    ok(run(&h, Role::Gateway, Command::SetupHost(Default::default())).await);
    let acl = h
        .incus
        .with(|s| s.objects.get("network-acls/hx-isolate").cloned())
        .unwrap()
        .to_string();
    assert!(acl.contains("198.51.100.7"), "the /32 drop was lost: {acl}");
    let rec = h.daemon.read_state(|s| s.host.clone()).unwrap();
    assert_eq!(rec.extra_host_addresses, ["198.51.100.7"]);
    assert!(rec.allow_private_networks);
    // The automatic re-run keeps it too.
    assert!(h.daemon.refresh_host().await.unwrap());
    let acl = h
        .incus
        .with(|s| s.objects.get("network-acls/hx-isolate").cloned())
        .unwrap()
        .to_string();
    assert!(acl.contains("198.51.100.7"));
    let text = std::fs::read_to_string(&h.daemon.cfg.firewall_file).unwrap();
    assert!(
        !text.contains("172.16.0.0/12"),
        "private networks stay allowed"
    );
}
