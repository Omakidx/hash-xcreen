//! `CheckUpdate`, `ApplyUpdate` and `RollbackUpdate` end to end on fakes (docs/ipc.md 6.12 and 7
//! rule 10): signatures and keys, freshness, forward-only, the preupdate snapshot, the switch, the
//! health check and the automatic rollback, roles and rate limits. The fetcher unit, systemd and
//! the health probes are the fakes of `privd_update_common`; no real unit is restarted.

mod privd_update_common;

use std::sync::atomic::Ordering;

use hx_agent::privd::cancel::CancelToken;
use hx_agent::privd::daemon::Ctx;
use hx_agent::privd::progress::ProgressSender;
use hx_agent::privd::state::Flag;
use hx_agent::privd::testing::request;
use hx_agent::privd::update::Unit;
use hx_agent::privd::update::state::UpdateState;
use hx_ipc::privd::pb::{
    self, ErrorCode, ProgressStage, Role, request::Command, response::Result as R,
};
use privd_update_common::*;

const T0: u64 = NOW - 100_000;

fn store(dir: &std::path::Path) -> hx_agent::privd::state::StateStore {
    hx_agent::privd::state::StateStore::open(dir).unwrap()
}

fn state(env: &Env) -> UpdateState {
    UpdateState::load(&store(&env.h.daemon.cfg.state_dir)).unwrap()
}

fn ctx_admin() -> Ctx {
    Ctx::new(Role::Admin)
}

// ----- CheckUpdate --------------------------------------------------------------------------

#[tokio::test]
async fn check_reports_the_verified_release_and_stages_it() {
    let env = Env::new();
    env.publish("1.1.0", T0);
    let c = check_result(env.check().await);
    assert_eq!(c.current, "1.0.0");
    assert_eq!(c.available.as_deref(), Some("1.1.0"));
    assert!(c.verified);
    assert_eq!(c.channel(), pb::UpdateChannel::Stable);
    assert!(c.rolled_back.is_none());
    let u = &env.h.daemon.cfg.update;
    assert!(u.staging_dir.join("manifest.json").is_file());
    assert!(u.staging_dir.join("manifest.json.minisig").is_file());
    let st = state(&env);
    assert_eq!(st.highest("stable"), T0);
    assert_eq!(st.verified_version.as_deref(), Some("1.1.0"));
    // The fetch directory was swept before the fetch and the fetcher was asked for the manifest.
    assert_eq!(env.server.lock().unwrap().jobs, ["manifest-stable"]);
}

#[tokio::test]
async fn a_release_that_is_not_newer_is_not_available() {
    let env = Env::new();
    env.publish("1.0.0", T0);
    let c = check_result(env.check().await);
    assert_eq!(c.available, None);
    assert!(c.verified);
    env.publish("0.9.0", T0 + 1);
    assert_eq!(check_result(env.check().await).available, None);
}

#[tokio::test]
async fn a_build_without_keys_refuses_every_update() {
    let env = Env::new();
    env.publish("1.1.0", T0);
    env.h.daemon.set_update_deps(env.deps(&[]));
    let (code, msg) = err(&env.check().await);
    assert_eq!(code, ErrorCode::FailedPrecondition);
    assert!(msg.contains("no release signing key"), "{msg}");
    assert_eq!(
        err(&env.apply("1.1.0").await).0,
        ErrorCode::FailedPrecondition
    );
    assert!(
        env.server.lock().unwrap().jobs.is_empty(),
        "nothing was fetched"
    );
}

#[tokio::test]
async fn an_unsigned_or_mis_signed_manifest_is_refused() {
    let env = Env::new();
    let good = env.publish("1.1.0", T0);

    // Signed by a key that is not embedded.
    let other = Signer::new();
    let p = env.sign_release("1.1.0", T0, good.artifact.clone(), None, &other);
    env.serve(&p);
    let (code, msg) = err(&env.check().await);
    assert_eq!(code, ErrorCode::FailedPrecondition);
    assert!(msg.contains("no embedded release key"), "{msg}");

    // Valid signature, manifest altered afterwards.
    let mut tampered = good.manifest.clone();
    let i = tampered.windows(5).position(|w| w == b"1.1.0").unwrap();
    tampered[i + 4] = b'9';
    env.server.lock().unwrap().manifest = Some((tampered, good.sig.clone()));
    assert_eq!(err(&env.check().await).0, ErrorCode::FailedPrecondition);

    // Not a signature file at all, and an empty one.
    for junk in [
        "",
        "not a signature",
        "untrusted comment: x\nAAAA\ntrusted comment: y\nBBBB\n",
    ] {
        env.server.lock().unwrap().manifest = Some((good.manifest.clone(), junk.into()));
        assert_eq!(
            err(&env.check().await).0,
            ErrorCode::FailedPrecondition,
            "{junk:?}"
        );
    }
    assert_eq!(state(&env).highest("stable"), 0, "nothing was accepted");
    assert!(
        !env.h
            .daemon
            .cfg
            .update
            .staging_dir
            .join("manifest.json")
            .exists()
    );

    // The honest release still works.
    env.serve(&good);
    assert_eq!(
        check_result(env.check().await).available.as_deref(),
        Some("1.1.0")
    );
}

#[tokio::test]
async fn the_next_key_is_accepted_and_a_rotation_needs_no_flag_day() {
    let env = Env::new();
    let next = Signer::new();
    // The build embeds current and next.
    env.h
        .daemon
        .set_update_deps(env.deps(&[&env.signer.public(), &next.public()]));
    let p = env.sign_release("1.1.0", T0, archive(&good_files("1.1.0")), None, &next);
    env.serve(&p);
    assert_eq!(
        check_result(env.check().await).available.as_deref(),
        Some("1.1.0")
    );
    // After the rotation the old key is gone: a release it signs is refused.
    env.h.daemon.set_update_deps(env.deps(&[&next.public()]));
    let p = env.sign_release(
        "1.2.0",
        T0 + 1,
        archive(&good_files("1.2.0")),
        None,
        &env.signer,
    );
    env.serve(&p);
    assert_eq!(err(&env.check().await).0, ErrorCode::FailedPrecondition);
}

#[tokio::test]
async fn a_manifest_with_bad_fields_is_refused_even_when_signed() {
    let env = Env::new();
    let art = archive(&good_files("1.1.0"));
    // Wrong channel.
    let mut m: hx_agent::privd::update::manifest::Manifest = serde_json::from_slice(
        &env.sign_release("1.1.0", T0, art.clone(), None, &env.signer)
            .manifest,
    )
    .unwrap();
    m.channel = "beta".into();
    let bytes = serde_json::to_vec(&m).unwrap();
    let sig = env.signer.sign(&bytes);
    env.server.lock().unwrap().manifest = Some((bytes, sig));
    assert_eq!(err(&env.check().await).0, ErrorCode::FailedPrecondition);
    // A version that is not a version, and an artifact name that is a path.
    for edit in [
        |m: &mut hx_agent::privd::update::manifest::Manifest| m.version = "1.1".into(),
        |m: &mut hx_agent::privd::update::manifest::Manifest| m.version = "../../etc".into(),
        |m: &mut hx_agent::privd::update::manifest::Manifest| m.artifact = "../x.tar.gz".into(),
        |m: &mut hx_agent::privd::update::manifest::Manifest| m.timestamp = 0,
        |m: &mut hx_agent::privd::update::manifest::Manifest| m.size = u64::MAX,
    ] {
        let mut m: hx_agent::privd::update::manifest::Manifest = serde_json::from_slice(
            &env.sign_release("1.1.0", T0, art.clone(), None, &env.signer)
                .manifest,
        )
        .unwrap();
        edit(&mut m);
        let bytes = serde_json::to_vec(&m).unwrap();
        let sig = env.signer.sign(&bytes);
        env.server.lock().unwrap().manifest = Some((bytes, sig));
        assert_eq!(err(&env.check().await).0, ErrorCode::FailedPrecondition);
    }
}

#[tokio::test]
async fn a_replayed_older_manifest_is_refused_and_the_counter_never_goes_back() {
    let env = Env::new();
    let old = env.publish("1.1.0", T0);
    assert_eq!(
        check_result(env.check().await).available.as_deref(),
        Some("1.1.0")
    );
    env.publish("1.2.0", T0 + 500);
    assert_eq!(
        check_result(env.check().await).available.as_deref(),
        Some("1.2.0")
    );
    assert_eq!(state(&env).highest("stable"), T0 + 500);
    // The old, validly signed release is served again (a replay of a vulnerable release).
    env.serve(&old);
    let (code, msg) = err(&env.check().await);
    assert_eq!(code, ErrorCode::FailedPrecondition);
    assert!(msg.contains("replay") || msg.contains("older"), "{msg}");
    assert_eq!(state(&env).highest("stable"), T0 + 500);
    // The same manifest again (equal timestamp) is fine.
    env.publish("1.2.0", T0 + 500);
    assert!(check_result(env.check().await).available.is_some());
    // The counter survives a restart of privd.
    let again = env.new_process("1.0.0");
    assert_eq!(
        UpdateState::load(&store(&again.cfg.state_dir))
            .unwrap()
            .highest("stable"),
        T0 + 500
    );
}

#[tokio::test]
async fn a_manifest_dated_far_in_the_future_cannot_pin_the_counter() {
    let env = Env::new();
    env.publish("1.1.0", NOW + 10 * 86_400);
    assert_eq!(err(&env.check().await).0, ErrorCode::FailedPrecondition);
    assert_eq!(state(&env).highest("stable"), 0);
}

#[tokio::test]
async fn a_failing_fetcher_is_unavailable_and_retryable() {
    let env = Env::new();
    env.server.lock().unwrap().fail = true;
    let r = env.check().await;
    let e = match &r.result {
        Some(R::Error(e)) => e,
        other => panic!("{other:?}"),
    };
    assert_eq!(e.code(), ErrorCode::Unavailable);
    assert!(e.retryable);
}

// ----- hostile fetch directory -----------------------------------------------------------------

#[tokio::test]
async fn hostile_fetch_directories_are_refused_without_following_anything() {
    use std::os::unix::fs::symlink;
    let env = Env::new();
    let p = env.publish("1.1.0", T0);
    let secret = env.h.dir.path().join("secret");
    std::fs::write(&secret, b"root only").unwrap();

    // A symlink in place of the manifest.
    {
        let secret = secret.clone();
        env.server.lock().unwrap().hook = Some(Box::new(move |_, dir| {
            symlink(&secret, dir.join("manifest.json")).unwrap();
            std::fs::write(dir.join("manifest.json.minisig"), "x").unwrap();
            Some(Ok(()))
        }));
    }
    let (code, msg) = err(&env.check().await);
    assert_eq!(code, ErrorCode::FailedPrecondition);
    assert!(msg.contains("not a regular file"), "{msg}");

    // A hard link to something privd owns.
    {
        let secret = secret.clone();
        env.server.lock().unwrap().hook = Some(Box::new(move |_, dir| {
            std::fs::hard_link(&secret, dir.join("manifest.json")).unwrap();
            std::fs::write(dir.join("manifest.json.minisig"), "x").unwrap();
            Some(Ok(()))
        }));
    }
    let (code, msg) = err(&env.check().await);
    assert_eq!(code, ErrorCode::FailedPrecondition);
    assert!(msg.contains("more than one link"), "{msg}");
    assert_eq!(std::fs::read(&secret).unwrap(), b"root only");

    // A fifo.
    env.server.lock().unwrap().hook = Some(Box::new(|_, dir| {
        rustix::fs::mknodat(
            rustix::fs::CWD,
            dir.join("manifest.json"),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        Some(Ok(()))
    }));
    assert_eq!(err(&env.check().await).0, ErrorCode::FailedPrecondition);

    // Over quota: a manifest larger than 1 MiB.
    env.server.lock().unwrap().hook = Some(Box::new(|_, dir| {
        std::fs::write(dir.join("manifest.json"), vec![b' '; 1024 * 1024 + 1]).unwrap();
        std::fs::write(dir.join("manifest.json.minisig"), "x").unwrap();
        Some(Ok(()))
    }));
    let (code, msg) = err(&env.check().await);
    assert_eq!(code, ErrorCode::FailedPrecondition);
    assert!(msg.contains("quota"), "{msg}");

    // Nothing was accepted, and an honest fetch afterwards works (the directory was swept).
    assert_eq!(state(&env).highest("stable"), 0);
    env.server.lock().unwrap().hook = None;
    env.serve(&p);
    assert_eq!(
        check_result(env.check().await).available.as_deref(),
        Some("1.1.0")
    );
}

#[tokio::test]
async fn the_fetch_directory_is_cleared_before_every_fetch() {
    let env = Env::new();
    env.publish("1.1.0", T0);
    check_result(env.check().await);
    // Leftovers: a stale artifact, a planted symlink and a sub-directory.
    let dir = env.h.daemon.cfg.update.fetch_dir.clone();
    std::fs::write(dir.join("artifact.tar.gz"), b"stale").unwrap();
    std::os::unix::fs::symlink("/etc/passwd", dir.join("evil")).unwrap();
    std::fs::create_dir(dir.join("sub")).unwrap();
    // The fake writes with create_new: it would panic on a leftover manifest.json.
    assert!(check_result(env.check().await).available.is_some());
    assert!(!dir.join("evil").exists() && !dir.join("sub").exists());
}

// ----- ApplyUpdate ---------------------------------------------------------------------------------

#[tokio::test]
async fn apply_refuses_what_check_did_not_verify() {
    let env = Env::new();
    // Nothing staged.
    let (code, msg) = err(&env.apply("1.1.0").await);
    assert_eq!(code, ErrorCode::FailedPrecondition);
    assert!(msg.contains("CheckUpdate"), "{msg}");
    // A different version than the verified one.
    env.publish("1.1.0", T0);
    check_result(env.check().await);
    let (code, msg) = err(&env.apply("1.2.0").await);
    assert_eq!(code, ErrorCode::FailedPrecondition);
    assert!(msg.contains("verified"), "{msg}");
    assert_eq!(
        env.server.lock().unwrap().jobs,
        ["manifest-stable"],
        "no artifact was fetched"
    );
}

#[tokio::test]
async fn downgrade_and_reinstall_by_request_are_refused() {
    let env = Env::new();
    env.publish("1.1.0", T0);
    check_result(env.check().await);
    for v in ["1.0.0", "0.9.0", "0.1.0-rc.1", "1.0.0-rc.1"] {
        let (code, msg) = err(&env.apply_fresh(v).await);
        assert_eq!(code, ErrorCode::FailedPrecondition, "{v}");
        assert!(msg.contains("not newer"), "{v}: {msg}");
    }
    // Even a signed, fresh manifest for an older version cannot be applied.
    env.publish("0.9.0", T0 + 5);
    check_result(env.check().await);
    assert_eq!(
        err(&env.apply_fresh("0.9.0").await).0,
        ErrorCode::FailedPrecondition
    );
    assert_eq!(env.layout().current().unwrap().as_deref(), Some("1.0.0"));
}

#[tokio::test]
async fn min_previous_is_enforced() {
    let env = Env::new();
    env.publish_with("2.0.0", T0, &good_files("2.0.0"), Some("1.5.0"));
    check_result(env.check().await);
    let (code, msg) = err(&env.apply("2.0.0").await);
    assert_eq!(code, ErrorCode::FailedPrecondition);
    assert!(msg.contains("too old"), "{msg}");
}

#[tokio::test]
async fn an_artifact_that_does_not_match_the_signed_manifest_is_refused() {
    let env = Env::new();
    let p = env.publish("1.1.0", T0);
    check_result(env.check().await);

    // SHA-256 mismatch, same length (one byte flipped after signing).
    let mut bad = p.artifact.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    env.server
        .lock()
        .unwrap()
        .artifacts
        .insert("1.1.0".into(), bad);
    let (code, msg) = err(&env.apply_fresh("1.1.0").await);
    assert_eq!(code, ErrorCode::FailedPrecondition);
    assert!(msg.contains("SHA-256"), "{msg}");

    // Longer and shorter than announced.
    let mut longer = p.artifact.clone();
    longer.push(0);
    env.server
        .lock()
        .unwrap()
        .artifacts
        .insert("1.1.0".into(), longer);
    assert_eq!(
        err(&env.apply_fresh("1.1.0").await).0,
        ErrorCode::FailedPrecondition
    );
    let shorter = p.artifact[..p.artifact.len() - 1].to_vec();
    env.server
        .lock()
        .unwrap()
        .artifacts
        .insert("1.1.0".into(), shorter);
    assert_eq!(
        err(&env.apply_fresh("1.1.0").await).0,
        ErrorCode::FailedPrecondition
    );

    // A symlink in place of the artifact.
    env.server.lock().unwrap().hook = Some(Box::new(|j, dir| {
        matches!(j, hx_agent::fetcher::Job::Artifact(_)).then(|| {
            std::os::unix::fs::symlink("/etc/passwd", dir.join("artifact.tar.gz")).unwrap();
            Ok(())
        })
    }));
    assert_eq!(
        err(&env.apply_fresh("1.1.0").await).0,
        ErrorCode::FailedPrecondition
    );

    // Nothing was installed or switched, and no pending record exists.
    assert_eq!(env.layout().current().unwrap().as_deref(), Some("1.0.0"));
    assert!(!env.h.daemon.cfg.update.versions_dir.join("1.1.0").exists());
    assert!(state(&env).pending.is_none());
    assert!(env.systemd.restarted().is_empty());
}

#[tokio::test]
async fn a_verified_artifact_with_a_hostile_member_is_not_installed() {
    let env = Env::new();
    let mut files = good_files("1.1.0");
    files.push(TarEntry::file("../escape", b"x", 0o644));
    env.publish_with("1.1.0", T0, &files, None);
    check_result(env.check().await);
    let (code, msg) = err(&env.apply("1.1.0").await);
    assert_eq!(code, ErrorCode::FailedPrecondition);
    assert!(msg.contains("refused"), "{msg}");
    let u = &env.h.daemon.cfg.update;
    // No half-extracted tree is left behind, and nothing escaped.
    let left: Vec<_> = std::fs::read_dir(&u.versions_dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        !left
            .iter()
            .any(|n| n.starts_with(".incoming") || n == "1.1.0"),
        "{left:?}"
    );
    assert!(!u.versions_dir.parent().unwrap().join("escape").exists());

    // An incomplete release (no gatewayd) is refused after unpacking, before the switch.
    let files: Vec<_> = good_files("1.2.0")
        .into_iter()
        .filter(|e| e.path != b"hx-gatewayd")
        .collect();
    env.publish_with("1.2.0", T0 + 1, &files, None);
    check_result(env.check().await);
    assert_eq!(
        err(&env.apply("1.2.0").await).0,
        ErrorCode::FailedPrecondition
    );
    assert_eq!(env.layout().current().unwrap().as_deref(), Some("1.0.0"));
}

#[tokio::test]
async fn apply_installs_switches_snapshots_and_restarts() {
    let env = Env::new();
    // A ready desktop, registered with privd.
    env.h
        .incus
        .add_desktop("hx-main", "ubuntu-24.04-xfce-basic", "alice", true);
    env.h.daemon.register_desktop("main").unwrap();
    env.publish("1.1.0", T0);
    check_result(env.check().await);

    let (progress, queue) = ProgressSender::new(7);
    let mut ctx = ctx_admin();
    ctx.progress = progress;
    let r = env
        .h
        .daemon
        .handle(
            request(
                7,
                Command::ApplyUpdate(pb::ApplyUpdateRequest {
                    version: "1.1.0".into(),
                }),
            ),
            ctx,
        )
        .await;
    match ok(r) {
        R::ApplyUpdate(a) => assert!(a.restarting),
        other => panic!("{other:?}"),
    }

    // Progress is reported under the UPDATE stage.
    let mut stages = Vec::new();
    while let Some(p) = queue.pop() {
        stages.push(p.stage());
    }
    assert!(
        !stages.is_empty() && stages.iter().all(|s| *s == ProgressStage::Update),
        "{stages:?}"
    );

    // The release is unpacked, owned and moded sanely, and current/previous moved.
    let lay = env.layout();
    assert_eq!(lay.current().unwrap().as_deref(), Some("1.1.0"));
    assert_eq!(lay.previous().unwrap().as_deref(), Some("1.0.0"));
    let u = &env.h.daemon.cfg.update;
    let v = u.versions_dir.join("1.1.0");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(v.join("hx-privd"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o755
    );
    assert_eq!(
        std::fs::metadata(v.join("VERSION"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o644
    );
    assert_eq!(
        std::fs::metadata(v.join("session"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o755
    );
    assert!(v.join("session/ubuntu-24.04/hx-session.deb").is_file());

    // The pending record is on disk for the next process.
    let st = state(&env);
    let p = st.pending.expect("pending");
    assert_eq!(
        (p.version.as_str(), p.previous.as_deref()),
        ("1.1.0", Some("1.0.0"))
    );

    // A preupdate snapshot of the desktop exists, with a name privd may delete.
    let snaps: Vec<String> = env
        .h
        .incus
        .with(|s| s.instances["hx-main"].snapshots.to_vec());
    assert_eq!(snaps.len(), 1, "{snaps:?}");
    assert!(hx_ipc::privd::is_valid_snapshot_name(&snaps[0]));
    assert_eq!(
        hx_ipc::privd::snapshot_kind_of(&snaps[0]),
        Some("preupdate")
    );

    // After the answer: gatewayd is restarted first, then privd re-execs.
    env.wait_restarts(2).await;
    assert_eq!(env.systemd.restarted(), [Unit::Gatewayd, Unit::Privd]);
    let jobs = env.server.lock().unwrap().jobs.clone();
    assert_eq!(jobs, ["manifest-stable", "artifact-1.1.0"]);
    assert!(
        env.h
            .audit
            .lines()
            .iter()
            .any(|l| l.contains("update 1.1.0 switched in")),
        "audited"
    );

    // While the update is pending, no other update command runs.
    assert_eq!(err(&env.check().await).0, ErrorCode::FailedPrecondition);
    assert_eq!(
        err(&env.apply("1.1.0").await).0,
        ErrorCode::FailedPrecondition
    );
    let _ = CancelToken::new();
}

#[tokio::test]
async fn only_two_preupdate_snapshots_are_kept() {
    let env = Env::new();
    env.h
        .incus
        .add_desktop("hx-main", "ubuntu-24.04-xfce-basic", "alice", true);
    env.h.daemon.register_desktop("main").unwrap();
    for (i, v) in ["1.1.0", "1.2.0", "1.3.0"].into_iter().enumerate() {
        env.publish(v, T0 + i as u64);
        check_result(env.check().await);
        ok(env.apply(v).await);
        // The new process confirms the update; the next one is applied from there.
        env.new_process(v).resume_update().await;
        // ApplyUpdate is limited to two a day.
        env.h.clock.advance_secs(86_401);
    }
    let n = env.h.incus.with(|s| {
        s.instances["hx-main"]
            .snapshots
            .iter()
            .filter(|x| x.starts_with("hx-preupdate-"))
            .count()
    });
    assert_eq!(n, 2);
}

// ----- the health check and the automatic rollback ------------------------------------------------

async fn applied_env() -> Env {
    let env = Env::new();
    env.publish("1.1.0", T0);
    check_result(env.check().await);
    ok(env.apply("1.1.0").await);
    env.wait_restarts(2).await;
    env
}

#[tokio::test]
async fn a_healthy_update_is_confirmed_and_old_versions_are_pruned() {
    let env = applied_env().await;
    install_release(&env.h.daemon.cfg.update.versions_dir, "0.8.0");
    std::fs::create_dir(
        env.h
            .daemon
            .cfg
            .update
            .versions_dir
            .join(".incoming-1.9.0-aa"),
    )
    .unwrap();
    let d = env.new_process("1.1.0");
    d.resume_update().await;
    let st = UpdateState::load(&store(&d.cfg.state_dir)).unwrap();
    assert!(st.pending.is_none() && st.rolled_back.is_none());
    assert!(
        env.health.status_calls.load(Ordering::SeqCst) >= 1,
        "Status was asked"
    );
    assert_eq!(env.layout().current().unwrap().as_deref(), Some("1.1.0"));
    assert!(!d.flags_for("main").contains(&Flag::UpdateRolledBack));
    // Two versions are kept: current and previous. The rest is gone.
    let vd = &env.h.daemon.cfg.update.versions_dir;
    assert!(vd.join("1.1.0").is_dir() && vd.join("1.0.0").is_dir());
    assert!(!vd.join("0.8.0").exists() && !vd.join(".incoming-1.9.0-aa").exists());
    assert!(
        env.h
            .audit
            .lines()
            .iter()
            .any(|l| l.contains("update 1.1.0 is healthy"))
    );
    // Nothing happens at the next start.
    d.resume_update().await;
}

async fn assert_rolled_back(
    env: &Env,
    d: &std::sync::Arc<hx_agent::privd::daemon::Daemon<hx_agent::privd::testing::FakeIncus>>,
    why: &str,
) {
    assert_eq!(
        env.layout().current().unwrap().as_deref(),
        Some("1.0.0"),
        "flipped back"
    );
    assert_eq!(env.layout().previous().unwrap().as_deref(), Some("1.1.0"));
    let st = UpdateState::load(&store(&d.cfg.state_dir)).unwrap();
    assert!(st.pending.is_none());
    let rb = st.rolled_back.expect("rolled_back recorded");
    assert_eq!(rb.version, "1.1.0");
    assert!(rb.reason.contains(why), "{}", rb.reason);
    assert!(d.read_state(|s| s.flags.contains(&Flag::UpdateRolledBack)));
    // Both units were restarted again (the second pair of restarts).
    assert!(env.systemd.restarted().len() >= 4);
    assert!(
        env.h
            .audit
            .lines()
            .iter()
            .any(|l| l.contains("needs_attention=UPDATE_ROLLED_BACK")),
        "audited"
    );
}

#[tokio::test]
async fn a_gatewayd_admin_socket_that_does_not_answer_rolls_back() {
    let env = applied_env().await;
    env.health.status_ok.store(false, Ordering::SeqCst);
    let d = env.new_process("1.1.0");
    d.resume_update().await;
    assert_rolled_back(&env, &d, "admin socket").await;
}

#[tokio::test]
async fn a_gatewayd_that_is_not_running_rolls_back() {
    let env = applied_env().await;
    env.systemd.gateway_active.store(false, Ordering::SeqCst);
    let d = env.new_process("1.1.0");
    d.resume_update().await;
    assert_rolled_back(&env, &d, "stable MainPID").await;
    assert_eq!(
        env.health.status_calls.load(Ordering::SeqCst),
        0,
        "Status is only asked of a stable gatewayd"
    );
}

#[tokio::test]
async fn a_gatewayd_in_a_crash_loop_rolls_back() {
    let env = applied_env().await;
    env.systemd.gateway_flapping.store(true, Ordering::SeqCst);
    let d = env.new_process("1.1.0");
    d.resume_update().await;
    assert_rolled_back(&env, &d, "stable MainPID").await;
}

#[tokio::test]
async fn a_privd_that_does_not_answer_after_the_reexec_rolls_back() {
    let env = applied_env().await;
    env.health.privd_ok.store(false, Ordering::SeqCst);
    let d = env.new_process("1.1.0");
    d.resume_update().await;
    assert_rolled_back(&env, &d, "privd did not answer").await;
}

#[tokio::test]
async fn a_new_privd_that_keeps_restarting_is_rolled_back_after_three_starts() {
    let env = applied_env().await;
    // Three starts that never get to finish the check (the process is replaced mid-way), simulated
    // by recording the attempts directly.
    let mut st = state(&env);
    st.pending.as_mut().unwrap().attempts = 3;
    st.save(&store(&env.h.daemon.cfg.state_dir)).unwrap();
    let d = env.new_process("1.1.0");
    d.resume_update().await;
    assert_rolled_back(&env, &d, "restarted repeatedly").await;
}

#[tokio::test]
async fn a_privd_running_the_wrong_version_rolls_back() {
    let env = applied_env().await;
    let d = env.new_process("1.0.0");
    d.resume_update().await;
    assert_rolled_back(&env, &d, "running version").await;
}

#[tokio::test]
async fn after_a_rollback_the_update_is_reoffered_but_never_reapplied_automatically() {
    let env = applied_env().await;
    env.health.status_ok.store(false, Ordering::SeqCst);
    let d = env.new_process("1.1.0");
    d.resume_update().await;
    env.systemd.restarts.lock().unwrap().clear();
    // The old binary is running again. CheckUpdate re-offers the same release, with the reason.
    env.health.status_ok.store(true, Ordering::SeqCst);
    env.publish("1.1.0", T0);
    let c = check_result(env.check().await);
    assert_eq!(c.available.as_deref(), Some("1.1.0"));
    let rb = c.rolled_back.expect("rolled_back");
    assert_eq!(rb.version, "1.1.0");
    assert!(rb.reason.contains("admin socket"));
    // Nothing restarted by itself.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(env.systemd.restarted().is_empty());
    assert_eq!(env.layout().current().unwrap().as_deref(), Some("1.0.0"));
    // A new ApplyUpdate works, and a healthy result clears the record and the flag.
    ok(env.apply("1.1.0").await);
    let d2 = env.new_process("1.1.0");
    d2.resume_update().await;
    let st = UpdateState::load(&store(&d2.cfg.state_dir)).unwrap();
    assert!(st.rolled_back.is_none());
    assert!(!d2.read_state(|s| s.flags.contains(&Flag::UpdateRolledBack)));
    assert_eq!(env.layout().current().unwrap().as_deref(), Some("1.1.0"));
}

#[tokio::test]
async fn if_privd_cannot_be_restarted_the_update_is_rolled_back_by_the_old_process() {
    let env = Env::new();
    env.systemd.fail_privd_restart.store(true, Ordering::SeqCst);
    env.publish("1.1.0", T0);
    check_result(env.check().await);
    ok(env.apply("1.1.0").await);
    // gatewayd, privd (fails), then the rollback's own pair of restarts.
    env.wait_restarts(4).await;
    for _ in 0..100 {
        if env.layout().current().unwrap().as_deref() == Some("1.0.0") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(env.layout().current().unwrap().as_deref(), Some("1.0.0"));
    assert!(state(&env).pending.is_none());
    assert!(state(&env).rolled_back.is_some());
}

// ----- RollbackUpdate --------------------------------------------------------------------------------

#[tokio::test]
async fn gateway_cannot_call_rollback_update() {
    let env = applied_env().await;
    let d = env.new_process("1.1.0");
    d.resume_update().await;
    env.systemd.restarts.lock().unwrap().clear();
    let r = env
        .call(
            Role::Gateway,
            Command::RollbackUpdate(pb::RollbackUpdateRequest {}),
        )
        .await;
    assert_eq!(err(&r).0, ErrorCode::PermissionDenied);
    assert_eq!(env.layout().current().unwrap().as_deref(), Some("1.1.0"));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(env.systemd.restarted().is_empty());
}

#[tokio::test]
async fn admin_rollback_flips_back_and_restarts() {
    let env = applied_env().await;
    let d = env.new_process("1.1.0");
    d.resume_update().await;
    env.systemd.restarts.lock().unwrap().clear();
    let r = env
        .call(
            Role::Admin,
            Command::RollbackUpdate(pb::RollbackUpdateRequest {}),
        )
        .await;
    assert!(matches!(ok(r), R::RollbackUpdate(_)));
    assert_eq!(env.layout().current().unwrap().as_deref(), Some("1.0.0"));
    assert_eq!(env.layout().previous().unwrap().as_deref(), Some("1.1.0"));
    env.wait_restarts(2).await;
    assert_eq!(env.systemd.restarted(), [Unit::Gatewayd, Unit::Privd]);
}

#[tokio::test]
async fn rollback_without_a_previous_version_is_refused() {
    let env = Env::new();
    let r = env
        .call(
            Role::Admin,
            Command::RollbackUpdate(pb::RollbackUpdateRequest {}),
        )
        .await;
    assert_eq!(err(&r).0, ErrorCode::FailedPrecondition);
    // A previous version that is not intact is not switched to.
    install_release(&env.h.daemon.cfg.update.versions_dir, "0.9.0");
    std::os::unix::fs::symlink(
        "0.9.0",
        env.h.daemon.cfg.update.versions_dir.join("previous"),
    )
    .unwrap();
    std::fs::remove_file(
        env.h
            .daemon
            .cfg
            .update
            .versions_dir
            .join("0.9.0/hx-gatewayd"),
    )
    .unwrap();
    let r = env
        .call(
            Role::Admin,
            Command::RollbackUpdate(pb::RollbackUpdateRequest {}),
        )
        .await;
    assert_eq!(err(&r).0, ErrorCode::FailedPrecondition);
    assert_eq!(env.layout().current().unwrap().as_deref(), Some("1.0.0"));
}

#[tokio::test]
async fn rollback_is_refused_while_an_update_is_pending() {
    let env = applied_env().await;
    let r = env
        .call(
            Role::Admin,
            Command::RollbackUpdate(pb::RollbackUpdateRequest {}),
        )
        .await;
    assert_eq!(err(&r).0, ErrorCode::FailedPrecondition);
}

// ----- roles and rates ---------------------------------------------------------------------------------

#[tokio::test]
async fn check_and_apply_are_open_to_gateway_once_set_up() {
    let env = Env::new();
    // Phase gates apply as for every class A command: refused until the host is set up.
    let r = env
        .call(
            Role::Gateway,
            Command::CheckUpdate(pb::CheckUpdateRequest {}),
        )
        .await;
    assert_eq!(err(&r).0, ErrorCode::FailedPrecondition);
    env.h
        .daemon
        .mutate_state(|s| s.phase.phase = hx_agent::privd::state::PhaseKind::Ready)
        .unwrap();
    env.publish("1.1.0", T0);
    let r = env
        .call(
            Role::Gateway,
            Command::CheckUpdate(pb::CheckUpdateRequest {}),
        )
        .await;
    assert_eq!(check_result(r).available.as_deref(), Some("1.1.0"));
}

#[tokio::test]
async fn check_update_is_limited_to_six_an_hour() {
    let env = Env::new();
    env.publish("1.1.0", T0);
    for _ in 0..6 {
        check_result(env.check().await);
    }
    let r = env.check().await;
    assert_eq!(err(&r).0, ErrorCode::ResourceExhausted);
    // Refused by the rate limit: the fetcher was not started again.
    assert_eq!(env.server.lock().unwrap().jobs.len(), 6);
    env.h.clock.advance_secs(3_601);
    check_result(env.check().await);
}

fn gateway_apply(version: &str) -> Command {
    Command::ApplyUpdate(pb::ApplyUpdateRequest {
        version: version.into(),
    })
}

fn set_ready(env: &Env) {
    env.h
        .daemon
        .mutate_state(|s| s.phase.phase = hx_agent::privd::state::PhaseKind::Ready)
        .unwrap();
}

#[tokio::test]
async fn refused_gateway_applies_do_not_use_the_two_a_day_allowance() {
    // M1: a Gateway that can only send refused requests must not lock the Admin out.
    let env = Env::new();
    set_ready(&env);
    env.publish("1.1.0", T0);
    for _ in 0..2 {
        let r = env.call(Role::Gateway, gateway_apply("0.0.1")).await;
        assert_eq!(err(&r).0, ErrorCode::FailedPrecondition);
    }
    assert!(state(&env).apply_log.is_empty(), "refusals are not counted");
    check_result(env.check().await);
    ok(env.apply("1.1.0").await);
    assert!(
        state(&env).apply_log.is_empty(),
        "an Admin apply is exempt from the Gateway allowance"
    );
}

#[tokio::test]
async fn gateway_refusals_have_their_own_hourly_limit() {
    let env = Env::new();
    set_ready(&env);
    for _ in 0..10 {
        let r = env.call(Role::Gateway, gateway_apply("0.0.1")).await;
        assert_eq!(err(&r).0, ErrorCode::FailedPrecondition);
    }
    let r = env.call(Role::Gateway, gateway_apply("0.0.1")).await;
    assert_eq!(err(&r).0, ErrorCode::ResourceExhausted);
    // The Admin is not subject to it.
    env.publish("1.1.0", T0);
    check_result(env.check().await);
    ok(env.apply("1.1.0").await);
    env.h.clock.advance_secs(3_601);
    let r = env.call(Role::Gateway, gateway_apply("0.0.1")).await;
    assert_ne!(err(&r).0, ErrorCode::ResourceExhausted);
}

#[tokio::test]
async fn apply_update_by_gateway_is_limited_to_two_started_a_day() {
    let env = Env::new();
    set_ready(&env);
    env.publish("1.1.0", T0);
    check_result(env.check().await);
    ok(env.call(Role::Gateway, gateway_apply("1.1.0")).await);
    env.new_process("1.1.0").resume_update().await;
    env.publish("1.2.0", T0 + 1);
    check_result(env.check().await);
    ok(env.call(Role::Gateway, gateway_apply("1.2.0")).await);
    assert_eq!(state(&env).apply_log.len(), 2);
    let r = env.call(Role::Gateway, gateway_apply("1.3.0")).await;
    let (code, msg) = err(&r);
    assert_eq!(code, ErrorCode::ResourceExhausted);
    assert!(msg.contains("2 a day"), "{msg}");
}

#[tokio::test]
async fn an_invalid_version_is_rejected_at_the_boundary() {
    let env = Env::new();
    // (The wire decoder rejects these first; this is the second line. ApplyUpdate is limited to
    // two a day, so two values.)
    for bad in ["1.2.3; rm -rf /", "../1.2.3"] {
        let r = env.apply(bad).await;
        assert_eq!(err(&r).0, ErrorCode::InvalidArgument, "{bad:?}");
    }
    assert!(env.server.lock().unwrap().jobs.is_empty());
}

// ----- rollback restores an explicit version (M1, N3), judging waits for the lock (M2), L4 -----------

fn set_pending(env: &Env, version: &str, previous: Option<&str>) {
    let store = store(&env.h.daemon.cfg.state_dir);
    let mut st = UpdateState::load(&store).unwrap();
    st.pending = Some(hx_agent::privd::update::state::Pending {
        version: version.into(),
        previous: previous.map(str::to_string),
        started_unix: NOW,
        attempts: 0,
        gateway_pid: None,
    });
    st.save(&store).unwrap();
}

fn links(env: &Env, current: &str, previous: &str) {
    let vd = &env.h.daemon.cfg.update.versions_dir;
    for v in ["0.9.0", "1.0.0", "1.1.0"] {
        if !vd.join(v).exists() {
            install_release(vd, v);
        }
    }
    for (name, target) in [("current", current), ("previous", previous)] {
        let p = vd.join(name);
        let _ = std::fs::remove_file(&p);
        std::os::unix::fs::symlink(target, p).unwrap();
    }
}

#[tokio::test]
async fn a_crash_before_the_switch_never_downgrades() {
    // Case (a): pending was saved, the switch never happened; links are 1.0 / 0.9.
    let env = Env::new();
    links(&env, "1.0.0", "0.9.0");
    set_pending(&env, "1.1.0", Some("1.0.0"));
    let d = env.new_process("1.0.0");
    d.resume_update().await;
    assert_eq!(
        env.layout().current().unwrap().as_deref(),
        Some("1.0.0"),
        "not 0.9.0"
    );
    assert_eq!(env.layout().previous().unwrap().as_deref(), Some("0.9.0"));
    assert!(
        UpdateState::load(&store(&d.cfg.state_dir))
            .unwrap()
            .pending
            .is_none()
    );
}

#[tokio::test]
async fn a_second_rollback_after_a_crash_does_not_flip_back_to_the_bad_version() {
    // Case (b): the rollback moved the links (1.0 / 1.1) but pending was not yet cleared.
    let env = Env::new();
    links(&env, "1.0.0", "1.1.0");
    set_pending(&env, "1.1.0", Some("1.0.0"));
    let d = env.new_process("1.0.0");
    d.resume_update().await;
    assert_eq!(env.layout().current().unwrap().as_deref(), Some("1.0.0"));
    assert_eq!(env.layout().previous().unwrap().as_deref(), Some("1.1.0"));
    let st = UpdateState::load(&store(&d.cfg.state_dir)).unwrap();
    assert!(st.pending.is_none());
    assert_eq!(st.rolled_back.unwrap().version, "1.1.0");
    // And again: nothing moves.
    d.resume_update().await;
    assert_eq!(env.layout().current().unwrap().as_deref(), Some("1.0.0"));
}

#[tokio::test]
async fn equal_current_and_previous_links_are_left_alone() {
    // Case (c).
    let env = Env::new();
    links(&env, "1.0.0", "1.0.0");
    set_pending(&env, "1.1.0", Some("1.0.0"));
    env.new_process("1.0.0").resume_update().await;
    assert_eq!(env.layout().current().unwrap().as_deref(), Some("1.0.0"));
    assert_eq!(env.layout().previous().unwrap().as_deref(), Some("1.0.0"));
}

#[tokio::test]
async fn a_rollback_restores_the_recorded_version_even_if_previous_is_something_else() {
    // The links say 1.1 / 0.9 (a stale `previous`): the automatic rollback restores 1.0 (what
    // was recorded), not 0.9.
    let env = Env::new();
    links(&env, "1.1.0", "0.9.0");
    set_pending(&env, "1.1.0", Some("1.0.0"));
    env.health.status_ok.store(false, Ordering::SeqCst);
    env.new_process("1.1.0").resume_update().await;
    assert_eq!(env.layout().current().unwrap().as_deref(), Some("1.0.0"));
    assert_eq!(env.layout().previous().unwrap().as_deref(), Some("1.1.0"));
}

#[tokio::test]
async fn an_update_with_no_recorded_predecessor_is_not_flipped_to_anything() {
    let env = Env::new();
    links(&env, "1.1.0", "0.9.0");
    set_pending(&env, "1.1.0", None);
    env.health.status_ok.store(false, Ordering::SeqCst);
    env.new_process("1.1.0").resume_update().await;
    assert_eq!(
        env.layout().current().unwrap().as_deref(),
        Some("1.1.0"),
        "no downgrade to 0.9"
    );
    assert!(state(&env).rolled_back.is_some());
}

#[tokio::test]
async fn admin_rollback_will_not_land_on_the_release_that_was_rolled_back() {
    let env = applied_env().await;
    env.health.status_ok.store(false, Ordering::SeqCst);
    env.new_process("1.1.0").resume_update().await;
    // current 1.0, previous 1.1 (known bad): a manual rollback would flip to it.
    let r = env
        .call(
            Role::Admin,
            Command::RollbackUpdate(pb::RollbackUpdateRequest {}),
        )
        .await;
    let (code, msg) = err(&r);
    assert_eq!(code, ErrorCode::FailedPrecondition);
    assert!(msg.contains("failed its health check"), "{msg}");
    assert_eq!(env.layout().current().unwrap().as_deref(), Some("1.0.0"));
}

#[tokio::test]
async fn the_new_process_judges_the_update_even_if_the_host_lock_is_busy_for_a_long_time() {
    let env = applied_env().await;
    let d = env.new_process("1.1.0");
    // The host refresh at start holds the lock for longer than the usual 10 s wait.
    let held = {
        let d = d.clone();
        tokio::spawn(async move {
            let _g = d.lock_host(&Ctx::new(Role::Admin)).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(11)).await;
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    d.resume_update().await;
    held.await.unwrap();
    let st = UpdateState::load(&store(&d.cfg.state_dir)).unwrap();
    assert!(st.pending.is_none(), "judged, not left pending");
    assert!(st.rolled_back.is_none());
    assert_eq!(env.layout().current().unwrap().as_deref(), Some("1.1.0"));
}

#[tokio::test]
async fn a_corrupt_updates_state_is_never_replaced_by_defaults() {
    let env = applied_env().await;
    let path = env.h.daemon.cfg.state_dir.join("updates-state");
    std::fs::write(&path, b"{oops").unwrap();
    env.health.status_ok.store(false, Ordering::SeqCst);
    let d = env.new_process("1.1.0");
    d.resume_update().await;
    assert_eq!(std::fs::read(&path).unwrap(), b"{oops", "left untouched");
    assert_eq!(err(&env.check().await).0, ErrorCode::Internal);
    assert_eq!(std::fs::read(&path).unwrap(), b"{oops");
}

// ----- L1, L3, N5, N6 -----------------------------------------------------------------------------

#[tokio::test]
async fn the_apply_limit_survives_a_restart_of_privd() {
    let env = Env::new();
    set_ready(&env);
    env.publish("1.1.0", T0);
    check_result(env.check().await);
    ok(env.call(Role::Gateway, gateway_apply("1.1.0")).await);
    env.new_process("1.1.0").resume_update().await;
    env.publish("1.2.0", T0 + 1);
    check_result(env.check().await);
    ok(env.call(Role::Gateway, gateway_apply("1.2.0")).await);
    // A fresh process has fresh in-memory buckets; the persisted log still says two.
    let n = env.new_process("1.2.0");
    let r = n
        .handle(
            request(
                1,
                Command::ApplyUpdate(pb::ApplyUpdateRequest {
                    version: "1.3.0".into(),
                }),
            ),
            Ctx::new(Role::Gateway),
        )
        .await;
    let (code, msg) = err(&r);
    assert_eq!(code, ErrorCode::ResourceExhausted);
    assert!(msg.contains("2 a day"), "{msg}");
    // A day later it is allowed again (refused here only because nothing is staged for 1.3.0).
    env.h.clock.advance_secs(86_401);
    let r = n
        .handle(
            request(
                2,
                Command::ApplyUpdate(pb::ApplyUpdateRequest {
                    version: "1.3.0".into(),
                }),
            ),
            Ctx::new(Role::Gateway),
        )
        .await;
    assert_ne!(err(&r).0, ErrorCode::ResourceExhausted);
}

#[tokio::test]
async fn gateway_cannot_loop_re_applying_a_rolled_back_release() {
    let env = applied_env().await;
    env.health.status_ok.store(false, Ordering::SeqCst);
    env.new_process("1.1.0").resume_update().await;
    env.h
        .daemon
        .mutate_state(|s| s.phase.phase = hx_agent::privd::state::PhaseKind::Ready)
        .unwrap();
    let gw = env
        .call(
            Role::Gateway,
            Command::ApplyUpdate(pb::ApplyUpdateRequest {
                version: "1.1.0".into(),
            }),
        )
        .await;
    let (code, msg) = err(&gw);
    assert_eq!(code, ErrorCode::PermissionDenied);
    assert!(msg.contains("Admin"), "{msg}");
    // Admin may; and the recovery snapshot is not rotated away while the record exists.
    env.health.status_ok.store(true, Ordering::SeqCst);
    env.publish("1.1.0", T0);
    check_result(env.check().await);
    assert!(matches!(ok(env.apply("1.1.0").await), R::ApplyUpdate(_)));
    // After an Admin's own rollback, Gateway is likewise refused for that release.
    let env = applied_env().await;
    env.new_process("1.1.0").resume_update().await;
    env.h
        .daemon
        .mutate_state(|s| s.phase.phase = hx_agent::privd::state::PhaseKind::Ready)
        .unwrap();
    ok(env
        .call(
            Role::Admin,
            Command::RollbackUpdate(pb::RollbackUpdateRequest {}),
        )
        .await);
    let gw = env
        .call(
            Role::Gateway,
            Command::ApplyUpdate(pb::ApplyUpdateRequest {
                version: "1.1.0".into(),
            }),
        )
        .await;
    assert_eq!(err(&gw).0, ErrorCode::PermissionDenied);
}

#[tokio::test]
async fn the_snapshot_before_the_first_bad_update_survives_a_reapply_loop() {
    let env = Env::new();
    env.h
        .incus
        .add_desktop("hx-main", "ubuntu-24.04-xfce-basic", "alice", true);
    env.h.daemon.register_desktop("main").unwrap();
    env.publish("1.1.0", T0);
    check_result(env.check().await);
    ok(env.apply("1.1.0").await);
    let first: Vec<String> = env
        .h
        .incus
        .with(|s| s.instances["hx-main"].snapshots.to_vec());
    assert_eq!(first.len(), 1);
    env.health.status_ok.store(false, Ordering::SeqCst);
    env.new_process("1.1.0").resume_update().await;
    env.health.status_ok.store(true, Ordering::SeqCst);
    for _ in 0..3 {
        env.h.clock.advance_secs(86_401);
        env.publish("1.1.0", T0);
        check_result(env.check().await);
        ok(env.apply("1.1.0").await);
        env.health.status_ok.store(false, Ordering::SeqCst);
        env.new_process("1.1.0").resume_update().await;
        env.health.status_ok.store(true, Ordering::SeqCst);
    }
    let all: Vec<String> = env
        .h
        .incus
        .with(|s| s.instances["hx-main"].snapshots.to_vec());
    assert!(
        all.contains(&first[0]),
        "the first recovery point is still there: {all:?}"
    );
    assert!(all.len() <= 4);
}

#[tokio::test]
async fn a_non_canonical_version_string_is_never_used() {
    let env = Env::new();
    env.publish("1.1.0", T0);
    check_result(env.check().await);
    let r = env.apply("01.1.0").await;
    assert_eq!(err(&r).0, ErrorCode::InvalidArgument);
    assert!(!env.h.daemon.cfg.update.versions_dir.join("01.1.0").exists());
    assert!(
        !env.server
            .lock()
            .unwrap()
            .jobs
            .iter()
            .any(|j| j.contains("01."))
    );
    // The canonical one works.
    assert!(matches!(ok(env.apply("1.1.0").await), R::ApplyUpdate(_)));
}

#[tokio::test]
async fn a_very_old_manifest_is_reported_but_not_refused() {
    let env = Env::new();
    env.publish("1.1.0", NOW - 100 * 86_400);
    let c = check_result(env.check().await);
    assert_eq!(c.available.as_deref(), Some("1.1.0"));
    assert!(
        env.h
            .audit
            .lines()
            .iter()
            .any(|l| l.contains("days old (possible freeze)")),
        "reported"
    );
    // A recent one is not.
    let env = Env::new();
    env.publish("1.1.0", T0);
    check_result(env.check().await);
    assert!(
        !env.h
            .audit
            .lines()
            .iter()
            .any(|l| l.contains("possible freeze"))
    );
}

#[tokio::test]
async fn freshness_is_tracked_per_channel() {
    // A beta counter far ahead must not make a valid stable manifest look like a replay.
    let env = Env::new();
    let store = store(&env.h.daemon.cfg.state_dir);
    let mut st = UpdateState::load(&store).unwrap();
    st.accept("beta", NOW + 3_600);
    st.save(&store).unwrap();
    env.publish("1.1.0", T0);
    assert_eq!(
        check_result(env.check().await).available.as_deref(),
        Some("1.1.0")
    );
    let st = state(&env);
    assert_eq!(st.highest("stable"), T0);
    assert_eq!(st.highest("beta"), NOW + 3_600);
    // Replay protection still holds within the stable channel.
    env.publish("1.1.0", T0 - 10);
    assert_eq!(err(&env.check().await).0, ErrorCode::FailedPrecondition);
}

#[tokio::test]
async fn entries_privd_cannot_remove_are_reported_not_hidden_behind_internal() {
    let env = Env::new();
    env.publish("1.1.0", T0);
    check_result(env.check().await);
    // A directory with content that the sweep cannot empty (stands for a chmod-ed one).
    let dir = env.h.daemon.cfg.update.fetch_dir.clone();
    std::fs::create_dir_all(dir.join("trap")).unwrap();
    std::fs::write(dir.join("trap/inner"), b"x").unwrap();
    let (code, msg) = err(&env.check().await);
    assert_eq!(code, ErrorCode::FailedPrecondition);
    assert!(msg.contains("administrator must clear"), "{msg}");
    assert!(
        env.h
            .audit
            .lines()
            .iter()
            .any(|l| l.contains("entries privd cannot remove")),
        "audited"
    );
    // Cleared by hand, it works again.
    std::fs::remove_dir_all(dir.join("trap")).unwrap();
    assert!(check_result(env.check().await).available.is_some());
}

// ----- N1, N2 ---------------------------------------------------------------------------------------

#[tokio::test]
async fn a_cancelled_check_stops_the_fetcher_unit() {
    let env = Env::new();
    env.publish("1.1.0", T0);
    env.systemd.block_fetch.store(true, Ordering::SeqCst);
    let ctx = Ctx::new(Role::Admin);
    let cancel = ctx.cancel.clone();
    let d = env.h.daemon.clone();
    let task = tokio::spawn(async move {
        d.handle(
            request(1, Command::CheckUpdate(pb::CheckUpdateRequest {})),
            ctx,
        )
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    cancel.cancel(hx_agent::privd::cancel::CancelReason::Cancelled);
    let r = task.await.unwrap();
    assert_eq!(err(&r).0, ErrorCode::Cancelled);
    assert_eq!(
        env.systemd.stops.lock().unwrap().clone(),
        ["manifest-stable"]
    );
}

#[tokio::test]
async fn apply_records_gatewayds_pid_and_the_health_check_wants_a_different_one() {
    let env = applied_env().await;
    assert_eq!(state(&env).pending.unwrap().gateway_pid, Some(4242));
    // gatewayd was never restarted: same MainPID as before the update, active and stable.
    let d = env.new_process("1.1.0");
    env.systemd.gateway_pid.store(4242, Ordering::SeqCst);
    d.resume_update().await;
    let rb = state(&env).rolled_back.expect("rolled back");
    assert!(rb.reason.contains("not restarted"), "{}", rb.reason);
    assert_eq!(env.health.status_calls.load(Ordering::SeqCst), 0);
    assert_eq!(env.layout().current().unwrap().as_deref(), Some("1.0.0"));
}

#[tokio::test]
async fn gatewayd_must_report_the_new_version() {
    let env = applied_env().await;
    let d = env.new_process("1.1.0");
    *env.health.gateway_version.lock().unwrap() = Some("1.0.0".into());
    d.resume_update().await;
    let rb = state(&env).rolled_back.expect("rolled back");
    assert!(
        rb.reason.contains("reports version `1.0.0`"),
        "{}",
        rb.reason
    );
    assert_eq!(env.layout().current().unwrap().as_deref(), Some("1.0.0"));
}

#[tokio::test]
async fn the_answering_privd_must_be_the_new_one() {
    let env = applied_env().await;
    let d = env.new_process("1.1.0");
    // An old process still holding the socket answers as 1.0.0.
    *env.health.privd_version.lock().unwrap() = Some("1.0.0".into());
    d.resume_update().await;
    let rb = state(&env).rolled_back.expect("rolled back");
    assert!(
        rb.reason.contains("privd answers as version 1.0.0"),
        "{}",
        rb.reason
    );
}
