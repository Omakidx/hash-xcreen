//! `Uninstall` deletes the `hx-img-*` images privd recorded, in both modes (docs/ipc.md 6.13).

mod privd_image_common;

use hx_agent::privd::testing::{FakeImage, request};
use hx_ipc::privd::pb::{self, Role, request::Command, response::Result as R};
use privd_image_common::*;

fn uninstall_cmd(keep: bool) -> Command {
    Command::Uninstall(pb::UninstallRequest {
        keep_desktop: keep,
        confirm_destroy: !keep,
    })
}

async fn run(env: &Env, keep: bool) -> pb::UninstallResult {
    let r = env
        .h
        .daemon
        .handle(
            request(1, uninstall_cmd(keep)),
            hx_agent::privd::daemon::Ctx::new(Role::Admin),
        )
        .await;
    match ok(r) {
        R::Uninstall(u) => u,
        other => panic!("{other:?}"),
    }
}

fn seed(env: &Env) -> (String, String) {
    let ours = "a".repeat(64);
    let theirs = "b".repeat(64);
    env.h.incus.with(|s| {
        s.images.insert(
            ours.clone(),
            FakeImage {
                aliases: vec![format!("hx-img-ubuntu-24.04-xfce-basic-{}", &ours[..12])],
                size: 1,
                data: vec![0],
            },
        );
        s.images.insert(
            theirs.clone(),
            FakeImage {
                aliases: vec!["debian/13".into()],
                size: 1,
                data: vec![0],
            },
        );
    });
    std::fs::write(
        env.h.daemon.cfg.state_dir.join("images-state"),
        serde_json::json!({"highest_manifest_ts": 5, "cached": [
            {"fingerprint": ours, "recipe": "ubuntu-24.04-xfce-basic", "build_id": "20261120.1", "imported_unix": NOW},
            {"fingerprint": "c".repeat(64), "recipe": "gone", "build_id": "20261120.2", "imported_unix": NOW},
        ]})
        .to_string(),
    )
    .unwrap();
    (ours, theirs)
}

#[tokio::test(flavor = "multi_thread")]
async fn keep_mode_deletes_the_recorded_images_and_only_those() {
    let env = Env::new().await;
    let (ours, theirs) = seed(&env);
    let u = run(&env, true).await;
    assert!(
        u.removed
            .iter()
            .any(|r| r.starts_with("image:aaaaaaaaaaaa")),
        "{:?}",
        u.removed
    );
    assert!(
        env.h
            .incus
            .with(|s| !s.images.contains_key(&ours) && s.images.contains_key(&theirs))
    );
    let st: serde_json::Value = serde_json::from_slice(
        &std::fs::read(env.h.daemon.cfg.state_dir.join("images-state")).unwrap(),
    )
    .unwrap();
    assert_eq!(st["cached"], serde_json::json!([]));
    assert_eq!(st["highest_manifest_ts"], 5);
}

#[tokio::test(flavor = "multi_thread")]
async fn destroy_mode_deletes_them_too_and_a_rerun_is_idempotent() {
    let env = Env::new().await;
    let (ours, theirs) = seed(&env);
    let u = run(&env, false).await;
    assert!(
        u.removed
            .iter()
            .any(|r| r.starts_with("image:aaaaaaaaaaaa")),
        "{:?}",
        u.removed
    );
    assert!(
        env.h
            .incus
            .with(|s| !s.images.contains_key(&ours) && s.images.contains_key(&theirs))
    );
    let again = run(&env, false).await;
    assert!(again.warnings.is_empty(), "{:?}", again.warnings);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_incus_is_a_warning_not_a_failure() {
    let env = Env::new().await;
    let (ours, _) = seed(&env);
    env.h.incus.with(|s| s.down = true);
    // The session-link step already needs Incus only for registered desktops: none here.
    let u = run(&env, true).await;
    assert!(
        u.warnings
            .iter()
            .any(|w| w.contains("could not be deleted")),
        "{:?}",
        u.warnings
    );
    env.h.incus.with(|s| s.down = false);
    assert!(env.h.incus.with(|s| s.images.contains_key(&ours)));
}
