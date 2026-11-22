//! `CreateDesktop` from a signed prebuilt image, online (docs/ipc.md 6.5 and 6.12, "Prebuilt images
//! (1D)"): the algorithm of `privd::image::choose` with a reason code for every outcome, the
//! prebuilt path against a fake Incus (import by fingerprint, launch from the image, the image
//! kept until `ready` and then deleted), the fall back to a build, the cache and its cleanup, and
//! the replay counter. The fetcher is a fake unit that writes the chunk protocol into the real fetch
//! directory (`privd_image_hostile.rs` makes it hostile, `privd_image_https.rs` puts the real
//! fetcher and a loopback HTTPS server behind it).

mod privd_image_common;

use std::sync::atomic::Ordering;

use hx_agent::privd::image::keys::{ImageKeys, ImageVerifyError, SignedComment};
use hx_agent::privd::probe::ImageSpace;
use hx_agent::privd::testing::{ExecRule, FakeIncus, FakeProbe};
use hx_ipc::privd::pb::{self, ErrorCode, ErrorDetail, ImageMode, ImageReason, PathTaken, Role};
use privd_image_common::*;

fn data() -> Vec<u8> {
    image_bytes(200 * 1024 + 123, 1)
}

fn job_names(env: &Env) -> Vec<String> {
    env.systemd.fetcher.started()
}

fn instance_source(env: &Env) -> serde_json::Value {
    env.h.incus.with(|s| s.instances["hx-main"].source.clone())
}

fn images_state(env: &Env) -> serde_json::Value {
    match std::fs::read(env.h.daemon.cfg.state_dir.join("images-state")) {
        Ok(b) => serde_json::from_slice(&b).unwrap(),
        Err(_) => serde_json::json!({}),
    }
}

fn staging_is_empty(env: &Env) -> bool {
    std::fs::read_dir(&env.h.daemon.cfg.image.staging_dir)
        .map(|d| d.count() == 0)
        .unwrap_or(true)
}

#[tokio::test(flavor = "multi_thread")]
async fn prebuilt_installs_from_the_signed_image_and_deletes_it_once_ready() {
    let env = Env::new().await;
    let d = data();
    let e = env.publish_image(&d, 2 * 86_400);
    let c = created(env.create(env.request(ImageMode::Prebuilt)).await);
    assert_eq!(c.path_taken(), PathTaken::Prebuilt);
    assert_eq!(c.reason_code(), ImageReason::PrebuiltRequested);
    assert!(
        c.reason
            .starts_with("prebuilt image 20261120.1 (2 days old)"),
        "{}",
        c.reason
    );
    let info = c.image.expect("image info");
    assert_eq!(
        (info.build_id.as_str(), info.created_unix, info.size),
        ("20261120.1", e.created, d.len() as u64)
    );
    // The signed bytes, once, under their own fingerprint; the instance came from it.
    assert_eq!(
        env.h.incus.with(|s| s.imports.clone()),
        [(e.sha256.clone(), d.len() as u64)]
    );
    assert_eq!(
        instance_source(&env),
        serde_json::json!({"type": "image", "fingerprint": e.sha256})
    );
    // ready, with metadata; the imported image is gone again, and so is its record.
    let cfg = env.h.incus.with(|s| s.instances["hx-main"].config.clone());
    assert_eq!(cfg["user.hx.state"], "ready");
    assert_eq!(cfg["user.hx.recipe"], "ubuntu-24.04-xfce-basic");
    assert!(env.h.incus.with(|s| s.images.is_empty()));
    assert_eq!(images_state(&env)["cached"], serde_json::json!([]));
    // The fetcher jobs: the list, then the image (no probe in `prebuilt`); nothing left behind.
    let jobs = job_names(&env);
    assert_eq!(jobs.len(), 2, "{jobs:?}");
    assert_eq!(jobs[0], "images-manifest");
    assert_eq!(jobs[1], "image-ubuntu-24.04-xfce-basic-20261120.1-1");
    assert!(
        env.fetch_dir_names().is_empty(),
        "{:?}",
        env.fetch_dir_names()
    );
    assert!(staging_is_empty(&env));
    // The timings name the image stages, and the post stage ran (the rename of `desk`).
    let stages: Vec<_> = c.timings.iter().map(|t| t.stage()).collect();
    assert!(stages.contains(&pb::ProgressStage::ImageFetch));
    assert!(stages.contains(&pb::ProgressStage::ImageImport));
    assert!(!stages.contains(&pb::ProgressStage::Build), "{stages:?}");
    assert!(
        env.h
            .incus
            .with(|s| s.execs.iter().any(|x| x.contains("usermod")))
    );
    // The audit log has the reason code and the build id, never the password.
    let audit = env.h.audit.lines().join("\n");
    assert!(
        audit.contains("reason_code=IMAGE_REASON_PREBUILT_REQUESTED"),
        "{audit}"
    );
    assert!(audit.contains("build_id=20261120.1"));
    assert!(!audit.contains("Correct-Horse"));
}

#[tokio::test(flavor = "multi_thread")]
async fn auto_chooses_the_prebuilt_image_when_the_release_host_is_fast_enough() {
    let env = Env::new().await;
    env.publish_image(&data(), 3 * 86_400);
    let c = created(env.create(env.request(ImageMode::Auto)).await);
    assert_eq!(c.path_taken(), PathTaken::Prebuilt);
    assert_eq!(c.reason_code(), ImageReason::PrebuiltFaster);
    assert_eq!(
        c.reason,
        "prebuilt image 20261120.1 (3 days old): release host 40.0 MiB/s, apt mirror 20.0 MiB/s"
    );
    let info = c.image.unwrap();
    assert_eq!((info.release_bps, info.mirror_bps), (40 << 20, 20 << 20));
    // list, probe, image.
    let jobs = job_names(&env);
    assert!(
        jobs[1].starts_with("probe-ubuntu-24.04-xfce-basic-20261120.1"),
        "{jobs:?}"
    );
    // The unspecified mode is AUTO.
    env.next_hour();
    env.h.incus.with(|s| s.instances.clear());
    let c = created(env.create(env.request(ImageMode::Unspecified)).await);
    assert_eq!(c.reason_code(), ImageReason::PrebuiltFaster);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_mirror_probe_alone_still_allows_the_prebuilt_image() {
    let env = Env::new().await;
    env.publish_image(&data(), 86_400);
    env.script(|s| s.probe = Some(probe_json(Some(10 << 20), None)));
    let c = created(env.create(env.request(ImageMode::Auto)).await);
    assert_eq!(c.reason_code(), ImageReason::PrebuiltFaster);
    assert!(c.reason.contains("apt mirror not measured"), "{}", c.reason);
}

/// Every reason for which `auto` builds on the server, and the same condition in `prebuilt` mode.
#[tokio::test(flavor = "multi_thread")]
async fn auto_builds_with_a_reason_and_prebuilt_fails_for_the_same_conditions() {
    struct Case {
        name: &'static str,
        setup: fn(&Env),
        probe: Option<FakeProbe>,
        reason: ImageReason,
        text: &'static str,
        /// `PREBUILT` mode: `None` means the case only exists in `auto` (the speed probe).
        prebuilt: Option<(ErrorCode, ErrorDetail)>,
    }
    let precondition = |d| Some((ErrorCode::FailedPrecondition, d));
    let cases = vec![
        Case {
            name: "no image key",
            setup: |e| {
                e.publish_image(&data(), 86_400);
                e.no_keys();
            },
            probe: None,
            reason: ImageReason::NoImageKey,
            text: "no image signing key",
            prebuilt: precondition(ErrorDetail::Image),
        },
        Case {
            name: "the list is not available",
            setup: |e| e.script(|s| s.manifest = None),
            probe: None,
            reason: ImageReason::ListUnavailable,
            text: "not available",
            prebuilt: Some((ErrorCode::Unavailable, ErrorDetail::Unspecified)),
        },
        Case {
            name: "the list is signed by another key",
            setup: |e| {
                e.publish_image(&data(), 86_400);
                let other = Signer::new();
                let m = manifest_json(
                    vec![entry_for(rid(), &data(), "20261120.1", NOW - 5, 1)],
                    NOW,
                );
                let sig = other.sign_manifest(&m, NOW);
                e.script(|s| s.manifest = Some((m, sig)));
            },
            probe: None,
            reason: ImageReason::ListUnverified,
            text: "did not verify",
            prebuilt: precondition(ErrorDetail::Image),
        },
        Case {
            name: "the signed comment is not an images manifest's",
            setup: |e| {
                e.publish_image(&data(), 86_400);
                let m = manifest_json(
                    vec![entry_for(rid(), &data(), "20261120.1", NOW - 5, 1)],
                    NOW,
                );
                let sig = e
                    .signer
                    .sign_with_comment(&m, "hx-release-manifest schema=1");
                e.script(|s| s.manifest = Some((m, sig)));
            },
            probe: None,
            reason: ImageReason::ListUnverified,
            text: "did not verify",
            prebuilt: precondition(ErrorDetail::Image),
        },
        Case {
            name: "the list is not JSON of the right shape",
            setup: |e| {
                let m = b"{\"schema\":1,\"unknown\":true}".to_vec();
                let sig = e.signer.sign_manifest(&m, NOW);
                e.script(|s| s.manifest = Some((m, sig)));
            },
            probe: None,
            reason: ImageReason::ListUnverified,
            text: "did not verify",
            prebuilt: precondition(ErrorDetail::Image),
        },
        Case {
            name: "the list is dated more than a day ahead",
            setup: |e| {
                e.publish(
                    vec![entry_for(rid(), &data(), "20261120.1", NOW - 5, 1)],
                    NOW + 2 * 86_400,
                );
            },
            probe: None,
            reason: ImageReason::ListUnverified,
            text: "did not verify",
            prebuilt: precondition(ErrorDetail::Image),
        },
        Case {
            name: "no image for the embedded recipe digest",
            setup: |e| {
                let mut en = entry_for(rid(), &data(), "20261120.1", NOW - 5, 1);
                en.recipe_digest = "0".repeat(64);
                e.publish(vec![en], NOW);
            },
            probe: None,
            reason: ImageReason::NoMatchingImage,
            text: "no prebuilt image matches",
            prebuilt: precondition(ErrorDetail::Image),
        },
        Case {
            name: "the image needs a newer agent",
            setup: |e| {
                let mut en = entry_for(rid(), &data(), "20261120.1", NOW - 5, 1);
                en.min_agent = "9.0.0".into();
                e.publish(vec![en], NOW);
            },
            probe: None,
            reason: ImageReason::NoMatchingImage,
            text: "no prebuilt image matches",
            prebuilt: precondition(ErrorDetail::Image),
        },
        Case {
            name: "the image is another recipe's",
            setup: |e| {
                let other = hx_provision::images::recipe_by_name("debian-13-xfce-basic").unwrap();
                e.publish(
                    vec![entry_for(other, &data(), "20261120.1", NOW - 5, 1)],
                    NOW,
                );
            },
            probe: None,
            reason: ImageReason::NoMatchingImage,
            text: "no prebuilt image matches",
            prebuilt: precondition(ErrorDetail::Image),
        },
        Case {
            name: "the newest image is older than 30 days",
            setup: |e| {
                e.publish_image(&data(), 31 * 86_400);
            },
            probe: None,
            reason: ImageReason::ImageStale,
            text: "31 days old (limit 30)",
            prebuilt: precondition(ErrorDetail::Image),
        },
        Case {
            name: "not enough disk for the copies",
            setup: |e| {
                e.publish_image(&data(), 86_400);
            },
            probe: Some(FakeProbe {
                image_space: Some(ImageSpace {
                    state_free: 1 << 20,
                    incus_free: 500 << 30,
                    same_device: false,
                }),
                ..FakeProbe::default()
            }),
            reason: ImageReason::Disk,
            text: "not enough disk for the prebuilt image (need 1.0 GiB on /var/lib/hx, 0.0 free)",
            prebuilt: precondition(ErrorDetail::Pool),
        },
        Case {
            name: "not enough room in the pool for the unpacked image",
            setup: |e| {
                e.publish_image(&data(), 86_400);
            },
            // 3 GiB unpacked + 8 GiB headroom = 11 GiB; the pool has 10.9 free of 40 total
            // (above both the creation minimum of 8 GiB and 15%).
            probe: Some(FakeProbe {
                pool: Some((40 << 30, 10 << 30)),
                ..FakeProbe::default()
            }),
            reason: ImageReason::Disk,
            text: "on the storage pool",
            prebuilt: precondition(ErrorDetail::Pool),
        },
        Case {
            name: "the release probe failed",
            setup: |e| {
                e.publish_image(&data(), 86_400);
                e.script(|s| s.probe = None);
            },
            probe: None,
            reason: ImageReason::ProbeFailed,
            text: "could not be measured",
            prebuilt: None,
        },
        Case {
            name: "the download would take more than 15 minutes",
            setup: |e| {
                e.publish_image(&data(), 86_400);
                // 100 bytes a second for a 200 KiB image.
                e.script(|s| s.probe = Some(probe_json(Some(100), Some(20 << 20))));
            },
            probe: None,
            reason: ImageReason::DownloadTooSlow,
            text: "would take about",
            prebuilt: None,
        },
        Case {
            name: "the release host is slower than half the mirror",
            setup: |e| {
                e.publish_image(&data(), 86_400);
                e.script(|s| s.probe = Some(probe_json(Some(5 << 20), Some(20 << 20))));
            },
            probe: None,
            reason: ImageReason::SlowerThanMirror,
            text: "slower than the apt mirror (5.0 vs 20.0 MiB/s)",
            prebuilt: None,
        },
        Case {
            name: "a hostile probe file is a failed probe",
            setup: |e| {
                e.publish_image(&data(), 86_400);
                e.script(|s| {
                    s.probe = Some("{\"release_bytes\":99999999999999,\"release_ms\":1}".into())
                });
            },
            probe: None,
            reason: ImageReason::ProbeFailed,
            text: "could not be measured",
            prebuilt: None,
        },
    ];
    for case in cases {
        let env = match &case.probe {
            Some(p) => Env::with(p.clone(), FakeIncus::new()).await,
            None => Env::new().await,
        };
        (case.setup)(&env);
        // AUTO: a build, with the reason; nothing was imported, nothing is left behind.
        let c = created(env.create(env.request(ImageMode::Auto)).await);
        assert_eq!(c.path_taken(), PathTaken::Build, "{}", case.name);
        assert_eq!(c.reason_code(), case.reason, "{}: {}", case.name, c.reason);
        assert!(c.reason.contains(case.text), "{}: {}", case.name, c.reason);
        assert!(c.reason.len() <= 256);
        assert!(c.image.is_none(), "{}", case.name);
        assert!(
            env.h
                .incus
                .with(|s| s.imports.is_empty() && s.images.is_empty()),
            "{}",
            case.name
        );
        assert!(
            !job_names(&env).iter().any(|j| j.starts_with("image-")),
            "{}",
            case.name
        );
        assert!(env.fetch_dir_names().is_empty(), "{}", case.name);
        assert!(
            env.h
                .incus
                .with(|s| s.instances["hx-main"].source["type"] == "image"
                    && s.instances["hx-main"].source["server"].is_string()),
            "{}: built from the remote base image",
            case.name
        );
        // PREBUILT: the same condition is an error (never a build).
        if let Some((code, detail)) = case.prebuilt {
            let env2 = match &case.probe {
                Some(p) => Env::with(p.clone(), FakeIncus::new()).await,
                None => Env::new().await,
            };
            (case.setup)(&env2);
            let r = env2.create(env2.request(ImageMode::Prebuilt)).await;
            let e = err(&r);
            assert_eq!(
                (e.code(), e.detail()),
                (code, detail),
                "{}: {}",
                case.name,
                e.message
            );
            if code == ErrorCode::Unavailable {
                assert!(e.retryable, "{}", case.name);
            }
            assert!(
                env2.h.incus.with(|s| s.instances.is_empty()),
                "{}",
                case.name
            );
            assert!(
                !env2
                    .h
                    .daemon
                    .read_state(|s| s.desktops.contains_key("main")),
                "{}",
                case.name
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn build_mode_never_asks_the_fetcher_and_says_so() {
    let env = Env::new().await;
    env.publish_image(&data(), 86_400);
    let c = created(env.create(env.request(ImageMode::Build)).await);
    assert_eq!(c.path_taken(), PathTaken::Build);
    assert_eq!(c.reason_code(), ImageReason::BuildRequested);
    assert_eq!(c.reason, "build on the server was requested");
    assert!(job_names(&env).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_existing_or_adopted_desktop_reports_existing() {
    let env = Env::new().await;
    env.publish_image(&data(), 86_400);
    created(env.create(env.request(ImageMode::Prebuilt)).await);
    env.next_hour();
    let again = created(env.create(env.request(ImageMode::Prebuilt)).await);
    assert_eq!(again.reason_code(), ImageReason::Existing);
    assert!(again.image.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn auto_falls_back_to_a_build_when_the_import_fails_before_the_post_stage() {
    let env = Env::new().await;
    env.publish_image(&data(), 86_400);
    env.h
        .incus
        .with(|s| s.import_fails = Some((500, "unpack failed".into())));
    let c = created(env.create(env.request(ImageMode::Auto)).await);
    assert_eq!(c.path_taken(), PathTaken::Build);
    assert_eq!(c.reason_code(), ImageReason::FellBack);
    assert!(
        c.reason
            .starts_with("building on the server: prebuilt image failed at IMAGE_IMPORT ("),
        "{}",
        c.reason
    );
    assert!(c.reason.len() <= 256);
    // The image record and the half-imported image are gone; the desktop was built from the base.
    assert!(env.h.incus.with(|s| s.images.is_empty()));
    assert_eq!(images_state(&env)["cached"], serde_json::json!([]));
    assert_eq!(
        env.h
            .incus
            .with(|s| s.instances["hx-main"].source["type"].clone()),
        "image"
    );
    assert!(
        env.h
            .incus
            .with(|s| s.instances["hx-main"].source["server"].is_string())
    );
    let cfg = env.h.incus.with(|s| s.instances["hx-main"].config.clone());
    assert_eq!(cfg["user.hx.state"], "ready");
}

#[tokio::test(flavor = "multi_thread")]
async fn auto_falls_back_to_a_build_when_the_launch_fails() {
    let env = Env::new().await;
    env.publish_image(&data(), 86_400);
    env.h
        .incus
        .with(|s| s.create_fails = Some((500, "no space left".into())));
    let c = created(env.create(env.request(ImageMode::Auto)).await);
    assert_eq!(c.reason_code(), ImageReason::FellBack);
    assert!(c.reason.contains("failed at LAUNCH"), "{}", c.reason);
    assert_eq!(c.path_taken(), PathTaken::Build);
    // The imported image is deleted when the attempt is undone.
    assert!(env.h.incus.with(|s| s.images.is_empty()));
}

#[tokio::test(flavor = "multi_thread")]
async fn prebuilt_never_falls_back_and_its_error_names_the_stage() {
    let env = Env::new().await;
    env.publish_image(&data(), 86_400);
    env.h
        .incus
        .with(|s| s.import_fails = Some((500, "unpack failed".into())));
    let r = env.create(env.request(ImageMode::Prebuilt)).await;
    let e = err(&r);
    assert_eq!(e.stage(), pb::ProgressStage::ImageImport);
    assert!(env.h.incus.with(|s| s.instances.is_empty()));
    assert!(!env.h.daemon.read_state(|s| s.desktops.contains_key("main")));
    // Launch failure: the stage is LAUNCH, and no instance is left.
    let env = Env::new().await;
    env.publish_image(&data(), 86_400);
    env.h
        .incus
        .with(|s| s.create_fails = Some((500, "no space left".into())));
    let e = err(&env.create(env.request(ImageMode::Prebuilt)).await);
    assert_eq!(e.stage(), pb::ProgressStage::Launch);
    assert!(env.h.incus.with(|s| s.instances.is_empty()));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failure_in_the_post_stage_is_an_ordinary_error_not_a_fall_back() {
    let env = Env::new().await;
    env.publish_image(&data(), 86_400);
    // The account rename is a post-stage step; it fails.
    env.h.incus.with(|s| {
        s.exec_rules.insert(
            0,
            ExecRule {
                needle: "usermod".into(),
                exit: 1,
                stdout: String::new(),
                delay: Some(std::time::Duration::ZERO),
            },
        );
    });
    let e = err(&env.create(env.request(ImageMode::Auto)).await);
    assert_eq!(e.stage(), pb::ProgressStage::Post, "{}", e.message);
    // No build was attempted (the instance was destroyed, the record forgotten) ...
    assert!(env.h.incus.with(|s| s.instances.is_empty()));
    assert!(!env.h.daemon.read_state(|s| s.desktops.contains_key("main")));
    // ... and the imported image is kept for a retry (it is cached until ready).
    assert_eq!(env.h.incus.with(|s| s.images.len()), 1);
    assert_eq!(images_state(&env)["cached"].as_array().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_25_minute_rule_keeps_a_late_failure_from_building() {
    let env = Env::new().await;
    env.publish_image(&data(), 86_400);
    env.h
        .incus
        .with(|s| s.import_fails = Some((500, "unpack failed".into())));
    // Only 10 minutes of the request's deadline are left in this configuration: not enough for a
    // build (25 minutes), so the failure is the answer.
    let d = env.daemon_with(|c| c.image.create_deadline = std::time::Duration::from_secs(10 * 60));
    let r = env
        .create_on(&d, Role::Admin, env.request(ImageMode::Auto))
        .await;
    let e = err(&r);
    assert_eq!(e.stage(), pb::ProgressStage::ImageImport, "{}", e.message);
    assert!(env.h.incus.with(|s| s.instances.is_empty()));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_retry_reuses_the_cached_image_and_skips_the_download() {
    let env = Env::new().await;
    let d = data();
    let e = env.publish_image(&d, 86_400);
    env.h.incus.with(|s| {
        s.exec_rules.insert(
            0,
            ExecRule {
                needle: "usermod".into(),
                exit: 1,
                stdout: String::new(),
                delay: Some(std::time::Duration::ZERO),
            },
        );
    });
    assert_eq!(
        err(&env.create(env.request(ImageMode::Auto)).await).stage(),
        pb::ProgressStage::Post
    );
    let started_before = job_names(&env).len();
    // The retry: the same fingerprint is the selected entry and the image is in Incus: no probe,
    // no download, no import.
    env.h.incus.with(|s| s.exec_rules.remove(0));
    env.next_hour();
    let c = created(env.create(env.request(ImageMode::Auto)).await);
    assert_eq!(c.path_taken(), PathTaken::Prebuilt);
    assert_eq!(c.reason_code(), ImageReason::PrebuiltFaster);
    assert!(c.reason.contains("already downloaded"), "{}", c.reason);
    let new_jobs: Vec<_> = job_names(&env).split_off(started_before);
    assert_eq!(new_jobs, ["images-manifest"], "{new_jobs:?}");
    assert_eq!(env.h.incus.with(|s| s.imports.len()), 1, "imported once");
    // Ready: the image is deleted.
    assert!(env.h.incus.with(|s| s.images.is_empty()));
    assert!(!images_state(&env).to_string().contains(&e.sha256));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cached_image_older_than_seven_days_is_downloaded_again() {
    let env = Env::new().await;
    let d = data();
    env.publish_image(&d, 86_400);
    env.h.incus.with(|s| {
        s.exec_rules.insert(
            0,
            ExecRule {
                needle: "usermod".into(),
                exit: 1,
                stdout: String::new(),
                delay: Some(std::time::Duration::ZERO),
            },
        );
    });
    err(&env.create(env.request(ImageMode::Prebuilt)).await);
    env.h.incus.with(|s| s.exec_rules.remove(0));
    // Eight days later the record is too old to trust (and the manifest, still the same, is
    // republished at the new time).
    env.h.clock.advance_secs(8 * 86_400);
    let now = NOW + 8 * 86_400;
    let e = entry_for(rid(), &d, "20261120.1", now - 86_400, 1);
    let m = manifest_json(vec![e], now);
    let sig = env.signer.sign_manifest(&m, now);
    env.script(|s| s.manifest = Some((m, sig)));
    let before = job_names(&env).len();
    let c = created(env.create(env.request(ImageMode::Prebuilt)).await);
    assert_eq!(c.path_taken(), PathTaken::Prebuilt);
    assert!(
        job_names(&env)
            .split_off(before)
            .iter()
            .any(|j| j.starts_with("image-"))
    );
    // The image was still in Incus, so there was no second upload.
    assert_eq!(env.h.incus.with(|s| s.imports.len()), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn recorded_images_that_are_not_selected_are_deleted_at_the_start() {
    let env = Env::new().await;
    env.publish_image(&data(), 86_400);
    // Two images privd imported earlier: a stale one and one recorded but already gone.
    let stale = "a".repeat(64);
    env.h.incus.with(|s| {
        s.images.insert(
            stale.clone(),
            hx_agent::privd::testing::FakeImage {
                aliases: vec![format!("hx-img-old-{}", &stale[..12])],
                size: 1,
                data: vec![0],
            },
        );
    });
    std::fs::write(
        env.h.daemon.cfg.state_dir.join("images-state"),
        serde_json::json!({"highest_manifest_ts": 0, "cached": [
            {"fingerprint": stale, "recipe": "old", "build_id": "20250101.1", "imported_unix": NOW - 100},
            {"fingerprint": "b".repeat(64), "recipe": "old", "build_id": "20250101.2", "imported_unix": NOW - 100},
        ]})
        .to_string(),
    )
    .unwrap();
    // An image the administrator imported themselves is never touched.
    let theirs = "c".repeat(64);
    env.h.incus.with(|s| {
        s.images.insert(
            theirs.clone(),
            hx_agent::privd::testing::FakeImage {
                aliases: vec!["ubuntu/24.04".into()],
                size: 1,
                data: vec![0],
            },
        );
    });
    created(env.create(env.request(ImageMode::Build)).await);
    assert!(env.h.incus.with(|s| !s.images.contains_key(&stale)));
    assert!(env.h.incus.with(|s| s.images.contains_key(&theirs)));
    assert_eq!(images_state(&env)["cached"], serde_json::json!([]));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_image_in_incus_without_our_alias_is_not_deleted_even_if_recorded() {
    let env = Env::new().await;
    env.publish_image(&data(), 86_400);
    let fp = "d".repeat(64);
    env.h.incus.with(|s| {
        s.images.insert(
            fp.clone(),
            hx_agent::privd::testing::FakeImage {
                aliases: vec![],
                size: 1,
                data: vec![0],
            },
        );
    });
    // Recorded under a fingerprint that is not ours to delete: no record, no deletion. (An
    // unrecorded, unaliased image is somebody else's.)
    created(env.create(env.request(ImageMode::Build)).await);
    assert!(env.h.incus.with(|s| s.images.contains_key(&fp)));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_replay_counter_refuses_an_older_list_and_survives_a_restart() {
    let env = Env::new().await;
    let d = data();
    // A list dated NOW + 1000 is accepted online and remembered.
    env.publish(
        vec![entry_for(rid(), &d, "20261120.1", NOW - 10, 1)],
        NOW + 1000,
    );
    env.script(|s| {
        s.image = Some(d.clone());
        s.probe = Some(probe_json(Some(10 << 20), Some(10 << 20)));
    });
    created(env.create(env.request(ImageMode::Auto)).await);
    assert_eq!(images_state(&env)["highest_manifest_ts"], NOW + 1000);
    // An older, validly signed list is refused as unverified (auto builds).
    env.publish(
        vec![entry_for(rid(), &d, "20261120.1", NOW - 10, 1)],
        NOW + 500,
    );
    env.next_hour();
    env.h.incus.with(|s| s.instances.clear());
    let c = created(env.create(env.request(ImageMode::Auto)).await);
    assert_eq!(c.reason_code(), ImageReason::ListUnverified);
    assert!(
        env.h
            .audit
            .lines()
            .iter()
            .any(|l| l.contains("image list not verified"))
    );
    // A restarted privd still knows (it is on disk) and still refuses.
    let d2 = env.daemon_with(|_| {});
    env.next_hour();
    env.h.incus.with(|s| s.instances.clear());
    let r = env
        .create_on(&d2, Role::Admin, env.request(ImageMode::Prebuilt))
        .await;
    assert_eq!(err(&r).detail(), ErrorDetail::Image);
    // The same timestamp again is fine (not older).
    env.publish(
        vec![entry_for(rid(), &d, "20261120.1", NOW - 10, 1)],
        NOW + 1000,
    );
    env.next_hour();
    env.h.incus.with(|s| s.instances.clear());
    let c = created(
        env.create_on(&d2, Role::Admin, env.request(ImageMode::Prebuilt))
            .await,
    );
    assert_eq!(c.path_taken(), PathTaken::Prebuilt);
    // And the counter is persisted only by full acceptance: a refused list never moves it.
    let st = images_state(&env);
    assert_eq!(st["highest_manifest_ts"], NOW + 1000);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_list_does_not_move_the_replay_counter() {
    let env = Env::new().await;
    let d = data();
    let other = Signer::new();
    let m = manifest_json(
        vec![entry_for(rid(), &d, "20261120.1", NOW - 10, 1)],
        NOW + 900,
    );
    let sig = other.sign_manifest(&m, NOW + 900);
    env.script(|s| s.manifest = Some((m, sig)));
    let c = created(env.create(env.request(ImageMode::Auto)).await);
    assert_eq!(c.reason_code(), ImageReason::ListUnverified);
    assert_eq!(
        images_state(&env)["highest_manifest_ts"],
        serde_json::Value::Null
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_gateway_cannot_ask_for_an_offline_image() {
    let env = Env::new().await;
    let mut req = env.request(ImageMode::Prebuilt);
    req.image_file = Some("x.img".into());
    let r = env.create_as(Role::Gateway, req).await;
    env.next_hour();
    // The gateway may not create a desktop outside the setup window either way; the point is that
    // it is refused, never served.
    assert!(matches!(
        err(&r).code(),
        ErrorCode::PermissionDenied | ErrorCode::FailedPrecondition
    ));
    // An offline image with BUILD is contradictory.
    let mut req = env.request(ImageMode::Build);
    req.image_file = Some("x.img".into());
    assert_eq!(
        err(&env.create(req).await).code(),
        ErrorCode::InvalidArgument
    );
    env.next_hour();
    // A path is not a file name, even when the wire validation is bypassed.
    for bad in ["../x", "/var/lib/hx/import/x.img", "a/b", ".x", ""] {
        let mut req = env.request(ImageMode::Prebuilt);
        req.image_file = Some(bad.into());
        assert_eq!(
            err(&env.create(req).await).code(),
            ErrorCode::InvalidArgument,
            "{bad:?}"
        );
        // CreateDesktop is limited to 3 an hour.
        env.next_hour();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelling_during_the_download_stops_the_unit_and_leaves_nothing() {
    let env = Env::new().await;
    let d = data();
    env.publish_image(&d, 86_400);
    // A fetcher that serves the list and the probe, and for the image writes the first chunk
    // and then waits to be stopped.
    let held = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (m, sig) = env.script(|s| s.manifest.clone()).unwrap();
    let probe = env.script(|s| s.probe.clone()).unwrap();
    let held3 = held.clone();
    let d2 = d.clone();
    env.script(|s| {
        s.hook = Some(std::sync::Arc::new(move |job, dir, stop| match job {
            hx_agent::fetcher::ImageJob::Manifest => {
                write_new(dir, "images.json", &m);
                write_new(dir, "images.json.minisig", sig.as_bytes());
                Ok(())
            }
            hx_agent::fetcher::ImageJob::Probe { .. } => {
                write_new(dir, "probe.json", probe.as_bytes());
                Ok(())
            }
            hx_agent::fetcher::ImageJob::Image { .. } => {
                write_new(dir, "c-000000", &d2[..CHUNK as usize]);
                write_new(dir, "r-000000", b"");
                held3.store(true, Ordering::SeqCst);
                while !stop.load(Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err("stopped".into())
            }
        }));
    });
    // Run the request on its own context, so that it can be cancelled from here.
    let ctx_cancel = hx_agent::privd::cancel::CancelToken::new();
    let mut r = hx_agent::privd::testing::request(
        1,
        hx_ipc::privd::pb::request::Command::CreateDesktop(env.request(ImageMode::Prebuilt)),
    );
    r.secret_slots = vec![pb::SecretSlot {
        slot: 0,
        kind: pb::SecretKind::UserPassword as i32,
        length: 32,
        ..Default::default()
    }];
    let mut c = hx_agent::privd::daemon::Ctx::new(Role::Admin);
    c.secrets = vec![Some(hx_ipc::secret::Secret::new(PASSWORD.to_vec()))];
    c.cancel = ctx_cancel.clone();
    let daemon = env.h.daemon.clone();
    let task = tokio::spawn(async move { daemon.handle(r, c).await });
    for _ in 0..400 {
        if held.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(held.load(Ordering::SeqCst), "the download never started");
    ctx_cancel.cancel(hx_agent::privd::cancel::CancelReason::Cancelled);
    let resp = tokio::time::timeout(std::time::Duration::from_secs(20), task)
        .await
        .expect("a cancelled request ends")
        .unwrap();
    assert_eq!(err(&resp).code(), ErrorCode::Cancelled);
    // The unit was stopped, the directories are clean, nothing was imported, no desktop remains.
    assert!(
        env.systemd
            .fetcher
            .stopped()
            .iter()
            .any(|j| j.starts_with("image-")),
        "{:?}",
        env.systemd.fetcher.stopped()
    );
    assert!(
        env.h
            .incus
            .with(|s| s.imports.is_empty() && s.instances.is_empty())
    );
    assert!(!env.h.daemon.read_state(|s| s.desktops.contains_key("main")));
    assert!(staging_is_empty(&env));
}

#[test]
fn the_trusted_comment_rule_and_the_key_rule_of_the_manifest_signature() {
    let signer = Signer::new();
    let other = Signer::new();
    let keys = ImageKeys::from_public_keys(&[&signer.public()]).unwrap();
    let m = b"{\"schema\":1}";
    assert_eq!(
        keys.verify_manifest(m, &signer.sign_manifest(m, 5)),
        Ok(SignedComment {
            arch: arch(),
            timestamp: 5
        })
    );
    assert_eq!(
        keys.verify_manifest(m, &signer.sign_with_comment(m, "hx-release-manifest x")),
        Err(ImageVerifyError::BadComment)
    );
    assert_eq!(
        keys.verify_manifest(m, &signer.sign_with_comment(m, "hx-images-manifest")),
        Err(ImageVerifyError::BadComment),
        "the prefix includes the space"
    );
    assert_eq!(
        keys.verify_manifest(m, &other.sign_manifest(m, 5)),
        Err(ImageVerifyError::SignatureMismatch)
    );
    assert_eq!(
        keys.verify_manifest(b"{\"schema\":2}", &signer.sign_manifest(m, 5)),
        Err(ImageVerifyError::SignatureMismatch),
        "altered data"
    );
    assert_eq!(
        keys.verify_manifest(m, "junk"),
        Err(ImageVerifyError::BadSignatureFile)
    );
    // The comment is the exact form hx-imagectl writes, not just a prefix (I3).
    for bad in [
        "hx-images-manifest schema=1 arch=x86_64 timestamp=5 extra",
        "hx-images-manifest schema=2 arch=x86_64 timestamp=5",
        "hx-images-manifest schema=1 arch=x86_64 timestamp=05",
        "hx-images-manifest schema=1 arch=x86_64 timestamp=-5",
        "hx-images-manifest schema=1 arch=x86_64  timestamp=5",
        "hx-images-manifest schema=1 arch= timestamp=5",
        "hx-images-manifest schema=1 timestamp=5 arch=x86_64",
        "hx-images-manifest anything",
    ] {
        assert_eq!(
            keys.verify_manifest(m, &signer.sign_with_comment(m, bad)),
            Err(ImageVerifyError::BadComment),
            "{bad:?}"
        );
    }
    // Either of two embedded keys (current and next) verifies.
    let both = ImageKeys::from_public_keys(&[&other.public(), &signer.public()]).unwrap();
    assert_eq!(both.len(), 2);
    assert!(both.verify_manifest(m, &signer.sign_manifest(m, 5)).is_ok());
    assert_eq!(
        ImageKeys::none().verify_manifest(m, &signer.sign_manifest(m, 5)),
        Err(ImageVerifyError::NoKeys)
    );
}

#[test]
fn the_signed_comment_is_bound_to_the_manifests_own_timestamp_and_arch() {
    use hx_agent::privd::image::choose::verify_manifest;
    let signer = Signer::new();
    let keys = ImageKeys::from_public_keys(&[&signer.public()]).unwrap();
    let m = manifest_json(vec![], NOW);
    let ok = signer.sign_manifest(&m, NOW);
    assert!(verify_manifest(&keys, &m, &ok, &arch(), NOW).is_ok());
    // A signature (valid, right form) carrying another timestamp is not this manifest's.
    let other_ts = signer.sign_manifest(&m, NOW - 1);
    let e = verify_manifest(&keys, &m, &other_ts, &arch(), NOW).unwrap_err();
    assert!(e.contains("does not match"), "{e}");
    // Nor one carrying another arch.
    let other_arch = signer.sign_with_comment(
        &m,
        &format!("hx-images-manifest schema=1 arch=aarch64 timestamp={NOW}"),
    );
    let e = verify_manifest(&keys, &m, &other_arch, "x86_64", NOW).unwrap_err();
    assert!(e.contains("does not match"), "{e}");
}
