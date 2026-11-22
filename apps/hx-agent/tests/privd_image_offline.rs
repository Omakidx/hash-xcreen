//! The offline `image_file` (docs/ipc.md 6.5): a file name in `/var/lib/hx/import/` with the signed
//! manifest beside it, Admin only, read with `openat2`, verified, no fallback, and consumed after
//! a successful import.

mod privd_image_common;

use std::os::unix::fs::{PermissionsExt, symlink};

use hx_ipc::privd::pb::{ErrorCode, ErrorDetail, ImageMode, ImageReason, PathTaken, Role};
use privd_image_common::*;

const NAME: &str = "hx-image-ubuntu-24.04-xfce-basic-20261120.1.img";

fn data() -> Vec<u8> {
    image_bytes(150 * 1024 + 5, 3)
}

fn request(env: &Env, name: &str) -> hx_ipc::privd::pb::CreateDesktopRequest {
    let mut r = env.request(ImageMode::Prebuilt);
    r.image_file = Some(name.into());
    r
}

fn good(env: &Env, age: u64) -> (Vec<u8>, hx_provision::images::ImageEntry) {
    let d = data();
    let e = entry_for(rid(), &d, "20261120.1", NOW - age, 1);
    let m = manifest_json(vec![e.clone()], NOW);
    let sig = env.signer.sign_manifest(&m, NOW);
    place_offline(&env.import_dir(), NAME, &d, &m, &sig);
    (d, e)
}

fn manifest_path(env: &Env) -> std::path::PathBuf {
    env.import_dir()
        .join(hx_provision::images::manifest_file_name(&arch()))
}

fn import_names(env: &Env) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(env.import_dir())
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

async fn refused(env: &Env, what: &str) {
    let e = err(&env.create(request(env, NAME)).await);
    assert_eq!(
        (e.code(), e.detail()),
        (ErrorCode::FailedPrecondition, ErrorDetail::Image),
        "{what}: {}",
        e.message
    );
    // Nothing was imported or created, no fetcher ran (offline is never online), and no fallback
    // happened.
    assert!(
        env.h
            .incus
            .with(|s| s.imports.is_empty() && s.instances.is_empty()),
        "{what}"
    );
    assert!(env.systemd.fetcher.started().is_empty(), "{what}");
    assert!(
        !env.h.daemon.read_state(|s| s.desktops.contains_key("main")),
        "{what}"
    );
    env.next_hour();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_good_offline_image_installs_and_its_three_files_are_consumed() {
    let env = Env::new().await;
    let (d, e) = good(&env, 3 * 86_400);
    // The online replay counter is ahead of this list: offline neither checks nor updates it.
    std::fs::write(
        env.h.daemon.cfg.state_dir.join("images-state"),
        br#"{"highest_manifest_ts": 1900000000, "cached": []}"#,
    )
    .unwrap();
    let c = created(env.create(request(&env, NAME)).await);
    assert_eq!(c.path_taken(), PathTaken::Prebuilt);
    assert_eq!(c.reason_code(), ImageReason::ImageFile);
    assert!(
        c.reason.contains("20261120.1") && c.reason.contains("offline"),
        "{}",
        c.reason
    );
    assert_eq!(c.image.unwrap().size, d.len() as u64);
    assert_eq!(
        env.h.incus.with(|s| s.imports.clone()),
        [(e.sha256.clone(), d.len() as u64)]
    );
    assert!(import_names(&env).is_empty(), "{:?}", import_names(&env));
    assert!(
        env.systemd.fetcher.started().is_empty(),
        "no fetcher job offline"
    );
    assert!(
        env.h.incus.with(|s| s.images.is_empty()),
        "deleted once ready"
    );
    let st: serde_json::Value = serde_json::from_slice(
        &std::fs::read(env.h.daemon.cfg.state_dir.join("images-state")).unwrap(),
    )
    .unwrap();
    assert_eq!(st["highest_manifest_ts"], 1_900_000_000u64);
    assert_eq!(st["cached"], serde_json::json!([]));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_old_offline_image_is_accepted_with_a_warning() {
    let env = Env::new().await;
    good(&env, 40 * 86_400);
    let c = created(env.create(request(&env, NAME)).await);
    assert_eq!(c.path_taken(), PathTaken::Prebuilt);
    assert!(
        c.warnings.iter().any(|w| w.contains("40 days old")),
        "{:?}",
        c.warnings
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_flipped_byte_in_the_image_or_the_manifest_is_refused() {
    let env = Env::new().await;
    good(&env, 86_400);
    let mut bytes = std::fs::read(env.import_dir().join(NAME)).unwrap();
    bytes[1000] ^= 1;
    std::fs::write(env.import_dir().join(NAME), bytes).unwrap();
    refused(&env, "image").await;
    // Nothing is consumed on a refusal.
    assert_eq!(import_names(&env).len(), 3);

    let env = Env::new().await;
    good(&env, 86_400);
    let mut m = std::fs::read(manifest_path(&env)).unwrap();
    let i = m.len() / 2;
    m[i] ^= 1;
    std::fs::write(manifest_path(&env), m).unwrap();
    refused(&env, "manifest").await;

    // The signature file.
    let env = Env::new().await;
    good(&env, 86_400);
    let sigp = format!("{}.minisig", manifest_path(&env).display());
    let mut sig = std::fs::read(&sigp).unwrap();
    let i = sig.len() / 2;
    sig[i] ^= 1;
    std::fs::write(&sigp, sig).unwrap();
    refused(&env, "signature").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_manifest_signed_by_another_key_or_with_another_comment_is_refused() {
    let env = Env::new().await;
    let d = data();
    let e = entry_for(rid(), &d, "20261120.1", NOW - 5, 1);
    let m = manifest_json(vec![e.clone()], NOW);
    place_offline(
        &env.import_dir(),
        NAME,
        &d,
        &m,
        &Signer::new().sign_manifest(&m, NOW),
    );
    refused(&env, "other key").await;

    let env = Env::new().await;
    let sig = env
        .signer
        .sign_with_comment(&m, "hx-release-manifest schema=1");
    place_offline(&env.import_dir(), NAME, &d, &m, &sig);
    refused(&env, "other comment").await;

    // No key embedded: nothing offline is accepted either.
    let env = Env::new().await;
    good(&env, 86_400);
    env.no_keys();
    refused(&env, "no key").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_entry_must_match_the_recipe_the_digest_the_size_and_the_clock() {
    // Another recipe digest.
    let env = Env::new().await;
    let d = data();
    let mut e = entry_for(rid(), &d, "20261120.1", NOW - 5, 1);
    e.recipe_digest = "1".repeat(64);
    let m = manifest_json(vec![e], NOW);
    place_offline(
        &env.import_dir(),
        NAME,
        &d,
        &m,
        &env.signer.sign_manifest(&m, NOW),
    );
    refused(&env, "digest").await;
    // The file is longer or shorter than the signed size.
    for delta in [1i64, -1] {
        let env = Env::new().await;
        let (mut d2, _) = good(&env, 86_400);
        if delta > 0 {
            d2.push(0);
        } else {
            d2.pop();
        }
        std::fs::write(env.import_dir().join(NAME), &d2).unwrap();
        refused(&env, "size").await;
    }
    // A manifest dated more than a day ahead of the clock.
    let env = Env::new().await;
    let e = entry_for(rid(), &d, "20261120.1", NOW - 5, 1);
    let m = manifest_json(vec![e], NOW + 2 * 86_400);
    place_offline(
        &env.import_dir(),
        NAME,
        &d,
        &m,
        &env.signer.sign_manifest(&m, NOW + 2 * 86_400),
    );
    refused(&env, "future").await;
    // The image file is missing.
    let env = Env::new().await;
    good(&env, 86_400);
    std::fs::remove_file(env.import_dir().join(NAME)).unwrap();
    refused(&env, "missing image").await;
    // The manifest is missing.
    let env = Env::new().await;
    good(&env, 86_400);
    std::fs::remove_file(manifest_path(&env)).unwrap();
    refused(&env, "missing manifest").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn symlinks_and_hard_links_are_refused() {
    // The image is a symlink to a file of the right content outside the directory.
    let env = Env::new().await;
    good(&env, 86_400);
    let outside = env.h.dir.path().join("outside.img");
    std::fs::rename(env.import_dir().join(NAME), &outside).unwrap();
    symlink(&outside, env.import_dir().join(NAME)).unwrap();
    refused(&env, "symlinked image").await;
    assert!(outside.exists(), "the target is untouched");

    // A hard link: the file is also named elsewhere.
    let env = Env::new().await;
    good(&env, 86_400);
    std::fs::hard_link(
        env.import_dir().join(NAME),
        env.h.dir.path().join("other-name"),
    )
    .unwrap();
    refused(&env, "hard-linked image").await;

    // The manifest is a symlink, or a hard link.
    let env = Env::new().await;
    good(&env, 86_400);
    let outside = env.h.dir.path().join("m.json");
    std::fs::rename(manifest_path(&env), &outside).unwrap();
    symlink(&outside, manifest_path(&env)).unwrap();
    refused(&env, "symlinked manifest").await;
    let env = Env::new().await;
    good(&env, 86_400);
    std::fs::hard_link(manifest_path(&env), env.h.dir.path().join("m2.json")).unwrap();
    refused(&env, "hard-linked manifest").await;

    // The image is a fifo (an `O_NONBLOCK` open does not hang) or a directory.
    let env = Env::new().await;
    good(&env, 86_400);
    std::fs::remove_file(env.import_dir().join(NAME)).unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        env.import_dir().join(NAME),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(20), refused(&env, "fifo"))
        .await
        .expect("no hang on a fifo");
    let env = Env::new().await;
    good(&env, 86_400);
    std::fs::remove_file(env.import_dir().join(NAME)).unwrap();
    std::fs::create_dir(env.import_dir().join(NAME)).unwrap();
    refused(&env, "directory").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_import_directory_itself_must_be_a_private_real_directory() {
    // Missing.
    let env = Env::new().await;
    refused(&env, "no directory").await;
    // Open to others.
    let env = Env::new().await;
    good(&env, 86_400);
    std::fs::set_permissions(env.import_dir(), std::fs::Permissions::from_mode(0o755)).unwrap();
    refused(&env, "mode 0755").await;
    // A symlink to a directory.
    let env = Env::new().await;
    good(&env, 86_400);
    let real = env.h.dir.path().join("real-import");
    std::fs::rename(env.import_dir(), &real).unwrap();
    symlink(&real, env.import_dir()).unwrap();
    refused(&env, "symlinked directory").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_gateway_never_gets_an_offline_install() {
    let env = Env::new().await;
    good(&env, 86_400);
    let r = env.create_as(Role::Gateway, request(&env, NAME)).await;
    assert!(matches!(
        err(&r).code(),
        ErrorCode::PermissionDenied | ErrorCode::FailedPrecondition
    ));
    assert!(env.h.incus.with(|s| s.imports.is_empty()));
    assert_eq!(import_names(&env).len(), 3);
}
