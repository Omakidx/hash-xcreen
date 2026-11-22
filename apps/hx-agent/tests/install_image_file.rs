//! `hx-agent install --image-file` (design 1D, C10): the offline prebuilt image. Preflight
//! verifies the signed manifest, the entry, the size and the SHA-256 with privd's own code (exit
//! 10 on a failure, exit 9 for an unusable file or too little disk); stage `desktop` copies the
//! three files into `/var/lib/hx/import/` and asks privd for `PREBUILT` with the file's name.
//! Everything runs against the fake machine of `install::testing`: no real program, no real host.

mod install_engine_common;

use std::io::Cursor;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use hx_agent::install::paths;
use hx_agent::install::testing::Machine;
use hx_agent::privd::image::ImageKeys;
use hx_agent::privd::update::verify::sha256_hex;
use hx_ipc::privd::pb;
use hx_provision::images::{
    FORMAT_UNIFIED, ImageEntry, ImagesManifest, KIND, Part, SCHEMA, file_name, manifest_file_name,
    recipe_by_name,
};
use hx_provision::{Catalog, RecipeId};
use install_engine_common::*;

const ENTRY_TIME: u64 = NOW - 86_400;

fn rid(name: &str) -> RecipeId {
    recipe_by_name(name).unwrap()
}

fn digest_of(id: RecipeId) -> String {
    Catalog::embedded().resolve(id, &[]).unwrap().build_digest()
}

fn image_bytes(n: usize) -> Vec<u8> {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

struct Signer(minisign::KeyPair);

impl Signer {
    fn new() -> Self {
        Self(minisign::KeyPair::generate_unencrypted_keypair().unwrap())
    }
    fn public(&self) -> String {
        self.0.pk.to_base64()
    }
    fn sign(&self, data: &[u8], comment: &str) -> String {
        minisign::sign(
            Some(&self.0.pk),
            &self.0.sk,
            Cursor::new(data),
            Some(comment),
            None,
        )
        .unwrap()
        .into_string()
    }
}

/// The exact trusted comment hx-imagectl writes, bound to the manifest's own timestamp (privd
/// refuses a comment whose arch or timestamp differs from the manifest's).
fn comment_for(timestamp: u64) -> String {
    format!("hx-images-manifest schema=1 arch=x86_64 timestamp={timestamp}")
}

/// An image, its signed manifest and the signature, in a directory of their own.
struct Fixture {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    name: String,
    image: Vec<u8>,
    manifest: Vec<u8>,
    sig: String,
    signer: Signer,
}

impl Fixture {
    fn new() -> Self {
        Self::with(|_| {}, |_| {})
    }

    /// `edit_entry` changes the entry before it is signed, `edit_sig` the signing.
    fn with(edit_entry: impl FnOnce(&mut ImageEntry), edit_sig: impl FnOnce(&mut Self)) -> Self {
        let id = rid("ubuntu-24.04-xfce-basic");
        let image = image_bytes(300 * 1024);
        let build_id = "20261122.1";
        let mut entry = ImageEntry {
            recipe: "ubuntu-24.04-xfce-basic".into(),
            distro: "ubuntu-24.04".into(),
            desktop: "xfce".into(),
            preset: "basic".into(),
            recipe_digest: digest_of(id),
            build_id: build_id.into(),
            created: ENTRY_TIME,
            min_agent: VERSION.into(),
            format: FORMAT_UNIFIED.into(),
            compression: "zstd".into(),
            base_alias: "ubuntu/24.04".into(),
            file: file_name(id, build_id),
            size: image.len() as u64,
            sha256: sha256_hex(&image),
            unpacked_size: 3 << 30,
            parts: vec![Part {
                size: image.len() as u64,
                sha256: sha256_hex(&image),
            }],
        };
        edit_entry(&mut entry);
        let name = entry.file.clone();
        let manifest = ImagesManifest {
            schema: SCHEMA,
            kind: KIND.into(),
            arch: "x86_64".into(),
            timestamp: NOW - 3600,
            images: vec![entry],
        }
        .to_json()
        .unwrap()
        .into_bytes();
        let signer = Signer::new();
        let sig = signer.sign(&manifest, &comment_for(NOW - 3600));
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let mut f = Self {
            _tmp: tmp,
            dir,
            name,
            image,
            manifest,
            sig,
            signer,
        };
        edit_sig(&mut f);
        f.write();
        f
    }

    fn write(&self) {
        std::fs::write(self.dir.join(&self.name), &self.image).unwrap();
        std::fs::write(self.dir.join(manifest_file_name("x86_64")), &self.manifest).unwrap();
        std::fs::write(
            self.dir
                .join(format!("{}.minisig", manifest_file_name("x86_64"))),
            &self.sig,
        )
        .unwrap();
    }

    fn image_path(&self) -> String {
        self.dir.join(&self.name).to_string_lossy().into_owned()
    }

    fn trust(&self, m: &mut Machine) {
        m.image_keys = ImageKeys::from_public_keys(&[&self.signer.public()]).unwrap();
    }
}

fn machine() -> (Machine, PathBuf) {
    let mut m = Machine::new();
    let dir = release(&mut m, &Tamper::default());
    (m, dir)
}

fn prebuilt_result() -> pb::CreateDesktopResult {
    pb::CreateDesktopResult {
        path_taken: pb::PathTaken::Prebuilt as i32,
        reason: "prebuilt image 20261122.1 (1 days old) from the offline file".into(),
        reason_code: pb::ImageReason::ImageFile as i32,
        image: Some(pb::ImageInfo {
            build_id: "20261122.1".into(),
            created_unix: ENTRY_TIME,
            size: 307_200,
            release_bps: 0,
            mirror_bps: 0,
        }),
        ..Default::default()
    }
}

fn install_with(m: &mut Machine, dir: &Path, extra: &[(&'static str, &str)]) -> u8 {
    m.install(ssh_args(dir, extra, &[]), Some(frames(None, None)))
}

fn import_dir(m: &Machine) -> PathBuf {
    path(m, paths::IMPORT_DIR)
}

fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// A failed run changed nothing: no state, no mutating tool, no daemon call, no import directory.
fn assert_untouched(m: &Machine) {
    assert!(m.state().is_none(), "no state");
    assert_eq!(m.runner.mutating(), Vec::<String>::new());
    assert_eq!(m.daemons.count("create_desktop"), 0);
    assert!(!exists(m, paths::IMPORT_DIR), "no import directory");
}

// ----- the good path --------------------------------------------------------------------------

#[test]
fn an_image_file_is_copied_into_the_import_directory_and_privd_gets_prebuilt_and_the_name() {
    let f = Fixture::new();
    let (mut m, dir) = machine();
    f.trust(&mut m);
    m.daemons.create_result = Some(prebuilt_result());
    let code = install_with(&mut m, &dir, &[("--image-file", &f.image_path())]);
    assert_eq!(code, 0, "{}", String::from_utf8_lossy(&m.err));

    let req = &m.daemons.create_requests[0];
    assert_eq!(req.image_mode, pb::ImageMode::Prebuilt as i32);
    assert_eq!(req.image_file.as_deref(), Some(f.name.as_str()));
    assert_eq!(m.state().unwrap().options.image, "prebuilt");

    // The three files, byte for byte, root-only, and nothing else (no temporary left behind).
    let imp = import_dir(&m);
    let mut want = vec![
        f.name.clone(),
        manifest_file_name("x86_64"),
        format!("{}.minisig", manifest_file_name("x86_64")),
    ];
    want.sort();
    assert_eq!(names(&imp), want);
    assert_eq!(std::fs::read(imp.join(&f.name)).unwrap(), f.image);
    assert_eq!(
        std::fs::read(imp.join(manifest_file_name("x86_64"))).unwrap(),
        f.manifest
    );
    assert_eq!(
        std::fs::read_to_string(imp.join(format!("{}.minisig", manifest_file_name("x86_64"))))
            .unwrap(),
        f.sig
    );
    for n in &want {
        let md = std::fs::metadata(imp.join(n)).unwrap();
        assert_eq!(md.permissions().mode() & 0o777, 0o600, "{n}");
        assert_eq!(std::os::unix::fs::MetadataExt::nlink(&md), 1, "{n}");
    }
    assert_eq!(
        std::fs::metadata(&imp).unwrap().permissions().mode() & 0o777,
        0o700
    );
    // The source files stay where they were: the copy is not a move.
    assert!(f.dir.join(&f.name).exists());

    // The result line.
    let d = m.result()["desktop"].clone();
    assert_eq!(d["path_taken"], "PREBUILT");
    assert_eq!(d["reason_code"], "image_file");
    assert_eq!(d["image"]["build_id"], "20261122.1");
    assert_eq!(d["image"]["created_unix"], ENTRY_TIME);
    assert_eq!(d["image"]["size"], 307_200);
    assert_eq!(d["image"]["release_bps"], 0);
    // ... and it is kept in the state for a resumed run.
    let st = m.state().unwrap();
    let rep = st.desktop.unwrap();
    assert_eq!(rep.reason_code, "image_file");
    assert_eq!(rep.image.unwrap().build_id, "20261122.1");
}

#[test]
fn the_image_file_name_is_not_tied_to_the_entry_and_a_rerun_after_success_does_not_copy_again() {
    let f = Fixture::new();
    // Renamed: privd matches by recipe and digest and hashes the bytes, not by name.
    std::fs::rename(f.dir.join(&f.name), f.dir.join("my-image.img")).unwrap();
    let (mut m, dir) = machine();
    f.trust(&mut m);
    m.daemons.create_result = Some(prebuilt_result());
    let p = f.dir.join("my-image.img").to_string_lossy().into_owned();
    assert_eq!(install_with(&mut m, &dir, &[("--image-file", &p)]), 0);
    assert_eq!(
        m.daemons.create_requests[0].image_file.as_deref(),
        Some("my-image.img")
    );
    // privd consumed the files; a second run finds the desktop and does not copy or call again.
    for n in names(&import_dir(&m)) {
        std::fs::remove_file(import_dir(&m).join(n)).unwrap();
    }
    let mut a = ssh_args(
        std::path::Path::new("/nonexistent"),
        &[("--image-file", &p)],
        &[],
    );
    a.bootstrap_dir = None;
    assert_eq!(m.install(a, Some(frames(None, None))), 0);
    assert_eq!(m.daemons.count("create_desktop"), 1);
    assert_eq!(names(&import_dir(&m)), Vec::<String>::new());
}

#[test]
fn a_retry_replaces_files_a_failed_attempt_left_in_the_import_directory() {
    let f = Fixture::new();
    let (mut m, dir) = machine();
    f.trust(&mut m);
    m.daemons.create_result = Some(prebuilt_result());
    m.daemons.fail.insert(
        "create_desktop",
        hx_agent::install::error::InstallError::unavailable("privd went away"),
    );
    assert_eq!(
        install_with(&mut m, &dir, &[("--image-file", &f.image_path())]),
        3
    );
    // privd keeps the files after a failed import: they are still there, stale ones included.
    let imp = import_dir(&m);
    std::fs::write(imp.join(&f.name), b"stale").unwrap();
    assert_eq!(
        install_with(&mut m, &dir, &[("--image-file", &f.image_path())]),
        0,
        "{}",
        String::from_utf8_lossy(&m.err)
    );
    assert_eq!(std::fs::read(imp.join(&f.name)).unwrap(), f.image);
    assert_eq!(names(&imp).len(), 3, "{:?}", names(&imp));
}

// ----- usage ---------------------------------------------------------------------------------

#[test]
fn an_image_file_with_image_build_is_exit_2_and_changes_nothing() {
    let f = Fixture::new();
    let (mut m, dir) = machine();
    f.trust(&mut m);
    let code = install_with(
        &mut m,
        &dir,
        &[("--image-file", &f.image_path()), ("--image", "build")],
    );
    assert_eq!(code, 2);
    assert_eq!(m.result()["code"], "USAGE");
    assert!(
        m.result()["message"]
            .as_str()
            .unwrap()
            .contains("--image build")
    );
    assert_untouched(&m);
}

#[test]
fn a_relative_path_or_a_bad_file_name_is_exit_2() {
    for p in ["image.img", "/tmp/.hidden", "/tmp/dir/", "/tmp/a b.img"] {
        let (mut m, dir) = machine();
        assert_eq!(install_with(&mut m, &dir, &[("--image-file", p)]), 2, "{p}");
        assert_untouched(&m);
    }
}

#[test]
fn image_file_with_prebuilt_or_auto_is_the_same_as_alone() {
    for img in ["prebuilt", "auto"] {
        let f = Fixture::new();
        let (mut m, dir) = machine();
        f.trust(&mut m);
        m.daemons.create_result = Some(prebuilt_result());
        assert_eq!(
            install_with(
                &mut m,
                &dir,
                &[("--image-file", &f.image_path()), ("--image", img)]
            ),
            0,
            "{img}"
        );
        assert_eq!(
            m.daemons.create_requests[0].image_mode,
            pb::ImageMode::Prebuilt as i32,
            "{img}"
        );
    }
}

// ----- verification: exit 10 and nothing changed ----------------------------------------------

fn assert_verify_failure(m: &Machine, code: u8, what: &str) {
    assert_eq!(code, 10, "{what}: {}", String::from_utf8_lossy(&m.err));
    let r = m.result();
    assert_eq!(r["code"], "VERIFY", "{what}");
    assert_eq!(r["exit"], 10, "{what}");
    assert_untouched(m);
}

#[test]
fn one_flipped_manifest_byte_is_exit_10_and_nothing_changes() {
    let mut f = Fixture::new();
    let (mut m, dir) = machine();
    f.trust(&mut m);
    // Flip one byte inside the JSON text (a digit of the timestamp keeps it parseable: only the
    // signature can catch it).
    let at = f.manifest.iter().position(|b| *b == b'1').unwrap();
    f.manifest[at] ^= 0x01;
    f.write();
    let code = install_with(&mut m, &dir, &[("--image-file", &f.image_path())]);
    assert_verify_failure(&m, code, "flipped manifest byte");
}

#[test]
fn a_manifest_signed_by_another_key_is_exit_10() {
    let f = Fixture::new();
    let (mut m, dir) = machine();
    m.image_keys = ImageKeys::from_public_keys(&[&Signer::new().public()]).unwrap();
    let code = install_with(&mut m, &dir, &[("--image-file", &f.image_path())]);
    assert_verify_failure(&m, code, "wrong signer");
}

#[test]
fn a_signature_with_another_trusted_comment_is_exit_10() {
    let f = Fixture::with(
        |_| {},
        |f| {
            f.sig = f
                .signer
                .sign(&f.manifest, "hx-release-manifest channel=stable")
        },
    );
    let (mut m, dir) = machine();
    f.trust(&mut m);
    let code = install_with(&mut m, &dir, &[("--image-file", &f.image_path())]);
    assert_verify_failure(&m, code, "wrong trusted comment");
}

#[test]
fn a_build_without_an_image_key_cannot_verify_anything_and_is_exit_10() {
    let f = Fixture::new();
    let (mut m, dir) = machine();
    m.image_keys = ImageKeys::none();
    let code = install_with(&mut m, &dir, &[("--image-file", &f.image_path())]);
    assert_verify_failure(&m, code, "no image key");
    assert!(
        m.result()["message"]
            .as_str()
            .unwrap()
            .contains("no image signing key")
    );
}

#[test]
fn an_image_that_differs_from_its_signed_digest_or_size_is_exit_10() {
    // Same size, one byte flipped.
    let mut f = Fixture::new();
    let (mut m, dir) = machine();
    f.trust(&mut m);
    f.image[1000] ^= 0xff;
    f.write();
    let code = install_with(&mut m, &dir, &[("--image-file", &f.image_path())]);
    assert_verify_failure(&m, code, "flipped image byte");
    assert!(m.result()["message"].as_str().unwrap().contains("SHA-256"));
    // Shorter.
    let mut f = Fixture::new();
    let (mut m, dir) = machine();
    f.trust(&mut m);
    f.image.truncate(f.image.len() - 1);
    f.write();
    let code = install_with(&mut m, &dir, &[("--image-file", &f.image_path())]);
    assert_verify_failure(&m, code, "truncated image");
}

#[test]
fn an_entry_for_another_recipe_digest_or_a_newer_agent_matches_nothing_and_is_exit_10() {
    for (what, edit) in [
        (
            "digest",
            Box::new(|e: &mut ImageEntry| e.recipe_digest = "0".repeat(64))
                as Box<dyn FnOnce(&mut ImageEntry)>,
        ),
        (
            "min_agent",
            Box::new(|e: &mut ImageEntry| e.min_agent = "99.0.0".into()),
        ),
    ] {
        let f = Fixture::with(edit, |_| {});
        let (mut m, dir) = machine();
        f.trust(&mut m);
        let code = install_with(&mut m, &dir, &[("--image-file", &f.image_path())]);
        assert_verify_failure(&m, code, what);
        assert!(
            m.result()["message"].as_str().unwrap().contains("no entry"),
            "{what}"
        );
    }
}

#[test]
fn an_entry_for_a_different_distro_than_asked_is_exit_10() {
    let f = Fixture::new();
    let (mut m, dir) = machine();
    f.trust(&mut m);
    let code = install_with(
        &mut m,
        &dir,
        &[("--image-file", &f.image_path()), ("--distro", "debian-13")],
    );
    assert_verify_failure(&m, code, "other distro");
}

#[test]
fn an_old_entry_is_accepted_with_a_warning_and_a_future_manifest_is_refused() {
    let f = Fixture::with(|e| e.created = NOW - 40 * 86_400, |_| {});
    let (mut m, dir) = machine();
    f.trust(&mut m);
    m.daemons.create_result = Some(prebuilt_result());
    assert_eq!(
        install_with(&mut m, &dir, &[("--image-file", &f.image_path())]),
        0
    );
    assert!(m.json_lines().iter().any(|v| v["t"] == "warn"
        && v["id"] == "preflight"
        && v["message"].as_str().unwrap().contains("40 days old")));
    // A manifest signed more than 24 hours ahead of the clock.
    let mut f = Fixture::new();
    let mut parsed: ImagesManifest = serde_json::from_slice(&f.manifest).unwrap();
    parsed.timestamp = NOW + 3 * 86_400;
    parsed.images[0].created = NOW - 1000;
    f.manifest = parsed.to_json().unwrap().into_bytes();
    f.sig = f.signer.sign(&f.manifest, &comment_for(parsed.timestamp));
    f.write();
    let (mut m, dir) = machine();
    f.trust(&mut m);
    let code = install_with(&mut m, &dir, &[("--image-file", &f.image_path())]);
    assert_verify_failure(&m, code, "future manifest");
}

// ----- an unusable file or too little disk: exit 9 --------------------------------------------

fn assert_preflight_failure(m: &Machine, code: u8, what: &str) -> String {
    assert_eq!(code, 9, "{what}: {}", String::from_utf8_lossy(&m.err));
    let r = m.result();
    assert_eq!(r["code"], "PREFLIGHT", "{what}");
    assert_untouched(m);
    r["message"].as_str().unwrap().to_owned()
}

#[test]
fn a_missing_manifest_or_signature_or_image_is_exit_9() {
    for gone in ["manifest", "sig", "image"] {
        let f = Fixture::new();
        let (mut m, dir) = machine();
        f.trust(&mut m);
        let victim = match gone {
            "manifest" => f.dir.join(manifest_file_name("x86_64")),
            "sig" => f
                .dir
                .join(format!("{}.minisig", manifest_file_name("x86_64"))),
            _ => f.dir.join(&f.name),
        };
        std::fs::remove_file(victim).unwrap();
        let code = install_with(&mut m, &dir, &[("--image-file", &f.image_path())]);
        let msg = assert_preflight_failure(&m, code, gone);
        assert!(msg.contains("does not exist"), "{gone}: {msg}");
    }
}

#[test]
fn a_symlink_a_directory_and_a_fifo_are_not_images_exit_9() {
    // Symlink (O_NOFOLLOW).
    let f = Fixture::new();
    let (mut m, dir) = machine();
    f.trust(&mut m);
    let real = f.dir.join("real.img");
    std::fs::rename(f.dir.join(&f.name), &real).unwrap();
    std::os::unix::fs::symlink(&real, f.dir.join(&f.name)).unwrap();
    let code = install_with(&mut m, &dir, &[("--image-file", &f.image_path())]);
    let msg = assert_preflight_failure(&m, code, "symlink");
    assert!(msg.contains("symbolic link"), "{msg}");
    // Directory.
    let f = Fixture::new();
    let (mut m, dir) = machine();
    f.trust(&mut m);
    std::fs::remove_file(f.dir.join(&f.name)).unwrap();
    std::fs::create_dir(f.dir.join(&f.name)).unwrap();
    let code = install_with(&mut m, &dir, &[("--image-file", &f.image_path())]);
    let msg = assert_preflight_failure(&m, code, "directory");
    assert!(msg.contains("not a regular file"), "{msg}");
    // FIFO: opening it must not block (O_NONBLOCK) and it is refused.
    let f = Fixture::new();
    let (mut m, dir) = machine();
    f.trust(&mut m);
    std::fs::remove_file(f.dir.join(&f.name)).unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        f.dir.join(&f.name),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    let code = install_with(&mut m, &dir, &[("--image-file", &f.image_path())]);
    let msg = assert_preflight_failure(&m, code, "fifo");
    assert!(msg.contains("not a regular file"), "{msg}");
}

#[test]
fn an_image_over_4_gib_is_exit_9_without_reading_it() {
    let f = Fixture::new();
    let (mut m, dir) = machine();
    f.trust(&mut m);
    let big = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(f.dir.join(&f.name))
        .unwrap();
    big.set_len((4u64 << 30) + 1).unwrap(); // sparse
    drop(big);
    let code = install_with(&mut m, &dir, &[("--image-file", &f.image_path())]);
    let msg = assert_preflight_failure(&m, code, "too big");
    assert!(msg.contains("larger than 4 GiB"), "{msg}");
}

#[test]
fn too_little_free_space_for_three_copies_is_exit_9() {
    let f = Fixture::new();
    let (mut m, dir) = machine();
    f.trust(&mut m);
    // The image needs 3 x 300 KiB + 2 GiB = 3 GiB (rounded up) free on /var/lib. With a whole
    // device for the pool the 30 GiB check of the host does not apply, so only the free space
    // of 1 GiB (everywhere on the fake host) is short.
    m.probe.free_gib = 1;
    m.probe.blocks.insert(
        "/dev/vdb".into(),
        hx_agent::install::probe::BlockInfo {
            is_block: true,
            size_gib: 100,
            whole_disk: true,
            mounted: false,
            signature: false,
        },
    );
    let code = install_with(
        &mut m,
        &dir,
        &[
            ("--image-file", &f.image_path()),
            ("--storage-device", "/dev/vdb"),
        ],
    );
    let msg = assert_preflight_failure(&m, code, "disk");
    assert!(
        msg.contains("1 GiB free on /var/lib; the image file needs 3 GiB"),
        "{msg}"
    );
}

// ----- the import directory -------------------------------------------------------------------

#[test]
fn an_import_directory_open_to_others_is_refused_and_nothing_is_copied() {
    let f = Fixture::new();
    let (mut m, dir) = machine();
    f.trust(&mut m);
    m.daemons.create_result = Some(prebuilt_result());
    let imp = import_dir(&m);
    std::fs::create_dir_all(&imp).unwrap();
    std::fs::set_permissions(&imp, std::fs::Permissions::from_mode(0o755)).unwrap();
    let code = install_with(&mut m, &dir, &[("--image-file", &f.image_path())]);
    assert_eq!(code, 1, "{}", String::from_utf8_lossy(&m.err));
    assert_eq!(m.result()["stage"], "desktop");
    assert!(
        m.result()["message"]
            .as_str()
            .unwrap()
            .contains("mode 0700")
    );
    assert_eq!(names(&imp), Vec::<String>::new());
    assert_eq!(m.daemons.count("create_desktop"), 0);
}

#[test]
fn an_import_directory_that_is_a_symlink_is_refused() {
    let f = Fixture::new();
    let (mut m, dir) = machine();
    f.trust(&mut m);
    let elsewhere = tempfile::tempdir().unwrap();
    let imp = import_dir(&m);
    std::fs::create_dir_all(imp.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(elsewhere.path(), &imp).unwrap();
    let code = install_with(&mut m, &dir, &[("--image-file", &f.image_path())]);
    assert_eq!(code, 1, "{}", String::from_utf8_lossy(&m.err));
    assert_eq!(names(elsewhere.path()), Vec::<String>::new());
    assert_eq!(m.daemons.count("create_desktop"), 0);
}

// ----- other modes ----------------------------------------------------------------------------

#[test]
fn the_image_file_of_a_mode_that_builds_no_desktop_is_not_looked_at() {
    // `--pair` / `--token` build no desktop; the image file is not read (it need not even exist).
    let (mut m, dir) = machine();
    let args = hx_agent::install::InstallArgs {
        mode: Some(hx_agent::install::options::Mode::Token),
        raw: raw(&[("--image-file", "/does/not/exist.img")], &[]),
        bootstrap_dir: Some(dir.to_string_lossy().into_owned()),
        ..hx_agent::install::InstallArgs::default()
    };
    let code = m.install(args, Some(frames(Some(&token_text()), None)));
    assert_ne!(code, 9, "{}", String::from_utf8_lossy(&m.err));
    assert_ne!(code, 10);
    assert_eq!(m.daemons.count("create_desktop"), 0);
}
