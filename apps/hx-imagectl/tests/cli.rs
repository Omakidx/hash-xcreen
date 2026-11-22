//! The `hx-imagectl` binary end to end where no Incus is needed: argument errors, `digest`,
//! the manifest build and verify round trip with a test key made here, and the exit codes of
//! `compare` and `verify`.

use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use hx_provision::images::{self, FORMAT_UNIFIED, ImageEntry, ImagesManifest, Part};
use sha2::{Digest, Sha256};

const NOW: u64 = 1_795_000_000;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hx-imagectl"))
}

fn run(args: &[&str]) -> Output {
    bin().args(args).output().expect("run hx-imagectl")
}

fn code(o: &Output) -> i32 {
    o.status.code().expect("exit code")
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A cell directory: a small "image" file and the entry.json that describes it.
fn cell(dir: &Path, recipe: &str, build_id: &str, digest: &str, created: u64) -> PathBuf {
    let id = images::recipe_by_name(recipe).unwrap();
    let d = dir.join(format!("{recipe}-{build_id}"));
    fs::create_dir_all(&d).unwrap();
    let file = images::file_name(id, build_id);
    let data = format!("not really an image: {recipe} {build_id}").into_bytes();
    fs::write(d.join(&file), &data).unwrap();
    let sha = hex(&Sha256::digest(&data));
    let entry = ImageEntry {
        recipe: recipe.into(),
        distro: id.distro.as_str().into(),
        desktop: id.desktop.as_str().into(),
        preset: id.preset.as_str().into(),
        recipe_digest: digest.into(),
        build_id: build_id.into(),
        created,
        min_agent: "0.1.0".into(),
        format: FORMAT_UNIFIED.into(),
        compression: "zstd".into(),
        base_alias: "ubuntu/24.04".into(),
        file,
        size: data.len() as u64,
        sha256: sha.clone(),
        unpacked_size: data.len() as u64 * 4,
        parts: vec![Part {
            size: data.len() as u64,
            sha256: sha,
        }],
    };
    fs::write(d.join("entry.json"), serde_json::to_vec(&entry).unwrap()).unwrap();
    d
}

struct Keys {
    kp: minisign::KeyPair,
}

impl Keys {
    fn new() -> Self {
        Self {
            kp: minisign::KeyPair::generate_unencrypted_keypair().unwrap(),
        }
    }

    fn pub_file(&self, dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, self.kp.pk.to_box().unwrap().into_string()).unwrap();
        p
    }

    fn sign(&self, data: &[u8], trusted: &str) -> String {
        minisign::sign(
            Some(&self.kp.pk),
            &self.kp.sk,
            Cursor::new(data),
            Some(trusted),
            Some("test image key"),
        )
        .unwrap()
        .into_string()
    }
}

fn comment_for(manifest: &Path) -> String {
    let m = ImagesManifest::parse(&fs::read(manifest).unwrap()).unwrap();
    format!(
        "hx-images-manifest schema=1 arch=x86_64 timestamp={}",
        m.timestamp
    )
}

/// Build a manifest from `cells` and sign it; returns (manifest, signature).
fn build_signed(
    dir: &Path,
    keys: &Keys,
    cells: &[&Path],
    ts: u64,
    extra: &[&str],
    name: &str,
) -> (PathBuf, PathBuf) {
    let m = dir.join(format!("{name}.json"));
    let ts = ts.to_string();
    let mut args = vec!["manifest"];
    if !cells.is_empty() {
        args.push("--entries");
        args.extend(cells.iter().map(|c| s(c)));
    }
    args.extend(["--timestamp", &ts, "--out", s(&m)]);
    args.extend_from_slice(extra);
    let o = run(&args);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let sig = dir.join(format!("{name}.json.minisig"));
    fs::write(&sig, keys.sign(&fs::read(&m).unwrap(), &comment_for(&m))).unwrap();
    (m, sig)
}

fn verify(m: &Path, sig: &Path, key: &Path, extra: &[&str]) -> Output {
    let now = (NOW + 5).to_string();
    let mut args = vec![
        "verify",
        "--manifest",
        s(m),
        "--sig",
        s(sig),
        "--pubkey",
        s(key),
        "--now",
        &now,
    ];
    args.extend_from_slice(extra);
    run(&args)
}

#[test]
fn usage_errors_exit_2() {
    for args in [
        &[][..],
        &["frobnicate"],
        &["digest"],
        &["digest", "--all", "--recipe", "ubuntu-24.04-xfce-basic"],
        &["digest", "--recipe", "no-such-recipe"],
        &["digest", "--bogus"],
        &["build-image", "--recipe", "ubuntu-24.04-xfce-basic"],
        &[
            "compare",
            "only-one.json",
            "--recipe",
            "ubuntu-24.04-xfce-basic",
        ],
        &["manifest", "--timestamp", "1", "--out", "/nonexistent/m"],
    ] {
        let o = run(args);
        assert_eq!(code(&o), 2, "{args:?}: {}", err(&o));
    }
    // a build id that is not YYYYMMDD.N is a usage error before anything touches Incus
    let o = run(&[
        "build-image",
        "--recipe",
        "ubuntu-24.04-xfce-basic",
        "--build-id",
        "tomorrow",
        "--out",
        "/nonexistent/x",
    ]);
    assert_eq!(code(&o), 2, "{}", err(&o));
}

#[test]
fn help_exits_0() {
    let o = run(&["--help"]);
    assert_eq!(code(&o), 0);
    assert!(out(&o).contains("build-image"));
}

#[test]
fn digest_all_lists_the_eight_recipes() {
    let o = run(&["digest", "--all"]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let text = out(&o);
    assert_eq!(text.lines().count(), 8, "{text}");
    let one = run(&["digest", "--recipe", "debian-13-xfce-developer"]);
    assert_eq!(code(&one), 0);
    assert!(text.contains(out(&one).trim_end()));
}

#[test]
fn manifest_build_sign_verify_round_trip() {
    let d = tempfile::tempdir().unwrap();
    let keys = Keys::new();
    let key = keys.pub_file(d.path(), "image.pub");
    let a = cell(
        d.path(),
        "ubuntu-24.04-xfce-basic",
        "20261123.1",
        &"a".repeat(64),
        NOW - 100,
    );
    let b = cell(
        d.path(),
        "debian-13-xfce-basic",
        "20261123.1",
        &"b".repeat(64),
        NOW - 90,
    );
    let (m, sig) = build_signed(d.path(), &keys, &[&a, &b], NOW, &[], "m1");

    let parsed = ImagesManifest::parse(&fs::read(&m).unwrap()).unwrap();
    assert_eq!(parsed.images.len(), 2);
    assert_eq!(
        parsed.images[0].recipe, "debian-13-xfce-basic",
        "sorted by recipe"
    );

    let o = verify(&m, &sig, &key, &[]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert!(out(&o).contains("2 image(s)"), "{}", out(&o));

    // --image: the whole file of a listed entry verifies, anything else is refused
    let img = a.join(images::file_name(
        images::recipe_by_name("ubuntu-24.04-xfce-basic").unwrap(),
        "20261123.1",
    ));
    let o = verify(&m, &sig, &key, &["--image", s(&img)]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert!(out(&o).contains("is the image of ubuntu-24.04-xfce-basic build 20261123.1"));
    let stray = d.path().join("hx-image-stray.img");
    fs::write(&stray, b"x").unwrap();
    assert_eq!(code(&verify(&m, &sig, &key, &["--image", s(&stray)])), 1);
    let tampered = d.path().join(img.file_name().unwrap());
    fs::write(&tampered, b"tampered").unwrap();
    assert_eq!(code(&verify(&m, &sig, &key, &["--image", s(&tampered)])), 1);
}

#[test]
fn verify_refuses_every_kind_of_bad_manifest() {
    let d = tempfile::tempdir().unwrap();
    let keys = Keys::new();
    let key = keys.pub_file(d.path(), "image.pub");
    let a = cell(
        d.path(),
        "ubuntu-24.04-xfce-basic",
        "20261123.1",
        &"a".repeat(64),
        NOW - 100,
    );
    let (m, sig) = build_signed(d.path(), &keys, &[&a], NOW, &[], "m");
    assert_eq!(code(&verify(&m, &sig, &key, &[])), 0);

    // one flipped byte in the manifest
    let mut bytes = fs::read(&m).unwrap();
    let at = bytes.iter().position(|b| *b == b'x').unwrap();
    bytes[at] = b'y';
    let flipped = d.path().join("flipped.json");
    fs::write(&flipped, &bytes).unwrap();
    assert_eq!(code(&verify(&flipped, &sig, &key, &[])), 1);

    // another key
    let other = Keys::new().pub_file(d.path(), "other.pub");
    assert_eq!(code(&verify(&m, &sig, &other, &[])), 1);

    // UNPROVISIONED keys verify nothing
    let unprov = d.path().join("unprov.pub");
    fs::write(&unprov, "UNPROVISIONED\n").unwrap();
    assert_eq!(code(&verify(&m, &sig, &unprov, &[])), 1);

    // a trusted comment that names another timestamp (valid signature, wrong comment)
    let bad_comment = d.path().join("badcomment.minisig");
    fs::write(
        &bad_comment,
        keys.sign(
            &fs::read(&m).unwrap(),
            "hx-images-manifest schema=1 arch=x86_64 timestamp=1",
        ),
    )
    .unwrap();
    let o = verify(&m, &bad_comment, &key, &[]);
    assert_eq!(code(&o), 1);
    assert!(err(&o).contains("trusted comment"), "{}", err(&o));

    // a manifest timestamp too far ahead of the clock
    let o = run(&[
        "verify",
        "--manifest",
        s(&m),
        "--sig",
        s(&sig),
        "--pubkey",
        s(&key),
        "--now",
        "1000",
    ]);
    assert_eq!(code(&o), 1);

    // a missing file is a failure to run, not a refusal
    let o = verify(&d.path().join("nope.json"), &sig, &key, &[]);
    assert_eq!(code(&o), 3);
}

#[test]
fn the_previous_manifest_is_verified_and_carried_over() {
    let d = tempfile::tempdir().unwrap();
    let keys = Keys::new();
    let key = keys.pub_file(d.path(), "image.pub");
    let a1 = cell(
        d.path(),
        "ubuntu-24.04-xfce-basic",
        "20261110.1",
        &"a".repeat(64),
        NOW - 800,
    );
    let b1 = cell(
        d.path(),
        "debian-13-xfce-basic",
        "20261110.1",
        &"b".repeat(64),
        NOW - 790,
    );
    let (m1, s1) = build_signed(d.path(), &keys, &[&a1, &b1], NOW - 700, &[], "m1");

    // second run: only the ubuntu cell was rebuilt; debian's cell failed
    let a2 = cell(
        d.path(),
        "ubuntu-24.04-xfce-basic",
        "20261120.1",
        &"a".repeat(64),
        NOW - 50,
    );
    let (m2, s2) = build_signed(
        d.path(),
        &keys,
        &[&a2],
        NOW,
        &[
            "--previous",
            s(&m1),
            "--previous-sig",
            s(&s1),
            "--pubkey",
            s(&key),
        ],
        "m2",
    );
    let parsed = ImagesManifest::parse(&fs::read(&m2).unwrap()).unwrap();
    let ids: Vec<(&str, &str)> = parsed
        .images
        .iter()
        .map(|e| (e.recipe.as_str(), e.build_id.as_str()))
        .collect();
    assert_eq!(
        ids,
        [
            ("debian-13-xfce-basic", "20261110.1"),
            ("ubuntu-24.04-xfce-basic", "20261120.1")
        ]
    );
    assert_eq!(code(&verify(&m2, &s2, &key, &[])), 0);

    // a previous manifest signed by another key is refused
    let other = Keys::new().pub_file(d.path(), "other.pub");
    let o = run(&[
        "manifest",
        "--entries",
        s(&a2),
        "--previous",
        s(&m1),
        "--previous-sig",
        s(&s1),
        "--pubkey",
        s(&other),
        "--timestamp",
        &NOW.to_string(),
        "--out",
        s(&d.path().join("x.json")),
    ]);
    assert_eq!(code(&o), 1, "{}", err(&o));

    // a timestamp older than the previous manifest's is refused (replay)
    let o = run(&[
        "manifest",
        "--entries",
        s(&a2),
        "--previous",
        s(&m2),
        "--previous-sig",
        s(&s2),
        "--pubkey",
        s(&key),
        "--timestamp",
        &(NOW - 1).to_string(),
        "--out",
        s(&d.path().join("y.json")),
    ]);
    assert_eq!(code(&o), 1, "{}", err(&o));
}

#[test]
fn an_entry_whose_file_changed_is_refused_when_building_the_manifest() {
    let d = tempfile::tempdir().unwrap();
    let a = cell(
        d.path(),
        "ubuntu-24.04-xfce-basic",
        "20261123.1",
        &"a".repeat(64),
        NOW - 100,
    );
    let id = images::recipe_by_name("ubuntu-24.04-xfce-basic").unwrap();
    fs::write(
        a.join(images::file_name(id, "20261123.1")),
        b"changed after the build",
    )
    .unwrap();
    let o = run(&[
        "manifest",
        "--entries",
        s(&a),
        "--timestamp",
        &NOW.to_string(),
        "--out",
        s(&d.path().join("m.json")),
    ]);
    assert_eq!(code(&o), 3, "{}", err(&o));
    assert!(!d.path().join("m.json").exists());
}

#[test]
fn compare_exit_codes_and_the_table_on_stdout() {
    let d = tempfile::tempdir().unwrap();
    // Facts of an empty desktop satisfy nothing the recipe expects: error-level drift, exit 1,
    // and the table is on stdout.
    let facts = hx_provision::equiv::Facts {
        schema: hx_provision::equiv::FACTS_SCHEMA,
        instance: "i".into(),
        user: "alice".into(),
        ..Default::default()
    };
    let f = d.path().join("f.json");
    fs::write(&f, serde_json::to_vec(&facts).unwrap()).unwrap();
    let o = run(&[
        "compare",
        s(&f),
        s(&f),
        "--recipe",
        "ubuntu-24.04-xfce-basic",
    ]);
    assert_eq!(code(&o), 1, "{}", err(&o));
    assert!(out(&o).starts_with("| Severity | Area |"), "{}", out(&o));
    assert!(err(&o).contains("not equivalent"));

    // an unreadable or malformed facts file is a failure to run
    let bad = d.path().join("bad.json");
    fs::write(&bad, "{").unwrap();
    let o = run(&[
        "compare",
        s(&f),
        s(&bad),
        "--recipe",
        "ubuntu-24.04-xfce-basic",
    ]);
    assert_eq!(code(&o), 3, "{}", err(&o));
    let o = run(&[
        "compare",
        s(&f),
        "/nonexistent",
        "--recipe",
        "ubuntu-24.04-xfce-basic",
    ]);
    assert_eq!(code(&o), 3);
}

#[test]
fn a_withdrawal_re_signs_the_published_manifest_without_the_bad_image() {
    let d = tempfile::tempdir().unwrap();
    let keys = Keys::new();
    let key = keys.pub_file(d.path(), "image.pub");
    let a = cell(
        d.path(),
        "ubuntu-24.04-xfce-basic",
        "20261110.1",
        &"a".repeat(64),
        NOW - 800,
    );
    let b = cell(
        d.path(),
        "debian-13-xfce-basic",
        "20261110.1",
        &"b".repeat(64),
        NOW - 790,
    );
    let (m1, s1) = build_signed(d.path(), &keys, &[&a, &b], NOW - 700, &[], "m1");
    let prev = [
        "--previous",
        s(&m1),
        "--previous-sig",
        s(&s1),
        "--pubkey",
        s(&key),
    ];

    // no --entries: only the previous manifest minus the withdrawn image, with a newer timestamp
    let mut extra: Vec<&str> = prev.to_vec();
    extra.extend(["--drop", "debian-13-xfce-basic/20261110.1"]);
    let (m2, s2) = build_signed(d.path(), &keys, &[], NOW, &extra, "m2");
    let parsed = ImagesManifest::parse(&fs::read(&m2).unwrap()).unwrap();
    assert_eq!(parsed.images.len(), 1);
    assert_eq!(parsed.images[0].recipe, "ubuntu-24.04-xfce-basic");
    assert_eq!(code(&verify(&m2, &s2, &key, &[])), 0);

    // a name that is not in the previous manifest is refused (a typo must not pass silently)
    let now = NOW.to_string();
    let x = d.path().join("x.json");
    let mut args = vec!["manifest"];
    args.extend(prev);
    args.extend([
        "--drop",
        "debian-13-xfce-basic/20261199.9",
        "--timestamp",
        &now,
        "--out",
        s(&x),
    ]);
    let o = run(&args);
    assert_eq!(code(&o), 1, "{}", err(&o));

    // nothing to put in the manifest at all is a usage error
    let y = d.path().join("y.json");
    let o = run(&["manifest", "--timestamp", "1", "--out", s(&y)]);
    assert_eq!(code(&o), 2, "{}", err(&o));
}
