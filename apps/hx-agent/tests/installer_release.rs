//! Gate G1a: `release/make-test-release.sh` builds a test-keyed release directory that is accepted
//! by BOTH consumers: privd's own update code (signature, manifest checks, size and SHA-256,
//! `extract`) and `installer/install.sh` (its verification function, in test mode, and the
//! hand-off, which `installer/tests/handoff.sh` runs end to end).

use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use hx_agent::privd::update::UpdateKeys;
use hx_agent::privd::update::extract::{Limits, extract_tar_gz};
use hx_agent::privd::update::manifest::{Expect, Manifest, artifact_name};
use hx_agent::privd::update::switch::{REQUIRED_BINARIES, VERSION_FILE};
use hx_agent::privd::update::verify::sha256_hex;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn make(out: &Path, extra: &[&str]) {
    let o = Command::new("sh")
        .arg(repo().join("release/make-test-release.sh"))
        .arg("--out")
        .arg(out)
        .args(extra)
        .output()
        .unwrap();
    assert!(
        o.status.success(),
        "make-test-release.sh failed:\n{}",
        String::from_utf8_lossy(&o.stderr)
    );
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn privd_accepts_the_test_release_dir() {
    let t = tempfile::tempdir().unwrap();
    let rel = t.path().join("rel");
    make(&rel, &["--version", "0.3.0-rc.2", "--min-previous", "0.2.0"]);

    let manifest = std::fs::read(rel.join("manifest-x86_64.json")).unwrap();
    let sig = std::fs::read_to_string(rel.join("manifest-x86_64.json.minisig")).unwrap();
    let pubkey = std::fs::read_to_string(rel.join("test-release.pubkey")).unwrap();

    // signature: only the test CURRENT key signs, privd's prehash-only verifier accepts it
    let keys = UpdateKeys::from_public_keys(&[pubkey.trim()]).unwrap();
    keys.verify(&manifest, &sig).expect("privd must accept the signature");

    // manifest: the canonical one-liner, every privd field check passes
    assert_eq!(manifest.iter().filter(|b| **b == b'\n').count(), 1);
    assert!(manifest.ends_with(b"}\n") && !manifest.contains(&b' '));
    let text = String::from_utf8(manifest.clone()).unwrap();
    assert!(
        text.starts_with(r#"{"schema":1,"channel":"stable","version":"0.3.0-rc.2","arch":"x86_64","artifact":"hx-0.3.0-rc.2-x86_64.tar.gz","size":"#),
        "{text}"
    );
    assert!(text.trim_end().ends_with(r#","min_previous":"0.2.0"}"#));
    let release = Manifest::parse(&manifest)
        .unwrap()
        .check(&Expect {
            channel: "stable",
            arch: "x86_64",
            now: now(),
        })
        .expect("privd must accept the manifest");
    assert_eq!(release.manifest.artifact, artifact_name("0.3.0-rc.2", "x86_64"));

    // artifact: size and SHA-256 equal the manifest's, then privd's extract unpacks it
    let art = std::fs::read(rel.join(&release.manifest.artifact)).unwrap();
    assert_eq!(art.len() as u64, release.manifest.size);
    assert_eq!(sha256_hex(&art), release.manifest.sha256);
    let root = t.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let fd = rustix::fs::open(
        &root,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    let stats = extract_tar_gz(art.as_slice(), fd.as_fd(), &Limits::default(), &|| false)
        .expect("privd's extract must accept the tarball (ustar only)");
    assert!(stats.files >= 10, "{stats:?}");
    for b in REQUIRED_BINARIES.iter().chain(&["hx-backup-worker", "hx-privd-rescue"]) {
        let m = std::fs::metadata(root.join(b)).unwrap_or_else(|e| panic!("{b}: {e}"));
        assert!(m.is_file() && m.permissions().mode() & 0o111 != 0, "{b}");
    }
    assert_eq!(
        std::fs::read_to_string(root.join(VERSION_FILE)).unwrap(),
        "0.3.0-rc.2\n"
    );
    for d in ["ubuntu-24.04", "ubuntu-26.04", "debian-12", "debian-13"] {
        assert!(root.join("session").join(d).join("hx-session.deb").is_file(), "{d}");
    }
}

#[test]
fn install_sh_of_the_test_release_dir_accepts_the_same_signature() {
    let t = tempfile::tempdir().unwrap();
    let rel = t.path().join("rel");
    make(&rel, &[]);
    let verify = |sh: &str, manifest: &Path| {
        Command::new(sh)
            .arg(repo().join("release/verify-with-installer.sh"))
            .arg(rel.join("install.sh"))
            .arg(manifest)
            .arg(rel.join("manifest-x86_64.json.minisig"))
            .status()
            .unwrap()
            .code()
    };
    for sh in ["sh", "bash"] {
        assert_eq!(verify(sh, &rel.join("manifest-x86_64.json")), Some(0), "{sh}");
    }
    let tampered = t.path().join("tampered.json");
    let mut bytes = std::fs::read(rel.join("manifest-x86_64.json")).unwrap();
    bytes[10] ^= 1;
    std::fs::write(&tampered, bytes).unwrap();
    assert_eq!(verify("sh", &tampered), Some(1));
    // the repository's own install.sh (no key provisioned) must refuse the test signature
    let o = Command::new("sh")
        .arg(repo().join("release/verify-with-installer.sh"))
        .arg(repo().join("installer/install.sh"))
        .arg(rel.join("manifest-x86_64.json"))
        .arg(rel.join("manifest-x86_64.json.minisig"))
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
}

#[test]
fn the_tarball_is_reproducible_and_ustar() {
    let t = tempfile::tempdir().unwrap();
    let args = ["--version", "0.3.0", "--timestamp", "1790000000"];
    make(&t.path().join("a"), &args);
    make(&t.path().join("b"), &args);
    let a = std::fs::read(t.path().join("a/hx-0.3.0-x86_64.tar.gz")).unwrap();
    let b = std::fs::read(t.path().join("b/hx-0.3.0-x86_64.tar.gz")).unwrap();
    assert_eq!(sha256_hex(&a), sha256_hex(&b), "same inputs, same bytes");
    // the second byte-run of the gzip header is zero (no mtime, no name: `gzip -n`)
    assert_eq!(&a[4..8], &[0, 0, 0, 0]);
}
