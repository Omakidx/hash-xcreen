//! The layout guard of ipc.md §36: `hx-privd` and `hx-gatewayd` (the `hx-agent` package) must never
//! contain `rustic_core`.
//!
//! Cargo unifies the features of one package across all of its binaries, so the worker lives in its
//! own package. This test asks Cargo what the `hx-agent` package would build with (`cargo tree`,
//! resolved as for `cargo build -p hx-agent`, which is what the release workflow runs) and fails if
//! rustic, its backends, the worker package or the `engine` feature of `hx-backup` is in it. It
//! needs no network: the lockfile and the local registry are enough.

use std::path::PathBuf;
use std::process::Command;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn tree(args: &[&str]) -> Option<String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let out = Command::new(cargo)
        .current_dir(workspace_root())
        .args([
            "tree",
            "--offline",
            "--locked",
            "--prefix",
            "none",
            "--charset",
            "ascii",
        ])
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        eprintln!(
            "cargo tree failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn no_hx_agent_binary_can_contain_rustic() {
    let Some(normal) = tree(&["-p", "hx-agent", "-e", "normal"]) else {
        panic!("cargo tree must work offline in this workspace");
    };
    // The Drive helper's HTTP stack (OpenDAL, reqwest) is the worker package's alone: privd and
    // gatewayd never link it either (ipc.md section 36, decision 11).
    for forbidden in ["rustic", "hx-backup-worker", "opendal", "reqwest"] {
        assert!(
            !normal.contains(forbidden),
            "hx-agent's dependency tree contains {forbidden}:\n{normal}"
        );
    }
    // privd may use hx-backup's pure modules later; never its engine.
    let features = tree(&["-p", "hx-agent", "-e", "normal,features"]).expect("cargo tree");
    assert!(
        !features.contains("hx-backup feature \"engine\""),
        "hx-agent enables the engine feature of hx-backup"
    );
    assert!(!features.contains("rustic"), "{features}");
    assert!(!features.contains("opendal"), "{features}");
}

#[test]
fn the_drive_helpers_http_stack_is_small_and_has_no_openssl() {
    let normal = tree(&["-p", "hx-backup-worker", "-e", "normal"]).expect("cargo tree");
    for wanted in ["opendal", "reqwest", "rustls"] {
        assert!(normal.contains(wanted), "the Drive role links {wanted}");
    }
    // pure Rust TLS with ring: no OpenSSL, no native-tls, no aws-lc
    for forbidden in ["openssl-sys", "native-tls", "aws-lc"] {
        assert!(
            !normal.contains(forbidden),
            "the worker's tree contains {forbidden}:\n{normal}"
        );
    }
    // OpenDAL with only the Google Drive service and none of its other services or layers
    let features = tree(&["-p", "hx-backup-worker", "-e", "normal,features"]).expect("cargo tree");
    let opendal: Vec<&str> = features
        .lines()
        .filter(|l| l.contains("opendal feature "))
        .collect();
    assert!(
        opendal.iter().any(|l| l.contains("\"services-gdrive\"")),
        "{opendal:?}"
    );
    for l in &opendal {
        assert!(
            l.contains("\"services-gdrive\"") || !l.contains("\"services-"),
            "another OpenDAL service is enabled: {l}"
        );
    }
    assert!(
        !features.contains("opendal-service-s3") && !features.contains("opendal-service-fs"),
        "{features}"
    );
}

#[test]
fn the_worker_package_is_where_rustic_lives() {
    let normal = tree(&["-p", "hx-backup-worker", "-e", "normal"]).expect("cargo tree");
    assert!(
        normal.contains("rustic_core"),
        "the worker must link the engine"
    );
    assert!(
        normal.contains("hx-ipc"),
        "the worker speaks the repository link"
    );
}
