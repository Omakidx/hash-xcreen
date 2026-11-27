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
    for forbidden in ["rustic", "hx-backup-worker"] {
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
