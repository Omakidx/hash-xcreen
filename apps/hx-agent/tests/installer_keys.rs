//! The release signing keys must be the same in the three places that carry them: the binary
//! (`release-keys/{current,next}.pub`, compiled into privd) and `installer/install.sh`
//! (`KEY_CURRENT`, `KEY_NEXT`). While the maintainer has not provisioned real keys both are the
//! word `UNPROVISIONED` and the release gate (`release/gate.sh`) blocks a release.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The base64 key line of a key file, or `UNPROVISIONED` (the rule of `privd::update::keys`).
fn file_key(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("release-keys")
        .join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("untrusted comment:"))
        .unwrap_or("UNPROVISIONED")
        .to_string()
}

/// The value of `KEY_CURRENT='...'` / `KEY_NEXT='...'` in install.sh.
fn sh_key(var: &str) -> String {
    let sh = std::fs::read_to_string(repo().join("installer/install.sh")).unwrap();
    let prefix = format!("{var}='");
    let line = sh
        .lines()
        .find(|l| l.starts_with(&prefix))
        .unwrap_or_else(|| panic!("install.sh has no {var}"));
    line[prefix.len()..]
        .strip_suffix('\'')
        .unwrap_or_else(|| panic!("{var} is not single-quoted"))
        .to_string()
}

#[test]
fn install_sh_embeds_the_release_keys() {
    assert_eq!(sh_key("KEY_CURRENT"), file_key("current.pub"));
    assert_eq!(sh_key("KEY_NEXT"), file_key("next.pub"));
}

#[test]
fn a_provisioned_key_is_a_valid_minisign_key_and_the_two_differ() {
    let (c, n) = (file_key("current.pub"), file_key("next.pub"));
    for k in [&c, &n] {
        if k != "UNPROVISIONED" {
            minisign_verify::PublicKey::from_base64(k).expect("a provisioned key must parse");
        }
    }
    if c != "UNPROVISIONED" && n != "UNPROVISIONED" {
        assert_ne!(c, n, "current and next must be different keys");
    }
}

#[test]
fn the_release_gate_blocks_exactly_while_a_key_is_unprovisioned() {
    let out = Command::new("sh")
        .arg(repo().join("release/gate.sh"))
        .output()
        .unwrap();
    let provisioned =
        file_key("current.pub") != "UNPROVISIONED" && file_key("next.pub") != "UNPROVISIONED";
    assert_eq!(
        out.status.success(),
        provisioned,
        "gate output:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if !provisioned {
        assert!(String::from_utf8_lossy(&out.stderr).contains("UNPROVISIONED"));
    }
}

#[test]
fn the_gate_rejects_a_tag_that_is_not_the_workspace_version() {
    let out = Command::new("sh")
        .arg(repo().join("release/gate.sh"))
        .args(["--tag", "v9.9.9"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("workspace version"));
}

/// Runs `release/gate.sh --dry-run --workflow <file>` on a workflow text.
fn gate_on_workflow(text: &str) -> (bool, String) {
    let dir = tempfile::tempdir().unwrap();
    let wf = dir.path().join("release.yml");
    std::fs::write(&wf, text).unwrap();
    let out = Command::new("sh")
        .arg(repo().join("release/gate.sh"))
        .args(["--dry-run", "--workflow"])
        .arg(&wf)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

const SHA: &str = "11d5960a326750d5838078e36cf38b85af677262";

#[test]
fn the_gate_requires_every_action_pinned_to_a_full_commit_sha() {
    let ok = format!("jobs:\n  a:\n    steps:\n      - uses: actions/checkout@{SHA} # v4\n");
    assert!(gate_on_workflow(&ok).0, "a pinned workflow must pass");
    for bad in [
        "      - uses: actions/checkout@v4\n".to_string(),
        format!("      - uses: actions/checkout@{}\n", &SHA[..39]),
        format!("      - uses: actions/checkout@{SHA}0\n"),
        "      - uses: docker://rhysd/actionlint:1.7.7\n".to_string(),
        "      - uses: ./local-action\n".to_string(),
        format!("      - uses: actions/checkout@{SHA}\n      - uses: actions/upload-artifact@v4\n"),
    ] {
        let (passed, stderr) = gate_on_workflow(&format!("jobs:\n  a:\n    steps:\n{bad}"));
        assert!(!passed, "must refuse: {bad}");
        assert!(stderr.contains("not pinned"), "{stderr}");
    }
}

#[test]
fn the_gate_refuses_a_build_cache_in_the_release_workflow() {
    for cache in [
        format!("      - uses: Swatinem/rust-cache@{SHA}\n"),
        format!("      - uses: actions/cache@{SHA}\n"),
        format!("      - uses: actions/cache/restore@{SHA}\n"),
    ] {
        let (passed, stderr) = gate_on_workflow(&format!("jobs:\n  a:\n    steps:\n{cache}"));
        assert!(!passed, "must refuse: {cache}");
        assert!(stderr.contains("build cache"), "{stderr}");
    }
}

#[test]
fn the_shipped_release_workflow_is_pinned_and_uncached() {
    let text = std::fs::read_to_string(repo().join(".github/workflows/release.yml")).unwrap();
    assert!(gate_on_workflow(&text).0);
}
