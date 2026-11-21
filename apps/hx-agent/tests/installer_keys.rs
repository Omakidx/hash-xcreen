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
    let provisioned = file_key("current.pub") != "UNPROVISIONED"
        && file_key("next.pub") != "UNPROVISIONED";
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
