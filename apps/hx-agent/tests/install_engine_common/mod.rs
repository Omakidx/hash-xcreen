//! Shared support of the `install_engine*` tests: a fake machine (`install::testing`), a signed
//! bootstrap directory made with a per-run test key, and builders for the install arguments and
//! the C2 secret frames. Nothing here runs a real program or touches the real host.
#![allow(dead_code)]

#[path = "../privd_update_common/mod.rs"]
pub mod upd;

use std::io::Cursor;
use std::path::PathBuf;

use hx_agent::install::InstallArgs;
use hx_agent::install::options::{Mode, RawOptions, SecretString};
use hx_agent::install::paths;
use hx_agent::install::stdin::{Frames, read_frames};
use hx_agent::install::testing::Machine;
use hx_agent::privd::update::keys::UpdateKeys;
use hx_agent::privd::update::manifest::{Manifest, artifact_name};
use hx_agent::privd::update::verify::sha256_hex;
use serde_json::Value;
use std::os::unix::fs::PermissionsExt;

pub const PASSWORD: &str = "S3cr3t-canary-pw-9f2k";
pub const PIN: &str = "718293";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NOW: u64 = 1_800_000_000;

/// What to tamper with in a release.
#[derive(Default, Clone)]
pub struct Tamper {
    pub version: Option<String>,
    pub channel: Option<String>,
    pub wrong_signer: bool,
    pub flip_artifact_byte: bool,
    pub truncate_signature: bool,
    pub dir_mode: Option<u32>,
    pub drop_member: Option<&'static str>,
    pub rescue: bool,
}

/// Writes a bootstrap directory under the machine's root and points the machine's keys at the
/// test signer. Returns the directory.
pub fn release(m: &mut Machine, tamper: &Tamper) -> PathBuf {
    let signer = upd::Signer::new();
    let other = upd::Signer::new();
    m.keys = UpdateKeys::from_public_keys(&[&signer.public()]).unwrap();
    let version = tamper.version.clone().unwrap_or_else(|| VERSION.to_owned());
    let mut files = upd::good_files(&version);
    if tamper.rescue {
        files.push(upd::TarEntry::file(
            "hx-privd-rescue",
            b"#!/bin/true\n",
            0o755,
        ));
    }
    if let Some(d) = tamper.drop_member {
        files.retain(|e| e.path != d.as_bytes());
    }
    let mut artifact = upd::archive(&files);
    let manifest = Manifest {
        schema: 1,
        channel: tamper.channel.clone().unwrap_or_else(|| "stable".into()),
        version: version.clone(),
        arch: "x86_64".into(),
        artifact: artifact_name(&version, "x86_64"),
        size: artifact.len() as u64,
        sha256: sha256_hex(&artifact),
        timestamp: NOW - 1000,
        min_previous: None,
    };
    let bytes = serde_json::to_vec(&manifest).unwrap();
    let mut sig = if tamper.wrong_signer {
        other.sign(&bytes)
    } else {
        signer.sign(&bytes)
    };
    if tamper.truncate_signature {
        sig.truncate(20);
    }
    if tamper.flip_artifact_byte {
        let n = artifact.len() / 2;
        artifact[n] ^= 0xff;
    }
    let dir = m.paths.at("/var/lib/hx-bootstrap.test");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(
        &dir,
        std::fs::Permissions::from_mode(tamper.dir_mode.unwrap_or(0o700)),
    )
    .unwrap();
    std::fs::write(dir.join("manifest.json"), &bytes).unwrap();
    std::fs::write(dir.join("manifest.json.minisig"), sig).unwrap();
    std::fs::write(dir.join("artifact.tar.gz"), &artifact).unwrap();
    dir
}

/// Options by name.
pub fn raw(values: &[(&'static str, &str)], flags: &[&'static str]) -> RawOptions {
    RawOptions {
        values: values.iter().map(|(k, v)| (*k, (*v).to_owned())).collect(),
        flags: flags.iter().copied().collect(),
    }
}

/// `install --ssh --user alice` with the bootstrap directory.
pub fn ssh_args(
    dir: &std::path::Path,
    extra: &[(&'static str, &str)],
    flags: &[&'static str],
) -> InstallArgs {
    let mut v = vec![("--user", "alice")];
    v.extend_from_slice(extra);
    InstallArgs {
        mode: Some(Mode::Ssh),
        raw: raw(&v, flags),
        bootstrap_dir: Some(dir.to_string_lossy().into_owned()),
        ..InstallArgs::default()
    }
}

pub fn token_text() -> String {
    hx_crypto::PairingToken::generate()
        .unwrap()
        .to_text()
        .to_string()
}

fn rec(k: u8, v: &[u8]) -> Vec<u8> {
    let mut o = vec![k];
    o.extend_from_slice(&(v.len() as u16).to_le_bytes());
    o.extend_from_slice(v);
    o
}

/// The C2 frames of an app: password, PIN, and optionally a token and an owner key.
pub fn frames(token: Option<&str>, owner_key: Option<[u8; 32]>) -> Frames {
    let mut s = b"HXI1".to_vec();
    s.extend(rec(1, PASSWORD.as_bytes()));
    s.extend(rec(2, PIN.as_bytes()));
    if let Some(t) = token {
        s.extend(rec(3, t.as_bytes()));
    }
    if let Some(k) = owner_key {
        s.extend(rec(4, &k));
    }
    s.extend(rec(0, b""));
    read_frames(&mut Cursor::new(s), true).unwrap()
}

/// A full `--ssh` install on `m`; returns the exit code.
pub fn full_install(m: &mut Machine, dir: &std::path::Path) -> u8 {
    m.install(ssh_args(dir, &[], &[]), Some(frames(None, None)))
}

/// The stage lines of the last run: `(id, state)`.
pub fn stage_lines(m: &Machine) -> Vec<(String, String)> {
    m.json_lines()
        .iter()
        .filter(|v| v["t"] == "stage")
        .map(|v| {
            (
                v["id"].as_str().unwrap().to_owned(),
                v["state"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

pub fn states(m: &Machine, wanted: &str) -> Vec<String> {
    stage_lines(m)
        .into_iter()
        .filter(|(_, s)| s == wanted)
        .map(|(i, _)| i)
        .collect()
}

/// Every file below `root` (relative) with its SHA-256, for "nothing changed" checks. The log and
/// the state file's timestamps are excluded: they record that a run happened.
pub fn tree_hash(m: &Machine) -> Vec<(String, String)> {
    fn walk(dir: &std::path::Path, base: &std::path::Path, out: &mut Vec<(String, String)>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            let rel = p.strip_prefix(base).unwrap().to_string_lossy().into_owned();
            let ft = e.file_type().unwrap();
            if ft.is_dir() {
                walk(&p, base, out);
            } else if ft.is_file() {
                if rel.ends_with("hx-install.log") || rel.ends_with("install-state.json") {
                    continue;
                }
                out.push((rel, sha256_hex(&std::fs::read(&p).unwrap())));
            } else {
                out.push((rel, format!("link:{:?}", std::fs::read_link(&p).unwrap())));
            }
        }
    }
    let mut v = Vec::new();
    walk(m.dir.path(), m.dir.path(), &mut v);
    v.sort();
    v
}

pub fn result_exit(m: &Machine) -> u64 {
    m.result()["exit"].as_u64().unwrap_or(999)
}

pub fn token_args(token: &str, dir: &std::path::Path) -> InstallArgs {
    InstallArgs {
        mode: Some(Mode::Token),
        token: Some(SecretString::new(token.to_owned())),
        bootstrap_dir: Some(dir.to_string_lossy().into_owned()),
        ..InstallArgs::default()
    }
}

pub fn pair_args(dir: &std::path::Path) -> InstallArgs {
    InstallArgs {
        mode: Some(Mode::Pair),
        bootstrap_dir: Some(dir.to_string_lossy().into_owned()),
        ..InstallArgs::default()
    }
}

pub fn path(m: &Machine, abs: &str) -> PathBuf {
    m.paths.at(abs)
}

pub fn exists(m: &Machine, abs: &str) -> bool {
    m.paths.at(abs).exists()
}

pub fn unit_dir(m: &Machine) -> PathBuf {
    m.paths.at(paths::UNIT_DIR)
}

pub fn json_has(v: &Value, key: &str) -> bool {
    v.get(key).is_some()
}
