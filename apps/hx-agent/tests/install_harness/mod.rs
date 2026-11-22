//! Helpers of `install_nested_incus.rs`: the Incus side (`incus`), the C2 frames (`frames`), the
//! C3 progress parser and runner (`progress`), the build of a test-keyed release directory, and
//! the results table.
//!
//! Nothing here is production code. Every deviation from a real host is listed in the test's
//! module documentation and in `docs/spikes/1e-installer-nested-incus.md`.
#![allow(dead_code)]

pub mod client;
pub mod frames;
pub mod incus;
pub mod progress;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::Instant;

// ----- the results table ------------------------------------------------------------------------------

static ROWS: Mutex<Vec<(String, String, String)>> = Mutex::new(Vec::new());
static START: Mutex<Option<Instant>> = Mutex::new(None);

/// Records one passed check (a failed check panics at once, so every row here passed).
pub fn pass(distro: &str, check: &str, detail: impl std::fmt::Display) {
    let mut s = START.lock().unwrap();
    let t = s.get_or_insert_with(Instant::now).elapsed().as_secs();
    eprintln!("PASS [{distro}] {check} (t+{t}s): {detail}");
    ROWS.lock()
        .unwrap()
        .push((distro.to_owned(), check.to_owned(), detail.to_string()));
}

/// Prints the table of everything that passed.
pub fn print_rows() {
    eprintln!("\n==== results ====");
    for (d, c, det) in ROWS.lock().unwrap().iter() {
        eprintln!("| {d} | {c} | {det} |");
    }
}

// ----- paths and builds ---------------------------------------------------------------------------------

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

pub fn target_dir() -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| repo_root().join("target"), PathBuf::from)
}

/// Where the harness keeps its persistent test keys and its build products.
pub fn work_dir() -> PathBuf {
    let d = target_dir().join("hx1e");
    std::fs::create_dir_all(&d).expect("work dir");
    d
}

fn run(mut c: Command, what: &str) {
    eprintln!("BUILD {what}: {c:?}");
    let o = c.output().unwrap_or_else(|e| panic!("{what}: spawn: {e}"));
    assert!(
        o.status.success(),
        "{what} failed ({}):\n{}\n{}",
        o.status,
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
}

fn cargo() -> Command {
    Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
}

pub fn workspace_version() -> String {
    let t = std::fs::read_to_string(repo_root().join("Cargo.toml")).expect("Cargo.toml");
    let mut in_ws = false;
    for l in t.lines() {
        if l.starts_with('[') {
            in_ws = l.trim() == "[workspace.package]";
        } else if in_ws && l.starts_with("version") {
            return l.split('"').nth(1).expect("version").to_owned();
        }
    }
    panic!("workspace version not found");
}

/// What a build produced.
pub struct Artifacts {
    /// The release directory to push into L1 (`install.sh`, tarball, manifest, signature).
    pub release_dir: PathBuf,
    pub version: String,
}

/// Builds the real binaries with the test key and the test features, the `hx-session` package for
/// Ubuntu 24.04, and a test-keyed release directory around them.
///
/// Key order: the agent embeds the test key at build time, so the key directory is made first and
/// persists under `target/hx1e/keys` between runs (a new key per run would force a rebuild).
pub fn build_artifacts() -> Artifacts {
    let root = repo_root();
    let work = work_dir();
    let keys = work.join("keys");
    for k in ["current", "next"] {
        if !keys.join(k).join("key.line").is_file() || !keys.join(k).join("secret.pem").is_file() {
            let _ = std::fs::remove_dir_all(keys.join(k));
            let mut c = Command::new("sh");
            c.arg(root.join("release/openssl-minisign.sh"))
                .arg("keygen")
                .arg(keys.join(k));
            run(c, "test key");
        }
    }
    let pubkey = std::fs::read_to_string(keys.join("current/key.line"))
        .expect("key")
        .trim()
        .to_owned();

    let mut c = cargo();
    c.current_dir(&root)
        .env("HX_TEST_RELEASE_PUBKEY", &pubkey)
        .args([
            "build",
            "-p",
            "hx-agent",
            "--bins",
            "--release",
            "--features",
            "test-release-key,install-test-hooks,privd-test-hooks",
        ]);
    run(c, "hx-agent (test key, test hooks)");

    let mut c = cargo();
    c.current_dir(&root).args([
        "build",
        "--release",
        "--locked",
        "-p",
        "hx-session",
        "--bin",
        "hx-session",
        "-p",
        "hx-pwcheck",
        "--bin",
        "hx-pwcheck",
    ]);
    run(c, "hx-session and hx-pwcheck");

    let rel = target_dir().join("release");
    let bins = work.join("bin");
    let _ = std::fs::remove_dir_all(&bins);
    std::fs::create_dir_all(&bins).unwrap();
    for b in [
        "hx-privd",
        "hx-gatewayd",
        "hx-agent",
        "hx-update-fetcher",
        "hx-backup-worker",
        "hx-privd-rescue",
    ] {
        std::fs::copy(rel.join(b), bins.join(b)).unwrap_or_else(|e| panic!("{b}: {e}"));
    }

    let version = workspace_version();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();

    // The session package: real for this host's distro (Ubuntu 24.04), placeholders for the
    // others (their FFmpeg sonames differ, and `build-deb.sh` must run on the distro itself).
    let sess = work.join("session");
    let _ = std::fs::remove_dir_all(&sess);
    let pkg_in = work.join("pkg-in");
    let _ = std::fs::remove_dir_all(&pkg_in);
    std::fs::create_dir_all(&pkg_in).unwrap();
    for b in ["hx-session", "hx-pwcheck"] {
        std::fs::copy(rel.join(b), pkg_in.join(b)).unwrap_or_else(|e| panic!("{b}: {e}"));
    }
    for d in ["ubuntu-24.04", "ubuntu-26.04", "debian-12", "debian-13"] {
        std::fs::create_dir_all(sess.join(d)).unwrap();
        if d == "ubuntu-24.04" {
            let mut c = Command::new("sh");
            c.arg(root.join("packaging/hx-session/build-deb.sh"))
                .args(["--version", &version, "--distro", d, "--bin-dir"])
                .arg(&pkg_in)
                .arg("--out")
                .arg(sess.join(d))
                .args(["--source-date-epoch", &now]);
            run(c, "hx-session.deb (ubuntu-24.04)");
        } else {
            std::fs::write(
                sess.join(d).join("hx-session.deb"),
                format!("!<arch>\nplaceholder {d}\n"),
            )
            .unwrap();
        }
    }

    let out = work.join("release");
    let _ = std::fs::remove_dir_all(&out);
    let mut c = Command::new("sh");
    c.arg(root.join("release/make-test-release.sh"))
        .arg("--out")
        .arg(&out)
        .arg("--bin-dir")
        .arg(&bins)
        .arg("--session-dir")
        .arg(&sess)
        .arg("--key-dir")
        .arg(&keys)
        .args(["--timestamp", &now]);
    run(c, "test release directory");
    assert_eq!(
        std::fs::read_to_string(out.join("test-release.pubkey"))
            .unwrap()
            .trim(),
        pubkey,
        "the release is signed with the key the agent embeds"
    );
    Artifacts {
        release_dir: out,
        version,
    }
}

// ----- small random secrets ---------------------------------------------------------------------------------

pub fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).expect("getrandom");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A random decimal PIN of `n` digits (long, so that the canary scan has no chance matches).
pub fn random_pin(n: usize) -> String {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).expect("getrandom");
    b.iter().map(|x| char::from(b'0' + x % 10)).collect()
}
