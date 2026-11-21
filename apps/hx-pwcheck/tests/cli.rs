//! The `hx-pwcheck` binary, run the way hx-privd runs it: `hx-pwcheck <login>`, the candidate on
//! standard input, the answer in the exit status. The shadow file is a fixture named by
//! `HX_PWCHECK_SHADOW`, which exists only in builds with the `test-shadow-path` feature (the
//! crate's own tests); the real `/etc/shadow` is never read here.
//!
//! The hashes are fixed vectors produced by libxcrypt (`crypt(3)`, through Python's ctypes
//! binding, independently of this crate), plus hashes this crate computes itself.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

use hx_pwcheck::{
    EXIT_MATCH, EXIT_MISMATCH, EXIT_NO_HASH, EXIT_UNAVAILABLE, EXIT_USAGE, MAX_PASSWORD, crypt,
};

// "$6$" sha512crypt.
const SHA512: &str = "$6$saltsalt$CPgxBHZBXfhC6lX1yxpdEsbQfXmg3WXVj8AoVwyNFLfb5AtbfM8k6A8yehv1z6sgzoH/DUIs7YK9hVnGhTjhW/";
const SHA512_PW: &str = "correct horse battery staple";
// "$6$" with an explicit round count and a non-ASCII password.
const SHA512_ROUNDS: &str = "$6$rounds=5000$abcdefghijklmnop$PgfBRn5NkXbA2XZtilnguWKQpJpfJShmLyZHZeZDGfPC0OAI0h9GDSq13PAh4FBaE5zk5GFVxj.FP0gNFfKla1";
const UMLAUT_PW: &str = "pässword";
// "$y$" yescrypt, the default scheme of Debian 11+ and Ubuntu 22.04+.
const YESCRYPT: &str =
    "$y$j9T$/6k.2IU/5UE08g.1Bsk1E2V2$oo8cKVpsqNZ3WJflMKT6Fc310lnPIJM7OtLLuiIvU80";
const YESCRYPT_PW: &str = "hunter2";
// "$5$" and "$2b$": the other schemes libxcrypt reads.
const SHA256: &str = "$5$saltsalt$Mtm6KOxb.PwaKES1sp80SDYOu1T0RdwsBVakhLiqA64";
const BCRYPT: &str = "$2b$05$abcdefghijklmnopqrstuuoXuKqgZXLiJqzfmMXDDhSFPIvxV7t8.";

fn shadow_with(dir: &Path, lines: &[(&str, &str)]) -> std::path::PathBuf {
    let path = dir.join("shadow");
    let mut text = String::new();
    for (user, hash) in lines {
        text.push_str(&format!("{user}:{hash}:19000:0:99999:7:::\n"));
    }
    std::fs::write(&path, text).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    path
}

/// Runs the binary with `args`, `stdin` bytes and the shadow fixture; returns the exit status,
/// stdout and stderr.
fn run(shadow: &Path, args: &[&str], stdin: &[u8]) -> (i32, Vec<u8>, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_hx-pwcheck"))
        .args(args)
        .env_clear()
        .env("HX_PWCHECK_SHADOW", shadow)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut sin = child.stdin.take().unwrap();
    let data = stdin.to_vec();
    // A writer thread: an over-long candidate must not deadlock against a closed pipe.
    let w = std::thread::spawn(move || {
        let _ = sin.write_all(&data);
    });
    let out = child.wait_with_output().unwrap();
    let _ = w.join();
    (
        out.status.code().expect("exited with a status"),
        out.stdout,
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn status(shadow: &Path, user: &str, password: &str) -> i32 {
    run(shadow, &[user], password.as_bytes()).0
}

#[test]
fn every_scheme_matches_and_mismatches() {
    let dir = tempfile::tempdir().unwrap();
    let shadow = shadow_with(
        dir.path(),
        &[
            ("sha512", SHA512),
            ("rounds", SHA512_ROUNDS),
            ("yescrypt", YESCRYPT),
            ("sha256", SHA256),
            ("bcrypt", BCRYPT),
        ],
    );
    for (user, pw) in [
        ("sha512", SHA512_PW),
        ("rounds", UMLAUT_PW),
        ("yescrypt", YESCRYPT_PW),
        ("sha256", "a"),
        ("bcrypt", "hunter2"),
    ] {
        assert_eq!(status(&shadow, user, pw), i32::from(EXIT_MATCH), "{user}");
        assert_eq!(
            status(&shadow, user, &format!("{pw} ")),
            i32::from(EXIT_MISMATCH),
            "{user}: a trailing space is part of the password"
        );
        assert_eq!(
            status(&shadow, user, ""),
            i32::from(EXIT_MISMATCH),
            "{user}"
        );
        assert_eq!(
            status(&shadow, user, &format!("{pw}\n")),
            i32::from(EXIT_MISMATCH),
            "{user}: no newline is stripped"
        );
    }
    // The yescrypt hash of one user is not the password of another.
    assert_eq!(
        status(&shadow, "yescrypt", SHA512_PW),
        i32::from(EXIT_MISMATCH)
    );
}

#[test]
fn hashes_computed_here_round_trip() {
    // The test generates the hash with `crypt_rn` itself (salt only, as `chpasswd` would pass it).
    let dir = tempfile::tempdir().unwrap();
    for (scheme, setting) in [
        ("sha512", "$6$0123456789abcdef"),
        ("sha256", "$5$0123456789abcdef"),
        ("yescrypt", "$y$j9T$/6k.2IU/5UE08g.1Bsk1E2V2"),
    ] {
        let hash = crypt::crypt(b"s3cr3t pass phrase", setting.as_bytes()).unwrap();
        let hash = std::str::from_utf8(&hash).unwrap().to_owned();
        assert!(hash.starts_with(setting), "{scheme}: {hash}");
        let shadow = shadow_with(dir.path(), &[("u", &hash)]);
        assert_eq!(status(&shadow, "u", "s3cr3t pass phrase"), 0, "{scheme}");
        assert_eq!(status(&shadow, "u", "s3cr3t pass phrasf"), 1, "{scheme}");
    }
}

#[test]
fn locked_star_empty_and_unknown_users_are_exit_3() {
    let dir = tempfile::tempdir().unwrap();
    let locked_with_hash = format!("!{YESCRYPT}");
    let shadow = shadow_with(
        dir.path(),
        &[
            ("locked", "!"),
            ("locked2", "!!"),
            ("lockedhash", &locked_with_hash),
            ("star", "*"),
            ("starlk", "*LK*"),
            ("empty", ""),
            ("real", YESCRYPT),
        ],
    );
    for user in ["locked", "locked2", "lockedhash", "star", "starlk", "empty"] {
        // The right password of the locked hash does not unlock it either.
        for pw in ["", "x", YESCRYPT_PW] {
            assert_eq!(status(&shadow, user, pw), i32::from(EXIT_NO_HASH), "{user}");
        }
    }
    // Unknown, a prefix of a known name, a superstring and a different case.
    for user in ["nobody", "rea", "realx", "REAL", "real "] {
        assert_eq!(
            status(&shadow, user, YESCRYPT_PW),
            i32::from(EXIT_NO_HASH),
            "{user:?}"
        );
    }
    assert_eq!(status(&shadow, "real", YESCRYPT_PW), 0);
}

#[test]
fn the_first_entry_of_a_name_wins() {
    let dir = tempfile::tempdir().unwrap();
    let shadow = shadow_with(dir.path(), &[("dup", SHA512), ("dup", YESCRYPT)]);
    assert_eq!(status(&shadow, "dup", SHA512_PW), 0);
    assert_eq!(status(&shadow, "dup", YESCRYPT_PW), 1);
}

#[test]
fn a_symlinked_shadow_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let real = shadow_with(dir.path(), &[("u", YESCRYPT)]);
    let link = dir.path().join("shadow-link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    // The same file through the symlink would match; O_NOFOLLOW refuses it.
    assert_eq!(status(&real, "u", YESCRYPT_PW), 0);
    let (code, _, err) = run(&link, &["u"], YESCRYPT_PW.as_bytes());
    assert_eq!(code, i32::from(EXIT_UNAVAILABLE), "{err}");
}

#[test]
fn a_missing_or_non_regular_shadow_is_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope");
    assert_eq!(status(&missing, "u", "x"), i32::from(EXIT_UNAVAILABLE));
    // A directory.
    assert_eq!(status(dir.path(), "u", "x"), i32::from(EXIT_UNAVAILABLE));
    // A FIFO (opened read-only it would block: it must be refused, not waited on). The open of
    // a FIFO without a writer blocks, so only a device-like non-regular file that opens at once
    // is used here.
    assert_eq!(
        status(Path::new("/dev/null"), "u", "x"),
        i32::from(EXIT_UNAVAILABLE)
    );
}

#[test]
fn an_unsupported_stored_hash_is_unavailable_not_a_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let shadow = shadow_with(
        dir.path(),
        &[("junk", "$9$whatever$notahash"), ("plain", "x")],
    );
    for user in ["junk", "plain"] {
        assert_eq!(
            status(&shadow, user, "pw"),
            i32::from(EXIT_UNAVAILABLE),
            "{user}"
        );
    }
}

#[test]
fn a_hash_that_is_only_a_scheme_prefix_never_matches() {
    let dir = tempfile::tempdir().unwrap();
    let shadow = shadow_with(dir.path(), &[("short", "$6$")]);
    assert_eq!(status(&shadow, "short", "pw"), i32::from(EXIT_MISMATCH));
    assert_eq!(status(&shadow, "short", ""), i32::from(EXIT_MISMATCH));
    assert_eq!(status(&shadow, "short", "$6$"), i32::from(EXIT_MISMATCH));
}

#[test]
fn nul_and_over_long_candidates_are_mismatches_never_truncated() {
    let dir = tempfile::tempdir().unwrap();
    let shadow = shadow_with(dir.path(), &[("u", YESCRYPT)]);
    // A NUL after the right password: C would stop at it and match.
    let mut pw = YESCRYPT_PW.as_bytes().to_vec();
    pw.push(0);
    pw.extend_from_slice(b"junk");
    assert_eq!(run(&shadow, &["u"], &pw).0, i32::from(EXIT_MISMATCH));
    // The right password followed by a lot of data.
    let mut long = YESCRYPT_PW.as_bytes().to_vec();
    long.resize(MAX_PASSWORD + 1, b'a');
    assert_eq!(run(&shadow, &["u"], &long).0, i32::from(EXIT_MISMATCH));
    let huge = vec![b'a'; 1 << 20];
    assert_eq!(run(&shadow, &["u"], &huge).0, i32::from(EXIT_MISMATCH));
    // Exactly the maximum is hashed (and does not match).
    let max = vec![b'a'; MAX_PASSWORD];
    assert_eq!(run(&shadow, &["u"], &max).0, i32::from(EXIT_MISMATCH));
}

#[test]
fn usage_errors_are_exit_2_before_anything_is_read() {
    let dir = tempfile::tempdir().unwrap();
    let shadow = shadow_with(dir.path(), &[("u", YESCRYPT)]);
    for args in [
        vec![],
        vec!["u", "extra"],
        vec![""],
        vec!["a:b"],
        vec!["a\nb"],
    ] {
        let (code, out, _) = run(&shadow, &args, YESCRYPT_PW.as_bytes());
        assert_eq!(code, i32::from(EXIT_USAGE), "{args:?}");
        assert!(out.is_empty());
    }
    // Not UTF-8.
    use std::os::unix::ffi::OsStrExt;
    let out = Command::new(env!("CARGO_BIN_EXE_hx-pwcheck"))
        .arg(std::ffi::OsStr::from_bytes(b"\xff\xfe"))
        .env("HX_PWCHECK_SHADOW", &shadow)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(i32::from(EXIT_USAGE)));
}

#[test]
fn nothing_is_printed_on_stdout_and_no_secret_on_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let shadow = shadow_with(dir.path(), &[("u", YESCRYPT), ("l", "!")]);
    for (user, pw) in [("u", YESCRYPT_PW), ("u", "wrong-password-xyz"), ("l", "pw")] {
        let (_, out, err) = run(&shadow, &[user], pw.as_bytes());
        assert!(out.is_empty(), "stdout: {out:?}");
        assert!(!err.contains(pw) || pw.len() < 3, "stderr: {err}");
        assert!(
            !err.contains(YESCRYPT) && !err.contains("$y$"),
            "stderr: {err}"
        );
    }
}
