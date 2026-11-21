//! Source-level and binary-level rules for `hx-pwcheck`: `unsafe` lives in exactly one audited
//! module, the test-only shadow path cannot reach a release build, and libcrypt is linked
//! dynamically.

use std::path::Path;

fn src(name: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(name)).unwrap()
}

fn code_lines(text: &str) -> Vec<&str> {
    text.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect()
}

/// `unsafe` code is confined to the files named here, each with exactly one
/// `allow(unsafe_code)` and every `unsafe` block under a `// SAFETY:` comment. A new file that
/// needs `unsafe` must be added on purpose, in review.
#[test]
fn unsafe_code_is_confined_to_the_audited_ffi_module() {
    const ALLOWED: [&str; 1] = ["crypt.rs"];
    let mut found = Vec::new();
    for entry in std::fs::read_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("src")).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        let text = src(&name);
        let code = code_lines(&text);
        let allows = code
            .iter()
            .filter(|l| l.contains("allow(unsafe_code)"))
            .count();
        let blocks = code.iter().filter(|l| l.contains("unsafe {")).count();
        let externs = code.iter().filter(|l| l.contains("unsafe extern")).count();
        if ALLOWED.contains(&name.as_str()) {
            assert_eq!(allows, 1, "{name}: exactly one allow(unsafe_code)");
            let safety = text.matches("// SAFETY:").count();
            assert!(
                blocks >= 1 && safety >= blocks,
                "{name}: every unsafe block needs a SAFETY comment"
            );
            found.push(name);
        } else {
            assert!(
                allows == 0 && blocks == 0 && externs == 0,
                "{name} may not contain unsafe code"
            );
        }
    }
    assert_eq!(found, ALLOWED);
    // The one FFI declaration is crypt_rn: nothing else is imported from libcrypt.
    let ffi = src("crypt.rs");
    let imports: Vec<&str> = code_lines(&ffi)
        .into_iter()
        .filter(|l| l.trim_start().starts_with("fn ") && l.trim_end().ends_with("("))
        .collect();
    assert_eq!(imports.len(), 1, "{imports:?}");
    assert!(imports[0].contains("crypt_rn"));
}

#[test]
fn the_library_denies_and_the_binary_forbids_unsafe() {
    assert!(src("lib.rs").contains("#![deny(unsafe_code)]"));
    assert!(src("main.rs").contains("#![forbid(unsafe_code)]"));
}

/// The shadow path override exists only behind the test feature, and the feature is off by
/// default, so a release build never reads the environment.
#[test]
fn the_shadow_path_override_is_test_feature_only() {
    let lib = src("lib.rs");
    let guard = lib
        .find("#[cfg(feature = \"test-shadow-path\")]")
        .expect("override is behind the feature");
    let env_read = lib.find("HX_PWCHECK_SHADOW\")").expect("override exists");
    assert!(guard < env_read && env_read - guard < 120, "guarded read");
    assert_eq!(lib.matches("HX_PWCHECK_SHADOW\")").count(), 1);
    for name in ["main.rs", "crypt.rs"] {
        assert!(!src(name).contains("HX_PWCHECK_SHADOW"), "{name}");
        assert!(
            !src(name).contains("env::var"),
            "{name} reads the environment"
        );
    }
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    assert!(manifest.contains("test-shadow-path = []"));
    assert!(!manifest.contains("default ="), "no default features");
    // Only the crate's own dev-dependency turns it on.
    let deps = manifest.split("[dev-dependencies]").collect::<Vec<_>>();
    assert_eq!(deps.len(), 2);
    assert!(!deps[0].contains("features = [\"test-shadow-path\"]"));
}

/// libcrypt is a dynamic dependency named by its soname (libcrypt1, which is Essential), not
/// linked statically.
#[test]
fn libcrypt_is_linked_dynamically_by_soname() {
    let exe = std::fs::read(env!("CARGO_BIN_EXE_hx-pwcheck")).unwrap();
    let has = |needle: &[u8]| exe.windows(needle.len()).any(|w| w == needle);
    assert!(has(b"libcrypt.so.1"), "DT_NEEDED libcrypt.so.1");
    // A statically linked libxcrypt would carry its own scheme implementations.
    let out = std::process::Command::new("ldd")
        .arg(env!("CARGO_BIN_EXE_hx-pwcheck"))
        .output();
    if let Ok(out) = out {
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("libcrypt.so.1"), "{text}");
    }
}

/// The password is read from fd 0 straight into a wiped buffer, never through `std`'s stdin
/// buffer (8 KiB, never wiped).
#[test]
fn the_password_does_not_pass_through_stds_stdin_buffer() {
    let main = src("main.rs");
    assert!(main.contains("RawStdin"));
    for name in ["main.rs", "lib.rs", "crypt.rs"] {
        let text = src(name);
        assert!(
            !code_lines(&text)
                .iter()
                .any(|l| l.contains("std::io::stdin(")),
            "{name} uses std::io::stdin"
        );
    }
}

/// A reader that hands out one byte at a time and interrupts once: the password is still
/// assembled, bounded, and an over-long one is a "too long" answer.
#[test]
fn read_password_handles_short_reads_and_the_bound() {
    use std::io::{ErrorKind, Read};
    struct Dribble<'a>(&'a [u8], bool);
    impl Read for Dribble<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !std::mem::replace(&mut self.1, true) {
                return Err(ErrorKind::Interrupted.into());
            }
            let n = self.0.len().min(1).min(buf.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }
    let p = hx_pwcheck::read_password(Dribble(b"abc", false))
        .unwrap()
        .unwrap();
    assert_eq!(p.as_slice(), b"abc");
    let max = vec![b'a'; hx_pwcheck::MAX_PASSWORD];
    let p = hx_pwcheck::read_password(Dribble(&max, false))
        .unwrap()
        .unwrap();
    assert_eq!(p.len(), hx_pwcheck::MAX_PASSWORD);
    let over = vec![b'a'; hx_pwcheck::MAX_PASSWORD + 1];
    assert!(
        hx_pwcheck::read_password(Dribble(&over, false))
            .unwrap()
            .is_none()
    );
    assert!(
        hx_pwcheck::read_password(std::io::empty())
            .unwrap()
            .unwrap()
            .is_empty()
    );
}
