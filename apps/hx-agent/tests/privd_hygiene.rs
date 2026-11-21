//! Source-level rules that keep secrets and `unsafe` where docs/ipc.md and the review say.

use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

fn sources(sub: &str) -> Vec<(PathBuf, String)> {
    let mut v = Vec::new();
    rust_files(&Path::new(env!("CARGO_MANIFEST_DIR")).join(sub), &mut v);
    v.into_iter()
        .map(|p| {
            let s = std::fs::read_to_string(&p).unwrap();
            (p, s)
        })
        .collect()
}

/// L2: a secret's bytes are borrowed (`&str`, `&[u8]`) and moved into `Zeroizing` owners, never
/// copied into a `String` or `Vec` that nothing wipes.
#[test]
fn l2_secret_bytes_are_never_copied_into_unzeroized_owners() {
    for (path, text) in sources("src/privd") {
        if path.ends_with("testing.rs") {
            continue;
        }
        let code = text.split("#[cfg(test)]").next().unwrap_or(&text);
        for (n, line) in code.lines().enumerate() {
            if line.trim_start().starts_with("//") || !line.contains("expose()") {
                continue;
            }
            for bad in [
                "to_string",
                "to_owned",
                "String::from",
                "to_vec",
                "from_utf8_lossy",
                "format!",
                ".clone()",
                "into_owned",
            ] {
                assert!(
                    !line.contains(bad),
                    "{}:{}: `{bad}` next to `expose()`: {line}",
                    path.display(),
                    n + 1
                );
            }
        }
    }
}

/// N1: `unsafe` lives only in the files named here, each with exactly one `allow(unsafe_code)`
/// and every `unsafe` block under it commented with `SAFETY:`. A new file that needs `unsafe`
/// must be added to this list on purpose, in review.
#[test]
fn n1_unsafe_code_is_confined_to_the_audited_modules() {
    const ALLOWED: [&str; 3] = [
        "cli/sigblock.rs",
        "privd/activation.rs",
        "privd/peergroups.rs",
    ];
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    for (path, text) in sources("src") {
        let rel = path
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let code: Vec<&str> = text
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect();
        let allows = code
            .iter()
            .filter(|l| l.contains("allow(unsafe_code)"))
            .count();
        let blocks = code.iter().filter(|l| l.contains("unsafe {")).count();
        if allows > 0 || blocks > 0 {
            found.push((rel.clone(), allows, blocks));
        }
        if ALLOWED.contains(&rel.as_str()) {
            assert_eq!(allows, 1, "{rel}: exactly one allow(unsafe_code)");
            let safety = text.matches("// SAFETY:").count();
            assert!(
                blocks >= 1 && safety >= blocks,
                "{rel}: every unsafe block needs a SAFETY comment"
            );
        } else {
            assert!(
                allows == 0 && blocks == 0,
                "{rel} may not contain unsafe code"
            );
        }
    }
    let mut names: Vec<&str> = found.iter().map(|f| f.0.as_str()).collect();
    names.sort_unstable();
    assert_eq!(
        names, ALLOWED,
        "exactly the audited files contain unsafe code"
    );
}

/// N1: the daemon binary itself forbids unsafe code and adopts the socket before it builds a
/// runtime (no thread can have opened descriptor 3 by then).
#[test]
fn n1_the_binary_forbids_unsafe_and_adopts_the_socket_before_the_runtime() {
    let bin =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bin/hx-privd.rs"))
            .unwrap();
    assert!(bin.contains("#![forbid(unsafe_code)]"));
    let adopt = bin.find("activation::from_env").expect("adopts the socket");
    let runtime = bin
        .find("tokio::runtime::Builder")
        .expect("builds a runtime");
    assert!(
        adopt < runtime,
        "from_env must run before the runtime exists"
    );
}
