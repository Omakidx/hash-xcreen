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
