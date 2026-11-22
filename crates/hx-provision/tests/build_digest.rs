//! `Plan::build_digest`: stable, discriminating, golden.

use std::collections::BTreeSet;
use std::path::Path;

use hx_provision::{Catalog, Plan, RecipeId, Step};

fn plan(id: RecipeId) -> Plan {
    Catalog::embedded()
        .resolve(id, &[])
        .unwrap_or_else(|e| panic!("{}: {e}", id.file_name()))
}

#[test]
fn build_digest_is_stable_and_discriminating() {
    let mut seen = BTreeSet::new();
    for rid in RecipeId::all() {
        let p = plan(rid);
        let d = p.build_digest();
        assert_eq!(d.len(), 64);
        assert!(
            d.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        assert_eq!(d, p.build_digest(), "deterministic");
        assert!(seen.insert(d), "digests are unique per recipe");
    }
    // The post stage is not part of the digest; the build stage is.
    let mut p = plan(RecipeId::all()[0]);
    let d = p.build_digest();
    p.post.push(Step::SecurityUpdates);
    assert_eq!(d, p.build_digest());
    p.build.push(Step::SecurityUpdates);
    assert_ne!(d, p.build_digest());
}

/// Golden digests of every shipped recipe. A change here means every published prebuilt image
/// stops matching: update only on purpose, with `HX_UPDATE_GOLDEN=1`.
#[test]
fn build_digest_golden() {
    let mut out = String::new();
    for rid in RecipeId::all() {
        out.push_str(&format!(
            "{} {}\n",
            rid.file_name().trim_end_matches(".toml"),
            plan(rid).build_digest()
        ));
    }
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/build-digests.txt");
    if std::env::var_os("HX_UPDATE_GOLDEN").is_some() {
        std::fs::write(&path, &out).unwrap();
        return;
    }
    let want = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e} (run with HX_UPDATE_GOLDEN=1)", path.display()));
    assert_eq!(
        want, out,
        "build digests changed: every published image stops matching; rerun with HX_UPDATE_GOLDEN=1 only on purpose"
    );
}
