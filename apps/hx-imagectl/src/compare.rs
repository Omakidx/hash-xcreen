//! `compare A.json B.json --recipe R`: the equivalence check of the server-built desktop (A) and
//! the prebuilt-path desktop (B). The drift table goes to stdout; any error-level drift exits 1.

use std::path::Path;

use hx_provision::Manifest;
use hx_provision::equiv::{Facts, Severity, compare, has_errors, render_table};

use crate::args::{Parsed, Spec};
use crate::util::{CliError, default_plan, failed, read_bounded, recipe, refused};

/// Options of `compare`.
pub const SPEC: Spec = Spec {
    values: &["recipe"],
    lists: &[],
    flags: &[],
    positionals: 2,
};

/// Largest facts file read: 64 MiB.
const MAX_FACTS: u64 = 64 * 1024 * 1024;

fn load(path: &str) -> Result<Facts, CliError> {
    let bytes = read_bounded(Path::new(path), MAX_FACTS)?;
    serde_json::from_slice(&bytes).map_err(|e| failed(format!("{path} is not a facts file: {e}")))
}

/// Compare the two desktops against the expected manifest. `Ok` carries the table; error-level
/// drift is `Refused`, and the table is printed to stdout first (it is the command's output
/// either way).
pub fn evaluate(a: &Facts, b: &Facts, manifest: &Manifest) -> Result<String, CliError> {
    let drifts = compare(a, b, manifest);
    let table = render_table(&drifts);
    if has_errors(&drifts) {
        print!("{table}");
        let n = drifts
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .count();
        return Err(refused(format!(
            "the desktops are not equivalent: {n} error-level drift(s) of {}",
            drifts.len()
        )));
    }
    Ok(table)
}

/// Run `compare`: returns the table to print.
pub fn run(p: &Parsed) -> Result<String, CliError> {
    let id = recipe(p.require("recipe")?)?;
    let a = load(&p.positional[0])?;
    let b = load(&p.positional[1])?;
    evaluate(&a, &b, &default_plan(id)?.manifest())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hx_provision::equiv::{FACTS_SCHEMA, PackageFact};

    fn facts(packages: &[&str]) -> Facts {
        Facts {
            schema: FACTS_SCHEMA,
            instance: "i".into(),
            user: "alice".into(),
            packages: packages
                .iter()
                .map(|n| PackageFact {
                    name: (*n).into(),
                    arch: "amd64".into(),
                    status: "ii".into(),
                    version: "1".into(),
                })
                .collect(),
            apt_manual: packages.iter().map(|s| (*s).into()).collect(),
            passwd: vec!["alice:x:1000:1000::/home/alice:/bin/bash".into()],
            group: vec!["alice:x:1000:".into()],
            user_groups: vec!["alice".into()],
            system_state: "running".into(),
            ..Facts::default()
        }
    }

    fn manifest(packages: &[&str]) -> Manifest {
        Manifest {
            recipe: "t".into(),
            packages: packages.iter().map(|s| (*s).into()).collect(),
            user: Some("desk".into()),
            ..Manifest::default()
        }
    }

    #[test]
    fn equivalent_desktops_give_the_no_drift_table() {
        let t = evaluate(&facts(&["bash"]), &facts(&["bash"]), &manifest(&["bash"])).unwrap();
        assert!(t.contains("No drift"), "{t}");
    }

    #[test]
    fn a_manual_package_missing_on_one_side_is_refused() {
        let e = evaluate(
            &facts(&["bash", "xfce4"]),
            &facts(&["bash"]),
            &manifest(&["bash"]),
        )
        .unwrap_err();
        assert!(matches!(e, CliError::Refused(_)), "{e:?}");
        assert_eq!(e.exit_code(), 1);
    }

    #[test]
    fn a_missing_file_is_an_operational_failure() {
        let p = Parsed::parse(
            &SPEC,
            &[
                "/nonexistent/a.json".into(),
                "/nonexistent/b.json".into(),
                "--recipe".into(),
                "ubuntu-24.04-xfce-basic".into(),
            ],
        )
        .unwrap();
        assert!(matches!(run(&p), Err(CliError::Failed(_))));
    }
}
