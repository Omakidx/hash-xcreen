//! `hx-imagectl`: the image CI tool of the prebuilt desktop images (docs/architecture.md 4.3, 12
//! and 13; docs/ipc.md 6.12 "Images manifest"). CI only: it is never shipped and never runs on a
//! user's server.
//!
//! ```text
//! hx-imagectl digest (--recipe R | --all)
//! hx-imagectl build-image --recipe R --build-id B --out DIR [--prefix hxci] [--min-agent V]
//!                         [--pool-gib N] [--cpu N] [--memory-mib N]
//! hx-imagectl desktop --recipe R --path build|prebuilt [--image F] --user U --password-file P
//!                     --facts OUT [--prefix hxci] [--pool-gib N] [--cpu N] [--memory-mib N] [--keep]
//! hx-imagectl compare A.json B.json --recipe R
//! hx-imagectl manifest [--entries DIR...] [--previous M --previous-sig S --pubkey K...]
//!                      [--wanted FILE] [--drop RECIPE/BUILD_ID...] --timestamp T --out M
//! hx-imagectl verify --manifest M --sig S --pubkey K... [--image F]
//! hx-imagectl cleanup [--prefix hxci]
//! ```
//!
//! Exit status: 0 success; 1 the answer is "no" (drift between the desktops, a manifest, signature
//! or image that does not verify); 2 usage; 3 something broke while running. See the `--help` text.
//!
//! The manifest rules, the build digest, the seal step and the equivalence comparison all live in
//! `hx-provision`, shared with `hx-privd`, so the publisher and the verifier cannot disagree.

#![forbid(unsafe_code)]

pub mod args;
pub mod build;
pub mod cleanup;
pub mod compare;
pub mod desktop;
pub mod devproxy;
pub mod host;
pub mod manifest;
pub mod sign;
pub mod util;

use std::process::ExitCode;

use args::{Parsed, Spec};
use hx_provision::RecipeId;
use hx_provision::images;
use util::{CliError, default_plan, recipe};

const HELP: &str = "\
hx-imagectl: build, compare, manifest and verify the prebuilt desktop images (CI only)

  digest (--recipe R | --all)              print `<recipe> <build digest>`
  build-image --recipe R --build-id B --out DIR [--prefix hxci] [--min-agent V]
              [--pool-gib N] [--cpu N] [--memory-mib N]
                                           build, seal, publish (zstd), export, split, write DIR/entry.json
  desktop --recipe R --path build|prebuilt [--image F] --user U --password-file P --facts OUT
          [--prefix hxci] [--pool-gib N] [--cpu N] [--memory-mib N] [--keep]
                                           create a desktop on one path and write its facts
  compare A.json B.json --recipe R         equivalence check; the table goes to stdout, exit 1 on drift
  manifest [--entries DIR...] [--previous M --previous-sig S --pubkey K...] [--wanted FILE]
           [--drop RECIPE/BUILD_ID...] --timestamp T --out M
                                           build the images manifest (signed with minisign afterwards);
                                           --drop withdraws published images, with no --entries it re-signs
  verify --manifest M --sig S --pubkey K... [--image F]
                                           verify the signature, the trusted comment, the rules and an image file
  cleanup [--prefix hxci]                  remove the objects created under the prefix (local runs)

Exit status: 0 ok, 1 drift or verification refused, 2 usage, 3 failure while running.
Incus: HX_INCUS_SOCKET (default /var/lib/incus/unix.socket). HX_IMAGECTL_DEV_PROXY=1 is for local
development behind a Docker host only (see src/devproxy.rs); it caches one proxied copy per base
image, and `cleanup` removes them all.
";

/// `digest`: one line per recipe.
fn digest(p: &Parsed) -> Result<String, CliError> {
    let ids: Vec<RecipeId> = match (p.get("recipe"), p.flag("all")) {
        (Some(r), false) => vec![recipe(r)?],
        (None, true) => RecipeId::all(),
        _ => {
            return Err(CliError::Usage(
                "give exactly one of --recipe R and --all".into(),
            ));
        }
    };
    let mut out = String::new();
    for id in ids {
        out.push_str(&format!(
            "{} {}\n",
            images::recipe_name(id),
            default_plan(id)?.build_digest()
        ));
    }
    Ok(out)
}

const DIGEST_SPEC: Spec = Spec {
    values: &["recipe"],
    lists: &[],
    flags: &["all"],
    positionals: 0,
};

async fn dispatch(cmd: &str, rest: &[String]) -> Result<String, CliError> {
    match cmd {
        "digest" => digest(&Parsed::parse(&DIGEST_SPEC, rest)?),
        "build-image" => {
            build::run(&Parsed::parse(&build::SPEC, rest)?).await?;
            Ok(String::new())
        }
        "desktop" => {
            desktop::run(&Parsed::parse(&desktop::SPEC, rest)?).await?;
            Ok(String::new())
        }
        "compare" => compare::run(&Parsed::parse(&compare::SPEC, rest)?),
        "manifest" => manifest::run_manifest(&Parsed::parse(&manifest::MANIFEST_SPEC, rest)?),
        "verify" => manifest::run_verify(&Parsed::parse(&manifest::VERIFY_SPEC, rest)?),
        "cleanup" => cleanup::run(&Parsed::parse(&cleanup::SPEC, rest)?).await,
        other => Err(CliError::Usage(format!(
            "unknown command `{other}` (try --help)"
        ))),
    }
}

/// Run the tool with the words after the program name. Command output goes to stdout, progress
/// and errors to stderr.
pub fn main_with_args(args: Vec<String>) -> ExitCode {
    let Some((cmd, rest)) = args.split_first() else {
        eprint!("{HELP}");
        return ExitCode::from(2);
    };
    if matches!(cmd.as_str(), "--help" | "-h" | "help") {
        print!("{HELP}");
        return ExitCode::SUCCESS;
    }
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("hx-imagectl: cannot start the runtime: {e}");
            return ExitCode::from(3);
        }
    };
    match rt.block_on(dispatch(cmd, rest)) {
        Ok(out) => {
            print!("{out}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("hx-imagectl {cmd}: {}", e.message());
            ExitCode::from(e.exit_code())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn digest_prints_one_line_per_recipe() {
        let p = Parsed::parse(&DIGEST_SPEC, &w("--all")).unwrap();
        let out = digest(&p).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 8);
        for l in &lines {
            let (name, d) = l.split_once(' ').unwrap();
            assert!(images::recipe_by_name(name).is_some(), "{l}");
            assert_eq!(d.len(), 64);
        }
        let one =
            digest(&Parsed::parse(&DIGEST_SPEC, &w("--recipe ubuntu-24.04-xfce-basic")).unwrap())
                .unwrap();
        assert!(out.contains(one.trim_end()));
    }

    #[test]
    fn digest_needs_exactly_one_selector() {
        for bad in ["", "--all --recipe ubuntu-24.04-xfce-basic"] {
            let p = Parsed::parse(&DIGEST_SPEC, &w(bad)).unwrap();
            assert!(matches!(digest(&p), Err(CliError::Usage(_))), "{bad}");
        }
    }
}
