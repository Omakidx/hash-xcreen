//! The command line of `hx-gatewayd`, parsed in the library so that it can be tested.
//!
//! `--admin-allow-uid <uid>` lets one unprivileged uid use the admin socket. It exists only for
//! tests that cannot run as root, and only in a binary built with the Cargo feature
//! `gateway-test-hooks` (the crate's own tests enable it through a dev-dependency on itself).
//! A production build does not recognise the flag at all: it is an unknown argument.
//!
//! `--link-socket <path>` (same feature) replaces the link socket after the configuration is
//! validated, for a test that cannot create `/run/hx/link` (it needs root) but runs the real
//! binary against privd's real proxy device. The configuration file's own `link_socket` keeps its
//! `/run/hx/link/` check; only this flag, absent from a production build, bypasses it.

use std::path::PathBuf;

/// The default configuration file.
pub const DEFAULT_CONFIG: &str = "/etc/hx/gatewayd.toml";

/// What the command line asked for.
#[derive(Debug, PartialEq, Eq)]
pub struct Args {
    /// The configuration file.
    pub config: PathBuf,
    /// Test builds only: one uid that may use the admin socket besides root.
    pub admin_allow_uid: Option<u32>,
    /// Test builds only: the link socket to dial instead of `/run/hx/link/<desktop_id>.sock`.
    pub link_socket: Option<PathBuf>,
    /// `--version` was given.
    pub version: bool,
}

/// Parses `args` (without the program name). `test_hooks` says whether this build has the
/// `gateway-test-hooks` feature; without it the test-only flags are unknown arguments.
pub fn parse_args<I: IntoIterator<Item = String>>(
    args: I,
    test_hooks: bool,
) -> Result<Args, String> {
    let mut out = Args {
        config: DEFAULT_CONFIG.into(),
        admin_allow_uid: None,
        link_socket: None,
        version: false,
    };
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--config" => out.config = it.next().ok_or("--config needs a path")?.into(),
            "--admin-allow-uid" if test_hooks => {
                let v = it.next().ok_or("--admin-allow-uid needs a uid")?;
                out.admin_allow_uid = Some(v.parse().map_err(|_| "bad uid")?);
            }
            "--link-socket" if test_hooks => {
                let v = PathBuf::from(it.next().ok_or("--link-socket needs a path")?);
                if !v.is_absolute() {
                    return Err("--link-socket needs an absolute path".into());
                }
                out.link_socket = Some(v);
            }
            "--version" => out.version = true,
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn a_production_build_rejects_the_test_only_flag() {
        let e = parse_args(args(&["--admin-allow-uid", "1000"]), false).unwrap_err();
        assert!(e.contains("unknown argument"), "{e}");
        // Whatever else is given, the flag never takes effect.
        assert!(parse_args(args(&["--config", "/x", "--admin-allow-uid", "0"]), false).is_err());
        let e = parse_args(args(&["--link-socket", "/tmp/l.sock"]), false).unwrap_err();
        assert!(e.contains("unknown argument"), "{e}");
    }

    #[test]
    fn a_test_build_accepts_it() {
        let a = parse_args(args(&["--config", "/x", "--admin-allow-uid", "1000"]), true).unwrap();
        assert_eq!(a.admin_allow_uid, Some(1000));
        assert_eq!(a.config, PathBuf::from("/x"));
        assert!(parse_args(args(&["--admin-allow-uid", "nope"]), true).is_err());
        assert!(parse_args(args(&["--admin-allow-uid"]), true).is_err());
        let l = parse_args(args(&["--link-socket", "/tmp/l.sock"]), true).unwrap();
        assert_eq!(l.link_socket, Some(PathBuf::from("/tmp/l.sock")));
        assert!(parse_args(args(&["--link-socket", "rel.sock"]), true).is_err());
        assert!(parse_args(args(&["--link-socket"]), true).is_err());
    }

    #[test]
    fn the_ordinary_flags_work_in_both() {
        for hooks in [false, true] {
            assert_eq!(
                parse_args(args(&[]), hooks).unwrap().config,
                PathBuf::from(DEFAULT_CONFIG)
            );
            assert!(parse_args(args(&["--version"]), hooks).unwrap().version);
            assert!(parse_args(args(&["--bogus"]), hooks).is_err());
            assert!(parse_args(args(&["--config"]), hooks).is_err());
        }
    }
}
