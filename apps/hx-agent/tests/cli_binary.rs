//! The real `hx-agent` binary: the root check, help, version, usage errors and the JSON error
//! envelope, run with a cleared environment (the binary reads none).

use std::process::{Command, Stdio};

fn run(args: &[&str]) -> (Option<i32>, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_hx-agent"))
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .expect("run hx-agent");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

#[test]
fn a_non_root_user_is_refused_with_a_clear_message() {
    if is_root() {
        eprintln!("running as root: the refusal cannot be shown");
        return;
    }
    for args in [
        vec!["status"],
        vec!["devices", "list"],
        vec!["pairing", "code"],
        vec!["pin", "reset-lockout", "--yes"],
        vec!["uninstall", "--keep-desktop", "--yes"],
        vec!["logs"],
    ] {
        let (code, out, err) = run(&args);
        assert_eq!(code, Some(7), "{args:?}: {err}");
        assert!(err.contains("must run as root"), "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: {out}");
    }
    let (code, out, _) = run(&["status", "--json"]);
    assert_eq!(code, Some(7));
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["code"], "NOT_ROOT");
}

#[test]
fn help_and_version_need_no_privilege() {
    let (code, out, _) = run(&["--version"]);
    assert_eq!(code, Some(0));
    assert_eq!(
        out.trim(),
        format!("hx-agent {}", env!("CARGO_PKG_VERSION"))
    );
    let (code, out, _) = run(&["help"]);
    assert_eq!(code, Some(0));
    for needle in [
        "status",
        "devices revoke",
        "pairing token",
        "pin reset-lockout",
        "setup begin",
        "desktop limits",
        "docker enable",
        "snapshots delete",
        "logs",
        "update apply",
        "uninstall",
        "exit codes",
    ] {
        assert!(out.contains(needle), "{needle:?} missing from help:\n{out}");
    }
    let (code, out, _) = run(&["devices", "--help"]);
    assert_eq!(code, Some(0));
    assert!(out.contains("devices reinstate") && !out.contains("pairing token"));
    let (code, out, _) = run(&[]);
    assert_eq!(code, Some(0));
    assert!(out.contains("usage: hx-agent"));
}

#[test]
fn usage_errors_exit_2_before_the_root_check() {
    for args in [
        vec!["frobnicate"],
        vec!["devices"],
        vec!["devices", "list", "extra"],
        vec!["status", "--bogus"],
        vec!["setup", "begin", "--for", "5"],
        vec!["pin", "set", "--pin", "123456"],
    ] {
        let (code, out, err) = run(&args);
        assert_eq!(code, Some(2), "{args:?}: {err}");
        assert!(err.starts_with("hx-agent: error: "), "{args:?}: {err}");
        assert!(out.is_empty());
    }
    let (code, out, _) = run(&["frobnicate", "--json"]);
    assert_eq!(code, Some(2));
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(v["error"]["code"], "USAGE");
}
