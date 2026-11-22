//! The `install`, `port-rule` and `uninstall` commands through the real CLI entry (`cli::run`):
//! parsing, the exit codes that need no host (usage 2, not root 7, lock 11, conflict 12), the
//! JSON Lines output, and the rule that a non-production configuration never reaches the host.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use hx_agent::cli::{Config, Env};
use hx_agent::install::options::Options;
use hx_agent::install::state::{self, InstallState};
use hx_agent::install::testing::ScriptedTty;

struct Run {
    code: u8,
    out: String,
    err: String,
}

fn config(dir: &Path) -> Config {
    Config {
        privd_socket: dir.join("privd.sock"),
        admin_socket: dir.join("admin.sock"),
        audit_log: dir.join("audit.log"),
        audit_owner_uid: 0,
        journalctl: dir.join("no-journalctl"),
        expected_peer_uid: rustix::process::getuid().as_raw(),
        verifier_params: hx_crypto::PinParams {
            memory_kib: 64,
            iterations: 1,
            parallelism: 1,
        },
    }
}

fn cli_as(dir: &Path, euid: u32, args: &[&str], tty: ScriptedTty) -> Run {
    let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut tty = tty;
    let code = {
        let mut env = Env {
            config: config(dir),
            euid,
            out: &mut out,
            err: &mut err,
            prompt: &mut tty,
            stop: Arc::new(AtomicBool::new(false)),
            now: || 1_800_000_000,
            json: false,
        };
        hx_agent::cli::run(&args, &mut env)
    };
    Run {
        code,
        out: String::from_utf8_lossy(&out).into_owned(),
        err: String::from_utf8_lossy(&err).into_owned(),
    }
}

fn cli(dir: &Path, args: &[&str]) -> Run {
    cli_as(dir, 0, args, ScriptedTty::default())
}

fn root(dir: &Path) -> PathBuf {
    dir.join("root")
}

fn last_json(r: &Run) -> serde_json::Value {
    r.out
        .lines()
        .rev()
        .find_map(|l| serde_json::from_str(l).ok())
        .unwrap_or(serde_json::Value::Null)
}

// ----- parsing --------------------------------------------------------------------------------

#[test]
fn usage_errors_exit_2_before_anything_else() {
    let d = tempfile::tempdir().unwrap();
    for args in [
        vec!["install", "--interactive", "--pair"],
        vec!["install", "--pair", "--ssh"],
        vec!["install", "--pair", "--token", "hxt1-x"],
        vec!["install", "--token", "hxt1-x"],
        vec!["install", "--pair", "--token-on-command-line"],
        vec!["install", "--password", "x"],
        vec!["install", "--pin=123456"],
        vec!["install", "--frobnicate"],
        vec!["install", "extra"],
        vec!["install", "--pair", "--bootstrap-dir", "relative"],
        vec!["install", "--pair", "--lock-fd", "1"],
        vec!["install", "--pair", "--lock-fd", "x"],
        vec!["install", "--pair", "--test-fail-after", "nosuch"],
        vec!["install", "--pair", "--port"],
        vec!["port-rule"],
        vec!["port-rule", "frob"],
        vec!["__empty-dir", "relative"],
    ] {
        let r = cli(d.path(), &args);
        assert_eq!(r.code, 2, "{args:?}: {}", r.err);
        assert!(
            r.err.starts_with("hx-agent: error: "),
            "{args:?}: {}",
            r.err
        );
    }
    // The text of an unexpected argument (a secret typed in the wrong place) is never shown.
    let r = cli(d.path(), &["install", "SuperSecretWord"]);
    assert!(!r.err.contains("SuperSecretWord") && !r.out.contains("SuperSecretWord"));
}

#[test]
fn values_are_validated_and_reported_as_json_when_asked() {
    let d = tempfile::tempdir().unwrap();
    for (args, needle) in [
        (
            vec!["install", "--pair", "--port", "22", "--json"],
            "--port",
        ),
        (
            vec!["install", "--pair", "--distro", "ubuntu-22.04", "--json"],
            "--distro",
        ),
        (
            vec!["install", "--pair", "--memory", "lots", "--json"],
            "--memory",
        ),
        (
            vec!["install", "--pair", "--image", "x", "--json"],
            "--image",
        ),
    ] {
        let r = cli(d.path(), &args);
        assert_eq!(r.code, 2, "{args:?}");
        let v = last_json(&r);
        assert_eq!(v["t"], "result");
        assert_eq!(v["ok"], false);
        assert_eq!(v["code"], "USAGE");
        assert!(v["message"].as_str().unwrap().contains(needle));
    }
}

#[test]
fn a_fresh_host_without_a_mode_is_exit_2() {
    let d = tempfile::tempdir().unwrap();
    let r = cli(d.path(), &["install", "--json"]);
    assert_eq!(r.code, 2);
    assert!(
        last_json(&r)["message"]
            .as_str()
            .unwrap()
            .contains("needs a mode")
    );
}

#[test]
fn ssh_implies_json_and_refuses_a_stdin_without_the_magic() {
    let d = tempfile::tempdir().unwrap();
    let r = cli(d.path(), &["install", "--ssh", "--user", "alice"]);
    assert_eq!(r.code, 2, "{}", r.err);
    let v = last_json(&r);
    assert_eq!(v["t"], "result", "JSON Lines without --json: {}", r.out);
    assert_eq!(v["ok"], false);
}

#[test]
fn install_needs_root_and_says_so_in_json() {
    let d = tempfile::tempdir().unwrap();
    let r = cli_as(
        d.path(),
        1000,
        &["install", "--pair", "--json"],
        ScriptedTty::default(),
    );
    assert_eq!(r.code, 7);
    assert_eq!(last_json(&r)["code"], "NOT_ROOT");
    let r = cli_as(
        d.path(),
        1000,
        &["install", "--pair"],
        ScriptedTty::default(),
    );
    assert_eq!(r.code, 7);
    assert!(r.err.contains("must run as root"));
    assert!(r.out.is_empty());
    // port-rule and uninstall need it too.
    assert_eq!(
        cli_as(
            d.path(),
            1000,
            &["port-rule", "apply"],
            ScriptedTty::default()
        )
        .code,
        7
    );
    assert_eq!(
        cli_as(
            d.path(),
            1000,
            &["uninstall", "--keep-desktop", "--yes"],
            ScriptedTty::default()
        )
        .code,
        7
    );
}

#[test]
fn help_describes_install_and_the_new_exit_codes() {
    let d = tempfile::tempdir().unwrap();
    let r = cli(d.path(), &["help"]);
    for needle in [
        "install --interactive | --pair | --ssh | --token",
        "port-rule apply",
        "9 preflight failed",
        "11 another install",
        "12 the options conflict",
    ] {
        assert!(r.out.contains(needle), "{needle}:\n{}", r.out);
    }
    let r = cli(d.path(), &["install", "--help"]);
    assert_eq!(r.code, 0);
    assert!(r.out.contains("--storage-device") && !r.out.contains("devices revoke"));
    assert!(r.out.contains("WEAKER"));
}

#[test]
fn the_test_flags_exist_only_with_the_feature_and_are_documented_nowhere() {
    // This test crate builds hx-agent with `install-test-hooks`; the flags parse, the help hides them.
    let d = tempfile::tempdir().unwrap();
    let r = cli(d.path(), &["help", "install"]);
    assert!(!r.out.contains("test-fail-after") && !r.out.contains("test-allow-container"));
}

// ----- exit codes that need the root directory ---------------------------------------------------

#[test]
fn a_held_lock_is_exit_11() {
    let d = tempfile::tempdir().unwrap();
    let lock = root(d.path()).join("run/hx-install.lock");
    let held = hx_agent::install::lock::acquire(&lock, None).unwrap();
    let r = cli(d.path(), &["install", "--pair", "--json"]);
    assert_eq!(r.code, 11, "{}", r.err);
    assert_eq!(last_json(&r)["code"], "LOCKED");
    let r = cli(
        d.path(),
        &["uninstall", "--keep-desktop", "--yes", "--json"],
    );
    assert_eq!(r.code, 11, "{}{}", r.out, r.err);
    drop(held);
}

fn write_state(d: &Path, user: &str, desktop_done: bool) {
    let opts = Options {
        user: Some(user.into()),
        ..Options::default()
    };
    let mut st = InstallState::new("0".repeat(32), "ssh", opts, 1);
    if desktop_done {
        st.record("desktop", "done", 2, None);
    }
    state::save(&root(d).join("var/lib/hx/install-state.json"), &st).unwrap();
}

#[test]
fn options_that_conflict_with_the_recorded_install_are_exit_12() {
    let d = tempfile::tempdir().unwrap();
    write_state(d.path(), "alice", true);
    // The conflict is found before stdin is read or any tool runs.
    let r = cli(d.path(), &["install", "--ssh", "--user", "bob"]);
    assert_eq!(r.code, 12, "{}{}", r.out, r.err);
    let v = last_json(&r);
    assert_eq!(v["code"], "CONFLICT");
    assert!(v["message"].as_str().unwrap().contains("--user"));
    let r = cli(d.path(), &["install", "--docker", "--json"]);
    assert_eq!(r.code, 12);
    assert!(
        last_json(&r)["message"]
            .as_str()
            .unwrap()
            .contains("docker enable")
    );
    // Before the desktop is ready the same option is not a conflict (it fails later, on the host).
    write_state(d.path(), "alice", false);
    let r = cli(d.path(), &["install", "--user", "bob", "--json"]);
    assert_ne!(r.code, 12);
}

#[test]
fn a_non_production_configuration_never_reaches_the_host() {
    let d = tempfile::tempdir().unwrap();
    let token = hx_crypto::PairingToken::generate()
        .unwrap()
        .to_text()
        .to_string();
    let r = cli_as(
        d.path(),
        0,
        &["install", "--pair", "--json"],
        ScriptedTty::new(&[], &[token.as_bytes()]),
    );
    assert_eq!(r.code, 9, "{}{}", r.out, r.err);
    let v = last_json(&r);
    assert_eq!(v["code"], "PREFLIGHT");
    let m = v["message"].as_str().unwrap();
    assert!(
        m.contains("cannot run systemctl") || m.contains("not supported"),
        "{m}"
    );
    assert!(
        !root(d.path())
            .join("var/lib/hx/install-state.json")
            .exists(),
        "nothing recorded"
    );
    assert!(!r.out.contains(&token) && !r.err.contains(&token));
}

#[test]
fn port_rule_apply_reads_the_recorded_backend() {
    let d = tempfile::tempdir().unwrap();
    let r = cli(d.path(), &["port-rule", "apply"]);
    assert_eq!(r.code, 1);
    assert!(r.err.contains("no install state"));
    write_state(d.path(), "alice", true);
    let r = cli(d.path(), &["port-rule", "apply", "--json"]);
    assert_eq!(r.code, 0);
    assert_eq!(last_json(&r)["data"]["backend"], "none");
    let mut st = state::load(&root(d.path()).join("var/lib/hx/install-state.json"))
        .unwrap()
        .unwrap();
    st.created.port_rule = Some(state::PortRule {
        backend: "ufw".into(),
        port: 443,
        ..Default::default()
    });
    state::save(&root(d.path()).join("var/lib/hx/install-state.json"), &st).unwrap();
    let r = cli(d.path(), &["port-rule", "apply", "--json"]);
    assert_eq!(r.code, 0);
    assert_eq!(last_json(&r)["data"]["applied"], false);
}

#[test]
fn the_cleaning_child_empties_a_tree_without_following_links() {
    let d = tempfile::tempdir().unwrap();
    let tree = d.path().join("g");
    std::fs::create_dir_all(tree.join("a")).unwrap();
    std::fs::write(tree.join("a/f"), b"1").unwrap();
    let outside = d.path().join("o");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("keep"), b"1").unwrap();
    std::os::unix::fs::symlink(&outside, tree.join("l")).unwrap();
    // It needs no root check: it runs as the gateway's user.
    let r = cli_as(
        d.path(),
        1234,
        &["__empty-dir", tree.to_str().unwrap()],
        ScriptedTty::default(),
    );
    assert_eq!(r.code, 0);
    assert!(std::fs::read_dir(&tree).unwrap().next().is_none());
    assert!(outside.join("keep").exists());
    let r = cli(
        d.path(),
        &["__empty-dir", d.path().join("missing").to_str().unwrap()],
    );
    assert_eq!(r.code, 1);
}

#[test]
fn uninstall_without_a_reachable_privd_prints_the_manual_steps_and_changes_nothing() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root(d.path()).join("usr/lib/hx")).unwrap();
    let r = cli_as(
        d.path(),
        0,
        &["uninstall", "--destroy-desktop", "--yes", "--json"],
        ScriptedTty::default(),
    );
    assert_eq!(r.code, 6, "{}{}", r.out, r.err);
    let v = last_json(&r);
    assert_eq!(v["ok"], false);
    assert_eq!(v["data"]["uninstalled"], false);
    assert_eq!(
        v["data"]["implemented"], true,
        "privd is unreachable, not unimplemented"
    );
    assert!(v["data"]["manual_steps"].as_array().unwrap().len() >= 5);
    assert!(
        root(d.path()).join("usr/lib/hx").exists(),
        "nothing was removed"
    );
}

#[test]
fn uninstall_still_asks_before_it_does_anything() {
    let d = tempfile::tempdir().unwrap();
    let r = cli_as(
        d.path(),
        0,
        &["uninstall", "--destroy-desktop"],
        ScriptedTty::new(&["no"], &[]),
    );
    assert_eq!(r.code, 8);
    let r = cli_as(d.path(), 0, &["uninstall", "--yes"], ScriptedTty::default());
    assert_eq!(
        r.code, 2,
        "--yes needs a mode: deleting the desktop is never the default"
    );
}
