//! `hx-privd-rescue` (design C10): the helper `hx-privd.service` runs through `OnFailure=` when a new
//! privd cannot start. No-op without a pending update, restores `current` otherwise, never writes
//! `updates-state`, refuses a state file that is not exactly what privd writes, and hands over to
//! the old privd's own `resume_update`, which finishes the rollback.
//!
//! `systemctl` is a fake: nothing here starts, stops or resets a unit.

mod privd_update_common;

use std::cell::RefCell;
use std::io;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use hx_agent::privd::rescue::{
    Ctl, MAX_STATE_BYTES, Outcome, Paths, RESET_ARGS, RescueError, START_ARGS, read_pending, run,
};
use hx_agent::privd::state::Flag;
use hx_agent::privd::update::state::UpdateState;
use hx_agent::privd::update::switch::Layout;
use privd_update_common::{Env, install_release};

// ----- fixtures --------------------------------------------------------------------------------

#[derive(Default)]
struct FakeCtl {
    calls: RefCell<Vec<Vec<String>>>,
    reset_fails: bool,
    start_fails: bool,
    start_errors: bool,
}

impl Ctl for FakeCtl {
    fn systemctl(&self, args: &[&str]) -> io::Result<bool> {
        self.calls
            .borrow_mut()
            .push(args.iter().map(|s| (*s).to_string()).collect());
        match args[0] {
            "reset-failed" => Ok(!self.reset_fails),
            _ if self.start_errors => Err(io::Error::other("no systemctl")),
            _ => Ok(!self.start_fails),
        }
    }
}

impl FakeCtl {
    fn calls(&self) -> Vec<Vec<String>> {
        self.calls.borrow().clone()
    }
}

struct Fix {
    _t: tempfile::TempDir,
    paths: Paths,
}

fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// A state directory (0700) and a release directory (0755) with the given versions installed.
fn fix(versions: &[&str]) -> Fix {
    let t = tempfile::tempdir().unwrap();
    let state = t.path().join("state");
    let releases = t.path().join("lib-hx");
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir(&releases).unwrap();
    std::fs::set_permissions(&releases, std::fs::Permissions::from_mode(0o755)).unwrap();
    for v in versions {
        install_release(&releases, v);
    }
    Fix {
        paths: Paths {
            state_dir: state,
            releases_dir: releases,
            owner_uid: euid(),
        },
        _t: t,
    }
}

impl Fix {
    fn state_file(&self) -> PathBuf {
        self.paths.state_dir.join("updates-state")
    }

    fn write_state(&self, json: &str) {
        std::fs::write(self.state_file(), json).unwrap();
        std::fs::set_permissions(self.state_file(), std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }

    fn layout(&self) -> Layout {
        Layout::new(&self.paths.releases_dir)
    }

    fn current(&self) -> Option<String> {
        self.layout().current().unwrap()
    }

    fn previous(&self) -> Option<String> {
        self.layout().previous().unwrap()
    }

    /// `current` is 1.1.0 (the failed update), `previous` 1.0.0, and 1.1.0 is pending.
    fn pending_update(&self) {
        self.layout().switch_to("1.0.0").unwrap();
        self.layout().switch_to("1.1.0").unwrap();
        self.write_state(PENDING);
    }
}

const PENDING: &str = r#"{"highest_by_channel":{"stable":1700000000},"pending":{"version":"1.1.0","previous":"1.0.0","started_unix":1800000000,"attempts":2,"gateway_pid":4242},"future_field":{"kept":true}}"#;

fn bytes_and_mtime(p: &Path) -> (Vec<u8>, std::time::SystemTime) {
    (
        std::fs::read(p).unwrap(),
        std::fs::metadata(p).unwrap().modified().unwrap(),
    )
}

fn untrusted(r: Result<Outcome, RescueError>) -> &'static str {
    match r {
        Err(RescueError::Untrusted(why)) => why,
        other => panic!("expected Untrusted, got {other:?}"),
    }
}

// ----- no-op -----------------------------------------------------------------------------------

#[test]
fn without_a_state_file_it_does_nothing() {
    let f = fix(&["1.0.0", "1.1.0"]);
    f.layout().switch_to("1.1.0").unwrap();
    let ctl = FakeCtl::default();
    assert_eq!(run(&f.paths, &ctl).unwrap(), Outcome::NoPending);
    assert!(ctl.calls().is_empty(), "no unit is touched");
    assert_eq!(f.current().as_deref(), Some("1.1.0"));
    assert!(!f.state_file().exists(), "and it creates nothing");
}

#[test]
fn without_a_state_directory_it_does_nothing() {
    let mut f = fix(&["1.0.0"]);
    f.paths.state_dir = f.paths.state_dir.join("missing");
    let ctl = FakeCtl::default();
    assert_eq!(run(&f.paths, &ctl).unwrap(), Outcome::NoPending);
    assert!(ctl.calls().is_empty());
}

#[test]
fn without_a_pending_update_it_does_nothing_even_if_the_links_look_odd() {
    let f = fix(&["1.0.0", "1.1.0"]);
    f.layout().switch_to("1.0.0").unwrap();
    f.layout().switch_to("1.1.0").unwrap();
    for json in [
        r#"{}"#,
        r#"{"pending":null}"#,
        r#"{"highest_by_channel":{"stable":5},"rolled_back":{"version":"1.1.0","reason":"x","at":1}}"#,
    ] {
        f.write_state(json);
        let before = bytes_and_mtime(&f.state_file());
        let ctl = FakeCtl::default();
        assert_eq!(run(&f.paths, &ctl).unwrap(), Outcome::NoPending, "{json}");
        assert!(ctl.calls().is_empty());
        assert_eq!(f.current().as_deref(), Some("1.1.0"));
        assert_eq!(bytes_and_mtime(&f.state_file()), before);
    }
}

// ----- restore ---------------------------------------------------------------------------------

#[test]
fn a_pending_update_is_rolled_back_by_the_links_and_privd_is_started() {
    let f = fix(&["1.0.0", "1.1.0"]);
    f.pending_update();
    let before = bytes_and_mtime(&f.state_file());
    let ctl = FakeCtl::default();
    assert_eq!(
        run(&f.paths, &ctl).unwrap(),
        Outcome::Restarted {
            restored: true,
            links_untouched: false
        }
    );
    assert_eq!(f.current().as_deref(), Some("1.0.0"));
    assert_eq!(
        f.previous().as_deref(),
        Some("1.1.0"),
        "the failed one is parked"
    );
    // Fixed arguments, in this order: the limit is reset, then the socket and the service start.
    let want: Vec<Vec<String>> = [RESET_ARGS, START_ARGS]
        .iter()
        .map(|a| a.iter().map(|s| (*s).to_string()).collect())
        .collect();
    assert_eq!(ctl.calls(), want);
    assert_eq!(
        want[0],
        ["reset-failed", "hx-privd.service", "hx-privd.socket"]
    );
    assert_eq!(want[1], ["start", "hx-privd.socket", "hx-privd.service"]);
    // updates-state is exactly as it was, including a field this helper does not know.
    assert_eq!(bytes_and_mtime(&f.state_file()), before);
    // No stray file was left in either directory.
    let names: Vec<String> = std::fs::read_dir(&f.paths.state_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["updates-state"]);
}

#[test]
fn a_second_run_changes_nothing_more() {
    let f = fix(&["1.0.0", "1.1.0"]);
    f.pending_update();
    let ctl = FakeCtl::default();
    run(&f.paths, &ctl).unwrap();
    let ctl = FakeCtl::default();
    assert_eq!(
        run(&f.paths, &ctl).unwrap(),
        Outcome::Restarted {
            restored: false,
            links_untouched: false
        }
    );
    assert_eq!(f.current().as_deref(), Some("1.0.0"));
    assert_eq!(f.previous().as_deref(), Some("1.1.0"));
    assert_eq!(ctl.calls().len(), 2, "privd is still started");
}

#[test]
fn an_update_that_was_never_switched_in_only_restarts_privd() {
    let f = fix(&["1.0.0", "1.1.0"]);
    f.layout().switch_to("1.0.0").unwrap();
    f.write_state(PENDING);
    let ctl = FakeCtl::default();
    assert_eq!(
        run(&f.paths, &ctl).unwrap(),
        Outcome::Restarted {
            restored: false,
            links_untouched: false
        }
    );
    assert_eq!(f.current().as_deref(), Some("1.0.0"));
    assert_eq!(ctl.calls().len(), 2);
}

#[test]
fn a_current_link_that_names_an_unrelated_version_is_left_alone() {
    // Someone moved `current` after the update: restoring `previous` could move it backwards.
    let f = fix(&["1.0.0", "1.1.0", "1.2.0"]);
    f.layout().switch_to("1.2.0").unwrap();
    f.write_state(PENDING);
    let ctl = FakeCtl::default();
    assert_eq!(
        run(&f.paths, &ctl).unwrap(),
        Outcome::Restarted {
            restored: false,
            links_untouched: true
        }
    );
    assert_eq!(f.current().as_deref(), Some("1.2.0"));
    assert_eq!(ctl.calls().len(), 2);
}

#[test]
fn a_previous_release_that_is_incomplete_is_not_restored_and_privd_is_not_started() {
    let f = fix(&["1.1.0"]);
    f.layout().switch_to("1.1.0").unwrap();
    std::fs::create_dir(f.paths.releases_dir.join("1.0.0")).unwrap(); // no binaries
    f.write_state(PENDING);
    let ctl = FakeCtl::default();
    assert!(matches!(run(&f.paths, &ctl), Err(RescueError::Layout(_))));
    assert!(ctl.calls().is_empty(), "no point starting what cannot work");
    assert_eq!(f.current().as_deref(), Some("1.1.0"));
}

#[test]
fn a_pending_update_with_no_previous_version_is_an_error_without_side_effects() {
    let f = fix(&["1.1.0"]);
    f.layout().switch_to("1.1.0").unwrap();
    f.write_state(r#"{"pending":{"version":"1.1.0","previous":null,"started_unix":1}}"#);
    let ctl = FakeCtl::default();
    assert!(matches!(run(&f.paths, &ctl), Err(RescueError::NoPrevious)));
    assert!(ctl.calls().is_empty());
}

#[test]
fn a_failed_reset_is_ignored_but_a_failed_start_is_an_error() {
    let f = fix(&["1.0.0", "1.1.0"]);
    f.pending_update();
    let ctl = FakeCtl {
        reset_fails: true,
        ..FakeCtl::default()
    };
    assert!(run(&f.paths, &ctl).is_ok());
    let f = fix(&["1.0.0", "1.1.0"]);
    f.pending_update();
    let ctl = FakeCtl {
        start_fails: true,
        ..FakeCtl::default()
    };
    assert!(matches!(run(&f.paths, &ctl), Err(RescueError::StartFailed)));
    let ctl = FakeCtl {
        start_errors: true,
        ..FakeCtl::default()
    };
    assert!(matches!(run(&f.paths, &ctl), Err(RescueError::Start(_))));
    // The links were restored before the start was attempted.
    assert_eq!(f.current().as_deref(), Some("1.0.0"));
}

// ----- refusals --------------------------------------------------------------------------------

#[test]
fn a_symlinked_state_file_is_refused() {
    let f = fix(&["1.0.0", "1.1.0"]);
    f.pending_update();
    let real = f.paths.state_dir.join("elsewhere");
    std::fs::rename(f.state_file(), &real).unwrap();
    symlink(&real, f.state_file()).unwrap();
    let ctl = FakeCtl::default();
    assert_eq!(untrusted(run(&f.paths, &ctl)), "updates-state is a symlink");
    assert!(ctl.calls().is_empty());
    assert_eq!(
        f.current().as_deref(),
        Some("1.1.0"),
        "nothing was restored"
    );
}

#[test]
fn a_symlinked_state_directory_is_refused() {
    let f = fix(&["1.0.0", "1.1.0"]);
    f.pending_update();
    let moved = f.paths.state_dir.with_file_name("real-state");
    std::fs::rename(&f.paths.state_dir, &moved).unwrap();
    symlink(&moved, &f.paths.state_dir).unwrap();
    let ctl = FakeCtl::default();
    untrusted(run(&f.paths, &ctl));
    assert!(ctl.calls().is_empty());
    assert_eq!(f.current().as_deref(), Some("1.1.0"));
}

#[test]
fn a_state_file_with_the_wrong_mode_is_refused() {
    let f = fix(&["1.0.0", "1.1.0"]);
    f.pending_update();
    for mode in [0o644, 0o640, 0o660, 0o666, 0o700, 0o400] {
        std::fs::set_permissions(f.state_file(), std::fs::Permissions::from_mode(mode)).unwrap();
        let ctl = FakeCtl::default();
        assert_eq!(
            untrusted(run(&f.paths, &ctl)),
            "updates-state is not mode 0600",
            "{mode:o}"
        );
        assert!(ctl.calls().is_empty());
        assert_eq!(f.current().as_deref(), Some("1.1.0"));
    }
}

#[test]
fn a_state_file_or_directory_with_the_wrong_owner_or_writable_by_others_is_refused() {
    let f = fix(&["1.0.0", "1.1.0"]);
    f.pending_update();
    // Pretend root is somebody else: the files are then "owned by the wrong user".
    let mut p = f.paths.clone();
    p.owner_uid = euid() + 1;
    assert_eq!(
        untrusted(run(&p, &FakeCtl::default())),
        "the state directory is not owned by root or is writable by others"
    );
    // The directory is the right owner but writable by others.
    std::fs::set_permissions(
        &f.paths.state_dir,
        std::fs::Permissions::from_mode(0o770 | 0o002),
    )
    .unwrap();
    assert_eq!(
        untrusted(run(&f.paths, &FakeCtl::default())),
        "the state directory is not owned by root or is writable by others"
    );
    std::fs::set_permissions(&f.paths.state_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(f.current().as_deref(), Some("1.1.0"));
}

#[test]
fn a_state_file_that_is_not_a_regular_file_is_refused() {
    let f = fix(&["1.0.0", "1.1.0"]);
    f.pending_update();
    std::fs::remove_file(f.state_file()).unwrap();
    std::fs::create_dir(f.state_file()).unwrap();
    assert_eq!(
        untrusted(run(&f.paths, &FakeCtl::default())),
        "updates-state is not a regular file"
    );
    std::fs::remove_dir(f.state_file()).unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        f.state_file(),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    assert_eq!(
        untrusted(run(&f.paths, &FakeCtl::default())),
        "updates-state is not a regular file"
    );
    assert_eq!(f.current().as_deref(), Some("1.1.0"));
}

#[test]
fn an_oversized_state_file_is_refused() {
    let f = fix(&["1.0.0", "1.1.0"]);
    f.pending_update();
    let mut big = String::from(r#"{"pending":null,"pad":""#);
    big.push_str(&"x".repeat(MAX_STATE_BYTES as usize));
    big.push_str(r#""}"#);
    f.write_state(&big);
    assert_eq!(
        untrusted(run(&f.paths, &FakeCtl::default())),
        "updates-state is too large"
    );
}

#[test]
fn a_corrupt_state_file_is_an_error_never_a_reset() {
    let f = fix(&["1.0.0", "1.1.0"]);
    f.pending_update();
    for junk in [
        "{not json",
        "",
        r#"{"pending":{"version":1}}"#,
        r#"{"pending":"x"}"#,
    ] {
        f.write_state(junk);
        let ctl = FakeCtl::default();
        assert!(
            matches!(run(&f.paths, &ctl), Err(RescueError::Corrupt)),
            "{junk:?}"
        );
        assert!(ctl.calls().is_empty());
        assert_eq!(
            std::fs::read_to_string(f.state_file()).unwrap(),
            junk,
            "left as found"
        );
    }
    assert_eq!(f.current().as_deref(), Some("1.1.0"));
}

#[test]
fn versions_that_could_become_a_path_are_refused_before_any_path_is_built() {
    let f = fix(&["1.0.0", "1.1.0"]);
    f.pending_update();
    let bad = [
        "../../etc",
        "..",
        ".",
        "1.0",
        "1.0.0/../../x",
        "1.0.0\n",
        "01.0.0.0",
        "99999.0.0",
        "1.0.0-gamma.1",
        "1.0.0-rc",
        "/usr/lib/hx/1.0.0",
        "",
        " 1.0.0",
    ];
    for v in bad {
        for (version, previous) in [(v, "1.0.0"), ("1.1.0", v)] {
            let json = serde_json::json!({"pending": {"version": version, "previous": previous}});
            f.write_state(&json.to_string());
            let ctl = FakeCtl::default();
            let r = run(&f.paths, &ctl);
            assert!(
                matches!(r, Err(RescueError::BadVersion(_))),
                "{version:?}/{previous:?}: {r:?}"
            );
            assert!(ctl.calls().is_empty());
        }
    }
    assert_eq!(f.current().as_deref(), Some("1.1.0"));
    // A pre-release version is fine.
    let good = serde_json::json!({"pending": {"version": "1.1.0", "previous": "1.0.0"}});
    f.write_state(&good.to_string());
    assert!(read_pending(&f.paths).unwrap().is_some());
}

// ----- the helper reads the two fields and nothing else ---------------------------------------------

#[test]
fn only_pending_version_and_previous_are_read() {
    let f = fix(&["1.0.0"]);
    f.write_state(PENDING);
    let p = read_pending(&f.paths).unwrap().unwrap();
    assert_eq!(
        (p.version.as_str(), p.previous.as_deref()),
        ("1.1.0", Some("1.0.0"))
    );
    // Unknown and malformed *other* fields do not matter to it (privd owns their meaning), as long
    // as the document parses.
    f.write_state(
        r#"{"highest_by_channel":"nonsense","apply_log":[-1],"pending":{"version":"2.0.0-rc.1","attempts":"x","gateway_pid":[]}}"#,
    );
    let p = read_pending(&f.paths).unwrap().unwrap();
    assert_eq!((p.version.as_str(), p.previous), ("2.0.0-rc.1", None));
}

#[test]
fn the_helper_never_reads_the_environment_or_arguments_and_never_writes_updates_state() {
    let src = |p: &str| {
        std::fs::read_to_string(format!("{}/src/{p}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    };
    for file in ["bin/hx-privd-rescue.rs", "privd/rescue.rs"] {
        let text = src(file);
        for needle in [
            "env::var",
            "env::vars",
            "var_os",
            "getenv",
            "set_var",
            "UpdateState",
            "save_json",
            "write_atomic",
            "fs::write",
            "OpenOptions",
        ] {
            // Mentions in comments are fine; code is not.
            let code: String = text
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(!code.contains(needle), "{file} uses {needle}");
        }
    }
    assert!(
        src("privd/rescue.rs").contains(".env_clear()"),
        "systemctl runs with a cleared environment"
    );
}

#[test]
fn the_binary_takes_no_arguments() {
    let exe = env!("CARGO_BIN_EXE_hx-privd-rescue");
    for args in [vec!["--help"], vec!["x"], vec!["/var/lib/hx", "1.0.0"]] {
        let out = std::process::Command::new(exe)
            .args(&args)
            .env_clear()
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("takes no arguments"));
    }
}

// ----- the hand-over: the restarted old privd finishes the rollback ----------------------------------

#[tokio::test]
async fn the_old_privd_started_by_the_helper_completes_the_rollback_through_resume_update() {
    // An update was applied (current 1.1.0, pending in updates-state) and the new privd never came
    // up, so its own health check never ran.
    let env = Env::new();
    env.publish("1.1.0", 1_799_900_000);
    env.check().await;
    let r = env.apply("1.1.0").await;
    assert!(r.result.is_some());
    assert_eq!(env.layout().current().unwrap().as_deref(), Some("1.1.0"));
    let state_dir = env.h.daemon.cfg.state_dir.clone();
    let state_file = state_dir.join("updates-state");
    assert!(
        UpdateState::load(&hx_agent::privd::state::StateStore::open(&state_dir).unwrap())
            .unwrap()
            .pending
            .is_some()
    );
    let before = bytes_and_mtime(&state_file);

    // The helper, as systemd would run it after the start limit is hit.
    let paths = Paths {
        state_dir: state_dir.clone(),
        releases_dir: env.h.daemon.cfg.update.versions_dir.clone(),
        owner_uid: euid(),
    };
    let ctl = FakeCtl::default();
    assert_eq!(
        run(&paths, &ctl).unwrap(),
        Outcome::Restarted {
            restored: true,
            links_untouched: false
        }
    );
    assert_eq!(env.layout().current().unwrap().as_deref(), Some("1.0.0"));
    assert_eq!(
        bytes_and_mtime(&state_file),
        before,
        "the helper never wrote updates-state"
    );

    // Privd starts again: the old binary (1.0.0), with `pending` still there.
    env.systemd.restarts.lock().unwrap().clear();
    let old = env.new_process("1.0.0");
    old.resume_update().await;

    // It saw running_version != pending.version and ran rollback_now: bookkeeping, flag, both
    // units restarted, and `current` still the old version.
    let st =
        UpdateState::load(&hx_agent::privd::state::StateStore::open(&state_dir).unwrap()).unwrap();
    assert!(
        st.pending.is_none(),
        "pending is cleared by privd, not by the helper"
    );
    let rb = st.rolled_back.expect("rolled_back recorded");
    assert_eq!(rb.version, "1.1.0");
    assert!(rb.reason.contains("running version 1.0.0"), "{}", rb.reason);
    assert!(old.read_state(|s| s.flags.contains(&Flag::UpdateRolledBack)));
    assert_eq!(env.layout().current().unwrap().as_deref(), Some("1.0.0"));
    assert_eq!(env.layout().previous().unwrap().as_deref(), Some("1.1.0"));
    use hx_agent::privd::update::Unit;
    assert_eq!(env.systemd.restarted(), [Unit::Gatewayd, Unit::Privd]);
    assert!(
        env.h
            .audit
            .lines()
            .iter()
            .any(|l| l.contains("needs_attention=UPDATE_ROLLED_BACK")),
        "audited"
    );
    // And a later run of the helper finds nothing to do.
    let ctl = FakeCtl::default();
    assert_eq!(run(&paths, &ctl).unwrap(), Outcome::NoPending);
    assert!(ctl.calls().is_empty());
}
