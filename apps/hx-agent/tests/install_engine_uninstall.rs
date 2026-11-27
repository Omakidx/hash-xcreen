//! `hx-agent uninstall` (U0 to U8) against a simulated host that was installed by the engine:
//! the order of the steps, keep and destroy, resume after a failure at each step, the manual
//! paths, the lock, and the rule that root never walks gatewayd's directory itself.

mod install_engine_common;

use std::io;
use std::path::Path;

use hx_agent::install::error::InstallError;
use hx_agent::install::paths;
use hx_agent::install::runner::Tool;
use hx_agent::install::testing::Machine;
use hx_agent::install::uninstall::{
    Cleaner, Report, UninstallDeps, UninstallError, empty_dir_beneath, resume_path,
};
use install_engine_common::*;

#[derive(Default)]
struct FakeCleaner {
    calls: Vec<(String, u32, u32)>,
    /// A path that must still exist whenever the cleaner is called (the agent binary's release
    /// directory: the real cleaner re-executes the agent from it).
    watch: Option<std::path::PathBuf>,
    watched_existed: Vec<bool>,
}

impl Cleaner for FakeCleaner {
    fn empty_as_owner(&mut self, dir: &Path, uid: u32, gid: u32) -> io::Result<()> {
        self.calls
            .push((dir.to_string_lossy().into_owned(), uid, gid));
        if let Some(w) = &self.watch {
            self.watched_existed.push(w.exists());
        }
        empty_dir_beneath(dir)
    }
}

fn installed() -> Machine {
    let mut m = Machine::new();
    let dir = release(&mut m, &Tamper::default());
    assert_eq!(
        full_install(&mut m, &dir),
        0,
        "{}",
        String::from_utf8_lossy(&m.err)
    );
    // What the running system adds: gatewayd's registry (with a link out of the tree), privd's
    // firewall file, a file the state must not be able to make us delete.
    let reg = path(&m, "/var/lib/hx-gatewayd/registry");
    std::fs::create_dir_all(&reg).unwrap();
    std::fs::write(reg.join("devices"), b"d").unwrap();
    std::fs::write(path(&m, "/etc/hx/host-firewall.nft"), b"table inet hx {}").unwrap();
    m
}

fn uninstall(
    m: &mut Machine,
    keep: bool,
    euid: u32,
) -> (Result<Report, UninstallError>, FakeCleaner, String) {
    let mut cleaner = FakeCleaner {
        watch: Some(m.paths.at(paths::USR_LIB_HX)),
        ..FakeCleaner::default()
    };
    let mut said = String::new();
    let mut progress = |_: &hx_agent::cli::privd::ProgressLine| {};
    let r = {
        let mut say = |s: &str| said.push_str(s);
        hx_agent::install::uninstall::run(
            keep,
            UninstallDeps {
                paths: m.paths.clone(),
                runner: &mut m.runner,
                daemons: &mut m.daemons,
                cleaner: &mut cleaner,
                now: || NOW,
                sleep: |_| {},
                host: true,
                euid,
            },
            &mut progress,
            &mut say,
        )
    };
    (r, cleaner, said)
}

fn ok(r: Result<Report, UninstallError>) -> Report {
    match r {
        Ok(r) => r,
        Err(UninstallError::Failed(e)) => panic!("failed: {e}"),
        Err(e) => panic!("{e:?}"),
    }
}

fn index_of(lines: &[String], prefix: &str) -> usize {
    lines
        .iter()
        .position(|l| l.starts_with(prefix))
        .unwrap_or_else(|| panic!("no call {prefix}: {lines:#?}"))
}

#[test]
fn destroy_removes_everything_in_order() {
    let mut m = installed();
    m.runner.calls.clear();
    let (r, cleaner, _) = uninstall(&mut m, false, 0);
    let rep = ok(r);
    assert_eq!(rep.ran, ["U1", "U2", "U3", "U4", "U5", "U6", "U7"]);
    assert_eq!(m.daemons.uninstalls, [false]);
    // Order of the host-level steps.
    let l = m.runner.lines();
    let u1 = index_of(
        &l,
        "systemctl disable --now hx-gatewayd.service hx-gatewayd-public.socket hx-gatewayd-admin.socket",
    );
    let u3 = index_of(
        &l,
        "systemctl disable --now hx-privd.socket hx-privd.service hx-privd-rescue.service var-lib-hx-updates.mount var-lib-hx-imagein.mount hx-host-firewall.service hx-docker-user.service",
    );
    let fetch = index_of(
        &l,
        "systemctl stop hx-update-fetcher@*.service hx-image-fetcher@*.service hx-drive.socket hx-drive.service",
    );
    let user = index_of(&l, "userdel hx-gatewayd");
    let reload = index_of(&l, "systemctl daemon-reload");
    let failed = index_of(&l, "systemctl reset-failed");
    assert!(
        u1 < u3 && u3 <= fetch && fetch < user && user < reload && reload < failed,
        "{l:#?}"
    );
    // Files and directories are gone.
    for gone in [
        "/usr/lib/hx",
        "/usr/lib/hx-rescue",
        "/var/lib/hx",
        "/var/lib/hx-gatewayd",
        "/var/log/hx",
        "/etc/hx",
        "/usr/local/lib/sysusers.d/hx-gatewayd.conf",
        "/usr/local/lib/tmpfiles.d/hx.conf",
        "/etc/logrotate.d/hx-audit",
        "/etc/systemd/system/hx-gatewayd-public.socket.d",
        "/etc/systemd/system/hx-update-fetcher@.service.d",
        "/etc/systemd/system/hx-image-fetcher@.service.d",
        "/usr/local/lib/systemd/system/hx-privd.service",
        "/usr/local/lib/systemd/system/hx-image-fetcher@.service",
        "/usr/local/lib/systemd/system/var-lib-hx-imagein.mount",
        "/usr/local/lib/systemd/system/hx-host-firewall.service",
        "/usr/local/lib/systemd/system/hx-docker-user.service",
        "/usr/local/lib/systemd/system/hx-agent-port.service",
    ] {
        assert!(!exists(&m, gone), "{gone} should be gone");
    }
    assert!(!m.read(paths::PASSWD).unwrap().contains("hx-gatewayd"));
    assert!(
        !resume_path(&m.paths).exists(),
        "U8: the resume file is dropped"
    );
    // gatewayd's state is emptied by the child that runs as its user (rule 15).
    assert_eq!(cleaner.calls.len(), 1);
    assert_eq!((cleaner.calls[0].1, cleaner.calls[0].2), (998, 998));
}

#[test]
fn keep_leaves_the_firewall_and_its_units() {
    let mut m = installed();
    m.runner.calls.clear();
    let rep = ok(uninstall(&mut m, true, 0).0);
    assert!(rep.notes.iter().any(|n| n.contains("kept")));
    assert_eq!(m.daemons.uninstalls, [true]);
    assert!(exists(&m, "/etc/hx/host-firewall.nft"), "the ruleset stays");
    assert!(exists(
        &m,
        "/usr/local/lib/systemd/system/hx-host-firewall.service"
    ));
    assert!(exists(
        &m,
        "/usr/local/lib/systemd/system/hx-docker-user.service"
    ));
    assert!(
        m.runner.enabled.contains("hx-host-firewall.service"),
        "still enabled"
    );
    let l = m.runner.lines();
    let u3 = index_of(&l, "systemctl disable --now hx-privd.socket");
    assert!(!l[u3].contains("hx-host-firewall"), "{}", l[u3]);
    // Everything else is gone, including the credentials.
    assert!(!exists(&m, "/etc/hx/creds"));
    assert!(!exists(&m, "/etc/hx/gatewayd.toml"));
    assert!(!exists(
        &m,
        "/usr/local/lib/systemd/system/hx-privd.service"
    ));
    assert!(!exists(&m, "/var/lib/hx"));
    let left: Vec<_> = std::fs::read_dir(path(&m, "/etc/hx"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left, ["host-firewall.nft"]);
}

#[test]
fn the_port_rule_is_removed_by_backend() {
    // ufw
    let mut m = Machine::new();
    m.runner.ufw = Some(true);
    let dir = release(&mut m, &Tamper::default());
    assert_eq!(full_install(&mut m, &dir), 0);
    assert_eq!(
        m.runner.ufw_rules.len(),
        6,
        "two port rules and four bridge rules"
    );
    ok(uninstall(&mut m, true, 0).0);
    assert!(m.runner.ufw_rules.is_empty());
    // nft
    let mut m = Machine::new();
    m.runner.nft_items.push(serde_json::json!({"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 1,
        "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}}));
    let dir = release(&mut m, &Tamper::default());
    assert_eq!(full_install(&mut m, &dir), 0);
    assert!(m.runner.enabled.contains("hx-agent-port.service"));
    ok(uninstall(&mut m, false, 0).0);
    assert!(
        m.runner.nft_items.iter().all(|i| i.get("rule").is_none()),
        "our rule is gone"
    );
    assert!(!m.runner.enabled.contains("hx-agent-port.service"));
    // manual
    let mut m = Machine::new();
    m.runner.active.insert("firewalld".into());
    let dir = release(&mut m, &Tamper::default());
    assert_eq!(full_install(&mut m, &dir), 0);
    let rep = ok(uninstall(&mut m, false, 0).0);
    assert!(
        rep.notes.iter().any(|n| n.contains("by hand")),
        "{:?}",
        rep.notes
    );
}

#[test]
fn the_notes_say_what_stays_installed() {
    let mut m = installed();
    let mut st = m.state().unwrap();
    st.created.apt = vec![paths::ZABBLY_KEY.into(), paths::ZABBLY_SOURCES.into()];
    hx_agent::install::state::save(&m.paths.at(paths::STATE_FILE), &st).unwrap();
    let rep = ok(uninstall(&mut m, false, 0).0);
    let all = rep.notes.join("\n");
    assert!(all.contains("Incus stays installed"), "{all}");
    assert!(all.contains("Zabbly apt repository stays") && all.contains("hx-zabbly.asc"));
}

#[test]
fn uninstall_removes_our_hx_agent_link_in_both_modes() {
    for keep in [false, true] {
        let mut m = installed();
        let link = path(&m, paths::CLI_LINK);
        assert!(std::fs::symlink_metadata(&link).is_ok());
        let rep = ok(uninstall(&mut m, keep, 0).0);
        assert!(
            std::fs::symlink_metadata(&link).is_err(),
            "keep={keep}: our link is gone"
        );
        assert!(!rep.notes.join("\n").contains(paths::CLI_LINK));
        // The directory is the system's, not ours.
        assert!(link.parent().unwrap().is_dir());
    }
}

#[test]
fn uninstall_leaves_a_foreign_hx_agent_and_says_so() {
    use std::os::unix::fs::PermissionsExt;
    for foreign_link in [false, true] {
        let mut m = installed();
        let link = path(&m, paths::CLI_LINK);
        std::fs::remove_file(&link).unwrap();
        if foreign_link {
            // A link to our binary, but not through `current`: still not ours.
            std::os::unix::fs::symlink(format!("/usr/lib/hx/{VERSION}/hx-agent"), &link).unwrap();
        } else {
            std::fs::write(&link, b"mine").unwrap();
            std::fs::set_permissions(&link, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        // Even a state that claims the name cannot make uninstall delete it.
        let mut st = m.state().unwrap();
        st.created.files.push(paths::CLI_LINK.into());
        hx_agent::install::state::save(&m.paths.at(paths::STATE_FILE), &st).unwrap();
        let rep = ok(uninstall(&mut m, false, 0).0);
        let md = std::fs::symlink_metadata(&link).expect("a foreign hx-agent stays");
        if foreign_link {
            assert!(md.file_type().is_symlink());
        } else {
            assert_eq!(std::fs::read(&link).unwrap(), b"mine");
        }
        let all = rep.notes.join("\n");
        assert!(
            all.contains(paths::CLI_LINK) && all.contains("stays"),
            "{all}"
        );
    }
}

// ----- resume ---------------------------------------------------------------------------------

fn resume_state(m: &Machine) -> hx_agent::install::uninstall::UninstallState {
    serde_json::from_slice(&std::fs::read(resume_path(&m.paths)).unwrap()).unwrap()
}

#[test]
fn a_failure_in_privd_stops_after_u1_and_resumes_there() {
    let mut m = installed();
    m.daemons.uninstall_answer = Some(InstallError::tool("boom"));
    let (r, _, _) = uninstall(&mut m, false, 0);
    assert!(matches!(r, Err(UninstallError::Failed(_))));
    let st = resume_state(&m);
    assert_eq!(st.done, ["U1"]);
    assert!(!st.privd_done);
    assert!(exists(&m, "/usr/lib/hx"), "nothing was removed");
    m.daemons.uninstall_answer = None;
    m.runner.calls.clear();
    let rep = ok(uninstall(&mut m, false, 0).0);
    assert_eq!(
        rep.ran,
        ["U2", "U3", "U4", "U5", "U6", "U7"],
        "U1 is not repeated"
    );
    assert!(
        !m.runner
            .lines()
            .iter()
            .any(|l| l.starts_with("systemctl disable --now hx-gatewayd"))
    );
}

#[test]
fn a_failure_at_u4_u5_and_u6_resumes_without_redoing_privd() {
    // U4: ufw refuses to delete.
    let mut m = Machine::new();
    m.runner.ufw = Some(true);
    let dir = release(&mut m, &Tamper::default());
    assert_eq!(full_install(&mut m, &dir), 0);
    m.runner.fail_on(Tool::Ufw, "delete", 1, Some(1));
    assert!(matches!(
        uninstall(&mut m, true, 0).0,
        Err(UninstallError::Failed(_))
    ));
    assert_eq!(resume_state(&m).done, ["U1", "U2", "U3"]);
    assert!(resume_state(&m).privd_done);
    assert!(uninstall(&mut m, true, 0).0.is_ok());
    assert_eq!(m.daemons.uninstalls.len(), 1, "privd was asked once");
    // U5: a non-empty updates directory is never walked by root.
    let mut m = installed();
    std::fs::create_dir_all(path(&m, "/var/lib/hx/updates")).unwrap();
    std::fs::write(path(&m, "/var/lib/hx/updates/planted"), b"x").unwrap();
    let (r, _, _) = uninstall(&mut m, false, 0);
    match r {
        Err(UninstallError::Failed(e)) => assert!(e.message.contains("refusing to walk"), "{e}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(resume_state(&m).done, ["U1", "U2", "U3", "U4"]);
    std::fs::remove_file(path(&m, "/var/lib/hx/updates/planted")).unwrap();
    ok(uninstall(&mut m, false, 0).0);
    assert_eq!(m.daemons.uninstalls.len(), 1);
    assert!(!exists(&m, "/var/lib/hx"));
    // U5: the same for the image fetcher's directory; a prebuilt image placed in the import
    // directory (root-only, 4 GiB at most) goes with /var/lib/hx.
    let mut m = installed();
    std::fs::create_dir_all(path(&m, "/var/lib/hx/imagein")).unwrap();
    std::fs::write(path(&m, "/var/lib/hx/imagein/planted"), b"x").unwrap();
    std::fs::create_dir_all(path(&m, "/var/lib/hx/import")).unwrap();
    std::fs::write(path(&m, "/var/lib/hx/import/hx-image.img"), b"image").unwrap();
    let (r, _, _) = uninstall(&mut m, false, 0);
    match r {
        Err(UninstallError::Failed(e)) => {
            assert!(e.message.contains("/var/lib/hx/imagein"), "{e}");
            assert!(e.message.contains("refusing to walk"), "{e}");
        }
        other => panic!("{other:?}"),
    }
    assert!(
        exists(&m, "/var/lib/hx/import/hx-image.img"),
        "nothing was walked"
    );
    std::fs::remove_file(path(&m, "/var/lib/hx/imagein/planted")).unwrap();
    ok(uninstall(&mut m, false, 0).0);
    assert!(!exists(&m, "/var/lib/hx"));
    // U6: userdel fails.
    let mut m = installed();
    m.runner.fail_on(Tool::Userdel, "", 8, Some(1));
    assert!(matches!(
        uninstall(&mut m, false, 0).0,
        Err(UninstallError::Failed(_))
    ));
    assert_eq!(resume_state(&m).done, ["U1", "U2", "U3", "U4", "U5"]);
    // After U5 the user is still in passwd (the fake failed); the retry deletes it.
    ok(uninstall(&mut m, false, 0).0);
    assert!(!m.read(paths::PASSWD).unwrap().contains("hx-gatewayd"));
    assert!(!resume_path(&m.paths).exists());
}

#[test]
fn a_second_run_after_completion_is_a_clean_noop_that_asks_privd_nothing() {
    let mut m = installed();
    ok(uninstall(&mut m, false, 0).0);
    m.runner.calls.clear();
    // privd's state directory is gone: its part was done by the earlier run.
    let rep = ok(uninstall(&mut m, false, 0).0);
    assert_eq!(
        m.daemons.uninstalls.len(),
        1,
        "privd's own marker or the missing state dir says it is done"
    );
    assert_eq!(rep.ran.len(), 7);
}

#[test]
fn privds_own_marker_skips_its_step() {
    let mut m = installed();
    std::fs::write(
        path(&m, paths::PRIVD_UNINSTALL_STATE),
        br#"{"version":1,"mode":"destroy","started":1,"done":[],"privd_done":true,"removed":[]}"#,
    )
    .unwrap();
    ok(uninstall(&mut m, false, 0).0);
    assert!(m.daemons.uninstalls.is_empty());
}

// ----- the manual paths -----------------------------------------------------------------------

#[test]
fn an_old_privd_gets_the_manual_steps_and_the_gateway_comes_back() {
    let mut m = installed();
    m.daemons.uninstall_answer = Some(InstallError::unimplemented("not in this release"));
    m.runner.calls.clear();
    let (r, _, _) = uninstall(&mut m, true, 0);
    assert!(matches!(r, Err(UninstallError::Unimplemented)));
    assert!(
        exists(&m, "/usr/lib/hx") && exists(&m, "/etc/hx/gatewayd.toml"),
        "nothing was removed"
    );
    assert!(!resume_path(&m.paths).exists());
    let l = m.runner.lines();
    let off = index_of(&l, "systemctl disable --now hx-gatewayd.service");
    let on = index_of(&l, "systemctl enable --now hx-gatewayd.service");
    assert!(
        off < on,
        "the units stopped for U1 are started again: {l:#?}"
    );
}

#[test]
fn an_unreachable_privd_is_started_once_then_the_manual_steps_are_given() {
    let mut m = installed();
    m.daemons.uninstall_answer = Some(InstallError::unavailable("no socket"));
    m.runner.calls.clear();
    let (r, _, _) = uninstall(&mut m, false, 0);
    assert!(matches!(r, Err(UninstallError::PrivdUnreachable)));
    assert!(
        m.runner
            .lines()
            .iter()
            .any(|l| l == "systemctl start hx-privd.socket")
    );
    assert_eq!(
        m.daemons.uninstalls.len(),
        2,
        "tried again after starting the socket"
    );
    assert!(exists(&m, "/usr/lib/hx"));
}

// ----- refusals -------------------------------------------------------------------------------

#[test]
fn modes_cannot_be_switched_once_it_is_too_late() {
    // destroy -> keep is refused.
    let mut m = installed();
    m.daemons.uninstall_answer = Some(InstallError::tool("boom"));
    let _ = uninstall(&mut m, false, 0);
    let (r, _, _) = uninstall(&mut m, true, 0);
    match r {
        Err(UninstallError::Failed(e)) => assert_eq!(e.exit, 12, "{e}"),
        other => panic!("{other:?}"),
    }
    // keep -> destroy while privd has not run yet is fine; after privd's part it is refused.
    let mut m = installed();
    m.runner.fail_on(Tool::Userdel, "", 8, Some(1));
    assert!(matches!(
        uninstall(&mut m, true, 0).0,
        Err(UninstallError::Failed(_))
    ));
    assert!(resume_state(&m).privd_done);
    let (r, _, _) = uninstall(&mut m, false, 0);
    match r {
        Err(UninstallError::Failed(e)) => assert_eq!(e.exit, 12, "{e}"),
        other => panic!("{other:?}"),
    }
    let mut m = installed();
    m.daemons.uninstall_answer = Some(InstallError::tool("boom"));
    let _ = uninstall(&mut m, true, 0);
    m.daemons.uninstall_answer = None;
    assert!(
        uninstall(&mut m, false, 0).0.is_ok(),
        "keep to destroy before privd's part is allowed"
    );
    assert_eq!(m.daemons.uninstalls.last(), Some(&false));
}

#[test]
fn the_lock_and_root_are_checked() {
    let mut m = installed();
    let held = hx_agent::install::lock::acquire(&path(&m, paths::LOCK_FILE), None).unwrap();
    match uninstall(&mut m, false, 0).0 {
        Err(UninstallError::Failed(e)) => assert_eq!(e.exit, 11),
        other => panic!("{other:?}"),
    }
    drop(held);
    match uninstall(&mut m, false, 1000).0 {
        Err(UninstallError::Failed(e)) => assert_eq!(e.exit, 7),
        other => panic!("{other:?}"),
    }
    assert!(exists(&m, "/usr/lib/hx"));
}

#[test]
fn a_tampered_state_cannot_make_uninstall_delete_other_files() {
    let mut m = installed();
    std::fs::write(path(&m, "/etc/important"), b"keep me").unwrap();
    std::fs::create_dir_all(path(&m, "/etc/hx-evil")).unwrap();
    let mut st = m.state().unwrap();
    st.created.files.extend([
        "/etc/important".into(),
        "/etc/hx/../important".into(),
        "/etc/hx-evil".into(),
        "relative".into(),
    ]);
    st.created
        .dropins
        .push("/usr/lib/hx/../../etc/important".into());
    hx_agent::install::state::save(&m.paths.at(paths::STATE_FILE), &st).unwrap();
    ok(uninstall(&mut m, false, 0).0);
    assert!(exists(&m, "/etc/important"));
    assert!(exists(&m, "/etc/hx-evil"));
}

#[test]
fn gatewayd_state_is_not_touched_when_its_user_is_gone() {
    let mut m = installed();
    std::fs::write(path(&m, paths::PASSWD), "root:x:0:0:root:/root:/bin/bash\n").unwrap();
    let (r, cleaner, _) = uninstall(&mut m, false, 0);
    match r {
        Err(UninstallError::Failed(e)) => assert!(e.message.contains("refusing to walk"), "{e}"),
        other => panic!("{other:?}"),
    }
    assert!(cleaner.calls.is_empty());
    assert!(exists(&m, "/var/lib/hx-gatewayd/registry/devices"));
}

#[test]
fn the_cleaner_never_follows_links_out_of_gatewayds_tree() {
    let mut m = installed();
    let outside = m.dir.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("precious"), b"x").unwrap();
    std::os::unix::fs::symlink(&outside, path(&m, "/var/lib/hx-gatewayd/registry/link")).unwrap();
    ok(uninstall(&mut m, false, 0).0);
    assert!(outside.join("precious").exists());
    assert!(!exists(&m, "/var/lib/hx-gatewayd"));
}

#[test]
fn gatewayds_state_is_emptied_while_the_agent_binary_still_exists() {
    // M1: the real cleaner re-executes the agent from /usr/lib/hx, so U5 must empty gatewayd's
    // state before it removes that directory.
    let mut m = installed();
    let (r, cleaner, _) = uninstall(&mut m, false, 0);
    ok(r);
    assert_eq!(
        cleaner.watched_existed,
        [true],
        "/usr/lib/hx existed when the cleaner ran"
    );
    assert!(!exists(&m, "/usr/lib/hx") && !exists(&m, "/var/lib/hx-gatewayd"));
}

#[test]
fn the_real_cleaner_runs_even_when_the_binary_was_unlinked() {
    use hx_agent::install::uninstall::SelfExecCleaner;
    let d = tempfile::tempdir().unwrap();
    // A stand-in executable that exits 0 whatever it is given.
    let exe = d.path().join("agent");
    std::fs::copy("/usr/bin/true", &exe).unwrap();
    let file = std::fs::File::open(&exe).unwrap();
    let mut c = SelfExecCleaner::with_exe(Some(file), Some(exe.clone()));
    let uid = rustix::process::getuid().as_raw();
    let gid = rustix::process::getgid().as_raw();
    let dir = d.path().join("g");
    std::fs::create_dir(&dir).unwrap();
    c.empty_as_owner(&dir, uid, gid).expect("by path");
    // The path is gone (release directory removed): the descriptor still runs it.
    std::fs::remove_file(&exe).unwrap();
    assert!(!exe.exists());
    c.empty_as_owner(&dir, uid, gid)
        .expect("through the descriptor of the unlinked binary");
    // With neither, it is an error, not a hang or a panic.
    let mut none = SelfExecCleaner::with_exe(None, Some(exe));
    assert!(none.empty_as_owner(&dir, uid, gid).is_err());
}

#[test]
fn a_state_naming_directories_or_foreign_units_removes_nothing_of_them() {
    // L3: the removal set is exact; the state cannot widen it.
    let mut m = installed();
    let sys = path(&m, "/etc/systemd/system");
    std::fs::create_dir_all(sys.join("multi-user.target.wants")).unwrap();
    std::fs::write(sys.join("multi-user.target.wants/sshd.service"), b"x").unwrap();
    std::fs::write(sys.join("x.service"), b"x").unwrap();
    let other_d = sys.join("other.service.d");
    std::fs::create_dir_all(&other_d).unwrap();
    std::fs::write(other_d.join("a.conf"), b"x").unwrap();
    let mut st = m.state().unwrap();
    st.created.files.extend([
        "/etc/systemd/system/".into(),
        "/etc/systemd/system".into(),
        "/etc/systemd/system/multi-user.target.wants".into(),
        "/etc/systemd/system/x.service".into(),
        "/etc/systemd/system/other.service.d".into(),
    ]);
    st.created
        .dropins
        .push("/etc/systemd/system/other.service.d/a.conf".into());
    hx_agent::install::state::save(&m.paths.at(paths::STATE_FILE), &st).unwrap();
    ok(uninstall(&mut m, false, 0).0);
    assert!(sys.join("multi-user.target.wants/sshd.service").exists());
    assert!(sys.join("x.service").exists());
    assert!(other_d.join("a.conf").exists());
    // Our own drop-in directory is gone because it was empty after its file went.
    assert!(!sys.join("hx-gatewayd-public.socket.d").exists());
}

#[test]
fn our_dropin_directory_stays_if_something_else_is_in_it() {
    let mut m = installed();
    let d = path(&m, "/etc/systemd/system/hx-gatewayd-public.socket.d");
    std::fs::write(d.join("90-admin.conf"), b"[Socket]\n").unwrap();
    ok(uninstall(&mut m, false, 0).0);
    assert!(d.join("90-admin.conf").exists());
    assert!(!d.join("50-port.conf").exists());
}

// ----- the port rule (L4) -----------------------------------------------------------------------

fn drop_chain(family: &str, table: &str, name: &str) -> serde_json::Value {
    serde_json::json!({"chain": {"family": family, "table": table, "name": name, "handle": 1,
        "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}})
}

fn our_nft_rules(m: &Machine) -> usize {
    m.runner
        .nft_items
        .iter()
        .filter_map(|i| i.get("rule"))
        .filter(|r| r["comment"] == "hx-agent-port")
        .count()
}

fn rerun_ssh(m: &mut Machine, extra: &[(&'static str, &str)]) -> u8 {
    let mut a = ssh_args(std::path::Path::new("/none"), extra, &[]);
    a.bootstrap_dir = None;
    m.install(a, Some(frames(None, None)))
}

#[test]
fn a_rule_in_a_chain_that_stopped_dropping_is_still_removed() {
    let mut m = Machine::new();
    m.runner
        .nft_items
        .push(drop_chain("inet", "filter", "input"));
    let dir = release(&mut m, &Tamper::default());
    assert_eq!(full_install(&mut m, &dir), 0);
    assert_eq!(our_nft_rules(&m), 1);
    // The administrator changed the policy afterwards: the chain no longer drops.
    m.runner.nft_items[0]["chain"]["policy"] = serde_json::json!("accept");
    ok(uninstall(&mut m, false, 0).0);
    assert_eq!(
        our_nft_rules(&m),
        0,
        "found by comment in every input chain"
    );
}

#[test]
fn a_stale_rule_in_a_chain_that_stopped_dropping_is_cleaned_on_the_next_install_run() {
    let mut m = Machine::new();
    m.runner
        .nft_items
        .push(drop_chain("inet", "filter", "input"));
    m.runner.nft_items.push(drop_chain("ip", "filter", "INPUT"));
    let dir = release(&mut m, &Tamper::default());
    assert_eq!(full_install(&mut m, &dir), 0);
    assert_eq!(our_nft_rules(&m), 2);
    m.runner.nft_items[1]["chain"]["policy"] = serde_json::json!("accept");
    assert_eq!(rerun_ssh(&mut m, &[("--port", "8443")]), 0);
    assert_eq!(
        our_nft_rules(&m),
        1,
        "only the chain that still drops keeps a rule"
    );
}

#[test]
fn a_failure_half_way_is_recorded_before_it_happens_and_removed_by_uninstall() {
    let mut m = Machine::new();
    m.runner
        .nft_items
        .push(drop_chain("inet", "filter", "input"));
    m.runner.nft_items.push(drop_chain("ip", "filter", "INPUT"));
    // The first insert works, the second fails.
    m.runner
        .fail_on(Tool::Nft, "insert rule ip filter INPUT", 1, Some(1));
    let dir = release(&mut m, &Tamper::default());
    assert_eq!(full_install(&mut m, &dir), 1);
    assert_eq!(m.result()["stage"], "firewall-port");
    assert_eq!(our_nft_rules(&m), 1, "one rule is in");
    let rec = m
        .state()
        .unwrap()
        .created
        .port_rule
        .expect("recorded before the insert");
    assert_eq!((rec.backend.as_str(), rec.port), ("nft", 443));
    ok(uninstall(&mut m, false, 0).0);
    assert_eq!(our_nft_rules(&m), 0);
}

#[test]
fn an_unreadable_state_does_not_skip_the_port_rule() {
    // nft by comment
    let mut m = Machine::new();
    m.runner
        .nft_items
        .push(drop_chain("inet", "filter", "input"));
    let dir = release(&mut m, &Tamper::default());
    assert_eq!(full_install(&mut m, &dir), 0);
    std::fs::write(path(&m, paths::STATE_FILE), b"{ not json").unwrap();
    let rep = ok(uninstall(&mut m, false, 0).0);
    assert_eq!(our_nft_rules(&m), 0);
    assert!(
        rep.warnings.iter().any(|w| w.contains("unreadable")),
        "{:?}",
        rep.warnings
    );
    // ufw by its comment: ours go, the administrator's stay.
    let mut m = Machine::new();
    m.runner.ufw = Some(true);
    m.runner.ufw_rules.push("allow 22/tcp".into());
    m.runner.ufw_foreign.insert("allow 22/tcp".into());
    let dir = release(&mut m, &Tamper::default());
    assert_eq!(full_install(&mut m, &dir), 0);
    std::fs::write(path(&m, paths::STATE_FILE), b"\xff\xfe").unwrap();
    let rep = ok(uninstall(&mut m, false, 0).0);
    assert_eq!(m.runner.ufw_rules, ["allow 22/tcp"]);
    assert!(rep.warnings.iter().any(|w| w.contains("unreadable")));
}

#[test]
fn a_ufw_rule_that_was_already_there_is_adopted_and_survives_uninstall() {
    let mut m = Machine::new();
    m.runner.ufw = Some(true);
    m.runner.ufw_rules.push("allow 443/tcp".into());
    m.runner.ufw_foreign.insert("allow 443/tcp".into());
    let dir = release(&mut m, &Tamper::default());
    assert_eq!(full_install(&mut m, &dir), 0);
    let rec = m.state().unwrap().created.port_rule.unwrap();
    assert_eq!(
        rec.adopted,
        ["tcp"],
        "the existing tcp rule is the administrator's"
    );
    assert_eq!(port_rules(&m), ["allow 443/tcp", "allow 443/udp"]);
    // A re-run does not turn it into ours, and keeps what is ours.
    assert_eq!(rerun_ssh(&mut m, &[]), 0);
    assert_eq!(
        m.state().unwrap().created.port_rule.unwrap().adopted,
        ["tcp"]
    );
    ok(uninstall(&mut m, false, 0).0);
    assert_eq!(
        m.runner.ufw_rules,
        ["allow 443/tcp"],
        "only the udp rule was ours"
    );
}

#[test]
fn moving_the_port_leaves_an_adopted_rule_alone() {
    let mut m = Machine::new();
    m.runner.ufw = Some(true);
    m.runner.ufw_rules.push("allow 443/tcp".into());
    m.runner.ufw_foreign.insert("allow 443/tcp".into());
    let dir = release(&mut m, &Tamper::default());
    assert_eq!(full_install(&mut m, &dir), 0);
    assert_eq!(rerun_ssh(&mut m, &[("--port", "8443")]), 0);
    assert_eq!(
        port_rules(&m),
        ["allow 443/tcp", "allow 8443/tcp", "allow 8443/udp"]
    );
    assert!(
        m.state()
            .unwrap()
            .created
            .port_rule
            .unwrap()
            .adopted
            .is_empty()
    );
    ok(uninstall(&mut m, false, 0).0);
    assert_eq!(m.runner.ufw_rules, ["allow 443/tcp"]);
}

// ----- the bridge rules at uninstall ---------------------------------------------------------------

fn forward_drop() -> serde_json::Value {
    serde_json::json!({"chain": {"family": "inet", "table": "filter", "name": "forward", "handle": 2,
        "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}})
}

fn nft_rule_count(m: &Machine) -> usize {
    m.runner
        .nft_items
        .iter()
        .filter(|i| i.get("rule").is_some())
        .count()
}

#[test]
fn uninstall_removes_the_ufw_bridge_rules_except_an_adopted_one() {
    let mut m = Machine::new();
    m.runner.ufw = Some(true);
    // The administrator already allowed DNS over udp on the bridge.
    let theirs = "allow in on hxbr0 to any port 53 proto udp".to_owned();
    m.runner.ufw_rules.push(theirs.clone());
    m.runner.ufw_foreign.insert(theirs.clone());
    let dir = release(&mut m, &Tamper::default());
    assert_eq!(full_install(&mut m, &dir), 0);
    let rec = m.state().unwrap().created.port_rule.unwrap();
    assert_eq!(rec.adopted, ["bridge:dns-udp"]);
    assert_eq!(bridge_rules(&m).len(), 4);
    // A re-run keeps the adoption.
    assert_eq!(rerun_ssh(&mut m, &[]), 0);
    assert_eq!(
        m.state().unwrap().created.port_rule.unwrap().adopted,
        ["bridge:dns-udp"]
    );
    ok(uninstall(&mut m, false, 0).0);
    assert_eq!(
        m.runner.ufw_rules,
        [theirs],
        "only the adopted rule is left"
    );
}

#[test]
fn uninstall_removes_every_ufw_bridge_rule_when_the_state_is_unreadable_or_the_install_half_done() {
    // Unreadable state: found by the hash-xcreen comment, the administrator's rules stay.
    let mut m = Machine::new();
    m.runner.ufw = Some(true);
    m.runner
        .ufw_rules
        .push("allow in on eth0 to any port 53 proto udp".into());
    m.runner
        .ufw_foreign
        .insert("allow in on eth0 to any port 53 proto udp".into());
    let dir = release(&mut m, &Tamper::default());
    assert_eq!(full_install(&mut m, &dir), 0);
    std::fs::write(path(&m, paths::STATE_FILE), b"{ not json").unwrap();
    ok(uninstall(&mut m, false, 0).0);
    assert_eq!(
        m.runner.ufw_rules,
        ["allow in on eth0 to any port 53 proto udp"]
    );
    // Half done: the third bridge rule failed; uninstall removes the ones that went in.
    let mut m = Machine::new();
    m.runner.ufw = Some(true);
    m.runner.fail_on(Tool::Ufw, "port 53 proto tcp", 1, Some(1));
    let dir = release(&mut m, &Tamper::default());
    assert_eq!(full_install(&mut m, &dir), 1);
    assert!(!m.runner.ufw_rules.is_empty());
    ok(uninstall(&mut m, false, 0).0);
    assert!(m.runner.ufw_rules.is_empty(), "{:?}", m.runner.ufw_rules);
}

#[test]
fn uninstall_removes_the_nft_bridge_rules_in_input_and_forward_chains_even_if_they_stopped_dropping()
 {
    let mut m = Machine::new();
    m.runner
        .nft_items
        .push(drop_chain("inet", "filter", "input"));
    m.runner.nft_items.push(forward_drop());
    let dir = release(&mut m, &Tamper::default());
    assert_eq!(full_install(&mut m, &dir), 0);
    assert_eq!(nft_rule_count(&m), 5, "port + 2 input + 2 forward");
    // The forward chain no longer drops.
    m.runner.nft_items[1]["chain"]["policy"] = serde_json::json!("accept");
    ok(uninstall(&mut m, false, 0).0);
    assert_eq!(nft_rule_count(&m), 0);
    // And with an unreadable state.
    let mut m = Machine::new();
    m.runner
        .nft_items
        .push(drop_chain("inet", "filter", "input"));
    m.runner.nft_items.push(forward_drop());
    let dir = release(&mut m, &Tamper::default());
    assert_eq!(full_install(&mut m, &dir), 0);
    std::fs::write(path(&m, paths::STATE_FILE), b"\xff").unwrap();
    ok(uninstall(&mut m, false, 0).0);
    assert_eq!(nft_rule_count(&m), 0);
}

#[test]
fn stale_nft_bridge_rules_are_cleaned_when_a_chain_stops_dropping() {
    let mut m = Machine::new();
    m.runner
        .nft_items
        .push(drop_chain("inet", "filter", "input"));
    m.runner.nft_items.push(forward_drop());
    let dir = release(&mut m, &Tamper::default());
    assert_eq!(full_install(&mut m, &dir), 0);
    m.runner.nft_items[1]["chain"]["policy"] = serde_json::json!("accept");
    assert_eq!(rerun_ssh(&mut m, &[]), 0);
    assert_eq!(
        nft_rule_count(&m),
        3,
        "only the input chain keeps its rules"
    );
}

#[test]
fn uninstall_removes_our_legacy_out_route_rule_but_never_an_adopted_one() {
    for adopted in [false, true] {
        let mut m = Machine::new();
        m.runner.ufw = Some(true);
        let dir = release(&mut m, &Tamper::default());
        assert_eq!(full_install(&mut m, &dir), 0);
        let legacy = "route allow out on hxbr0".to_owned();
        m.runner.ufw_rules.push(legacy.clone());
        if adopted {
            m.runner.ufw_foreign.insert(legacy.clone());
            let mut st = m.state().unwrap();
            st.created
                .port_rule
                .as_mut()
                .unwrap()
                .adopted
                .push("bridge:route-out".into());
            hx_agent::install::state::save(&m.paths.at(paths::STATE_FILE), &st).unwrap();
        }
        ok(uninstall(&mut m, false, 0).0);
        if adopted {
            assert_eq!(
                m.runner.ufw_rules,
                [legacy],
                "the administrator's rule stays"
            );
        } else {
            assert!(m.runner.ufw_rules.is_empty(), "{:?}", m.runner.ufw_rules);
        }
    }
    // An unreadable state: found by the comment, and only if it is ours.
    let mut m = Machine::new();
    m.runner.ufw = Some(true);
    let dir = release(&mut m, &Tamper::default());
    assert_eq!(full_install(&mut m, &dir), 0);
    m.runner.ufw_rules.push("route allow out on hxbr0".into());
    std::fs::write(path(&m, paths::STATE_FILE), b"{ no").unwrap();
    ok(uninstall(&mut m, false, 0).0);
    assert!(m.runner.ufw_rules.is_empty());
}
