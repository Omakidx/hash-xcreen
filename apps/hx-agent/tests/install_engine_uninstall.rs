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
}

impl Cleaner for FakeCleaner {
    fn empty_as_owner(&mut self, dir: &Path, uid: u32, gid: u32) -> io::Result<()> {
        self.calls
            .push((dir.to_string_lossy().into_owned(), uid, gid));
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
    let mut cleaner = FakeCleaner::default();
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
        "systemctl disable --now hx-privd.socket hx-privd.service hx-privd-rescue.service var-lib-hx-updates.mount hx-host-firewall.service hx-docker-user.service",
    );
    let fetch = index_of(&l, "systemctl stop hx-update-fetcher@*.service");
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
        "/usr/local/lib/systemd/system/hx-privd.service",
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
    assert_eq!(m.runner.ufw_rules.len(), 2);
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
