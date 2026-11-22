//! The install engine against a simulated host: every stage (run, skip when done, converge on
//! drift), the modes, preflight, the release check, the port rule, credentials, secrets canaries
//! and the JSON Lines output. Nothing here runs a real program or touches the real host.

mod install_engine_common;

use hx_agent::install::InstallArgs;
use hx_agent::install::options::Mode;
use hx_agent::install::paths;
use hx_agent::install::runner::Tool;
use hx_agent::install::state::STAGES;
use hx_agent::install::testing::Machine;
use install_engine_common::*;

fn fresh() -> (Machine, std::path::PathBuf) {
    let mut m = Machine::new();
    let dir = release(&mut m, &Tamper::default());
    (m, dir)
}

fn installed() -> (Machine, std::path::PathBuf) {
    let (mut m, dir) = fresh();
    assert_eq!(
        full_install(&mut m, &dir),
        0,
        "{}",
        String::from_utf8_lossy(&m.err)
    );
    (m, dir)
}

/// An `--ssh` re-run without a bootstrap directory (the release is installed).
fn rerun(m: &mut Machine, extra: &[(&'static str, &str)], flags: &[&'static str]) -> u8 {
    let mut a = ssh_args(std::path::Path::new("/nonexistent"), extra, flags);
    a.bootstrap_dir = None;
    m.install(a, Some(frames(None, None)))
}

// ----- a complete install ---------------------------------------------------------------------

#[test]
fn a_full_ssh_install_runs_every_stage_and_reports_it() {
    let (m, _dir) = installed();
    let lines = stage_lines(&m);
    let done: Vec<&str> = lines
        .iter()
        .filter(|(_, s)| matches!(s.as_str(), "done" | "deferred" | "skip"))
        .map(|(i, _)| i.as_str())
        .collect();
    // pairing-token is not part of --ssh; owner-key has no key to enrol.
    for id in STAGES.iter().filter(|i| **i != "pairing-token") {
        assert!(done.contains(id), "{id} did not finish: {lines:?}");
    }
    let r = m.result();
    assert_eq!(r["ok"], true);
    assert_eq!(r["exit"], 0);
    assert_eq!(r["port"], 443);
    assert_eq!(r["desktop"]["id"], "main");
    assert_eq!(r["desktop"]["path_taken"], "BUILD");
    assert_eq!(r["pairing"]["kind"], "none");
    assert_eq!(r["install_id"].as_str().unwrap().len(), 32);
    assert_eq!(r["server_public_key"].as_str().unwrap().len(), 64);
    assert_eq!(r["addresses"][0], "203.0.113.9");
    assert_eq!(r["port_rule"], "none");
    let st = m.state().unwrap();
    assert!(st.complete);
    assert_eq!(st.mode, "ssh");
    assert_eq!(st.stages["backup"].state, "deferred");
    assert_eq!(st.stages["owner-key"].state, "skipped");
    assert_eq!(st.created.incus.as_ref().unwrap().source, "distro");
    assert_eq!(st.created.socket_port, 443);
    assert!(st.created.user);
    assert_eq!(st.desktop.as_ref().unwrap().path_taken, "BUILD");
    assert_eq!(
        m.daemons.desktop_password.as_deref(),
        Some(PASSWORD.as_bytes())
    );
    assert_eq!(m.daemons.phase, hx_ipc::privd::pb::Phase::Ready);
}

#[test]
fn the_files_the_install_writes_are_all_there() {
    let (m, _d) = installed();
    for f in [
        "/etc/hx/gatewayd.toml",
        "/etc/hx/privd.toml",
        "/etc/hx/creds/pepper.cred",
        "/etc/hx/creds/identity.cred",
        paths::PORT_DROPIN,
        "/usr/local/lib/sysusers.d/hx-gatewayd.conf",
        "/usr/local/lib/tmpfiles.d/hx.conf",
        "/etc/logrotate.d/hx-audit",
        "/var/lib/hx/install-state.json",
        "/var/log/hx-install.log",
    ] {
        assert!(exists(&m, f), "{f}");
    }
    for f in hx_agent::install::units::FILES
        .iter()
        .filter(|f| f.dest == hx_agent::install::units::Dest::Unit)
    {
        assert!(unit_dir(&m).join(f.name).exists(), "{}", f.name);
    }
    assert_eq!(
        std::fs::read_link(path(&m, "/usr/lib/hx/current"))
            .unwrap()
            .to_string_lossy(),
        VERSION,
        "a relative link"
    );
    assert!(
        m.read("/etc/hx/gatewayd.toml")
            .unwrap()
            .contains("listen = \"[::]:443\"")
    );
    assert!(
        m.read("/etc/hx/privd.toml")
            .unwrap()
            .contains("channel = \"stable\"")
    );
    let dropin = m.read(paths::PORT_DROPIN).unwrap();
    assert!(dropin.contains("ListenStream=[::]:443") && dropin.contains("ListenDatagram=[::]:443"));
    for n in [
        "hx-privd.socket",
        "hx-privd.service",
        "hx-gatewayd-admin.socket",
        "hx-gatewayd.service",
        "var-lib-hx-updates.mount",
    ] {
        assert!(m.runner.active.contains(n), "{n} is started");
    }
    assert!(
        m.runner.enabled.contains("hx-host-firewall.service")
            && !m.runner.active.contains("hx-host-firewall.service")
    );
    assert!(m.runner.enabled.contains("hx-docker-user.service"));
    // The bootstrap directory is gone; modes are private where they must be.
    assert!(!exists(&m, "/var/lib/hx-bootstrap.test"));
    use std::os::unix::fs::PermissionsExt;
    let mode = |abs: &str| {
        std::fs::metadata(path(&m, abs))
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode("/etc/hx/creds"), 0o700);
    assert_eq!(mode("/etc/hx/creds/pepper.cred"), 0o600);
    assert_eq!(mode("/var/lib/hx/install-state.json"), 0o600);
    assert_eq!(mode("/var/log/hx-install.log"), 0o600);
    assert_eq!(mode("/etc/hx/gatewayd.toml"), 0o644);
}

#[test]
fn a_second_run_changes_nothing() {
    let (mut m, _d) = installed();
    let before = tree_hash(&m);
    m.runner.calls.clear();
    assert_eq!(
        rerun(&mut m, &[], &[]),
        0,
        "{}",
        String::from_utf8_lossy(&m.err)
    );
    assert_eq!(
        m.runner.mutating(),
        Vec::<String>::new(),
        "no tool call that changes the host"
    );
    assert_eq!(tree_hash(&m), before, "no file changed");
    let skipped = states(&m, "skip");
    for id in [
        "packages",
        "incus",
        "release",
        "system-files",
        "credentials",
        "config",
        "units",
        "setup-window",
        "firewall-port",
        "desktop",
        "verifiers",
    ] {
        assert!(
            skipped.contains(&id.to_owned()),
            "{id} should be skipped: {:?}",
            stage_lines(&m)
        );
    }
    assert!(String::from_utf8_lossy(&m.err).contains("already installed"));
    assert_eq!(m.daemons.count("create_desktop"), 1);
    assert!(m.state().unwrap().complete);
}

// ----- resume ---------------------------------------------------------------------------------

#[test]
fn resume_after_a_failure_at_every_stage() {
    for (idx, id) in STAGES.iter().enumerate() {
        if *id == "pairing-token" {
            continue; // not a stage of --ssh
        }
        let (mut m, dir) = fresh();
        let mut a = ssh_args(&dir, &[], &[]);
        a.test_fail_after = Some((*id).to_owned());
        let code = m.install(a, Some(frames(None, None)));
        assert_eq!(code, 1, "{id}");
        let r = m.result();
        assert_eq!(r["ok"], false);
        assert_eq!(r["code"], "TEST_HOOK");
        assert_eq!(r["stage"], *id);
        assert_eq!(r["retryable"], true);
        let err_text = String::from_utf8_lossy(&m.err).into_owned();
        assert!(
            err_text.contains("run the same command again") || *id == "preflight",
            "{err_text}"
        );
        if let Some(st) = m.state() {
            assert!(st.stages.contains_key(*id), "{id} is recorded");
            assert!(!st.complete || *id == "done");
        }
        // Run the same command again: it resumes and finishes.
        m.runner.calls.clear();
        // The bootstrap directory was removed on exit; install.sh makes a new one each run.
        let dir = release(&mut m, &Tamper::default());
        let code = m.install(ssh_args(&dir, &[], &[]), Some(frames(None, None)));
        assert_eq!(code, 0, "{id}: {}", String::from_utf8_lossy(&m.err));
        assert!(m.state().unwrap().complete, "{id}");
        // Everything up to the failed stage that has a done-check was skipped, not redone.
        let skipped = states(&m, "skip");
        for earlier in [
            "packages",
            "incus",
            "release",
            "system-files",
            "credentials",
            "config",
            "units",
        ] {
            let pos = STAGES.iter().position(|s| *s == earlier).unwrap();
            if pos <= idx {
                assert!(
                    skipped.contains(&earlier.to_owned()),
                    "{id}: {earlier} was redone: {:?}",
                    stage_lines(&m)
                );
            }
        }
        assert_eq!(m.daemons.count("create_desktop"), 1, "{id}: one desktop");
        let installs: Vec<String> = m
            .runner
            .lines()
            .into_iter()
            .filter(|l| l.starts_with("apt-get") && l.contains("install"))
            .collect();
        let mut unique = installs.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            installs.len(),
            unique.len(),
            "{id}: an apt install ran twice: {installs:?}"
        );
    }
}

#[test]
fn a_real_failure_is_recorded_and_resumed() {
    let (mut m, dir) = fresh();
    m.runner.fail_on(Tool::AptGet, "install", 100, Some(1));
    assert_eq!(
        m.install(ssh_args(&dir, &[], &[]), Some(frames(None, None))),
        1
    );
    let r = m.result();
    assert_eq!(r["stage"], "packages");
    assert_eq!(r["code"], "TOOL");
    assert_eq!(r["retryable"], true);
    let st = m.state().unwrap();
    assert_eq!(st.stages["packages"].state, "failed");
    assert_eq!(st.stages["packages"].error.as_ref().unwrap().code, "TOOL");
    assert!(!st.complete);
    assert!(String::from_utf8_lossy(&m.err).contains("stage 'packages' failed"));
    // The bootstrap directory is removed on every exit; install.sh makes a new one each run.
    let dir = release(&mut m, &Tamper::default());
    assert_eq!(
        m.install(ssh_args(&dir, &[], &[]), Some(frames(None, None))),
        0
    );
    assert!(m.state().unwrap().complete);
}

#[test]
fn a_failure_in_privd_maps_to_its_exit_code() {
    let (mut m, dir) = fresh();
    m.daemons.fail.insert(
        "create_desktop",
        hx_agent::install::error::InstallError::from(hx_agent::cli::error::CliError::Remote(
            hx_agent::cli::error::Remote {
                code: hx_ipc::privd::pb::ErrorCode::FailedPrecondition,
                detail: hx_ipc::privd::pb::ErrorDetail::Unspecified,
                message: "no space".into(),
                retryable: false,
                retry_after_ms: 0,
            },
        )),
    );
    assert_eq!(
        m.install(ssh_args(&dir, &[], &[]), Some(frames(None, None))),
        4
    );
    assert_eq!(m.result()["stage"], "desktop");
    assert_eq!(m.result()["exit"], 4);
    // privd unreachable: 3.
    let (mut m2, dir2) = fresh();
    m2.daemons.fail.insert(
        "begin_setup",
        hx_agent::install::error::InstallError::unavailable("down"),
    );
    assert_eq!(
        m2.install(ssh_args(&dir2, &[], &[]), Some(frames(None, None))),
        3
    );
}

// ----- converge on drift ----------------------------------------------------------------------

#[test]
fn packages_converge() {
    let (mut m, _d) = installed();
    m.runner.installed.remove("nftables");
    assert_eq!(rerun(&mut m, &[], &[]), 0);
    assert!(states(&m, "done").contains(&"packages".to_owned()));
    assert!(m.runner.installed.contains_key("nftables"));
}

#[test]
fn incus_converges() {
    let (mut m, _d) = installed();
    std::fs::remove_file(path(&m, "/var/lib/incus/unix.socket")).unwrap();
    m.runner.enabled.remove("incus.socket");
    assert_eq!(rerun(&mut m, &[], &[]), 0);
    assert!(states(&m, "done").contains(&"incus".to_owned()));
    assert!(exists(&m, "/var/lib/incus/unix.socket"));
    assert!(
        m.state().unwrap().created.incus.unwrap().by_installer,
        "still ours"
    );
}

#[test]
fn the_release_converges_from_a_new_bootstrap() {
    let (mut m, _d) = installed();
    std::fs::remove_file(path(&m, "/usr/lib/hx/current")).unwrap();
    let dir = release(&mut m, &Tamper::default());
    let mut a = ssh_args(&dir, &[], &[]);
    a.bootstrap_dir = Some(dir.to_string_lossy().into_owned());
    assert_eq!(
        m.install(a, Some(frames(None, None))),
        0,
        "{}",
        String::from_utf8_lossy(&m.err)
    );
    assert!(states(&m, "done").contains(&"release".to_owned()));
    assert!(path(&m, "/usr/lib/hx/current").exists());
}

#[test]
fn system_files_config_and_units_converge() {
    let (mut m, _d) = installed();
    std::fs::remove_file(path(&m, "/usr/local/lib/tmpfiles.d/hx.conf")).unwrap();
    std::fs::write(path(&m, "/etc/hx/gatewayd.toml"), "listen = \"[::]:1\"\n").unwrap();
    std::fs::write(unit_dir(&m).join("hx-privd.service"), "[Service]\n").unwrap();
    m.runner.active.remove("hx-privd.socket");
    assert_eq!(rerun(&mut m, &[], &[]), 0);
    let done = states(&m, "done");
    for id in ["system-files", "config", "units"] {
        assert!(done.contains(&id.to_owned()), "{id}: {:?}", stage_lines(&m));
    }
    assert!(exists(&m, "/usr/local/lib/tmpfiles.d/hx.conf"));
    assert!(
        m.read("/etc/hx/gatewayd.toml")
            .unwrap()
            .contains("[::]:443")
    );
    assert!(
        m.read("/usr/local/lib/systemd/system/hx-privd.service")
            .unwrap()
            .contains("ExecStart=")
    );
    assert!(m.runner.active.contains("hx-privd.socket"));
}

#[test]
fn credentials_converge_and_keep_the_identity() {
    let (mut m, _d) = installed();
    let key = m.state().unwrap().server_public_key;
    std::fs::remove_file(path(&m, "/etc/hx/creds/pepper.cred")).unwrap();
    assert_eq!(rerun(&mut m, &[], &[]), 0);
    assert!(states(&m, "done").contains(&"credentials".to_owned()));
    assert!(exists(&m, "/etc/hx/creds/pepper.cred"));
    assert_eq!(
        m.state().unwrap().server_public_key,
        key,
        "the identity key is unchanged"
    );
}

#[test]
fn a_lost_desktop_is_created_again() {
    let (mut m, _d) = installed();
    m.daemons.desktop = None;
    assert_eq!(rerun(&mut m, &[], &[]), 0);
    assert!(states(&m, "done").contains(&"desktop".to_owned()));
    assert_eq!(m.daemons.count("create_desktop"), 2);
}

#[test]
fn a_changed_limit_is_applied_not_refused() {
    let (mut m, _d) = installed();
    assert_eq!(
        rerun(&mut m, &[("--cpu", "2")], &[]),
        0,
        "{}",
        String::from_utf8_lossy(&m.err)
    );
    assert_eq!(m.daemons.limit_calls.len(), 1);
    assert_eq!(m.daemons.limit_calls[0].cpu, 2);
    assert_eq!(
        m.daemons.limit_calls[0].memory_mib, 4096,
        "unspecified limits keep their value"
    );
    assert_eq!(m.daemons.count("create_desktop"), 1);
    assert_eq!(m.state().unwrap().options.cpu, Some(2));
}

#[test]
fn the_resolver_dropin_follows_resolv_conf() {
    let (mut m, dir) = fresh();
    std::fs::write(
        path(&m, "/etc/resolv.conf"),
        "nameserver 10.0.0.2\nnameserver 8.8.8.8\n",
    )
    .unwrap();
    assert_eq!(full_install(&mut m, &dir), 0);
    let d = m.read(paths::RESOLVERS_DROPIN).unwrap();
    assert!(d.contains("IPAddressAllow=10.0.0.2/32") && !d.contains("8.8.8.8"));
    assert!(
        m.state()
            .unwrap()
            .created
            .dropins
            .iter()
            .any(|x| x == paths::RESOLVERS_DROPIN)
    );
    std::fs::write(path(&m, "/etc/resolv.conf"), "nameserver 8.8.8.8\n").unwrap();
    assert_eq!(rerun(&mut m, &[], &[]), 0);
    assert!(
        !exists(&m, paths::RESOLVERS_DROPIN),
        "removed when no resolver needs it"
    );
    assert!(
        !m.state()
            .unwrap()
            .created
            .dropins
            .iter()
            .any(|x| x == paths::RESOLVERS_DROPIN)
    );
}

// ----- options on a re-run --------------------------------------------------------------------

#[test]
fn fixed_options_conflict_with_exit_12_and_change_nothing() {
    let (mut m, _d) = installed();
    let before = tree_hash(&m);
    m.runner.calls.clear();
    for (extra, flags, needle, remedy) in [
        (
            vec![("--user", "bob")],
            vec![],
            "--user",
            "uninstall --destroy-desktop",
        ),
        (
            vec![("--distro", "debian-13")],
            vec![],
            "--distro",
            "uninstall --destroy-desktop",
        ),
        (
            vec![("--hostname", "other")],
            vec![],
            "--hostname",
            "uninstall --destroy-desktop",
        ),
        (vec![], vec!["--docker"], "--docker", "docker enable"),
    ] {
        assert_eq!(rerun(&mut m, &extra, &flags), 12, "{needle}");
        let r = m.result();
        assert_eq!(r["code"], "CONFLICT");
        let msg = r["message"].as_str().unwrap();
        assert!(msg.contains(needle) && msg.contains(remedy), "{msg}");
    }
    assert_eq!(m.runner.mutating(), Vec::<String>::new());
    assert_eq!(tree_hash(&m), before);
}

#[test]
fn fixed_options_may_change_while_the_desktop_is_not_ready() {
    let (mut m, dir) = fresh();
    let mut a = ssh_args(&dir, &[], &[]);
    a.test_fail_after = Some("host".into());
    assert_eq!(m.install(a, Some(frames(None, None))), 1);
    // The desktop stage has not run: another user is fine.
    let mut a2 = ssh_args(&dir, &[("--user", "bob")], &[]);
    a2.bootstrap_dir = Some(dir.to_string_lossy().into_owned());
    assert_eq!(
        m.install(a2, Some(frames(None, None))),
        0,
        "{}",
        String::from_utf8_lossy(&m.err)
    );
    assert_eq!(m.daemons.create_requests[0].username, "bob");
}

#[test]
fn a_changed_port_moves_the_socket_and_the_rule() {
    let (mut m, dir) = fresh();
    m.runner.ufw = Some(true);
    assert_eq!(full_install(&mut m, &dir), 0);
    assert_eq!(port_rules(&m), ["allow 443/tcp", "allow 443/udp"]);
    assert_eq!(m.result()["port_rule"], "ufw");
    m.runner.calls.clear();
    assert_eq!(
        rerun(&mut m, &[("--port", "8443")], &[]),
        0,
        "{}",
        String::from_utf8_lossy(&m.err)
    );
    assert_eq!(port_rules(&m), ["allow 8443/tcp", "allow 8443/udp"]);
    assert_eq!(
        bridge_rules(&m).len(),
        4,
        "the bridge rules stay when the port moves"
    );
    assert!(
        m.read(paths::PORT_DROPIN)
            .unwrap()
            .contains("ListenStream=[::]:8443")
    );
    assert!(
        m.read("/etc/hx/gatewayd.toml")
            .unwrap()
            .contains("[::]:8443")
    );
    assert!(
        m.runner
            .lines()
            .iter()
            .any(|l| l == "systemctl restart hx-gatewayd-public.socket hx-gatewayd.service")
    );
    assert_eq!(m.state().unwrap().created.socket_port, 8443);
    assert_eq!(m.result()["port"], 8443);
}

#[test]
fn the_channel_and_private_networks_are_reconciled() {
    let (mut m, _d) = installed();
    assert_eq!(
        rerun(
            &mut m,
            &[("--channel", "beta")],
            &["--allow-private-networks"]
        ),
        0
    );
    assert!(
        m.read("/etc/hx/privd.toml")
            .unwrap()
            .contains("channel = \"beta\"")
    );
    assert_eq!(
        m.daemons
            .host_requests
            .last()
            .unwrap()
            .allow_private_networks,
        Some(true)
    );
}

// ----- the port rule --------------------------------------------------------------------------

fn nft_input_drop() -> serde_json::Value {
    serde_json::json!({"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 1,
        "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}})
}

fn our_rules(m: &Machine) -> Vec<u64> {
    m.runner
        .nft_items
        .iter()
        .filter_map(|i| i.get("rule"))
        .filter(|r| r["comment"] == "hx-agent-port")
        .map(|r| r["handle"].as_u64().unwrap())
        .collect()
}

#[test]
fn nft_gets_one_rule_and_a_unit_that_brings_it_back() {
    let (mut m, dir) = fresh();
    m.runner.nft_items.push(nft_input_drop());
    assert_eq!(
        full_install(&mut m, &dir),
        0,
        "{}",
        String::from_utf8_lossy(&m.err)
    );
    assert_eq!(m.result()["port_rule"], "nft");
    assert_eq!(our_rules(&m).len(), 1);
    assert!(m.runner.enabled.contains("hx-agent-port.service"));
    // A reload of the ruleset drops the rule: the next run puts it back (check, not skip).
    m.runner.nft_items.retain(|i| i.get("rule").is_none());
    assert_eq!(rerun(&mut m, &[], &[]), 0);
    assert!(states(&m, "done").contains(&"firewall-port".to_owned()));
    assert_eq!(our_rules(&m).len(), 1);
    // And a second time it is left alone.
    m.runner.calls.clear();
    assert_eq!(rerun(&mut m, &[], &[]), 0);
    assert!(!m.runner.mutating().iter().any(|l| l.starts_with("nft")));
    // A port change moves the rule.
    assert_eq!(rerun(&mut m, &[("--port", "8443")], &[]), 0);
    let rules = our_rules(&m);
    assert_eq!(rules.len(), 1);
    let port = m
        .runner
        .nft_items
        .iter()
        .filter_map(|i| i.get("rule"))
        .find(|r| r["comment"] == "hx-agent-port")
        .unwrap()["expr"][0]["match"]["right"]
        .clone();
    assert_eq!(port, 8443);
}

#[test]
fn firewalld_is_a_manual_step_with_the_commands() {
    let (mut m, dir) = fresh();
    m.runner.active.insert("firewalld".into());
    assert_eq!(full_install(&mut m, &dir), 0);
    assert_eq!(m.result()["port_rule"], "manual");
    assert_eq!(m.state().unwrap().stages["firewall-port"].state, "manual");
    let warns: Vec<String> = m
        .json_lines()
        .iter()
        .filter(|v| v["t"] == "warn")
        .map(|v| v["message"].as_str().unwrap().to_owned())
        .collect();
    assert!(
        warns
            .iter()
            .any(|w| w.contains("firewall-cmd --permanent --add-port=443/tcp")),
        "{warns:?}"
    );
    assert!(m.state().unwrap().complete);
}

#[test]
fn an_iptables_drop_is_a_manual_step_too() {
    let (mut m, dir) = fresh();
    m.runner.iptables_input = "-P INPUT DROP\n".into();
    assert_eq!(full_install(&mut m, &dir), 0);
    assert_eq!(m.result()["port_rule"], "manual");
}

// ----- preflight ------------------------------------------------------------------------------

fn preflight_fails(setup: impl FnOnce(&mut Machine), needle: &str) {
    let (mut m, dir) = fresh();
    setup(&mut m);
    assert_eq!(
        m.install(ssh_args(&dir, &[], &[]), Some(frames(None, None))),
        9,
        "{needle}"
    );
    let r = m.result();
    assert_eq!(r["code"], "PREFLIGHT");
    assert!(
        r["message"].as_str().unwrap().contains(needle),
        "{needle}: {}",
        r["message"]
    );
    assert!(m.state().is_none(), "preflight records nothing");
    assert!(
        !path(&m, "/var/lib/hx-bootstrap.test").exists(),
        "the bootstrap directory is removed"
    );
    assert_eq!(
        m.runner.mutating(),
        Vec::<String>::new(),
        "nothing was changed"
    );
    assert!(
        m.daemons
            .log
            .iter()
            .all(|l| l == "hello" || l == "host_info")
            || m.daemons.log.is_empty()
    );
    assert_eq!(m.daemons.count("begin_setup"), 0);
}

#[test]
fn preflight_refuses_ubuntu_22_04() {
    preflight_fails(
        |m| {
            std::fs::write(
                path(m, paths::OS_RELEASE),
                "ID=ubuntu\nVERSION_ID=\"22.04\"\n",
            )
            .unwrap()
        },
        "Ubuntu 22.04 is not supported",
    );
}

#[test]
fn preflight_refuses_other_distros_and_architectures() {
    preflight_fails(
        |m| std::fs::write(path(m, paths::OS_RELEASE), "ID=fedora\nVERSION_ID=40\n").unwrap(),
        "not supported",
    );
    preflight_fails(|m| m.probe.machine = "aarch64".into(), "x86_64");
}

#[test]
fn preflight_refuses_an_old_systemd_and_a_missing_one() {
    preflight_fails(|m| m.runner.systemd = 249, "systemd 249 is too old");
    preflight_fails(
        |m| std::fs::remove_dir_all(path(m, "/run/systemd/system")).unwrap(),
        "not the init system",
    );
}

#[test]
fn preflight_refuses_missing_kernel_features() {
    preflight_fails(
        |m| std::fs::remove_file(path(m, "/sys/fs/cgroup/cgroup.controllers")).unwrap(),
        "cgroup v2",
    );
    preflight_fails(
        |m| std::fs::write(path(m, "/proc/sys/user/max_user_namespaces"), "0\n").unwrap(),
        "user namespaces",
    );
}

#[test]
fn preflight_refuses_a_container_unless_the_test_hook_allows_it() {
    preflight_fails(|m| m.runner.virt = "lxc".into(), "container");
    let (mut m, dir) = fresh();
    m.runner.virt = "lxc".into();
    let mut a = ssh_args(&dir, &[], &[]);
    a.test_allow_container = true;
    assert_eq!(m.install(a, Some(frames(None, None))), 0);
}

#[test]
fn preflight_checks_memory_cpus_and_disk() {
    preflight_fails(
        |m| std::fs::write(path(m, "/proc/meminfo"), "MemTotal: 2000000 kB\n").unwrap(),
        "MiB of RAM",
    );
    preflight_fails(|m| m.probe.cpus = 1, "1 CPU");
    preflight_fails(|m| m.probe.free_gib = 10, "10 GiB free");
}

#[test]
fn preflight_checks_the_port() {
    preflight_fails(
        |m| {
            m.probe.busy_ports.insert(443);
        },
        "port 443 is in use",
    );
}

#[test]
fn preflight_refuses_a_missing_release_and_missing_user() {
    let mut m = Machine::new();
    let mut a = ssh_args(std::path::Path::new("/x"), &[], &[]);
    a.bootstrap_dir = None;
    assert_eq!(m.install(a, Some(frames(None, None))), 9);
    assert!(
        m.result()["message"]
            .as_str()
            .unwrap()
            .contains("no release to install")
    );
    let (mut m2, dir) = fresh();
    let mut a = ssh_args(&dir, &[], &[]);
    a.raw.values.remove("--user");
    assert_eq!(m2.install(a, Some(frames(None, None))), 9);
    assert!(
        m2.result()["message"]
            .as_str()
            .unwrap()
            .contains("--user is required")
    );
}

#[test]
fn preflight_checks_the_storage_device() {
    use hx_agent::install::probe::BlockInfo;
    let ok = BlockInfo {
        is_block: true,
        size_gib: 100,
        whole_disk: true,
        mounted: false,
        signature: false,
    };
    let dev = |m: &mut Machine, i: BlockInfo| {
        m.probe.blocks.insert("/dev/sdb".into(), i);
    };
    let run = |i: BlockInfo| {
        let (mut m, dir) = fresh();
        dev(&mut m, i);
        let code = m.install(
            ssh_args(&dir, &[("--storage-device", "/dev/sdb")], &[]),
            Some(frames(None, None)),
        );
        (code, m)
    };
    assert_eq!(run(ok.clone()).0, 0);
    for (bad, needle) in [
        (
            BlockInfo {
                whole_disk: false,
                ..ok.clone()
            },
            "partition",
        ),
        (
            BlockInfo {
                mounted: true,
                ..ok.clone()
            },
            "mounted",
        ),
        (
            BlockInfo {
                signature: true,
                ..ok.clone()
            },
            "signature",
        ),
        (
            BlockInfo {
                size_gib: 10,
                ..ok.clone()
            },
            "10 GiB",
        ),
        (
            BlockInfo {
                is_block: false,
                ..ok.clone()
            },
            "not a block device",
        ),
    ] {
        let (code, m) = run(bad);
        assert_eq!(code, 9, "{needle}");
        assert!(
            m.result()["message"].as_str().unwrap().contains(needle),
            "{needle}"
        );
    }
    // The device reaches SetupHost.
    let (_, m) = run(ok);
    assert_eq!(
        m.daemons.host_requests[0].pool_device.as_deref(),
        Some("/dev/sdb")
    );
}

#[test]
fn prebuilt_images_and_image_files_are_not_in_this_release() {
    for extra in [
        ("--image", "prebuilt"),
        ("--image-file", "/var/lib/hx/import/a.img"),
    ] {
        let (mut m, dir) = fresh();
        assert_eq!(
            m.install(ssh_args(&dir, &[extra], &[]), Some(frames(None, None))),
            6,
            "{extra:?}"
        );
        assert_eq!(m.result()["code"], "UNIMPLEMENTED");
        assert!(m.state().is_none());
        assert_eq!(m.runner.mutating(), Vec::<String>::new());
    }
    let (mut m, dir) = fresh();
    assert_eq!(
        m.install(
            ssh_args(&dir, &[("--image", "build")], &[]),
            Some(frames(None, None))
        ),
        0
    );
    assert_eq!(
        m.daemons.create_requests[0].image_mode,
        hx_ipc::privd::pb::ImageMode::Build as i32
    );
}

// ----- incus ----------------------------------------------------------------------------------

#[test]
fn an_existing_incus_is_adopted_and_never_installed_or_upgraded() {
    let (mut m, dir) = fresh();
    m.runner
        .installed
        .insert("incus".into(), "1:6.0.4-1ubuntu1".into());
    assert_eq!(full_install(&mut m, &dir), 0);
    let rec = m.state().unwrap().created.incus.unwrap();
    assert!(!rec.by_installer);
    assert_eq!(rec.source, "existing");
    assert!(
        !m.runner
            .lines()
            .iter()
            .any(|l| l.contains("install") && l.contains("incus"))
    );
    // A socket without a package (a snap) is adopted too.
    let (mut m, dir) = fresh();
    std::fs::create_dir_all(path(&m, "/var/lib/incus")).unwrap();
    std::fs::write(path(&m, "/var/lib/incus/unix.socket"), b"").unwrap();
    assert_eq!(full_install(&mut m, &dir), 0);
    assert!(!m.state().unwrap().created.incus.unwrap().by_installer);
}

#[test]
fn an_incus_that_is_too_old_is_refused_at_preflight() {
    preflight_fails(
        |m| {
            m.runner.installed.insert("incus".into(), "5.0.2-1".into());
        },
        "older than 6.0.0",
    );
}

#[test]
fn docker_needs_6_0_5_and_an_existing_incus_is_never_upgraded_for_it() {
    let (mut m, dir) = fresh();
    m.runner
        .installed
        .insert("incus".into(), "1:6.0.4-1".into());
    assert_eq!(
        m.install(ssh_args(&dir, &[], &["--docker"]), Some(frames(None, None))),
        9
    );
    assert!(m.result()["message"].as_str().unwrap().contains("6.0.5"));
    assert!(m.state().is_none());
}

#[test]
fn the_distro_incus_is_used_when_new_enough_for_docker() {
    let (mut m, dir) = fresh();
    m.runner.apt_candidate = Some("1:6.0.5-1".into());
    m.runner
        .apt_versions
        .insert("incus".into(), "1:6.0.5-1".into());
    m.daemons.incus_version = Some("6.0.5".into());
    assert_eq!(
        m.install(ssh_args(&dir, &[], &["--docker"]), Some(frames(None, None))),
        0,
        "{}",
        String::from_utf8_lossy(&m.err)
    );
    assert_eq!(m.state().unwrap().created.incus.unwrap().source, "distro");
    let req = &m.daemons.create_requests[0];
    assert!(req.docker && req.docker_isolation_acknowledged);
}

#[test]
fn zabbly_is_used_only_when_needed_and_its_key_is_pinned() {
    // The Zabbly key file is not provisioned in this build: a host that needs it fails clearly.
    let (mut m, dir) = fresh();
    m.runner.apt_candidate = Some("1:5.0.2-1".into());
    let code = m.install(ssh_args(&dir, &[], &[]), Some(frames(None, None)));
    if hx_agent::install::zabbly::embedded_key().is_none() {
        assert_eq!(code, 9);
        let r = m.result();
        assert_eq!(r["stage"], "incus");
        assert!(
            r["message"].as_str().unwrap().contains("Zabbly"),
            "{}",
            r["message"]
        );
        assert!(!exists(&m, paths::ZABBLY_KEY), "nothing was written");
        assert!(!exists(&m, paths::ZABBLY_SOURCES));
    } else {
        assert_eq!(code, 0, "{}", String::from_utf8_lossy(&m.err));
        let src = m.read(paths::ZABBLY_SOURCES).unwrap();
        assert!(
            src.contains("Suites: noble")
                && src.contains("Signed-By: /etc/apt/keyrings/hx-zabbly.asc")
        );
        assert_eq!(m.state().unwrap().created.incus.unwrap().source, "zabbly");
    }
}

// ----- the release ----------------------------------------------------------------------------

fn release_fails(t: Tamper, needle: &str) {
    let mut m = Machine::new();
    let dir = release(&mut m, &t);
    assert_eq!(
        m.install(ssh_args(&dir, &[], &[]), Some(frames(None, None))),
        10,
        "{needle}"
    );
    let r = m.result();
    assert_eq!(r["stage"], "release");
    assert_eq!(r["code"], "VERIFY");
    assert!(
        r["message"].as_str().unwrap().contains(needle),
        "{needle}: {}",
        r["message"]
    );
    assert!(!exists(&m, "/usr/lib/hx/current"), "nothing was switched");
    let versions: Vec<_> = std::fs::read_dir(path(&m, "/usr/lib/hx"))
        .map(|d| d.flatten().collect())
        .unwrap_or_default();
    assert!(
        versions.is_empty(),
        "no partial release is left: {versions:?}"
    );
    assert!(
        !dir.exists(),
        "the bootstrap directory is removed on every exit"
    );
    assert_eq!(m.state().unwrap().stages["release"].state, "failed");
    assert_eq!(m.daemons.count("begin_setup"), 0);
}

#[test]
fn a_signature_from_another_key_is_refused() {
    release_fails(
        Tamper {
            wrong_signer: true,
            ..Tamper::default()
        },
        "signature",
    );
}

#[test]
fn a_damaged_signature_is_refused() {
    release_fails(
        Tamper {
            truncate_signature: true,
            ..Tamper::default()
        },
        "signature",
    );
}

#[test]
fn a_release_of_another_version_is_refused() {
    release_fails(
        Tamper {
            version: Some("9.9.9".into()),
            ..Tamper::default()
        },
        "9.9.9",
    );
}

#[test]
fn a_manifest_for_another_channel_is_refused() {
    release_fails(
        Tamper {
            channel: Some("beta".into()),
            ..Tamper::default()
        },
        "manifest",
    );
}

#[test]
fn a_changed_artifact_is_refused() {
    release_fails(
        Tamper {
            flip_artifact_byte: true,
            ..Tamper::default()
        },
        "SHA-256",
    );
}

#[test]
fn an_incomplete_release_is_refused() {
    release_fails(
        Tamper {
            drop_member: Some("hx-agent"),
            ..Tamper::default()
        },
        "incomplete",
    );
}

#[test]
fn a_bootstrap_directory_that_is_not_private_or_is_a_link_is_refused() {
    release_fails(
        Tamper {
            dir_mode: Some(0o755),
            ..Tamper::default()
        },
        "0700",
    );
    let mut m = Machine::new();
    let dir = release(&mut m, &Tamper::default());
    let link = m.paths.at("/var/lib/hx-bootstrap.link");
    std::os::unix::fs::symlink(&dir, &link).unwrap();
    let mut a = ssh_args(&link, &[], &[]);
    a.bootstrap_dir = Some(link.to_string_lossy().into_owned());
    assert_eq!(m.install(a, Some(frames(None, None))), 10);
    assert!(m.result()["message"].as_str().unwrap().contains("symlink"));
}

#[test]
fn the_rescue_helper_is_installed_outside_the_release_directory() {
    let mut m = Machine::new();
    let dir = release(
        &mut m,
        &Tamper {
            rescue: true,
            ..Tamper::default()
        },
    );
    assert_eq!(
        m.install(ssh_args(&dir, &[], &[]), Some(frames(None, None))),
        0,
        "{}",
        String::from_utf8_lossy(&m.err)
    );
    use std::os::unix::fs::PermissionsExt;
    let p = path(&m, paths::RESCUE_BIN);
    assert_eq!(
        std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert!(
        m.state()
            .unwrap()
            .created
            .files
            .iter()
            .any(|f| f == paths::RESCUE_BIN)
    );
    // Without it in the release the install warns and goes on.
    let (m2, _d2) = installed();
    assert!(!exists(&m2, paths::RESCUE_BIN));
    assert!(m2.json_lines().iter().any(|v| v["t"] == "warn" && v["message"].as_str().unwrap().contains("hx-privd-rescue")));
}

// ----- credentials ----------------------------------------------------------------------------

fn key_bytes(fill: u8) -> Vec<u8> {
    vec![fill; 32]
}

#[test]
fn the_sealed_secrets_go_through_stdin_not_argv() {
    let (m, _d) = installed();
    let enc: Vec<_> = m
        .runner
        .calls
        .iter()
        .filter(|c| c.tool == Tool::SystemdCreds && c.args[0] == "encrypt")
        .collect();
    assert_eq!(enc.len(), 2, "pepper and identity");
    for c in &enc {
        assert_eq!(c.stdin.as_ref().unwrap().len(), 32);
        let hexed = hx_agent::cli::text::hex(c.stdin.as_ref().unwrap());
        assert!(c.args.iter().all(|a| !a.contains(&hexed)));
        assert_eq!(c.args[2], "-");
        assert!(c.env.is_empty());
    }
    assert_eq!(enc[0].args[1], "--name=pepper");
    assert_eq!(enc[1].args[1], "--name=identity");
    assert!(!exists(&m, "/var/lib/hx/pepper.key"));
}

#[test]
fn an_old_pepper_key_is_migrated_and_wiped_when_the_macs_match() {
    let (mut m, dir) = fresh();
    std::fs::create_dir_all(path(&m, "/var/lib/hx")).unwrap();
    std::fs::write(path(&m, paths::PEPPER_KEY), key_bytes(3)).unwrap();
    assert_eq!(
        full_install(&mut m, &dir),
        0,
        "{}",
        String::from_utf8_lossy(&m.err)
    );
    assert!(!exists(&m, paths::PEPPER_KEY), "removed after the check");
    assert!(exists(&m, "/etc/hx/creds/pepper.cred"));
    assert!(
        m.runner
            .calls
            .iter()
            .any(|c| c.tool == Tool::Systemctl && c.args == ["restart", "hx-privd.service"])
    );
    assert!(m.daemons.count("pepper_enrol") >= 2);
}

#[test]
fn a_migration_whose_macs_differ_keeps_the_key_and_fails() {
    let (mut m, dir) = fresh();
    std::fs::create_dir_all(path(&m, "/var/lib/hx")).unwrap();
    std::fs::write(path(&m, paths::PEPPER_KEY), key_bytes(3)).unwrap();
    m.daemons.pepper_after_restart = Some([9u8; 32]);
    assert_eq!(full_install(&mut m, &dir), 1);
    assert_eq!(m.result()["stage"], "credentials");
    assert!(exists(&m, paths::PEPPER_KEY), "the key stays");
    assert!(
        !exists(&m, "/etc/hx/creds/pepper.cred"),
        "the sealed copy is removed"
    );
}

#[test]
fn a_leftover_key_equal_to_the_sealed_pepper_is_wiped_and_a_different_one_is_kept_aside() {
    let (mut m, _d) = installed();
    let sealed = m.read("/etc/hx/creds/pepper.cred").unwrap();
    let hexed = sealed.rsplit(':').next().unwrap().trim().to_owned();
    let plain: Vec<u8> = (0..hexed.len() / 2)
        .map(|i| u8::from_str_radix(&hexed[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    std::fs::create_dir_all(path(&m, "/var/lib/hx")).unwrap();
    std::fs::write(path(&m, paths::PEPPER_KEY), &plain).unwrap();
    assert_eq!(rerun(&mut m, &[], &[]), 0);
    assert!(!exists(&m, paths::PEPPER_KEY));
    std::fs::write(path(&m, paths::PEPPER_KEY), key_bytes(77)).unwrap();
    assert_eq!(rerun(&mut m, &[], &[]), 0);
    assert!(!exists(&m, paths::PEPPER_KEY));
    let orphans: Vec<_> = std::fs::read_dir(path(&m, "/var/lib/hx"))
        .unwrap()
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("pepper.key.orphaned-")
        })
        .collect();
    assert_eq!(orphans.len(), 1);
}

// ----- the modes ------------------------------------------------------------------------------

#[test]
fn a_fresh_host_needs_a_mode() {
    let (mut m, _d) = fresh();
    assert_eq!(m.install(InstallArgs::default(), None), 2);
    assert_eq!(m.result()["code"], "USAGE");
    assert!(m.state().is_none());
}

#[test]
fn not_root_is_exit_7() {
    use hx_agent::install::{Deps, StdinSource};
    let mut m = Machine::new();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = hx_agent::install::run(
        InstallArgs {
            mode: Some(Mode::Pair),
            ..InstallArgs::default()
        },
        Deps {
            paths: m.paths.clone(),
            runner: &mut m.runner,
            daemons: &mut m.daemons,
            probe: &m.probe,
            prompt: &mut m.tty,
            out: &mut out,
            err: &mut err,
            json: true,
            now: || NOW,
            keys: m.keys.clone(),
            verifier_params: hx_crypto::PinParams {
                memory_kib: 64,
                iterations: 1,
                parallelism: 1,
            },
            euid: 1000,
            timing: Default::default(),
            stdin: StdinSource::Frames(None),
        },
    );
    assert_eq!(code, 7);
    assert!(String::from_utf8_lossy(&out).contains("\"code\":\"NOT_ROOT\""));
    assert!(m.runner.calls.is_empty());
}

#[test]
fn the_lock_gives_exit_11() {
    let (mut m, dir) = fresh();
    let held = hx_agent::install::lock::acquire(&path(&m, paths::LOCK_FILE), None).unwrap();
    assert_eq!(full_install(&mut m, &dir), 11);
    let r = m.result();
    assert_eq!(r["code"], "LOCKED");
    assert_eq!(r["exit"], 11);
    assert!(m.state().is_none());
    assert!(m.runner.calls.is_empty());
    drop(held);
    let dir = release(&mut m, &Tamper::default());
    assert_eq!(full_install(&mut m, &dir), 0);
}

#[test]
fn pair_installs_the_agent_and_the_token_and_stops() {
    let (mut m, dir) = fresh();
    let token = token_text();
    m.tty = hx_agent::install::testing::ScriptedTty::new(&[], &[token.as_bytes()]);
    assert_eq!(
        m.install(pair_args(&dir), None),
        0,
        "{}",
        String::from_utf8_lossy(&m.err)
    );
    assert_eq!(m.daemons.tokens, vec![token.as_bytes().to_vec()]);
    assert_eq!(m.daemons.count("create_desktop"), 0);
    assert_eq!(m.daemons.count("create_pairing_code"), 0);
    assert_eq!(
        m.daemons.count("finish_setup"),
        0,
        "the window stays open for the app"
    );
    assert_eq!(m.daemons.phase, hx_ipc::privd::pb::Phase::SetupOpen);
    assert_eq!(m.tty.asked, ["Pairing token (input hidden): "]);
    let st = m.state().unwrap();
    assert_eq!(st.mode, "pair");
    assert!(st.complete);
    for id in ["desktop", "verifiers", "owner-key", "pairing", "finish"] {
        assert!(
            !st.stages.contains_key(id),
            "{id} must not be recorded in pair mode"
        );
    }
    assert_eq!(st.stages["pairing-token"].state, "done");
    assert_eq!(m.result()["pairing"]["kind"], "token");
    assert!(m.result()["desktop"].is_null());
    // The window opens before the port and the token are installed.
    let order: Vec<&str> = m.daemons.log.iter().map(String::as_str).collect();
    let pos = |n: &str| order.iter().position(|x| *x == n).unwrap();
    assert!(
        pos("begin_setup") < pos("setup_host") && pos("setup_host") < pos("create_pairing_token")
    );
}

#[test]
fn pair_asks_for_a_fresh_token_on_every_run() {
    let (mut m, dir) = fresh();
    let (t1, t2) = (token_text(), token_text());
    m.tty = hx_agent::install::testing::ScriptedTty::new(&[], &[t1.as_bytes(), t2.as_bytes()]);
    assert_eq!(m.install(pair_args(&dir), None), 0);
    m.runner.calls.clear();
    // Again with --pair, and with no flag at all (the recorded mode).
    assert_eq!(m.install(pair_args(&dir), None), 0);
    assert_eq!(m.daemons.tokens.len(), 2);
    assert_eq!(m.daemons.tokens[1], t2.as_bytes());
    assert!(
        states(&m, "done").contains(&"pairing-token".to_owned()),
        "never skipped"
    );
    assert_eq!(m.runner.mutating(), Vec::<String>::new());
    let t3 = token_text();
    m.tty = hx_agent::install::testing::ScriptedTty::new(&[], &[t3.as_bytes()]);
    assert_eq!(m.install(InstallArgs::default(), None), 0);
    assert_eq!(m.daemons.tokens.len(), 3);
    assert_eq!(m.state().unwrap().mode, "pair");
}

#[test]
fn pair_refuses_something_that_is_not_a_token() {
    let (mut m, dir) = fresh();
    m.tty = hx_agent::install::testing::ScriptedTty::new(&[], &[b"not-a-token"]);
    assert_eq!(m.install(pair_args(&dir), None), 2);
    assert_eq!(
        m.runner.mutating(),
        Vec::<String>::new(),
        "refused before any change"
    );
    assert!(m.state().is_none());
}

#[test]
fn token_behaves_like_pair_with_the_token_from_argv() {
    let (mut m, dir) = fresh();
    let token = token_text();
    assert_eq!(
        m.install(token_args(&token, &dir), None),
        0,
        "{}",
        String::from_utf8_lossy(&m.err)
    );
    assert!(String::from_utf8_lossy(&m.err).contains("WEAKER"));
    assert!(m.tty.asked.is_empty(), "no prompt");
    assert_eq!(m.daemons.tokens, vec![token.as_bytes().to_vec()]);
    assert_eq!(m.daemons.count("create_desktop"), 0);
    assert_eq!(m.state().unwrap().mode, "token");
    // A re-run takes a fresh token and installs it again.
    let t2 = token_text();
    assert_eq!(m.install(token_args(&t2, &dir), None), 0);
    assert_eq!(m.daemons.tokens.len(), 2);
    // A resume without the token is refused rather than silently skipped.
    assert_eq!(m.install(InstallArgs::default(), None), 2);
}

#[test]
fn ssh_installs_its_token_last_after_the_desktop() {
    let (mut m, dir) = fresh();
    let token = token_text();
    assert_eq!(
        m.install(ssh_args(&dir, &[], &[]), Some(frames(Some(&token), None))),
        0
    );
    assert_eq!(m.daemons.tokens, vec![token.as_bytes().to_vec()]);
    let order: Vec<&str> = m.daemons.log.iter().map(String::as_str).collect();
    let pos = |n: &str| order.iter().position(|x| *x == n).unwrap();
    assert!(pos("create_desktop") < pos("set_password_verifier"));
    assert!(pos("set_password_verifier") < pos("create_pairing_token"));
    assert!(pos("create_pairing_token") < pos("finish_setup"));
    assert_eq!(m.result()["pairing"]["kind"], "token");
    // Never skipped on resume: a re-run installs the (new) token again.
    let t2 = token_text();
    assert_eq!(
        m.install(ssh_args(&dir, &[], &[]), Some(frames(Some(&t2), None))),
        0
    );
    assert_eq!(m.daemons.tokens.len(), 2);
}

#[test]
fn ssh_enrols_an_owner_key_and_needs_secrets_on_a_resume() {
    let (mut m, dir) = fresh();
    assert_eq!(
        m.install(
            ssh_args(&dir, &[], &[]),
            Some(frames(None, Some([7u8; 32])))
        ),
        0
    );
    assert_eq!(m.daemons.owner_key, Some(vec![7u8; 32]));
    assert_eq!(m.state().unwrap().stages["owner-key"].state, "done");
    // An install that failed before its desktop needs the secrets again when resumed.
    let (mut m2, dir2) = fresh();
    let mut a = ssh_args(&dir2, &[], &[]);
    a.test_fail_after = Some("host".into());
    assert_eq!(m2.install(a, Some(frames(None, None))), 1);
    let b = InstallArgs {
        bootstrap_dir: Some(dir2.to_string_lossy().into_owned()),
        ..InstallArgs::default()
    };
    assert_eq!(m2.install(b, None), 2, "no --ssh and nothing on stdin");
    assert!(m2.result()["message"].as_str().unwrap().contains("--ssh"));
}

#[test]
fn interactive_asks_everything_first_and_ends_with_a_code() {
    let (mut m, dir) = fresh();
    m.json = false;
    std::fs::create_dir_all(path(&m, "/etc/default")).unwrap();
    std::fs::write(path(&m, paths::DEFAULT_LOCALE), "LANG=de_DE.UTF-8\n").unwrap();
    // distro, user (a bad one first), apps, docker, cpu, memory, disk, device, port, private
    // networks, hostname, time zone, locale, keyboard.
    m.tty = hx_agent::install::testing::ScriptedTty::new(
        &[
            "",
            "Bad Name",
            "carol",
            "developer",
            "no",
            "2",
            "",
            "",
            "",
            "",
            "no",
            "box",
            "Europe/Berlin",
            "",
            "",
        ],
        &[b"inter-pw", b"inter-pw", b"135790", b"135790"],
    );
    let mut a = InstallArgs {
        mode: Some(Mode::Interactive),
        ..InstallArgs::default()
    };
    a.bootstrap_dir = Some(dir.to_string_lossy().into_owned());
    assert_eq!(m.install(a, None), 0, "{}", String::from_utf8_lossy(&m.err));
    let asked = m.tty.asked.clone();
    assert!(
        asked
            .iter()
            .filter(|q| q.starts_with("Linux user name"))
            .count()
            == 2,
        "the bad name is asked again"
    );
    assert!(
        asked.iter().any(|q| q.contains("Locale [de_DE.UTF-8]")),
        "host default offered: {asked:?}"
    );
    assert_eq!(
        m.daemons.desktop_password.as_deref(),
        Some(&b"inter-pw"[..])
    );
    let r = &m.daemons.create_requests[0];
    assert_eq!(r.username, "carol");
    assert_eq!(r.preset, hx_ipc::privd::pb::Preset::Developer as i32);
    assert_eq!(r.limits.unwrap().cpu, 2);
    let s = r.settings.as_ref().unwrap();
    assert_eq!(
        (s.hostname.as_str(), s.timezone.as_str(), s.locale.as_str()),
        ("box", "Europe/Berlin", "de_DE.UTF-8")
    );
    // No change happened before the last question was answered.
    let out = String::from_utf8_lossy(&m.out).into_owned();
    assert!(out.contains("pairing code: ABCD-EFGH"), "{out}");
    assert!(out.contains("203.0.113.9 port 443"));
    assert_eq!(
        m.result(),
        serde_json::Value::Null,
        "text mode prints no JSON"
    );
    let st = m.state().unwrap();
    assert_eq!(st.mode, "interactive");
    assert_eq!(st.options.user.as_deref(), Some("carol"));
    assert!(st.complete);
    assert_eq!(m.daemons.codes, 1);
    // A re-run without the flag does not ask again (nothing left to build) and does not print a code
    // unless it is asked for: the code stage never skips, so a new one is made.
    m.tty = hx_agent::install::testing::ScriptedTty::default();
    assert_eq!(m.install(InstallArgs::default(), None), 0);
    assert!(m.tty.asked.is_empty());
    assert_eq!(m.daemons.codes, 2);
}

#[test]
fn interactive_asks_for_docker_with_a_typed_yes_and_refuses_mismatched_secrets() {
    let (mut m, dir) = fresh();
    let lines: Vec<&str> = vec![
        "", "carol", "", "yes", "", "", "", "", "", "no", "", "", "", "",
    ];
    // Docker needs Incus 6.0.5.
    m.runner.apt_candidate = Some("1:6.0.5-1".into());
    m.runner
        .apt_versions
        .insert("incus".into(), "1:6.0.5-1".into());
    m.daemons.incus_version = Some("6.0.5".into());
    m.tty =
        hx_agent::install::testing::ScriptedTty::new(&lines, &[b"pw", b"pw", b"135790", b"135790"]);
    let mut a = InstallArgs {
        mode: Some(Mode::Interactive),
        ..InstallArgs::default()
    };
    a.bootstrap_dir = Some(dir.to_string_lossy().into_owned());
    assert_eq!(m.install(a, None), 0, "{}", String::from_utf8_lossy(&m.err));
    assert!(m.daemons.create_requests[0].docker);
    assert!(
        String::from_utf8_lossy(&m.err).contains("AppArmor"),
        "the warning was shown"
    );
    // Mismatched passwords: nothing changed.
    let (mut m2, dir2) = fresh();
    m2.tty = hx_agent::install::testing::ScriptedTty::new(&lines, &[b"pw", b"other"]);
    let mut a = InstallArgs {
        mode: Some(Mode::Interactive),
        ..InstallArgs::default()
    };
    a.bootstrap_dir = Some(dir2.to_string_lossy().into_owned());
    assert_eq!(m2.install(a, None), 2);
    assert_eq!(m2.runner.mutating(), Vec::<String>::new());
    assert!(m2.state().is_none());
}

#[test]
fn interactive_without_a_terminal_is_declined() {
    let (mut m, dir) = fresh();
    let mut a = InstallArgs {
        mode: Some(Mode::Interactive),
        ..InstallArgs::default()
    };
    a.bootstrap_dir = Some(dir.to_string_lossy().into_owned());
    assert_eq!(m.install(a, None), 8);
    assert_eq!(m.runner.mutating(), Vec::<String>::new());
}

// ----- secrets never leak ---------------------------------------------------------------------

fn assert_no_secret_anywhere(m: &Machine, secrets: &[&str]) {
    // Recorded tool calls: argv and environment.
    for c in &m.runner.calls {
        let hay = format!("{:?} {:?}", c.args, c.env);
        for s in secrets {
            assert!(
                !hay.contains(s),
                "a secret is in the argv or environment of {}",
                c.line()
            );
        }
    }
    // Every file the install wrote (the log, the state, the units, the configuration).
    let mut stack = vec![m.dir.path().to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            let ft = e.file_type().unwrap();
            if ft.is_dir() {
                stack.push(p);
            } else if ft.is_file() {
                let bytes = std::fs::read(&p).unwrap();
                let text = String::from_utf8_lossy(&bytes);
                for s in secrets {
                    assert!(!text.contains(s), "a secret is in {}", p.display());
                }
            }
        }
    }
    // The output channels.
    let (out, err) = (
        String::from_utf8_lossy(&m.out),
        String::from_utf8_lossy(&m.err),
    );
    for s in secrets {
        assert!(!out.contains(s) && !err.contains(s), "a secret was printed");
    }
    // The verifiers hold a MAC, never the secret.
    for v in [&m.daemons.pin_verifier, &m.daemons.password_verifier]
        .into_iter()
        .flatten()
    {
        let t = String::from_utf8_lossy(v);
        for s in secrets {
            assert!(!t.contains(s));
        }
    }
}

#[test]
fn canaries_ssh_install_leaves_no_secret_in_argv_environment_log_state_or_output() {
    let (mut m, dir) = fresh();
    let token = token_text();
    assert_eq!(
        m.install(ssh_args(&dir, &[], &[]), Some(frames(Some(&token), None))),
        0
    );
    // Positive controls: the secrets did reach their destinations.
    assert_eq!(
        m.daemons.desktop_password.as_deref(),
        Some(PASSWORD.as_bytes())
    );
    assert_eq!(m.daemons.tokens[0], token.as_bytes());
    assert!(
        m.daemons
            .pin_verifier
            .as_ref()
            .unwrap()
            .starts_with(b"hx-pv1$")
    );
    assert_no_secret_anywhere(&m, &[PASSWORD, PIN, &token]);
    // Also after a failure and a resume.
    let (mut m2, dir2) = fresh();
    m2.runner.fail_on(Tool::SystemdSysusers, "", 1, Some(1));
    assert_eq!(
        m2.install(ssh_args(&dir2, &[], &[]), Some(frames(Some(&token), None))),
        1
    );
    assert_no_secret_anywhere(&m2, &[PASSWORD, PIN, &token]);
    assert_eq!(
        m2.install(ssh_args(&dir2, &[], &[]), Some(frames(Some(&token), None))),
        0
    );
    assert_no_secret_anywhere(&m2, &[PASSWORD, PIN, &token]);
}

#[test]
fn canaries_token_and_pair_leave_no_token_behind() {
    let (mut m, dir) = fresh();
    let token = token_text();
    assert_eq!(m.install(token_args(&token, &dir), None), 0);
    assert_no_secret_anywhere(&m, &[&token]);
    let (mut m2, dir2) = fresh();
    let t2 = token_text();
    m2.tty = hx_agent::install::testing::ScriptedTty::new(&[], &[t2.as_bytes()]);
    assert_eq!(m2.install(pair_args(&dir2), None), 0);
    assert_no_secret_anywhere(&m2, &[&t2]);
}

#[test]
fn canaries_interactive_install_leaves_no_secret_behind() {
    let (mut m, dir) = fresh();
    let lines: Vec<&str> = vec![
        "", "carol", "", "no", "", "", "", "", "", "no", "", "", "", "",
    ];
    m.tty = hx_agent::install::testing::ScriptedTty::new(
        &lines,
        &[
            b"Tty-canary-pw-77x",
            b"Tty-canary-pw-77x",
            b"246801",
            b"246801",
        ],
    );
    let mut a = InstallArgs {
        mode: Some(Mode::Interactive),
        ..InstallArgs::default()
    };
    a.bootstrap_dir = Some(dir.to_string_lossy().into_owned());
    assert_eq!(m.install(a, None), 0);
    assert_no_secret_anywhere(&m, &["Tty-canary-pw-77x", "246801"]);
    assert!(
        !m.tty.asked.iter().any(|q| q.contains("Tty-canary")),
        "answers are never echoed into prompts"
    );
}

#[test]
fn every_tool_call_has_an_empty_extra_environment_except_apt() {
    let (m, _d) = installed();
    for c in &m.runner.calls {
        if c.tool == Tool::AptGet || c.tool == Tool::AptCache {
            let keys: Vec<&str> = c.env.iter().map(|(k, _)| k.as_str()).collect();
            assert!(
                keys.iter().all(|k| matches!(
                    *k,
                    "DEBIAN_FRONTEND" | "NEEDRESTART_MODE" | "APT_LISTCHANGES_FRONTEND"
                )),
                "{keys:?}"
            );
        } else {
            assert!(c.env.is_empty(), "{}", c.line());
        }
        assert!(c.args.iter().all(|a| !a.contains('\0')));
    }
    let apt = m
        .runner
        .calls
        .iter()
        .find(|c| c.tool == Tool::AptGet && c.args.iter().any(|a| a == "install"))
        .unwrap();
    assert!(apt.args.contains(&"DPkg::Lock::Timeout=600".to_owned()));
    assert!(
        apt.env
            .iter()
            .any(|(k, v)| k == "DEBIAN_FRONTEND" && v == "noninteractive")
    );
    assert!(
        apt.env
            .iter()
            .any(|(k, v)| k == "NEEDRESTART_MODE" && v == "a")
    );
}

// ----- JSON Lines -----------------------------------------------------------------------------

#[test]
fn the_json_stream_is_only_json_lines_with_the_documented_shapes() {
    let (mut m, dir) = fresh();
    let token = token_text();
    m.tty = hx_agent::install::testing::ScriptedTty::new(&[], &[token.as_bytes()]);
    assert_eq!(m.install(pair_args(&dir), None), 0);
    let text = String::from_utf8(m.out.clone()).unwrap();
    for l in text.lines() {
        let v: serde_json::Value =
            serde_json::from_str(l).unwrap_or_else(|_| panic!("not JSON: {l}"));
        assert_eq!(v["v"], 1);
    }
    let lines = m.json_lines();
    // Key order of a stage line.
    let first = text.lines().next().unwrap();
    assert!(
        first.starts_with(
            r#"{"v":1,"t":"stage","id":"preflight","n":1,"of":19,"state":"start","ms":0}"#
        ),
        "{first}"
    );
    // Golden: the stage ids and states of a pair run.
    let got: Vec<String> = lines
        .iter()
        .filter(|v| v["t"] == "stage" && v["state"] != "start")
        .map(|v| {
            format!(
                "{}:{}:{}",
                v["n"],
                v["id"].as_str().unwrap(),
                v["state"].as_str().unwrap()
            )
        })
        .collect();
    let want = [
        "1:preflight:done",
        "2:packages:done",
        "3:incus:done",
        "4:release:done",
        "5:system-files:done",
        "6:credentials:done",
        "7:config:done",
        "8:units:done",
        "9:setup-window:done",
        "10:host:done",
        "11:firewall-port:done",
        "12:pairing-token:done",
        "13:desktop:skip",
        "14:verifiers:skip",
        "15:owner-key:skip",
        "16:backup:deferred",
        "17:pairing:skip",
        "18:finish:skip",
        "19:done:done",
    ];
    assert_eq!(got, want);
    // Every stage line has n, of and ms.
    for v in lines.iter().filter(|v| v["t"] == "stage") {
        assert!(v["n"].is_u64() && v["of"] == 19 && v["ms"].is_u64());
    }
    let r = m.result();
    assert_eq!(r["t"], "result");
    for k in [
        "install_id",
        "agent_version",
        "server_public_key",
        "addresses",
        "port",
        "desktop",
        "pairing",
        "port_rule",
    ] {
        assert!(r.get(k).is_some(), "{k}");
    }
    // Human text went to stderr.
    assert!(String::from_utf8_lossy(&m.err).contains("[1/19] preflight: done"));
}

#[test]
fn privd_progress_is_relayed_one_to_one() {
    let (mut m, dir) = fresh();
    assert_eq!(full_install(&mut m, &dir), 0);
    let steps: Vec<_> = m
        .json_lines()
        .into_iter()
        .filter(|v| v["t"] == "step")
        .collect();
    let build = steps.iter().find(|v| v["id"] == "desktop").unwrap();
    assert_eq!(build["privd_stage"], "BUILD");
    assert_eq!(
        (
            build["index"].as_u64(),
            build["total"].as_u64(),
            build["percent"].as_u64()
        ),
        (Some(3), Some(12), Some(40))
    );
    assert_eq!(build["step"], "install packages");
    let host = steps.iter().find(|v| v["id"] == "host").unwrap();
    assert_eq!(host["percent"], 255, "unknown percent is 255");
}

#[test]
fn desktop_warnings_are_reported_as_warn_lines() {
    let (mut m, dir) = fresh();
    assert_eq!(full_install(&mut m, &dir), 0);
    let w: Vec<_> = m
        .json_lines()
        .into_iter()
        .filter(|v| v["t"] == "warn" && v["id"] == "desktop")
        .collect();
    assert_eq!(w.len(), 1);
    assert!(w[0]["message"].as_str().unwrap().contains("hx-session"));
    assert_eq!(
        m.result()["desktop"]["warnings"][0],
        "hx-session package missing"
    );
}

#[test]
fn only_this_branchs_unit_files_exist_and_all_are_embedded() {
    // The directory listing and the table agree (the unit test in units.rs says it too).
    let n = hx_agent::install::units::FILES.len();
    assert!(n >= 12);
}

#[test]
fn loopback_link_local_and_multicast_resolvers_are_never_allowed_and_the_install_warns() {
    // M2: IPAddressAllow has no port limit; 127.0.0.1 and 169.254.169.254 must never get one.
    let (mut m, dir) = fresh();
    std::fs::write(
        path(&m, "/etc/resolv.conf"),
        "nameserver 127.0.0.53\nnameserver 127.0.0.1\nnameserver 169.254.169.254\nnameserver fe80::1%eth0\nnameserver ::1\nnameserver ff02::1\nnameserver 10.0.0.2\nnameserver fd00::53\nnameserver 8.8.8.8\n",
    )
    .unwrap();
    assert_eq!(
        full_install(&mut m, &dir),
        0,
        "{}",
        String::from_utf8_lossy(&m.err)
    );
    let d = m.read(paths::RESOLVERS_DROPIN).unwrap();
    let allows: Vec<&str> = d
        .lines()
        .filter(|l| l.starts_with("IPAddressAllow="))
        .collect();
    assert_eq!(
        allows,
        ["IPAddressAllow=10.0.0.2/32", "IPAddressAllow=fd00::53/128"],
        "{d}"
    );
    for bad in ["127.", "::1", "169.254", "fe80", "ff02"] {
        assert!(!d.contains(bad), "{bad}");
    }
    let warns: Vec<String> = m
        .json_lines()
        .iter()
        .filter(|v| v["t"] == "warn" && v["id"] == "config")
        .map(|v| v["message"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].contains("169.254.169.254")
            && warns[0].contains("CheckUpdate needs systemd-resolved or a private resolver")
    );
    assert!(
        m.state()
            .unwrap()
            .notes
            .iter()
            .any(|n| n.contains("CheckUpdate needs"))
    );
    // Only skipped nameservers: no drop-in at all, still a warning, and the install does not fail.
    let (mut m2, dir2) = fresh();
    std::fs::write(path(&m2, "/etc/resolv.conf"), "nameserver 127.0.0.1\n").unwrap();
    assert_eq!(full_install(&mut m2, &dir2), 0);
    assert!(!exists(&m2, paths::RESOLVERS_DROPIN));
    assert!(
        m2.json_lines()
            .iter()
            .any(|v| v["t"] == "warn" && v["id"] == "config")
    );
}

#[test]
fn a_bootstrap_directory_outside_run_or_with_dotdot_is_refused_and_nothing_is_deleted() {
    // L2: the installer deletes its bootstrap directory, so it must not be talked into deleting
    // another one.
    let (mut m, dir) = fresh();
    let victim = path(&m, "/victim");
    std::fs::create_dir_all(&victim).unwrap();
    std::fs::write(victim.join("precious"), b"x").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o700)).unwrap();
    let elsewhere = m.dir.path().join("etc-hx-bootstrap.x");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o700)).unwrap();
    for bad in [
        path(&m, "/var/lib/../victim"),
        path(&m, "/var/lib/hx-bootstrap.x/../../victim"),
        path(&m, "/var/lib/victim"),
        path(&m, "/var/lib/hx-bootstrap."),
        path(&m, "/var/lib/sub/hx-bootstrap.x"),
        elsewhere.clone(),
        path(&m, "/victim"),
    ] {
        let mut a = ssh_args(&dir, &[], &[]);
        a.bootstrap_dir = Some(bad.to_string_lossy().into_owned());
        assert_eq!(
            m.install(a, Some(frames(None, None))),
            10,
            "{}",
            bad.display()
        );
        assert!(
            m.result()["message"]
                .as_str()
                .unwrap()
                .contains("bootstrap directory")
        );
        assert!(
            victim.join("precious").exists(),
            "{} deleted the victim",
            bad.display()
        );
        assert!(elsewhere.exists());
        assert!(m.runner.mutating().is_empty());
    }
    assert!(
        dir.exists(),
        "the real bootstrap directory was not part of those runs"
    );
}

#[test]
fn the_bootstrap_directory_is_removed_when_the_lock_is_held_or_a_stage_fails() {
    let (mut m, dir) = fresh();
    let held = hx_agent::install::lock::acquire(&path(&m, paths::LOCK_FILE), None).unwrap();
    assert_eq!(full_install(&mut m, &dir), 11);
    assert!(!dir.exists());
    drop(held);
    let (mut m2, dir2) = fresh();
    m2.runner.fail_on(Tool::AptGet, "install", 100, None);
    assert_eq!(full_install(&mut m2, &dir2), 1);
    assert!(
        !dir2.exists(),
        "removed although the install failed after the release"
    );
}

#[test]
fn a_password_longer_than_libxcrypt_reads_is_refused_before_any_change() {
    // N5: 511 bytes is the most that can ever be checked later.
    let (mut m, dir) = fresh();
    let lines: Vec<&str> = vec![
        "", "carol", "", "no", "", "", "", "", "", "no", "", "", "", "",
    ];
    let long = vec![b'p'; 512];
    m.tty = hx_agent::install::testing::ScriptedTty::new(&lines, &[&long, &long]);
    let mut a = InstallArgs {
        mode: Some(Mode::Interactive),
        ..InstallArgs::default()
    };
    a.bootstrap_dir = Some(dir.to_string_lossy().into_owned());
    assert_eq!(m.install(a, None), 2);
    assert!(m.result()["message"].as_str().unwrap().contains("511"));
    assert!(m.runner.mutating().is_empty() && m.state().is_none());
    // Exactly 511 is fine.
    let (mut m2, dir2) = fresh();
    let ok = vec![b'p'; 511];
    m2.tty =
        hx_agent::install::testing::ScriptedTty::new(&lines, &[&ok, &ok, b"135790", b"135790"]);
    let mut a = InstallArgs {
        mode: Some(Mode::Interactive),
        ..InstallArgs::default()
    };
    a.bootstrap_dir = Some(dir2.to_string_lossy().into_owned());
    assert_eq!(
        m2.install(a, None),
        0,
        "{}",
        String::from_utf8_lossy(&m2.err)
    );
    assert_eq!(
        m2.daemons.desktop_password.as_deref().map(<[u8]>::len),
        Some(511)
    );
}

// ----- the bridge rules: ufw or a dropping nftables firewall must not stop the desktop ------------

const BRIDGE_UFW: [&str; 4] = [
    "allow in on hxbr0 to any port 67 proto udp",
    "allow in on hxbr0 to any port 53 proto udp",
    "allow in on hxbr0 to any port 53 proto tcp",
    "route allow in on hxbr0",
];

fn nft_comments(m: &Machine, chain: &str) -> Vec<String> {
    m.runner
        .nft_items
        .iter()
        .filter_map(|i| i.get("rule"))
        .filter(|r| r["chain"] == chain)
        .filter_map(|r| r["comment"].as_str().map(str::to_owned))
        .collect()
}

fn forward_drop() -> serde_json::Value {
    serde_json::json!({"chain": {"family": "inet", "table": "filter", "name": "forward", "handle": 2,
        "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}})
}

#[test]
fn ufw_also_lets_dhcp_dns_and_forwarding_through_on_the_bridge() {
    // The ubuntu-24.04 / build / ufw cell: input and forward drop by default, so the desktop
    // build found no DNS.
    let (mut m, dir) = fresh();
    m.runner.ufw = Some(true);
    assert_eq!(
        full_install(&mut m, &dir),
        0,
        "{}",
        String::from_utf8_lossy(&m.err)
    );
    assert_eq!(bridge_rules(&m), BRIDGE_UFW);
    // Exactly these calls, each with the comment, and nothing else on the bridge.
    let lines = m.runner.lines();
    for r in BRIDGE_UFW {
        assert!(
            lines.contains(&format!("ufw {r} comment hash-xcreen")),
            "{r}: {lines:#?}"
        );
    }
    let rec = m.state().unwrap().created.port_rule.unwrap();
    assert!(rec.bridge && rec.adopted.is_empty());
    // Before the desktop is built (stage 11 of 13).
    let order: Vec<&str> = m.daemons.log.iter().map(String::as_str).collect();
    assert!(order.contains(&"create_desktop"));
    // No out-on-bridge route rule: ufw's own before.rules accept related and established replies.
    assert!(
        !lines.iter().any(|l| l.contains("route allow out")),
        "{lines:#?}"
    );
}

#[test]
fn an_out_route_rule_that_an_earlier_version_added_is_removed_but_an_adopted_one_stays() {
    // Ours (recorded, comment hash-xcreen): removed on the next run.
    let (mut m, dir) = fresh();
    m.runner.ufw = Some(true);
    assert_eq!(full_install(&mut m, &dir), 0);
    m.runner.ufw_rules.push("route allow out on hxbr0".into());
    m.runner.calls.clear();
    assert_eq!(rerun(&mut m, &[], &[]), 0);
    assert!(
        states(&m, "done").contains(&"firewall-port".to_owned()),
        "not skipped"
    );
    assert!(
        !m.runner
            .ufw_rules
            .contains(&"route allow out on hxbr0".to_owned())
    );
    assert_eq!(bridge_rules(&m), BRIDGE_UFW);
    // The administrator's own identical rule, adopted: never touched.
    let (mut m, dir) = fresh();
    m.runner.ufw = Some(true);
    assert_eq!(full_install(&mut m, &dir), 0);
    let theirs = "route allow out on hxbr0".to_owned();
    m.runner.ufw_rules.push(theirs.clone());
    m.runner.ufw_foreign.insert(theirs.clone());
    let mut st = m.state().unwrap();
    st.created
        .port_rule
        .as_mut()
        .unwrap()
        .adopted
        .push("bridge:route-out".into());
    hx_agent::install::state::save(&m.paths.at(paths::STATE_FILE), &st).unwrap();
    assert_eq!(rerun(&mut m, &[], &[]), 0);
    assert!(m.runner.ufw_rules.contains(&theirs));
}

#[test]
fn ufw_bridge_rules_converge_on_a_resume_and_a_second_run_changes_nothing() {
    let (mut m, dir) = fresh();
    m.runner.ufw = Some(true);
    assert_eq!(full_install(&mut m, &dir), 0);
    m.runner.calls.clear();
    assert_eq!(rerun(&mut m, &[], &[]), 0);
    assert!(
        !m.runner.mutating().iter().any(|l| l.starts_with("ufw")),
        "{:?}",
        m.runner.mutating()
    );
    assert!(states(&m, "skip").contains(&"firewall-port".to_owned()));
    // A rule was deleted by hand: the stage is not skipped and puts it back.
    m.runner
        .ufw_rules
        .retain(|r| r != "route allow in on hxbr0");
    assert_eq!(rerun(&mut m, &[], &[]), 0);
    assert!(states(&m, "done").contains(&"firewall-port".to_owned()));
    assert_eq!(bridge_rules(&m), BRIDGE_UFW);
    // An install that was recorded before the bridge rules existed gets them on the next run.
    let mut st = m.state().unwrap();
    st.created.port_rule.as_mut().unwrap().bridge = false;
    hx_agent::install::state::save(&m.paths.at(paths::STATE_FILE), &st).unwrap();
    m.runner.ufw_rules.retain(|r| !r.contains("hxbr0"));
    assert_eq!(rerun(&mut m, &[], &[]), 0);
    assert_eq!(bridge_rules(&m), BRIDGE_UFW);
    assert!(m.state().unwrap().created.port_rule.unwrap().bridge);
}

#[test]
fn a_partial_ufw_failure_is_recorded_and_the_next_run_finishes() {
    let (mut m, dir) = fresh();
    m.runner.ufw = Some(true);
    m.runner.fail_on(Tool::Ufw, "route allow in", 1, Some(1));
    assert_eq!(full_install(&mut m, &dir), 1);
    assert_eq!(m.result()["stage"], "firewall-port");
    assert!(
        m.state().unwrap().created.port_rule.unwrap().bridge,
        "recorded before the rules"
    );
    assert_eq!(bridge_rules(&m).len(), 3);
    let dir = release(&mut m, &Tamper::default());
    assert_eq!(full_install(&mut m, &dir), 0);
    assert_eq!(bridge_rules(&m), BRIDGE_UFW);
}

#[test]
fn nft_input_chains_get_dhcp_and_dns_and_forward_chains_get_forwarding() {
    let (mut m, dir) = fresh();
    m.runner.nft_items.push(nft_input_drop());
    m.runner.nft_items.push(forward_drop());
    assert_eq!(
        full_install(&mut m, &dir),
        0,
        "{}",
        String::from_utf8_lossy(&m.err)
    );
    let mut input = nft_comments(&m, "input");
    input.sort();
    assert_eq!(
        input,
        [
            "hx-agent-bridge:in-tcp",
            "hx-agent-bridge:in-udp",
            "hx-agent-port"
        ]
    );
    let mut fwd = nft_comments(&m, "forward");
    fwd.sort();
    assert_eq!(
        fwd,
        ["hx-agent-bridge:fwd-in", "hx-agent-bridge:fwd-out"],
        "no port rule in forward"
    );
    // The rules as nft receives them.
    let lines = m.runner.lines();
    assert!(lines.contains(&"nft insert rule inet filter input iifname \"hxbr0\" udp dport { 53, 67 } accept comment \"hx-agent-bridge:in-udp\"".to_owned()), "{lines:#?}");
    assert!(lines.contains(&"nft insert rule inet filter input iifname \"hxbr0\" tcp dport 53 accept comment \"hx-agent-bridge:in-tcp\"".to_owned()));
    assert!(lines.contains(&"nft insert rule inet filter forward iifname \"hxbr0\" accept comment \"hx-agent-bridge:fwd-in\"".to_owned()));
    assert!(lines.contains(&"nft insert rule inet filter forward oifname \"hxbr0\" ct state established,related accept comment \"hx-agent-bridge:fwd-out\"".to_owned()));
    assert!(m.runner.enabled.contains("hx-agent-port.service"));
}

#[test]
fn nft_bridge_rules_are_brought_back_after_a_reload_and_left_alone_otherwise() {
    let (mut m, dir) = fresh();
    m.runner.nft_items.push(nft_input_drop());
    m.runner.nft_items.push(forward_drop());
    assert_eq!(full_install(&mut m, &dir), 0);
    m.runner.calls.clear();
    assert_eq!(rerun(&mut m, &[], &[]), 0);
    assert!(
        !m.runner.mutating().iter().any(|l| l.starts_with("nft")),
        "{:?}",
        m.runner.mutating()
    );
    // One bridge rule is gone (a partial reload): not skipped, restored.
    m.runner.nft_items.retain(|i| {
        i.get("rule")
            .is_none_or(|r| r["comment"] != "hx-agent-bridge:fwd-out")
    });
    assert_eq!(rerun(&mut m, &[], &[]), 0);
    assert!(states(&m, "done").contains(&"firewall-port".to_owned()));
    assert_eq!(nft_comments(&m, "forward").len(), 2);
    // `hx-agent port-rule apply` does the same, with no state or stage.
    m.runner.nft_items.retain(|i| i.get("rule").is_none());
    assert!(hx_agent::install::stages::port::apply_nft(&mut m.runner, 443).unwrap());
    assert_eq!(nft_comments(&m, "input").len(), 3);
    assert_eq!(nft_comments(&m, "forward").len(), 2);
}

#[test]
fn nft_with_only_a_dropping_forward_chain_gets_only_the_forward_rules() {
    let (mut m, dir) = fresh();
    m.runner.nft_items.push(serde_json::json!({"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 1,
        "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}}));
    m.runner.nft_items.push(forward_drop());
    assert_eq!(full_install(&mut m, &dir), 0);
    assert_eq!(m.result()["port_rule"], "nft");
    assert!(
        nft_comments(&m, "input").is_empty(),
        "an accepting input chain needs nothing"
    );
    assert_eq!(nft_comments(&m, "forward").len(), 2);
}

#[test]
fn an_nft_firewall_that_accepts_everything_needs_no_bridge_rules() {
    let (mut m, dir) = fresh();
    assert_eq!(full_install(&mut m, &dir), 0);
    assert_eq!(m.result()["port_rule"], "none");
    assert!(m.runner.nft_items.is_empty());
    assert!(m.runner.ufw_rules.is_empty());
}
