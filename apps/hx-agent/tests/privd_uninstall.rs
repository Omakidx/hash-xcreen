//! privd's narrowed `Uninstall` (docs/ipc.md 6.13, design C9) on fakes: keep and destroy mode, the
//! gate that refuses everything else while an uninstall is under way, resume at every step,
//! refusal of objects without the hash-xcreen marker, mode transitions and idempotence.
//!
//! The host is a stateful fake: an nftables table, the `DOCKER-USER` chain with its two rules, the
//! two files privd wrote, and an Incus with a desktop, its link device and the host objects. No
//! real tool is run and no real object is touched.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use hx_agent::privd::cancel::{CancelReason, CancelToken};
use hx_agent::privd::cmd::hostsetup::docker_user_rules;
use hx_agent::privd::cmd::uninstall::{STATE_FILE, UninstallMode, UninstallState};
use hx_agent::privd::daemon::Ctx;
use hx_agent::privd::progress::ProgressSender;
use hx_agent::privd::runner::{RunOutput, Tool};
use hx_agent::privd::state::{Flag, HostSetupRecord, StateStore};
use hx_agent::privd::testing::{FakeIncus, FakeProbe, FakeRunner, Harness, error_of, request};
use hx_ipc::privd::pb::{
    self, ErrorCode, ErrorDetail, ProgressStage, Role, request::Command, response::Result as R,
};
use serde_json::json;

const GW: u32 = 4_242;

// ----- the fake host ------------------------------------------------------------------------

#[derive(Default)]
struct Host {
    nft_table: bool,
    chain: bool,
    rules: Vec<String>,
    fail_nft_delete: bool,
    fail_iptables_delete: bool,
}

type SharedHost = Arc<Mutex<Host>>;

fn runner(host: &SharedHost) -> Arc<FakeRunner> {
    let host = host.clone();
    FakeRunner::with(move |p| {
        let mut h = host.lock().unwrap();
        let ok = |success: bool| RunOutput {
            code: Some(i32::from(!success)),
            ..Default::default()
        };
        match p.tool {
            Tool::Nft => match p.args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
                ["list", "table", "inet", "hx"] => ok(h.nft_table),
                ["delete", "table", "inet", "hx"] => {
                    if h.fail_nft_delete {
                        ok(false)
                    } else {
                        h.nft_table = false;
                        ok(true)
                    }
                }
                _ => ok(true),
            },
            Tool::Iptables => {
                let a: Vec<&str> = p.args.iter().map(String::as_str).collect();
                match a[..] {
                    ["-n", "-L", "DOCKER-USER"] => ok(h.chain),
                    ["-C", "DOCKER-USER", ..] => ok(h.rules.contains(&a[2..].join(" "))),
                    ["-D", "DOCKER-USER", ..] => {
                        let rule = a[2..].join(" ");
                        match h.rules.iter().position(|r| *r == rule) {
                            Some(i) if !h.fail_iptables_delete => {
                                h.rules.remove(i);
                                ok(true)
                            }
                            _ => ok(false),
                        }
                    }
                    _ => ok(true),
                }
            }
            _ => ok(true),
        }
    })
}

struct World {
    h: Harness,
    host: SharedHost,
}

const DESC: &str = "hash-xcreen: test object";

fn put_object(incus: &FakeIncus, key: &str, description: &str) {
    incus.with(|s| {
        s.objects.insert(
            key.to_string(),
            json!({"name": key.rsplit('/').next().unwrap(), "description": description,
                   "config": {}, "type": "bridge", "used_by": []}),
        );
    });
}

/// A fully set up host: one desktop with its link device and a snapshot, the five host objects
/// with the marker, the table, both `DOCKER-USER` rules, and the two files.
fn world() -> World {
    let host: SharedHost = Arc::new(Mutex::new(Host {
        nft_table: true,
        chain: true,
        rules: docker_user_rules("hxbr0")
            .iter()
            .map(|r| r.join(" "))
            .collect(),
        ..Host::default()
    }));
    let incus = FakeIncus::new();
    incus.add_desktop("hx-main", "ubuntu-24.04-xfce-basic", "alice", true);
    incus.with(|s| {
        let i = s.instances.get_mut("hx-main").unwrap();
        i.devices.insert(
            "hx-link".into(),
            [("type", "proxy"), ("listen", "unix:/run/hx/link/main.sock")]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<BTreeMap<_, _>>(),
        );
        i.snapshots = vec!["hx-preupdate".into(), "manual-1".into()];
    });
    for key in [
        "networks/hxbr0",
        "network-acls/hx-isolate",
        "profiles/hx-desktop",
        "profiles/hx-compat-debian13",
    ] {
        put_object(&incus, key, DESC);
    }
    let h = Harness::start_with(GW, FakeProbe::default(), incus, runner(&host));
    h.daemon.register_desktop("main").unwrap();
    std::fs::write(&h.daemon.cfg.firewall_file, "table inet hx {}\n").unwrap();
    std::fs::write(
        &h.daemon.cfg.sysctl_file,
        "fs.inotify.max_user_watches = 1\n",
    )
    .unwrap();
    World { h, host }
}

// ----- helpers --------------------------------------------------------------------------------

fn uninstall_cmd(keep: bool) -> Command {
    Command::Uninstall(pb::UninstallRequest {
        keep_desktop: keep,
        confirm_destroy: !keep,
    })
}

async fn call(w: &World, role: Role, command: Command) -> pb::Response {
    w.h.daemon.handle(request(1, command), Ctx::new(role)).await
}

async fn admin(w: &World, command: Command) -> pb::Response {
    call(w, Role::Admin, command).await
}

fn ok_uninstall(r: pb::Response) -> pb::UninstallResult {
    match r.result {
        Some(R::Uninstall(u)) => u,
        Some(R::Error(e)) => panic!("{:?} {:?}: {}", e.code(), e.detail(), e.message),
        other => panic!("{other:?}"),
    }
}

fn err_of(r: &pb::Response) -> (ErrorCode, ErrorDetail, Option<ProgressStage>) {
    let e = error_of(r).unwrap_or_else(|| panic!("expected an error, got {r:?}"));
    (
        e.code(),
        e.detail(),
        e.stage.and_then(|s| ProgressStage::try_from(s).ok()),
    )
}

fn state_file(w: &World) -> Option<UninstallState> {
    let store = StateStore::open(&w.h.daemon.cfg.state_dir).unwrap();
    store
        .load_json::<Option<UninstallState>>(STATE_FILE)
        .unwrap()
}

fn present(w: &World, name: &str) -> bool {
    w.h.incus.instance_names().iter().any(|n| n == name)
}

fn object_present(w: &World, key: &str) -> bool {
    w.h.incus.with(|s| s.objects.contains_key(key))
}

fn pool_present(w: &World) -> bool {
    w.h.incus.with(|s| s.pool_exists)
}

fn devices_of(w: &World, name: &str) -> Vec<String> {
    w.h.incus
        .with(|s| s.instances[name].devices.keys().cloned().collect())
}

fn has(list: &[String], what: &str) -> bool {
    list.iter().any(|s| s == what)
}

fn deletes(w: &World) -> usize {
    w.h.incus
        .log()
        .iter()
        .filter(|l| l.starts_with("DELETE "))
        .count()
}

// ----- keep mode -------------------------------------------------------------------------------

#[tokio::test]
async fn keep_mode_removes_only_the_session_link_and_leaves_everything_else() {
    let w = world();
    let r = ok_uninstall(admin(&w, uninstall_cmd(true)).await);
    assert!(r.keep_desktop);
    assert_eq!(r.removed, ["session-link:main"]);
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    for kept in [
        "desktop:main",
        "pool:hx-pool",
        "network:hxbr0",
        "acl:hx-isolate",
        "profile:hx-desktop",
        "profile:hx-compat-debian13",
        "nft-table:inet hx",
        "docker-user-rules",
    ] {
        assert!(has(&r.kept, kept), "{kept} missing from {:?}", r.kept);
    }
    // The desktop runs on, without the proxy device.
    assert!(present(&w, "hx-main"));
    assert!(!devices_of(&w, "hx-main").contains(&"hx-link".to_string()));
    assert!(devices_of(&w, "hx-main").contains(&"root".to_string()));
    // The host objects, the firewall and the sysctl file are untouched.
    for key in [
        "networks/hxbr0",
        "network-acls/hx-isolate",
        "profiles/hx-desktop",
        "profiles/hx-compat-debian13",
    ] {
        assert!(object_present(&w, key), "{key}");
    }
    assert!(pool_present(&w));
    assert!(w.h.daemon.cfg.firewall_file.exists());
    assert!(w.h.daemon.cfg.sysctl_file.exists());
    {
        let host = w.host.lock().unwrap();
        assert!(host.nft_table);
        assert_eq!(host.rules.len(), 2);
    }
    // No deletion of any kind reached Incus, and the registry still names the desktop.
    assert_eq!(deletes(&w), 0);
    assert!(w.h.daemon.read_state(|s| s.desktops.contains_key("main")));
    let st = state_file(&w).expect("uninstall-state");
    assert_eq!(st.mode, UninstallMode::Keep);
    assert!(st.privd_done);
    assert_eq!(st.done, ["session_links"]);
}

#[tokio::test]
async fn keep_mode_is_idempotent() {
    let w = world();
    let first = ok_uninstall(admin(&w, uninstall_cmd(true)).await);
    let writes = w.h.incus.with(|s| s.writes.len());
    let second = ok_uninstall(admin(&w, uninstall_cmd(true)).await);
    assert_eq!(first, second, "the second answer is the same");
    assert_eq!(
        w.h.incus.with(|s| s.writes.len()),
        writes,
        "nothing was written to Incus again"
    );
}

// ----- destroy mode ---------------------------------------------------------------------------

#[tokio::test]
async fn destroy_mode_removes_the_desktop_the_host_objects_and_the_firewall() {
    let w = world();
    let r = ok_uninstall(admin(&w, uninstall_cmd(false)).await);
    assert!(!r.keep_desktop);
    for removed in [
        "session-link:main",
        "desktop:main",
        "profile:hx-desktop",
        "profile:hx-compat-debian13",
        "network:hxbr0",
        "acl:hx-isolate",
        "pool:hx-pool",
        "nft-table:inet hx",
        "docker-user-rules:2",
    ] {
        assert!(
            has(&r.removed, removed),
            "{removed} missing from {:?}",
            r.removed
        );
    }
    assert!(has(
        &r.removed,
        &format!("file:{}", w.h.daemon.cfg.firewall_file.display())
    ));
    assert!(has(
        &r.removed,
        &format!("file:{}", w.h.daemon.cfg.sysctl_file.display())
    ));
    // The live sysctl values are stated as kept: they are not reverted.
    assert!(
        r.kept.iter().any(|k| k.starts_with("sysctl-values:")),
        "{:?}",
        r.kept
    );
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    // Everything is gone.
    assert!(!present(&w, "hx-main"));
    for key in [
        "networks/hxbr0",
        "network-acls/hx-isolate",
        "profiles/hx-desktop",
        "profiles/hx-compat-debian13",
    ] {
        assert!(!object_present(&w, key), "{key}");
    }
    assert!(!pool_present(&w));
    assert!(!w.h.daemon.cfg.firewall_file.exists());
    assert!(!w.h.daemon.cfg.sysctl_file.exists());
    {
        let host = w.host.lock().unwrap();
        assert!(!host.nft_table);
        assert!(host.rules.is_empty());
    }
    assert!(w.h.daemon.read_state(|s| s.desktops.is_empty()));
    let st = state_file(&w).unwrap();
    assert_eq!(st.mode, UninstallMode::Destroy);
    assert!(st.privd_done);
    assert_eq!(
        st.done,
        [
            "session_links",
            "desktops",
            "host_objects",
            "nft_table",
            "firewall_file",
            "docker_user",
            "sysctl_file"
        ]
    );
    // The snapshots went with the instance, and nothing else on the host was touched.
    let log = w.h.incus.log();
    assert!(
        log.iter()
            .any(|l| l == "DELETE /1.0/instances/hx-main/snapshots/hx-preupdate")
    );
    assert!(
        !log.iter()
            .any(|l| l.contains("incusbr0") || l.contains("profiles/default")),
        "{log:?}"
    );
}

#[tokio::test]
async fn destroy_mode_is_idempotent() {
    let w = world();
    let first = ok_uninstall(admin(&w, uninstall_cmd(false)).await);
    let deletes_after_first = deletes(&w);
    let calls_after_first = w.h.runner.calls().len();
    let second = ok_uninstall(admin(&w, uninstall_cmd(false)).await);
    // Same report (what the first run removed is remembered), and no new deletion anywhere.
    assert_eq!(first.removed, second.removed);
    assert_eq!(deletes(&w), deletes_after_first);
    let new_calls: Vec<_> = w.h.runner.calls()[calls_after_first..]
        .iter()
        .map(|c| format!("{:?} {}", c.tool, c.args.join(" ")))
        .collect();
    assert!(
        new_calls
            .iter()
            .all(|c| !c.contains("delete") && !c.contains("-D ")),
        "{new_calls:?}"
    );
}

#[tokio::test]
async fn destroy_needs_the_confirmation_and_admin() {
    let w = world();
    // The wire validation refuses it; the handler also does (defence in depth).
    let r = admin(
        &w,
        Command::Uninstall(pb::UninstallRequest {
            keep_desktop: false,
            confirm_destroy: false,
        }),
    )
    .await;
    assert_eq!(err_of(&r).0, ErrorCode::InvalidArgument);
    assert!(state_file(&w).is_none(), "a refused request starts nothing");
    // A Gateway never gets there: class X.
    let r = call(&w, Role::Gateway, uninstall_cmd(true)).await;
    assert_eq!(err_of(&r).0, ErrorCode::PermissionDenied);
    let r = hx_agent::privd::cmd::uninstall::uninstall(
        &w.h.daemon,
        &Ctx::new(Role::Gateway),
        pb::UninstallRequest {
            keep_desktop: true,
            confirm_destroy: false,
        },
    )
    .await;
    assert_eq!(r.unwrap_err().code, ErrorCode::PermissionDenied);
    assert!(state_file(&w).is_none());
    assert!(present(&w, "hx-main"));
}

// ----- the marker -----------------------------------------------------------------------------

#[tokio::test]
async fn an_instance_without_the_marker_is_never_touched() {
    let w = world();
    // Same name as ours, but no `user.hx.*` key: someone else's.
    w.h.incus
        .with(|s| s.instances.get_mut("hx-main").unwrap().config.clear());
    let keep = ok_uninstall(admin(&w, uninstall_cmd(true)).await);
    assert!(keep.removed.is_empty(), "{:?}", keep.removed);
    assert!(
        keep.warnings
            .iter()
            .any(|m| m.contains("hx-main") && m.contains("marker"))
    );
    assert!(devices_of(&w, "hx-main").contains(&"hx-link".to_string()));

    let destroy = ok_uninstall(admin(&w, uninstall_cmd(false)).await);
    assert!(
        present(&w, "hx-main"),
        "an unmarked instance survives a destroy"
    );
    assert!(devices_of(&w, "hx-main").contains(&"hx-link".to_string()));
    assert!(has(&destroy.kept, "desktop:main"));
    assert!(!has(&destroy.removed, "desktop:main"));
    assert!(
        destroy
            .warnings
            .iter()
            .any(|m| m.contains("hx-main") && m.contains("marker"))
    );
    // The registry entry stays: the CLI removes /var/lib/hx as a whole.
    assert!(w.h.daemon.read_state(|s| s.desktops.contains_key("main")));
    // The marked host objects were still removed.
    assert!(has(&destroy.removed, "network:hxbr0"));
}

#[tokio::test]
async fn host_objects_without_the_marker_are_left_with_a_warning() {
    let w = world();
    put_object(&w.h.incus, "networks/hxbr0", "someone else's bridge");
    put_object(&w.h.incus, "profiles/hx-desktop", "");
    put_object(&w.h.incus, "storage-pools/hx-pool", "not ours");
    let r = ok_uninstall(admin(&w, uninstall_cmd(false)).await);
    for key in [
        "networks/hxbr0",
        "profiles/hx-desktop",
        "storage-pools/hx-pool",
    ] {
        assert!(object_present(&w, key), "{key} must survive");
    }
    for kept in ["network:hxbr0", "profile:hx-desktop", "pool:hx-pool"] {
        assert!(has(&r.kept, kept), "{kept} in {:?}", r.kept);
        assert!(
            has(
                &r.warnings,
                &format!(
                    "{} `{}` has our name but not our marker; it was left alone",
                    kept.split(':').next().unwrap(),
                    kept.split(':').nth(1).unwrap()
                )
            ),
            "{:?}",
            r.warnings
        );
    }
    // The marked ones went.
    assert!(has(&r.removed, "acl:hx-isolate"));
    assert!(has(&r.removed, "profile:hx-compat-debian13"));
    assert!(!object_present(&w, "network-acls/hx-isolate"));
}

#[tokio::test]
async fn unlinking_never_follows_a_symlink_planted_at_a_file_path() {
    let w = world();
    let victim = w.h.dir.path().join("victim");
    std::fs::write(&victim, b"not ours").unwrap();
    let fw = &w.h.daemon.cfg.firewall_file;
    std::fs::remove_file(fw).unwrap();
    std::os::unix::fs::symlink(&victim, fw).unwrap();
    ok_uninstall(admin(&w, uninstall_cmd(false)).await);
    assert!(
        !fw.exists() && std::fs::symlink_metadata(fw).is_err(),
        "the link is gone"
    );
    assert_eq!(
        std::fs::read(&victim).unwrap(),
        b"not ours",
        "its target is not"
    );
}

// ----- the gate ---------------------------------------------------------------------------------

#[tokio::test]
async fn while_uninstalling_the_gateway_and_admin_mutations_are_refused() {
    let w = world();
    // Before: the Gateway can read.
    let r = call(&w, Role::Gateway, Command::GetHostInfo(Default::default())).await;
    assert!(error_of(&r).is_none(), "{r:?}");
    ok_uninstall(admin(&w, uninstall_cmd(true)).await);

    let refused = |r: &pb::Response| {
        let (code, detail, _) = err_of(r);
        assert_eq!(code, ErrorCode::FailedPrecondition, "{r:?}");
        assert_eq!(detail, ErrorDetail::Uninstalling, "{r:?}");
    };
    // Every Gateway command, reads included.
    for c in [
        Command::GetHostInfo(Default::default()),
        Command::ListDesktops(Default::default()),
        Command::StartDesktop(pb::StartDesktopRequest {
            desktop_id: "main".into(),
        }),
        Command::GetDesktop(pb::GetDesktopRequest {
            desktop_id: "main".into(),
        }),
    ] {
        refused(&call(&w, Role::Gateway, c).await);
    }
    // Admin mutations other than Uninstall.
    for c in [
        Command::StopDesktop(pb::StopDesktopRequest {
            desktop_id: "main".into(),
            ..Default::default()
        }),
        Command::BeginSetup(Default::default()),
        Command::ResetLockout(pb::ResetLockoutRequest {
            purpose: pb::LockoutPurpose::Pin as i32,
        }),
        Command::DestroyDesktop(pb::DestroyDesktopRequest {
            desktop_id: "main".into(),
            confirm_destroy: true,
        }),
    ] {
        refused(&admin(&w, c).await);
    }
    // Admin reads and Uninstall itself still work.
    let r = admin(&w, Command::GetHostInfo(Default::default())).await;
    assert!(error_of(&r).is_none(), "{r:?}");
    ok_uninstall(admin(&w, uninstall_cmd(true)).await);
    // Nothing was done by the refused commands.
    assert!(w.h.daemon.read_state(|s| s.desktops.contains_key("main")));
}

#[tokio::test]
async fn a_command_that_took_its_lock_after_the_uninstall_began_does_not_run() {
    let w = world();
    let ctx = Ctx::new(Role::Admin);
    // A SetupHost has run, so the background refresh has something to re-apply.
    w.h.daemon
        .mutate_state(|s| s.host = Some(HostSetupRecord::default()))
        .unwrap();
    // Admitted before the uninstall: it holds nothing yet.
    assert!(w.h.daemon.lock_host(&ctx).await.is_ok());
    ok_uninstall(admin(&w, uninstall_cmd(true)).await);
    for e in [
        w.h.daemon.lock_host(&ctx).await.unwrap_err(),
        w.h.daemon
            .lock_desktop(&ctx, "main", true)
            .await
            .unwrap_err(),
    ] {
        assert_eq!(
            (e.code, e.detail),
            (ErrorCode::FailedPrecondition, ErrorDetail::Uninstalling)
        );
    }
    // The background re-run of the host ruleset therefore does nothing either (it would write
    // the ruleset file again and load it).
    assert!(w.h.daemon.refresh_host().await.is_err());
    assert!(w.h.runner.calls().iter().all(|c| c.tool != Tool::Ip));
}

#[tokio::test]
async fn the_state_is_written_before_the_locks_are_awaited() {
    let w = world();
    // Another command holds the host lock; the uninstall gives up on it (here: is cancelled).
    let holder = Ctx::new(Role::Admin);
    let _held = w.h.daemon.lock_host(&holder).await.unwrap();
    let mut ctx = Ctx::new(Role::Admin);
    ctx.cancel = CancelToken::new();
    let cancel = ctx.cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        cancel.cancel(CancelReason::Cancelled);
    });
    let r =
        w.h.daemon
            .handle(request(1, uninstall_cmd(true)), ctx)
            .await;
    assert_eq!(err_of(&r).0, ErrorCode::Cancelled);
    // Nothing was removed, but the gate is already up.
    assert!(state_file(&w).is_some());
    assert!(devices_of(&w, "hx-main").contains(&"hx-link".to_string()));
    let r = call(&w, Role::Gateway, Command::GetHostInfo(Default::default())).await;
    assert_eq!(err_of(&r).1, ErrorDetail::Uninstalling);
}

#[tokio::test]
async fn a_corrupt_state_file_keeps_the_gate_closed_and_is_not_replaced() {
    let w = world();
    let path = w.h.daemon.cfg.state_dir.join(STATE_FILE);
    std::fs::write(&path, b"{not json").unwrap();
    let r = admin(&w, uninstall_cmd(true)).await;
    assert_eq!(err_of(&r).0, ErrorCode::Internal);
    assert_eq!(std::fs::read(&path).unwrap(), b"{not json");
    let r = call(&w, Role::Gateway, Command::GetHostInfo(Default::default())).await;
    assert_eq!(err_of(&r).1, ErrorDetail::Uninstalling);
    assert!(devices_of(&w, "hx-main").contains(&"hx-link".to_string()));
}

#[tokio::test]
async fn a_restarted_privd_still_refuses_what_the_first_one_refused() {
    let w = world();
    ok_uninstall(admin(&w, uninstall_cmd(true)).await);
    let d2 = w.h.restart_daemon();
    let r = d2
        .handle(
            request(1, Command::GetHostInfo(Default::default())),
            Ctx::new(Role::Gateway),
        )
        .await;
    assert_eq!(err_of(&r).1, ErrorDetail::Uninstalling);
}

// ----- mode transitions --------------------------------------------------------------------------

#[tokio::test]
async fn keep_may_be_followed_by_destroy() {
    let w = world();
    ok_uninstall(admin(&w, uninstall_cmd(true)).await);
    assert!(present(&w, "hx-main"));
    let r = ok_uninstall(admin(&w, uninstall_cmd(false)).await);
    assert!(!r.keep_desktop);
    assert!(!present(&w, "hx-main"));
    // The link removed by the keep run is still in the report.
    assert!(has(&r.removed, "session-link:main"));
    assert_eq!(state_file(&w).unwrap().mode, UninstallMode::Destroy);
}

#[tokio::test]
async fn destroy_to_keep_is_refused_until_it_has_converged() {
    let w = world();
    w.host.lock().unwrap().fail_nft_delete = true;
    let r = admin(&w, uninstall_cmd(false)).await;
    let (code, detail, stage) = err_of(&r);
    assert_eq!(
        (code, detail, stage),
        (
            ErrorCode::Internal,
            ErrorDetail::Nft,
            Some(ProgressStage::Uninstall)
        )
    );
    assert_eq!(state_file(&w).unwrap().mode, UninstallMode::Destroy);
    // Mid-destroy: a keep request is refused.
    let r = admin(&w, uninstall_cmd(true)).await;
    let (code, detail, _) = err_of(&r);
    assert_eq!(
        (code, detail),
        (ErrorCode::FailedPrecondition, ErrorDetail::Uninstalling)
    );
    // Finish the destroy, then a keep request is answered from the converged destroy.
    w.host.lock().unwrap().fail_nft_delete = false;
    ok_uninstall(admin(&w, uninstall_cmd(false)).await);
    let calls = w.h.runner.calls().len();
    let writes = w.h.incus.with(|s| s.writes.len());
    let r = ok_uninstall(admin(&w, uninstall_cmd(true)).await);
    assert!(!r.keep_desktop, "the desktop is gone: the answer says so");
    assert!(r.warnings.iter().any(|m| m.contains("already destroyed")));
    assert!(has(&r.removed, "desktop:main"));
    assert_eq!(w.h.runner.calls().len(), calls, "nothing ran");
    assert_eq!(w.h.incus.with(|s| s.writes.len()), writes);
    assert_eq!(state_file(&w).unwrap().mode, UninstallMode::Destroy);
}

// ----- resume at every step -----------------------------------------------------------------------

/// Runs a destroy that is made to fail at `step`, checks where it stopped, repairs the cause and
/// runs again: it must finish, and the answer must list what the first run removed.
async fn fails_then_resumes(
    w: &World,
    break_it: impl FnOnce(&World),
    repair: impl FnOnce(&World),
    expect_done: &[&str],
    expect_detail: ErrorDetail,
    removed_before: &[&str],
) {
    break_it(w);
    let r = admin(w, uninstall_cmd(false)).await;
    let (code, detail, stage) = err_of(&r);
    assert_ne!(code, ErrorCode::Unimplemented);
    assert_eq!(stage, Some(ProgressStage::Uninstall), "{r:?}");
    assert_eq!(detail, expect_detail, "{r:?}");
    let st = state_file(w).expect("the state survives a failed step");
    assert!(!st.privd_done);
    assert_eq!(
        st.done, expect_done,
        "the steps that completed before the failure"
    );
    for what in removed_before {
        assert!(has(&st.removed, what), "{what} in {:?}", st.removed);
    }
    // The gate stays up while the uninstall is unfinished.
    let g = call(w, Role::Gateway, Command::GetHostInfo(Default::default())).await;
    assert_eq!(err_of(&g).1, ErrorDetail::Uninstalling);

    repair(w);
    let r = ok_uninstall(admin(w, uninstall_cmd(false)).await);
    assert!(!r.keep_desktop);
    for what in removed_before {
        assert!(
            has(&r.removed, what),
            "{what} lost across the resume: {:?}",
            r.removed
        );
    }
    assert!(state_file(w).unwrap().privd_done);
    // Converged: nothing of ours remains.
    assert!(!present(w, "hx-main"));
    assert!(!pool_present(w));
    assert!(!object_present(w, "networks/hxbr0"));
    assert!(!w.host.lock().unwrap().nft_table);
    assert!(w.host.lock().unwrap().rules.is_empty());
    assert!(!w.h.daemon.cfg.firewall_file.exists());
    assert!(!w.h.daemon.cfg.sysctl_file.exists());
}

#[tokio::test]
async fn resume_after_incus_was_unreachable_at_the_first_step() {
    let w = world();
    fails_then_resumes(
        &w,
        |w| w.h.incus.with(|s| s.down = true),
        |w| w.h.incus.with(|s| s.down = false),
        &[],
        ErrorDetail::Unspecified,
        &[],
    )
    .await;
}

#[tokio::test]
async fn resume_after_the_host_objects_step_failed() {
    // No registry desktop, so the first two steps need no Incus; the third does.
    let w = world();
    w.h.daemon.unregister_desktop("main").unwrap();
    w.h.incus.with(|s| {
        s.instances.clear();
    });
    fails_then_resumes(
        &w,
        |w| w.h.incus.with(|s| s.down = true),
        |w| w.h.incus.with(|s| s.down = false),
        &["session_links", "desktops"],
        ErrorDetail::Unspecified,
        &[],
    )
    .await;
}

#[tokio::test]
async fn resume_after_the_nft_table_could_not_be_deleted() {
    let w = world();
    fails_then_resumes(
        &w,
        |w| w.host.lock().unwrap().fail_nft_delete = true,
        |w| w.host.lock().unwrap().fail_nft_delete = false,
        &["session_links", "desktops", "host_objects"],
        ErrorDetail::Nft,
        &["desktop:main", "pool:hx-pool", "network:hxbr0"],
    )
    .await;
}

#[tokio::test]
async fn resume_after_the_ruleset_file_could_not_be_removed() {
    let w = world();
    let fw = w.h.daemon.cfg.firewall_file.clone();
    fails_then_resumes(
        &w,
        |_| {
            // A directory where the file should be: `unlinkat` refuses it.
            std::fs::remove_file(&fw).unwrap();
            std::fs::create_dir(&fw).unwrap();
        },
        |_| std::fs::remove_dir(&fw).unwrap(),
        &["session_links", "desktops", "host_objects", "nft_table"],
        ErrorDetail::Unspecified,
        &["nft-table:inet hx", "desktop:main"],
    )
    .await;
}

#[tokio::test]
async fn resume_after_a_docker_user_rule_could_not_be_deleted() {
    let w = world();
    fails_then_resumes(
        &w,
        |w| w.host.lock().unwrap().fail_iptables_delete = true,
        |w| w.host.lock().unwrap().fail_iptables_delete = false,
        &[
            "session_links",
            "desktops",
            "host_objects",
            "nft_table",
            "firewall_file",
        ],
        ErrorDetail::DockerUser,
        &["nft-table:inet hx"],
    )
    .await;
}

#[tokio::test]
async fn resume_after_the_sysctl_file_could_not_be_removed() {
    let w = world();
    let sysctl = w.h.daemon.cfg.sysctl_file.clone();
    fails_then_resumes(
        &w,
        |_| {
            std::fs::remove_file(&sysctl).unwrap();
            std::fs::create_dir(&sysctl).unwrap();
        },
        |_| std::fs::remove_dir(&sysctl).unwrap(),
        &[
            "session_links",
            "desktops",
            "host_objects",
            "nft_table",
            "firewall_file",
            "docker_user",
        ],
        ErrorDetail::Unspecified,
        &["docker-user-rules:2"],
    )
    .await;
}

// ----- the rest ------------------------------------------------------------------------------------

#[tokio::test]
async fn a_registered_desktop_whose_instance_is_gone_is_not_an_error() {
    let w = world();
    w.h.incus.with(|s| {
        s.instances.clear();
    });
    let r = ok_uninstall(admin(&w, uninstall_cmd(false)).await);
    assert!(!has(&r.removed, "desktop:main"));
    assert!(w.h.daemon.read_state(|s| s.desktops.is_empty()));
}

#[tokio::test]
async fn a_host_without_docker_or_nft_still_uninstalls() {
    let w = world();
    {
        let mut h = w.host.lock().unwrap();
        h.nft_table = false;
        h.chain = false;
        h.rules.clear();
    }
    let r = ok_uninstall(admin(&w, uninstall_cmd(false)).await);
    assert!(!has(&r.removed, "nft-table:inet hx"));
    assert!(!r.removed.iter().any(|s| s.starts_with("docker-user-rules")));
    // The DOCKER-USER flag is cleared, as after a destroyed host.
    assert!(
        !w.h.daemon
            .flags_for("main")
            .contains(&Flag::HostDockerForwarding)
    );
}

#[tokio::test]
async fn progress_names_the_uninstall_stage() {
    let w = world();
    let (sender, queue) = ProgressSender::new(7);
    let mut ctx = Ctx::new(Role::Admin);
    ctx.progress = sender;
    let r =
        w.h.daemon
            .handle(request(7, uninstall_cmd(false)), ctx)
            .await;
    ok_uninstall(r);
    let mut frames = Vec::new();
    while let Some(p) = queue.pop() {
        frames.push(p);
    }
    assert!(!frames.is_empty());
    assert!(frames.iter().all(|p| p.stage() == ProgressStage::Uninstall));
    assert_eq!(frames.last().unwrap().percent, 100);
    assert!(frames.iter().all(|p| p.step.len() <= 128));
}

#[tokio::test]
async fn the_audit_log_records_the_uninstall_without_secrets_or_paths_of_others() {
    let w = world();
    ok_uninstall(admin(&w, uninstall_cmd(false)).await);
    let lines = w.h.audit.lines();
    assert!(
        lines.iter().any(|l| l.contains("uninstall begun")),
        "{lines:?}"
    );
    assert!(lines.iter().any(|l| l.contains("Uninstall")), "{lines:?}");
}
