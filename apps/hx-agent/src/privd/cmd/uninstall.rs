//! `Uninstall` (class X, Admin only): privd's part of removing the agent (ipc.md 6.13, narrowed).
//!
//! privd runs under `ProtectSystem=strict` without `CAP_DAC_OVERRIDE`, so it cannot remove units,
//! users, binaries, credentials or gatewayd's state. It removes only the objects **it created**:
//!
//! | Step | Mode | What |
//! |---|---|---|
//! | `session_links` | both | the session-link proxy device of each registry desktop |
//! | `desktops` | destroy | each registry desktop and its `hx-` snapshots |
//! | `host_objects` | destroy | profiles, bridge, ACL, pool (each only with the hash-xcreen marker) |
//! | `nft_table` | destroy | `nft delete table inet hx` if the table exists |
//! | `firewall_file` | destroy | `/etc/hx/host-firewall.nft` |
//! | `docker_user` | destroy | both `DOCKER-USER` accept rules |
//! | `sysctl_file` | destroy | `/etc/sysctl.d/90-hx-incus.conf` (live values are not reverted) |
//!
//! `hx-agent uninstall` does the rest (units, `/etc/hx/creds`, `/var/lib/hx-gatewayd`, the user).
//!
//! # State and gate
//!
//! `/var/lib/hx/uninstall-state` is written **first**. While it exists, every Gateway command and
//! every Admin mutation other than `Uninstall` answers `FAILED_PRECONDITION` with detail
//! `UNINSTALLING` ([`Daemon::refuse_while_uninstalling`], applied at admission and again when a
//! command takes a lock, so a command admitted just before the file appeared cannot run after the
//! uninstall). privd never deletes the file: the CLI removes `/var/lib/hx` as a whole.
//!
//! # Idempotent and resumable
//!
//! Every step looks at the host and only acts on what is there, so a run that stopped half way is
//! finished by calling `Uninstall` again. What was removed is accumulated in the state file, so the
//! final answer lists the objects of earlier runs too. Moving from keep to destroy is allowed;
//! destroy to keep is refused until a destroy has converged (`privd_done`), and then answers the
//! converged destroy without doing anything.
//!
//! # What it never does
//!
//! It never deletes an object that lacks the hash-xcreen marker (reported as kept, with a
//! warning), never touches Incus itself, units, `/etc/hx/creds` or `/var/lib/hx-gatewayd`, and
//! unlinks files only relative to a directory descriptor opened `O_NOFOLLOW`.

use std::io;
use std::path::Path;

use hx_ipc::privd::pb::{self, ErrorDetail, ProgressStage, Role, response};
use hx_ipc::privd::{MAX_UNINSTALL_ITEMS, MAX_UNINSTALL_TEXT_LEN};
use hx_ipc::text::sanitize_text;
use hx_provision::incus::{Transport, instance_is_marked};
use hx_provision::teardown::{self, Teardown};
use rustix::fs::{AtFlags, Mode, OFlags};
use serde::{Deserialize, Serialize};

use super::hostsetup::docker_user_rules;
use crate::privd::cancel::{LOCK_WAIT, LockKey};
use crate::privd::daemon::{Ctx, Daemon, Reply};
use crate::privd::error::CmdError;
use crate::privd::log;
use crate::privd::runner::{Program, Tool};

/// The progress file in privd's state directory.
pub const STATE_FILE: &str = "uninstall-state";

/// Most `-D` rounds per `DOCKER-USER` rule (a rule that was inserted twice is removed twice).
const MAX_RULE_DELETES: usize = 8;

/// What the uninstall removes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UninstallMode {
    /// Remove the agent's links to the desktop; leave the desktop and the host objects.
    #[default]
    Keep,
    /// Also destroy the desktop and delete the host objects.
    Destroy,
}

/// The persisted progress (`/var/lib/hx/uninstall-state`, 0600).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct UninstallState {
    /// Format version (1).
    #[serde(default)]
    pub version: u32,
    /// The strongest mode requested so far.
    #[serde(default)]
    pub mode: UninstallMode,
    /// When the first request arrived, Unix seconds.
    #[serde(default)]
    pub started: u64,
    /// Steps completed by the latest run.
    #[serde(default)]
    pub done: Vec<String>,
    /// privd's part has finished: nothing is left for privd to remove in `mode`.
    #[serde(default)]
    pub privd_done: bool,
    /// Everything removed by this and earlier runs (`kind:name`).
    #[serde(default)]
    pub removed: Vec<String>,
}

/// The steps, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    SessionLinks,
    Desktops,
    HostObjects,
    NftTable,
    FirewallFile,
    DockerUser,
    SysctlFile,
}

impl Step {
    fn name(self) -> &'static str {
        match self {
            Self::SessionLinks => "session_links",
            Self::Desktops => "desktops",
            Self::HostObjects => "host_objects",
            Self::NftTable => "nft_table",
            Self::FirewallFile => "firewall_file",
            Self::DockerUser => "docker_user",
            Self::SysctlFile => "sysctl_file",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::SessionLinks => "removing the session links",
            Self::Desktops => "destroying the desktops",
            Self::HostObjects => "deleting the profiles, bridge, ACL and pool",
            Self::NftTable => "removing the host nftables table",
            Self::FirewallFile => "removing the persisted ruleset",
            Self::DockerUser => "removing the DOCKER-USER rules",
            Self::SysctlFile => "removing the sysctl drop-in",
        }
    }
}

fn steps_for(mode: UninstallMode) -> &'static [Step] {
    match mode {
        UninstallMode::Keep => &[Step::SessionLinks],
        UninstallMode::Destroy => &[
            Step::SessionLinks,
            Step::Desktops,
            Step::HostObjects,
            Step::NftTable,
            Step::FirewallFile,
            Step::DockerUser,
            Step::SysctlFile,
        ],
    }
}

/// What a request does to the persisted state.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Plan {
    /// Run the steps of `mode`, with this state written first.
    Run(UninstallState),
    /// A destroy has already converged; a keep request is answered from it, nothing runs.
    ConvergedDestroy(UninstallState),
}

/// Decides how a request (`keep` or destroy) combines with the state left by earlier requests.
/// Pure, so the transitions are unit-tested.
pub(crate) fn plan(
    existing: Option<UninstallState>,
    keep: bool,
    now: u64,
) -> Result<Plan, CmdError> {
    let want = if keep { UninstallMode::Keep } else { UninstallMode::Destroy };
    let Some(mut st) = existing else {
        return Ok(Plan::Run(UninstallState {
            version: 1,
            mode: want,
            started: now,
            ..UninstallState::default()
        }));
    };
    if st.mode == UninstallMode::Destroy && want == UninstallMode::Keep {
        if st.privd_done {
            return Ok(Plan::ConvergedDestroy(st));
        }
        return Err(CmdError::precondition(
            ErrorDetail::Uninstalling,
            "a destroying uninstall is in progress; finish it with keep_desktop=false",
        ));
    }
    st.version = 1;
    st.mode = want;
    st.done.clear();
    st.privd_done = false;
    Ok(Plan::Run(st))
}

/// What a run reports besides what the state already holds.
#[derive(Default)]
struct Report {
    kept: Vec<String>,
    warnings: Vec<String>,
}

fn io_err(what: &str, e: &io::Error) -> CmdError {
    log::error(&format!("uninstall: {what}: {e}"));
    CmdError::internal(format!("uninstall: {what} failed"))
}

/// Removes `path`'s final component relative to a descriptor of its directory opened
/// `O_NOFOLLOW`. `Ok(true)` if it was removed, `Ok(false)` if it was not there. A symlink at the
/// path is removed as an entry, never followed.
pub(crate) fn unlink_beneath(path: &Path) -> io::Result<bool> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no parent directory"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
    let fd = match rustix::fs::open(
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    match rustix::fs::unlinkat(&fd, name, AtFlags::empty()) {
        Ok(()) => {
            std::fs::File::from(rustix::io::fcntl_dupfd_cloexec(&fd, 0)?).sync_all()?;
            Ok(true)
        }
        Err(rustix::io::Errno::NOENT) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

impl<T: Transport + Clone + 'static> Daemon<T> {
    /// Whether an uninstall has begun (the state file exists). Fails closed: a file that cannot be
    /// examined counts as present.
    pub fn uninstalling(&self) -> bool {
        match std::fs::symlink_metadata(self.store.path(STATE_FILE)) {
            Ok(_) => true,
            Err(e) => e.kind() != io::ErrorKind::NotFound,
        }
    }

    /// `FAILED_PRECONDITION` / `UNINSTALLING` while an uninstall has begun.
    pub fn refuse_while_uninstalling(&self) -> Result<(), CmdError> {
        if self.uninstalling() {
            return Err(CmdError::precondition(
                ErrorDetail::Uninstalling,
                "the agent is being uninstalled",
            ));
        }
        Ok(())
    }

    fn load_uninstall_state(&self) -> Result<Option<UninstallState>, CmdError> {
        match std::fs::read(self.store.path(STATE_FILE)) {
            Ok(b) => serde_json::from_slice(&b).map(Some).map_err(|e| {
                log::error(&format!(
                    "{STATE_FILE} is corrupt ({e}); remove it by hand to start again"
                ));
                CmdError::internal("uninstall-state is corrupt; refusing to guess")
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_err("reading uninstall-state", &e)),
        }
    }

    fn save_uninstall_state(&self, st: &UninstallState) -> Result<(), CmdError> {
        self.store
            .save_json(STATE_FILE, st)
            .map_err(|e| io_err("writing uninstall-state", &e))
    }
}

/// `Uninstall`: see the module documentation.
pub async fn uninstall<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &Ctx,
    r: pb::UninstallRequest,
) -> Result<Reply, CmdError> {
    if ctx.role != Role::Admin {
        return Err(CmdError::denied("uninstall: Admin only"));
    }
    if !r.keep_desktop && !r.confirm_destroy {
        return Err(CmdError::invalid("uninstall.confirm_destroy"));
    }
    // The gate goes up before any lock is awaited, so that new commands are refused while an
    // in-flight one finishes. The mutex serialises the read-decide-write of the state file.
    let mut st = {
        let _g = d.uninstall_gate.lock().unwrap_or_else(|e| e.into_inner());
        let existing = d.load_uninstall_state()?;
        match plan(existing, r.keep_desktop, d.now())? {
            Plan::ConvergedDestroy(st) => {
                return Ok(response::Result::Uninstall(result_of(
                    &st,
                    &Report {
                        kept: Vec::new(),
                        warnings: vec![
                            "the desktop was already destroyed by an earlier uninstall".into(),
                        ],
                    },
                )));
            }
            Plan::Run(st) => {
                d.save_uninstall_state(&st)?;
                st
            }
        }
    };
    d.audit_notice(&format!("uninstall begun (mode {:?})", st.mode));

    let _host = d
        .locks
        .acquire_as(LockKey::Host, &ctx.cancel, LOCK_WAIT, true)
        .await?;
    let ids: Vec<String> = d.read_state(|s| s.desktops.keys().cloned().collect());
    let mut _desktop_locks = Vec::with_capacity(ids.len());
    for id in &ids {
        _desktop_locks.push(
            d.locks
                .acquire_as(LockKey::Desktop(id), &ctx.cancel, LOCK_WAIT, true)
                .await?,
        );
    }

    let mut rep = Report::default();
    let steps = steps_for(st.mode);
    for (i, step) in steps.iter().enumerate() {
        ctx.check_cancelled()?;
        ctx.progress.emit(
            ProgressStage::Uninstall,
            i as u32,
            steps.len() as u32,
            step.label(),
            u32::try_from(i * 100 / steps.len()).unwrap_or(0),
            true,
        );
        run_step(d, ctx, *step, &ids, &mut st, &mut rep)
            .await
            .map_err(|e| e.at_stage(ProgressStage::Uninstall))?;
        st.done.push(step.name().to_string());
        d.save_uninstall_state(&st)?;
    }
    match st.mode {
        UninstallMode::Keep => keep_list(d, &ids, &mut rep),
        UninstallMode::Destroy => rep
            .kept
            .push("sysctl-values:live values revert at the next boot".into()),
    }
    st.privd_done = true;
    d.save_uninstall_state(&st)?;
    ctx.progress.emit(
        ProgressStage::Uninstall,
        steps.len() as u32,
        steps.len() as u32,
        "privd's part is done",
        100,
        true,
    );
    d.audit_notice(&format!(
        "uninstall: privd's part is done (mode {:?}, {} removed)",
        st.mode,
        st.removed.len()
    ));
    Ok(response::Result::Uninstall(result_of(&st, &rep)))
}

fn cap(list: &[String]) -> Vec<String> {
    list.iter()
        .take(MAX_UNINSTALL_ITEMS)
        .map(|s| sanitize_text(s, MAX_UNINSTALL_TEXT_LEN))
        .collect()
}

fn result_of(st: &UninstallState, rep: &Report) -> pb::UninstallResult {
    pb::UninstallResult {
        keep_desktop: st.mode == UninstallMode::Keep,
        removed: cap(&st.removed),
        kept: cap(&rep.kept),
        warnings: cap(&rep.warnings),
    }
}

/// What a keep-mode run leaves in place (the destroy list, stated rather than probed).
fn keep_list<T: Transport + Clone + 'static>(d: &Daemon<T>, ids: &[String], rep: &mut Report) {
    for id in ids {
        rep.kept.push(format!("desktop:{id}"));
    }
    let n = &d.cfg.naming;
    for (kind, name) in [
        ("pool", &n.pool),
        ("network", &n.bridge),
        ("acl", &n.acl),
        ("profile", &n.desktop_profile),
        ("profile", &n.compat_profile),
    ] {
        rep.kept.push(format!("{kind}:{name}"));
    }
    rep.kept.push("nft-table:inet hx".into());
    rep.kept
        .push(format!("file:{}", d.cfg.firewall_file.display()));
    rep.kept.push("docker-user-rules".into());
    rep.kept
        .push(format!("file:{}", d.cfg.sysctl_file.display()));
}

fn note_removed(st: &mut UninstallState, what: String) {
    if !st.removed.contains(&what) && st.removed.len() < MAX_UNINSTALL_ITEMS {
        st.removed.push(what);
    }
}

fn teardown_entry(
    t: Teardown,
    kind: &str,
    name: &str,
    st: &mut UninstallState,
    rep: &mut Report,
) {
    match t {
        Teardown::Removed => note_removed(st, format!("{kind}:{name}")),
        Teardown::Absent => {}
        Teardown::SkippedUnmarked => {
            rep.kept.push(format!("{kind}:{name}"));
            rep.warnings.push(format!(
                "{kind} `{name}` has our name but not our marker; it was left alone"
            ));
        }
    }
}

async fn run_step<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &Ctx,
    step: Step,
    ids: &[String],
    st: &mut UninstallState,
    rep: &mut Report,
) -> Result<(), CmdError> {
    match step {
        Step::SessionLinks => session_links(d, ctx, ids, st, rep).await,
        Step::Desktops => desktops(d, ctx, ids, st, rep).await,
        Step::HostObjects => host_objects(d, ctx, st, rep).await,
        Step::NftTable => nft_table(d, st, rep).await,
        Step::FirewallFile => unlink_file(&d.cfg.firewall_file, st),
        Step::DockerUser => docker_user(d, st, rep).await,
        Step::SysctlFile => unlink_file(&d.cfg.sysctl_file, st),
    }
}

/// What the session-link step found on one instance.
enum Link {
    NoInstance,
    Unmarked,
    Done(bool),
}

/// Both modes: the proxy device of each registry desktop, only on an instance with our marker.
async fn session_links<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &Ctx,
    ids: &[String],
    st: &mut UninstallState,
    rep: &mut Report,
) -> Result<(), CmdError> {
    let client = d.incus.scoped();
    for id in ids {
        let name = d.instance_name(id);
        let found = d
            .run_cancellable(ctx, &client, Some(id), async {
                let Some(inst) = client.get_instance(&name).await? else {
                    return Ok::<_, CmdError>(Link::NoInstance);
                };
                if !instance_is_marked(&inst.config) {
                    return Ok(Link::Unmarked);
                }
                Ok(Link::Done(client.remove_session_link(&name).await?))
            })
            .await?;
        match found {
            Link::Done(true) => note_removed(st, format!("session-link:{id}")),
            Link::Done(false) | Link::NoInstance => {}
            Link::Unmarked => rep.warnings.push(format!(
                "instance `{name}` has our name but not our marker; its devices were left alone"
            )),
        }
    }
    Ok(())
}

/// Destroy mode: each registry desktop and its `hx-` snapshots, then its registry entry.
async fn desktops<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &Ctx,
    ids: &[String],
    st: &mut UninstallState,
    rep: &mut Report,
) -> Result<(), CmdError> {
    let client = d.incus.scoped();
    for id in ids {
        let name = d.instance_name(id);
        let outcome = d
            .run_cancellable(ctx, &client, Some(id), async {
                teardown::destroy_desktop(&client, &name).await
            })
            .await;
        match outcome {
            Ok(report) => {
                if report.instance_removed {
                    note_removed(st, format!("desktop:{id}"));
                }
                d.mutate_state(|s| {
                    s.desktops.remove(id);
                })?;
            }
            // `destroy_desktop` refuses an instance without the marker; the uninstall goes on.
            Err(e) if e.code == pb::ErrorCode::PermissionDenied => {
                rep.kept.push(format!("desktop:{id}"));
                rep.warnings.push(format!(
                    "instance `{name}` has our name but not our marker; it was left alone"
                ));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Destroy mode: profiles, bridge, ACL, pool, each only with the marker (`teardown_host`).
async fn host_objects<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &Ctx,
    st: &mut UninstallState,
    rep: &mut Report,
) -> Result<(), CmdError> {
    let client = d.incus.scoped();
    let naming = d.cfg.naming.clone();
    let t = d
        .run_cancellable(ctx, &client, None, async {
            teardown::teardown_host(&client, &naming).await
        })
        .await?;
    teardown_entry(
        t.desktop_profile,
        "profile",
        &naming.desktop_profile,
        st,
        rep,
    );
    teardown_entry(t.compat_profile, "profile", &naming.compat_profile, st, rep);
    teardown_entry(t.network, "network", &naming.bridge, st, rep);
    teardown_entry(t.acl, "acl", &naming.acl, st, rep);
    teardown_entry(t.pool, "pool", &naming.pool, st, rep);
    Ok(())
}

async fn nft_table<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    st: &mut UninstallState,
    rep: &mut Report,
) -> Result<(), CmdError> {
    let nft = |args: &[&str]| {
        let p = Program::new(Tool::Nft, args).with_timeout(std::time::Duration::from_secs(30));
        async move { d.runner.run(p).await }
    };
    let listed = match nft(&["list", "table", "inet", "hx"]).await {
        Ok(o) => o,
        Err(e) => {
            // No nft binary means no table of ours can exist.
            log::warn(&format!("uninstall: nft: {e}"));
            rep.warnings
                .push("nft is not available; the host table was not checked".into());
            return Ok(());
        }
    };
    if !listed.success() {
        return Ok(());
    }
    let del = nft(&["delete", "table", "inet", "hx"])
        .await
        .map_err(CmdError::from)?;
    if !del.success() {
        return Err(
            CmdError::internal("`nft delete table inet hx` failed").with_detail(ErrorDetail::Nft)
        );
    }
    note_removed(st, "nft-table:inet hx".into());
    Ok(())
}

fn unlink_file(path: &Path, st: &mut UninstallState) -> Result<(), CmdError> {
    match unlink_beneath(path) {
        Ok(true) => {
            note_removed(st, format!("file:{}", path.display()));
            Ok(())
        }
        Ok(false) => Ok(()),
        Err(e) => Err(io_err(&format!("removing {}", path.display()), &e)),
    }
}

/// Destroy mode: delete both accept rules from `DOCKER-USER` until `-C` no longer finds them.
async fn docker_user<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    st: &mut UninstallState,
    rep: &mut Report,
) -> Result<(), CmdError> {
    let run = |args: Vec<String>| async move {
        d.runner
            .run(Program {
                tool: Tool::Iptables,
                args,
                stdin: None,
                timeout: std::time::Duration::from_secs(10),
            })
            .await
    };
    let s = |v: &[&str]| v.iter().map(|x| (*x).to_string()).collect::<Vec<_>>();
    match run(s(&["-n", "-L", "DOCKER-USER"])).await {
        Ok(o) if o.success() => {}
        Ok(_) => return Ok(()), // no chain, no rules
        Err(e) => {
            log::warn(&format!("uninstall: iptables: {e}"));
            rep.warnings
                .push("iptables is not available; DOCKER-USER was not checked".into());
            return Ok(());
        }
    }
    let mut deleted = 0usize;
    for rule in docker_user_rules(&d.cfg.naming.bridge) {
        for _ in 0..MAX_RULE_DELETES {
            let with = |op: &str| {
                let mut a = vec![op.to_string(), "DOCKER-USER".to_string()];
                a.extend(rule.iter().cloned());
                a
            };
            if !run(with("-C")).await.is_ok_and(|o| o.success()) {
                break;
            }
            if !run(with("-D")).await.is_ok_and(|o| o.success()) {
                return Err(CmdError::internal("`iptables -D DOCKER-USER` failed")
                    .with_detail(ErrorDetail::DockerUser));
            }
            deleted += 1;
        }
    }
    if deleted > 0 {
        note_removed(st, format!("docker-user-rules:{deleted}"));
    }
    d.set_flag(None, crate::privd::state::Flag::HostDockerForwarding, false);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(mode: UninstallMode, done: bool) -> UninstallState {
        UninstallState {
            version: 1,
            mode,
            started: 5,
            done: vec!["session_links".into()],
            privd_done: done,
            removed: vec!["x:y".into()],
        }
    }

    #[test]
    fn a_first_request_starts_in_its_own_mode() {
        let Plan::Run(s) = plan(None, true, 9).unwrap() else {
            panic!()
        };
        assert_eq!((s.mode, s.started, s.privd_done), (UninstallMode::Keep, 9, false));
        let Plan::Run(s) = plan(None, false, 9).unwrap() else {
            panic!()
        };
        assert_eq!(s.mode, UninstallMode::Destroy);
    }

    #[test]
    fn keep_may_become_destroy_and_a_rerun_clears_the_done_flag() {
        let Plan::Run(s) = plan(Some(state(UninstallMode::Keep, true)), false, 99).unwrap() else {
            panic!()
        };
        assert_eq!(s.mode, UninstallMode::Destroy);
        assert!(!s.privd_done && s.done.is_empty());
        assert_eq!(s.started, 5, "the start time of the first request is kept");
        assert_eq!(s.removed, ["x:y"], "what was removed is kept");
        let Plan::Run(s) = plan(Some(state(UninstallMode::Keep, true)), true, 99).unwrap() else {
            panic!()
        };
        assert_eq!(s.mode, UninstallMode::Keep);
    }

    #[test]
    fn destroy_to_keep_is_refused_until_converged() {
        let e = plan(Some(state(UninstallMode::Destroy, false)), true, 1).unwrap_err();
        assert_eq!(e.code, pb::ErrorCode::FailedPrecondition);
        assert_eq!(e.detail, ErrorDetail::Uninstalling);
        assert!(matches!(
            plan(Some(state(UninstallMode::Destroy, true)), true, 1).unwrap(),
            Plan::ConvergedDestroy(_)
        ));
        // Destroy again is always allowed.
        assert!(matches!(
            plan(Some(state(UninstallMode::Destroy, false)), false, 1).unwrap(),
            Plan::Run(_)
        ));
    }

    #[test]
    fn unlink_beneath_never_follows_a_symlink() {
        let t = tempfile::tempdir().unwrap();
        let victim = t.path().join("victim");
        std::fs::write(&victim, b"keep me").unwrap();
        let link = t.path().join("link");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(unlink_beneath(&link).unwrap());
        assert!(victim.exists() && !link.exists());
        // A missing file or directory is not an error.
        assert!(!unlink_beneath(&link).unwrap());
        assert!(!unlink_beneath(&t.path().join("no/such/file")).unwrap());
        // A directory whose own path is a symlink is refused, not followed.
        let real = t.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(real.join("f"), b"x").unwrap();
        let dlink = t.path().join("dlink");
        std::os::unix::fs::symlink(&real, &dlink).unwrap();
        assert!(unlink_beneath(&dlink.join("f")).is_err());
        assert!(real.join("f").exists());
    }
}
