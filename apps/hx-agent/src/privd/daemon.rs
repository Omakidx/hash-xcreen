//! The daemon core: shared state, request admission and dispatch.
//!
//! One [`Daemon`] serves every connection. A request goes through, in this order: validation
//! (done by `hx_ipc::privd::decode`), [`auth::authorize`] (class, `gateway_denied`, phase gates),
//! the `UNIMPLEMENTED` answer for reserved commands, rate-limit admission, and then the command in
//! `cmd`. One audit record is written when the command completes, whatever its outcome.

use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use hx_ipc::peer::PeerCred;
use hx_ipc::privd::command_info;
use hx_ipc::privd::pb::{self, ErrorCode, ErrorDetail, Role, request::Command, response};
use hx_ipc::secret::Secret;
use hx_provision::Catalog;
use hx_provision::incus::{Client, Instance, Transport, UnixTransport, instance_is_marked};
use hx_provision::orchestrate::destroy_instance;

use super::audit::{self, AuditSink, FileAudit, RequestRecord};
use super::auth;
use super::cancel::{CancelToken, Guard, LOCK_WAIT, LockKey, Locks};
use super::clock::{Clock, SystemClock};
use super::cmd;
use super::config::PrivdConfig;
use super::error::CmdError;
use super::identity::{self, Violation};
use super::limiter::{Limiter, Purpose};
use super::log;
use super::pepper::Pepper;
use super::probe::{HostProbe, SystemProbe};
use super::progress::ProgressSender;
use super::runner::{CommandRunner, SystemRunner};
use super::state::{DesktopRecord, Flag, PhaseKind, PrivdState, StateStore};

/// A command's successful answer.
pub type Reply = response::Result;

/// The replaceable collaborators of a [`Daemon`] (everything that touches the host other than
/// Incus). Production uses [`Deps::system`]; tests substitute fakes.
pub struct Deps {
    /// Runs `nft`, `sysctl`, `iptables`, `ip` and `blkid`.
    pub runner: Arc<dyn CommandRunner>,
    /// Host facts.
    pub probe: Arc<dyn HostProbe>,
    /// Time.
    pub clock: Arc<dyn Clock>,
    /// The audit log.
    pub audit: Arc<dyn AuditSink>,
}

impl Deps {
    /// The real collaborators, with the audit log opened at `cfg.audit_log`.
    pub fn system(cfg: &PrivdConfig) -> io::Result<Self> {
        Ok(Self {
            runner: Arc::new(SystemRunner),
            probe: Arc::new(SystemProbe::new(&cfg.incus_dir)),
            clock: Arc::new(SystemClock),
            audit: Arc::new(FileAudit::open(&cfg.audit_log)?),
        })
    }
}

/// Per-request context handed to a command.
pub struct Ctx {
    /// Role derived from `SO_PEERCRED` (never from a message).
    pub role: Role,
    /// The peer's credentials as the kernel reported them.
    pub peer: PeerCred,
    /// The caller's request id.
    pub request_id: u64,
    /// Secrets by slot number, each filled once.
    pub secrets: Vec<Option<Secret>>,
    /// Fires on `Cancel`, deadline or a closed connection.
    pub cancel: CancelToken,
    /// Progress frames of this request.
    pub progress: ProgressSender,
}

impl Ctx {
    /// A context for calling a command without a connection (tests, internal use).
    pub fn new(role: Role) -> Self {
        Self {
            role,
            peer: PeerCred {
                pid: 0,
                uid: if role == Role::Admin { 0 } else { u32::MAX },
                gid: 0,
            },
            request_id: 1,
            secrets: Vec::new(),
            cancel: CancelToken::new(),
            progress: ProgressSender::discard(),
        }
    }

    /// Takes the secret of `slot` (leaving `None`), so it is moved to its consumer, never copied.
    pub fn take_secret(&mut self, slot: usize) -> Option<Secret> {
        self.secrets.get_mut(slot).and_then(Option::take)
    }

    /// `Err` with the cancellation error if the request has been cancelled.
    pub fn check_cancelled(&self) -> Result<(), CmdError> {
        match self.cancel.reason() {
            Some(r) => Err(r.error()),
            None => Ok(()),
        }
    }
}

/// Connections currently served, by role (ipc.md 8: at most 4 of each).
#[derive(Default)]
pub struct ConnCounter {
    gateway: AtomicUsize,
    admin: AtomicUsize,
}

/// Most connections per role.
pub const MAX_CONNECTIONS_PER_ROLE: usize = 4;

/// Releases a connection slot on drop.
pub struct ConnSlot {
    counter: Arc<ConnCounter>,
    role: Role,
}

impl Drop for ConnSlot {
    fn drop(&mut self) {
        let c = match self.role {
            Role::Gateway => &self.counter.gateway,
            _ => &self.counter.admin,
        };
        c.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The daemon.
pub struct Daemon<T: Transport + Clone + 'static> {
    /// Fixed configuration.
    pub cfg: PrivdConfig,
    pub(crate) incus: Client<T>,
    pub(crate) runner: Arc<dyn CommandRunner>,
    pub(crate) probe: Arc<dyn HostProbe>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) audit: Arc<dyn AuditSink>,
    pub(crate) store: StateStore,
    state: Mutex<PrivdState>,
    pub(crate) limiter: Mutex<Limiter>,
    pub(crate) pepper: Pepper,
    pub(crate) locks: Locks,
    pub(crate) catalog: Catalog,
    conns: Arc<ConnCounter>,
    /// Refusals not written to the audit log since the last line that was.
    suppressed: std::sync::atomic::AtomicU64,
    /// `(unix ms, docker_on_host, host_firewall_loaded)` of the last host probe.
    pub(crate) host_probe: Mutex<Option<(u64, bool, bool)>>,
}

impl Daemon<UnixTransport> {
    /// The production daemon: the real Incus socket, runner, probe, clock and audit log.
    pub fn system(cfg: PrivdConfig) -> io::Result<Arc<Self>> {
        let deps = Deps::system(&cfg)?;
        let incus = Client::unix(&cfg.incus_socket);
        Self::new(cfg, incus, deps)
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl<T: Transport + Clone + 'static> Daemon<T> {
    /// Builds a daemon: opens the state directory (a corrupt state file is an error, never a
    /// reset), loads or creates the pepper, and loads the persisted budgets.
    pub fn new(cfg: PrivdConfig, incus: Client<T>, deps: Deps) -> io::Result<Arc<Self>> {
        Self::build(cfg, incus, deps, Catalog::embedded())
    }

    /// Like [`Daemon::new`] with another recipe catalog: the real-Incus test uses a minimal
    /// recipe so that a run takes minutes, not an hour. Only with the `test-support` feature; the
    /// binary always uses `Catalog::embedded()`.
    #[cfg(any(test, feature = "test-support"))]
    pub fn new_with_catalog(
        cfg: PrivdConfig,
        incus: Client<T>,
        deps: Deps,
        catalog: Catalog,
    ) -> io::Result<Arc<Self>> {
        Self::build(cfg, incus, deps, catalog)
    }

    fn build(
        cfg: PrivdConfig,
        incus: Client<T>,
        deps: Deps,
        catalog: Catalog,
    ) -> io::Result<Arc<Self>> {
        let store = StateStore::open(&cfg.state_dir)?;
        let state = store.load_state()?;
        let pepper = Pepper::load_or_create(&store.path("pepper.key"))?;
        let limiter = Limiter::load(deps.clock.clone(), store.clone())?;
        Ok(Arc::new(Self {
            cfg,
            incus,
            runner: deps.runner,
            probe: deps.probe,
            clock: deps.clock,
            audit: deps.audit,
            store,
            state: Mutex::new(state),
            limiter: Mutex::new(limiter),
            pepper,
            locks: Locks::new(),
            catalog,
            conns: Arc::new(ConnCounter::default()),
            suppressed: std::sync::atomic::AtomicU64::new(0),
            host_probe: Mutex::new(None),
        }))
    }

    // ----- connections -------------------------------------------------------------------

    /// Admits a connection of `role` if fewer than 4 of that role are open.
    pub fn admit_connection(&self, role: Role) -> Option<ConnSlot> {
        let c = match role {
            Role::Gateway => &self.conns.gateway,
            Role::Admin => &self.conns.admin,
            Role::Unspecified => return None,
        };
        if c.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS_PER_ROLE {
            c.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(ConnSlot {
            counter: self.conns.clone(),
            role,
        })
    }

    // ----- state helpers -----------------------------------------------------------------

    /// Unix seconds now.
    pub fn now(&self) -> u64 {
        self.clock.unix_secs()
    }

    /// The effective phase: an expired setup window is closed (and the state saved) first.
    pub fn phase(&self) -> PhaseKind {
        let now = self.now();
        let mut g = lock(&self.state);
        if g.expire_window(now) {
            if let Err(e) = self.store.save_state(&g) {
                log::error(&format!("cannot persist the closed setup window: {e}"));
            }
            self.audit
                .append(&audit::notice_line(now, "setup window expired"));
        }
        g.phase.phase
    }

    /// Reads the state.
    pub fn read_state<R>(&self, f: impl FnOnce(&PrivdState) -> R) -> R {
        f(&lock(&self.state))
    }

    /// Changes the state and persists it; if persisting fails the change is rolled back and the
    /// command fails (no half-applied phase or flag).
    pub fn mutate_state<R>(&self, f: impl FnOnce(&mut PrivdState) -> R) -> Result<R, CmdError> {
        let now = self.now();
        let mut g = lock(&self.state);
        g.expire_window(now);
        let before = g.clone();
        let r = f(&mut g);
        if *g != before
            && let Err(e) = self.store.save_state(&g)
        {
            *g = before;
            log::error(&format!("cannot persist the state: {e}"));
            return Err(CmdError::internal("cannot persist privd's state"));
        }
        Ok(r)
    }

    /// Sets or clears an attention flag, host-wide (`desktop` is `None`) or for one desktop.
    pub fn set_flag(&self, desktop: Option<&str>, flag: Flag, on: bool) {
        let r = self.mutate_state(|s| {
            let set = match desktop {
                Some(id) => &mut s.desktops.entry(id.to_string()).or_default().flags,
                None => &mut s.flags,
            };
            if on {
                set.insert(flag)
            } else {
                set.remove(&flag)
            }
        });
        if let Err(e) = r {
            log::error(&format!("cannot update attention flag {flag:?}: {e}"));
        }
    }

    /// The flags that hold for a desktop (its own and the host-wide ones).
    pub fn flags_for(&self, id: &str) -> Vec<Flag> {
        self.read_state(|s| s.attention_for(id))
    }

    /// Writes a notice line of privd's own to the audit log.
    pub fn audit_notice(&self, text: &str) {
        self.audit.append(&audit::notice_line(self.now(), text));
    }

    // ----- desktops ----------------------------------------------------------------------

    /// The instance name of a desktop id.
    pub fn instance_name(&self, id: &str) -> String {
        self.cfg.instance_name(id)
    }

    /// Takes the per-desktop lock. A desktop with `STUCK_OPERATION` is refused (privd does not
    /// start new work on an instance with an operation that would not end) unless `allow_stuck`.
    pub async fn lock_desktop(
        &self,
        ctx: &Ctx,
        id: &str,
        allow_stuck: bool,
    ) -> Result<Guard, CmdError> {
        let g = self
            .locks
            .acquire(LockKey::Desktop(id), &ctx.cancel, LOCK_WAIT)
            .await?;
        if !allow_stuck && self.flags_for(id).contains(&Flag::StuckOperation) {
            return Err(CmdError::precondition(
                ErrorDetail::NeedsAttention,
                "an Incus operation on this desktop did not end; an administrator must resolve it",
            ));
        }
        Ok(g)
    }

    /// Takes the host lock.
    pub async fn lock_host(&self, ctx: &Ctx) -> Result<Guard, CmdError> {
        self.locks
            .acquire(LockKey::Host, &ctx.cancel, LOCK_WAIT)
            .await
    }

    /// The registered desktop's instance and metadata. `NOT_FOUND` when privd does not know the id
    /// or the instance is gone; a desktop privd did not create is never touched (ipc.md 7 rule 8).
    pub async fn load_desktop(&self, id: &str) -> Result<LoadedDesktop, CmdError> {
        self.load_desktop_with(&self.incus, id).await
    }

    /// Like [`Daemon::load_desktop`] with a specific (scoped) client.
    pub async fn load_desktop_with(
        &self,
        client: &Client<T>,
        id: &str,
    ) -> Result<LoadedDesktop, CmdError> {
        if !self.read_state(|s| s.desktops.contains_key(id)) {
            return Err(CmdError::not_found("unknown desktop"));
        }
        let name = self.instance_name(id);
        let instance = client
            .get_instance(&name)
            .await?
            .ok_or_else(|| CmdError::not_found("unknown desktop"))?;
        if !instance_is_marked(&instance.config) {
            return Err(CmdError::not_found("unknown desktop"));
        }
        Ok(LoadedDesktop {
            name,
            meta: DesktopMeta::from_config(&instance),
            instance,
        })
    }

    /// Registers a desktop id (before its instance exists, so a crash leaves a record to clean).
    pub fn register_desktop(&self, id: &str) -> Result<(), CmdError> {
        self.mutate_state(|s| {
            s.desktops
                .entry(id.to_string())
                .or_insert_with(DesktopRecord::default);
        })
    }

    /// Forgets a desktop id and its flags.
    pub fn unregister_desktop(&self, id: &str) -> Result<(), CmdError> {
        self.mutate_state(|s| {
            s.desktops.remove(id);
        })
    }

    // ----- cancellation ------------------------------------------------------------------

    /// Drives `fut` (a call into `hx-provision` or the Incus client) to completion or until the
    /// request is cancelled.
    ///
    /// On cancel the future is dropped (which does **not** stop an Incus background operation),
    /// then every operation `client` started is cancelled and waited for, at most 30 s
    /// ([`Client::cancel_in_flight`]). If one will not end, `STUCK_OPERATION` is set on `desktop`
    /// and the answer is `INTERNAL`; otherwise it is the cancellation error, so `CANCELLED` is
    /// only ever answered once the work has really ended.
    pub async fn run_cancellable<F, R, E>(
        &self,
        ctx: &Ctx,
        client: &Client<T>,
        desktop: Option<&str>,
        fut: F,
    ) -> Result<R, CmdError>
    where
        F: Future<Output = Result<R, E>>,
        E: Into<CmdError>,
    {
        let mut fut = Box::pin(fut);
        let outcome = tokio::select! {
            r = &mut fut => Ok(r),
            reason = ctx.cancel.cancelled() => Err(reason),
        };
        match outcome {
            Ok(r) => r.map_err(Into::into),
            Err(reason) => {
                // Really drop the future (and its connection to Incus) before cleaning up.
                drop(fut);
                self.end_operations(client, desktop).await?;
                Err(reason.error())
            }
        }
    }

    /// Cancels and waits for every operation `client` started (the part of a cancel that follows
    /// dropping the futures). `Err(INTERNAL)` and `STUCK_OPERATION` when one does not end.
    pub async fn end_operations(
        &self,
        client: &Client<T>,
        desktop: Option<&str>,
    ) -> Result<(), CmdError> {
        match client.cancel_in_flight(Duration::from_secs(30)).await {
            Ok(_) => Ok(()),
            Err(ids) => {
                log::error(&format!(
                    "{} Incus operation(s) did not end after a cancel",
                    ids.len()
                ));
                if let Some(id) = desktop {
                    self.set_flag(Some(id), Flag::StuckOperation, true);
                }
                self.audit_notice("needs_attention=STUCK_OPERATION");
                Err(CmdError::internal(
                    "an Incus operation did not end after the cancel",
                ))
            }
        }
    }

    /// Forced stop and delete of an instance (what ends exec operations that cannot be cancelled
    /// on Incus 6.0.0). Errors are logged; the caller decides what to answer.
    pub async fn destroy_unfinished(&self, client: &Client<T>, instance: &str) -> bool {
        match destroy_instance(client, instance).await {
            Ok(()) => true,
            Err(e) => {
                log::error(&format!("cleanup of `{instance}` failed: {e}"));
                false
            }
        }
    }

    // ----- self-checks -------------------------------------------------------------------

    /// Re-runs the account-policy self-checks of ipc.md 3 and sets or clears
    /// `needs_attention=HOST_ACCOUNT_POLICY`. The daemon calls it at start (a failure is fatal)
    /// and then daily; the update path calls it after every update.
    pub fn run_self_checks(&self) -> Vec<Violation> {
        let v = identity::run_self_checks(&self.cfg);
        self.set_flag(None, Flag::HostAccountPolicy, !v.is_empty());
        for x in &v {
            log::error(&format!("self-check failed: {x}"));
            self.audit_notice(&format!("self-check failed: {x}"));
        }
        v
    }

    // ----- request handling --------------------------------------------------------------

    /// Handles one request end to end and returns the `Response` to send.
    pub async fn handle(&self, req: pb::Request, mut ctx: Ctx) -> pb::Response {
        let started = Instant::now();
        let request_id = req.request_id;
        let Some(cmd) = req.command.as_ref() else {
            return error_response(request_id, &CmdError::invalid("request: no command set"));
        };
        let info = command_info(cmd);
        let desktop = auth::desktop_of(cmd).map(str::to_string);
        let result = self.admit_and_run(&req, cmd, &mut ctx).await;
        let refusal = result.as_ref().err().is_some_and(|e| {
            matches!(
                e.code,
                ErrorCode::PermissionDenied
                    | ErrorCode::InvalidArgument
                    | ErrorCode::ResourceExhausted
                    | ErrorCode::FailedPrecondition
            )
        });
        // A Gateway that keeps provoking refusals must not be able to grow the audit log or the
        // journal at will: at most 5 refusal lines a second, the rest are counted and summarised.
        if self.audit_slot(ctx.role, refusal) {
            let outcome = audit::outcome_name(result.as_ref().err().map(|e| e.code));
            self.audit.append(&audit::request_line(
                self.now(),
                &RequestRecord {
                    request_id,
                    role: ctx.role,
                    peer_uid: ctx.peer.uid,
                    peer_pid: ctx.peer.pid,
                    command: info.name,
                    desktop_id: desktop.as_deref(),
                    outcome,
                    duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                },
            ));
        }
        match result {
            Ok(r) => pb::Response {
                request_id,
                result: Some(r),
            },
            Err(e) => {
                if refusal && self.last_refusal_logged(ctx.role) {
                    // Refusals are visible at warning level: a compromised gatewayd probing the
                    // command set must show up (ipc.md 8).
                    log::warn(&format!(
                        "{} refused for {}: {:?}: {}",
                        info.name,
                        audit::role_name(ctx.role),
                        e.code,
                        e.message
                    ));
                }
                error_response(request_id, &e)
            }
        }
    }

    /// Whether a request's audit line is written. Only refusals of a Gateway are limited (5 a
    /// second); when a line is written after some were suppressed, a notice says how many.
    fn audit_slot(&self, role: Role, refusal: bool) -> bool {
        if role != Role::Gateway || !refusal {
            return true;
        }
        if lock(&self.limiter).admit("audit:refusal", 1000, 5).is_err() {
            self.suppressed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return false;
        }
        let n = self
            .suppressed
            .swap(0, std::sync::atomic::Ordering::Relaxed);
        if n > 0 {
            self.audit_notice(&format!("{n} refusals suppressed"));
        }
        true
    }

    /// Same limit for the warning line on stderr (shares the bucket's verdict loosely: it only
    /// logs when the refusal bucket still has room).
    fn last_refusal_logged(&self, role: Role) -> bool {
        role != Role::Gateway || lock(&self.limiter).admit("log:refusal", 1000, 5).is_ok()
    }

    /// Admission of an invalid request from a connection (the server's reject path): a Gateway
    /// gets 20 a second, the excess is answered `RESOURCE_EXHAUSTED` and not audited.
    pub fn admit_reject(&self, role: Role) -> bool {
        if role != Role::Gateway {
            return true;
        }
        let ok = lock(&self.limiter)
            .admit("gateway:reject", 1000, 20)
            .is_ok();
        if !ok {
            self.suppressed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        ok
    }

    /// The accept-time check for a Gateway peer (ipc.md 3): refuse a process that holds one of the
    /// forbidden groups, as the kernel recorded them at `connect` (`SO_PEERGROUPS`), whatever the
    /// account files say. Fails closed: groups that cannot be read refuse the connection.
    pub fn check_gateway_peer(
        &self,
        stream: impl std::os::fd::AsFd,
        primary_gid: u32,
    ) -> Result<(), String> {
        let text = std::fs::read_to_string(&self.cfg.group_file)
            .map_err(|e| format!("cannot read the group file: {e}"))?;
        let forbidden = identity::forbidden_gids(&identity::parse_group(&text));
        let groups = super::peergroups::peer_groups(stream)
            .map_err(|e| format!("cannot read the peer's groups: {e}"))?;
        match super::peergroups::forbidden_peer_group(&groups, primary_gid, &forbidden) {
            Some(g) => Err(format!("the peer holds the forbidden group {g}")),
            None => Ok(()),
        }
    }

    /// Reopens the audit file (SIGHUP, after `logrotate`).
    pub fn reopen_audit(&self) {
        self.audit.reopen();
    }

    async fn admit_and_run(
        &self,
        req: &pb::Request,
        cmd: &Command,
        ctx: &mut Ctx,
    ) -> Result<Reply, CmdError> {
        let info = command_info(cmd);
        // Reads cost host work (Incus calls, forks): a Gateway gets 20 a second.
        if ctx.role == Role::Gateway && info.class == hx_ipc::privd::CommandClass::R {
            lock(&self.limiter)
                .admit("gateway:read", 1000, 20)
                .map_err(|ms| CmdError::exhausted("too many read requests per second", ms))?;
        }
        let phase = self.phase();
        auth::authorize(ctx.role, req, phase)?;
        // Sealed secrets need HPKE (Phase 2). A slot marked sealed must never be used as if it
        // were the plain value: refuse it.
        if req.secret_slots.iter().any(|s| s.sealed) {
            return Err(CmdError::unimplemented(
                "sealed secrets are not available in this release",
            ));
        }
        if info.reserved {
            return Err(CmdError::unimplemented(format!(
                "{} is reserved and not available in this release",
                info.name
            )));
        }
        self.admit_rate(ctx.role, cmd)?;
        self.execute(cmd, ctx).await
    }

    /// Rate-limit admission (ipc.md 8). A refused request consumes nothing.
    fn admit_rate(&self, role: Role, cmd: &Command) -> Result<(), CmdError> {
        let name = command_info(cmd).name;
        let role_name = audit::role_name(role);
        let mut l = lock(&self.limiter);
        if role == Role::Gateway && auth::counts_as_mutating(cmd) {
            l.admit(
                &format!("{role_name}:mutating"),
                60_000,
                auth::MUTATING_PER_MINUTE,
            )
            .map_err(|ms| CmdError::exhausted("too many commands per minute", ms))?;
        }
        if let Some(rule) = auth::rate_rule(cmd) {
            let key = if rule.per_desktop {
                format!(
                    "{role_name}:{name}:{}",
                    auth::desktop_of(cmd).unwrap_or_default()
                )
            } else {
                format!("{role_name}:{name}")
            };
            l.admit(&key, rule.window_ms, rule.max)
                .map_err(|ms| CmdError::exhausted(format!("{name} is rate limited"), ms))?;
        }
        Ok(())
    }

    async fn execute(&self, cmd: &Command, ctx: &mut Ctx) -> Result<Reply, CmdError> {
        use cmd::*;
        match cmd.clone() {
            Command::GetHostInfo(_) => info::get_host_info(self).await,
            Command::GetRecipientKey(_) => info::get_recipient_key(self).await,
            Command::BeginSetup(r) => setup::begin(self, ctx, r),
            Command::ExtendSetup(r) => setup::extend(self, r),
            Command::FinishSetup(r) => setup::finish(self, ctx, r).await,
            Command::SetupHost(r) => hostsetup::setup_host(self, ctx, r).await,
            Command::CreateDesktop(r) => create::create_desktop(self, ctx, r).await,
            Command::GetDesktop(r) => desktop::get_desktop(self, r).await,
            Command::ListDesktops(_) => desktop::list_desktops(self).await,
            Command::StartDesktop(r) => power::start(self, ctx, r).await,
            Command::StopDesktop(r) => power::stop(self, ctx, r).await,
            Command::RestartDesktop(r) => power::restart(self, ctx, r).await,
            Command::SetLimits(r) => limits::set_limits(self, ctx, r).await,
            Command::SetUserPassword(r) => password::set_user_password(self, ctx, r).await,
            Command::EnableDocker(r) => docker::enable(self, ctx, r).await,
            Command::DisableDocker(r) => docker::disable(self, ctx, r).await,
            Command::CreateSnapshot(r) => snapshot::create(self, ctx, r).await,
            Command::ListSnapshots(r) => snapshot::list(self, r).await,
            Command::DeleteSnapshot(r) => snapshot::delete(self, ctx, r).await,
            Command::ProvisionSessionLink(r) => session::provision_link(self, ctx, r).await,
            Command::InstallSession(r) => session::install(self, ctx, r).await,
            Command::RestartSession(r) => session::restart(self, ctx, r).await,
            Command::CheckUpdate(_) | Command::ApplyUpdate(_) | Command::RollbackUpdate(_) => Err(
                CmdError::unimplemented("self-update is not available in this release"),
            ),
            Command::DestroyDesktop(r) => desktop::destroy_desktop(self, ctx, r).await,
            Command::Uninstall(_) => Err(CmdError::unimplemented(
                "uninstall is not available in this release",
            )),
            Command::ResetLockout(r) => admin::reset_lockout(self, ctx, r),
            Command::EnrolOwnerKey(r) => admin::enrol_owner_key(self, r),
            Command::PepperVerify(r) => pepper_cmds::verify(self, ctx, r).await,
            Command::PepperEnrol(r) => pepper_cmds::enrol(self, ctx, r).await,
            Command::RecordEvent(r) => admin::record_event(self, ctx, r),
            // UpgradeIncus and the reserved Phase 2 commands never get here (`reserved`), but the
            // match stays total.
            _ => Err(CmdError::unimplemented("reserved command")),
        }
    }

    /// Records the attention flag and the audit notice after a purpose got locked.
    pub(crate) fn after_lock(&self, purpose: Purpose) {
        let flag = match purpose {
            Purpose::Pin => Flag::PinLocked,
            Purpose::Password => Flag::PasswordLocked,
        };
        self.set_flag(None, flag, true);
        self.audit_notice(&format!("{} purpose locked", purpose.label()));
    }

    /// Charges one failed verification to `purpose` (shared by `PepperVerify` and the
    /// current-password check). Returns whether this failure locked the purpose.
    pub(crate) fn charge_failure(&self, purpose: Purpose) -> bool {
        // If the charge cannot be saved it stays in memory and the limiter refuses everything that
        // depends on it until a save works (see `limiter::Unsaved`).
        let newly = lock(&self.limiter).record_failure(purpose).unwrap_or(false);
        if newly {
            self.after_lock(purpose);
        }
        newly
    }
}

/// The desktop as loaded from Incus.
pub struct LoadedDesktop {
    /// Instance name.
    pub name: String,
    /// The Incus instance.
    pub instance: Instance,
    /// Metadata from the `user.hx.*` keys.
    pub meta: DesktopMeta,
}

/// The `user.hx.*` metadata of a desktop (ipc.md 2: privd reads the username and recipe from
/// here and never trusts the caller to repeat them).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DesktopMeta {
    /// `creating`, `ready` or `failed`.
    pub state: String,
    /// The desktop user's name.
    pub username: String,
    /// Recipe id text, `ubuntu-24.04-xfce-basic`.
    pub recipe: String,
    /// Creation time, Unix seconds.
    pub created: u64,
    /// Time the Docker isolation warning was acknowledged, Unix seconds.
    pub docker_ack: Option<u64>,
}

impl DesktopMeta {
    /// Reads the keys from an instance.
    pub fn from_config(i: &Instance) -> Self {
        let get = |k: &str| {
            i.config
                .get(&format!("user.hx.{k}"))
                .cloned()
                .unwrap_or_default()
        };
        Self {
            state: get("state"),
            username: get("username"),
            recipe: get("recipe"),
            created: get("created").parse().unwrap_or(0),
            docker_ack: get("docker_ack").parse().ok(),
        }
    }
}

/// An error as a `Response`.
pub fn error_response(request_id: u64, e: &CmdError) -> pb::Response {
    pb::Response {
        request_id,
        result: Some(response::Result::Error(e.to_pb())),
    }
}
