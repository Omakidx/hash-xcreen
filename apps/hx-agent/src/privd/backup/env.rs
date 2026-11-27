//! The daemon behind the runner: [`DaemonEnv`] implements [`BackupEnv`] for a [`Daemon`], and
//! `Daemon::recover_backups` and `Daemon::backup_teardown` are the two calls the rest of privd
//! makes (start-up, `DestroyDesktop` and `Uninstall`).

use std::sync::{Arc, Weak};

use hx_ipc::privd::pb::Role;
use hx_provision::incus::Transport;

use super::host::IncusHost;
use super::runner::JobRunner;
use super::{Alert, AlertKind, BackupEnv, BoxFuture, LockGuard};
use crate::privd::cancel::CancelToken;
use crate::privd::daemon::{Ctx, Daemon};
use crate::privd::log;
use crate::privd::state::Flag;

/// The runner's view of the daemon. It holds the daemon weakly, so the runner (which the daemon
/// owns) makes no cycle; a daemon that is gone answers with the safe defaults.
pub struct DaemonEnv<T: Transport + Clone + 'static> {
    daemon: Weak<Daemon<T>>,
}

impl<T: Transport + Clone + 'static> DaemonEnv<T> {
    /// An env for `daemon`.
    pub fn new(daemon: Weak<Daemon<T>>) -> Self {
        Self { daemon }
    }
}

impl<T: Transport + Clone + 'static> BackupEnv for DaemonEnv<T> {
    fn now_unix(&self) -> u64 {
        self.daemon.upgrade().map_or(0, |d| d.now())
    }

    fn audit(&self, text: &str) {
        if let Some(d) = self.daemon.upgrade() {
            d.audit_notice(text);
        }
    }

    fn set_flag(&self, desktop: Option<&str>, flag: Flag, on: bool) {
        if let Some(d) = self.daemon.upgrade() {
            d.set_flag(desktop, flag, on);
        }
    }

    fn flags_for(&self, desktop: &str) -> Vec<Flag> {
        self.daemon
            .upgrade()
            .map(|d| d.flags_for(desktop))
            .unwrap_or_default()
    }

    fn desktop_known(&self, desktop: &str) -> bool {
        self.daemon
            .upgrade()
            .is_some_and(|d| d.read_state(|s| s.desktops.contains_key(desktop)))
    }

    fn desktops(&self) -> Vec<String> {
        self.daemon
            .upgrade()
            .map(|d| d.read_state(|s| s.desktops.keys().cloned().collect()))
            .unwrap_or_default()
    }

    fn uninstalling(&self) -> bool {
        self.daemon.upgrade().is_none_or(|d| d.uninstalling())
    }

    fn alert(&self, alert: &Alert) {
        let what = match alert.kind {
            AlertKind::Integrity => "integrity",
        };
        // The hook of 2B (ntfy, webhooks) replaces this line; until then the owner finds it in
        // the audit log and the journal.
        let line = format!(
            "alert: {what} desktop={} job={}",
            alert.desktop_id, alert.job_id
        );
        log::error(&line);
        self.audit(&line);
    }

    fn lock_desktop<'a>(
        &'a self,
        desktop: &'a str,
        cancel: &'a CancelToken,
    ) -> BoxFuture<'a, Result<LockGuard, String>> {
        Box::pin(async move {
            let d = self
                .daemon
                .upgrade()
                .ok_or_else(|| "privd is shutting down".to_string())?;
            let mut ctx = Ctx::new(Role::Admin);
            ctx.cancel = cancel.clone();
            d.lock_desktop(&ctx, desktop, false)
                .await
                .map(|g| Box::new(g) as LockGuard)
                .map_err(|e| e.message)
        })
    }
}

/// The runner a daemon owns.
pub type DaemonRunner<T> = JobRunner<IncusHost<T>, DaemonEnv<T>>;

impl<T: Transport + Clone + 'static> Daemon<T> {
    /// The backup job runner (the internal API that the commands of ipc.md section 6.14 will
    /// use; today they all answer `UNIMPLEMENTED`).
    pub fn backups(&self) -> &DaemonRunner<T> {
        &self.backup
    }

    /// Crash recovery of the backup runner (ipc.md section 35), repeated every 30 s until a run
    /// could look at everything. Backup jobs are refused until it has. Called once at start by
    /// `serve`.
    pub async fn recover_backups(self: &Arc<Self>) {
        loop {
            let rep = self.backup.recover().await;
            if rep.complete {
                return;
            }
            log::error("backup recovery is incomplete; it will be repeated in 30 s");
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    }

    /// What `DestroyDesktop` and `Uninstall` run before they touch the instance or the pool
    /// (ipc.md section 35): the active job is cancelled and awaited, then the helpers, restore
    /// targets, sockets and records of `desktops` are removed.
    pub async fn backup_teardown(&self, desktops: &[String], all: bool) {
        let rep = self.backup.teardown_cleanup(desktops, all).await;
        if !rep.complete {
            log::error("the backup cleanup before the teardown was incomplete");
        }
    }
}
