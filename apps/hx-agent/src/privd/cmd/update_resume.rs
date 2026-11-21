//! What happens after `ApplyUpdate` has answered: the restarts, and, in the **new** privd
//! process, the health check and the automatic rollback (ipc.md 6.12).
//!
//! `ApplyUpdate` records a `pending` update in `updates-state` before it switches `current`. The
//! old process then restarts gatewayd and re-execs itself (`systemctl restart`, the socket unit
//! keeps the socket). The process that starts next reads `pending` in `serve` and runs
//! [`Daemon::resume_update`]: the health check, then either confirmation or rollback. Because the
//! judge is the new process, "privd answers on its socket after the re-exec" is a real test of
//! the new binary.
//!
//! A new privd that crashes in a loop is counted (`pending.attempts`, one per start) and rolled
//! back after the third start; one that cannot start at all is not seen by this code (see the
//! README's "Self-update" notes for the safety net the installer provides).

use std::time::Duration;

use hx_ipc::text::sanitize_text;
use hx_provision::incus::Transport;

use crate::privd::cancel::{CancelToken, LOCK_WAIT, LockKey};
use crate::privd::daemon::Daemon;
use crate::privd::log;
use crate::privd::state::Flag;
use crate::privd::update::health;
use crate::privd::update::state::{RolledBack, UpdateState};
use crate::privd::update::switch::Layout;
use crate::privd::update::system::Unit;

/// A privd that starts this many times with the same pending update, without it becoming healthy,
/// rolls it back.
pub const MAX_ATTEMPTS: u32 = 3;

/// After the response to `ApplyUpdate` or `RollbackUpdate` has been sent, restarts gatewayd and
/// then privd itself. If privd cannot be restarted and `rollback_if_stuck` is set, the update is
/// rolled back at once (the old process is still the one running).
pub(crate) fn schedule_restarts<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    rollback_if_stuck: bool,
) {
    let deps = d.update_deps();
    let grace = d.cfg.update.restart_grace;
    let me = d.me.clone();
    tokio::spawn(async move {
        tokio::time::sleep(grace).await;
        if let Err(e) = deps.systemd.restart(Unit::Gatewayd).await {
            // The new privd's health check will see gatewayd not running and roll back.
            log::error(&format!("update: {e}"));
        }
        if let Err(e) = deps.systemd.restart(Unit::Privd).await {
            log::error(&format!("update: {e}"));
            if rollback_if_stuck && let Some(d) = me.upgrade() {
                let cancel = CancelToken::new();
                let _g = d
                    .locks
                    .acquire(LockKey::Host, &cancel, LOCK_WAIT)
                    .await
                    .ok();
                d.rollback_now("privd could not be re-executed").await;
            }
        }
    });
}

impl<T: Transport + Clone + 'static> Daemon<T> {
    /// At start: if an update was switched in by the previous process, judge it. Does nothing
    /// when none is pending.
    pub async fn resume_update(&self) {
        let deps = self.update_deps();
        let u = &self.cfg.update;
        let cancel = CancelToken::new();
        // The host refresh at start may hold the lock for up to 120 s; the update must still be
        // judged, so wait through that and the health window, not the usual 10 s. If the lock
        // truly cannot be had, roll back rather than leave `pending` set for ever.
        let wait = Duration::from_secs(150) + u.health.window;
        let Ok(_g) = self.locks.acquire(LockKey::Host, &cancel, wait).await else {
            log::error("update: could not take the host lock to judge the update");
            self.rollback_now("the update could not be judged (the host lock was never free)")
                .await;
            return;
        };
        let mut st = match UpdateState::load(&self.store) {
            Ok(s) => s,
            Err(e) => {
                log::error(&format!("updates-state: {e}"));
                return;
            }
        };
        let Some(mut p) = st.pending.clone() else {
            return;
        };
        p.attempts += 1;
        st.pending = Some(p.clone());
        if let Err(e) = st.save(&self.store) {
            log::error(&format!("updates-state: {e}"));
        }
        self.audit_notice(&format!(
            "update {} resumed after the re-exec (start {})",
            p.version, p.attempts
        ));
        if p.attempts > MAX_ATTEMPTS {
            self.rollback_now("privd restarted repeatedly without the update becoming healthy")
                .await;
            return;
        }
        if u.running_version != p.version {
            self.rollback_now(&format!(
                "privd is running version {}, the update expected {}",
                u.running_version, p.version
            ))
            .await;
            return;
        }
        // The window counts from the switch; a slow restart leaves at least enough time to
        // observe a stable gatewayd.
        let used = Duration::from_secs(self.now().saturating_sub(p.started_unix));
        let floor = u.health.stable + u.health.poll * 3;
        let budget = u.health.window.saturating_sub(used).max(floor);
        let expect = health::Expect {
            version: &p.version,
            old_gateway_pid: p.gateway_pid,
        };
        match health::check(&deps, &u.health, budget, &expect).await {
            Ok(()) => self.confirm_update(&p.version),
            Err(reason) => {
                self.rollback_now(&reason).await;
            }
        }
    }

    fn confirm_update(&self, version: &str) {
        let layout = Layout::new(&self.cfg.update.versions_dir);
        // An unreadable updates-state is never replaced by defaults: that would reset the
        // freshness counters. Leave it alone and say so.
        let mut st = match UpdateState::load(&self.store) {
            Ok(s) => s,
            Err(e) => {
                log::error(&format!("updates-state: {e}; leaving it untouched"));
                self.audit_notice("update confirmation skipped: updates-state is unreadable");
                return;
            }
        };
        st.pending = None;
        st.rolled_back = None;
        if let Err(e) = st.save(&self.store) {
            log::error(&format!("updates-state: {e}"));
        }
        self.set_flag(None, Flag::UpdateRolledBack, false);
        // Two versions are kept: the new one and the one before it.
        let current = layout.current().ok().flatten();
        let previous = layout.previous().ok().flatten();
        let keep: Vec<&str> = [current.as_deref(), previous.as_deref()]
            .into_iter()
            .flatten()
            .collect();
        if let Err(e) = layout.prune(&keep) {
            log::warn(&format!("update: pruning old versions failed: {e}"));
        }
        self.audit_notice(&format!("update {version} is healthy"));
        // ipc.md 3: the account-policy self-checks re-run after every update.
        let _ = self.run_self_checks();
    }

    /// Restores the version the pending update recorded as its predecessor, records why, and
    /// restarts both units. Returns whether a version was restored. Idempotent: if `current`
    /// already is that version (the update was never switched in, or a crash interrupted an
    /// earlier rollback) only the bookkeeping is done; `current` is never moved to anything older.
    /// The caller holds the host lock (or is the only user of the files).
    pub(crate) async fn rollback_now(&self, reason: &str) -> bool {
        let deps = self.update_deps();
        let layout = Layout::new(&self.cfg.update.versions_dir);
        let reason = sanitize_text(reason, 200);
        let mut st = match UpdateState::load(&self.store) {
            Ok(s) => s,
            Err(e) => {
                log::error(&format!("updates-state: {e}; the rollback cannot proceed"));
                self.audit_notice("update rollback refused: updates-state is unreadable");
                return false;
            }
        };
        let Some(p) = st.pending.clone() else {
            return false;
        };
        let restored = match &p.previous {
            Some(to) => layout.restore(to, &p.version),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "the update recorded no previous version",
            )),
        };
        match &restored {
            Ok(_) => self.audit_notice(&format!(
                "needs_attention=UPDATE_ROLLED_BACK: {} rolled back to {}: {reason}",
                p.version,
                p.previous.as_deref().unwrap_or("?")
            )),
            Err(e) => {
                log::error(&format!("update: the rollback could not restore: {e}"));
                self.audit_notice(&format!(
                    "needs_attention=UPDATE_ROLLED_BACK: rollback of {} failed: {reason}",
                    p.version
                ));
            }
        }
        st.pending = None;
        st.rolled_back = Some(RolledBack {
            version: p.version,
            reason,
            at: self.now(),
        });
        if let Err(e) = st.save(&self.store) {
            log::error(&format!("updates-state: {e}"));
        }
        self.set_flag(None, Flag::UpdateRolledBack, true);
        if restored.is_ok() {
            if let Err(e) = deps.systemd.restart(Unit::Gatewayd).await {
                log::error(&format!("update: {e}"));
            }
            if let Err(e) = deps.systemd.restart(Unit::Privd).await {
                log::error(&format!("update: {e}"));
            }
        }
        restored.is_ok()
    }
}
