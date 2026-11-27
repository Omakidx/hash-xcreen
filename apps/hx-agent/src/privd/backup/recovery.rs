//! Crash recovery and the cleanup before `DestroyDesktop` and `Uninstall` (ipc.md section 35).
//!
//! **At privd start, before any backup command is admitted**, [`recover_all`]:
//!
//! 1. force-deletes every instance marked as a backup helper (`user.hx.kind=backup-worker`, an
//!    `hx-bkw-<8 hex>` name and a `user.hx.job` whose first 8 digits match the name);
//! 2. removes every `*.sock` in the run directory;
//! 3. deletes every `hx-backup-*` snapshot of the desktops privd manages;
//! 4. keeps an `hx-restore-*` target (an instance marked `user.hx.kind=restore-target`; one
//!    without that marker is never touched) only if a record says that the restore can resume,
//!    and deletes it otherwise;
//! 5. stops `hx-drive.service`;
//! 6. clears the job records: `job.json` is removed once the objects it names are gone, and a
//!    kept target is recorded in `resume.json`.
//!
//! Every step is idempotent and independent: a step that fails is audited and the others still
//! run, and the report says whether every listing succeeded (`complete`), because a recovery that
//! could not look must be repeated before jobs are admitted.
//!
//! [`recover_desktop`] is the same cleanup for the objects one `job.json` names (a job whose
//! cleanup failed leaves its record behind; the next admission for that desktop runs it first),
//! and [`teardown_cleanup`] is steps 1 and 4 plus the sockets and the records, for
//! `DestroyDesktop` and `Uninstall`: there every restore target goes, resumable or not.

use std::collections::BTreeSet;
use std::path::Path;

use hx_provision::incus::{HelperName, JobId, RestoreTargetName};

use super::host::BackupHost;
use super::slot::{BackupDirs, JobRecord, RecordError, ResumeRecord, remove_record};
use super::{BackupConfig, BackupEnv};
use crate::privd::cmd::uninstall::unlink_beneath;

/// What a recovery run did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Helpers force-deleted.
    pub helpers_deleted: Vec<String>,
    /// Socket files removed.
    pub sockets_removed: Vec<String>,
    /// `hx-backup-*` snapshots deleted (`desktop/snapshot`).
    pub snapshots_deleted: Vec<String>,
    /// Restore targets deleted.
    pub targets_deleted: Vec<String>,
    /// Restore targets kept because a record says they can resume.
    pub targets_kept: Vec<String>,
    /// Whether `hx-drive.service` was stopped.
    pub drive_stopped: bool,
    /// Job records cleared.
    pub records_cleared: Vec<String>,
    /// What failed (privd's own texts).
    pub failures: Vec<String>,
    /// Whether every listing succeeded and every record could be read: only then is the host
    /// known to be clean.
    pub complete: bool,
}

/// The collaborators of a recovery.
pub struct Recovery<'a, H: BackupHost, E: BackupEnv> {
    /// Incus and systemd.
    pub host: &'a H,
    /// Audit and the registry.
    pub env: &'a E,
    /// Paths.
    pub cfg: &'a BackupConfig,
    /// The records.
    pub dirs: &'a BackupDirs,
}

fn is_sock_name(name: &str) -> bool {
    name.ends_with(".sock") && !name.contains('/') && name.len() > 5
}

impl<H: BackupHost, E: BackupEnv> Recovery<'_, H, E> {
    fn fail(&self, rep: &mut RecoveryReport, what: String) {
        self.env.audit(&format!("backup recovery: {what}"));
        rep.failures.push(what);
        rep.complete = false;
    }

    /// A failure that does not make the run incomplete: a record that does not parse is left
    /// for an administrator and refuses jobs of its desktop (at admission), but it does not keep
    /// every other desktop from running jobs.
    fn note(&self, rep: &mut RecoveryReport, what: String) {
        self.env.audit(&format!("backup recovery: {what}"));
        rep.failures.push(what);
    }

    /// Removes `*.sock` from the run directory (a missing directory is fine).
    fn remove_sockets(&self, rep: &mut RecoveryReport) {
        let rd = match std::fs::read_dir(&self.cfg.run_dir) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                self.fail(rep, format!("cannot list the run directory: {e}"));
                return;
            }
        };
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !is_sock_name(&name) {
                continue;
            }
            match unlink_beneath(&self.cfg.run_dir.join(&name)) {
                Ok(true) => rep.sockets_removed.push(name),
                Ok(false) => {}
                Err(e) => self.fail(rep, format!("cannot remove a socket: {e}")),
            }
        }
    }

    /// Every record of every registered desktop that says a restore target can resume.
    fn resumable_targets(&self, rep: &mut RecoveryReport) -> BTreeSet<String> {
        let mut keep = BTreeSet::new();
        for id in self.env.desktops() {
            if let Ok(p) = self.dirs.job_path(&id) {
                match JobRecord::load(&p) {
                    Ok(Some(r)) if r.resumable => keep.extend(r.target),
                    Ok(_) => {}
                    Err(RecordError::Corrupt(_)) => {
                        self.note(rep, format!("{id}: job.json is corrupt"))
                    }
                    Err(e) => self.fail(rep, format!("{id}: {e}")),
                }
            }
            if let Ok(p) = self.dirs.resume_path(&id) {
                match ResumeRecord::load(&p) {
                    Ok(Some(r)) => {
                        keep.insert(r.target);
                    }
                    Ok(None) => {}
                    Err(RecordError::Corrupt(_)) => {
                        self.note(rep, format!("{id}: resume.json is corrupt"))
                    }
                    Err(e) => self.fail(rep, format!("{id}: {e}")),
                }
            }
        }
        keep
    }

    /// Steps 1 to 6 for the whole host.
    pub async fn recover_all(&self) -> RecoveryReport {
        let mut rep = RecoveryReport {
            complete: true,
            ..RecoveryReport::default()
        };
        // 1. helpers
        match self.host.list_helpers().await {
            Ok(list) => {
                for h in list {
                    match self.host.force_delete_helper(h.job).await {
                        Ok(_) => rep.helpers_deleted.push(h.name.to_string()),
                        Err(e) => {
                            self.fail(&mut rep, format!("cannot delete helper {}: {e}", h.name))
                        }
                    }
                }
            }
            Err(e) => self.fail(&mut rep, format!("cannot list the helpers: {e}")),
        }
        // 2. sockets
        self.remove_sockets(&mut rep);
        // 3. snapshots
        for id in self.env.desktops() {
            let instance = format!("{}{id}", self.cfg.instance_prefix);
            match self.host.list_backup_snapshots(&instance).await {
                Ok(names) => {
                    for n in names {
                        match self.host.delete_snapshot(&instance, &n).await {
                            Ok(()) => rep.snapshots_deleted.push(format!("{id}/{n}")),
                            Err(e) => {
                                self.fail(&mut rep, format!("cannot delete snapshot {n}: {e}"))
                            }
                        }
                    }
                }
                Err(e) => self.fail(&mut rep, format!("cannot list snapshots of {id}: {e}")),
            }
        }
        // 4. restore targets
        let keep = self.resumable_targets(&mut rep);
        match self.host.list_restore_targets().await {
            Ok(list) => {
                for t in list {
                    if keep.contains(t.name.as_str()) {
                        rep.targets_kept.push(t.name.to_string());
                        continue;
                    }
                    match self.host.delete_restore_target(&t.name, t.job).await {
                        Ok(_) => rep.targets_deleted.push(t.name.to_string()),
                        Err(e) => {
                            self.fail(&mut rep, format!("cannot delete target {}: {e}", t.name));
                        }
                    }
                }
            }
            Err(e) => self.fail(&mut rep, format!("cannot list the restore targets: {e}")),
        }
        // 5. the Drive helper
        match self.host.stop_drive_service().await {
            Ok(()) => rep.drive_stopped = true,
            Err(e) => self.fail(&mut rep, format!("cannot stop the Drive helper: {e}")),
        }
        // 6. the records
        for id in self.env.desktops() {
            self.clear_records(&id, &rep.targets_kept.clone(), &mut rep);
        }
        let summary = format!(
            "backup recovery: {} helper(s), {} socket(s), {} snapshot(s), {} target(s) deleted, {} kept, {} record(s) cleared, {} failure(s)",
            rep.helpers_deleted.len(),
            rep.sockets_removed.len(),
            rep.snapshots_deleted.len(),
            rep.targets_deleted.len(),
            rep.targets_kept.len(),
            rep.records_cleared.len(),
            rep.failures.len()
        );
        self.env.audit(&summary);
        rep
    }

    /// Step 6 for one desktop: the job record is removed (a kept target moves to `resume.json`
    /// first), and a `resume.json` that names no kept target is removed.
    fn clear_records(&self, id: &str, kept: &[String], rep: &mut RecoveryReport) {
        let (Ok(jp), Ok(rp)) = (self.dirs.job_path(id), self.dirs.resume_path(id)) else {
            return;
        };
        match JobRecord::load(&jp) {
            Ok(Some(r)) => {
                let kept_target = r
                    .target
                    .as_deref()
                    .filter(|t| r.resumable && kept.iter().any(|k| k == t));
                if let (Some(t), Some(job)) = (kept_target, r.job())
                    && let Ok(name) = RestoreTargetName::new(t)
                    && let Err(e) = ResumeRecord::new(job, &name).store(&rp)
                {
                    self.fail(rep, format!("{id}: cannot write resume.json: {e}"));
                    return;
                }
                match remove_record(&jp) {
                    Ok(()) => rep.records_cleared.push(id.to_string()),
                    Err(e) => self.fail(rep, format!("{id}: cannot remove job.json: {e}")),
                }
            }
            Ok(None) => {}
            // Left for an administrator: the objects it can name were removed by their markers.
            Err(RecordError::Corrupt(what)) => {
                self.note(rep, format!("{id}: {what} is corrupt and was left alone"));
            }
            Err(e) => self.fail(rep, format!("{id}: {e}")),
        }
        if let Ok(Some(r)) = ResumeRecord::load(&rp)
            && !kept.iter().any(|k| *k == r.target)
        {
            let _ = remove_record(&rp);
        }
    }

    /// The cleanup of one leftover job record: the helper, the socket, the snapshot and the
    /// target it names. Returns whether everything it names is gone.
    pub async fn recover_desktop(&self, desktop: &str) -> RecoveryReport {
        let mut rep = RecoveryReport {
            complete: true,
            ..RecoveryReport::default()
        };
        let Ok(jp) = self.dirs.job_path(desktop) else {
            return rep;
        };
        let record = match JobRecord::load(&jp) {
            Ok(Some(r)) => r,
            Ok(None) => return rep,
            Err(e) => {
                self.fail(&mut rep, format!("{desktop}: {e}"));
                return rep;
            }
        };
        if let Some(job) = record.job() {
            match self.host.force_delete_helper(job).await {
                Ok(true) => rep.helpers_deleted.push(record.helper.clone()),
                Ok(false) => {}
                Err(e) => self.fail(
                    &mut rep,
                    format!("cannot delete helper {}: {e}", record.helper),
                ),
            }
            let sock = self.cfg.run_dir.join(format!("{}.sock", job.hex()));
            match unlink_beneath(&sock) {
                Ok(true) => rep.sockets_removed.push(format!("{}.sock", job.hex())),
                Ok(false) => {}
                Err(e) => self.fail(&mut rep, format!("cannot remove a socket: {e}")),
            }
        }
        let instance = format!("{}{desktop}", self.cfg.instance_prefix);
        if let Some(s) = &record.snapshot {
            match self.host.delete_snapshot(&instance, s).await {
                Ok(()) => rep.snapshots_deleted.push(format!("{desktop}/{s}")),
                Err(e) => self.fail(&mut rep, format!("cannot delete snapshot {s}: {e}")),
            }
        }
        let mut kept = Vec::new();
        if let Some(t) = &record.target
            && let Ok(name) = RestoreTargetName::new(t)
        {
            if record.resumable {
                kept.push(t.clone());
                rep.targets_kept.push(t.clone());
            } else {
                match self.host.delete_restore_target(&name, record.job()).await {
                    Ok(_) => rep.targets_deleted.push(t.clone()),
                    Err(e) => self.fail(&mut rep, format!("cannot delete target {t}: {e}")),
                }
            }
        }
        if rep.complete {
            self.clear_records(desktop, &kept, &mut rep);
        }
        self.env.audit(&format!(
            "backup recovery of {desktop}: {} failure(s)",
            rep.failures.len()
        ));
        rep
    }

    /// Steps 1 and 4 for `DestroyDesktop` and `Uninstall`, and the sockets and records of the
    /// desktops in `desktops`. Every restore target goes, resumable or not.
    pub async fn teardown(&self, desktops: &[String]) -> RecoveryReport {
        let mut rep = RecoveryReport {
            complete: true,
            ..RecoveryReport::default()
        };
        match self.host.list_helpers().await {
            Ok(list) => {
                for h in list {
                    match self.host.force_delete_helper(h.job).await {
                        Ok(_) => rep.helpers_deleted.push(h.name.to_string()),
                        Err(e) => {
                            self.fail(&mut rep, format!("cannot delete helper {}: {e}", h.name))
                        }
                    }
                }
            }
            Err(e) => self.fail(&mut rep, format!("cannot list the helpers: {e}")),
        }
        self.remove_sockets(&mut rep);
        match self.host.list_restore_targets().await {
            Ok(list) => {
                for t in list {
                    match self.host.delete_restore_target(&t.name, t.job).await {
                        Ok(_) => rep.targets_deleted.push(t.name.to_string()),
                        Err(e) => {
                            self.fail(&mut rep, format!("cannot delete target {}: {e}", t.name));
                        }
                    }
                }
            }
            Err(e) => self.fail(&mut rep, format!("cannot list the restore targets: {e}")),
        }
        if rep.complete {
            for id in desktops {
                for p in [self.dirs.job_path(id), self.dirs.resume_path(id)]
                    .into_iter()
                    .flatten()
                {
                    if let Err(e) = remove_record(&p) {
                        self.fail(&mut rep, format!("{id}: cannot remove a record: {e}"));
                    } else {
                        rep.records_cleared.push(id.clone());
                    }
                }
            }
        }
        self.env.audit(&format!(
            "backup teardown: {} helper(s), {} target(s) deleted, {} failure(s)",
            rep.helpers_deleted.len(),
            rep.targets_deleted.len(),
            rep.failures.len()
        ));
        rep
    }
}

/// Whether the run directory is what ipc.md section 24 requires: a directory (not a link), mode
/// 0700, owned by `owner` when given. A job is refused otherwise.
pub fn check_run_dir(dir: &Path, owner: Option<u32>) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let m = std::fs::symlink_metadata(dir).map_err(|e| format!("the run directory: {e}"))?;
    if !m.is_dir() {
        return Err("the run directory is not a directory".into());
    }
    if m.permissions().mode() & 0o777 != 0o700 {
        return Err("the run directory is not mode 0700".into());
    }
    if owner.is_some_and(|o| m.uid() != o) {
        return Err("the run directory has the wrong owner".into());
    }
    Ok(())
}

/// The helper name of a job record, for tests and audit lines.
pub fn helper_of(job: JobId) -> HelperName {
    job.helper_name()
}
