//! The progress mapping of ipc.md section 33: privd's fixed phase table, its own English step
//! texts, `percent` computed by privd, and at most 10 frames per second.
//!
//! The worker sends numbers only (`Progress` of `repo.proto`); nothing it sends can reach a step
//! text, because the text comes from [`step_text`] and nowhere else.

use hx_ipc::privd::pb as ppb;
use hx_ipc::repo::pb::{self, JobKind, ProgressPhase};

/// Frames per second at most.
pub const MAX_PER_SECOND: u64 = 10;

/// One frame privd reports (the `Progress` of ipc.md section 4, without its `request_id`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobProgress {
    /// `BACKUP` or `RESTORE`.
    pub stage: ppb::ProgressStage,
    /// Phase number, from 1.
    pub index: u32,
    /// Phases in the table of this kind of job.
    pub total: u32,
    /// privd's own text for the phase.
    pub step: &'static str,
    /// 0 to 100, or 255 when unknown.
    pub percent: u32,
    /// False only for a frame that reports a failure.
    pub ok: bool,
    /// The worker's byte count of the current phase.
    pub bytes_done: u64,
    /// The worker's byte total of the current phase (0 = unknown).
    pub bytes_total: u64,
    /// Object bytes privd relayed to or from the Drive helper in this job.
    pub transfer_bytes: u64,
}

impl JobProgress {
    /// The wire message for the request `request_id`.
    pub fn to_pb(&self, request_id: u64) -> ppb::Progress {
        ppb::Progress {
            request_id,
            stage: self.stage as i32,
            index: self.index,
            total: self.total,
            step: self.step.to_string(),
            percent: self.percent,
            ok: self.ok,
            bytes_done: self.bytes_done,
            bytes_total: self.bytes_total,
            transfer_bytes: self.transfer_bytes,
        }
    }
}

const BACKUP_STEPS: [&str; 6] = [
    "Taking a snapshot",
    "Starting the backup worker",
    "Repairing the index",
    "Scanning and uploading",
    "Writing the snapshot",
    "Cleaning up",
];

const RESTORE_STEPS: [&str; 5] = [
    "Preparing the restore target",
    "Planning the restore",
    "Downloading and writing files",
    "Fixing ownership and modes",
    "Checking that the desktop boots",
];

fn work_text(kind: JobKind) -> &'static str {
    match kind {
        JobKind::Init => "Creating the repository",
        JobKind::Keys => "Managing keys",
        JobKind::Snapshots => "Listing snapshots",
        JobKind::RestorePlan => "Planning the restore",
        JobKind::ForgetPrune => "Forgetting and pruning",
        JobKind::Check => "Checking the repository",
        _ => "Working",
    }
}

/// The stage and the number of phases of a job of `kind`.
pub fn table(kind: JobKind) -> (ppb::ProgressStage, u32) {
    match kind {
        JobKind::Backup => (ppb::ProgressStage::Backup, BACKUP_STEPS.len() as u32),
        JobKind::Restore => (ppb::ProgressStage::Restore, RESTORE_STEPS.len() as u32),
        _ => (ppb::ProgressStage::Backup, 3),
    }
}

/// The phase privd enters when the job is over and its objects are removed: Backup 6, the
/// repository-only kinds 3; a restore's table has none (its last phase belongs to 2C).
pub fn cleanup_index(kind: JobKind) -> Option<u32> {
    match kind {
        JobKind::Backup => Some(6),
        JobKind::Restore => None,
        _ => Some(3),
    }
}

/// privd's text for phase `index` (from 1) of a job of `kind`.
pub fn step_text(kind: JobKind, index: u32) -> &'static str {
    let i = (index.max(1) - 1) as usize;
    match kind {
        JobKind::Backup => BACKUP_STEPS.get(i).copied().unwrap_or(BACKUP_STEPS[5]),
        JobKind::Restore => RESTORE_STEPS.get(i).copied().unwrap_or(RESTORE_STEPS[4]),
        _ => match i {
            0 => "Starting the backup worker",
            1 => work_text(kind),
            _ => "Cleaning up",
        },
    }
}

/// The phase of privd's table that a worker phase belongs to, `None` for a phase the kind's
/// table does not have.
pub fn phase_index(kind: JobKind, phase: ProgressPhase) -> Option<u32> {
    use ProgressPhase as P;
    match kind {
        JobKind::Backup => match phase {
            P::RepairIndex => Some(3),
            P::ScanAndUpload => Some(4),
            P::WriteSnapshot => Some(5),
            _ => None,
        },
        JobKind::Restore => match phase {
            P::Plan => Some(2),
            P::DownloadAndWrite => Some(3),
            P::Fixups => Some(4),
            _ => None,
        },
        _ => match phase {
            P::Unspecified => None,
            _ => Some(2),
        },
    }
}

/// Turns what happens in a job into throttled [`JobProgress`] frames.
#[derive(Debug)]
pub struct ProgressMapper {
    kind: JobKind,
    index: u32,
    files_done: u64,
    files_total: u64,
    bytes_done: u64,
    bytes_total: u64,
    transfer: u64,
    finished: Option<bool>,
    dirty: bool,
    last_emit_ms: Option<u64>,
    interval_ms: u64,
    /// The phases entered, in order (starts with 1): not throttled, so what the job went
    /// through can be told even when the throttle held the last frame.
    history: Vec<u32>,
}

impl ProgressMapper {
    /// A mapper for a job of `kind` at phase 1, emitting at most [`MAX_PER_SECOND`] frames a
    /// second.
    pub fn new(kind: JobKind) -> Self {
        Self {
            kind,
            index: 1,
            files_done: 0,
            files_total: 0,
            bytes_done: 0,
            bytes_total: 0,
            transfer: 0,
            finished: None,
            dirty: true,
            last_emit_ms: None,
            interval_ms: 1000 / MAX_PER_SECOND,
            history: vec![1],
        }
    }

    /// The job moves to phase `index` of privd's table (a phase privd runs itself).
    pub fn enter(&mut self, index: u32) {
        if index != self.index {
            self.index = index;
            self.history.push(index);
            self.files_done = 0;
            self.files_total = 0;
            self.bytes_done = 0;
            self.bytes_total = 0;
            self.dirty = true;
        }
    }

    /// The phases the job entered, in order (not throttled).
    pub fn history(&self) -> &[u32] {
        &self.history
    }

    /// The worker's latest numbers.
    pub fn worker(&mut self, p: &pb::Progress) {
        let phase = ProgressPhase::try_from(p.phase).unwrap_or(ProgressPhase::Unspecified);
        let Some(index) = phase_index(self.kind, phase) else {
            return;
        };
        // The numbers restart when the phase changes (section 33).
        self.enter(index);
        self.files_done = p.files_done;
        self.files_total = p.files_total;
        self.bytes_done = p.bytes_done;
        self.bytes_total = p.bytes_total;
        self.dirty = true;
    }

    /// Object bytes relayed to or from the Drive helper.
    pub fn add_transfer(&mut self, n: u64) {
        self.transfer = self.transfer.saturating_add(n);
        self.dirty = true;
    }

    /// The job ended (`ok` or not): the next frame is its last.
    pub fn finish(&mut self, ok: bool) {
        self.finished = Some(ok);
        self.dirty = true;
    }

    fn percent(&self) -> u32 {
        if self.finished == Some(true) {
            return 100;
        }
        let ratio = |done: u64, total: u64| -> Option<u32> {
            (total > 0).then(|| {
                u32::try_from((u128::from(done) * 100 / u128::from(total)).min(100)).unwrap_or(100)
            })
        };
        ratio(self.bytes_done, self.bytes_total)
            .or_else(|| ratio(self.files_done, self.files_total))
            .unwrap_or(255)
    }

    /// The current frame, whether or not it is due.
    pub fn current(&self) -> JobProgress {
        let (stage, total) = table(self.kind);
        JobProgress {
            stage,
            index: self.index,
            total,
            step: step_text(self.kind, self.index),
            percent: self.percent(),
            ok: self.finished != Some(false),
            bytes_done: self.bytes_done,
            bytes_total: self.bytes_total,
            transfer_bytes: self.transfer,
        }
    }

    /// The frame to emit now, if something changed and 100 ms have passed since the last one
    /// (`now_ms` is the monotonic clock). A frame that is not due is held: the newest wins, and
    /// the next call after the interval emits it.
    pub fn poll(&mut self, now_ms: u64) -> Option<JobProgress> {
        if !self.dirty {
            return None;
        }
        if self
            .last_emit_ms
            .is_some_and(|t| now_ms.saturating_sub(t) < self.interval_ms)
        {
            return None;
        }
        self.dirty = false;
        self.last_emit_ms = Some(now_ms);
        Some(self.current())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wp(phase: ProgressPhase, done: u64, total: u64) -> pb::Progress {
        pb::Progress {
            phase: phase as i32,
            bytes_done: done,
            bytes_total: total,
            ..Default::default()
        }
    }

    #[test]
    fn at_most_ten_frames_a_second_and_the_newest_wins() {
        let mut m = ProgressMapper::new(JobKind::Backup);
        let mut out = Vec::new();
        // 100 updates in one second of clock time, one every 10 ms.
        for i in 0..100u64 {
            m.worker(&wp(ProgressPhase::ScanAndUpload, i, 100));
            if let Some(f) = m.poll(1_000 + i * 10) {
                out.push((1_000 + i * 10, f));
            }
        }
        assert!(out.len() <= 10, "{} frames", out.len());
        assert!(out.len() >= 9, "the throttle must not starve the stream");
        for w in out.windows(2) {
            assert!(w[1].0 - w[0].0 >= 100, "{:?}", w);
        }
        // The newest numbers were held and go out at the next poll; nothing is repeated.
        assert_eq!(m.poll(10_000).map(|f| f.percent), Some(99));
        assert_eq!(m.poll(10_500), None, "nothing changed since the last emit");
        m.worker(&wp(ProgressPhase::ScanAndUpload, 100, 100));
        assert_eq!(m.poll(10_500).unwrap().percent, 100);
    }

    #[test]
    fn a_transfer_only_frame_uses_the_window_and_the_held_numbers_go_out_after_it() {
        let mut m = ProgressMapper::new(JobKind::Backup);
        m.enter(4);
        assert!(m.poll(1_000).is_some());
        // Bytes relayed: a frame, but inside the 100 ms window, so it is held...
        m.add_transfer(1_500_001);
        assert!(m.poll(1_050).is_none());
        // ...and the worker's numbers that arrive meanwhile replace nothing: the next frame
        // that is due carries both.
        m.worker(&wp(ProgressPhase::ScanAndUpload, 50, 100));
        let f = m.poll(1_100).unwrap();
        assert_eq!(
            (
                f.index,
                f.percent,
                f.bytes_done,
                f.bytes_total,
                f.transfer_bytes
            ),
            (4, 50, 50, 100, 1_500_001)
        );
    }

    #[test]
    fn the_step_text_is_privds_and_the_phase_table_is_fixed() {
        let mut m = ProgressMapper::new(JobKind::Backup);
        assert_eq!(m.current().step, "Taking a snapshot");
        assert_eq!((m.current().index, m.current().total), (1, 6));
        m.enter(2);
        assert_eq!(m.current().step, "Starting the backup worker");
        for (phase, idx, text) in [
            (ProgressPhase::RepairIndex, 3, "Repairing the index"),
            (ProgressPhase::ScanAndUpload, 4, "Scanning and uploading"),
            (ProgressPhase::WriteSnapshot, 5, "Writing the snapshot"),
        ] {
            m.worker(&wp(phase, 0, 0));
            assert_eq!((m.current().index, m.current().step), (idx, text));
        }
        m.enter(6);
        assert_eq!(m.current().step, "Cleaning up");
        // A phase the backup table does not have is ignored.
        m.worker(&wp(ProgressPhase::Check, 1, 2));
        assert_eq!(m.current().index, 6);
        assert_eq!(m.current().stage, ppb::ProgressStage::Backup);
    }

    #[test]
    fn restore_has_its_own_table_and_stage() {
        let mut m = ProgressMapper::new(JobKind::Restore);
        assert_eq!(m.current().stage, ppb::ProgressStage::Restore);
        assert_eq!((m.current().index, m.current().total), (1, 5));
        assert_eq!(m.current().step, "Preparing the restore target");
        for (phase, idx, text) in [
            (ProgressPhase::Plan, 2, "Planning the restore"),
            (
                ProgressPhase::DownloadAndWrite,
                3,
                "Downloading and writing files",
            ),
            (ProgressPhase::Fixups, 4, "Fixing ownership and modes"),
        ] {
            m.worker(&wp(phase, 5, 10));
            assert_eq!(
                (m.current().index, m.current().step, m.current().percent),
                (idx, text, 50)
            );
        }
    }

    #[test]
    fn other_kinds_have_three_phases_under_the_backup_stage() {
        for (kind, work) in [
            (JobKind::Init, "Creating the repository"),
            (JobKind::Keys, "Managing keys"),
            (JobKind::Snapshots, "Listing snapshots"),
            (JobKind::RestorePlan, "Planning the restore"),
            (JobKind::ForgetPrune, "Forgetting and pruning"),
            (JobKind::Check, "Checking the repository"),
        ] {
            let mut m = ProgressMapper::new(kind);
            assert_eq!(m.current().total, 3);
            assert_eq!(m.current().stage, ppb::ProgressStage::Backup);
            m.worker(&wp(ProgressPhase::Check, 1, 2));
            assert_eq!((m.current().index, m.current().step), (2, work), "{kind:?}");
            m.enter(3);
            assert_eq!(m.current().step, "Cleaning up");
        }
    }

    #[test]
    fn percent_is_computed_by_privd_from_bytes_then_files_else_unknown() {
        let mut m = ProgressMapper::new(JobKind::Backup);
        m.worker(&pb::Progress {
            phase: ProgressPhase::ScanAndUpload as i32,
            files_done: 3,
            files_total: 4,
            ..Default::default()
        });
        assert_eq!(m.current().percent, 75);
        m.worker(&pb::Progress {
            phase: ProgressPhase::ScanAndUpload as i32,
            bytes_done: 10,
            bytes_total: 40,
            files_done: 3,
            files_total: 4,
        });
        assert_eq!(m.current().percent, 25);
        m.worker(&wp(ProgressPhase::ScanAndUpload, 5, 0));
        assert_eq!(m.current().percent, 255);
        m.worker(&wp(ProgressPhase::ScanAndUpload, 500, 100));
        assert_eq!(m.current().percent, 100, "clamped");
        // The numbers restart at 0 when the phase changes.
        m.worker(&wp(ProgressPhase::WriteSnapshot, 0, 0));
        assert_eq!((m.current().bytes_done, m.current().percent), (0, 255));
    }

    #[test]
    fn transfer_bytes_count_and_a_finished_job_reports_100_or_failure() {
        let mut m = ProgressMapper::new(JobKind::Backup);
        m.add_transfer(1000);
        m.add_transfer(24);
        assert_eq!(m.current().transfer_bytes, 1024);
        let mut f = m.clone_for_test();
        f.finish(true);
        let c = f.current();
        assert!((c.percent, c.ok) == (100, true));
        m.finish(false);
        assert!(!m.current().ok);
        let p = m.current().to_pb(7);
        assert_eq!((p.request_id, p.transfer_bytes), (7, 1024));
        assert_eq!(p.step, "Taking a snapshot");
    }

    impl ProgressMapper {
        fn clone_for_test(&self) -> Self {
            Self {
                kind: self.kind,
                index: self.index,
                files_done: self.files_done,
                files_total: self.files_total,
                bytes_done: self.bytes_done,
                bytes_total: self.bytes_total,
                transfer: self.transfer,
                finished: self.finished,
                dirty: self.dirty,
                last_emit_ms: self.last_emit_ms,
                interval_ms: self.interval_ms,
                history: self.history.clone(),
            }
        }
    }
}
