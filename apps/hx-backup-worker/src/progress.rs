//! `Progress` frames (ipc.md §33): numbers only, at most two a second.
//!
//! The engine calls [`Reporter::event`] from its own threads, often and from many; that only
//! records the latest numbers under a lock. A thread of the reporter's own wakes every
//! [`INTERVAL`], and sends one frame when something changed. Nothing the engine says in text
//! (titles carry item names from the user's desktop) is looked at.

use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use hx_backup::engine::{Link, Phase, ProgressEvent, ProgressSink, ProgressUnit};
use hx_ipc::repo::pb;

/// Time between two `Progress` frames: 500 ms, so at most two a second.
pub const INTERVAL: Duration = Duration::from_millis(500);

/// The `Progress.phase` of an engine step (ipc.md §33), or `None` when the step says nothing worth
/// a frame (`OpenRepository` outside `INIT` and `KEYS`).
#[must_use]
pub fn map_phase(
    phase: Phase,
    kind: pb::JobKind,
    snapshot_written: bool,
) -> Option<pb::ProgressPhase> {
    use pb::ProgressPhase as P;
    Some(match phase {
        Phase::OpenRepository => match kind {
            pb::JobKind::Init => P::Init,
            pb::JobKind::Keys => P::Keys,
            _ => return None,
        },
        Phase::RepairIndex => P::RepairIndex,
        Phase::ResolveRules | Phase::ScanSource => P::ScanAndUpload,
        Phase::Backup if snapshot_written => P::WriteSnapshot,
        Phase::Backup => P::ScanAndUpload,
        Phase::PrepareRestore => P::Plan,
        Phase::Restore => P::DownloadAndWrite,
        Phase::VerifyRestore | Phase::RestoreMountPoints => P::Fixups,
        Phase::Forget => P::Forget,
        Phase::Prune => P::Prune,
        Phase::Check | Phase::ReadData => P::Check,
    })
}

#[derive(Default)]
struct Numbers {
    phase: Option<pb::ProgressPhase>,
    files_done: u64,
    files_total: u64,
    bytes_done: u64,
    bytes_total: u64,
    dirty: bool,
    stop: bool,
}

struct Shared {
    kind: pb::JobKind,
    link: Arc<Link>,
    n: Mutex<Numbers>,
    cv: Condvar,
}

fn lock(m: &Mutex<Numbers>) -> MutexGuard<'_, Numbers> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The engine's progress sink and the thread that sends what it recorded.
pub struct Reporter {
    shared: Arc<Shared>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl Reporter {
    /// Starts the sending thread. `kind` is the job's kind (it names the phase of opening the
    /// repository).
    ///
    /// # Errors
    /// If the thread cannot be spawned.
    pub fn start(link: Arc<Link>, kind: pb::JobKind) -> std::io::Result<Arc<Self>> {
        let shared = Arc::new(Shared {
            kind,
            link,
            n: Mutex::new(Numbers::default()),
            cv: Condvar::new(),
        });
        let s = Arc::clone(&shared);
        let handle = thread::Builder::new()
            .name("hx-progress".into())
            .spawn(move || send_loop(&s))?;
        Ok(Arc::new(Self {
            shared,
            thread: Mutex::new(Some(handle)),
        }))
    }

    /// Stops the thread (after it has sent nothing more). Call before the `JobResult`.
    pub fn stop(&self) {
        lock(&self.shared.n).stop = true;
        self.shared.cv.notify_all();
        if let Some(h) = self
            .thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            let _ = h.join();
        }
    }
}

impl ProgressSink for Reporter {
    fn event(&self, e: &ProgressEvent) {
        let Some(phase) = map_phase(
            e.phase,
            self.shared.kind,
            self.shared.link.snapshot_write_started(),
        ) else {
            return;
        };
        let mut n = lock(&self.shared.n);
        if n.phase != Some(phase) {
            *n = Numbers {
                phase: Some(phase),
                dirty: true,
                stop: n.stop,
                ..Numbers::default()
            };
        }
        match e.unit {
            ProgressUnit::Items => {
                n.files_done = e.done;
                n.files_total = e.total.unwrap_or(0);
            }
            ProgressUnit::Bytes => {
                n.bytes_done = e.done;
                n.bytes_total = e.total.unwrap_or(0);
            }
            ProgressUnit::Spinner => {}
        }
        n.dirty = true;
    }
}

fn send_loop(s: &Shared) {
    let mut last: Option<Instant> = None;
    let mut n = lock(&s.n);
    loop {
        if n.stop {
            return;
        }
        let wait = match last {
            Some(t) => INTERVAL.saturating_sub(t.elapsed()),
            None => Duration::ZERO,
        };
        if n.dirty && wait.is_zero() {
            if let Some(phase) = n.phase {
                let p = pb::Progress {
                    phase: phase as i32,
                    files_done: n.files_done,
                    files_total: n.files_total,
                    bytes_done: n.bytes_done,
                    bytes_total: n.bytes_total,
                };
                n.dirty = false;
                last = Some(Instant::now());
                drop(n);
                if s.link.send_progress(p).is_err() {
                    return;
                }
                n = lock(&s.n);
                continue;
            }
            n.dirty = false;
        }
        let timeout = if n.dirty { wait } else { INTERVAL };
        n =
            s.cv.wait_timeout(n, timeout.max(Duration::from_millis(10)))
                .unwrap_or_else(PoisonError::into_inner)
                .0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_engine_step_has_a_phase_and_opening_only_for_init_and_keys() {
        use pb::JobKind as K;
        use pb::ProgressPhase as P;
        assert_eq!(
            map_phase(Phase::OpenRepository, K::Init, false),
            Some(P::Init)
        );
        assert_eq!(
            map_phase(Phase::OpenRepository, K::Keys, false),
            Some(P::Keys)
        );
        assert_eq!(map_phase(Phase::OpenRepository, K::Backup, false), None);
        assert_eq!(
            map_phase(Phase::Backup, K::Backup, false),
            Some(P::ScanAndUpload)
        );
        assert_eq!(
            map_phase(Phase::Backup, K::Backup, true),
            Some(P::WriteSnapshot)
        );
        assert_eq!(map_phase(Phase::ReadData, K::Check, false), Some(P::Check));
        assert_eq!(
            map_phase(Phase::VerifyRestore, K::Restore, false),
            Some(P::Fixups)
        );
    }
}
