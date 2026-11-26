//! Progress reporting and cancellation for the engine.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use rustic_core::{Progress, ProgressBars, ProgressType, RusticProgress};

use super::EngineError;

/// The step the engine is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Phase {
    /// Opening or initialising the repository.
    OpenRepository,
    /// `repair index` before a backup (architecture 9.4 step 0).
    RepairIndex,
    /// Resolving exclude and protected-path rules against the source tree.
    ResolveRules,
    /// Measuring the source tree for the manifest.
    ScanSource,
    /// Reading the source and writing packs.
    Backup,
    /// Comparing the snapshot with the restore target.
    PrepareRestore,
    /// Writing files into the restore target.
    Restore,
    /// Comparing owners and modes of the restored entries with the snapshot.
    VerifyRestore,
    /// Recreating the mount-point directories.
    RestoreMountPoints,
    /// Applying retention rules.
    Forget,
    /// Removing unused data.
    Prune,
    /// Checking repository structure.
    Check,
    /// Reading and verifying pack data.
    ReadData,
}

/// What `done` and `total` count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressUnit {
    /// Bytes.
    Bytes,
    /// Files or other items.
    Items,
    /// No measure; only the title and `finished` carry information.
    Spinner,
}

/// A progress update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgressEvent {
    /// The engine step.
    pub phase: Phase,
    /// Unit of `done` and `total`.
    pub unit: ProgressUnit,
    /// Short description from the engine or rustic (never contains key material).
    pub title: String,
    /// Progress so far.
    pub done: u64,
    /// Total, when known.
    pub total: Option<u64>,
    /// Set on the last event of a sub-step.
    pub finished: bool,
}

/// Receives progress events. Called from engine threads, possibly concurrently and often:
/// events from rustic are throttled to about ten per second per sub-step, but implementations
/// must stay cheap and must not block.
pub trait ProgressSink: Send + Sync {
    /// Handle one event.
    fn event(&self, event: &ProgressEvent);
}

/// A sink that ignores everything.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullSink;

impl ProgressSink for NullSink {
    fn event(&self, _event: &ProgressEvent) {}
}

/// A cancellation flag, cheap to clone and share with another thread.
///
/// The engine checks it between steps and inside the source scan. A running rustic backup or
/// restore call cannot be interrupted from inside; killing the worker is safe because backups
/// resume through `repair index` and restores resume by skipping verified files.
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    /// A fresh, un-cancelled token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether cancellation was requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    /// `Err(Cancelled)` once cancellation was requested.
    ///
    /// # Errors
    /// [`EngineError::Cancelled`].
    pub fn check(&self) -> Result<(), EngineError> {
        if self.is_cancelled() {
            Err(EngineError::Cancelled)
        } else {
            Ok(())
        }
    }
}

pub(crate) struct Shared {
    sink: Arc<dyn ProgressSink>,
    phase: Mutex<Phase>,
    /// Bytes of pack data rustic announced it would read (`reading pack data...`), for `check`.
    read_data_bytes: AtomicU64,
}

impl fmt::Debug for Shared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shared").finish_non_exhaustive()
    }
}

impl Shared {
    pub(crate) fn new(sink: Arc<dyn ProgressSink>) -> Arc<Self> {
        Arc::new(Self {
            sink,
            phase: Mutex::new(Phase::OpenRepository),
            read_data_bytes: AtomicU64::new(0),
        })
    }

    pub(crate) fn reset_read_bytes(&self) {
        self.read_data_bytes.store(0, Ordering::SeqCst);
    }

    pub(crate) fn read_bytes(&self) -> u64 {
        self.read_data_bytes.load(Ordering::SeqCst)
    }

    pub(crate) fn set_phase(&self, phase: Phase) {
        *self.phase.lock().unwrap_or_else(PoisonError::into_inner) = phase;
    }

    fn phase(&self) -> Phase {
        *self.phase.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Emit an engine-originated event for the current phase.
    pub(crate) fn emit(
        &self,
        unit: ProgressUnit,
        title: &str,
        done: u64,
        total: Option<u64>,
        finished: bool,
    ) {
        self.sink.event(&ProgressEvent {
            phase: self.phase(),
            unit,
            title: title.to_owned(),
            done,
            total,
            finished,
        });
    }
}

/// Adapter handing rustic's progress calls to the sink.
#[derive(Debug, Clone)]
pub(crate) struct Bars(pub(crate) Arc<Shared>);

impl ProgressBars for Bars {
    fn progress(&self, progress_type: ProgressType, prefix: &str) -> Progress {
        let unit = match progress_type {
            ProgressType::Spinner => ProgressUnit::Spinner,
            ProgressType::Counter => ProgressUnit::Items,
            ProgressType::Bytes => ProgressUnit::Bytes,
        };
        let p = Item {
            shared: Arc::clone(&self.0),
            unit,
            title: Mutex::new(prefix.to_owned()),
            done: AtomicU64::new(0),
            total: AtomicU64::new(u64::MAX),
            last: Mutex::new(None),
        };
        p.send(false, true);
        Progress::new(p)
    }
}

const THROTTLE: Duration = Duration::from_millis(100);

struct Item {
    shared: Arc<Shared>,
    unit: ProgressUnit,
    title: Mutex<String>,
    done: AtomicU64,
    /// `u64::MAX` while unknown.
    total: AtomicU64,
    last: Mutex<Option<Instant>>,
}

impl fmt::Debug for Item {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Item")
            .field("unit", &self.unit)
            .finish_non_exhaustive()
    }
}

impl Item {
    fn send(&self, finished: bool, force: bool) {
        if !force {
            let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
            let now = Instant::now();
            if last.is_some_and(|l| now.duration_since(l) < THROTTLE) {
                return;
            }
            *last = Some(now);
        }
        let total = self.total.load(Ordering::Relaxed);
        let title = self
            .title
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        self.shared.emit(
            self.unit,
            &title,
            self.done.load(Ordering::Relaxed),
            (total != u64::MAX).then_some(total),
            finished,
        );
    }
}

impl RusticProgress for Item {
    fn is_hidden(&self) -> bool {
        false
    }

    fn set_length(&self, len: u64) {
        self.total.store(len, Ordering::Relaxed);
        if self
            .title
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .starts_with("reading pack data")
        {
            self.shared.read_data_bytes.fetch_add(len, Ordering::SeqCst);
        }
        self.send(false, false);
    }

    fn set_title(&self, title: &str) {
        title.clone_into(&mut self.title.lock().unwrap_or_else(PoisonError::into_inner));
        self.send(false, true);
    }

    fn inc(&self, inc: u64) {
        self.done.fetch_add(inc, Ordering::Relaxed);
        self.send(false, false);
    }

    fn finish(&self) {
        self.send(true, true);
    }

    fn error(&self, item: Option<&str>, during: &str, message: &str) {
        // Item names are paths from the user's desktop: logged at warn, never forwarded.
        tracing::warn!(
            item = item.unwrap_or(""),
            during,
            message,
            "backup engine item error"
        );
    }
}
