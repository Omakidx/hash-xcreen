//! `Progress` frames (ipc.md 4): lossy and bounded.
//!
//! A command pushes events into a queue of at most 256 entries (the oldest are dropped when a
//! slow peer lets it fill); the connection task drains it at most 10 times a second. The final
//! `Response` never goes through this queue.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use hx_ipc::privd::pb::{self, ProgressStage};
use hx_ipc::text::sanitize_text;
use tokio::sync::Notify;

/// Frames buffered per connection.
pub const MAX_QUEUED: usize = 256;
/// Minimum spacing between `Progress` frames of one request.
pub const MIN_INTERVAL_MS: u64 = 100;

/// The queue shared by a command and its connection.
#[derive(Default)]
pub struct ProgressQueue {
    q: Mutex<VecDeque<pb::Progress>>,
    notify: Notify,
}

impl ProgressQueue {
    /// Takes the oldest queued frame.
    pub fn pop(&self) -> Option<pb::Progress> {
        self.q.lock().ok()?.pop_front()
    }

    /// Completes when something has been queued since the last wait (or is queued now).
    pub async fn wait(&self) {
        let n = self.notify.notified();
        tokio::pin!(n);
        n.as_mut().enable();
        if self.q.lock().map(|q| !q.is_empty()).unwrap_or(false) {
            return;
        }
        n.await;
    }

    /// Number of queued frames (tests).
    pub fn len(&self) -> usize {
        self.q.lock().map(|q| q.len()).unwrap_or(0)
    }

    /// True when nothing is queued.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// What a command uses to report progress. Cloning shares the queue.
#[derive(Clone)]
pub struct ProgressSender {
    request_id: u64,
    queue: Arc<ProgressQueue>,
}

impl ProgressSender {
    /// A sender and the queue its connection drains.
    pub fn new(request_id: u64) -> (Self, Arc<ProgressQueue>) {
        let queue = Arc::new(ProgressQueue::default());
        (
            Self {
                request_id,
                queue: queue.clone(),
            },
            queue,
        )
    }

    /// A sender that drops everything (commands called outside a connection).
    pub fn discard() -> Self {
        Self::new(0).0
    }

    /// Queues a frame; `step` is sanitized and cut to 128 bytes.
    pub fn emit(
        &self,
        stage: ProgressStage,
        index: u32,
        total: u32,
        step: &str,
        percent: u32,
        ok: bool,
    ) {
        let p = pb::Progress {
            request_id: self.request_id,
            stage: stage as i32,
            index,
            total,
            step: sanitize_text(step, hx_ipc::privd::MAX_PROGRESS_STEP_LEN),
            percent: if percent <= 100 { percent } else { 255 },
            ok,
        };
        if let Ok(mut q) = self.queue.q.lock() {
            if q.len() >= MAX_QUEUED {
                q.pop_front();
            }
            q.push_back(p);
        }
        self.queue.notify.notify_one();
    }

    /// A coarse stage marker without counters.
    pub fn stage(&self, stage: ProgressStage, step: &str) {
        self.emit(stage, 0, 0, step, 255, true);
    }

    /// Maps `hx_provision::Progress` one to one (`Started` and `Finished`); the step text is
    /// `hx-provision`'s own recipe-defined description, never container output.
    pub fn from_provision(&self, p: &hx_provision::Progress) {
        self.from_provision_as(p, None);
    }

    /// Like [`ProgressSender::from_provision`], reporting every event under `stage` when given
    /// (the Docker add-on runs `hx-provision`'s build stage but is the `DOCKER` stage here).
    pub fn from_provision_as(&self, p: &hx_provision::Progress, over: Option<ProgressStage>) {
        use hx_provision::{Progress as P, Stage};
        let stage_of = |s: &Stage| {
            over.unwrap_or(match s {
                Stage::Build => ProgressStage::Build,
                Stage::Post => ProgressStage::Post,
            })
        };
        match p {
            P::Started {
                stage,
                index,
                total,
                step,
            } => self.emit(
                stage_of(stage),
                u32::try_from(*index).unwrap_or(u32::MAX),
                u32::try_from(*total).unwrap_or(u32::MAX),
                step,
                255,
                true,
            ),
            P::Finished {
                stage,
                index,
                step,
                ok,
                ..
            } => self.emit(
                stage_of(stage),
                u32::try_from(*index).unwrap_or(u32::MAX),
                0,
                step,
                255,
                *ok,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_queue_keeps_the_newest_256_and_sanitizes_steps() {
        let (tx, q) = ProgressSender::new(5);
        for i in 0..300 {
            tx.emit(ProgressStage::Build, i, 300, "step\u{1b}[31m", 50, true);
        }
        assert_eq!(q.len(), MAX_QUEUED);
        let first = q.pop().unwrap();
        assert_eq!(first.index, 300 - MAX_QUEUED as u32);
        assert_eq!(first.request_id, 5);
        assert_eq!(first.step, "step[31m");
    }

    #[test]
    fn a_long_step_is_cut_and_a_bad_percent_is_unknown() {
        let (tx, q) = ProgressSender::new(1);
        tx.emit(ProgressStage::Host, 0, 0, &"x".repeat(500), 101, true);
        let p = q.pop().unwrap();
        assert_eq!(p.step.len(), 128);
        assert_eq!(p.percent, 255);
        assert!(q.is_empty());
    }
}
