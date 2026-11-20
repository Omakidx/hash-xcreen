//! Per-frame acknowledgements: the hook for the sender's congestion controller.
//!
//! The transport only reports what happened to each video frame; the policy that reacts
//! (bitrate ladder, cancelling stale frames) belongs to the session (workstream 1F).

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::sync::{Notify, oneshot};

/// What happened to a video frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckOutcome {
    /// The peer received the whole frame (stream completion on QUIC, ack message on WebSocket).
    Delivered,
    /// The sender cancelled the frame before it was fully delivered.
    Cancelled,
    /// The peer stopped the stream (QUIC `STOP_SENDING` with this code).
    Rejected(u64),
    /// The connection ended before the frame was acknowledged.
    ConnectionLost,
}

/// Acknowledgement of one video frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameAck {
    /// Frame number from the media header.
    pub frame_number: u32,
    /// Payload bytes of the frame.
    pub bytes: usize,
    /// Time from handing the frame to the transport until the outcome.
    pub elapsed: Duration,
    /// Result.
    pub outcome: AckOutcome,
}

/// Callback invoked for every [`FrameAck`], on a transport task: keep it short and non-blocking.
pub type AckHandler = Arc<dyn Fn(FrameAck) + Send + Sync>;

#[derive(Debug, Default)]
pub(crate) struct CancelFlag {
    flag: AtomicBool,
    notify: Notify,
}

impl CancelFlag {
    pub(crate) fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
        self.notify.notify_one();
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    pub(crate) async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        self.notify.notified().await;
    }
}

/// Handle to a frame being sent.
#[derive(Debug)]
pub struct FrameTicket {
    pub(crate) frame_number: u32,
    pub(crate) bytes: usize,
    pub(crate) cancel: Arc<CancelFlag>,
    pub(crate) done: oneshot::Receiver<FrameAck>,
}

impl FrameTicket {
    /// Frame number this ticket belongs to.
    pub fn frame_number(&self) -> u32 {
        self.frame_number
    }

    /// Cancel the frame: on QUIC its stream is reset with `STALE_FRAME`; on WebSocket it is
    /// dropped if it has not been written yet. The ack then reports [`AckOutcome::Cancelled`]
    /// (unless it was already delivered).
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// Wait for the frame's outcome.
    pub async fn ack(self) -> FrameAck {
        match self.done.await {
            Ok(a) => a,
            Err(_) => FrameAck {
                frame_number: self.frame_number,
                bytes: self.bytes,
                elapsed: Duration::ZERO,
                outcome: AckOutcome::ConnectionLost,
            },
        }
    }
}
