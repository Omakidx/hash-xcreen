//! The decode thread: frames in, pictures out, a keyframe request when sync is lost.

use std::sync::Arc;
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use hx_transport::VideoFrame;

use super::decode::Decoder;
use super::present::Presenter;
use super::stats::Stats;

/// Frames queued between the network task and the decoder. Beyond this the oldest news is
/// worthless: new frames are dropped and a keyframe is requested.
pub const QUEUE_DEPTH: usize = 8;

/// Handle of the running thread. Dropping the sender ends it.
pub struct DecodeThread {
    handle: Option<JoinHandle<()>>,
}

impl DecodeThread {
    /// Waits for the thread to end (after the sender was dropped).
    pub fn join(mut self) {
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Starts the decoder. `request_keyframe(last_decoded_frame)` is called when sync is lost,
/// at most twice a second.
pub fn spawn_decoder(
    presenter: Arc<dyn Presenter>,
    stats: Arc<Stats>,
    request_keyframe: Arc<dyn Fn(u32) + Send + Sync>,
) -> std::io::Result<(SyncSender<VideoFrame>, DecodeThread)> {
    let (tx, rx) = sync_channel::<VideoFrame>(QUEUE_DEPTH);
    let handle = std::thread::Builder::new()
        .name("hx-decode".into())
        .spawn(move || run(rx, presenter, stats, request_keyframe))?;
    Ok((
        tx,
        DecodeThread {
            handle: Some(handle),
        },
    ))
}

fn run(
    rx: Receiver<VideoFrame>,
    presenter: Arc<dyn Presenter>,
    stats: Arc<Stats>,
    request_keyframe: Arc<dyn Fn(u32) + Send + Sync>,
) {
    let Ok(mut dec) = Decoder::new() else {
        tracing::error!("no H.264 decoder");
        return;
    };
    let mut need_key = true;
    let mut last_ok = 0u32;
    let mut last_req: Option<Instant> = None;
    let ask = |last: u32, last_req: &mut Option<Instant>| {
        if last_req.is_none_or(|t| t.elapsed() > Duration::from_millis(500)) {
            *last_req = Some(Instant::now());
            request_keyframe(last);
        }
    };
    while let Ok(f) = rx.recv() {
        stats.add_bytes(f.payload.len() as u64);
        if need_key && !f.header.is_key() {
            stats.dropped();
            ask(last_ok, &mut last_req);
            continue;
        }
        let t0 = Instant::now();
        match dec.decode(&f.payload) {
            Ok(Some(pic)) => {
                need_key = false;
                last_ok = f.header.frame_number;
                stats.decoded(t0.elapsed().as_micros().min(u128::from(u32::MAX)) as u32);
                presenter.present(pic);
                stats.presented();
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!("decode: {e}");
                stats.dropped();
                need_key = true;
                ask(last_ok, &mut last_req);
            }
        }
    }
}
