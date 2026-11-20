//! The capture, convert and encode pipeline.
//!
//! ```text
//! display --damage--> [capture thread] --Frame--> [convert thread] --YuvFrame--> [encode thread] --> EncodedFrame
//!                          |  paced by `Pacer`        bounded queues (crossbeam)          bounded output queue
//!                          +--> CursorEvent queue
//! ```
//!
//! * **Capture when free:** a frame is taken as soon as damage exists and the frame-rate
//!   ceiling has elapsed since the last capture; while a later stage is busy, damage keeps
//!   accumulating and the next capture covers all of it. Idle display means no work.
//! * **Backpressure, not growth:** every queue and buffer pool is bounded. A slow consumer
//!   of [`Pipeline::frames`] stalls the encoder, then conversion, then capture (which keeps
//!   coalescing damage); memory stays flat.
//! * **No per-frame allocation** in steady state: capture buffers, YUV pictures and encoded
//!   byte buffers are all pooled. A display resize allocates new ones once.
//! * **No async runtime.** Everything here is plain OS threads.
//!
//! Control (bitrate, frame-rate ceiling, IDR, resize) and statistics are on [`Control`],
//! a cheap clone that any thread may hold.

use crate::pacing::{Decision, IDLE_POLL, Pacer};
use crate::stats::{QueueId, Stats, StatsSnapshot};
use crossbeam_channel::{Receiver, RecvTimeoutError, SendTimeoutError, Sender, bounded};
use hx_capture::{Capture, CaptureError, CursorEvent, Frame, Size, X11Capture, X11Config, mono_ns};
use hx_codec::EncodedFrame;
use hx_codec::encode::{
    EncodeError, EncoderConfig, FrameMeta, X264Encoder, YuvFrame, convert_bgrx, even_size,
};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use thiserror::Error;

/// How long a grab waits for a free capture buffer before the loop re-checks control.
const GRAB_BUFFER_WAIT: Duration = Duration::from_millis(5);
/// Pause after a recoverable capture error, so a persistent one cannot spin a core.
const ERROR_BACKOFF: Duration = Duration::from_millis(10);
/// Consecutive encode or convert failures after which the pipeline gives up.
const MAX_CONSECUTIVE_ERRORS: u32 = 10;
/// Cursor events buffered for the consumer; further ones are dropped (positions coalesce
/// upstream, so a stalled consumer loses only stale movement).
const CURSOR_QUEUE: usize = 256;

const BITRATE_RANGE: std::ops::RangeInclusive<u32> = 100..=100_000;
const FPS_RANGE: std::ops::RangeInclusive<u32> = 1..=240;

/// Pipeline failures.
#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("capture: {0}")]
    Capture(#[from] CaptureError),
    #[error("encode: {0}")]
    Encode(#[from] EncodeError),
    #[error("cannot start a pipeline thread: {0}")]
    Spawn(std::io::Error),
    #[error("the {0} thread panicked")]
    Panicked(&'static str),
    #[error("invalid setting: {0}")]
    InvalidSetting(String),
    /// A pipeline thread stopped on an unrecoverable error.
    #[error("pipeline stopped: {0}")]
    Failed(String),
}

/// Pipeline settings.
#[derive(Clone, Debug)]
pub struct PipelineConfig {
    pub capture: X11Config,
    /// Encoder settings. `width` and `height` are ignored: the picture size follows the
    /// display (rounded down to even). `bitrate_kbps` and `fps` are the starting values.
    pub encoder: EncoderConfig,
    /// Frame-rate ceiling: the minimum interval between captures. 60 in v1.
    pub max_fps: u32,
    /// Depth of the capture-to-convert and convert-to-encode queues.
    pub queue_depth: usize,
    /// Depth of the output queue read through [`Pipeline::frames`].
    pub output_depth: usize,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        let encoder = EncoderConfig::new(1920, 1080);
        Self {
            capture: X11Config::default(),
            max_fps: encoder.fps,
            encoder,
            queue_depth: 2,
            output_depth: 4,
        }
    }
}

struct Shared {
    stop: AtomicBool,
    bitrate_kbps: AtomicU32,
    max_fps: AtomicU32,
    /// Bumped by every IDR request; each thread compares with the value it last acted on.
    idr_epoch: AtomicU64,
    /// Pending resize as `width << 32 | height`; 0 for none.
    resize: AtomicU64,
    fatal: Mutex<Option<String>>,
    last_error: Mutex<Option<String>>,
    stats: Stats,
}

impl Shared {
    fn stopped(&self) -> bool {
        self.stop.load(Relaxed)
    }

    /// Note a recoverable problem.
    fn soft_error(&self, what: impl std::fmt::Display) {
        self.stats.errors.fetch_add(1, Relaxed);
        if let Ok(mut g) = self.last_error.lock() {
            *g = Some(what.to_string());
        }
    }

    fn fail(&self, what: String) {
        if let Ok(mut g) = self.fatal.lock() {
            g.get_or_insert(what);
        }
        self.stop.store(true, Relaxed);
    }
}

/// Handle for steering a running pipeline and reading its statistics. Cheap to clone.
#[derive(Clone)]
pub struct Control {
    shared: Arc<Shared>,
}

impl Control {
    /// Set the encoder's rate cap in kbit/s (100 to 100000; the product ladder tops out at
    /// 20000). Applied to the next frame without reopening the encoder.
    pub fn set_bitrate_kbps(&self, kbps: u32) -> Result<(), PipelineError> {
        if !BITRATE_RANGE.contains(&kbps) {
            return Err(PipelineError::InvalidSetting(format!(
                "bitrate {kbps} kbit/s is outside {BITRATE_RANGE:?}"
            )));
        }
        self.shared.bitrate_kbps.store(kbps, Relaxed);
        Ok(())
    }

    /// Set the frame-rate ceiling (1 to 240): the minimum interval between captures.
    pub fn set_max_fps(&self, fps: u32) -> Result<(), PipelineError> {
        if !FPS_RANGE.contains(&fps) {
            return Err(PipelineError::InvalidSetting(format!(
                "fps {fps} is outside {FPS_RANGE:?}"
            )));
        }
        self.shared.max_fps.store(fps, Relaxed);
        Ok(())
    }

    /// Make the next encoded frame an IDR. Works on an idle display too: it also forces a
    /// full capture, and re-sends the current cursor shape. Use it when a client connects
    /// or reports lost frames.
    pub fn request_idr(&self) {
        self.shared.idr_epoch.fetch_add(1, Relaxed);
    }

    /// Ask the display to switch to `size` (the client window). Frames change size once the
    /// display has switched; a refusal is counted in [`StatsSnapshot::errors`].
    pub fn request_resize(&self, size: Size) -> Result<(), PipelineError> {
        if size.width == 0 || size.height == 0 || size.width > 0xffff || size.height > 0xffff {
            return Err(PipelineError::InvalidSetting(format!(
                "size {}x{} is out of range",
                size.width, size.height
            )));
        }
        self.shared.resize.store(
            u64::from(size.width) << 32 | u64::from(size.height),
            Relaxed,
        );
        Ok(())
    }

    /// Statistics so far.
    pub fn stats(&self) -> StatsSnapshot {
        self.shared.stats.snapshot()
    }

    /// The most recent recoverable error message, if any.
    pub fn last_error(&self) -> Option<String> {
        self.shared.last_error.lock().ok().and_then(|g| g.clone())
    }

    /// Why the pipeline stopped on its own, if it did.
    pub fn fatal_error(&self) -> Option<String> {
        self.shared.fatal.lock().ok().and_then(|g| g.clone())
    }

    /// False once the pipeline has been told to stop or a thread failed.
    pub fn is_running(&self) -> bool {
        !self.shared.stopped()
    }
}

struct ConvJob {
    yuv: YuvFrame,
    meta: FrameMeta,
}

/// A running capture, convert and encode pipeline.
pub struct Pipeline {
    shared: Arc<Shared>,
    frames: Receiver<EncodedFrame>,
    cursor: Receiver<CursorEvent>,
    threads: Vec<(&'static str, JoinHandle<()>)>,
}

impl Pipeline {
    /// Start against an X11 display ([`X11Config::display`], else `$DISPLAY`).
    pub fn start_x11(cfg: PipelineConfig) -> Result<Self, PipelineError> {
        let cap = X11Capture::connect(&cfg.capture)?;
        Self::start(Box::new(cap), cfg)
    }

    /// Start with any capture backend. The encoder is created here, so a bad setting or a
    /// missing codec is reported before any thread runs.
    pub fn start(capture: Box<dyn Capture>, cfg: PipelineConfig) -> Result<Self, PipelineError> {
        if !FPS_RANGE.contains(&cfg.max_fps) {
            return Err(PipelineError::InvalidSetting(format!(
                "max_fps {} is outside {FPS_RANGE:?}",
                cfg.max_fps
            )));
        }
        let queue_depth = cfg.queue_depth.max(1);
        let output_depth = cfg.output_depth.max(1);
        let (w, h) = even_size(capture.size().width, capture.size().height);
        let mut enc_cfg = cfg.encoder.clone();
        enc_cfg.width = w;
        enc_cfg.height = h;
        enc_cfg.fps = cfg.max_fps;
        let encoder = X264Encoder::new(enc_cfg.clone())?;

        let shared = Arc::new(Shared {
            stop: AtomicBool::new(false),
            bitrate_kbps: AtomicU32::new(enc_cfg.bitrate_kbps),
            max_fps: AtomicU32::new(cfg.max_fps),
            idr_epoch: AtomicU64::new(0),
            resize: AtomicU64::new(0),
            fatal: Mutex::new(None),
            last_error: Mutex::new(None),
            stats: Stats::new([queue_depth, queue_depth, output_depth]),
        });

        let (conv_tx, conv_rx) = bounded::<Frame>(queue_depth);
        let (enc_tx, enc_rx) = bounded::<ConvJob>(queue_depth);
        let (out_tx, out_rx) = bounded::<EncodedFrame>(output_depth);
        let (cursor_tx, cursor_rx) = bounded::<CursorEvent>(CURSOR_QUEUE);
        let pool = queue_depth + 2;
        let (yuv_tx, yuv_rx) = bounded::<YuvFrame>(pool);
        for _ in 0..pool {
            let _ = yuv_tx.try_send(YuvFrame::new(enc_cfg.format, w, h)?);
        }

        let mut threads = Vec::new();
        let mut spawn = |name: &'static str, body: Box<dyn FnOnce() + Send>| {
            std::thread::Builder::new()
                .name(format!("hx-{name}"))
                .spawn(body)
                .map(|h| threads.push((name, h)))
                .map_err(PipelineError::Spawn)
        };
        let result = (|| {
            spawn(
                "capture",
                run(&shared, "capture", {
                    let sh = shared.clone();
                    move || capture_loop(capture, &sh, cfg.max_fps, &conv_tx, &cursor_tx)
                }),
            )?;
            spawn(
                "convert",
                run(&shared, "convert", {
                    let sh = shared.clone();
                    let format = enc_cfg.format;
                    move || convert_loop(&sh, format, &conv_rx, &yuv_rx, &enc_tx)
                }),
            )?;
            spawn(
                "encode",
                run(&shared, "encode", {
                    let sh = shared.clone();
                    move || encode_loop(encoder, &sh, &enc_rx, &yuv_tx, &out_tx)
                }),
            )
        })();
        let mut pipeline = Pipeline {
            shared,
            frames: out_rx,
            cursor: cursor_rx,
            threads,
        };
        match result {
            Ok(()) => Ok(pipeline),
            Err(e) => {
                pipeline.stop_and_join();
                Err(e)
            }
        }
    }

    /// Encoded frames, in order. Disconnects when the pipeline stops.
    pub fn frames(&self) -> &Receiver<EncodedFrame> {
        &self.frames
    }

    /// Cursor shape and position events for the cursor channel.
    pub fn cursor_events(&self) -> &Receiver<CursorEvent> {
        &self.cursor
    }

    /// A clonable handle for control and statistics.
    pub fn control(&self) -> Control {
        Control {
            shared: self.shared.clone(),
        }
    }

    /// Statistics so far.
    pub fn stats(&self) -> StatsSnapshot {
        self.shared.stats.snapshot()
    }

    fn stop_and_join(&mut self) {
        self.shared.stop.store(true, Relaxed);
        for (name, handle) in self.threads.drain(..) {
            if handle.join().is_err() {
                self.shared.fail(format!("the {name} thread panicked"));
            }
        }
    }

    /// Stop all threads, wait for them, and return the final statistics. An error means a
    /// thread had already stopped on an unrecoverable error (or panicked).
    pub fn shutdown(mut self) -> Result<StatsSnapshot, PipelineError> {
        self.stop_and_join();
        let stats = self.shared.stats.snapshot();
        let fatal = self.shared.fatal.lock().ok().and_then(|g| g.clone());
        match fatal {
            Some(msg) => Err(PipelineError::Failed(msg)),
            None => Ok(stats),
        }
    }
}

impl Drop for Pipeline {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

/// Wrap a thread body: its error stops the whole pipeline and is recorded.
fn run(
    shared: &Arc<Shared>,
    name: &'static str,
    body: impl FnOnce() -> Result<(), PipelineError> + Send + 'static,
) -> Box<dyn FnOnce() + Send> {
    let sh = shared.clone();
    Box::new(move || {
        if let Err(e) = body() {
            sh.fail(format!("{name}: {e}"));
        }
    })
}

/// Send, giving up only when the pipeline is stopping or the receiver is gone.
fn send<T>(tx: &Sender<T>, mut item: T, sh: &Shared) -> bool {
    loop {
        match tx.send_timeout(item, IDLE_POLL) {
            Ok(()) => return true,
            Err(SendTimeoutError::Timeout(back)) => {
                if sh.stopped() {
                    return false;
                }
                item = back;
            }
            Err(SendTimeoutError::Disconnected(_)) => return false,
        }
    }
}

/// Receive the next item, or `None` when the pipeline is stopping or the sender is gone.
fn recv<T>(rx: &Receiver<T>, sh: &Shared) -> Option<T> {
    loop {
        match rx.recv_timeout(IDLE_POLL) {
            Ok(v) => return Some(v),
            Err(RecvTimeoutError::Timeout) => {
                if sh.stopped() {
                    return None;
                }
            }
            Err(RecvTimeoutError::Disconnected) => return None,
        }
    }
}

fn capture_loop(
    mut cap: Box<dyn Capture>,
    sh: &Shared,
    max_fps: u32,
    conv_tx: &Sender<Frame>,
    cursor_tx: &Sender<CursorEvent>,
) -> Result<(), PipelineError> {
    // Recoverable display errors are counted and retried; a lost display ends the pipeline.
    let soft = |e: CaptureError| -> Result<(), PipelineError> {
        if e.is_fatal() {
            return Err(e.into());
        }
        sh.soft_error(&e);
        std::thread::sleep(ERROR_BACKOFF);
        Ok(())
    };
    let mut pacer = Pacer::new(max_fps);
    let (mut idr_seen, mut fps_seen) = (0u64, max_fps);
    // The first frame, so a consumer always starts from a full picture.
    cap.force_full_frame();
    while !sh.stopped() {
        let epoch = sh.idr_epoch.load(Relaxed);
        if epoch != idr_seen {
            idr_seen = epoch;
            cap.force_full_frame();
            if let Err(e) = cap.refresh_cursor() {
                soft(e)?;
            }
        }
        let fps = sh.max_fps.load(Relaxed);
        if fps != fps_seen {
            fps_seen = fps;
            pacer.set_max_fps(fps);
        }
        let want = sh.resize.swap(0, Relaxed);
        if want != 0 {
            let size = Size::new((want >> 32) as u32, (want & 0xffff_ffff) as u32);
            if let Err(e) = cap.request_resize(size) {
                soft(e)?;
            }
        }
        cap.drain_cursor(&mut |ev| {
            // A full queue means the consumer is behind; stale cursor movement is dropped.
            let _ = cursor_tx.try_send(ev);
        });

        match pacer.decide(mono_ns(), cap.damage_pending()) {
            Decision::Capture => {
                let t0 = mono_ns();
                match cap.grab(GRAB_BUFFER_WAIT) {
                    Ok(Some(frame)) => {
                        let t1 = frame.t_capture_ns();
                        pacer.on_capture(t1);
                        sh.stats.record_capture(
                            t1.saturating_sub(frame.t_damage_ns()),
                            t1.saturating_sub(t0),
                        );
                        if !send(conv_tx, frame, sh) {
                            return Ok(());
                        }
                        sh.stats
                            .record_queue(QueueId::CaptureToConvert, conv_tx.len());
                    }
                    Ok(None) => {
                        if cap.damage_pending() {
                            sh.stats.buffer_waits.fetch_add(1, Relaxed);
                        }
                    }
                    Err(e) => soft(e)?,
                }
            }
            Decision::Wait(d) => {
                if let Err(e) = cap.wait(Some(d)) {
                    soft(e)?;
                }
            }
            Decision::Idle => {
                if let Err(e) = cap.wait(Some(IDLE_POLL)) {
                    soft(e)?;
                }
            }
        }
    }
    Ok(())
}

fn convert_loop(
    sh: &Shared,
    format: hx_codec::encode::YuvFormat,
    rx: &Receiver<Frame>,
    yuv_pool: &Receiver<YuvFrame>,
    tx: &Sender<ConvJob>,
) -> Result<(), PipelineError> {
    let mut failures = 0u32;
    while let Some(frame) = recv(rx, sh) {
        let (w, h) = even_size(frame.size().width, frame.size().height);
        let mut yuv = match yuv_pool.try_recv() {
            Ok(y) if (y.width(), y.height()) == (w, h) => y,
            // First frame after a resize (or an empty pool): allocate for the new size.
            _ => match YuvFrame::new(format, w, h) {
                Ok(y) => y,
                Err(e) => {
                    sh.soft_error(&e);
                    continue;
                }
            },
        };
        let t0 = mono_ns();
        if let Err(e) = convert_bgrx(frame.data(), frame.stride(), &mut yuv) {
            sh.soft_error(&e);
            failures += 1;
            if failures >= MAX_CONSECUTIVE_ERRORS {
                return Err(e.into());
            }
            continue;
        }
        failures = 0;
        let t1 = mono_ns();
        sh.stats.record_convert(t1.saturating_sub(t0));
        let meta = FrameMeta {
            t_damage_ns: frame.t_damage_ns(),
            t_capture_ns: frame.t_capture_ns(),
            t_convert_ns: t1,
        };
        // Give the capture buffer back before the (possibly blocking) hand-off.
        drop(frame);
        if !send(tx, ConvJob { yuv, meta }, sh) {
            break;
        }
        sh.stats.record_queue(QueueId::ConvertToEncode, tx.len());
    }
    Ok(())
}

fn encode_loop(
    mut enc: X264Encoder,
    sh: &Shared,
    rx: &Receiver<ConvJob>,
    yuv_pool: &Sender<YuvFrame>,
    tx: &Sender<EncodedFrame>,
) -> Result<(), PipelineError> {
    let mut idr_seen = 0u64;
    let mut failures = 0u32;
    while let Some(job) = recv(rx, sh) {
        let mut step = || -> Result<Option<EncodedFrame>, EncodeError> {
            let epoch = sh.idr_epoch.load(Relaxed);
            if epoch != idr_seen {
                idr_seen = epoch;
                enc.request_idr();
            }
            let kbps = sh.bitrate_kbps.load(Relaxed);
            if kbps != enc.config().bitrate_kbps {
                enc.set_bitrate_kbps(kbps)?;
            }
            let fps = sh.max_fps.load(Relaxed);
            if fps != enc.config().fps {
                enc.set_fps(fps)?;
            }
            if (job.yuv.width(), job.yuv.height()) != (enc.config().width, enc.config().height) {
                enc.resize(job.yuv.width(), job.yuv.height())?;
            }
            enc.encode(&job.yuv, &job.meta)
        };
        let result = step();
        // Return the picture to the pool whatever happened.
        let _ = yuv_pool.try_send(job.yuv);
        match result {
            Ok(Some(frame)) => {
                failures = 0;
                let t = frame.timing;
                sh.stats.record_frame(
                    t.t_encode_end_ns.saturating_sub(t.t_encode_start_ns),
                    t.t_encode_end_ns.saturating_sub(t.t_damage_ns),
                    frame.bytes().len(),
                    frame.keyframe,
                    frame.idr,
                );
                if !send(tx, frame, sh) {
                    break;
                }
                sh.stats.record_queue(QueueId::EncodeToOutput, tx.len());
            }
            Ok(None) => {}
            Err(e) => {
                sh.soft_error(&e);
                failures += 1;
                if failures >= MAX_CONSECUTIVE_ERRORS {
                    return Err(e.into());
                }
            }
        }
    }
    Ok(())
}
