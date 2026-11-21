//! The runtime of one live link: its threads, queues and the glue to the pipeline, the
//! congestion controller, the input gate and the clipboard (`docs/ipc.md` sections 12 to 20).
//!
//! ```text
//!  gateway ──ctl──► [ctl reader] ── input/mouse ──► InputGate (XTest)       (never waits for video)
//!                        │  start/stop/reconfigure/idr ──► [engine] ── Pipeline start/stop, controller poll,
//!                        │                                   stats, resize pacing, media-lane probe
//!                        └─ feedback ──► CongestionController ──► Control (bitrate, fps, IDR), cancel_frames
//!  gateway ◄─ctl── [ctl writer] ◄── CtlOut (bounded, positions latest-wins) ◄── cursor, events, stats, pong
//!  gateway ◄─media─ [media writer] ◄── Pipeline::frames (bounded: a blocked write stalls the encoder)
//!  gateway ◄─bulk─► [bulk reader] / clipboard watcher (transfers)
//! ```
//!
//! Every queue is bounded: the pipeline's own queues, [`CtlOut`], the engine command queue, and
//! the transfer buffers (one clipboard of at most 64 MiB, files go straight to disk). When any
//! thread ends for any reason the whole link closes, the threads wind down, and the supervisor
//! injects `release_all`, stops the pipeline and withdraws the clipboard (section 12.4).

use super::SessionConfig;
use super::bulk;
use super::convert;
use super::io::{CtlOut, LaneError, LaneReader, session_policy, write_all};
use crate::clipboard::ClipboardManager;
use crate::congestion::{
    AckOutcome, Actions, BandwidthCap, CongestionConfig, CongestionController, FrameAck,
    FrameDisposition,
};
use crate::input::InputGate;
use crate::pipeline::{Control, Pipeline};
use crate::stats::StatsSnapshot;
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, bounded};
use hx_capture::clipboard::Selection;
use hx_capture::{CursorEvent, Size, X11Input, mono_ns};
use hx_codec::EncodedFrame;
use hx_ipc::link::budget::{RateWindow, limits};
use hx_ipc::link::frames::{LinkFrame, encode_session_message, encode_video_prefix, parse};
use hx_ipc::link::{Lane, pb};
use hx_ipc::text::sanitize_text;
use hx_proto::datagram::MouseMove;
use hx_proto::order::serial_gt;
use hx_proto::pb as hx;
use std::collections::VecDeque;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant};

/// The 8 + 16 byte preamble negotiated a link; the minor decides nothing in 1.0.
pub(crate) struct Lanes {
    pub ctl: UnixStream,
    pub media: UnixStream,
    pub bulk: UnixStream,
}

/// Commands for the engine thread (everything that starts, stops or changes the pipeline runs
/// there, so the control reader stays responsive).
pub(crate) enum Cmd {
    Start { cfg: pb::StreamConfig },
    Stop { epoch: u32 },
    Reconfigure(pb::StreamConfig),
}

/// State shared between the media writer, the control reader and the engine, behind one lock so
/// that frame numbering, the resync gate and the epoch boundary are decided atomically.
pub(crate) struct CcState {
    pub cc: CongestionController,
    /// The number the next encoded frame gets (counts every frame taken from the pipeline).
    pub next_frame: u32,
    /// Frames numbered before this belong to an earlier client: their feedback is discarded.
    pub epoch_start: u32,
    /// `StreamConfig.max_fps` of the current client (0: none).
    pub fps_ceiling: u32,
    pub idr_pending: bool,
    pub last_idr: Option<Instant>,
    cancel_rl: RateWindow,
}

/// A running pipeline and the receivers of its outputs.
pub(crate) struct StreamRt {
    pub generation: u64,
    pub control: Control,
    pub frames: Receiver<EncodedFrame>,
    pub cursor: Receiver<CursorEvent>,
    pipeline: Mutex<Option<Pipeline>>,
}

impl StreamRt {
    fn stop(&self) {
        let p = self.pipeline.lock().ok().and_then(|mut g| g.take());
        if let Some(p) = p {
            let _ = p.shutdown();
        }
    }
}

/// Everything the threads of one link share.
pub(crate) struct LinkCtx {
    pub cfg: Arc<SessionConfig>,
    pub closed: AtomicBool,
    reason: Mutex<Option<String>>,
    lanes: Mutex<Vec<UnixStream>>,
    pub out: CtlOut,
    pub bulk_tx: Mutex<UnixStream>,
    pub next_tid: AtomicU32,
    pub aborted_out: Mutex<VecDeque<u32>>,
    pub received: Arc<super::received::ReceivedStore>,
    pub manager: Option<Arc<ClipboardManager>>,
    pub clipboard_on: AtomicBool,
    pub files_on: AtomicBool,
    cmd_tx: Sender<Cmd>,
    pub epoch: AtomicU32,
    pub started: AtomicBool,
    pub state: Mutex<CcState>,
    stream: RwLock<Option<Arc<StreamRt>>>,
    generation: AtomicU64,
    events_rl: Mutex<RateWindow>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Closes the link when the owning thread ends, however it ends.
struct CloseGuard(Arc<LinkCtx>);

impl Drop for CloseGuard {
    fn drop(&mut self) {
        let why = if std::thread::panicking() {
            "a link thread panicked"
        } else {
            "a link thread ended"
        };
        self.0.close(why);
    }
}

impl LinkCtx {
    /// Builds the context of a link whose three lanes are connected.
    pub(crate) fn new(
        cfg: Arc<SessionConfig>,
        received: Arc<super::received::ReceivedStore>,
        lanes: &Lanes,
    ) -> std::io::Result<(Arc<Self>, Receiver<Cmd>)> {
        let (cmd_tx, cmd_rx) = bounded(32);
        let manager = match &cfg.clipboard {
            Some(settings) => ClipboardManager::start(settings.clone()).ok().map(Arc::new),
            None => None,
        };
        let now = mono_ns();
        let ctx = Arc::new(Self {
            closed: AtomicBool::new(false),
            reason: Mutex::new(None),
            lanes: Mutex::new(vec![
                lanes.ctl.try_clone()?,
                lanes.media.try_clone()?,
                lanes.bulk.try_clone()?,
            ]),
            out: CtlOut::new(),
            bulk_tx: Mutex::new(lanes.bulk.try_clone()?),
            next_tid: AtomicU32::new(2),
            aborted_out: Mutex::new(VecDeque::new()),
            received,
            manager,
            clipboard_on: AtomicBool::new(false),
            files_on: AtomicBool::new(false),
            cmd_tx,
            epoch: AtomicU32::new(0),
            started: AtomicBool::new(false),
            state: Mutex::new(CcState {
                cc: CongestionController::new(CongestionConfig::default(), now),
                next_frame: 0,
                epoch_start: 0,
                fps_ceiling: 0,
                idr_pending: false,
                last_idr: None,
                cancel_rl: RateWindow::per_second(limits::CANCEL_FRAMES),
            }),
            stream: RwLock::new(None),
            generation: AtomicU64::new(0),
            events_rl: Mutex::new(RateWindow::per_second(limits::EVENT)),
            cfg,
        });
        Ok((ctx, cmd_rx))
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Relaxed)
    }

    /// Closes all three lanes; every thread notices within its poll interval. Idempotent.
    pub(crate) fn close(&self, why: &str) {
        if self.closed.swap(true, Relaxed) {
            return;
        }
        *lock(&self.reason) = Some(sanitize_text(why, 200));
        for s in lock(&self.lanes).iter() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
        self.out.wake();
    }

    /// Why the link closed (for the log).
    pub(crate) fn reason(&self) -> String {
        lock(&self.reason).clone().unwrap_or_default()
    }

    /// Queues one session message on `ctl`. A full queue means the gateway stopped reading:
    /// the link closes.
    pub(crate) fn send_msg(&self, m: pb::session_to_gateway::Message) -> bool {
        let msg = pb::SessionToGateway { message: Some(m) };
        match encode_session_message(&msg) {
            Ok(f) => {
                if self.out.push(f).is_err() {
                    self.close("ctl output queue full");
                    return false;
                }
                true
            }
            Err(_) => false,
        }
    }

    /// An `event` for the gateway's log (at most 10 per second; text sanitised and cut).
    pub(crate) fn event(&self, kind: pb::EventKind, message: &str) {
        if !lock(&self.events_rl).allow(Instant::now()) {
            return;
        }
        self.send_msg(pb::session_to_gateway::Message::Event(pb::Event {
            kind: kind as i32,
            message: sanitize_text(message, 256),
        }));
    }

    /// Orderly end: a `goodbye`, a moment for the writer to flush it, then close.
    pub(crate) fn goodbye_and_close(&self, code: u32, message: &str) {
        self.send_msg(pb::session_to_gateway::Message::Goodbye(pb::Goodbye {
            code,
            message: sanitize_text(message, 256),
        }));
        std::thread::sleep(Duration::from_millis(150));
        self.close("session shutting down");
    }

    fn command(&self, c: Cmd) -> Result<(), &'static str> {
        self.cmd_tx
            .try_send(c)
            .map_err(|_| "engine command queue overflow")
    }

    pub(crate) fn stream(&self) -> Option<Arc<StreamRt>> {
        self.stream.read().ok().and_then(|g| g.clone())
    }

    fn same_stream(&self, rt: &Arc<StreamRt>) -> bool {
        self.stream
            .read()
            .ok()
            .is_some_and(|g| g.as_ref().is_some_and(|c| Arc::ptr_eq(c, rt)))
    }

    fn stop_stream(&self) {
        let rt = self.stream.write().ok().and_then(|mut g| g.take());
        if let Some(rt) = rt {
            rt.stop();
        }
    }

    /// Wants an IDR (a gateway `request_idr`, or the controller's resync).
    pub(crate) fn request_idr(&self) {
        lock(&self.state).idr_pending = true;
    }

    /// Carries out controller actions on the pipeline and the link.
    fn apply_actions(&self, rt: &StreamRt, a: &Actions) {
        let mut st = lock(&self.state);
        if let Some(k) = a.bitrate_kbps {
            let _ = rt.control.set_bitrate_kbps(k.clamp(100, 100_000));
        }
        if let Some(f) = a.max_fps {
            let f = if st.fps_ceiling != 0 {
                f.min(st.fps_ceiling)
            } else {
                f
            };
            let _ = rt.control.set_max_fps(f.clamp(1, 240));
        }
        if a.resync {
            st.idr_pending = true;
        }
        // The controller lists in-flight frames oldest first: cancel everything up to the newest.
        if let Some(&last) = a.cancel.last()
            && st.cancel_rl.allow(Instant::now())
        {
            drop(st);
            self.send_msg(pb::session_to_gateway::Message::CancelFrames(
                pb::CancelFrames { up_to_frame: last },
            ));
        }
    }
}

// ----- thread entry points -----

/// Runs a link until it closes. `desktop` serialises links: a superseding link waits for the old
/// one's teardown before it touches the display.
pub(crate) fn run(ctx: Arc<LinkCtx>, cmd_rx: Receiver<Cmd>, lanes: Lanes, desktop: &Mutex<()>) {
    let _desk = lock(desktop);
    if ctx.is_closed() {
        return;
    }
    let setup = (|| -> std::io::Result<_> {
        let stall = ctx.cfg.write_stall;
        lanes.ctl.set_write_timeout(Some(stall))?;
        lanes.media.set_write_timeout(Some(stall))?;
        lanes.bulk.set_write_timeout(Some(stall))?;
        let ctl_r = LaneReader::new(
            lanes.ctl.try_clone()?,
            Lane::Ctl,
            session_policy(Lane::Ctl),
            Some(ctx.cfg.gateway_silence),
        )?;
        let bulk_r = LaneReader::new(
            lanes.bulk.try_clone()?,
            Lane::Bulk,
            session_policy(Lane::Bulk),
            None,
        )?;
        let media_probe = LaneReader::new(
            lanes.media.try_clone()?,
            Lane::Media,
            session_policy(Lane::Media),
            None,
        )?;
        Ok((ctl_r, bulk_r, media_probe))
    })();
    let Ok((ctl_r, bulk_r, media_probe)) = setup else {
        ctx.close("cannot set up the lanes");
        return;
    };
    let mut handles = Vec::new();
    let mut spawn = |name: &str, f: Box<dyn FnOnce(Arc<LinkCtx>) + Send>| {
        let c = ctx.clone();
        match std::thread::Builder::new()
            .name(format!("hx-link-{name}"))
            .spawn(move || {
                let _g = CloseGuard(c.clone());
                f(c);
            }) {
            Ok(h) => handles.push(h),
            Err(_) => ctx.close("cannot start a link thread"),
        }
    };
    spawn("ctl-rx", Box::new(move |c| ctl_loop(&c, ctl_r)));
    let ctl_w = lanes.ctl;
    spawn("ctl-tx", Box::new(move |c| ctl_writer(&c, &ctl_w)));
    let media_w = lanes.media;
    spawn("media", Box::new(move |c| media_loop(&c, &media_w)));
    spawn(
        "engine",
        Box::new(move |c| engine_loop(&c, &cmd_rx, media_probe)),
    );
    spawn("cursor", Box::new(move |c| cursor_loop(&c)));
    spawn("bulk-rx", Box::new(move |c| bulk::reader_loop(&c, bulk_r)));
    if ctx.manager.is_some() {
        spawn("clipboard", Box::new(|c| bulk::clipboard_loop(&c)));
    }
    for h in handles {
        let _ = h.join();
    }
    // Link loss (section 12.4): capture and encoding stop, the clipboard offer is withdrawn.
    ctx.stop_stream();
    if let Some(m) = &ctx.manager {
        let _ = m.withdraw(Selection::Clipboard);
    }
}

fn ctl_writer(ctx: &Arc<LinkCtx>, stream: &UnixStream) {
    while !ctx.is_closed() {
        if let Some(f) = ctx.out.next(Duration::from_millis(100), &ctx.closed)
            && write_all(stream, &f).is_err()
        {
            ctx.close("ctl write stalled or failed");
        }
    }
}

// ----- control reader -----

fn ctl_loop(ctx: &Arc<LinkCtx>, mut reader: LaneReader) {
    let mut gate = X11Input::connect(ctx.cfg.display.as_deref())
        .ok()
        .map(|i| InputGate::new(i, ctx.cfg.input));
    let mut unknown = RateWindow::per_second(limits::UNKNOWN_VARIANTS);
    loop {
        let raw = match reader.next(&ctx.closed) {
            Ok(r) => r,
            Err(LaneError::Closed) => break,
            Err(e) => {
                ctx.close(&format!("ctl lane: {}", e.text()));
                break;
            }
        };
        let result = match parse(reader.policy(), raw, ctx.cfg.max_file_bytes) {
            Ok(LinkFrame::FromGateway(m)) => handle_ctl(ctx, &mut gate, m),
            Ok(LinkFrame::UnknownVariant) => {
                if unknown.allow(Instant::now()) {
                    Ok(())
                } else {
                    Err("too many frames of unknown variants".to_owned())
                }
            }
            Ok(_) => Err("unexpected frame on ctl".to_owned()),
            Err(e) => Err(e.to_string()),
        };
        if let Err(why) = result {
            ctx.close(&format!("ctl lane violation: {why}"));
            break;
        }
    }
    // Section 12.4: every held key and button goes up when the link ends.
    if let Some(g) = &mut gate {
        let _ = g.on_disconnect();
    }
}

fn handle_ctl(
    ctx: &Arc<LinkCtx>,
    gate: &mut Option<InputGate<X11Input>>,
    m: pb::GatewayToSession,
) -> Result<(), String> {
    use pb::gateway_to_session::Message as M;
    let Some(m) = m.message else { return Ok(()) };
    match m {
        M::Start(s) => {
            ctx.epoch.store(s.epoch, Relaxed);
            ctx.started.store(true, Relaxed);
            ctx.command(Cmd::Start {
                cfg: s.config.unwrap_or_default(),
            })?;
        }
        M::Stop(s) => {
            // A stop of an earlier client (after a takeover) must not stop the new one.
            if ctx.started.load(Relaxed) && s.epoch == ctx.epoch.load(Relaxed) {
                ctx.started.store(false, Relaxed);
                if let Some(g) = gate {
                    let _ = g.on_focus_lost();
                }
                ctx.command(Cmd::Stop { epoch: s.epoch })?;
            }
        }
        M::Reconfigure(r) => {
            if ctx.started.load(Relaxed) {
                ctx.command(Cmd::Reconfigure(r.config.unwrap_or_default()))?;
            }
        }
        M::RequestIdr(r) => {
            if ctx.started.load(Relaxed) && r.epoch == ctx.epoch.load(Relaxed) {
                ctx.request_idr();
            }
        }
        M::Input(ev) => {
            if let Some(g) = gate {
                match g.on_input(mono_ns(), &ev) {
                    Ok(_) => {}
                    Err(e) if e.is_fatal() => {
                        ctx.event(pb::EventKind::Fatal, "the display connection was lost");
                        return Err("display lost".to_owned());
                    }
                    // Rate-limited or refused input is dropped and counted by the gate.
                    Err(_) => {}
                }
            }
        }
        M::Mouse(mv) => {
            if let Some(g) = gate {
                let m = MouseMove {
                    relative: mv.relative,
                    seq: mv.seq,
                    x: mv.x,
                    y: mv.y,
                };
                if let Err(e) = g.on_mouse_move(mono_ns(), &m)
                    && e.is_fatal()
                {
                    ctx.event(pb::EventKind::Fatal, "the display connection was lost");
                    return Err("display lost".to_owned());
                }
            }
        }
        M::FrameFeedback(f) => on_feedback(ctx, &f),
        M::TransportStats(t) => {
            if t.rtt_us > 0 {
                lock(&ctx.state)
                    .cc
                    .on_rtt_sample(mono_ns(), Duration::from_micros(u64::from(t.rtt_us)));
            }
        }
        M::ClientStats(_) => {}
        M::Ping(p) => {
            ctx.send_msg(pb::session_to_gateway::Message::Pong(pb::Pong {
                nonce: p.nonce,
            }));
        }
        M::Goodbye(_) => return Err("the gateway said goodbye".to_owned()),
    }
    Ok(())
}

/// Turns the gateway's per-frame results into controller acks (feedback for frames of an
/// earlier client is discarded) and carries out what the controller decides.
fn on_feedback(ctx: &Arc<LinkCtx>, f: &pb::FrameFeedback) {
    let now = mono_ns();
    let mut merged = Actions::default();
    {
        let mut st = lock(&ctx.state);
        for r in &f.results {
            if serial_gt(st.epoch_start, r.frame_number) {
                continue;
            }
            let outcome = match pb::FrameOutcome::try_from(r.outcome) {
                Ok(pb::FrameOutcome::Delivered) => AckOutcome::Delivered,
                Ok(pb::FrameOutcome::Rejected) => AckOutcome::Rejected,
                // The gateway dropped it unsent: the same loss as a cancel for the decode chain.
                Ok(pb::FrameOutcome::Cancelled | pb::FrameOutcome::Dropped) => {
                    AckOutcome::Cancelled
                }
                _ => continue,
            };
            let a = st.cc.on_frame_ack(
                now,
                FrameAck {
                    frame_number: r.frame_number,
                    bytes: r.bytes as usize,
                    elapsed: Duration::from_micros(u64::from(r.elapsed_us)),
                    outcome,
                },
            );
            merged.bitrate_kbps = a.bitrate_kbps.or(merged.bitrate_kbps);
            merged.max_fps = a.max_fps.or(merged.max_fps);
            merged.resync |= a.resync;
            merged.cancel.extend(a.cancel);
        }
    }
    if !merged.is_empty()
        && let Some(rt) = ctx.stream()
    {
        ctx.apply_actions(&rt, &merged);
    }
}

// ----- engine -----

struct Engine {
    prev_stats: StatsSnapshot,
    last_stats: Instant,
    seen_gen: u64,
    fatal_sent: bool,
    pending_resize: Option<(u32, u32)>,
    last_resize: Option<Instant>,
    resize_check: Option<(u64, Instant)>,
}

fn engine_loop(ctx: &Arc<LinkCtx>, rx: &Receiver<Cmd>, mut media_probe: LaneReader) {
    let mut e = Engine {
        prev_stats: StatsSnapshot::default(),
        last_stats: Instant::now(),
        seen_gen: 0,
        fatal_sent: false,
        pending_resize: None,
        last_resize: None,
        resize_check: None,
    };
    while !ctx.is_closed() {
        let wait = if ctx.stream().is_some() {
            lock(&ctx.state)
                .cc
                .next_poll()
                .min(Duration::from_millis(20))
        } else {
            Duration::from_millis(100)
        };
        match rx.recv_timeout(wait) {
            Ok(cmd) => e.handle(ctx, cmd),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        // Drain what queued behind it without waiting again.
        while let Ok(cmd) = rx.try_recv() {
            e.handle(ctx, cmd);
        }
        e.tick(ctx);
        // The gateway to session direction of `media` is silent: anything there is a violation,
        // and an end of stream means the gateway dropped the link.
        if media_probe.readable_now() {
            match media_probe.next(&ctx.closed) {
                Err(LaneError::Closed) => break,
                Err(err) => {
                    ctx.close(&format!("media lane: {}", err.text()));
                    break;
                }
                Ok(_) => {}
            }
        }
    }
}

impl Engine {
    fn handle(&mut self, ctx: &Arc<LinkCtx>, cmd: Cmd) {
        match cmd {
            Cmd::Start { cfg } => self.start(ctx, &cfg),
            Cmd::Stop { epoch } => {
                // A stop that is not for the current client was already filtered by the reader;
                // a start that arrived after it wins.
                if ctx.epoch.load(Relaxed) == epoch && !ctx.started.load(Relaxed) {
                    ctx.stop_stream();
                    self.pending_resize = None;
                }
            }
            Cmd::Reconfigure(cfg) => self.apply_config(ctx, &cfg, false),
        }
    }

    fn start(&mut self, ctx: &Arc<LinkCtx>, cfg: &pb::StreamConfig) {
        if !hx_ipc::link::validate::config_codec_supported(cfg) {
            ctx.event(pb::EventKind::CaptureError, "unsupported codec requested");
            return;
        }
        ctx.clipboard_on.store(cfg.clipboard_enabled, Relaxed);
        ctx.files_on.store(cfg.file_transfer_enabled, Relaxed);
        let now = mono_ns();
        // A new client: back to the starting rate, a resync armed, feedback for earlier frames
        // discarded (section 18).
        let actions = {
            let mut st = lock(&ctx.state);
            let a = st.cc.reset(now);
            st.epoch_start = st.next_frame;
            st.fps_ceiling = cfg.max_fps;
            st.idr_pending = false;
            a
        };
        // `bitrate_cap_kbps` 0 means automatic on a start.
        let cap = if cfg.bitrate_cap_kbps == 0 {
            BandwidthCap::Auto
        } else {
            BandwidthCap::Custom(cfg.bitrate_cap_kbps)
        };
        let cap_actions = lock(&ctx.state).cc.set_cap(cap, now);
        if let Some(rt) = ctx.stream() {
            // A takeover: keep the pipeline, send a fresh full image and the cursor shape.
            ctx.apply_actions(&rt, &actions);
            ctx.apply_actions(&rt, &cap_actions);
            rt.control.request_idr();
            lock(&ctx.state).last_idr = Some(Instant::now());
        } else {
            let (kbps, fps) = {
                let st = lock(&ctx.state);
                let fps = if st.fps_ceiling != 0 {
                    st.cc.fps().min(st.fps_ceiling)
                } else {
                    st.cc.fps()
                };
                (st.cc.kbps(), fps)
            };
            let mut pc = ctx.cfg.pipeline.clone();
            pc.capture.display = ctx.cfg.display.clone();
            pc.encoder.bitrate_kbps = kbps;
            pc.max_fps = fps.clamp(1, 240);
            match Pipeline::start_x11(pc) {
                Ok(p) => {
                    let generation = ctx.generation.fetch_add(1, Relaxed) + 1;
                    let rt = Arc::new(StreamRt {
                        generation,
                        control: p.control(),
                        frames: p.frames().clone(),
                        cursor: p.cursor_events().clone(),
                        pipeline: Mutex::new(Some(p)),
                    });
                    self.prev_stats = StatsSnapshot::default();
                    self.last_stats = Instant::now();
                    self.fatal_sent = false;
                    if let Ok(mut g) = ctx.stream.write() {
                        *g = Some(rt);
                    }
                }
                Err(e) => {
                    ctx.event(pb::EventKind::CaptureError, &e.to_string());
                    return;
                }
            }
        }
        self.apply_config(ctx, cfg, true);
    }

    /// Applies the fields of a `StreamConfig` (a zero keeps the current value, except that a
    /// start resets the cap; the two policy booleans are applied as given).
    fn apply_config(&mut self, ctx: &Arc<LinkCtx>, cfg: &pb::StreamConfig, is_start: bool) {
        if !hx_ipc::link::validate::config_codec_supported(cfg) {
            ctx.event(pb::EventKind::CaptureError, "unsupported codec requested");
            return;
        }
        if !is_start {
            ctx.clipboard_on.store(cfg.clipboard_enabled, Relaxed);
            ctx.files_on.store(cfg.file_transfer_enabled, Relaxed);
        }
        let now = mono_ns();
        let Some(rt) = ctx.stream() else { return };
        if cfg.max_fps != 0 {
            let fps = {
                let mut st = lock(&ctx.state);
                st.fps_ceiling = cfg.max_fps;
                st.cc.fps().min(cfg.max_fps)
            };
            let _ = rt.control.set_max_fps(fps.clamp(1, 240));
        }
        if !is_start && cfg.bitrate_cap_kbps != 0 {
            let a = lock(&ctx.state)
                .cc
                .set_cap(BandwidthCap::Custom(cfg.bitrate_cap_kbps), now);
            ctx.apply_actions(&rt, &a);
        }
        if cfg.width != 0 && cfg.height != 0 {
            // Rounded down to even; the encoder takes 16 to 8192 per side.
            let (w, h) = (cfg.width & !1, cfg.height & !1);
            if (16..=8192).contains(&w) && (16..=8192).contains(&h) {
                self.pending_resize = Some((w, h));
            } else {
                ctx.event(pb::EventKind::ResizeRefused, "size outside 16 to 8192");
            }
        }
        // `scale_percent` is validated and accepted but has no session-side effect in Phase 1.
        // `audio_enabled` is ignored: audio is not negotiated.
    }

    fn tick(&mut self, ctx: &Arc<LinkCtx>) {
        let Some(rt) = ctx.stream() else { return };
        let now = Instant::now();
        let actions = lock(&ctx.state).cc.poll(mono_ns());
        if !actions.is_empty() {
            ctx.apply_actions(&rt, &actions);
        }
        // IDR requests are paced: at most one per 250 ms reaches the encoder (section 13 allows
        // 4 IDR frames per second).
        {
            let mut st = lock(&ctx.state);
            if st.idr_pending
                && st
                    .last_idr
                    .is_none_or(|t| now.duration_since(t) >= Duration::from_millis(250))
            {
                st.idr_pending = false;
                st.last_idr = Some(now);
                drop(st);
                rt.control.request_idr();
            }
        }
        if let Some((w, h)) = self.pending_resize
            && self
                .last_resize
                .is_none_or(|t| now.duration_since(t) >= Duration::from_millis(500))
        {
            self.pending_resize = None;
            self.last_resize = Some(now);
            let errors = rt.control.stats().errors;
            if rt.control.request_resize(Size::new(w, h)).is_ok() {
                self.resize_check = Some((errors, now + Duration::from_secs(1)));
            }
        }
        if let Some((errors, at)) = self.resize_check
            && now >= at
        {
            self.resize_check = None;
            if rt.control.stats().errors > errors {
                ctx.event(pb::EventKind::ResizeRefused, "the display refused the size");
            }
        }
        if rt.generation != self.seen_gen {
            self.seen_gen = rt.generation;
        }
        if let Some(why) = rt.control.fatal_error()
            && !self.fatal_sent
        {
            self.fatal_sent = true;
            ctx.event(pb::EventKind::Fatal, &why);
            ctx.stop_stream();
            return;
        }
        if now.duration_since(self.last_stats) >= Duration::from_secs(1) {
            let ms =
                u32::try_from(now.duration_since(self.last_stats).as_millis()).unwrap_or(u32::MAX);
            self.last_stats = now;
            let snap = rt.control.stats();
            let depth = snap
                .queues
                .iter()
                .map(|q| u32::try_from(q.max).unwrap_or(u32::MAX))
                .max()
                .unwrap_or(0);
            let s = convert::session_stats(&self.prev_stats, &snap, ms, depth);
            self.prev_stats = snap;
            ctx.send_msg(pb::session_to_gateway::Message::Stats(s));
        }
    }
}

// ----- media writer -----

fn media_loop(ctx: &Arc<LinkCtx>, stream: &UnixStream) {
    let mut announced: Option<(u32, u32, u32, i32)> = None;
    let mut format_rl = RateWindow::per_second(limits::STREAM_FORMAT);
    // After a frame was skipped (too large) everything up to the next IDR is built on it.
    let mut broken = false;
    while !ctx.is_closed() {
        let Some(rt) = ctx.stream() else {
            std::thread::sleep(Duration::from_millis(25));
            continue;
        };
        loop {
            match rt.frames.recv_timeout(Duration::from_millis(50)) {
                Ok(frame) => {
                    if !send_frame(
                        ctx,
                        stream,
                        &frame,
                        &mut announced,
                        &mut format_rl,
                        &mut broken,
                    ) {
                        return;
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    if ctx.is_closed() || !ctx.same_stream(&rt) {
                        break;
                    }
                }
                Err(RecvTimeoutError::Disconnected) => {
                    // The pipeline stopped; the engine clears the slot, then a new one may come.
                    std::thread::sleep(Duration::from_millis(10));
                    break;
                }
            }
        }
    }
}

/// Numbers, gates, announces and writes one frame. `false` ends the thread (the link closed).
fn send_frame(
    ctx: &Arc<LinkCtx>,
    stream: &UnixStream,
    frame: &EncodedFrame,
    announced: &mut Option<(u32, u32, u32, i32)>,
    format_rl: &mut RateWindow,
    broken: &mut bool,
) -> bool {
    let (number, disposition, epoch, fps) = {
        let mut st = lock(&ctx.state);
        let n = st.next_frame;
        st.next_frame = n.wrapping_add(1);
        let fps = if st.fps_ceiling != 0 {
            st.fps_ceiling
        } else {
            ctx.cfg.pipeline.max_fps
        };
        (
            n,
            st.cc.on_frame_ready(frame.idr),
            ctx.epoch.load(Relaxed),
            fps,
        )
    };
    let mut resync = match disposition {
        FrameDisposition::Drop => return true,
        FrameDisposition::Send { resync } => resync,
    };
    if *broken && !frame.idr {
        return true;
    }
    if frame.bytes().len() as u64 > u64::from(ctx.cfg.max_frame_bytes) {
        // The encoder must stay under the link's frame limit; one that does not breaks the
        // chain, so everything is dropped up to a fresh IDR.
        *broken = true;
        ctx.request_idr();
        ctx.event(
            pb::EventKind::CaptureError,
            "an encoded frame exceeded max_frame_bytes",
        );
        return true;
    }
    if *broken {
        resync = true;
        *broken = false;
    }
    let codec = convert::wire_codec(frame.codec);
    let key = (epoch, frame.width, frame.height, codec as i32);
    if *announced != Some(key) {
        // Changes of picture size are paced to the gateway's 4 per second.
        while !format_rl.allow(Instant::now()) {
            if ctx.is_closed() {
                return false;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        ctx.send_msg(pb::session_to_gateway::Message::StreamFormat(
            pb::StreamFormat {
                epoch,
                codec: codec as i32,
                width: frame.width,
                height: frame.height,
                fps: fps.clamp(1, 240),
                first_frame: number,
            },
        ));
        *announced = Some(key);
    }
    let header = convert::media_header(frame, number, resync);
    let Ok(prefix) = encode_video_prefix(&header, ctx.cfg.max_frame_bytes) else {
        ctx.close("cannot encode a media header");
        return false;
    };
    lock(&ctx.state)
        .cc
        .on_frame_sent(mono_ns(), number, frame.bytes().len());
    if write_all(stream, &prefix).is_err() || write_all(stream, frame.bytes()).is_err() {
        ctx.close("media write stalled or failed");
        return false;
    }
    true
}

// ----- cursor -----

fn cursor_loop(ctx: &Arc<LinkCtx>) {
    let mut shape_rl = RateWindow::per_second(limits::CURSOR_SHAPES);
    let mut shape_bytes: std::collections::VecDeque<(Instant, usize)> = Default::default();
    let mut pending: Option<Arc<hx_capture::CursorShape>> = None;
    let mut shape_id = 0u64;
    while !ctx.is_closed() {
        let Some(rt) = ctx.stream() else {
            std::thread::sleep(Duration::from_millis(25));
            continue;
        };
        while !ctx.is_closed() && ctx.same_stream(&rt) {
            // A shape held back by the rate limit is retried first.
            if let Some(s) = pending.take() {
                let wire = convert::cursor_shape_to_wire(&s);
                let bytes = wire.as_ref().map_or(0, |w| w.rgba.len());
                let now = Instant::now();
                while shape_bytes
                    .front()
                    .is_some_and(|(t, _)| now.duration_since(*t) >= Duration::from_secs(1))
                {
                    shape_bytes.pop_front();
                }
                let used: usize = shape_bytes.iter().map(|(_, b)| *b).sum();
                if used + bytes > 4 * 1024 * 1024 || !shape_rl.allow(now) {
                    pending = Some(s);
                } else if let Some(w) = wire {
                    shape_bytes.push_back((now, bytes));
                    shape_id = w.id;
                    ctx.send_msg(pb::session_to_gateway::Message::Cursor(hx::CursorEvent {
                        event: Some(hx::cursor_event::Event::Shape(w)),
                    }));
                }
            }
            match rt
                .cursor
                .recv_timeout(Duration::from_millis(if pending.is_some() {
                    20
                } else {
                    50
                })) {
                Ok(CursorEvent::Shape(s)) => pending = Some(s),
                Ok(CursorEvent::Position(p)) => {
                    let msg = pb::SessionToGateway {
                        message: Some(pb::session_to_gateway::Message::Cursor(hx::CursorEvent {
                            event: Some(hx::cursor_event::Event::Position(hx::CursorPosition {
                                x: i32::from(p.x),
                                y: i32::from(p.y),
                                shape_id,
                                visible: true,
                            })),
                        })),
                    };
                    if let Ok(f) = encode_session_message(&msg) {
                        ctx.out.push_position(f);
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    std::thread::sleep(Duration::from_millis(10));
                    break;
                }
            }
        }
    }
}
