//! The relay of one attached client: its state, its tasks and the gateway's
//! [`LinkClient`](crate::gateway::desktop::LinkClient) handle.
//!
//! # Tasks (all end together on `shutdown`)
//!
//! | Task | Reads | Writes |
//! |---|---|---|
//! | video sender | [`VideoShared::queue`] | client video streams, `StreamInfo` on control |
//! | feedback | the ack buffer | `frame_feedback` (and `request_idr` after an overflow) |
//! | cursor sender | [`CursorSlot`] | the client's cursor stream |
//! | input | the client's input stream | `input` |
//! | mouse | the client's mouse datagrams | `mouse` |
//! | transfers in | the client's transfer streams | the `bulk` lane |
//! | transfers out | [`Inbox`] | client transfer streams |
//! | statistics | `SessionStats`, transport numbers | `transport_stats`, `ServerStats` |
//!
//! The link's events are not read by any of these: the **pump** ([`super::Core`]) reads them and
//! calls [`ClientRelay::deliver`], which only ever pushes into the bounded structures above and
//! never waits, so no client can slow the pump, the session or another client down.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::Relaxed};

use hx_ipc::link::pb;
use hx_proto::VideoCodec;
use hx_proto::channel::CloseCode;
use hx_proto::pb::ViewConfig;
use hx_proto::version::Features;
use hx_transport::Connection;
use tokio::sync::watch;

use super::Core;
use super::cursor::{self, CursorSlot};
use super::input::{self, InputPath};
use super::reconf::Reconf;
use super::stats::{self, StatsShared};
use super::transfer::{self, Inbox, TransferCtx};
use super::video::{self, VideoShared};
use crate::gateway::desktop::{
    AttachRequest, BoxFuture, DetachReason, LinkClient as GatewayHandle,
};
use crate::link::{CursorUpdate, FailureClass, LinkClient, LinkEvent};

const NO_GOODBYE: u32 = u32::MAX;
/// The fixed text a client gets when the link to the desktop failed: never session text.
const LINK_FAILED: &str = "the desktop connection failed";
const SESSION_ENDED: &str = "the desktop session ended";

/// One attached client.
pub(super) struct ClientRelay {
    core: Arc<Core>,
    pub(super) link: LinkClient,
    pub(super) epoch: u32,
    name: String,
    conn: Connection,
    features: Features,
    video: Arc<VideoShared>,
    cursor: Arc<CursorSlot>,
    inbox: Arc<Inbox>,
    stats: Arc<StatsShared>,
    pub(super) input: Arc<InputPath>,
    reconf: Arc<Reconf>,
    /// `ClientStats` forwarded: a client sends about one a second, the session gets at most 4.
    stats_rl: std::sync::Mutex<super::util::TokenBucket>,
    clipboard_ok: Arc<AtomicBool>,
    files_ok: Arc<AtomicBool>,
    max_file_bytes: u64,
    shutdown: watch::Sender<bool>,
    abort: watch::Sender<u64>,
    abort_clip: watch::Sender<u64>,
    abort_file: watch::Sender<u64>,
    detached: AtomicBool,
    goodbye_code: AtomicU32,
    /// Tasks that must be waited for are not tracked: they all end on `shutdown`.
    started: AtomicU64,
}

impl ClientRelay {
    pub(super) fn new(
        core: Arc<Core>,
        link: LinkClient,
        request: &AttachRequest,
        epoch: u32,
    ) -> Arc<Self> {
        let features = request.connection.enabled_features();
        let display = link.info().display;
        let (shutdown, _) = watch::channel(false);
        let (abort, _) = watch::channel(0u64);
        let (abort_clip, _) = watch::channel(0u64);
        let (abort_file, _) = watch::channel(0u64);
        Arc::new(Self {
            input: Arc::new(InputPath::new(
                link.clone(),
                request.connection.clone(),
                epoch,
                core.epoch.clone(),
                display,
            )),
            reconf: Reconf::new(link.clone()),
            stats_rl: std::sync::Mutex::new(super::util::TokenBucket::new(4, 4)),
            video: VideoShared::new(core.cfg.link.max_frame_bytes),
            cursor: Arc::new(CursorSlot::default()),
            inbox: Arc::new(Inbox::default()),
            stats: Arc::new(StatsShared::default()),
            clipboard_ok: Arc::new(AtomicBool::new(false)),
            files_ok: Arc::new(AtomicBool::new(false)),
            max_file_bytes: request
                .negotiated
                .max_file_bytes
                .min(core.cfg.link.max_file_bytes),
            name: request.device_name.clone(),
            conn: request.connection.clone(),
            features,
            link,
            epoch,
            core,
            shutdown,
            abort,
            abort_clip,
            abort_file,
            detached: AtomicBool::new(false),
            goodbye_code: AtomicU32::new(NO_GOODBYE),
            started: AtomicU64::new(0),
        })
    }

    /// Applies what a `ViewConfig` changes in the relay itself (policies, the stats switch) and
    /// returns the `StreamConfig` for the session.
    pub(super) fn apply_view(&self, view: &ViewConfig, codec: VideoCodec) -> pb::StreamConfig {
        let clipboard = view.clipboard_enabled && self.features.contains(Features::CLIPBOARD);
        let files = self.features.contains(Features::FILE_TRANSFER);
        // A policy that turns off ends what runs under it, in both directions.
        if self.clipboard_ok.swap(clipboard, Relaxed) && !clipboard {
            self.abort_clip.send_modify(|g| *g += 1);
        }
        if self.files_ok.swap(files, Relaxed) && !files {
            self.abort_file.send_modify(|g| *g += 1);
        }
        self.link.set_policy(clipboard, files);
        self.stats.on.store(
            view.stats_enabled && self.features.contains(Features::SERVER_STATS),
            Relaxed,
        );
        let size_set = view.width != 0 && view.height != 0;
        pb::StreamConfig {
            codec: codec as i32,
            max_fps: if view.max_fps <= 240 { view.max_fps } else { 0 },
            bitrate_cap_kbps: match view.bandwidth_cap_kbps {
                0 => 0,
                k => k.clamp(100, 100_000),
            },
            width: if size_set && view.width <= 16_384 && view.height <= 16_384 {
                view.width
            } else {
                0
            },
            height: if size_set && view.width <= 16_384 && view.height <= 16_384 {
                view.height
            } else {
                0
            },
            scale_percent: match view.scale_percent {
                0 => 0,
                s => s.clamp(50, 400),
            },
            audio_enabled: false,
            clipboard_enabled: clipboard,
            file_transfer_enabled: files,
        }
    }

    /// Starts the tasks. Call once, right after the relay became the desktop's active one.
    pub(super) fn start_tasks(self: &Arc<Self>) {
        if self.started.swap(1, Relaxed) != 0 {
            return;
        }
        let rx = || self.shutdown.subscribe();
        let video = self.video.clone();
        self.conn
            .set_ack_handler(Some(Arc::new(move |ack| video.on_ack(ack))));
        tokio::spawn(video::sender(self.conn.clone(), self.video.clone(), rx()));
        tokio::spawn(video::feedback_task(
            self.link.clone(),
            self.video.clone(),
            rx(),
        ));
        tokio::spawn(cursor::sender(self.conn.clone(), self.cursor.clone(), rx()));
        tokio::spawn(input::input_task(
            self.conn.clone(),
            self.input.clone(),
            rx(),
        ));
        tokio::spawn(input::mouse_task(
            self.conn.clone(),
            self.input.clone(),
            rx(),
        ));
        let tcx = TransferCtx {
            conn: self.conn.clone(),
            link: self.link.clone(),
            clipboard_ok: self.clipboard_ok.clone(),
            files_ok: self.files_ok.clone(),
            max_file_bytes: self.max_file_bytes,
            features: self.features,
            abort: self.abort.subscribe(),
            abort_clip: self.abort_clip.subscribe(),
            abort_file: self.abort_file.subscribe(),
        };
        tokio::spawn(transfer::inbound(tcx.clone(), rx()));
        tokio::spawn(transfer::outbound(tcx, self.inbox.clone(), rx()));
        tokio::spawn(stats::run(
            self.conn.clone(),
            self.link.clone(),
            self.video.clone(),
            self.stats.clone(),
            self.features,
            rx(),
        ));
        // The connection ending ends the relay's tasks (the session loop detaches the handle as
        // well; this covers the time in between).
        let me = self.clone();
        tokio::spawn(async move {
            let mut stop = me.shutdown.subscribe();
            tokio::select! {
                _ = me.conn.closed() => { let _ = me.shutdown.send(true); }
                _ = stop.changed() => {}
            }
        });
    }

    /// What the relay holds and has done for this client.
    pub(super) fn snapshot(&self) -> super::RelaySnapshot {
        use std::sync::atomic::Ordering::Relaxed;
        let (queued_bytes, inflight_frames, inflight_bytes) = self.video.occupancy();
        super::RelaySnapshot {
            queued_video_bytes: queued_bytes,
            inflight_frames,
            inflight_video_bytes: inflight_bytes,
            frames_sent: self.video.total_sent.load(Relaxed),
            frames_dropped: self.video.total_dropped.load(Relaxed),
            frames_cancelled: self.video.total_cancelled.load(Relaxed),
            input_refused: self.input.refused.load(Relaxed),
        }
    }

    /// True once the relay was detached.
    pub(super) fn is_detached(&self) -> bool {
        self.detached.load(Relaxed)
    }

    /// What the pump hands over. Never waits.
    pub(super) fn deliver(&self, ev: LinkEvent) {
        if self.is_detached() {
            if let LinkEvent::Transfer(crate::link::TransferEvent::Open { id, .. }) = ev {
                self.link
                    .abort_transfer(id, hx_proto::channel::STOP_TRANSFER_REJECTED);
            }
            return;
        }
        match ev {
            LinkEvent::Frame(f) => {
                for old in self.video.queue.push(f) {
                    self.video.report_dropped(&old);
                }
            }
            LinkEvent::StreamFormat(f) => self.input.set_display(f.width, f.height),
            LinkEvent::Cursor(CursorUpdate::Shape(s)) => self.cursor.push(CursorUpdate::Shape(s)),
            LinkEvent::Cursor(CursorUpdate::Position(p)) => {
                self.cursor.push(CursorUpdate::Position(p));
            }
            LinkEvent::CancelFrames { up_to_frame } => self.video.cancel_up_to(up_to_frame),
            LinkEvent::Stats(s) => self.stats.set_session(s),
            LinkEvent::Transfer(t) => self.inbox.push(&self.link, t),
            LinkEvent::SessionGoodbye { code } => self.goodbye_code.store(code, Relaxed),
            // Logged by the pump; never forwarded.
            LinkEvent::Event(_) | LinkEvent::Closed(_) => {}
        }
    }

    /// The link ended under this client: tell it with a fixed text and close it (ipc.md 12.4:
    /// `INTERNAL_ERROR`; a session that said goodbye for a shutdown is `SHUTDOWN`). The session
    /// loop then detaches the handle.
    pub(super) fn link_lost(&self, class: FailureClass) {
        if self.is_detached() {
            return;
        }
        let orderly = class == FailureClass::SessionGoodbye
            && matches!(self.goodbye_code.load(Relaxed), 0 | 7);
        let (code, text) = if orderly {
            (CloseCode::Shutdown, SESSION_ENDED)
        } else {
            (CloseCode::InternalError, LINK_FAILED)
        };
        let _ = self.shutdown.send(true);
        let conn = self.conn.clone();
        tokio::spawn(async move {
            crate::gateway::session::goodbye(&conn, code, text, text).await;
        });
    }

    /// Stops the tasks and forgets the client's state, without telling the session (a relay that
    /// was replaced).
    pub(super) fn retire(&self) {
        if self.detached.swap(true, Relaxed) {
            return;
        }
        self.input.release();
        self.stop_tasks();
    }

    fn stop_tasks(&self) {
        self.reconf.close();
        let _ = self.shutdown.send(true);
        self.conn.set_ack_handler(None);
        for f in self.video.queue.clear() {
            drop(f);
        }
        self.inbox.clear(&self.link);
    }
}

impl GatewayHandle for ClientRelay {
    fn view_config(&self, config: ViewConfig) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if self.is_detached() {
                return;
            }
            let codec = self
                .core
                .choose_codec(&self.link, &self.conn, config.codec)
                .unwrap_or(VideoCodec::H264);
            let cfg = self.apply_view(&config, codec);
            // At most 10 a second reach the session; the last one always does (reconf.rs).
            self.reconf.push(cfg);
        })
    }

    fn request_keyframe(&self, last_decoded_frame: u32) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if self.is_detached() {
                return;
            }
            // Until the session's fresh image arrives nothing else is worth sending.
            self.video.broken.store(true, Relaxed);
            let _ = self.link.request_idr(last_decoded_frame);
        })
    }

    fn client_stats(&self, stats: hx_proto::pb::ClientStats) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if !self.is_detached()
                && super::util::lock(&self.stats_rl).allow(std::time::Instant::now())
            {
                let _ = self.link.client_stats(stats);
            }
        })
    }

    fn release_input(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move { self.input.release() })
    }

    fn cancel_in_flight(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.video.cancel_all();
            for f in self.video.queue.clear() {
                self.video.report_dropped(&f);
            }
            // Every transfer, in both directions, is aborted.
            self.abort.send_modify(|g| *g += 1);
            self.inbox.clear(&self.link);
        })
    }

    fn detach(&self, reason: DetachReason) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if self.detached.swap(true, Relaxed) {
                return;
            }
            tracing::debug!(
                device = %crate::gateway::util::log_text(&self.name, 64),
                ?reason,
                "detaching a client from the desktop"
            );
            // Nothing of this client reaches the session after this point.
            self.input.release();
            self.video.cancel_all();
            self.abort.send_modify(|g| *g += 1);
            self.stop_tasks();
            let current = self.core.clear_active(self);
            if reason == DetachReason::Left && current {
                let _ = self.link.stop(self.epoch);
            }
            self.core.keeper.detach(&self.link);
        })
    }
}
