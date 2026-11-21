//! The relay: the real [`DesktopLink`] of the gateway, on top of the session-link client
//! ([`crate::link`]).
//!
//! `hx-gatewayd` terminates the client protocol (protocol.md); `hx-session` speaks the session
//! link (ipc.md Part 2). This module is the bridge, per attached client:
//!
//! ```text
//!  client (hx_transport::Connection)                       desktop (link::LinkClient)
//!  --------------------------------                        --------------------------
//!  video streams  <-- video::sender  <-- FrameQueue  <--+
//!  StreamInfo     <--                                   |
//!  cursor stream  <-- cursor::sender <-- CursorSlot  <--+-- pump (one task per link) <-- LinkEvents
//!  transfers      <-- transfer::outbound <-- Inbox   <--+       never waits for a client
//!  ServerStats    <-- stats::run <------ SessionStats <-+
//!  frame acks     --> VideoShared::on_ack --> Feedback --> feedback_task --> frame_feedback
//!  input stream   --> input::input_task  --> InputPath --> input   (epoch gate)
//!  mouse datagram --> input::mouse_task  --> InputPath --> mouse
//!  transfers      --> transfer::inbound  ------------------> begin_transfer / bulk lane
//!  ViewConfig, RequestKeyframe, ClientStats (the session loop, via the LinkClient trait)
//!                 --> reconfigure / request_idr / client_stats
//! ```
//!
//! # Mapping (ipc.md 20.1)
//!
//! | Client protocol | Session link |
//! |---|---|
//! | first `ViewConfig` | `start{epoch, StreamConfig}` (at attach) |
//! | later `ViewConfig` | `reconfigure` (resize, fps, bitrate cap, policies) |
//! | `StreamInfo` | built from the frame's [`StreamFormat`](crate::link::StreamFormat) |
//! | `RequestKeyframe` | `request_idr` |
//! | `ClientStats` | `client_stats` |
//! | input stream, mouse datagram | `input`, `mouse` (current epoch only) |
//! | cursor stream | `cursor` |
//! | video stream per frame, its ack or reset | media lane frame, `frame_feedback`; `cancel_frames` resets streams |
//! | `ServerStats` | `SessionStats` + transport RTT |
//! | clipboard and file streams | bulk lane transfers, both ways |
//! | `Goodbye`, connection close | `stop` (last client), then the 30 s keep |
//! | `Goodbye(TAKEN_OVER)` (gateway side) | `input{release_all}`, aborts, then `start` with a new epoch |
//!
//! # Bounds
//!
//! * The pump reads [`LinkEvents`](crate::link::LinkEvents) and **never awaits client I/O**: it
//!   pushes into per-client bounded structures. Frames: 4 queued (and `2 x max(max_frame_bytes,
//!   4 MiB)` bytes), evicting the oldest, plus at most 16 in flight (and `max(2 x max_frame_bytes,
//!   12 MiB)` bytes), because the link's pool stops counting a frame once it is popped. Cursor:
//!   16 shapes, one position. Transfers: a 128 entry inbox whose chunks keep the link's unread
//!   credit (1 MiB per transfer, 4 MiB per link). Feedback: 256 results. Statistics: one slot.
//! * Every wait on a client is bounded: 150 ms to hand a frame to the transport, 5 s for control
//!   and cursor writes (then the client is closed with `BUSY`), 5 s to open a transfer stream,
//!   30 s per transfer chunk.
//! * A slow client costs only itself: its frames are cancelled and dropped, reported to the
//!   session's congestion controller, and replaced by one IDR (`RESYNC`).
//!
//! # Security properties
//!
//! * No session text reaches a client: `SessionEvent::message` and `SessionInfo::software` are
//!   logged (sanitised) only; goodbyes to clients carry fixed texts; `ServerStats` has no string
//!   field.
//! * Only the current epoch's input reaches the session ([`input::InputPath`]); a detached or
//!   displaced client's handle ignores everything ([`GuardedClient`](super::desktop::GuardedClient)
//!   and the relay's own `detached` flag).
//! * `attach` re-checks the connection (and the session manager re-checks the device's revocation)
//!   before and after the desktop is dialled; the dial itself is bounded.
//! * A session-initiated close is a fault with backoff ([`crate::link::ReconnectPolicy`]); the
//!   privd actions it advises (`RestartSession`, `InstallSession`) are additionally limited here.

mod client;
mod cursor;
mod input;
mod stats;
mod transfer;
mod util;
mod video;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hx_ipc::admin::pb::LinkState;
use hx_proto::VideoCodec;
use hx_transport::Connection;

use self::client::ClientRelay;
use self::util::{ActionLimiter, lock};
use super::config::GatewayConfig;
use super::desktop::{
    AttachRequest, BoxFuture, DesktopLink, LinkClient as GatewayHandle, LinkError,
};
use super::privd_client::PrivdClient;
use super::util::log_text;
use crate::link::{
    Advice, Attached, DesktopState, DialError, FailureClass, IDLE_KEEP, LinkClient, LinkConfig,
    LinkEvent, LinkEvents, LinkKeeper,
};

/// Dialling the desktop (connect, preamble, `info`, the extra lanes) is bounded by the link
/// client's own timeouts (3 + 5 + 5 s); this bounds the whole attach a little beyond that.
const ATTACH_TIMEOUT: Duration = Duration::from_secs(20);
/// `RestartSession` and `InstallSession` run in the background, bounded.
const ACTION_TIMEOUT: Duration = Duration::from_secs(330);

/// Settings of the relay.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// The host side of the link socket (`/run/hx/link/<desktop>.sock`).
    pub socket: PathBuf,
    /// The link client's settings: frame and file limits, codecs, timeouts.
    pub link: LinkConfig,
    /// How long the link is kept after the last client leaves (ipc.md 18: 30 s).
    pub idle_keep: Duration,
    /// The desktop whose session privd is asked to restart or reinstall.
    pub desktop_id: String,
}

impl RelayConfig {
    /// The relay of a gateway configuration: the link socket (`link_socket` or the default
    /// `/run/hx/link/<desktop_id>.sock`) and its file limit.
    pub fn from_gateway(config: &GatewayConfig) -> Self {
        Self {
            socket: config.link_socket_path(),
            link: LinkConfig {
                max_file_bytes: config.max_file_bytes,
                ..LinkConfig::default()
            },
            idle_keep: IDLE_KEEP,
            desktop_id: config.desktop_id.clone(),
        }
    }

    /// A relay of the socket at `socket` with every default (tests and tools).
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            link: LinkConfig::default(),
            idle_keep: IDLE_KEEP,
            desktop_id: "main".into(),
        }
    }
}

/// What the relay holds for the active client and what it has done for it (metrics, tests).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelaySnapshot {
    /// Bytes of video waiting for the sender (bounded: see the module documentation).
    pub queued_video_bytes: u64,
    /// Frames handed to the transport and not yet acknowledged.
    pub inflight_frames: usize,
    /// Payload bytes of those frames.
    pub inflight_video_bytes: u64,
    /// Frames handed to the transport since the client attached.
    pub frames_sent: u64,
    /// Frames discarded without being sent (queue evictions, a broken chain, a full window).
    pub frames_dropped: u64,
    /// Frames the transport reported cancelled or rejected.
    pub frames_cancelled: u64,
    /// Input events refused because the client was no longer the current one.
    pub input_refused: u64,
}

struct Core {
    cfg: RelayConfig,
    keeper: Arc<LinkKeeper>,
    privd: Option<PrivdClient>,
    /// The current client's epoch; a relay whose epoch differs is not the active one.
    epoch: Arc<AtomicU32>,
    active: Mutex<Option<Arc<ClientRelay>>>,
    restarts: Mutex<ActionLimiter>,
    installs: Mutex<ActionLimiter>,
    outdated: AtomicBool,
}

impl Core {
    /// The relay of the active client if it belongs to `link`.
    fn active_on(&self, link: &LinkClient) -> Option<Arc<ClientRelay>> {
        lock(&self.active)
            .as_ref()
            .filter(|r| r.link.same_link(link))
            .cloned()
    }

    /// Clears the active slot if it still holds `relay`; true if it did.
    fn clear_active(&self, relay: &ClientRelay) -> bool {
        let mut a = lock(&self.active);
        if a.as_ref()
            .is_some_and(|r| std::ptr::eq(Arc::as_ptr(r), relay))
        {
            *a = None;
            true
        } else {
            false
        }
    }

    /// The codec for a client: its request if both ends accept it, else the first codec of the
    /// negotiated set the session offers.
    fn choose_codec(
        &self,
        link: &LinkClient,
        conn: &Connection,
        requested: i32,
    ) -> Option<VideoCodec> {
        let offered = &link.info().codecs;
        let negotiated = &conn.negotiated().codecs;
        let ok = |c: &VideoCodec| offered.contains(c) && negotiated.contains(c);
        VideoCodec::try_from(requested)
            .ok()
            .filter(|c| *c != VideoCodec::Unspecified && ok(c))
            .or_else(|| negotiated.iter().copied().find(ok))
    }

    /// Does what a failed dial or a lost link advises, within the limits: privd calls run in the
    /// background and are rate limited here as well as in privd.
    fn act(self: &Arc<Self>, advice: Advice) {
        if advice.ask_install {
            self.outdated.store(true, Relaxed);
            if lock(&self.installs).permit(Instant::now()) {
                self.spawn_action(true);
            } else {
                tracing::warn!("InstallSession was not requested: rate limited");
            }
        }
        if advice.ask_restart {
            if lock(&self.restarts).permit(Instant::now()) {
                self.spawn_action(false);
            } else {
                tracing::warn!("RestartSession was not requested: rate limited");
            }
        }
        if advice.state == DesktopState::SessionUnavailable {
            tracing::warn!("the desktop session is unavailable; retrying every 10 minutes");
        }
    }

    fn spawn_action(self: &Arc<Self>, install: bool) {
        let Some(privd) = self.privd.clone() else {
            return;
        };
        let me = self.clone();
        let id = self.cfg.desktop_id.clone();
        tokio::spawn(async move {
            let call = async {
                if install {
                    privd.install_session(&id).await
                } else {
                    privd.restart_session(&id).await
                }
            };
            let what = if install {
                "InstallSession"
            } else {
                "RestartSession"
            };
            match tokio::time::timeout(ACTION_TIMEOUT, call).await {
                Ok(Ok(())) => {
                    tracing::info!(what, "privd did what the link policy asked");
                    me.outdated.store(false, Relaxed);
                    // A fresh session: dial at once and forget the backoff.
                    me.keeper.session_restarted();
                }
                Ok(Err(e)) => tracing::warn!(what, error = %e, "privd refused or failed"),
                Err(_) => tracing::warn!(what, "privd took too long"),
            }
        });
    }

    async fn attach(
        self: &Arc<Self>,
        request: AttachRequest,
    ) -> Result<Arc<dyn GatewayHandle>, LinkError> {
        // The client may have gone while the claim was waiting for its turn.
        if request.connection.close_info().is_some() {
            return Err(LinkError::Unavailable);
        }
        let attached = match tokio::time::timeout(ATTACH_TIMEOUT, self.keeper.attach()).await {
            Ok(Ok(a)) => a,
            Ok(Err(DialError::Wait(w))) => {
                tracing::debug!(wait_ms = w.as_millis(), "the desktop link is backing off");
                return Err(LinkError::Unavailable);
            }
            Ok(Err(DialError::Failed { error, advice })) => {
                tracing::warn!(
                    class = ?error.class,
                    detail = %log_text(&error.detail, 200),
                    "dialling the desktop failed"
                );
                self.act(advice);
                return Err(LinkError::Unavailable);
            }
            Err(_) => {
                tracing::warn!("dialling the desktop took too long");
                return Err(LinkError::Unavailable);
            }
        };
        let Attached {
            client: link,
            events,
        } = attached;
        self.outdated.store(false, Relaxed);
        if let Some(events) = events {
            tracing::info!(
                software = %log_text(&link.info().software, 128),
                "connected to the desktop session"
            );
            tokio::spawn(self.clone().pump(link.clone(), events));
        }
        let Some(codec) = self.choose_codec(&link, &request.connection, request.view.codec) else {
            tracing::warn!("no codec is common to the client and the session");
            self.keeper.detach(&link);
            return Err(LinkError::Unavailable);
        };
        let epoch = self.epoch.fetch_add(1, Relaxed).wrapping_add(1);
        let relay = ClientRelay::new(self.clone(), link.clone(), &request, epoch);
        let config = relay.apply_view(&request.view, codec);
        // The relay is the active one before `start`, so no frame or cursor update of the new
        // epoch can find nobody.
        let replaced = lock(&self.active).replace(relay.clone());
        if let Some(old) = replaced {
            old.retire();
        }
        relay.start_tasks();
        if request.connection.close_info().is_some() {
            self.abandon(&relay).await;
            return Err(LinkError::Unavailable);
        }
        if let Err(e) = link.start(epoch, config) {
            tracing::warn!(error = %e, "the session did not accept the start");
            self.abandon(&relay).await;
            return Err(LinkError::Unavailable);
        }
        Ok(relay)
    }

    /// Undoes an attach that did not complete.
    async fn abandon(&self, relay: &Arc<ClientRelay>) {
        GatewayHandle::detach(relay.as_ref(), super::desktop::DetachReason::Left).await;
    }

    /// Reads one link's events for as long as it lives and hands each to the active client's
    /// relay. **Nothing here waits for a client.**
    async fn pump(self: Arc<Self>, link: LinkClient, mut events: LinkEvents) {
        loop {
            let ev = events.next().await;
            match ev {
                LinkEvent::Closed(closed) => {
                    tracing::info!(
                        class = ?closed.class,
                        detail = %log_text(&closed.detail, 200),
                        "the desktop link ended"
                    );
                    let advice = self.keeper.on_closed(&link, &closed);
                    if closed.class != FailureClass::Closed {
                        if let Some(r) = self.active_on(&link) {
                            r.link_lost(closed.class);
                        }
                        self.act(advice);
                    }
                    return;
                }
                LinkEvent::Event(e) => {
                    // Log only: never forwarded to a client (ipc.md 19.1, rule 3).
                    tracing::debug!(kind = ?e.kind, message = %log_text(&e.message, 256), "session event");
                    if let Some(r) = self.active_on(&link) {
                        r.deliver(LinkEvent::Event(e));
                    }
                }
                other => match self.active_on(&link) {
                    Some(r) => r.deliver(other),
                    None => {
                        // Nobody to give it to: a transfer is refused, the rest is dropped.
                        if let LinkEvent::Transfer(crate::link::TransferEvent::Open {
                            id, ..
                        }) = other
                        {
                            link.abort_transfer(id, hx_proto::channel::STOP_TRANSFER_REJECTED);
                        }
                    }
                },
            }
        }
    }
}

/// The desktop link of the gateway: dials the session through the link socket, keeps it 30 s
/// after the last client, redials under the reconnect policy and relays one client at a time.
pub struct RelayLink {
    core: Arc<Core>,
}

impl RelayLink {
    /// A relay of `cfg`. `privd` is where `RestartSession` and `InstallSession` go (`None`: the
    /// advice is only logged).
    pub fn new(cfg: RelayConfig, privd: Option<PrivdClient>) -> Arc<Self> {
        let keeper =
            LinkKeeper::with_idle_keep(cfg.socket.clone(), cfg.link.clone(), cfg.idle_keep);
        Arc::new(Self {
            core: Arc::new(Core {
                cfg,
                keeper,
                privd,
                epoch: Arc::new(AtomicU32::new(0)),
                active: Mutex::new(None),
                // privd allows 6 per hour; the gateway asks at most 3, a minute apart.
                restarts: Mutex::new(ActionLimiter::new(Duration::from_secs(60), 3)),
                installs: Mutex::new(ActionLimiter::new(Duration::from_secs(60), 3)),
                outdated: AtomicBool::new(false),
            }),
        })
    }

    /// The active client's relay figures, if a client is attached.
    pub fn snapshot(&self) -> Option<RelaySnapshot> {
        lock(&self.core.active).as_ref().map(|r| r.snapshot())
    }

    /// The link keeper (tests move the policy through it).
    pub fn keeper(&self) -> &Arc<LinkKeeper> {
        &self.core.keeper
    }
}

impl DesktopLink for RelayLink {
    fn attach(
        &self,
        request: AttachRequest,
    ) -> BoxFuture<'_, Result<Arc<dyn GatewayHandle>, LinkError>> {
        let core = self.core.clone();
        Box::pin(async move {
            let relay = core.attach(request).await?;
            Ok(relay as Arc<dyn GatewayHandle>)
        })
    }

    fn state(&self) -> LinkState {
        if self.core.keeper.state() == DesktopState::SessionUnavailable {
            LinkState::SessionUnavailable
        } else if self.core.outdated.load(Relaxed) {
            LinkState::SessionOutdated
        } else if self.core.keeper.is_up() {
            LinkState::Up
        } else {
            LinkState::Down
        }
    }
}
