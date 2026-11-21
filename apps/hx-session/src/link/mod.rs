//! The session end of the session link (`docs/ipc.md` Part 2).
//!
//! `hx-session` **listens** (on the socket systemd hands it, [`activation`]) and the gateway
//! dials. One link is three unix connections, `ctl`, `media` and `bulk`, to the same socket, each
//! opened with the preamble of section 12.2. [`Server`] accepts connections, answers preambles,
//! assembles the three lanes of one `link_id` into a live link, and lets a new `link_id` on `ctl`
//! **supersede** the old link. A link that closes for any reason never ends the daemon: it stops
//! capture, injects `release_all`, aborts transfers and returns to listening (section 12.4).
//!
//! # Runtime structure
//!
//! * the **acceptor** (`Server::run`): polls the listener, drops connections beyond the handshake
//!   cap, expires a link whose extra lanes do not arrive in 5 s;
//! * short-lived **handshake threads** (at most [`SessionConfig::max_handshakes`], each bounded
//!   to the 5 s preamble timeout);
//! * per live link ([`runtime`]): control reader (input is injected straight from it, never
//!   waiting for video), control writer, media writer, engine (pipeline, controller, stats,
//!   resize pacing), cursor, bulk reader and the clipboard watcher. All queues are bounded.
//!
//! Nothing here launches user-facing programs (section 11), and no peer-supplied value sizes an
//! allocation beyond the limits of section 13.

pub mod activation;
mod bulk;
mod convert;
mod io;
mod runtime;

use hx_capture::X11Input;
use hx_ipc::link::preamble::{CLIENT_PREAMBLE_LEN, ClientPreamble, LINK_ID_LEN};
use hx_ipc::link::validate::{
    FEATURE_CLIPBOARD, FEATURE_FILE_TRANSFER, FEATURE_INPUT, FEATURE_RESIZE,
};
use hx_ipc::link::{DEFAULT_MAX_FRAME_BYTES, LINK_MAJOR, LINK_MINOR, Lane, frames, pb};
use hx_ipc::text::sanitize_text;
use hx_proto::pb::VideoCodec;
use io::{read_exact_deadline, write_all};
use runtime::{Lanes, LinkCtx};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::clipboard::ClipboardSettings;
use crate::input::InputLimits;
use crate::pipeline::PipelineConfig;

/// Where received files go (`docs/ipc.md` 21 item 3: the one writable path of the unit).
pub const DEFAULT_RECEIVED_DIR: &str = "/var/lib/hx-session/received";

/// Settings of the link end. The defaults are the contract's numbers.
#[derive(Clone, Debug)]
pub struct SessionConfig {
    /// X display (`None`: `$DISPLAY`). Used for capture, input and the clipboard.
    pub display: Option<String>,
    /// Directory for received files; created (0700) when missing.
    pub received_dir: PathBuf,
    /// `max_frame_bytes`: no encoded frame above this is sent (default 4 MiB).
    pub max_frame_bytes: u32,
    /// Largest file accepted or sent (default 4 GiB).
    pub max_file_bytes: u64,
    /// Pipeline template; display, bitrate and frame rate are filled in per `start`.
    pub pipeline: PipelineConfig,
    /// Rate limits of the input gate.
    pub input: InputLimits,
    /// Clipboard engine settings; `None` switches the clipboard off (`info` then does not
    /// advertise it).
    pub clipboard: Option<ClipboardSettings>,
    /// Send the files of a local copy to the gateway (the gateway still applies policy and may
    /// refuse each one).
    pub push_local_files: bool,
    /// Preamble must complete within this long of connect (5 s).
    pub preamble_timeout: Duration,
    /// The extra lanes must arrive within this long of `ctl` (5 s).
    pub extra_lanes_timeout: Duration,
    /// The link closes when nothing arrives on `ctl` for this long (15 s).
    pub gateway_silence: Duration,
    /// A write that makes no progress for this long closes the lane (2 s).
    pub write_stall: Duration,
    /// Handshake threads at once; further connections are closed on accept.
    pub max_handshakes: usize,
}

impl SessionConfig {
    /// The defaults for `display`.
    pub fn new(display: Option<String>) -> Self {
        let clipboard = ClipboardSettings {
            display: display.clone(),
            ..ClipboardSettings::default()
        };
        Self {
            display,
            received_dir: PathBuf::from(DEFAULT_RECEIVED_DIR),
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            max_file_bytes: hx_proto::channel::MAX_FILE_SIZE,
            pipeline: PipelineConfig::default(),
            input: InputLimits::default(),
            clipboard: Some(clipboard),
            push_local_files: true,
            preamble_timeout: Duration::from_secs(5),
            extra_lanes_timeout: Duration::from_secs(5),
            gateway_silence: Duration::from_secs(15),
            write_stall: Duration::from_secs(2),
            max_handshakes: 8,
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

struct Assembly {
    link_id: [u8; LINK_ID_LEN],
    ctl: UnixStream,
    media: Option<UnixStream>,
    bulk: Option<UnixStream>,
    started: Instant,
}

impl Assembly {
    fn close(self) {
        for s in [Some(self.ctl), self.media, self.bulk]
            .into_iter()
            .flatten()
        {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
    }
}

struct Live {
    link_id: [u8; LINK_ID_LEN],
    ctx: Arc<LinkCtx>,
}

#[derive(Default)]
struct HubState {
    assembling: Option<Assembly>,
    live: Option<Live>,
}

struct Hub {
    cfg: Arc<SessionConfig>,
    /// Held for the whole life of a link: a superseding link waits for the old one's teardown.
    desktop: Mutex<()>,
    state: Mutex<HubState>,
    supervisors: Mutex<Vec<JoinHandle<()>>>,
}

fn log(msg: &str) {
    eprintln!("hx-session: {msg}");
}

impl Hub {
    fn build_info(&self) -> Option<pb::Info> {
        let input = X11Input::connect(self.cfg.display.as_deref()).ok()?;
        let size = input.screen_size();
        let mut features = FEATURE_INPUT | FEATURE_RESIZE | FEATURE_FILE_TRANSFER;
        if self.cfg.clipboard.is_some() {
            features |= FEATURE_CLIPBOARD;
        }
        Some(pb::Info {
            software: sanitize_text(&format!("hx-session {}", env!("CARGO_PKG_VERSION")), 128),
            features,
            codecs: vec![VideoCodec::H264 as i32],
            display: Some(pb::Display {
                width: size.width.clamp(1, 16_384),
                height: size.height.clamp(1, 16_384),
            }),
            max_fps: self.cfg.pipeline.max_fps,
        })
    }

    /// The first lane of a link: supersedes whatever link exists, then sends `info`.
    fn on_ctl(self: &Arc<Self>, link_id: [u8; LINK_ID_LEN], stream: UnixStream) {
        // Probe the display before disturbing a working link: a desktop without X cannot serve.
        let Some(info) = self.build_info() else {
            log("the display is not available; refusing the link");
            return;
        };
        let Ok(keep) = stream.try_clone() else { return };
        {
            let mut st = lock(&self.state);
            let duplicate = st.live.as_ref().is_some_and(|l| l.link_id == link_id)
                || st.assembling.as_ref().is_some_and(|a| a.link_id == link_id);
            if duplicate {
                return; // a duplicate lane of the current link: closed
            }
            if let Some(old) = st.live.take() {
                old.ctx.close("superseded by a new link");
            }
            if let Some(old) = st.assembling.take() {
                old.close();
            }
            st.assembling = Some(Assembly {
                link_id,
                ctl: keep,
                media: None,
                bulk: None,
                started: Instant::now(),
            });
        }
        let frame = frames::encode_session_message(&pb::SessionToGateway {
            message: Some(pb::session_to_gateway::Message::Info(info)),
        });
        let sent = frame.is_ok_and(|f| write_all(&stream, &f).is_ok());
        if !sent {
            let mut st = lock(&self.state);
            if st.assembling.as_ref().is_some_and(|a| a.link_id == link_id)
                && let Some(a) = st.assembling.take()
            {
                a.close();
            }
        }
    }

    /// A `media` or `bulk` lane: joins the assembling link with the same id, else is closed.
    fn on_extra(self: &Arc<Self>, lane: Lane, link_id: [u8; LINK_ID_LEN], stream: UnixStream) {
        let complete = {
            let mut st = lock(&self.state);
            let Some(a) = st.assembling.as_mut() else {
                return;
            };
            if a.link_id != link_id {
                return;
            }
            let slot = match lane {
                Lane::Media => &mut a.media,
                Lane::Bulk => &mut a.bulk,
                Lane::Ctl => return,
            };
            if slot.is_some() {
                return; // a duplicate lane of the current link: closed
            }
            *slot = Some(stream);
            if a.media.is_some() && a.bulk.is_some() {
                st.assembling.take()
            } else {
                None
            }
        };
        if let Some(a) = complete {
            self.go_live(a);
        }
    }

    fn go_live(self: &Arc<Self>, a: Assembly) {
        let (Some(media), Some(bulk)) = (a.media, a.bulk) else {
            return;
        };
        let lanes = Lanes {
            ctl: a.ctl,
            media,
            bulk,
        };
        let Ok((ctx, rx)) = LinkCtx::new(self.cfg.clone(), &lanes) else {
            return;
        };
        lock(&self.state).live = Some(Live {
            link_id: a.link_id,
            ctx: ctx.clone(),
        });
        let hub = self.clone();
        let handle = std::thread::Builder::new()
            .name("hx-link".into())
            .spawn(move || {
                runtime::run(ctx.clone(), rx, lanes, &hub.desktop);
                let mut st = lock(&hub.state);
                if st.live.as_ref().is_some_and(|l| Arc::ptr_eq(&l.ctx, &ctx)) {
                    st.live = None;
                }
                drop(st);
                log(&format!("link closed: {}", ctx.reason()));
            });
        match handle {
            Ok(h) => {
                let mut sup = lock(&self.supervisors);
                sup.retain(|h| !h.is_finished());
                sup.push(h);
            }
            Err(_) => log("cannot start the link supervisor"),
        }
    }

    /// Drops an assembling link whose extra lanes did not arrive in time.
    fn expire(&self) {
        let mut st = lock(&self.state);
        if st
            .assembling
            .as_ref()
            .is_some_and(|a| a.started.elapsed() > self.cfg.extra_lanes_timeout)
            && let Some(a) = st.assembling.take()
        {
            a.close();
        }
    }

    fn shutdown(&self) {
        let (live, assembling) = {
            let mut st = lock(&self.state);
            (st.live.take(), st.assembling.take())
        };
        if let Some(a) = assembling {
            a.close();
        }
        if let Some(l) = live {
            l.ctx.goodbye_and_close(7, "session shutting down");
        }
        let handles: Vec<_> = lock(&self.supervisors).drain(..).collect();
        for h in handles {
            let _ = h.join();
        }
    }
}

/// Answers the preamble of one connection and hands the lane to the hub.
fn handshake(hub: &Arc<Hub>, stream: UnixStream) {
    let cfg = &hub.cfg;
    if stream.set_nonblocking(false).is_err()
        || stream.set_write_timeout(Some(cfg.write_stall)).is_err()
    {
        return;
    }
    let mut b = [0u8; CLIENT_PREAMBLE_LEN];
    if read_exact_deadline(&stream, &mut b, Instant::now() + cfg.preamble_timeout).is_err() {
        return;
    }
    let Ok(cp) = ClientPreamble::decode(&b) else {
        return;
    };
    // A different major is refused by closing, with no answer (section 12.2).
    let Ok(answer) = cp.preamble.answer(LINK_MAJOR, LINK_MINOR) else {
        return;
    };
    if write_all(&stream, &answer.encode()).is_err() {
        return;
    }
    match cp.preamble.lane {
        Lane::Ctl => hub.on_ctl(cp.link_id, stream),
        lane => hub.on_extra(lane, cp.link_id, stream),
    }
}

/// Decrements the handshake counter when a handshake thread ends.
struct HandshakeSlot(Arc<AtomicUsize>);

impl Drop for HandshakeSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Relaxed);
    }
}

/// The session link server.
pub struct Server {
    listener: UnixListener,
    hub: Arc<Hub>,
    stop: Arc<AtomicBool>,
}

/// Stops a running [`Server`].
#[derive(Clone)]
pub struct StopHandle {
    stop: Arc<AtomicBool>,
}

impl StopHandle {
    /// Asks the server to say goodbye on the live link, close it and return from `run`.
    pub fn stop(&self) {
        self.stop.store(true, Relaxed);
    }
}

/// A server running on its own thread (tests, embedding).
pub struct ServerHandle {
    stop: StopHandle,
    hub: Arc<Hub>,
    thread: Option<JoinHandle<()>>,
}

impl ServerHandle {
    /// Pushes the local file at `path` to the connected gateway as a file transfer: the path
    /// the clipboard watcher takes for the files of a local copy. Blocks until the transfer is
    /// written. For tests and tooling.
    pub fn send_file(&self, path: &Path) -> Result<(), String> {
        let ctx = lock(&self.hub.state)
            .live
            .as_ref()
            .map(|l| l.ctx.clone())
            .ok_or("no live link")?;
        bulk::send_path(&ctx, path).map_err(|e| format!("{e:?}"))
    }

    /// A handle that can stop the server from elsewhere.
    pub fn stop_handle(&self) -> StopHandle {
        self.stop.clone()
    }

    /// Stops the server and waits until the live link has been torn down.
    pub fn shutdown(mut self) {
        self.stop.stop();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.stop.stop();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Server {
    /// A server on an already listening socket (the one systemd passed, or a test's).
    pub fn new(listener: UnixListener, cfg: SessionConfig) -> std::io::Result<Self> {
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            hub: Arc::new(Hub {
                cfg: Arc::new(cfg),
                desktop: Mutex::new(()),
                state: Mutex::new(HubState::default()),
                supervisors: Mutex::new(Vec::new()),
            }),
            stop: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Binds `path` (tests; the daemon never binds, systemd does).
    pub fn bind(path: &Path, cfg: SessionConfig) -> std::io::Result<Self> {
        Self::new(UnixListener::bind(path)?, cfg)
    }

    /// A handle that stops [`Server::run`].
    pub fn stop_handle(&self) -> StopHandle {
        StopHandle {
            stop: self.stop.clone(),
        }
    }

    /// Serves until stopped. Returns after the live link was torn down.
    pub fn run(self) -> std::io::Result<()> {
        use rustix::event::{PollFd, PollFlags, poll};
        let inflight = Arc::new(AtomicUsize::new(0));
        let timeout = rustix::time::Timespec {
            tv_sec: 0,
            tv_nsec: 100_000_000,
        };
        while !self.stop.load(Relaxed) {
            self.hub.expire();
            match self.listener.accept() {
                Ok((stream, _)) => {
                    if inflight.load(Relaxed) >= self.hub.cfg.max_handshakes {
                        continue; // closed on drop: a flood cannot grow the thread count
                    }
                    inflight.fetch_add(1, Relaxed);
                    let slot = HandshakeSlot(inflight.clone());
                    let hub = self.hub.clone();
                    let spawned = std::thread::Builder::new()
                        .name("hx-handshake".into())
                        .spawn(move || {
                            let _slot = slot;
                            handshake(&hub, stream);
                        });
                    if spawned.is_err() {
                        log("cannot start a handshake thread");
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    let mut fds = [PollFd::new(&self.listener, PollFlags::IN)];
                    let _ = poll(&mut fds, Some(&timeout));
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    self.hub.shutdown();
                    return Err(e);
                }
            }
        }
        self.hub.shutdown();
        Ok(())
    }

    /// Runs on a new thread.
    pub fn spawn(self) -> ServerHandle {
        let stop = self.stop_handle();
        let hub = self.hub.clone();
        let thread = std::thread::Builder::new()
            .name("hx-session-server".into())
            .spawn(move || {
                if let Err(e) = self.run() {
                    log(&format!("server stopped: {e}"));
                }
            })
            .ok();
        ServerHandle { stop, hub, thread }
    }
}
