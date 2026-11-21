//! Harness of the relay tests: the real stack in one process.
//!
//! ```text
//! client (hx-crypto + hx-transport) -> [optional UDP shaper] -> Gateway (fake privd)
//!     -> RelayLink -> link::LinkClient -> unix socket -> hx-session link server + pipeline (Xvfb)
//! ```
//!
//! The unix socket stands in for the Incus proxy device. Needs Xvfb (`HX_REQUIRE_XVFB=1` turns
//! a missing Xvfb into a failure, as in CI), x264 and the FFmpeg libraries.
#![allow(dead_code)]

#[path = "../../../../crates/hx-capture/tests/common/mod.rs"]
pub mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub use common::{Xvfb, fill_root};
use hx_agent::gateway::desktop::DesktopLink;
use hx_agent::gateway::privd_client::PrivdClient;
use hx_agent::gateway::relay::{RelayConfig, RelayLink};
use hx_crypto::{IdentityKey, Pin};
use hx_proto::VideoCodec;
use hx_proto::pb::{
    ControlMessage, CursorEvent, TransferHeader, ViewConfig, control_message::Message as Ctl,
};
use hx_session::clipboard::ClipboardSettings;
use hx_session::link::{Server, ServerHandle, SessionConfig};
use hx_transport::{Connection, Target, TransferKind, TransportPreference, VideoFrame};
use rustls::pki_types::ServerName;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use x11rb::connection::Connection as _;
use x11rb::protocol::Event as XEvent;
use x11rb::protocol::xproto::{ChangeWindowAttributesAux, ConnectionExt as _, EventMask};
use x11rb::rust_connection::RustConnection;

use crate::gateway_common::{Env, EnvOptions, PIN, new_key, within};

pub const W: u32 = 640;
pub const H: u32 = 360;

static NEXT: AtomicU32 = AtomicU32::new(0);

#[derive(Default)]
pub struct RigOptions {
    /// The file limit of the gateway and of the relay's link (the session keeps its own).
    pub max_file: Option<u64>,
    /// The 30 s keep, shortened.
    pub idle_keep: Option<Duration>,
}

/// The whole stack.
pub struct Rig {
    pub env: Env,
    pub x: Xvfb,
    pub dir: PathBuf,
    pub sock: PathBuf,
    pub server: Option<ServerHandle>,
    pub relay: Arc<RelayLink>,
}

fn session_config(x: &Xvfb, dir: &std::path::Path) -> SessionConfig {
    let mut cfg = SessionConfig::new(Some(x.display.clone()));
    cfg.received_dir = dir.join("received");
    cfg.pipeline.encoder.threads = 2;
    cfg.clipboard = Some(ClipboardSettings {
        display: Some(x.display.clone()),
        staging_base: Some(dir.to_path_buf()),
        step_timeout: Duration::from_secs(2),
        ..ClipboardSettings::default()
    });
    cfg
}

impl Rig {
    pub async fn start(o: RigOptions) -> Option<Rig> {
        let x = Xvfb::start(W, H)?;
        let dir = std::env::temp_dir().join(format!(
            "hx-relay-it-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("link.sock");
        let server = Server::bind(&sock, session_config(&x, &dir))
            .unwrap()
            .spawn();
        let slot: Arc<Mutex<Option<Arc<RelayLink>>>> = Arc::new(Mutex::new(None));
        let (s2, sock2) = (slot.clone(), sock.clone());
        let (max_file, keep) = (o.max_file, o.idle_keep);
        let env = Env::start_with(EnvOptions {
            max_file_bytes: o.max_file,
            custom_link: Some(Box::new(move |privd| {
                let mut cfg = RelayConfig::new(sock2);
                if let Some(m) = max_file {
                    cfg.link.max_file_bytes = m;
                }
                if let Some(k) = keep {
                    cfg.idle_keep = k;
                }
                let relay =
                    RelayLink::new(cfg, Some(PrivdClient::new(&privd.path, Default::default())));
                *s2.lock().unwrap() = Some(relay.clone());
                relay as Arc<dyn DesktopLink>
            })),
            ..EnvOptions::default()
        })
        .await;
        env.set_pin(PIN).await;
        let relay = slot.lock().unwrap().take().unwrap();
        Some(Rig {
            env,
            x,
            dir,
            sock,
            server: Some(server),
            relay,
        })
    }

    pub fn received(&self) -> PathBuf {
        self.dir.join("received")
    }

    /// A new paired device.
    pub async fn device(&self, name: &str) -> Arc<IdentityKey> {
        let key = new_key();
        self.env.pair(&key, name).await;
        key
    }

    /// Logs `key` in (QUIC, straight to the gateway) and wraps the connection.
    pub async fn client(&self, key: &Arc<IdentityKey>, name: &str) -> Client {
        Client::new(self.env.login(key, name, PIN).await)
    }

    /// Logs `key` in through `addr` (a shaper in front of the gateway).
    pub async fn client_at(&self, key: &Arc<IdentityKey>, name: &str, addr: SocketAddr) -> Client {
        let conn = within(hx_crypto::connect_with_pin(
            &Target {
                addr,
                server_name: ServerName::try_from("hx.invalid").unwrap(),
            },
            key,
            self.env.server_public(),
            &Pin::new(PIN).unwrap(),
            &self.env.session_opts(TransportPreference::Quic, name),
        ))
        .await
        .expect("login through the shaper");
        Client::new(conn)
    }

    /// Replaces the session by a new one on the same socket path (a desktop restart).
    pub fn restart_session(&mut self) {
        if let Some(s) = self.server.take() {
            s.shutdown();
        }
        let _ = std::fs::remove_file(&self.sock);
        self.server = Some(
            Server::bind(&self.sock, session_config(&self.x, &self.dir))
                .unwrap()
                .spawn(),
        );
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        drop(self.server.take());
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A file or clipboard transfer received from the gateway, in full.
pub struct Received {
    pub kind: TransferKind,
    pub header: TransferHeader,
    pub body: Vec<u8>,
}

/// A client connection with everything it receives collected on channels.
pub struct Client {
    pub conn: Connection,
    pub frames: mpsc::UnboundedReceiver<VideoFrame>,
    pub ctl: mpsc::UnboundedReceiver<(Instant, Ctl)>,
    pub cursor: mpsc::UnboundedReceiver<CursorEvent>,
    pub transfers: mpsc::UnboundedReceiver<Received>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Client {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl Client {
    pub fn new(conn: Connection) -> Client {
        let (ftx, frames) = mpsc::unbounded_channel();
        let (ctx, ctl) = mpsc::unbounded_channel();
        let (utx, cursor) = mpsc::unbounded_channel();
        let (ttx, transfers) = mpsc::unbounded_channel();
        let mut tasks = Vec::new();
        let c = conn.clone();
        tasks.push(tokio::spawn(async move {
            while let Ok(f) = c.recv_video_frame().await {
                if ftx.send(f).is_err() {
                    break;
                }
            }
        }));
        let c = conn.clone();
        tasks.push(tokio::spawn(async move {
            while let Ok(m) = c.recv_control().await {
                if let Some(m) = m.message
                    && ctx.send((Instant::now(), m)).is_err()
                {
                    break;
                }
            }
        }));
        let c = conn.clone();
        tasks.push(tokio::spawn(async move {
            while let Ok(e) = c.recv_cursor().await {
                if utx.send(e).is_err() {
                    break;
                }
            }
        }));
        let c = conn.clone();
        tasks.push(tokio::spawn(async move {
            while let Ok(mut t) = c.accept_transfer().await {
                let ttx = ttx.clone();
                tokio::spawn(async move {
                    let mut body = Vec::new();
                    while let Ok(Some(chunk)) = t.next_chunk().await {
                        body.extend_from_slice(&chunk);
                    }
                    if body.len() as u64 == t.header.size {
                        let _ = ttx.send(Received {
                            kind: t.kind,
                            header: t.header.clone(),
                            body,
                        });
                    }
                });
            }
        }));
        Client {
            conn,
            frames,
            ctl,
            cursor,
            transfers,
            tasks,
        }
    }

    pub async fn send(&self, m: Ctl) {
        within(self.conn.send_control(&ControlMessage::new(m)))
            .await
            .expect("send control");
    }

    /// Sends a `ViewConfig` (H.264, 30 fps, clipboard on) adjusted by `f`.
    pub async fn view(&self, f: impl FnOnce(&mut ViewConfig)) {
        let mut v = ViewConfig {
            codec: VideoCodec::H264 as i32,
            max_fps: 30,
            clipboard_enabled: true,
            ..Default::default()
        };
        f(&mut v);
        self.send(Ctl::ViewConfig(v)).await;
    }

    /// The next frame within `within`.
    pub async fn next_frame(&mut self, secs: u64) -> VideoFrame {
        tokio::time::timeout(Duration::from_secs(secs), self.frames.recv())
            .await
            .expect("a frame in time")
            .expect("the connection is alive")
    }

    /// The first control message `pick` accepts, within `secs`.
    pub async fn wait_ctl<T>(
        &mut self,
        secs: u64,
        mut pick: impl FnMut(&Ctl) -> Option<T>,
    ) -> Option<T> {
        let end = tokio::time::Instant::now() + Duration::from_secs(secs);
        loop {
            match tokio::time::timeout_at(end, self.ctl.recv()).await {
                Ok(Some((_, m))) => {
                    if let Some(v) = pick(&m) {
                        return Some(v);
                    }
                }
                _ => return None,
            }
        }
    }

    /// Every control message that arrives within `secs`.
    pub async fn collect_ctl(&mut self, secs: u64) -> Vec<(Instant, Ctl)> {
        let end = tokio::time::Instant::now() + Duration::from_secs(secs);
        let mut out = Vec::new();
        while let Ok(Some(m)) = tokio::time::timeout_at(end, self.ctl.recv()).await {
            out.push(m);
        }
        out
    }

    /// Reads frames until `pick` accepts one (acks are the transport's job).
    pub async fn wait_frame<T>(
        &mut self,
        secs: u64,
        mut pick: impl FnMut(&VideoFrame) -> Option<T>,
    ) -> Option<T> {
        let end = tokio::time::Instant::now() + Duration::from_secs(secs);
        loop {
            match tokio::time::timeout_at(end, self.frames.recv()).await {
                Ok(Some(f)) => {
                    if let Some(v) = pick(&f) {
                        return Some(v);
                    }
                }
                _ => return None,
            }
        }
    }

    /// The next received transfer within `secs`.
    pub async fn next_transfer(&mut self, secs: u64) -> Option<Received> {
        tokio::time::timeout(Duration::from_secs(secs), self.transfers.recv())
            .await
            .ok()
            .flatten()
    }

    /// Sends one transfer body; returns whether the receiver accepted all of it.
    pub async fn send_transfer(
        &self,
        kind: TransferKind,
        mime: &str,
        name: &str,
        body: &[u8],
    ) -> Result<(), hx_transport::Error> {
        let mut s = self
            .conn
            .open_transfer(
                kind,
                TransferHeader {
                    mime: mime.into(),
                    name: name.into(),
                    size: body.len() as u64,
                },
            )
            .await?;
        for part in body.chunks(32 * 1024) {
            s.write(part).await?;
        }
        s.finish().await
    }
}

/// Changes the screen every few milliseconds until dropped: a rectangle that moves, or, when
/// `heavy`, the whole screen in noise.
pub struct Drawer {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drawer {
    pub fn start(display: &str, heavy: bool) -> Drawer {
        let stop = Arc::new(AtomicBool::new(false));
        let (s, d) = (stop.clone(), display.to_owned());
        let thread = std::thread::spawn(move || {
            let mut n = 0u32;
            while !s.load(SeqCst) {
                if heavy {
                    for row in 0..12i16 {
                        fill_root(
                            &d,
                            (0, row * 30, W as u16, 30),
                            n.wrapping_mul(0x0101_0305) ^ (row as u32 * 0x3377),
                        );
                    }
                } else {
                    fill_root(
                        &d,
                        (20 + (n % 20) as i16 * 10, 20, 30, 30),
                        n.wrapping_mul(0x0001_0203),
                    );
                }
                n += 1;
                std::thread::sleep(Duration::from_millis(15));
            }
        });
        Drawer {
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Drawer {
    fn drop(&mut self) {
        self.stop.store(true, SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

pub fn watcher(x: &Xvfb) -> (RustConnection, u32) {
    let (conn, n) = RustConnection::connect(Some(&x.display)).unwrap();
    let root = conn.setup().roots[n].root;
    conn.change_window_attributes(
        root,
        &ChangeWindowAttributesAux::new().event_mask(
            EventMask::KEY_PRESS
                | EventMask::KEY_RELEASE
                | EventMask::BUTTON_PRESS
                | EventMask::BUTTON_RELEASE,
        ),
    )
    .unwrap()
    .check()
    .unwrap();
    (conn, root)
}

/// (kind, detail) of key and button events, polled for up to `within`.
pub fn key_events(conn: &RustConnection, want: usize, within: Duration) -> Vec<(&'static str, u8)> {
    let end = Instant::now() + within;
    let mut out = Vec::new();
    while out.len() < want && Instant::now() < end {
        match conn.poll_for_event().unwrap() {
            Some(XEvent::KeyPress(e)) => out.push(("kp", e.detail)),
            Some(XEvent::KeyRelease(e)) => out.push(("kr", e.detail)),
            Some(XEvent::ButtonPress(e)) => out.push(("bp", e.detail)),
            Some(XEvent::ButtonRelease(e)) => out.push(("br", e.detail)),
            Some(_) => {}
            None => std::thread::sleep(Duration::from_millis(3)),
        }
    }
    out
}

/// The pointer position, polled until it equals `want` (or `within` passes).
pub async fn pointer_at(
    conn: &RustConnection,
    root: u32,
    want: (i16, i16),
    within: Duration,
) -> (i16, i16) {
    let end = Instant::now() + within;
    loop {
        let p = conn.query_pointer(root).unwrap().reply().unwrap();
        if (p.root_x, p.root_y) == want || Instant::now() > end {
            return (p.root_x, p.root_y);
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// A UDP forwarder in front of the gateway that shapes the way back to the client: a rate in
/// bytes per second (0 = unlimited), a one-way delay and a queue that drops its tail. It makes a
/// slow link without root (the tests' stand-in for `tc netem`).
pub struct Shaper {
    pub addr: SocketAddr,
    rate: Arc<AtomicU64>,
    tasks: Vec<JoinHandle<()>>,
}

impl Shaper {
    pub async fn start(gateway: SocketAddr) -> Shaper {
        let front = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let back = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        back.connect(gateway).await.unwrap();
        let addr = front.local_addr().unwrap();
        let rate = Arc::new(AtomicU64::new(0));
        let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
        let mut tasks = Vec::new();
        // Client to gateway: straight through.
        {
            let (front, back, client) = (front.clone(), back.clone(), client.clone());
            tasks.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 65_536];
                while let Ok((n, from)) = front.recv_from(&mut buf).await {
                    *client.lock().unwrap() = Some(from);
                    let _ = back.send(&buf[..n]).await;
                }
            }));
        }
        // Gateway to client: queued, delayed and rate limited.
        {
            let (front, back, client, rate) =
                (front.clone(), back.clone(), client.clone(), rate.clone());
            tasks.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 65_536];
                let (tx, mut rx) = mpsc::channel::<(Instant, Vec<u8>)>(64);
                let sender = tokio::spawn(async move {
                    while let Some((at, pkt)) = rx.recv().await {
                        tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await;
                        let r = rate.load(SeqCst);
                        if let Some(us) = (pkt.len() as u64 * 1_000_000).checked_div(r) {
                            tokio::time::sleep(Duration::from_micros(us)).await;
                        }
                        let to = *client.lock().unwrap();
                        if let Some(to) = to {
                            let _ = front.send_to(&pkt, to).await;
                        }
                    }
                });
                while let Ok(n) = back.recv(&mut buf).await {
                    // A full queue drops the packet (a tail-drop router).
                    let _ = tx.try_send((
                        Instant::now() + Duration::from_millis(20),
                        buf[..n].to_vec(),
                    ));
                }
                sender.abort();
            }));
        }
        Shaper { addr, rate, tasks }
    }

    /// Limits the way to the client to `bytes_per_s` (0: no limit).
    pub fn limit(&self, bytes_per_s: u64) {
        self.rate.store(bytes_per_s, SeqCst);
    }
}

impl Drop for Shaper {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}
