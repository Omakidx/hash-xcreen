//! The real session: pairing, PIN login, and a live connection with its tasks (video in,
//! control, cursor, transfers, input out, device management).
//!
//! Everything uses the 1.2 client APIs of `hx-crypto` and `hx-transport` directly.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering::Relaxed};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use hx_crypto::{
    AwaitingPin, IdentityKey, PairClientOptions, PairingCredential, Pin, PinReply, PublicKey,
    SessionOptions, connect_session, pair_device,
};
use hx_proto::VideoCodec;
use hx_proto::channel::CloseCode;
use hx_proto::pb::{
    self, ControlMessage, DeviceInfo, InputEvent, RevokeStatus, TransferHeader, ViewConfig,
    control_message::Message as Ctl, device_mgmt::Body,
};
use hx_proto::version::{Features, PROTOCOL_MINOR, capabilities_with_file_limit};
use hx_transport::{Connection, Target, TransferKind, TransportPreference, VideoFrame};
use rustls::pki_types::ServerName;
use tokio::sync::{mpsc, oneshot};

use super::connect::{Outcome, classify_error};
use super::lifecycle::{CloseReason, classify_close};
use crate::backend::{PairedInfo, SetupError};
use crate::files::{Activity, Direction, TransferState};
use crate::video::Stats;

/// A server to talk to: address, pinned key and this device.
#[derive(Clone)]
pub struct Link {
    /// Host or IP.
    pub host: String,
    /// Agent port.
    pub port: u16,
    /// Pinned server key.
    pub server_key: PublicKey,
    /// This device's key.
    pub device: Arc<IdentityKey>,
    /// Name shown in the server's device list.
    pub device_name: String,
}

/// Resolves `host:port` to a transport target.
pub async fn target(host: &str, port: u16) -> std::io::Result<Target> {
    let addr: SocketAddr = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => SocketAddr::new(ip, port),
        Err(_) => tokio::net::lookup_host((host, port))
            .await?
            .next()
            .ok_or_else(|| std::io::Error::other("no address"))?,
    };
    Ok(Target {
        addr,
        server_name: ServerName::try_from("hx.invalid").expect("static name"),
    })
}

/// Session options: H.264, every feature of this minor, our own file limit.
pub fn session_options(device_name: &str) -> SessionOptions {
    SessionOptions {
        preference: TransportPreference::Auto,
        device_name: device_name.chars().take(64).collect(),
        software: concat!("hx-desktop ", env!("CARGO_PKG_VERSION")).into(),
        capabilities: capabilities_with_file_limit(
            &[VideoCodec::H264],
            Features::defined_up_to(PROTOCOL_MINOR),
            0,
        ),
        ..Default::default()
    }
}

/// Pairs with a token (`hxt1-...`) or a code (`XXXX-XXXX`) and returns the server's key and
/// label. The caller pins the key; the pairing connection is closed here.
pub async fn pair(
    host: &str,
    port: u16,
    device: &Arc<IdentityKey>,
    credential: &str,
    device_name: &str,
) -> Result<PairedInfo, SetupError> {
    let cred =
        PairingCredential::parse(credential.trim()).map_err(|_| SetupError::PairingFailed)?;
    let t = target(host, port)
        .await
        .map_err(|_| SetupError::Unreachable)?;
    let opts = PairClientOptions {
        preference: TransportPreference::Auto,
        device_name: device_name.chars().take(64).collect(),
        software: concat!("hx-desktop ", env!("CARGO_PKG_VERSION")).into(),
        ..Default::default()
    };
    match pair_device(&t, device, &cred, &opts).await {
        Ok(p) => {
            let info = PairedInfo {
                server_key_hex: key_hex(&p.server_key),
                server_name: p.server_name.clone(),
            };
            p.finish().await;
            Ok(info)
        }
        Err(hx_crypto::Error::PairingClosed) => Err(SetupError::PairingClosed),
        Err(hx_crypto::Error::PairingFailed) => Err(SetupError::PairingFailed),
        Err(hx_crypto::Error::Refused { .. }) => Err(SetupError::PairingFailed),
        Err(hx_crypto::Error::Transport(_) | hx_crypto::Error::Timeout(_)) => {
            Err(SetupError::Unreachable)
        }
        Err(e) => Err(SetupError::Other(super::connect::sanitize(&e.to_string()))),
    }
}

/// A public key as 64 lowercase hex digits.
pub fn key_hex(k: &PublicKey) -> String {
    k.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// Parses 64 hex digits.
pub fn parse_key(h: &str) -> Option<PublicKey> {
    if h.len() != 64 || !h.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).ok()?;
    }
    PublicKey::from_bytes(&out).ok()
}

/// A secure connection that waits for the PIN.
pub struct PinLogin {
    awaiting: AwaitingPin,
}

/// Opens the pinned connection (step one of Connect).
pub async fn open_pin_login(link: &Link) -> Result<PinLogin, Outcome> {
    let t = target(&link.host, link.port)
        .await
        .map_err(|e| Outcome::Unreachable(e.to_string()))?;
    let opts = session_options(&link.device_name);
    let awaiting = connect_session(&t, &link.device, link.server_key, &opts)
        .await
        .map_err(|e| classify_error(&e))?;
    Ok(PinLogin { awaiting })
}

impl PinLogin {
    /// Sends one PIN attempt. On `Accepted` the authorized connection is returned.
    pub async fn submit(mut self, pin: &str) -> Result<Connection, (Outcome, Option<PinLogin>)> {
        let Ok(pin) = Pin::new(pin) else {
            return Err((
                Outcome::Wrong {
                    attempts_left: 0,
                    retry_after: Duration::ZERO,
                },
                Some(self),
            ));
        };
        match self.awaiting.submit(&pin).await {
            Ok(PinReply::Accepted) => self
                .awaiting
                .into_connection()
                .map_err(|e| (classify_error(&e), None)),
            Ok(PinReply::Wrong {
                attempts_left,
                retry_after,
            }) => Err((
                Outcome::Wrong {
                    attempts_left,
                    retry_after,
                },
                Some(self),
            )),
            Ok(PinReply::Backoff { retry_after }) => {
                Err((Outcome::Backoff { retry_after }, Some(self)))
            }
            Err(e) => Err((classify_error(&e), None)),
        }
    }

    /// Gives up (closes the connection).
    pub async fn abandon(self) {
        self.awaiting.abandon().await;
    }
}

/// Connects and submits one PIN in one go (a new connection per attempt).
pub async fn login(link: &Link, pin: &str) -> Result<Connection, Outcome> {
    let l = open_pin_login(link).await?;
    match l.submit(pin).await {
        Ok(c) => Ok(c),
        Err((o, rest)) => {
            if let Some(r) = rest {
                r.abandon().await;
            }
            Err(o)
        }
    }
}

// ----------------------------------------------------------------------------- live session

/// What a live session reports to the app.
#[derive(Debug)]
pub enum Event {
    /// The stream format (also after a resize).
    Stream(pb::StreamInfo),
    /// Server statistics, about once a second.
    Stats(pb::ServerStats),
    /// A cursor shape or position.
    Cursor(pb::CursorEvent),
    /// Text the desktop put on its clipboard.
    ClipboardText(String),
    /// A clipboard transfer that is a list of links (`text/uri-list`).
    LinkRequest(Vec<u8>),
    /// A clipboard image (PNG), kept for a native clipboard to take.
    ClipboardImage(Vec<u8>),
    /// A transfer started, advanced or ended.
    Transfer {
        /// Transfer id.
        id: u64,
        /// The row.
        activity: Activity,
        /// Where a received file was saved.
        saved: Option<PathBuf>,
    },
    /// The device list changed on the server.
    DeviceEvent(pb::DeviceEvent),
    /// The session ended.
    Closed(CloseReason),
}

/// Why a device-management call failed.
#[derive(Debug, thiserror::Error)]
pub enum MgmtError {
    /// Feature not negotiated (a 1.1 server).
    #[error("this server does not support device management")]
    Unsupported,
    /// The connection ended.
    #[error("the connection ended")]
    Closed,
    /// No answer in time.
    #[error("no answer from the server")]
    Timeout,
}

enum Out {
    Control(Ctl),
    Input(InputEvent),
    Move { x: i32, y: i32 },
}

type Pending = Arc<Mutex<HashMap<u32, oneshot::Sender<Body>>>>;

/// A live, authorized connection and the tasks that serve it.
pub struct Session {
    conn: Connection,
    out: mpsc::UnboundedSender<Out>,
    pending: Pending,
    next_request: AtomicU32,
    next_transfer: Arc<AtomicU32>,
    handle: tokio::runtime::Handle,
    features: Features,
    file_limit: u64,
    /// Shared counters.
    pub stats: Arc<Stats>,
}

impl Session {
    /// Starts the tasks. Video frames go to `frames` (the decoder), everything else to the
    /// returned event channel. A session that never sends a `ViewConfig` claims no desktop
    /// (device-management only).
    pub fn start(
        conn: Connection,
        frames: Option<SyncSender<VideoFrame>>,
        downloads: PathBuf,
        stats: Arc<Stats>,
        handle: tokio::runtime::Handle,
    ) -> (Session, mpsc::UnboundedReceiver<Event>) {
        let (ev_tx, ev_rx) = mpsc::unbounded_channel();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Out>();
        let pending: Pending = Arc::default();
        let goodbye: Arc<Mutex<Option<pb::Goodbye>>> = Arc::default();
        let negotiated = conn.negotiated().clone();

        // Output: control, input and coalesced mouse motion, in order.
        let c = conn.clone();
        handle.spawn(async move {
            while let Some(first) = out_rx.recv().await {
                let mut batch = vec![first];
                while let Ok(n) = out_rx.try_recv() {
                    batch.push(n);
                }
                let mut last_move = None;
                for o in batch {
                    let r = match o {
                        Out::Move { x, y } => {
                            last_move = Some((x, y));
                            continue;
                        }
                        other => {
                            if let Some((x, y)) = last_move.take() {
                                let _ = c.send_mouse_move(false, x, y).await;
                            }
                            match other {
                                Out::Control(m) => c.send_control(&ControlMessage::new(m)).await,
                                Out::Input(e) => c.send_input(&e).await,
                                Out::Move { .. } => Ok(()),
                            }
                        }
                    };
                    if r.is_err() {
                        return;
                    }
                }
                if let Some((x, y)) = last_move
                    && c.send_mouse_move(false, x, y).await.is_err()
                {
                    return;
                }
            }
        });

        // Video in.
        if let Some(frames) = frames {
            let (c, st, o) = (conn.clone(), stats.clone(), out_tx.clone());
            handle.spawn(async move {
                let mut asked = 0u32;
                while let Ok(f) = c.recv_video_frame().await {
                    if frames.try_send(f).is_err() {
                        st.dropped();
                        asked += 1;
                        if asked == 1 {
                            let _ =
                                o.send(Out::Control(Ctl::RequestKeyframe(pb::RequestKeyframe {
                                    last_decoded_frame: 0,
                                })));
                        }
                    } else {
                        asked = 0;
                    }
                }
            });
        }

        // Control in.
        let (c, tx, pend, gb) = (
            conn.clone(),
            ev_tx.clone(),
            pending.clone(),
            goodbye.clone(),
        );
        handle.spawn(async move {
            while let Ok(m) = c.recv_control().await {
                match m.message {
                    Some(Ctl::StreamInfo(s)) => {
                        let _ = tx.send(Event::Stream(s));
                    }
                    Some(Ctl::ServerStats(s)) => {
                        let _ = tx.send(Event::Stats(s));
                    }
                    Some(Ctl::Goodbye(g)) => {
                        if let Ok(mut slot) = gb.lock() {
                            *slot = Some(g);
                        }
                    }
                    Some(Ctl::DeviceMgmt(d)) => match (d.request_id, d.body) {
                        (0, Some(Body::Event(e))) => {
                            let _ = tx.send(Event::DeviceEvent(e));
                        }
                        (id, Some(body)) if id != 0 => {
                            let waiter = pend.lock().ok().and_then(|mut p| p.remove(&id));
                            if let Some(w) = waiter {
                                let _ = w.send(body);
                            }
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
        });

        // Cursor in.
        let (c, tx) = (conn.clone(), ev_tx.clone());
        handle.spawn(async move {
            while let Ok(e) = c.recv_cursor().await {
                if tx.send(Event::Cursor(e)).is_err() {
                    break;
                }
            }
        });

        // Transfers in.
        let (c, tx, ids) = (
            conn.clone(),
            ev_tx.clone(),
            Arc::new(AtomicU32::new(1 << 20)),
        );
        let limit = negotiated.max_file_bytes;
        let dl = downloads.clone();
        handle.spawn(async move {
            while let Ok(t) = c.accept_transfer().await {
                let id = u64::from(ids.fetch_add(1, Relaxed));
                tokio::spawn(receive_transfer(t, id, tx.clone(), dl.clone(), limit));
            }
        });

        // Once a second: our statistics to the server, and the round trip.
        let (c, st) = (conn.clone(), stats.clone());
        handle.spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            loop {
                tick.tick().await;
                if let Ok(rtt) = c.ping(Duration::from_secs(5)).await {
                    st.rtt_us
                        .store(rtt.as_micros().min(u128::from(u32::MAX)) as u32, Relaxed);
                }
                let i = st.take_interval();
                let m = ControlMessage::new(Ctl::Stats(pb::ClientStats {
                    interval_ms: 1000,
                    decoded_frames: i.decoded,
                    dropped_frames: i.dropped,
                    decode_p95_us: i.decode_p95_us,
                }));
                if c.send_control(&m).await.is_err() {
                    break;
                }
            }
        });

        // End.
        let (c, tx, gb) = (conn.clone(), ev_tx, goodbye);
        handle.spawn(async move {
            let info = c.closed().await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            let g = gb.lock().ok().and_then(|g| g.clone());
            let _ = tx.send(Event::Closed(classify_close(Some(&info), g.as_ref())));
        });

        (
            Session {
                conn,
                out: out_tx,
                pending,
                next_request: AtomicU32::new(1),
                next_transfer: Arc::new(AtomicU32::new(1)),
                handle,
                features: negotiated.features,
                file_limit: negotiated.max_file_bytes,
                stats,
            },
            ev_rx,
        )
    }

    /// The negotiated file limit.
    pub fn file_limit(&self) -> u64 {
        self.file_limit
    }

    /// Whether device management was negotiated.
    pub fn can_manage_devices(&self) -> bool {
        self.features.contains(Features::DEVICE_MANAGEMENT)
    }

    /// Sends a `ViewConfig` (claims the desktop on the first one).
    pub fn view(&self, v: ViewConfig) {
        let _ = self.out.send(Out::Control(Ctl::ViewConfig(v)));
    }

    /// Asks for a fresh keyframe.
    pub fn request_keyframe(&self, last: u32) {
        let _ = self
            .out
            .send(Out::Control(Ctl::RequestKeyframe(pb::RequestKeyframe {
                last_decoded_frame: last,
            })));
    }

    /// A key by HID usage.
    pub fn key(&self, usage: u32, pressed: bool) {
        let _ = self.out.send(Out::Input(InputEvent {
            event: Some(pb::input_event::Event::Key(pb::KeyEvent {
                scancode: usage,
                pressed,
            })),
        }));
    }

    /// A button at a remote pixel.
    pub fn button(&self, b: pb::MouseButton, pressed: bool, x: i32, y: i32) {
        let _ = self.out.send(Out::Input(InputEvent {
            event: Some(pb::input_event::Event::Button(pb::ButtonEvent {
                button: b as i32,
                pressed,
                x,
                y,
            })),
        }));
    }

    /// Scroll in 1/120 notches.
    pub fn scroll(&self, dx: i32, dy: i32) {
        let _ = self.out.send(Out::Input(InputEvent {
            event: Some(pb::input_event::Event::Scroll(pb::ScrollEvent { dx, dy })),
        }));
    }

    /// Pointer motion to a remote pixel (latest wins).
    pub fn motion(&self, x: i32, y: i32) {
        let _ = self.out.send(Out::Move { x, y });
    }

    /// Releases every key and button on the server.
    pub fn release_all(&self) {
        let _ = self.out.send(Out::Input(InputEvent {
            event: Some(pb::input_event::Event::ReleaseAll(pb::ReleaseAll {})),
        }));
    }

    /// Puts text on the desktop's clipboard.
    pub fn send_clipboard_text(&self, text: &str) {
        if !self.features.contains(Features::CLIPBOARD) || text.is_empty() {
            return;
        }
        let (c, body) = (self.conn.clone(), text.as_bytes().to_vec());
        self.handle.spawn(async move {
            let header = TransferHeader {
                mime: "text/plain;charset=utf-8".into(),
                name: String::new(),
                size: body.len() as u64,
            };
            if let Ok(mut s) = c.open_transfer(TransferKind::Clipboard, header).await {
                if s.write(&body).await.is_ok() {
                    let _ = s.finish().await;
                } else {
                    s.abort();
                }
            }
        });
    }

    /// Sends a file to the desktop. The limit is checked first by the caller
    /// ([`crate::files::check_send`]).
    pub fn send_file(&self, path: PathBuf, events: mpsc::UnboundedSender<Event>) {
        if !self.features.contains(Features::FILE_TRANSFER) {
            return;
        }
        let c = self.conn.clone();
        let id = u64::from(self.next_transfer.fetch_add(1, Relaxed));
        self.handle.spawn(async move {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "file".into());
            let report = |done: u64, total: u64, state: TransferState| {
                let _ = events.send(Event::Transfer {
                    id,
                    activity: Activity {
                        name: name.clone(),
                        dir: Direction::Up,
                        done,
                        total,
                        state,
                    },
                    saved: None,
                });
            };
            let result: Result<(), String> = async {
                use tokio::io::AsyncReadExt;
                let mut f = tokio::fs::File::open(&path)
                    .await
                    .map_err(|e| e.to_string())?;
                let md = f.metadata().await.map_err(|e| e.to_string())?;
                if !md.is_file() {
                    return Err("not a regular file".into());
                }
                let total = md.len();
                let header = TransferHeader {
                    mime: "application/octet-stream".into(),
                    name: crate::files::safe_file_name(&name),
                    size: total,
                };
                let mut s = c
                    .open_transfer(TransferKind::File, header)
                    .await
                    .map_err(|e| e.to_string())?;
                report(0, total, TransferState::Running);
                let mut buf = vec![0u8; 32 * 1024];
                let mut done = 0u64;
                let mut last = std::time::Instant::now();
                loop {
                    let n = f.read(&mut buf).await.map_err(|e| e.to_string())?;
                    if n == 0 {
                        break;
                    }
                    s.write(&buf[..n]).await.map_err(|e| e.to_string())?;
                    done += n as u64;
                    if last.elapsed() > Duration::from_millis(200) {
                        last = std::time::Instant::now();
                        report(done, total, TransferState::Running);
                    }
                }
                s.finish().await.map_err(|e| e.to_string())?;
                report(total, total, TransferState::Done);
                Ok(())
            }
            .await;
            if let Err(e) = result {
                report(0, 0, TransferState::Failed(super::connect::sanitize(&e)));
            }
        });
    }

    async fn request(&self, body: Body) -> Result<Body, MgmtError> {
        if !self.can_manage_devices() {
            return Err(MgmtError::Unsupported);
        }
        let id = self.next_request.fetch_add(1, Relaxed);
        let (tx, rx) = oneshot::channel();
        if let Ok(mut p) = self.pending.lock() {
            p.insert(id, tx);
        }
        let msg = Ctl::DeviceMgmt(pb::DeviceMgmt {
            request_id: id,
            body: Some(body),
        });
        if self.out.send(Out::Control(msg)).is_err() {
            return Err(MgmtError::Closed);
        }
        match tokio::time::timeout(Duration::from_secs(10), rx).await {
            Ok(Ok(b)) => Ok(b),
            Ok(Err(_)) => Err(MgmtError::Closed),
            Err(_) => {
                if let Ok(mut p) = self.pending.lock() {
                    p.remove(&id);
                }
                Err(MgmtError::Timeout)
            }
        }
    }

    /// The paired devices (revoked ones included).
    pub async fn list_devices(&self) -> Result<Vec<DeviceInfo>, MgmtError> {
        match self.request(Body::List(pb::ListDevices {})).await? {
            Body::DeviceList(l) => Ok(l.devices),
            _ => Err(MgmtError::Closed),
        }
    }

    /// Revokes a device.
    pub async fn revoke(&self, id: [u8; 16]) -> Result<RevokeStatus, MgmtError> {
        let b = Body::Revoke(pb::RevokeDevice {
            device_id: Bytes::copy_from_slice(&id),
        });
        match self.request(b).await? {
            Body::RevokeResult(r) => {
                Ok(RevokeStatus::try_from(r.status).unwrap_or(RevokeStatus::Failed))
            }
            _ => Err(MgmtError::Closed),
        }
    }

    /// Ends the session.
    pub async fn close(&self) {
        self.conn.close(CloseCode::NoError, "bye").await;
    }

    /// The transport connection (tests and advanced callers).
    pub fn connection(&self) -> &Connection {
        &self.conn
    }
}

async fn receive_transfer(
    mut t: hx_transport::IncomingTransfer,
    id: u64,
    tx: mpsc::UnboundedSender<Event>,
    downloads: PathBuf,
    limit: u64,
) {
    let name = crate::files::safe_file_name(&t.header.name);
    let total = t.header.size;
    match t.kind {
        TransferKind::Clipboard => {
            let mime = t.header.mime.clone();
            let Ok(body) = t.read_to_end(hx_proto::channel::MAX_CLIPBOARD_SIZE).await else {
                return;
            };
            let m = mime
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            let ev = match m.as_str() {
                "text/plain" => Event::ClipboardText(String::from_utf8_lossy(&body).into_owned()),
                "text/uri-list" => Event::LinkRequest(body.to_vec()),
                "image/png" => Event::ClipboardImage(body.to_vec()),
                _ => return,
            };
            let _ = tx.send(ev);
        }
        TransferKind::File => {
            let act = |done, state| Activity {
                name: name.clone(),
                dir: Direction::Down,
                done,
                total,
                state,
            };
            if t.header.validate_file(limit).is_err() {
                t.reject();
                let _ = tx.send(Event::Transfer {
                    id,
                    activity: act(
                        0,
                        TransferState::Failed(crate::files::refusal_text(&name, limit)),
                    ),
                    saved: None,
                });
                return;
            }
            let _ = std::fs::create_dir_all(&downloads);
            let path = crate::files::unique_path(&downloads, &name);
            let res: Result<(), String> = async {
                use tokio::io::AsyncWriteExt;
                let mut f = tokio::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .await
                    .map_err(|e| e.to_string())?;
                let mut done = 0u64;
                let mut last = std::time::Instant::now();
                let _ = tx.send(Event::Transfer {
                    id,
                    activity: act(0, TransferState::Running),
                    saved: None,
                });
                while let Some(chunk) = t.next_chunk().await.map_err(|e| e.to_string())? {
                    f.write_all(&chunk).await.map_err(|e| e.to_string())?;
                    done += chunk.len() as u64;
                    if last.elapsed() > Duration::from_millis(200) {
                        last = std::time::Instant::now();
                        let _ = tx.send(Event::Transfer {
                            id,
                            activity: act(done, TransferState::Running),
                            saved: None,
                        });
                    }
                }
                f.flush().await.map_err(|e| e.to_string())?;
                Ok(())
            }
            .await;
            match res {
                Ok(()) => {
                    let _ = tx.send(Event::Transfer {
                        id,
                        activity: act(total, TransferState::Done),
                        saved: Some(path),
                    });
                }
                Err(e) => {
                    let _ = std::fs::remove_file(&path);
                    let _ = tx.send(Event::Transfer {
                        id,
                        activity: act(0, TransferState::Failed(super::connect::sanitize(&e))),
                        saved: None,
                    });
                }
            }
        }
    }
}
