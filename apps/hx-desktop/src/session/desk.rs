//! The two seams of a live connection: [`Desk`] (what the app does on an authorized connection)
//! and [`Connector`] (how it gets one). The real implementations use `hx-crypto` and
//! `hx-transport`; the demo ones live in `crate::backend::demo`.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::SyncSender;

use hx_proto::pb::{DeviceInfo, MouseButton, RevokeStatus, ViewConfig};
use hx_transport::VideoFrame;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use super::connect::Outcome;
use super::net::{Event, Link, MgmtError, Session};
use crate::backend::BoxFuture;
use crate::video::{Presenter, Stats};

/// What the app does on an authorized connection.
pub trait Desk: Send + Sync {
    /// Sends a `ViewConfig`; the first one claims the desktop.
    fn view(&self, v: ViewConfig);
    /// Asks for a keyframe.
    fn request_keyframe(&self, last: u32);
    /// A key by HID usage.
    fn key(&self, usage: u32, pressed: bool);
    /// A mouse button at a remote pixel.
    fn button(&self, b: MouseButton, pressed: bool, x: i32, y: i32);
    /// Scroll in 1/120 notches.
    fn scroll(&self, dx: i32, dy: i32);
    /// Pointer motion.
    fn motion(&self, x: i32, y: i32);
    /// Releases every key and button.
    fn release_all(&self);
    /// Text for the desktop's clipboard.
    fn send_clipboard_text(&self, text: &str);
    /// Sends a file; progress arrives on `events`.
    fn send_file(&self, path: PathBuf, events: UnboundedSender<Event>);
    /// The effective file limit.
    fn file_limit(&self) -> u64;
    /// Shared counters.
    fn stats(&self) -> Arc<Stats>;
    /// Lists paired devices.
    fn list_devices(&self) -> BoxFuture<'_, Result<Vec<DeviceInfo>, MgmtError>>;
    /// Revokes a device.
    fn revoke(&self, id: [u8; 16]) -> BoxFuture<'_, Result<RevokeStatus, MgmtError>>;
    /// Ends the connection.
    fn close(&self) -> BoxFuture<'_, ()>;
    /// One server-management request (protocol 1.3) and its answer, over this connection's own
    /// control path (the single reader of control answers).
    fn server_request(
        &self,
        body: hx_proto::pb::server_mgmt::Body,
        wait: std::time::Duration,
    ) -> BoxFuture<'_, Result<hx_proto::pb::server_mgmt::Body, MgmtError>>;
    /// Asks the server for a pairing code (protocol 1.3, over this connection's own control
    /// path: the one place that reads `DeviceMgmt` answers).
    fn create_pairing_code(
        &self,
        expires_in_s: u32,
    ) -> BoxFuture<'_, Result<crate::backend::IssuedCode, crate::backend::AdminError>>;
}

impl Desk for Session {
    fn view(&self, v: ViewConfig) {
        Session::view(self, v);
    }
    fn request_keyframe(&self, last: u32) {
        Session::request_keyframe(self, last);
    }
    fn key(&self, usage: u32, pressed: bool) {
        Session::key(self, usage, pressed);
    }
    fn button(&self, b: MouseButton, pressed: bool, x: i32, y: i32) {
        Session::button(self, b, pressed, x, y);
    }
    fn scroll(&self, dx: i32, dy: i32) {
        Session::scroll(self, dx, dy);
    }
    fn motion(&self, x: i32, y: i32) {
        Session::motion(self, x, y);
    }
    fn release_all(&self) {
        Session::release_all(self);
    }
    fn send_clipboard_text(&self, text: &str) {
        Session::send_clipboard_text(self, text);
    }
    fn send_file(&self, path: PathBuf, events: UnboundedSender<Event>) {
        Session::send_file(self, path, events);
    }
    fn file_limit(&self) -> u64 {
        Session::file_limit(self)
    }
    fn stats(&self) -> Arc<Stats> {
        self.stats.clone()
    }
    fn list_devices(&self) -> BoxFuture<'_, Result<Vec<DeviceInfo>, MgmtError>> {
        Box::pin(Session::list_devices(self))
    }
    fn revoke(&self, id: [u8; 16]) -> BoxFuture<'_, Result<RevokeStatus, MgmtError>> {
        Box::pin(Session::revoke(self, id))
    }
    fn close(&self) -> BoxFuture<'_, ()> {
        Box::pin(Session::close(self))
    }
    fn server_request(
        &self,
        body: hx_proto::pb::server_mgmt::Body,
        wait: std::time::Duration,
    ) -> BoxFuture<'_, Result<hx_proto::pb::server_mgmt::Body, MgmtError>> {
        Box::pin(Session::server_request(self, body, wait))
    }
    fn create_pairing_code(
        &self,
        expires_in_s: u32,
    ) -> BoxFuture<'_, Result<crate::backend::IssuedCode, crate::backend::AdminError>> {
        Box::pin(Session::create_pairing_code(self, expires_in_s))
    }
}

/// What a connection needs from the app: where video goes and where files land.
pub struct Wiring {
    /// The decoder's input; `None` for a management-only session.
    pub frames: Option<SyncSender<VideoFrame>>,
    /// Where decoded pictures go (used by sources that decode themselves, like the demo).
    pub presenter: Option<Arc<dyn Presenter>>,
    /// Shared counters.
    pub stats: Arc<Stats>,
    /// Where received files are saved.
    pub downloads: PathBuf,
}

/// An authorized connection and its events.
pub struct Established {
    /// The protocol version the server showed (`major`, `minor`).
    pub server_version: Option<(u32, u32)>,
    /// The connection.
    pub desk: Arc<dyn Desk>,
    /// Everything the connection reports.
    pub events: UnboundedReceiver<Event>,
}

/// Opens connections.
pub trait Connector: Send + Sync {
    /// Connects securely, calls `on_secure` once the server is authenticated, then submits `pin`.
    /// Every call is one PIN attempt on the server.
    fn connect(
        &self,
        link: &Link,
        pin: &str,
        on_secure: Box<dyn FnOnce() + Send>,
        wiring: Wiring,
    ) -> BoxFuture<'_, Result<Established, Outcome>>;

    /// Whether anything answers at `host:port` (the Home status).
    fn probe(&self, host: &str, port: u16) -> BoxFuture<'_, bool>;
}

/// The real connector: pinned mutual TLS, then the PIN.
pub struct RealConnector {
    /// The runtime the session tasks run on.
    pub handle: tokio::runtime::Handle,
}

impl Connector for RealConnector {
    fn connect(
        &self,
        link: &Link,
        pin: &str,
        on_secure: Box<dyn FnOnce() + Send>,
        wiring: Wiring,
    ) -> BoxFuture<'_, Result<Established, Outcome>> {
        let (link, pin) = (link.clone(), zeroize::Zeroizing::new(pin.to_owned()));
        let handle = self.handle.clone();
        Box::pin(async move {
            let login = super::net::open_pin_login(&link).await?;
            on_secure();
            let version = Some(login.version);
            let conn = match login.submit(&pin).await {
                Ok(c) => c,
                Err((o, rest)) => {
                    if let Some(r) = rest {
                        r.abandon().await;
                    }
                    return Err(o);
                }
            };
            let (session, events) =
                Session::start(conn, wiring.frames, wiring.downloads, wiring.stats, handle);
            Ok(Established {
                server_version: version,
                desk: Arc::new(session),
                events,
            })
        })
    }

    fn probe(&self, host: &str, port: u16) -> BoxFuture<'_, bool> {
        let host = host.to_owned();
        Box::pin(async move {
            let Ok(t) = super::net::target(&host, port).await else {
                return false;
            };
            tokio::time::timeout(
                std::time::Duration::from_secs(3),
                tokio::net::TcpStream::connect(t.addr),
            )
            .await
            .is_ok_and(|r| r.is_ok())
        })
    }
}
