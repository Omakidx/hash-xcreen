//! The demo connection: a PIN check that follows the server's rules and a synthetic desktop.
//!
//! The PIN is `123456`. A wrong PIN answers with the attempts left and the protocol's wait
//! (`min(2^(n-1), 30)` s); the fifth wrong PIN revokes the device. Host hints: `down` is
//! unreachable, `changed` shows the identity-changed screen, `unavailable` is NOT_AVAILABLE,
//! `takeover` ends the session 10 s after it starts as taken over by another device, `drop`
//! loses the connection once after 10 s (the reconnect overlay).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use hx_proto::pb::{
    self, DeviceInfo, DeviceRevokeReason, DeviceStatus, MouseButton, RevokeStatus, ViewConfig,
};
use slint::{Rgba8Pixel, SharedPixelBuffer};
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};

use super::BoxFuture;
use crate::files::{Activity, Direction, TransferState};
use crate::session::connect::Outcome;
use crate::session::desk::{Connector, Desk, Established, Wiring};
use crate::session::lifecycle::CloseReason;
use crate::session::net::{Event, Link, MgmtError};
use crate::video::{Picture, Presenter, Stats};

/// The PIN the demo accepts.
pub const DEMO_PIN: &str = "123456";

/// Connector with per-server failure counters.
pub struct DemoConnector {
    failures: Mutex<HashMap<String, u32>>,
    dropped_once: Mutex<std::collections::HashSet<String>>,
    devices: Arc<Mutex<Vec<DeviceInfo>>>,
}

impl Default for DemoConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn device(id: u8, name: &str, last: u64, status: DeviceStatus, current: bool) -> DeviceInfo {
    DeviceInfo {
        device_id: Bytes::from(vec![id; 16]),
        name: name.into(),
        created_unix: 1_690_000_000,
        last_seen_unix: last,
        status: status as i32,
        revoke_reason: if status == DeviceStatus::Revoked {
            DeviceRevokeReason::User as i32
        } else {
            0
        },
        revoked_unix: if status == DeviceStatus::Revoked {
            1_699_920_000
        } else {
            0
        },
        current,
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl DemoConnector {
    /// A connector with the demo device list.
    pub fn new() -> Self {
        let n = now();
        Self {
            failures: Mutex::default(),
            dropped_once: Mutex::default(),
            devices: Arc::new(Mutex::new(vec![
                device(0xa1, "Alex's desktop", n, DeviceStatus::Active, true),
                device(
                    0xb2,
                    "Maya's laptop",
                    n - 2 * 3600,
                    DeviceStatus::Active,
                    false,
                ),
                device(0xc3, "Work PC", n - 2 * 86_400, DeviceStatus::Active, false),
                device(
                    0xd4,
                    "Old tablet",
                    n - 80 * 86_400,
                    DeviceStatus::Revoked,
                    false,
                ),
            ])),
        }
    }
}

impl Connector for DemoConnector {
    fn connect(
        &self,
        link: &Link,
        pin: &str,
        on_secure: Box<dyn FnOnce() + Send>,
        wiring: Wiring,
    ) -> BoxFuture<'_, Result<Established, Outcome>> {
        let host = link.host.clone();
        let key = format!("{}:{}", link.host, link.port);
        let pin = pin.to_owned();
        Box::pin(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            if host.contains("down") {
                return Err(Outcome::Unreachable(format!("no answer from {host}")));
            }
            if host.contains("changed") {
                return Err(Outcome::IdentityChanged);
            }
            on_secure();
            tokio::time::sleep(Duration::from_millis(400)).await;
            if host.contains("unavailable") {
                return Err(Outcome::NotAvailable {
                    retry_after: Duration::from_secs(20),
                });
            }
            if pin != DEMO_PIN {
                let n = {
                    let mut f = self
                        .failures
                        .lock()
                        .map_err(|_| Outcome::Failed("state".into()))?;
                    let c = f.entry(key).or_insert(0);
                    *c += 1;
                    *c
                };
                if n >= hx_crypto::MAX_PIN_FAILURES {
                    return Err(Outcome::Revoked);
                }
                return Err(Outcome::Wrong {
                    attempts_left: hx_crypto::MAX_PIN_FAILURES - n,
                    retry_after: hx_crypto::pin::backoff_after(n),
                });
            }
            if let Ok(mut f) = self.failures.lock() {
                f.remove(&key);
            }
            let first_drop =
                host.contains("drop") && self.dropped_once.lock().is_ok_and(|mut s| s.insert(key));
            Ok(demo_established(
                &host,
                wiring,
                self.devices.clone(),
                first_drop,
            ))
        })
    }

    fn probe(&self, host: &str, port: u16) -> BoxFuture<'_, bool> {
        let offline = host.contains("offline") || host.contains("down") || port == 8443;
        Box::pin(async move {
            tokio::time::sleep(Duration::from_millis(400)).await;
            !offline
        })
    }
}

fn demo_established(
    host: &str,
    wiring: Wiring,
    devices: Arc<Mutex<Vec<DeviceInfo>>>,
    drop_soon: bool,
) -> Established {
    let (tx, rx) = unbounded_channel();
    let desk = Arc::new(DemoDesk {
        events: tx.clone(),
        stop: Arc::new(AtomicBool::new(false)),
        pointer: Arc::new((AtomicU32::new(400), AtomicU32::new(225))),
        keys: AtomicU32::new(0),
        stats: wiring.stats.clone(),
        devices,
    });
    if let Some(p) = wiring.presenter.clone() {
        let (stop, ptr) = (desk.stop.clone(), desk.pointer.clone());
        let _ = std::thread::Builder::new()
            .name("hx-demo-video".into())
            .spawn(move || paint_loop(p, stop, ptr));
    }
    let (stop, st) = (desk.stop.clone(), desk.stats.clone());
    let tx2 = tx.clone();
    tokio::spawn(async move {
        let mut tick = 0u32;
        while !stop.load(SeqCst) {
            tokio::time::sleep(Duration::from_secs(1)).await;
            tick += 1;
            let i = st.take_interval();
            let _ = tx2.send(Event::Stats(pb::ServerStats {
                interval_ms: 1000,
                frames: 20 + (tick % 3),
                bitrate_kbps: 8400 + (tick % 5) * 40,
                rtt_us: 14_000 + (tick % 4) * 600,
                ..Default::default()
            }));
            let _ = i;
        }
    });
    let scenario_end = if host.contains("takeover") {
        Some(CloseReason::TakenOver {
            name: "Maya's laptop".into(),
            id_short: "b2b2b2b2".into(),
            id: Some([0xb2; 16]),
        })
    } else if drop_soon {
        Some(CloseReason::Network)
    } else {
        None
    };
    if let Some(reason) = scenario_end {
        let (stop, tx3) = (desk.stop.clone(), tx);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(10)).await;
            if !stop.load(SeqCst) {
                stop.store(true, SeqCst);
                let _ = tx3.send(Event::Closed(reason));
            }
        });
    }
    Established {
        server_version: Some((1, 3)),
        desk,
        events: rx,
    }
}

fn paint_loop(p: Arc<dyn Presenter>, stop: Arc<AtomicBool>, ptr: Arc<(AtomicU32, AtomicU32)>) {
    let (w, h) = (800u32, 450u32);
    let mut t = 0u32;
    while !stop.load(SeqCst) {
        let mut buf = SharedPixelBuffer::<Rgba8Pixel>::new(w, h);
        let px = buf.make_mut_slice();
        let ball = ((t * 4) % (2 * (w - 80)), 0);
        let bx = if ball.0 < w - 80 {
            ball.0
        } else {
            2 * (w - 80) - ball.0
        };
        let (cx, cy) = (ptr.0.load(SeqCst), ptr.1.load(SeqCst));
        for y in 0..h {
            for x in 0..w {
                let i = (y * w + x) as usize;
                let mut c = [
                    20 + (y * 40 / h) as u8,
                    50 + (y * 60 / h) as u8,
                    100 + (x * 60 / w) as u8,
                ];
                if y < 28 {
                    c = [60, 64, 70];
                } else if (60..420).contains(&x.saturating_add(0)) && (70..330).contains(&y) {
                    c = if y < 94 {
                        [90, 96, 108]
                    } else {
                        [245, 246, 248]
                    };
                    if y >= 94 && (y - 94) % 22 < 2 && x > 80 && x < 380 {
                        c = [200, 205, 212];
                    }
                }
                if (120 + bx..200 + bx).contains(&x) && (360..400).contains(&y) {
                    c = [255, 190, 60];
                }
                if (x == cx && (y.abs_diff(cy) < 12)) || (y == cy && (x.abs_diff(cx) < 12)) {
                    c = [255, 255, 255];
                }
                px[i] = Rgba8Pixel {
                    r: c[0],
                    g: c[1],
                    b: c[2],
                    a: 255,
                };
            }
        }
        p.present(Picture {
            width: w,
            height: h,
            pixels: buf,
        });
        t += 1;
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The synthetic desktop.
pub struct DemoDesk {
    events: UnboundedSender<Event>,
    stop: Arc<AtomicBool>,
    pointer: Arc<(AtomicU32, AtomicU32)>,
    keys: AtomicU32,
    stats: Arc<Stats>,
    devices: Arc<Mutex<Vec<DeviceInfo>>>,
}

impl Desk for DemoDesk {
    fn view(&self, v: ViewConfig) {
        let _ = self.events.send(Event::Stream(pb::StreamInfo {
            codec: pb::VideoCodec::H264 as i32,
            width: if v.width > 0 { v.width } else { 800 },
            height: if v.height > 0 { v.height } else { 450 },
            fps: v.max_fps.max(1),
            first_frame: 0,
        }));
    }
    fn request_keyframe(&self, _last: u32) {}
    fn key(&self, _usage: u32, pressed: bool) {
        if pressed {
            self.keys.fetch_add(1, SeqCst);
        }
    }
    fn button(&self, _b: MouseButton, _pressed: bool, x: i32, y: i32) {
        self.motion(x, y);
    }
    fn scroll(&self, _dx: i32, _dy: i32) {}
    fn motion(&self, x: i32, y: i32) {
        // The demo picture is 800x450 for a 1920x1080-looking remote: scale down.
        self.pointer.0.store((x.max(0) as u32) * 800 / 1920, SeqCst);
        self.pointer.1.store((y.max(0) as u32) * 450 / 1080, SeqCst);
    }
    fn release_all(&self) {}
    fn send_clipboard_text(&self, _text: &str) {}
    fn send_file(&self, path: PathBuf, events: UnboundedSender<Event>) {
        let name = path
            .file_name()
            .map_or("file".into(), |n| n.to_string_lossy().into_owned());
        let total = std::fs::metadata(&path).map_or(1_000_000, |m| m.len().max(1));
        tokio::spawn(async move {
            for i in 0..=5u64 {
                let st = if i == 5 {
                    TransferState::Done
                } else {
                    TransferState::Running
                };
                let _ = events.send(Event::Transfer {
                    id: 9000,
                    activity: Activity {
                        name: name.clone(),
                        dir: Direction::Up,
                        done: total * i / 5,
                        total,
                        state: st,
                    },
                    saved: None,
                });
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        });
    }
    fn file_limit(&self) -> u64 {
        hx_proto::channel::MAX_FILE_SIZE
    }
    fn stats(&self) -> Arc<Stats> {
        self.stats.clone()
    }
    fn list_devices(&self) -> BoxFuture<'_, Result<Vec<DeviceInfo>, MgmtError>> {
        Box::pin(async move { Ok(self.devices.lock().map(|d| d.clone()).unwrap_or_default()) })
    }
    fn revoke(&self, id: [u8; 16]) -> BoxFuture<'_, Result<RevokeStatus, MgmtError>> {
        Box::pin(async move {
            let Ok(mut d) = self.devices.lock() else {
                return Ok(RevokeStatus::Failed);
            };
            let active = d
                .iter()
                .filter(|x| x.status() == DeviceStatus::Active)
                .count();
            let Some(t) = d.iter_mut().find(|x| x.device_id[..] == id[..]) else {
                return Ok(RevokeStatus::NotFound);
            };
            if t.status() == DeviceStatus::Revoked {
                return Ok(RevokeStatus::AlreadyRevoked);
            }
            if t.current && active <= 1 {
                return Ok(RevokeStatus::LastActiveDevice);
            }
            t.status = DeviceStatus::Revoked as i32;
            t.revoke_reason = DeviceRevokeReason::User as i32;
            t.revoked_unix = now();
            Ok(RevokeStatus::Ok)
        })
    }
    fn close(&self) -> BoxFuture<'_, ()> {
        self.stop.store(true, SeqCst);
        Box::pin(async {})
    }
    fn server_request(
        &self,
        _body: hx_proto::pb::server_mgmt::Body,
        _wait: Duration,
    ) -> BoxFuture<'_, Result<hx_proto::pb::server_mgmt::Body, MgmtError>> {
        // The demo answers server management through `DemoServerControl`, not the wire.
        Box::pin(async { Err(MgmtError::Unsupported) })
    }
    fn create_pairing_code(
        &self,
        _ttl: u32,
    ) -> BoxFuture<'_, Result<crate::backend::IssuedCode, crate::backend::AdminError>> {
        Box::pin(async {
            Ok(crate::backend::IssuedCode {
                code: "K7QM-4XD2".into(),
                expires_in_secs: 900,
                tries: 3,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(host: &str) -> Link {
        Link {
            host: host.into(),
            port: 443,
            server_key: crate::session::net::parse_key(&"3f9ac1d477be0a52".repeat(4))
                .unwrap_or_else(|| hx_crypto::IdentityKey::generate().unwrap().public()),
            device: Arc::new(hx_crypto::IdentityKey::generate().unwrap()),
            device_name: "t".into(),
        }
    }

    fn wiring() -> Wiring {
        Wiring {
            frames: None,
            presenter: None,
            stats: Arc::new(Stats::default()),
        }
    }

    #[tokio::test]
    async fn pin_rules_match_the_server() {
        let c = DemoConnector::new();
        let l = link("demo.test");
        for left in (1..=4).rev() {
            match c.connect(&l, "000000", Box::new(|| {}), wiring()).await {
                Err(Outcome::Wrong { attempts_left, .. }) => assert_eq!(attempts_left, left),
                _ => panic!("expected a wrong PIN"),
            }
        }
        assert!(matches!(
            c.connect(&l, "000000", Box::new(|| {}), wiring()).await,
            Err(Outcome::Revoked)
        ));
    }

    #[tokio::test]
    async fn the_right_pin_connects_and_resets_the_count() {
        let c = DemoConnector::new();
        let l = link("demo.test");
        let _ = c.connect(&l, "1", Box::new(|| {}), wiring()).await;
        let est = c
            .connect(&l, DEMO_PIN, Box::new(|| {}), wiring())
            .await
            .unwrap_or_else(|_| panic!("connected"));
        est.desk.close().await;
        assert!(matches!(
            c.connect(&l, "1", Box::new(|| {}), wiring()).await,
            Err(Outcome::Wrong {
                attempts_left: 4,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn host_hints_pick_scenarios() {
        let c = DemoConnector::new();
        assert!(matches!(
            c.connect(&link("down.test"), DEMO_PIN, Box::new(|| {}), wiring())
                .await,
            Err(Outcome::Unreachable(_))
        ));
        assert!(matches!(
            c.connect(&link("changed.test"), DEMO_PIN, Box::new(|| {}), wiring())
                .await,
            Err(Outcome::IdentityChanged)
        ));
        assert!(matches!(
            c.connect(
                &link("unavailable.test"),
                DEMO_PIN,
                Box::new(|| {}),
                wiring()
            )
            .await,
            Err(Outcome::NotAvailable { .. })
        ));
    }

    #[tokio::test]
    async fn revoking_follows_the_server_rules() {
        let c = DemoConnector::new();
        let est = c
            .connect(&link("demo.test"), DEMO_PIN, Box::new(|| {}), wiring())
            .await
            .ok()
            .unwrap();
        assert_eq!(est.desk.revoke([0xb2; 16]).await.unwrap(), RevokeStatus::Ok);
        assert_eq!(
            est.desk.revoke([0xb2; 16]).await.unwrap(),
            RevokeStatus::AlreadyRevoked
        );
        assert_eq!(
            est.desk.revoke([9; 16]).await.unwrap(),
            RevokeStatus::NotFound
        );
        assert_eq!(est.desk.revoke([0xc3; 16]).await.unwrap(), RevokeStatus::Ok);
        // this device is now the only active one
        assert_eq!(
            est.desk.revoke([0xa1; 16]).await.unwrap(),
            RevokeStatus::LastActiveDevice
        );
        est.desk.close().await;
    }
}
