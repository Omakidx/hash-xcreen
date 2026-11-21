//! Input from one client to the session (protocol 5.3, 7.1; ipc.md 17, 18).
//!
//! * **Epoch gate.** Only the current client's input reaches the session: every event passes
//!   [`InputPath::forward`], which checks under one lock that the path is still open and that
//!   this client's epoch is the desktop's current one. Takeover step (1) closes the path and
//!   sends `release_all` under the same lock, so nothing of the old client can follow the
//!   release.
//! * **Validation and clamping.** Scancodes above `0xE7`, an unknown button and an event with
//!   no variant are dropped; coordinates are clamped to the display of the stream in force;
//!   scrolling is bounded; relative motion is limited to +-32 768.
//! * **Rate.** At most 2 000 input events a second with a burst of 500 reach the session
//!   (ipc.md 13 and 17: they must fit the session's `ctl` budget with the motion and the rest).
//!   A burst above that is *paced* (the task waits, and flow control slows the client); a client
//!   that is more than one second behind its allowance, that is, one that sends faster than
//!   2 000 a second for good, is closed with `PROTOCOL_ERROR`. Motion is coalesced by the
//!   transport and again by the link client (at most one message per millisecond), and the
//!   motion task never spins faster than that.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hx_proto::channel::CloseCode;
use hx_proto::datagram::MouseMove;
use hx_proto::pb::{InputEvent, input_event::Event};
use hx_transport::Connection;
use tokio::sync::watch;

use super::util::{TokenBucket, lock};
use crate::link::LinkClient;

/// Input events a client may send per second.
pub(super) const INPUT_RATE: u32 = 2_000;
/// The burst the input allowance holds (a quarter second: it bounds what a sliding second of
/// `ctl` can carry, see ipc.md 13).
pub(super) const INPUT_BURST: u32 = 500;
/// A client this far behind its allowance is sending too fast for good.
const MAX_LAG: Duration = Duration::from_secs(1);
/// The largest key usage the protocol allows (protocol 5.3).
const MAX_SCANCODE: u32 = 0xE7;
/// Scroll per event in 1/120 notch: 100 notches.
const MAX_SCROLL: i32 = 12_000;
/// Relative motion per message.
const MAX_RELATIVE: i32 = 32_768;

/// The way from one client's input to the session.
pub(super) struct InputPath {
    link: LinkClient,
    conn: Connection,
    epoch: u32,
    current: Arc<AtomicU32>,
    open: Mutex<bool>,
    display: AtomicU64,
    seq: AtomicU32,
    /// `release` was called: `open_now` must not reopen the path.
    released: std::sync::atomic::AtomicBool,
    /// Events refused because the path was closed or the epoch was not current.
    pub(super) refused: AtomicU64,
}

impl InputPath {
    pub(super) fn new(
        link: LinkClient,
        conn: Connection,
        epoch: u32,
        current: Arc<AtomicU32>,
        display: (u32, u32),
    ) -> Self {
        let p = Self {
            link,
            conn,
            epoch,
            current,
            // Closed until the session's `start` for this client is queued (`open_now`): the
            // client's first input can never come before it.
            open: Mutex::new(false),
            display: AtomicU64::new(0),
            seq: AtomicU32::new(0),
            released: std::sync::atomic::AtomicBool::new(false),
            refused: AtomicU64::new(0),
        };
        p.set_display(display.0, display.1);
        p
    }

    /// The `start` of this client is queued: its input is accepted from now on (unless it was
    /// released meanwhile).
    pub(super) fn open_now(&self) {
        let mut open = lock(&self.open);
        if !self.released.load(Relaxed) {
            *open = true;
        }
    }

    /// The display size of the stream in force (coordinates are clamped to it).
    pub(super) fn set_display(&self, w: u32, h: u32) {
        self.display
            .store((u64::from(w.max(1)) << 32) | u64::from(h.max(1)), Relaxed);
    }

    fn size(&self) -> (i32, i32) {
        let d = self.display.load(Relaxed);
        let clamp = |v: u64| i32::try_from(v).unwrap_or(i32::MAX);
        (clamp(d >> 32), clamp(d & 0xffff_ffff))
    }

    /// Takeover step (1) and the end of a client: stop accepting input and release every key and
    /// button in the session. Idempotent.
    pub(super) fn release(&self) {
        let mut open = lock(&self.open);
        self.released.store(true, Relaxed);
        if std::mem::replace(&mut *open, false) {
            let _ = self.link.input(InputEvent {
                event: Some(Event::ReleaseAll(Default::default())),
            });
        }
    }

    /// Forwards one validated event. `true` if it went to the session.
    pub(super) fn forward(&self, ev: InputEvent) -> bool {
        let open = lock(&self.open);
        // Events the transport queued before the connection closed (a revoked device) are still
        // readable after the close: they must not reach the session.
        if !*open || self.current.load(Relaxed) != self.epoch || self.conn.close_info().is_some() {
            self.refused.fetch_add(1, Relaxed);
            return false;
        }
        let Some(ev) = self.clean(ev) else {
            return false;
        };
        self.link.input(ev).is_ok()
    }

    fn clean(&self, ev: InputEvent) -> Option<InputEvent> {
        let (w, h) = self.size();
        let event = match ev.event? {
            Event::Key(k) if k.scancode <= MAX_SCANCODE => Event::Key(k),
            Event::Button(mut b) if (1..=5).contains(&b.button) => {
                b.x = b.x.clamp(0, w - 1);
                b.y = b.y.clamp(0, h - 1);
                Event::Button(b)
            }
            Event::Scroll(mut s) => {
                s.dx = s.dx.clamp(-MAX_SCROLL, MAX_SCROLL);
                s.dy = s.dy.clamp(-MAX_SCROLL, MAX_SCROLL);
                Event::Scroll(s)
            }
            Event::ReleaseAll(r) => Event::ReleaseAll(r),
            _ => return None,
        };
        Some(InputEvent { event: Some(event) })
    }

    /// Forwards pointer motion (coalesced by the transport; coalesced again by the link).
    pub(super) fn mouse(&self, relative: bool, x: i32, y: i32) -> bool {
        let open = lock(&self.open);
        if !*open || self.current.load(Relaxed) != self.epoch || self.conn.close_info().is_some() {
            self.refused.fetch_add(1, Relaxed);
            return false;
        }
        let (w, h) = self.size();
        let (x, y) = if relative {
            (
                x.clamp(-MAX_RELATIVE, MAX_RELATIVE),
                y.clamp(-MAX_RELATIVE, MAX_RELATIVE),
            )
        } else {
            (x.clamp(0, w - 1), y.clamp(0, h - 1))
        };
        self.link
            .mouse(MouseMove {
                relative,
                seq: self.seq.fetch_add(1, Relaxed),
                x,
                y,
            })
            .is_ok()
    }
}

/// Reads the client's input stream. Ends when the connection or the relay does.
pub(super) async fn input_task(
    conn: Connection,
    path: Arc<InputPath>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut bucket = TokenBucket::new(INPUT_RATE, INPUT_BURST);
    loop {
        let ev = tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            r = conn.recv_input() => match r {
                Ok(ev) => ev,
                Err(_) => return,
            },
        };
        let wait = bucket.reserve(Instant::now());
        if wait > MAX_LAG {
            tracing::warn!("a client sent input faster than 2000 events per second; closing it");
            conn.close(CloseCode::ProtocolError, "input rate").await;
            return;
        }
        if !wait.is_zero() {
            tokio::select! {
                biased;
                _ = shutdown.changed() => return,
                () = tokio::time::sleep(wait) => {}
            }
        }
        path.forward(ev);
    }
}

/// Reads the client's pointer motion.
pub(super) async fn mouse_task(
    conn: Connection,
    path: Arc<InputPath>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let u = tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            r = conn.recv_mouse_move() => match r {
                Ok(u) => u,
                Err(_) => return,
            },
        };
        if let Some((x, y)) = u.absolute {
            path.mouse(false, x, y);
        }
        if let Some((x, y)) = u.relative {
            path.mouse(true, x, y);
        }
        // New motion coalesces while this waits.
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}
