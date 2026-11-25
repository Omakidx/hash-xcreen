//! The desktop view: video presentation, input, toolbar, stats, transfers, links, reconnect and
//! takeover.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::atomic::{AtomicU32, Ordering::Relaxed};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hx_proto::VideoCodec;
use hx_proto::pb::{self, MouseButton, ViewConfig};
use hx_transport::VideoFrame;
use slint::winit_030::winit::event::{ElementState, WindowEvent};
use slint::winit_030::winit::keyboard::{KeyCode, PhysicalKey};
use slint::winit_030::{EventResult, WinitWindowAccessor};
use slint::{ComponentHandle, Image, Rgba8Pixel, SharedPixelBuffer};
use zeroize::Zeroizing;

use super::{App, model, post, spawn_ui, ss};
use crate::clipboard::{self, Incoming};
use crate::files::{
    Activity, Direction, SendCheck, TransferState, check_send, human_size, refusal_text,
};
use crate::input::{ChordDetector, Combo, Fit, Held, ViewTransform, hid_usage, scroll_units};
use crate::links::{self, Link as WebLink};
use crate::session::lifecycle::{Next, Reconnect, reconnects};
use crate::session::{CloseReason, Desk, Established, Event, Link, Outcome, Wiring};
use crate::video::{CpuPresenter, DecodeThread, Picture, Presenter, Stats, spawn_decoder};
use crate::{ActivityData, DesktopVm, Screen};

type DeskSlot = Arc<Mutex<Option<Arc<dyn Desk>>>>;

/// Video plumbing created before a connection exists (the decoder needs to be there when the
/// first frame arrives).
pub struct Prepared {
    tx: Option<SyncSender<VideoFrame>>,
    thread: Option<DecodeThread>,
    presenter: Arc<dyn Presenter>,
    stats: Arc<Stats>,
    slot: DeskSlot,
}

impl Prepared {
    /// What the connector needs.
    pub fn wiring(&self) -> Wiring {
        Wiring {
            frames: self.tx.clone(),
            presenter: Some(self.presenter.clone()),
            stats: self.stats.clone(),
        }
    }
}

impl Drop for Prepared {
    fn drop(&mut self) {
        // Dropping the sender ends the decode thread.
        self.tx = None;
        if let Some(t) = self.thread.take() {
            std::thread::spawn(move || t.join());
        }
    }
}

/// Creates the decoder, the presenter and the stats for the next connection.
pub fn prepare(app: &Rc<App>) -> Prepared {
    let weak = Mutex::new(app.ui.as_weak());
    let remote = Arc::new((AtomicU32::new(0), AtomicU32::new(0)));
    let sink: crate::video::FrameSink = Arc::new(move |pic: Picture| {
        if let Ok(w) = weak.lock()
            && let Some(ui) = w.upgrade()
        {
            let vm = ui.global::<DesktopVm>();
            vm.set_frame(Image::from_rgba8(pic.pixels));
            vm.set_has_frame(true);
            let _ = &remote;
        }
    });
    let presenter: Arc<dyn Presenter> = Arc::new(CpuPresenter::new(sink));
    let stats = Arc::new(Stats::default());
    let slot: DeskSlot = Arc::default();
    let s2 = slot.clone();
    let ask: Arc<dyn Fn(u32) + Send + Sync> = Arc::new(move |last| {
        if let Ok(g) = s2.lock()
            && let Some(d) = g.as_ref()
        {
            d.request_keyframe(last);
        }
    });
    let (tx, thread) = match spawn_decoder(presenter.clone(), stats.clone(), ask) {
        Ok((tx, t)) => (Some(tx), Some(t)),
        Err(_) => (None, None),
    };
    Prepared {
        tx,
        thread,
        presenter,
        stats,
        slot,
    }
}

/// Seconds of an outage, with the schedule of attempts.
struct Outage {
    started: Instant,
    schedule: Reconnect,
    timer: slint::Timer,
    left: u64,
}

struct Active {
    server_id: String,
    link: Link,
    desk: Arc<dyn Desk>,
    _prepared: Prepared,
    pin: Zeroizing<String>,
    epoch: u64,
    outage: Option<Outage>,
    events: tokio::sync::mpsc::UnboundedSender<Event>,
}

/// Desktop state.
#[derive(Default)]
pub struct Ctx {
    active: Option<Active>,
    held: Held,
    chord: ChordDetector,
    view: (f32, f32),
    remote: (u32, u32),
    shapes: HashMap<u64, (Image, (i32, i32))>,
    /// The shape shown as the system pointer, and whether the server shows its pointer.
    cursor_shown: Option<(u64, bool)>,
    activities: Vec<(u64, Activity)>,
    clip: clipboard::Sync,
    link: Option<WebLink>,
    /// When the open link dialog appeared, and whether the pointer has moved since it armed.
    link_shown: Option<Instant>,
    link_armed: bool,
    /// When a link dialog was last shown, and how many were cancelled in this session.
    link_last: Option<Instant>,
    link_cancels: u32,
    /// Whether the desktop view (so the app window) has the keyboard focus.
    view_focused: bool,
    peer: Option<([u8; 16], String)>,
    resize_gen: u64,
    note_gen: u64,
    epoch: u64,
}

/// The `ViewConfig` for the current choices. Quality has no field of its own in the protocol:
/// Sharp keeps the frame rate low (full detail), Smooth caps the bitrate (full motion).
pub fn build_view(
    quality: i32,
    bandwidth_kbps: u32,
    fit: i32,
    size_px: (u32, u32),
    stats: bool,
    clipboard: bool,
) -> ViewConfig {
    let (fps, cap) = match quality {
        1 => (30, bandwidth_kbps),
        2 => (
            60,
            if bandwidth_kbps == 0 {
                12_000
            } else {
                bandwidth_kbps.min(12_000)
            },
        ),
        _ => (60, bandwidth_kbps),
    };
    let (w, h) = if fit == 2 {
        (size_px.0.clamp(64, 16384), size_px.1.clamp(64, 16384))
    } else {
        (0, 0)
    };
    ViewConfig {
        codec: VideoCodec::H264 as i32,
        max_fps: fps,
        bandwidth_cap_kbps: cap,
        width: w,
        height: h,
        scale_percent: 0,
        audio_enabled: false,
        clipboard_enabled: clipboard,
        stats_enabled: stats,
    }
}

fn send_view(app: &Rc<App>) {
    let c = app.desk.borrow();
    let Some(a) = &c.active else { return };
    let ui = app.ui();
    let vm = ui.global::<DesktopVm>();
    let scale = ui.window().scale_factor();
    let size = ((c.view.0 * scale) as u32, (c.view.1 * scale) as u32);
    let p = app.prefs.borrow();
    let v = build_view(
        vm.get_quality(),
        p.bandwidth_kbps(),
        vm.get_fit(),
        size,
        vm.get_stats_on(),
        p.clip_send || p.clip_receive,
    );
    a.desk.view(v);
}

/// A connection was accepted: show the desktop.
pub fn enter(
    app: &Rc<App>,
    id: &str,
    link: Link,
    est: Established,
    prepared: Prepared,
    pin: Zeroizing<String>,
) {
    let (ev_tx, mut ev_rx) = tokio::sync::mpsc::unbounded_channel::<Event>();
    let epoch = {
        let mut c = app.desk.borrow_mut();
        c.epoch += 1;
        c.held.clear();
        c.shapes.clear();
        c.cursor_shown = None;
        c.activities.clear();
        c.link = None;
        c.link_armed = false;
        c.remote = (0, 0);
        let g = c.epoch;
        if let Ok(mut s) = prepared.slot.lock() {
            *s = Some(est.desk.clone());
        }
        c.active = Some(Active {
            server_id: id.to_owned(),
            link,
            desk: est.desk.clone(),
            _prepared: prepared,
            pin,
            epoch: g,
            outage: None,
            events: ev_tx.clone(),
        });
        g
    };
    let server_name = app.server(id).map(|s| s.name).unwrap_or_default();
    let ui = app.ui();
    let vm = ui.global::<DesktopVm>();
    vm.set_server_name(ss(&server_name));
    vm.set_has_frame(false);
    vm.set_overlay(0);
    vm.set_menu(0);
    vm.set_toolbar(false);
    vm.set_link_open(false);
    vm.set_link_armed(false);
    vm.set_activities(model(vec![]));
    vm.set_transfer_note(ss(""));
    vm.set_cursor_visible(false);
    vm.set_connecting_text(ss("Starting the desktop…"));
    vm.set_st_path(ss(crate::video::PresentKind::CpuUpload.label()));
    app.go(Screen::Desktop);
    send_view(app);
    // Events from the connection, and from file sends, both end up in `on_event`.
    let mut src = est.events;
    let tx2 = ev_tx.clone();
    app.rt.spawn(async move {
        while let Some(e) = src.recv().await {
            if tx2.send(e).is_err() {
                break;
            }
        }
    });
    app.rt.spawn(async move {
        while let Some(e) = ev_rx.recv().await {
            post(move |a| on_event(a, epoch, e));
        }
    });
    // The first frame must come: otherwise the desktop is not available.
    let a = app.clone();
    slint::Timer::single_shot(Duration::from_secs(20), move || {
        let waiting = a.ui().global::<DesktopVm>().get_has_frame();
        if !waiting
            && a.desk
                .borrow()
                .active
                .as_ref()
                .is_some_and(|x| x.epoch == epoch)
            && a.ui().global::<DesktopVm>().get_overlay() == 0
        {
            if let Some(id) = a.desk.borrow().active.as_ref().map(|x| x.server_id.clone()) {
                a.unavailable.borrow_mut().insert(id);
            }
            a.ui().global::<DesktopVm>().set_overlay(4);
        }
    });
}

fn transform(c: &Ctx, fit: i32) -> ViewTransform {
    ViewTransform {
        remote: if c.remote.0 == 0 {
            (1920, 1080)
        } else {
            c.remote
        },
        view: c.view,
        fit: match fit {
            1 => Fit::Actual,
            2 => Fit::Resize,
            _ => Fit::Fit,
        },
    }
}

fn set_note(app: &Rc<App>, text: &str) {
    let ui = app.ui();
    ui.global::<DesktopVm>().set_transfer_note(ss(text));
    let epoch = {
        let mut c = app.desk.borrow_mut();
        c.note_gen += 1;
        c.note_gen
    };
    let a = app.clone();
    slint::Timer::single_shot(Duration::from_secs(6), move || {
        if a.desk.borrow().note_gen == epoch {
            a.ui().global::<DesktopVm>().set_transfer_note(ss(""));
        }
    });
}

fn push_activities(app: &Rc<App>) {
    let c = app.desk.borrow();
    let rows: Vec<ActivityData> = c
        .activities
        .iter()
        .rev()
        .map(|(_, a)| ActivityData {
            name: ss(&a.name),
            direction: ss(if a.dir == Direction::Up { "up" } else { "down" }),
            percent: a.percent() as i32,
            state: ss(match &a.state {
                TransferState::Running => {
                    format!("{} of {}", human_size(a.done), human_size(a.total))
                }
                TransferState::Done => "done".to_owned(),
                TransferState::Failed(_) => "not sent".to_owned(),
            }),
            failed: matches!(a.state, TransferState::Failed(_)),
        })
        .collect();
    app.ui().global::<DesktopVm>().set_activities(model(rows));
}

/// Time before "Open link" can work, and the least gap between two dialogs.
const LINK_ARM_DELAY: Duration = Duration::from_secs(1);
const LINK_MIN_GAP: Duration = Duration::from_secs(5);
/// After this many cancelled dialogs in a session the desktop is not offered any more.
const LINK_MAX_CANCELS: u32 = 3;

/// A link request from the desktop: ignored while a dialog is open (it could swap the address
/// under the user's click), rate limited, and not offered at all after repeated Cancels.
fn on_link_request(app: &Rc<App>, body: &[u8]) {
    let vm = app.ui().global::<DesktopVm>();
    {
        let c = app.desk.borrow();
        if c.link.is_some()
            || vm.get_link_open()
            || c.link_cancels >= LINK_MAX_CANCELS
            || c.link_last.is_some_and(|t| t.elapsed() < LINK_MIN_GAP)
        {
            return;
        }
    }
    match links::from_uri_list(body) {
        Ok(l) => {
            vm.set_link_prefix(ss(&l.prefix));
            vm.set_link_host(ss(&l.host));
            vm.set_link_rest(ss(&l.rest));
            vm.set_link_domain(ss(&l.domain));
            vm.set_link_armed(false);
            vm.set_link_open(true);
            let mut c = app.desk.borrow_mut();
            c.link = Some(l);
            c.link_shown = Some(Instant::now());
            c.link_last = c.link_shown;
            c.link_armed = false;
        }
        Err(_) => set_note(
            app,
            "The desktop asked to open a link that was not offered: only http and https links can be opened.",
        ),
    }
}

fn on_event(app: &Rc<App>, epoch: u64, e: Event) {
    if app
        .desk
        .borrow()
        .active
        .as_ref()
        .is_none_or(|a| a.epoch != epoch)
    {
        return;
    }
    let ui = app.ui();
    let vm = ui.global::<DesktopVm>();
    match e {
        Event::Stream(s) => {
            app.desk.borrow_mut().remote = (s.width, s.height);
            vm.set_remote_w(s.width as i32);
            vm.set_remote_h(s.height as i32);
            vm.set_st_screen(ss(format!("{} x {}", s.width, s.height)));
            vm.set_st_codec(ss("H.264"));
        }
        Event::Stats(s) => {
            vm.set_st_fps(ss(format!("{} fps", s.frames)));
            let rtt = {
                let c = app.desk.borrow();
                c.active
                    .as_ref()
                    .map_or(0, |a| a.desk.stats().rtt_us.load(Relaxed))
            };
            let us = if rtt > 0 { rtt } else { s.rtt_us };
            vm.set_st_latency(ss(format!("{} ms", us / 1000)));
            vm.set_st_bitrate(ss(format!(
                "{:.1} Mbps",
                f64::from(s.bitrate_kbps) / 1000.0
            )));
            // The statistics message carries numbers only; the encoder is the server's choice
            // and today always software x264.
            vm.set_st_encoding(ss("Software (x264)"));
        }
        Event::Cursor(c) => on_cursor(app, c),
        Event::ClipboardText(t) => {
            // The local clipboard changes only while this window has the focus (a remote
            // program cannot overwrite it behind the user's back); anything that arrives
            // unfocused is dropped, and text over 1 MiB is never applied.
            let focused = app.desk.borrow().view_focused;
            if focused
                && t.len() as u64 <= crate::session::net::MAX_CLIPBOARD_TEXT
                && clipboard::classify_incoming(&app.clip_policy(), "text/plain") == Incoming::Text
            {
                app.desk.borrow_mut().clip.received(&t);
                app.set_clipboard(&t);
            }
        }
        Event::LinkRequest(body) => on_link_request(app, &body),
        Event::Transfer {
            id,
            activity,
            saved,
        } => {
            {
                let mut c = app.desk.borrow_mut();
                match c.activities.iter_mut().find(|(i, _)| *i == id) {
                    Some(slot) => slot.1 = activity.clone(),
                    None => {
                        c.activities.push((id, activity.clone()));
                        if c.activities.len() > 8 {
                            c.activities.remove(0);
                        }
                    }
                }
            }
            push_activities(app);
            match &activity.state {
                TransferState::Failed(t) => set_note(app, t),
                TransferState::Done if saved.is_some() => {
                    set_note(
                        app,
                        &format!("{} was saved to your Downloads folder.", activity.name),
                    );
                }
                _ => {}
            }
        }
        Event::DeviceEvent(_) => {}
        Event::Closed(reason) => on_closed(app, epoch, reason),
    }
}

fn on_cursor(app: &Rc<App>, e: pb::CursorEvent) {
    use pb::cursor_event::Event as C;
    let ui = app.ui();
    let vm = ui.global::<DesktopVm>();
    match e.event {
        Some(C::Shape(s)) => {
            let (w, h) = (s.width, s.height);
            if w == 0 || h == 0 || w > 256 || h > 256 || s.rgba.len() != (w * h * 4) as usize {
                return;
            }
            let buf = SharedPixelBuffer::<Rgba8Pixel>::clone_from_slice(&s.rgba, w, h);
            let mut c = app.desk.borrow_mut();
            if c.shapes.len() > 64 {
                c.shapes.clear();
            }
            c.shapes.insert(
                s.id,
                (
                    Image::from_rgba8(buf),
                    (s.hotspot_x as i32, s.hotspot_y as i32),
                ),
            );
        }
        Some(C::Position(p)) => {
            // The pointer is the local one (architecture 6.3): a report only brings the shape
            // and whether the server shows its pointer. Nothing to do while neither changes.
            let mut c = app.desk.borrow_mut();
            let shown = (p.shape_id, p.visible && c.active.is_some());
            if c.cursor_shown == Some(shown) {
                return;
            }
            let Some((img, hot)) = c.shapes.get(&p.shape_id).cloned() else {
                return;
            };
            c.cursor_shown = Some(shown);
            drop(c);
            vm.set_cursor(img);
            vm.set_cursor_hot_x(hot.0);
            vm.set_cursor_hot_y(hot.1);
            vm.set_cursor_visible(shown.1);
            // Slint picks the system pointer while it handles a pointer event: replay the last
            // position so a shape that arrives while the mouse is still shows at once.
            if vm.get_pointer_inside() {
                let at = slint::LogicalPosition::new(
                    vm.get_pointer_window_x(),
                    vm.get_pointer_window_y(),
                );
                ui.window()
                    .dispatch_event(slint::platform::WindowEvent::PointerMoved { position: at });
            }
        }
        None => {}
    }
}

// ----------------------------------------------------------------------------------- closing

fn on_closed(app: &Rc<App>, epoch: u64, reason: CloseReason) {
    let ui = app.ui();
    let vm = ui.global::<DesktopVm>();
    let id = app
        .desk
        .borrow()
        .active
        .as_ref()
        .map(|a| a.server_id.clone());
    app.desk.borrow_mut().held.clear();
    match reason {
        CloseReason::Local => {}
        CloseReason::Network | CloseReason::Shutdown => start_outage(app, epoch),
        CloseReason::TakenOver {
            name,
            id_short,
            id: pid,
        } => {
            let who = match (name.is_empty(), id_short.is_empty()) {
                (false, false) => format!("{name} ({id_short})"),
                (false, true) => name.clone(),
                (true, false) => format!("Another device ({id_short})"),
                (true, true) => "Another device".to_owned(),
            };
            let server = id
                .as_deref()
                .and_then(|i| app.server(i))
                .map(|s| s.name)
                .unwrap_or_default();
            vm.set_takeover_title(ss("This desktop was opened on another device"));
            vm.set_takeover_text(ss(format!(
                "{who} connected to {server} and took over, so this session ended. Nothing on the desktop was closed."
            )));
            vm.set_takeover_note(ss(""));
            vm.set_can_revoke(pid.is_some());
            app.desk.borrow_mut().peer = pid.map(|p| (p, who));
            vm.set_overlay(3);
            vm.set_toolbar(false);
        }
        CloseReason::Revoked => {
            if let Some(i) = &id {
                let _ = app.store.borrow_mut().set_lifecycle(
                    i,
                    crate::servers::Lifecycle::Revoked,
                    super::now_unix(),
                );
                leave_to_connect(app, i);
            }
        }
        CloseReason::DesktopUnavailable => {
            if let Some(i) = &id {
                app.unavailable.borrow_mut().insert(i.clone());
            }
            vm.set_overlay(4);
        }
    }
}

fn leave_to_connect(app: &Rc<App>, id: &str) {
    teardown(app);
    super::connect_ctl::open(app, id);
}

/// Closes the connection and forgets the session (and its PIN).
pub fn teardown(app: &Rc<App>) {
    let a = app.desk.borrow_mut().active.take();
    {
        let mut c = app.desk.borrow_mut();
        c.view_focused = false;
        c.link_cancels = 0;
        c.link_last = None;
    }
    if let Some(a) = a {
        let d = a.desk.clone();
        app.rt.spawn(async move { d.close().await });
        drop(a);
    }
    let ui = app.ui();
    let vm = ui.global::<DesktopVm>();
    vm.set_overlay(0);
    vm.set_has_frame(false);
    vm.set_fullscreen(false);
}

fn start_outage(app: &Rc<App>, epoch: u64) {
    let mut c = app.desk.borrow_mut();
    let Some(a) = c.active.as_mut() else { return };
    if a.epoch != epoch {
        return;
    }
    a.outage = Some(Outage {
        started: Instant::now(),
        schedule: Reconnect::new(),
        timer: slint::Timer::default(),
        left: 0,
    });
    drop(c);
    app.ui().global::<DesktopVm>().set_overlay(1);
    next_attempt(app, epoch);
}

fn next_attempt(app: &Rc<App>, epoch: u64) {
    let step = {
        let mut c = app.desk.borrow_mut();
        let Some(a) = c.active.as_mut() else { return };
        if a.epoch != epoch {
            return;
        }
        let Some(o) = a.outage.as_mut() else { return };
        o.schedule.next(o.started.elapsed())
    };
    let vm = app.ui().global::<DesktopVm>();
    match step {
        Next::GiveUp => {
            vm.set_overlay(2);
            if let Some(o) = app
                .desk
                .borrow_mut()
                .active
                .as_mut()
                .and_then(|a| a.outage.as_mut())
            {
                o.timer.stop();
            }
        }
        Next::Retry { attempt, wait } => {
            vm.set_attempt(attempt as i32);
            vm.set_next_secs(wait.as_secs() as i32);
            let mut c = app.desk.borrow_mut();
            let Some(o) = c.active.as_mut().and_then(|a| a.outage.as_mut()) else {
                return;
            };
            o.left = wait.as_secs();
            let a2 = app.clone();
            o.timer.start(
                slint::TimerMode::Repeated,
                Duration::from_secs(1),
                move || {
                    let fire = {
                        let mut c = a2.desk.borrow_mut();
                        let Some(o) = c.active.as_mut().and_then(|a| a.outage.as_mut()) else {
                            return;
                        };
                        o.left = o.left.saturating_sub(1);
                        a2.ui().global::<DesktopVm>().set_next_secs(o.left as i32);
                        o.left == 0
                    };
                    if fire {
                        if let Some(o) = a2
                            .desk
                            .borrow_mut()
                            .active
                            .as_mut()
                            .and_then(|a| a.outage.as_mut())
                        {
                            o.timer.stop();
                        }
                        try_reconnect(&a2, epoch);
                    }
                },
            );
        }
    }
}

fn try_reconnect(app: &Rc<App>, epoch: u64) {
    let (link, pin, id) = {
        let c = app.desk.borrow();
        let Some(a) = c.active.as_ref() else { return };
        (a.link.clone(), a.pin.clone(), a.server_id.clone())
    };
    let prepared = prepare(app);
    let wiring = prepared.wiring();
    let connector = app.be.connector.clone();
    let l2 = link.clone();
    let p2 = pin.clone();
    spawn_ui(
        app,
        async move { connector.connect(&l2, &p2, Box::new(|| {}), wiring).await },
        move |a, r| finish_reconnect(a, epoch, &id, link, pin, prepared, r),
    );
}

/// What a failed reconnect attempt leads to.
#[derive(Debug, PartialEq, Eq)]
enum AfterFailure {
    /// The device was removed: the revoked state.
    Revoked,
    /// The server's key changed: the identity screen.
    Identity,
    /// The server rejected the cached PIN (wrong, too soon, or unavailable): stop, forget the
    /// PIN and ask again. Sending it again could revoke the device after a PIN change elsewhere.
    AskPin,
    /// A network failure: keep trying on the schedule.
    Retry,
}

fn after_failure(o: &Outcome) -> AfterFailure {
    match o {
        Outcome::Revoked => AfterFailure::Revoked,
        Outcome::IdentityChanged => AfterFailure::Identity,
        Outcome::Wrong { .. } | Outcome::Backoff { .. } | Outcome::NotAvailable { .. } => {
            AfterFailure::AskPin
        }
        Outcome::Accepted | Outcome::Unreachable(_) | Outcome::Failed(_) => AfterFailure::Retry,
    }
}

fn finish_reconnect(
    a: &Rc<App>,
    epoch: u64,
    id: &str,
    link: Link,
    pin: Zeroizing<String>,
    prepared: Prepared,
    r: Result<Established, Outcome>,
) {
    if a.desk
        .borrow()
        .active
        .as_ref()
        .is_none_or(|x| x.epoch != epoch)
    {
        return;
    }
    match r {
        Ok(est) => {
            // The same screen, a new connection: the old plumbing goes with `active`.
            let old = a.desk.borrow_mut().active.take();
            if let Some(o) = old {
                let d = o.desk.clone();
                a.rt.spawn(async move { d.close().await });
            }
            enter(a, id, link, est, prepared, pin);
        }
        Err(o) => match after_failure(&o) {
            AfterFailure::Revoked => {
                let _ = a.store.borrow_mut().set_lifecycle(
                    id,
                    crate::servers::Lifecycle::Revoked,
                    super::now_unix(),
                );
                leave_to_connect(a, id);
            }
            AfterFailure::Identity => leave_to_connect(a, id),
            AfterFailure::AskPin => {
                // The cached PIN is dropped with the session; the PIN screen says why.
                drop((pin, prepared));
                teardown(a);
                super::connect_ctl::open(a, id);
                a.conn.borrow_mut().machine.outcome(o);
                super::connect_ctl::show(a);
            }
            AfterFailure::Retry => {
                drop(prepared);
                next_attempt(a, epoch);
            }
        },
    }
}

fn retry_now(app: &Rc<App>) {
    let epoch = {
        let mut c = app.desk.borrow_mut();
        let Some(a) = c.active.as_mut() else { return };
        a.outage = Some(Outage {
            started: Instant::now(),
            schedule: Reconnect::new(),
            timer: slint::Timer::default(),
            left: 0,
        });
        a.epoch
    };
    let vm = app.ui().global::<DesktopVm>();
    vm.set_overlay(1);
    vm.set_attempt(0);
    try_reconnect(app, epoch);
}

// ----------------------------------------------------------------------------------- takeover

fn revoke_peer(app: &Rc<App>) {
    let (link, pin, peer) = {
        let c = app.desk.borrow();
        let Some(a) = c.active.as_ref() else { return };
        (a.link.clone(), a.pin.clone(), c.peer.clone())
    };
    let Some((pid, who)) = peer else { return };
    let vm = app.ui().global::<DesktopVm>();
    vm.set_takeover_note(ss("Signing in to revoke that device…"));
    let connector = app.be.connector.clone();
    let stats = Arc::new(Stats::default());
    spawn_ui(
        app,
        async move {
            // A new authenticated session that sends no ViewConfig: it claims nothing and
            // displaces nobody (protocol 5.7, 5.9).
            let w = Wiring {
                frames: None,
                presenter: None,
                stats,
            };
            let est = connector
                .connect(&link, &pin, Box::new(|| {}), w)
                .await
                .map_err(|_| ())?;
            let r = est.desk.revoke(pid).await;
            est.desk.close().await;
            r.map_err(|_| ())
        },
        move |a, r| {
            let vm = a.ui().global::<DesktopVm>();
            let msg = match r {
                Ok(s) => crate::details::revoke_message(s)
                    .map_or_else(|| format!("{who} was revoked. Change your PIN under Server details, Security."), str::to_owned),
                Err(()) => "Could not reach the server to revoke that device. Try again from Server details, Security.".to_owned(),
            };
            vm.set_takeover_note(ss(msg));
            vm.set_can_revoke(false);
        },
    );
}

// ----------------------------------------------------------------------------------- input

fn forwarding(app: &Rc<App>) -> bool {
    let ui = app.ui();
    let vm = ui.global::<DesktopVm>();
    app.desk.borrow().active.is_some()
        && ui.global::<crate::Nav>().get_screen() == Screen::Desktop
        && vm.get_overlay() == 0
        && !vm.get_toolbar()
        && !vm.get_link_open()
}

fn key_event(app: &Rc<App>, code: KeyCode, pressed: bool, repeat: bool) -> bool {
    if !forwarding(app) {
        return false;
    }
    let vm = app.ui().global::<DesktopVm>();
    if code == KeyCode::F11 && pressed {
        toggle_fullscreen(app);
        return true;
    }
    let Some(u) = hid_usage(code) else {
        return false;
    };
    if !vm.get_capture_keys() && matches!(u, 0xE3 | 0xE7) {
        return false;
    }
    let mut c = app.desk.borrow_mut();
    if pressed && repeat {
        return true;
    }
    if !c.held.key(u, pressed) && pressed {
        return true;
    }
    if let Some(a) = c.active.as_ref() {
        a.desk.key(u, pressed);
    }
    true
}

fn release_all(app: &Rc<App>) {
    let mut c = app.desk.borrow_mut();
    if c.held.any() || c.active.is_some() {
        if let Some(a) = c.active.as_ref() {
            a.desk.release_all();
        }
        c.held.clear();
    }
}

fn toggle_fullscreen(app: &Rc<App>) {
    let vm = app.ui().global::<DesktopVm>();
    vm.set_fullscreen(!vm.get_fullscreen());
}

fn handle_winit(app: &Rc<App>, ev: &WindowEvent) -> EventResult {
    match ev {
        WindowEvent::ModifiersChanged(m) => {
            let s = m.state();
            let fire =
                app.desk
                    .borrow_mut()
                    .chord
                    .update(s.control_key(), s.alt_key(), s.shift_key());
            if fire
                && app.desk.borrow().active.is_some()
                && app.ui().global::<crate::Nav>().get_screen() == Screen::Desktop
            {
                release_all(app);
                let vm = app.ui().global::<DesktopVm>();
                vm.set_toolbar(!vm.get_toolbar());
                vm.set_menu(0);
            }
            EventResult::Propagate
        }
        WindowEvent::KeyboardInput { event, .. } => {
            if let PhysicalKey::Code(code) = event.physical_key {
                let pressed = event.state == ElementState::Pressed;
                if key_event(app, code, pressed, event.repeat) {
                    return EventResult::PreventDefault;
                }
            }
            EventResult::Propagate
        }
        WindowEvent::Focused(f) => {
            if !*f {
                release_all(app);
            } else {
                clipboard_to_desktop(app);
            }
            EventResult::Propagate
        }
        WindowEvent::HoveredFile(_) => {
            if app.desk.borrow().active.is_some() {
                app.ui().global::<DesktopVm>().set_drop_hover(true);
            }
            EventResult::Propagate
        }
        WindowEvent::HoveredFileCancelled => {
            app.ui().global::<DesktopVm>().set_drop_hover(false);
            EventResult::Propagate
        }
        WindowEvent::DroppedFile(p) => {
            app.ui().global::<DesktopVm>().set_drop_hover(false);
            send_file(app, p.clone());
            EventResult::Propagate
        }
        _ => EventResult::Propagate,
    }
}

fn clipboard_to_desktop(app: &Rc<App>) {
    if !forwarding(app) && app.desk.borrow().active.is_none() {
        return;
    }
    let policy = app.clip_policy();
    if !policy.send {
        return;
    }
    let text = app.get_clipboard();
    let mut c = app.desk.borrow_mut();
    if c.clip.should_send(&policy, &text)
        && let Some(a) = c.active.as_ref()
    {
        a.desk.send_clipboard_text(&text);
    }
}

fn send_file(app: &Rc<App>, path: std::path::PathBuf) {
    let (desk, tx) = {
        let c = app.desk.borrow();
        let Some(a) = c.active.as_ref() else { return };
        (a.desk.clone(), a.events.clone())
    };
    let name = path
        .file_name()
        .map_or("file".to_owned(), |n| n.to_string_lossy().into_owned());
    let size = match std::fs::metadata(&path) {
        Ok(m) if m.is_file() => m.len(),
        _ => {
            set_note(app, &format!("{name} was not sent: it is not a file."));
            return;
        }
    };
    match check_send(size, desk.file_limit()) {
        SendCheck::Ok => desk.send_file(path, tx),
        SendCheck::TooLarge { limit } => set_note(app, &refusal_text(&name, limit)),
    }
}

// ----------------------------------------------------------------------------------- wiring

pub fn wire(app: &Rc<App>) {
    let ui = app.ui();
    ui.window().on_winit_window_event({
        let a = app.clone();
        move |_w, ev| handle_winit(&a, ev)
    });
    let vm = ui.global::<DesktopVm>();
    let a = app.clone();
    vm.on_view_resized(move |w, h| {
        let epoch = {
            let mut c = a.desk.borrow_mut();
            let changed = (c.view.0 - w).abs() > 0.5 || (c.view.1 - h).abs() > 0.5;
            c.view = (w, h);
            if !changed || c.active.is_none() {
                return;
            }
            c.resize_gen += 1;
            c.resize_gen
        };
        if a.ui().global::<DesktopVm>().get_fit() == 2 {
            // Wait for the window to settle, then ask the server for the new size.
            let a2 = a.clone();
            slint::Timer::single_shot(Duration::from_millis(350), move || {
                if a2.desk.borrow().resize_gen == epoch {
                    send_view(&a2);
                }
            });
        }
    });
    let a = app.clone();
    vm.on_pointer_moved(move |x, y| {
        let c = a.desk.borrow();
        let Some(act) = c.active.as_ref() else { return };
        let t = transform(&c, a.ui().global::<DesktopVm>().get_fit());
        if let Some((rx, ry)) = t.to_remote(x, y) {
            act.desk.motion(rx, ry);
        }
    });
    let a = app.clone();
    vm.on_pointer_button(move |b, pressed, x, y| {
        let c = a.desk.borrow();
        let Some(act) = c.active.as_ref() else { return };
        let t = transform(&c, a.ui().global::<DesktopVm>().get_fit());
        let Some((rx, ry)) = t.to_remote(x, y) else {
            return;
        };
        let btn = match b {
            0 => MouseButton::Left,
            1 => MouseButton::Right,
            2 => MouseButton::Middle,
            3 => MouseButton::Back,
            _ => MouseButton::Forward,
        };
        act.desk.button(btn, pressed, rx, ry);
    });
    let a = app.clone();
    vm.on_pointer_scroll(move |dx, dy| {
        if let Some(act) = a.desk.borrow().active.as_ref() {
            act.desk.scroll(scroll_units(dx), scroll_units(dy));
        }
    });
    let a = app.clone();
    vm.on_view_focus(move |f| {
        a.desk.borrow_mut().view_focused = f;
        if f {
            clipboard_to_desktop(&a);
        } else {
            release_all(&a);
        }
    });
    let a = app.clone();
    vm.on_fit_changed(move |i| {
        let vm = a.ui().global::<DesktopVm>();
        vm.set_fit(i);
        vm.set_menu(0);
        send_view(&a);
    });
    let a = app.clone();
    vm.on_quality_changed(move |i| {
        let vm = a.ui().global::<DesktopVm>();
        vm.set_quality(i);
        vm.set_menu(0);
        send_view(&a);
    });
    let a = app.clone();
    vm.on_stats_toggled(move |_| send_view(&a));
    let a = app.clone();
    vm.on_capture_toggled(move |_| release_all(&a));
    let a = app.clone();
    vm.on_combo(move |i| {
        let combo = match i {
            0 => Combo::CtrlAltDel,
            1 => Combo::AltTab,
            2 => Combo::AltF4,
            _ => Combo::Super,
        };
        if let Some(act) = a.desk.borrow().active.as_ref() {
            for (k, pressed) in combo.events() {
                act.desk.key(k, pressed);
            }
        }
        a.ui().global::<DesktopVm>().set_menu(0);
    });
    let a = app.clone();
    vm.on_fullscreen_toggled(move || toggle_fullscreen(&a));
    let a = app.clone();
    vm.on_send_file(move || {
        let vm = a.ui().global::<DesktopVm>();
        let p = vm.get_file_path().trim().to_owned();
        if p.is_empty() {
            return;
        }
        let path = if let Some(rest) = p.strip_prefix("~/") {
            std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(rest)
        } else {
            std::path::PathBuf::from(&p)
        };
        vm.set_file_path(ss(""));
        send_file(&a, path);
    });
    let a = app.clone();
    vm.on_link_pointer_moved(move || {
        let arm = {
            let mut c = a.desk.borrow_mut();
            let ready = c.link.is_some()
                && !c.link_armed
                && c.link_shown.is_some_and(|t| t.elapsed() >= LINK_ARM_DELAY);
            if ready {
                c.link_armed = true;
            }
            ready
        };
        if arm {
            a.ui().global::<DesktopVm>().set_link_armed(true);
        }
    });
    let a = app.clone();
    vm.on_open_link(move || {
        // A click before the dialog was armed (a pause and a pointer move) does nothing.
        if !a.desk.borrow().link_armed {
            return;
        }
        let l = a.desk.borrow_mut().link.take();
        a.desk.borrow_mut().link_armed = false;
        let vm = a.ui().global::<DesktopVm>();
        vm.set_link_armed(false);
        vm.set_link_open(false);
        if let Some(l) = l
            && links::open_in_browser(&l).is_err()
        {
            set_note(
                &a,
                "The link could not be opened: no default browser handler was found.",
            );
        }
    });
    let a = app.clone();
    vm.on_cancel_link(move || {
        {
            let mut c = a.desk.borrow_mut();
            if c.link.take().is_some() {
                c.link_cancels += 1;
            }
            c.link_armed = false;
        }
        let vm = a.ui().global::<DesktopVm>();
        vm.set_link_armed(false);
        vm.set_link_open(false);
    });
    let a = app.clone();
    vm.on_copy_link(move || {
        let t = a.desk.borrow().link.as_ref().map(|l| l.url.clone());
        if let Some(t) = t {
            a.set_clipboard(&t);
        }
    });
    let a = app.clone();
    vm.on_disconnect(move || {
        teardown(&a);
        a.show_home();
    });
    let a = app.clone();
    vm.on_overlay_back(move || {
        teardown(&a);
        a.show_home();
    });
    let a = app.clone();
    vm.on_overlay_retry(move || retry_now(&a));
    let a = app.clone();
    vm.on_overlay_details(move || {
        let id = a.desk.borrow().active.as_ref().map(|x| x.server_id.clone());
        teardown(&a);
        if let Some(id) = id {
            super::details_ctl::open(&a, &id);
        }
    });
    let a = app.clone();
    vm.on_revoke_peer(move || revoke_peer(&a));
    let a = app.clone();
    vm.on_take_back(move || {
        let (id, who) = {
            let c = a.desk.borrow();
            (
                c.active.as_ref().map(|x| x.server_id.clone()),
                c.peer.as_ref().map(|p| p.1.clone()),
            )
        };
        teardown(&a);
        if let Some(id) = id {
            super::connect_ctl::open_take_back(&a, &id, &who.unwrap_or_default());
        }
    });
    let a = app.clone();
    vm.on_toolbar_shortcut(move || {
        let vm = a.ui().global::<DesktopVm>();
        vm.set_toolbar(!vm.get_toolbar());
    });
    let _ = (RefCell::new(()), reconnects);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn view_config_follows_quality_and_resize() {
        let v = build_view(0, 0, 0, (1200, 700), false, true);
        assert_eq!(
            (v.max_fps, v.bandwidth_cap_kbps, v.width, v.height),
            (60, 0, 0, 0)
        );
        assert!(v.clipboard_enabled && !v.stats_enabled);
        let v = build_view(1, 0, 0, (0, 0), true, false);
        assert_eq!(v.max_fps, 30);
        assert!(v.stats_enabled && !v.clipboard_enabled);
        let v = build_view(2, 0, 0, (0, 0), false, true);
        assert_eq!(v.bandwidth_cap_kbps, 12_000);
        let v = build_view(2, 5_000, 0, (0, 0), false, true);
        assert_eq!(v.bandwidth_cap_kbps, 5_000);
        // resize: both dimensions set and clamped; otherwise both zero (keep)
        let v = build_view(0, 0, 2, (1200, 700), false, true);
        assert_eq!((v.width, v.height), (1200, 700));
        let v = build_view(0, 0, 2, (10, 99_999), false, true);
        assert_eq!((v.width, v.height), (64, 16384));
        assert_eq!(v.codec, VideoCodec::H264 as i32);
    }

    // ------------------------------------------------------------------ controller tests

    use crate::AppWindow;
    use crate::app::{Config, showcase};
    use crate::backend::demo;
    use crate::keys::MemoryKeyStore;

    struct Rig {
        ui: AppWindow,
        app: Rc<App>,
        rt: tokio::runtime::Runtime,
    }

    fn rig() -> Rig {
        i_slint_backend_testing::init_no_event_loop();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let ui = AppWindow::new().unwrap();
        let app = App::start(
            &ui,
            rt.handle().clone(),
            Config {
                demo: true,
                config_dir: None,
                backends: demo::backends(demo::Pace::instant()),
                key_store: Arc::new(MemoryKeyStore::default()),
                seed: showcase::demo_servers(),
            },
        );
        Rig { ui, app, rt }
    }

    /// An active demo connection, without going through `enter`.
    fn activate(r: &Rig) -> (String, u64) {
        // The demo servers carry placeholder keys, so the link gets a fresh one.
        let srv = r.app.server("ws").expect("demo server");
        let id = srv.id.clone();
        let link = Link {
            host: srv.host.clone(),
            port: srv.port,
            server_key: hx_crypto::IdentityKey::generate().unwrap().public(),
            device: r.app.key.clone(),
            device_name: "test".into(),
        };
        let prepared = prepare(&r.app);
        let wiring = prepared.wiring();
        let est =
            r.rt.block_on(r.app.be.connector.connect(
                &link,
                crate::backend::demo_desk::DEMO_PIN,
                Box::new(|| {}),
                wiring,
            ))
            .unwrap_or_else(|_| panic!("demo connects"));
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let mut c = r.app.desk.borrow_mut();
        c.epoch += 1;
        let epoch = c.epoch;
        c.active = Some(Active {
            server_id: id.clone(),
            link,
            desk: est.desk,
            _prepared: prepared,
            pin: Zeroizing::new(crate::backend::demo_desk::DEMO_PIN.to_owned()),
            epoch,
            outage: None,
            events: tx,
        });
        (id, epoch)
    }

    fn uri(u: &str) -> Event {
        Event::LinkRequest(u.as_bytes().to_vec())
    }

    #[test]
    fn a_second_link_request_cannot_swap_an_open_dialog() {
        let r = rig();
        let (_, epoch) = activate(&r);
        on_event(&r.app, epoch, uri("https://first.test/a"));
        let vm = r.ui.global::<DesktopVm>();
        assert!(vm.get_link_open());
        on_event(&r.app, epoch, uri("https://second.test/b"));
        assert_eq!(vm.get_link_host().as_str(), "first.test");
        assert_eq!(
            r.app.desk.borrow().link.as_ref().unwrap().host,
            "first.test"
        );
    }

    #[test]
    fn open_link_does_nothing_until_armed() {
        let r = rig();
        let (_, epoch) = activate(&r);
        on_event(&r.app, epoch, uri("https://first.test/a"));
        let vm = r.ui.global::<DesktopVm>();
        // A click at once: no-op, the dialog stays.
        vm.invoke_open_link();
        assert!(vm.get_link_open());
        assert!(r.app.desk.borrow().link.is_some());
        // A pointer move before the pause does not arm it either.
        vm.invoke_link_pointer_moved();
        assert!(!vm.get_link_armed());
        vm.invoke_open_link();
        assert!(vm.get_link_open());
        // Cancel is always available, and counts.
        vm.invoke_cancel_link();
        assert!(!vm.get_link_open());
        assert_eq!(r.app.desk.borrow().link_cancels, 1);
    }

    #[test]
    fn a_pause_and_a_pointer_move_arm_the_dialog() {
        let r = rig();
        let (_, epoch) = activate(&r);
        on_event(&r.app, epoch, uri("https://first.test/a"));
        r.app.desk.borrow_mut().link_shown = Instant::now().checked_sub(Duration::from_secs(2));
        let vm = r.ui.global::<DesktopVm>();
        vm.invoke_link_pointer_moved();
        assert!(vm.get_link_armed());
    }

    #[test]
    fn link_requests_are_rate_limited_and_stop_after_cancels() {
        let r = rig();
        let (_, epoch) = activate(&r);
        let vm = r.ui.global::<DesktopVm>();
        on_event(&r.app, epoch, uri("https://one.test/"));
        vm.invoke_cancel_link();
        // Within 5 s of the last dialog: ignored.
        on_event(&r.app, epoch, uri("https://two.test/"));
        assert!(!vm.get_link_open());
        for _ in 0..3 {
            r.app.desk.borrow_mut().link_last = Instant::now().checked_sub(Duration::from_secs(6));
            on_event(&r.app, epoch, uri("https://again.test/"));
            if vm.get_link_open() {
                vm.invoke_cancel_link();
            }
        }
        // Three Cancels: no more offers in this session.
        r.app.desk.borrow_mut().link_last = Instant::now().checked_sub(Duration::from_secs(60));
        on_event(&r.app, epoch, uri("https://late.test/"));
        assert!(!vm.get_link_open());
    }

    #[test]
    fn remote_clipboard_text_needs_the_window_focus() {
        let r = rig();
        let (_, epoch) = activate(&r);
        r.app.set_clipboard("mine");
        assert_eq!(r.app.get_clipboard(), "mine");
        let vm = r.ui.global::<DesktopVm>();
        vm.invoke_view_focus(false);
        on_event(&r.app, epoch, Event::ClipboardText("theirs".into()));
        assert_eq!(r.app.get_clipboard(), "mine");
        vm.invoke_view_focus(true);
        on_event(&r.app, epoch, Event::ClipboardText("theirs".into()));
        assert_eq!(r.app.get_clipboard(), "theirs");
        // Over 1 MiB is never applied.
        let big = "x".repeat((crate::session::net::MAX_CLIPBOARD_TEXT as usize) + 1);
        on_event(&r.app, epoch, Event::ClipboardText(big));
        assert_eq!(r.app.get_clipboard(), "theirs");
    }

    #[test]
    fn a_rejected_cached_pin_is_not_sent_again() {
        assert_eq!(
            after_failure(&Outcome::Wrong {
                attempts_left: 3,
                retry_after: Duration::ZERO
            }),
            AfterFailure::AskPin
        );
        assert_eq!(
            after_failure(&Outcome::Backoff {
                retry_after: Duration::from_secs(2)
            }),
            AfterFailure::AskPin
        );
        assert_eq!(
            after_failure(&Outcome::NotAvailable {
                retry_after: Duration::from_secs(60)
            }),
            AfterFailure::AskPin
        );
        assert_eq!(
            after_failure(&Outcome::Unreachable("x".into())),
            AfterFailure::Retry
        );
        assert_eq!(after_failure(&Outcome::Revoked), AfterFailure::Revoked);
    }

    #[test]
    fn reconnect_with_a_wrong_pin_stops_and_shows_the_pin_screen() {
        let r = rig();
        let (id, epoch) = activate(&r);
        let (link, pin) = {
            let c = r.app.desk.borrow();
            let a = c.active.as_ref().unwrap();
            (a.link.clone(), a.pin.clone())
        };
        let prepared = prepare(&r.app);
        finish_reconnect(
            &r.app,
            epoch,
            &id,
            link,
            pin,
            prepared,
            Err(Outcome::Wrong {
                attempts_left: 4,
                retry_after: Duration::ZERO,
            }),
        );
        // No session, no cached PIN, no retry timer: the Connect screen with the message.
        assert!(r.app.desk.borrow().active.is_none());
        assert_eq!(r.ui.global::<crate::Nav>().get_screen(), Screen::Connect);
        assert!(
            r.ui.global::<crate::ConnectVm>()
                .get_notice_title()
                .starts_with("Incorrect PIN")
        );
    }
}
